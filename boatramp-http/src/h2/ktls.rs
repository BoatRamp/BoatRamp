//! First-party kTLS handoff (Linux) — replaces the `ktls` crate, which does not
//! build on musl: it constructs `cmsghdr`/`msghdr` with struct literals that omit
//! musl's private `__pad1` field. We need only the **handoff**, not the crate's
//! `recvmsg`-with-control-message read path, so none of that musl-hostile code is
//! reimplemented here.
//!
//! After the userspace rustls handshake completes we:
//! 1. **Drain** any application-data records rustls already decrypted and buffered
//!    (via [`CorkStream`], which stops rustls at a TLS record boundary so no partial
//!    record is stranded in its buffer — those raw bytes would be lost to the kernel).
//! 2. **Extract** the negotiated traffic secrets (`enable_secret_extraction` must be
//!    set on the `ServerConfig`).
//! 3. `setsockopt` the kernel TLS ULP with the TX **and** RX crypto info for the
//!    negotiated AEAD suite.
//!
//! The socket then encrypts/decrypts in the kernel, so a reverse-proxy body can be
//! `splice()`d upstream→socket with the kernel encrypting on TX. Reads go through a
//! plain `recv()` in [`super::wire::Socket`] — kTLS delivers application-data records
//! as plaintext — so we never touch the record-type control-message path (the part of
//! the `ktls` crate that breaks musl).
//!
//! The `cmsghdr`-free surface here is plain `#[repr(C)]` structs + `setsockopt`, which
//! compiles identically on glibc and musl.

use std::io;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use rustls::{Connection, ConnectionTrafficSecrets, ProtocolVersion};

// ---- kernel ABI (linux/tls.h, uapi) -----------------------------------------

/// `setsockopt` level: TCP.
const SOL_TCP: libc::c_int = 6;
/// `setsockopt` SOL_TCP name: "upper level protocol" (attach the `tls` ULP).
const TCP_ULP: libc::c_int = 31;
/// `setsockopt` level: TLS (once the ULP is attached).
const SOL_TLS: libc::c_int = 282;
/// SOL_TLS name: configure the transmit (encrypt) key.
const TLS_TX: libc::c_int = 1;
/// SOL_TLS name: configure the receive (decrypt) key.
const TLS_RX: libc::c_int = 2;

const TLS_1_2_VERSION: u16 = 0x0303;
const TLS_1_3_VERSION: u16 = 0x0304;

const TLS_CIPHER_AES_GCM_128: u16 = 51;
const TLS_CIPHER_AES_GCM_256: u16 = 52;
const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

/// `struct tls_crypto_info` — the common header of every cipher's crypto info.
#[repr(C)]
#[derive(Clone, Copy)]
struct CryptoInfoHeader {
    version: u16,
    cipher_type: u16,
}

/// `struct tls12_crypto_info_aes_gcm_128` (also used for TLS 1.3 AES-128-GCM).
#[repr(C)]
struct AesGcm128 {
    header: CryptoInfoHeader,
    iv: [u8; 8],
    key: [u8; 16],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}

/// `struct tls12_crypto_info_aes_gcm_256`.
#[repr(C)]
struct AesGcm256 {
    header: CryptoInfoHeader,
    iv: [u8; 8],
    key: [u8; 32],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}

/// `struct tls12_crypto_info_chacha20_poly1305` (salt is zero-length for ChaCha20).
#[repr(C)]
struct Chacha20Poly1305 {
    header: CryptoInfoHeader,
    iv: [u8; 12],
    key: [u8; 32],
    rec_seq: [u8; 8],
}

// The kernel copies exactly `sizeof(struct ...)` bytes out of the `setsockopt` buffer,
// so a wrong size (field reorder, stray padding) silently corrupts the key. Pin the
// layouts to the linux/tls.h ABI at compile time.
const _: () = {
    assert!(size_of::<AesGcm128>() == 4 + 8 + 16 + 4 + 8);
    assert!(size_of::<AesGcm256>() == 4 + 8 + 32 + 4 + 8);
    assert!(size_of::<Chacha20Poly1305>() == 4 + 12 + 32 + 8);
};

fn errno(context: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("kTLS: {context}: {e}"))
}

/// Attach the kernel `tls` ULP to the socket (`setsockopt(SOL_TCP, TCP_ULP, "tls")`).
fn setup_ulp(fd: libc::c_int) -> io::Result<()> {
    let r = unsafe {
        libc::setsockopt(
            fd,
            SOL_TCP,
            TCP_ULP,
            c"tls".as_ptr().cast::<libc::c_void>(),
            3,
        )
    };
    if r < 0 {
        return Err(errno("attach tls ULP (kernel CONFIG_TLS?)"));
    }
    Ok(())
}

/// `setsockopt(SOL_TLS, TLS_TX|TLS_RX, &crypto_info)` — hand the negotiated key to the
/// kernel for one direction. `info`/`len` point at a `#[repr(C)]` crypto-info struct.
fn set_crypto_info(
    fd: libc::c_int,
    dir: libc::c_int,
    info: *const u8,
    len: usize,
) -> io::Result<()> {
    let r = unsafe {
        libc::setsockopt(
            fd,
            SOL_TLS,
            dir,
            info.cast::<libc::c_void>(),
            len as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(errno("set crypto info (unsupported cipher/kernel?)"));
    }
    Ok(())
}

/// Configure one direction (TX or RX) from a rustls extracted secret.
fn setup_direction(
    fd: libc::c_int,
    dir: libc::c_int,
    version: u16,
    (seq, secrets): (u64, ConnectionTrafficSecrets),
) -> io::Result<()> {
    let header = |cipher_type| CryptoInfoHeader {
        version,
        cipher_type,
    };
    let bad = || io::Error::new(io::ErrorKind::Unsupported, "kTLS: cipher not supported");
    let rec_seq = seq.to_be_bytes();
    match secrets {
        // For TLS 1.2, rustls reports both GCM-128 and GCM-256 through the
        // `Aes128Gcm` variant (see rustls#1833); the key length disambiguates.
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } if key.as_ref().len() == 16 => {
            let iv = iv.as_ref();
            let info = AesGcm128 {
                header: header(TLS_CIPHER_AES_GCM_128),
                iv: iv
                    .get(4..12)
                    .ok_or_else(bad)?
                    .try_into()
                    .map_err(|_| bad())?,
                key: key.as_ref().try_into().map_err(|_| bad())?,
                salt: iv.get(..4).ok_or_else(bad)?.try_into().map_err(|_| bad())?,
                rec_seq,
            };
            set_crypto_info(
                fd,
                dir,
                (&info as *const AesGcm128).cast(),
                size_of::<AesGcm128>(),
            )
        }
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
        | ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            let iv = iv.as_ref();
            let info = AesGcm256 {
                header: header(TLS_CIPHER_AES_GCM_256),
                iv: iv
                    .get(4..12)
                    .ok_or_else(bad)?
                    .try_into()
                    .map_err(|_| bad())?,
                key: key.as_ref().try_into().map_err(|_| bad())?,
                salt: iv.get(..4).ok_or_else(bad)?.try_into().map_err(|_| bad())?,
                rec_seq,
            };
            set_crypto_info(
                fd,
                dir,
                (&info as *const AesGcm256).cast(),
                size_of::<AesGcm256>(),
            )
        }
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            let info = Chacha20Poly1305 {
                header: header(TLS_CIPHER_CHACHA20_POLY1305),
                iv: iv.as_ref().try_into().map_err(|_| bad())?,
                key: key.as_ref().try_into().map_err(|_| bad())?,
                rec_seq,
            };
            set_crypto_info(
                fd,
                dir,
                (&info as *const Chacha20Poly1305).cast(),
                size_of::<Chacha20Poly1305>(),
            )
        }
        _ => Err(bad()),
    }
}

/// Perform the kTLS handoff on a completed server-side TLS connection: drain any
/// buffered plaintext, extract the traffic secrets, and configure the kernel TLS ULP
/// for both directions. Returns the bare [`TcpStream`] (now a kTLS socket) plus the
/// drained plaintext to replay before reading from the kernel.
///
/// The `ServerConfig` behind the acceptor MUST have `enable_secret_extraction = true`.
pub async fn config_ktls_server(
    mut tls: TlsStream<CorkStream<TcpStream>>,
) -> io::Result<(TcpStream, Vec<u8>)> {
    // Cork the inner stream so rustls stops at a record boundary while we drain.
    tls.get_mut().0.corked = true;
    let drained = drain(&mut tls).await?;

    let (cork, conn) = tls.into_inner();
    let io = cork.io;
    let fd = io.as_raw_fd();

    let version = match conn.protocol_version() {
        Some(ProtocolVersion::TLSv1_3) => TLS_1_3_VERSION,
        Some(ProtocolVersion::TLSv1_2) => TLS_1_2_VERSION,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "kTLS: unsupported TLS version (need 1.2/1.3)",
            ))
        }
    };

    let secrets = Connection::Server(conn)
        .dangerous_extract_secrets()
        .map_err(|e| io::Error::other(format!("kTLS: extract secrets: {e}")))?;

    setup_ulp(fd)?;
    setup_direction(fd, TLS_TX, version, secrets.tx)?;
    setup_direction(fd, TLS_RX, version, secrets.rx)?;

    Ok((io, drained.unwrap_or_default()))
}

/// Read every already-decrypted plaintext byte rustls buffered during the handshake.
/// [`CorkStream`] returns a clean EOF at the first record boundary once corked, so this
/// terminates without consuming any bytes that belong to the kernel.
async fn drain(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Vec<u8>>> {
    let mut buf = vec![0u8; 128 * 1024];
    let mut filled = 0;
    loop {
        match stream.read(&mut buf[filled..]).await {
            Ok(0) => break,
            // CorkStream reports the drain terminus as a clean EOF; rustls may surface
            // it as UnexpectedEof — both mean "record boundary reached".
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
            Ok(n) => filled += n,
        }
        if filled == buf.len() {
            buf.resize(filled + 128 * 1024, 0);
        }
    }
    buf.truncate(filled);
    Ok((!buf.is_empty()).then_some(buf))
}

// ---- CorkStream --------------------------------------------------------------

/// Wraps the raw stream and tracks TLS record framing so that, once `corked`, it
/// returns empty reads at each record boundary. That lets rustls finish deframing the
/// record it is on and then stop — instead of reading ahead into the next record and
/// stranding those raw bytes in its buffer, where the kernel (which reads straight from
/// the socket after handoff) would never see them. Anything that doesn't look like a
/// TLS record (bad header, short read, EOF) drops to a transparent passthrough and lets
/// rustls report the error.
pub struct CorkStream<IO> {
    pub io: IO,
    /// Set true just before draining, to force the boundary EOFs.
    pub corked: bool,
    state: State,
}

enum State {
    ReadHeader { buf: [u8; 5], off: usize },
    ReadPayload { size: usize, off: usize },
    Passthrough,
}

impl<IO> CorkStream<IO> {
    pub fn new(io: IO) -> Self {
        Self {
            io,
            corked: false,
            state: State::ReadHeader {
                buf: [0; 5],
                off: 0,
            },
        }
    }
}

/// Decode a 5-byte TLS record header into its payload length, or `None` if it is not a
/// plausible record (so the caller falls back to passthrough).
fn record_len(hdr: [u8; 5]) -> Option<usize> {
    // hdr[0] content type (20 change_cipher_spec .. 23 application_data), hdr[1..3]
    // legacy version, hdr[3..5] length (big-endian). A record body is at most 2^14 +
    // 256 (TLS 1.3 expansion), so anything larger is not a real record.
    if !(20..=23).contains(&hdr[0]) {
        return None;
    }
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len == 0 || len > (1 << 14) + 256 {
        return None;
    }
    Some(len)
}

impl<IO: AsyncRead + Unpin> AsyncRead for CorkStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut io = Pin::new(&mut this.io);
        loop {
            match &mut this.state {
                State::ReadHeader { buf: hdr, off } => {
                    if *off == 0 && this.corked {
                        // At a record boundary and corked: hand rustls a clean EOF, but
                        // re-arm the waker so the task is not stalled.
                        cx.waker().wake_by_ref();
                        return Poll::Ready(Ok(()));
                    }
                    let mut rest = ReadBuf::new(&mut hdr[*off..]);
                    ready!(io.as_mut().poll_read(cx, &mut rest))?;
                    let got = rest.filled().len();
                    *off += got;
                    if got == 0 {
                        // Unexpected EOF mid-header: surface what we have and passthrough.
                        buf.put_slice(&hdr[..*off]);
                        this.state = State::Passthrough;
                        return Poll::Ready(Ok(()));
                    }
                    if *off == 5 {
                        buf.put_slice(&hdr[..]);
                        this.state = match record_len(*hdr) {
                            Some(size) => State::ReadPayload { size, off: 0 },
                            None => State::Passthrough,
                        };
                        return Poll::Ready(Ok(()));
                    }
                }
                State::ReadPayload { size, off } => {
                    let want = *size - *off;
                    let before = buf.filled().len();
                    let mut limited = buf.take(want);
                    ready!(io.as_mut().poll_read(cx, &mut limited))?;
                    let got = limited.filled().len();
                    *off += got;
                    if *off == *size {
                        this.state = State::ReadHeader {
                            buf: [0; 5],
                            off: 0,
                        };
                    }
                    let filled = before + got;
                    buf.set_filled(filled);
                    return Poll::Ready(Ok(()));
                }
                State::Passthrough => return io.poll_read(cx, buf),
            }
        }
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for CorkStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}
