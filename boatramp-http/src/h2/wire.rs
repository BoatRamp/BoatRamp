//! The connection I/O layer. The h2 driver talks only to [`Wire`], so it is
//! identical whether the connection is a plain buffered stream or a splice-capable
//! socket.
//!
//! - [`Wire::Buffered`] wraps any `AsyncRead + AsyncWrite` (tests, and any transport
//!   without a spliceable fd) — reads/writes go through the tokio traits.
//! - [`Wire::Socket`] wraps a plaintext-TCP or **kTLS** `TcpStream` and drives it via
//!   `async_io` (raw `recv`/`send`), so the *same* fd also serves the zero-copy
//!   `splice()` body path — the kernel moves the upstream body straight into the
//!   (kTLS) socket, encrypting on TX, with nothing copied through userspace.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use tokio::io::Interest;
#[cfg(target_os = "linux")]
use tokio::net::TcpStream;

pub(crate) enum Wire<IO> {
    Buffered(IO),
    #[cfg(target_os = "linux")]
    Socket(Socket),
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Wire<IO> {
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        match self {
            Wire::Buffered(io) => io.read_exact(buf).await.map(|_| ()),
            #[cfg(target_os = "linux")]
            Wire::Socket(s) => s.read_exact(buf).await,
        }
    }

    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Wire::Buffered(io) => io.write_all(buf).await,
            #[cfg(target_os = "linux")]
            Wire::Socket(s) => s.write_all(buf).await,
        }
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            Wire::Buffered(io) => io.shutdown().await,
            #[cfg(target_os = "linux")]
            Wire::Socket(s) => s.sock.shutdown().await,
        }
    }

    /// Whether this connection can take the kernel splice body path.
    #[cfg(target_os = "linux")]
    pub fn can_splice(&self) -> bool {
        matches!(self, Wire::Socket(_))
    }

    /// Send one DATA frame — `header` (its 9-byte frame header) plus `n` payload
    /// bytes moved from `upstream` — through the persistent pipe into the connection
    /// socket with `splice()`. The header is pushed into the pipe first and the
    /// payload spliced in behind it, so the whole frame drains to the socket in one
    /// pass and the header rides in the *same* TLS record as the body (a kTLS socket
    /// encrypts on TX): no userspace copy, no tiny per-frame TLS record. Only valid
    /// on [`Wire::Socket`]; `header.len() + n` must fit the pipe.
    #[cfg(target_os = "linux")]
    pub async fn splice_data_frame(
        &mut self,
        upstream: &TcpStream,
        header: &[u8],
        n: usize,
    ) -> io::Result<()> {
        match self {
            Wire::Socket(s) => s.splice_data_frame(upstream, header, n).await,
            Wire::Buffered(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "buffered wire cannot splice",
            )),
        }
    }
}

/// The persistent pipe is grown to this so a full `header + frame` always fits with
/// headroom (the default pipe is only 64 KiB). The connection flush loop caps a DATA
/// frame at 128 KiB (well above the usual 16 KiB `SETTINGS_MAX_FRAME_SIZE`), so the
/// pipe never fills mid-splice — which would make `splice()` block on the wrong
/// readiness.
#[cfg(target_os = "linux")]
const PIPE_CAPACITY: libc::c_int = 256 * 1024;

#[cfg(target_os = "linux")]
pub(crate) struct Socket {
    sock: TcpStream,
    /// Bytes rustls decrypted during the handshake drain before kTLS took over —
    /// a raw `recv` would miss them, so we replay them first.
    leftover: Vec<u8>,
    lpos: usize,
    pipe: Pipe,
}

#[cfg(target_os = "linux")]
impl Socket {
    pub fn new(sock: TcpStream, leftover: Vec<u8>) -> io::Result<Self> {
        Ok(Socket {
            sock,
            leftover,
            lpos: 0,
            pipe: Pipe::new()?,
        })
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut n = 0;
        if self.lpos < self.leftover.len() {
            let take = (self.leftover.len() - self.lpos).min(buf.len());
            buf[..take].copy_from_slice(&self.leftover[self.lpos..self.lpos + take]);
            self.lpos += take;
            n = take;
        }
        let fd = self.sock.as_raw_fd();
        while n < buf.len() {
            let got = self
                .sock
                .async_io(Interest::READABLE, || {
                    let r = unsafe {
                        libc::recv(
                            fd,
                            buf[n..].as_mut_ptr() as *mut libc::c_void,
                            buf.len() - n,
                            0,
                        )
                    };
                    if r < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(r as usize)
                    }
                })
                .await?;
            if got == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
            }
            n += got;
        }
        Ok(())
    }

    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let fd = self.sock.as_raw_fd();
        let mut n = 0;
        while n < buf.len() {
            let put = self
                .sock
                .async_io(Interest::WRITABLE, || {
                    let r = unsafe {
                        libc::send(
                            fd,
                            buf[n..].as_ptr() as *const libc::c_void,
                            buf.len() - n,
                            0,
                        )
                    };
                    if r < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(r as usize)
                    }
                })
                .await?;
            n += put;
        }
        Ok(())
    }

    async fn splice_data_frame(
        &mut self,
        upstream: &TcpStream,
        header: &[u8],
        n: usize,
    ) -> io::Result<()> {
        use std::ptr;
        let up_fd = upstream.as_raw_fd();
        let dst_fd = self.sock.as_raw_fd();
        let (pr, pw) = (self.pipe.r, self.pipe.w);
        let flags = libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK;

        // 1. Frame header into the (empty) pipe. `splice_data_frame` always drains
        //    the pipe fully before returning, so at entry it is empty and these few
        //    bytes never fill it — a plain non-blocking write suffices.
        let mut off = 0;
        while off < header.len() {
            let r = unsafe {
                libc::write(
                    pw,
                    header[off..].as_ptr() as *const libc::c_void,
                    header.len() - off,
                )
            };
            if r < 0 {
                return Err(io::Error::last_os_error());
            }
            off += r as usize;
        }

        // 2. Payload: splice upstream -> pipe, behind the header. `header.len() + n`
        //    fits the grown pipe, so this never fills it (only upstream readiness
        //    can gate — which is exactly the readiness we await).
        let mut got = 0;
        while got < n {
            let in_n = upstream
                .async_io(Interest::READABLE, || {
                    let r = unsafe {
                        libc::splice(up_fd, ptr::null_mut(), pw, ptr::null_mut(), n - got, flags)
                    };
                    if r < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(r as usize)
                    }
                })
                .await?;
            if in_n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream closed before content-length",
                ));
            }
            got += in_n;
        }

        // 3. Drain header+payload pipe -> connection socket (kTLS encrypts on TX) in
        //    one pass, so the header shares the body's TLS record.
        let mut left = header.len() + n;
        while left > 0 {
            let out_n = self
                .sock
                .async_io(Interest::WRITABLE, || {
                    let r = unsafe {
                        libc::splice(pr, ptr::null_mut(), dst_fd, ptr::null_mut(), left, flags)
                    };
                    if r < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(r as usize)
                    }
                })
                .await?;
            left -= out_n;
        }
        Ok(())
    }
}

/// A non-blocking pipe reused for every splice on a connection.
#[cfg(target_os = "linux")]
struct Pipe {
    r: i32,
    w: i32,
}

#[cfg(target_os = "linux")]
impl Pipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // Grow the pipe so a full `header + MAX_SPLICE_FRAME` DATA frame always fits
        // (the default is 64 KiB). Best-effort: if the resize is refused the frame
        // ceiling still keeps us under the default, so we ignore the result.
        unsafe { libc::fcntl(fds[1], libc::F_SETPIPE_SZ, PIPE_CAPACITY) };
        Ok(Pipe {
            r: fds[0],
            w: fds[1],
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.r);
            libc::close(self.w);
        }
    }
}
