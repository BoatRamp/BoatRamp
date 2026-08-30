//! The unified connection dispatcher — one entry point that serves an accepted
//! connection with the right codec.
//!
//! A connection is classified by **sniffing the HTTP/2 client preface** (`PRI *
//! HTTP/2.0\r\n\r\nSM\r\n\r\n`): if the first bytes are the preface it is HTTP/2 (the
//! [`h2`](crate::h2) mux driver), otherwise HTTP/1.1 (the [`h1`](crate::h1) loop). This
//! works uniformly for **plaintext** (h2c prior-knowledge vs h1) and for a
//! **TLS-terminated** stream: after ALPN negotiation an `h2` client sends the preface and
//! an `http/1.1` client sends a request line, so the same sniff routes both — no separate
//! ALPN branch needed at this layer. Sniffed bytes are replayed to the codec via
//! [`Rewind`], so neither driver sees a consumed preface.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use std::time::Duration;

use crate::Handler;

/// Serving timeouts (a slowloris defense at each blocking phase). Defaults suit a
/// public listener; an operator can tune them per deployment.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// How long to wait for enough opening bytes to classify a connection (h2 vs h1).
    pub sniff_timeout: Duration,
    /// How long the h1 loop waits on a stalled request head/body before dropping.
    pub read_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sniff_timeout: Duration::from_secs(10),
            read_timeout: crate::h1::DEFAULT_READ_TIMEOUT,
        }
    }
}

/// Serve one accepted connection (plaintext or already-TLS-decrypted) with the codec its
/// opening bytes select — with default [`Config`] timeouts. See [`serve_connection_with`].
pub async fn serve_connection<IO, H>(io: IO, handler: H) -> std::io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler,
{
    serve_connection_with(io, handler, Config::default()).await
}

/// Serve one accepted connection with explicit [`Config`] timeouts: HTTP/2 (preface
/// present) via the mux driver, else HTTP/1.1.
pub async fn serve_connection_with<IO, H>(io: IO, handler: H, config: Config) -> std::io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler,
{
    let (prefix, io, is_h2) = classify(io, config.sniff_timeout).await?;
    let rewound = Rewind::new(prefix, io);
    if is_h2 {
        crate::h2::serve_connection_mux(rewound, handler).await
    } else {
        crate::h1::serve_connection_with(rewound, handler, config.read_timeout).await
    }
}

/// Read just enough leading bytes to decide h2-vs-h1. Stops as soon as the accumulated
/// prefix diverges from the preface (→ h1) or matches it fully (→ h2). Returns the read
/// bytes (to replay), the stream, and the verdict.
async fn classify<IO>(mut io: IO, sniff_timeout: Duration) -> std::io::Result<(Vec<u8>, IO, bool)>
where
    IO: AsyncRead + Unpin,
{
    let preface = crate::h2::CLIENT_PREFACE;
    let mut prefix = Vec::with_capacity(preface.len());
    loop {
        // Diverged from the preface → HTTP/1.1.
        if !preface.starts_with(&prefix) {
            return Ok((prefix, io, false));
        }
        // Full preface accumulated → HTTP/2.
        if prefix.len() >= preface.len() {
            return Ok((prefix, io, true));
        }
        let mut byte = [0u8; 1];
        match tokio::time::timeout(sniff_timeout, io.read(&mut byte)).await {
            Ok(Ok(0)) => {
                // EOF before a decision: an empty/short connection — classify as h1 so
                // the h1 loop closes it cleanly (an empty buffer is a clean close there).
                return Ok((prefix, io, false));
            }
            Ok(Ok(_)) => prefix.push(byte[0]),
            // Read error or slowloris timeout → treat as h1 (its loop will close).
            _ => return Ok((prefix, io, false)),
        }
    }
}

/// A reader that replays a buffered prefix (bytes already read for classification) before
/// yielding the underlying stream, so the selected codec sees an untouched connection.
/// Writes pass straight through.
pub struct Rewind<IO> {
    prefix: Vec<u8>,
    pos: usize,
    inner: IO,
}

impl<IO> Rewind<IO> {
    fn new(prefix: Vec<u8>, inner: IO) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }

    /// The wrapped transport — so the `sendfile` fast-path can reach the underlying
    /// socket through the classify wrapper.
    pub(crate) fn get_ref(&self) -> &IO {
        &self.inner
    }
}

/// The plaintext TCP socket of `io` **if** this codec can `sendfile` to it — a bare
/// [`TcpStream`](tokio::net::TcpStream) or one behind the classify [`Rewind`] wrapper
/// (the shape the plaintext serve path produces). Any other transport (a TLS stream, a
/// duplex/test stream, a doubly-wrapped fallback) returns `None`, so the caller writes
/// the body normally. Returning the live `&TcpStream` (not a raw fd) is what lets
/// `sendfile` drive readiness on the socket's **existing** reactor registration — a
/// per-request `dup` + fresh registration regressed ~2.4× under load. Linux only.
#[cfg(target_os = "linux")]
pub(crate) fn sendfile_socket<IO: std::any::Any>(io: &IO) -> Option<&tokio::net::TcpStream> {
    let any = io as &dyn std::any::Any;
    if let Some(tcp) = any.downcast_ref::<tokio::net::TcpStream>() {
        return Some(tcp);
    }
    if let Some(rw) = any.downcast_ref::<Rewind<tokio::net::TcpStream>>() {
        return Some(rw.get_ref());
    }
    None
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn sendfile_socket<IO: std::any::Any>(_io: &IO) -> Option<&tokio::net::TcpStream> {
    None
}

/// Zero-copy `[offset, offset+len)` of `file` → `sock`, via `sendfile`, driving
/// readiness on the socket's **own** reactor registration (`async_io`) — no `dup`, no
/// second registration (which misroutes edge-triggered wakeups and collapsed
/// throughput). The head bytes were already flushed to the same socket, so ordering is
/// preserved. This mirrors the reverse-proxy `splice` fast-path's `async_io` loop.
#[cfg(target_os = "linux")]
pub(crate) async fn sendfile_all(
    sock: &tokio::net::TcpStream,
    file: &std::fs::File,
    mut offset: u64,
    len: u64,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    let sock_fd = sock.as_raw_fd();
    let file_fd = file.as_raw_fd();
    let mut remaining = len;
    while remaining > 0 {
        let want = remaining.min(1 << 20) as usize;
        let n = sock
            .async_io(Interest::WRITABLE, || {
                // `sendfile` reads from `*off` and advances it; a fresh `off` per call
                // (recomputed from `offset`) keeps the closure idempotent across the
                // EAGAIN retries `async_io` may drive.
                let mut off = offset as libc::off_t;
                let r = unsafe { libc::sendfile(sock_fd, file_fd, &mut off, want) };
                if r < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(r as usize)
                }
            })
            .await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "sendfile moved 0 bytes before the content-length",
            ));
        }
        offset += n as u64;
        remaining -= n as u64;
    }
    Ok(())
}

impl<IO: AsyncRead + Unpin> AsyncRead for Rewind<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Rewind<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    // Forward vectored writes to the inner stream — the h2 mux writer hands the
    // response header + body `Bytes` as separate `IoSlice`s so (k)TLS copies them
    // straight out with no intermediate buffer. The default `AsyncWrite` impl would
    // collapse that to a single first-slice `poll_write`, defeating the fast-path.
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
