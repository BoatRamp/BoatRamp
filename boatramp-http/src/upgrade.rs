//! HTTP/1.1 connection **upgrade** (RFC 9110 §7.8) — the mechanism behind WebSocket and
//! any `Connection: upgrade` protocol switch. It replaces hyper's `hyper::upgrade`, so
//! the serving path owns upgrades and does not fall back to hyper.
//!
//! Flow: the [`serve`](crate::h1::serve) loop, for a request that carries upgrade intent,
//! puts a pending handle in the request's extensions. A handler (or a reverse-proxy
//! bridge) calls [`on_upgrade`] to take that handle, returns a `101 Switching Protocols`
//! response, and awaits the returned [`OnUpgrade`]; once the loop has written the `101` it
//! reunites the connection and hands the raw byte stream — with any bytes the peer already
//! sent past the handshake replayed — to the awaiting consumer via [`Upgraded`].

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{header, HeaderMap};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

/// Whether a request head carries HTTP upgrade intent: a `Connection` header listing the
/// `upgrade` token **and** an `Upgrade` header naming the target protocol.
pub fn is_upgrade_request(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
        .unwrap_or(false);
    connection_upgrade && headers.contains_key(header::UPGRADE)
}

/// The raw connection handed to an upgrade consumer after the `101`, replaying any bytes
/// the peer already sent past the handshake before yielding the live socket. Both a
/// bidirectional byte stream ([`AsyncRead`] + [`AsyncWrite`]).
pub struct Upgraded {
    inner: Pin<Box<dyn Io>>,
    prefix: Bytes,
    pos: usize,
}

/// Object-safe bound for the upgraded IO.
trait Io: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> Io for T {}

impl Upgraded {
    pub(crate) fn new(
        io: impl AsyncRead + AsyncWrite + Send + 'static,
        prefix: Bytes,
    ) -> Self {
        Upgraded { inner: Box::pin(io), prefix, pos: 0 }
    }
}

impl AsyncRead for Upgraded {
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
        self.inner.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for Upgraded {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.inner.as_mut().poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_shutdown(cx)
    }
}

/// A future that resolves to the [`Upgraded`] connection once the server has written the
/// `101` and handed off the socket. Resolves to `Err` if the upgrade never completed (the
/// handler returned a non-`101` response, or the connection dropped first).
pub struct OnUpgrade(pub(crate) oneshot::Receiver<Upgraded>);

/// The upgrade never completed (no `101`, or the connection closed first).
#[derive(Debug, Clone, Copy)]
pub struct UpgradeError;

impl std::fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("connection was not upgraded")
    }
}
impl std::error::Error for UpgradeError {}

impl std::future::Future for OnUpgrade {
    type Output = Result<Upgraded, UpgradeError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|r| r.map_err(|_| UpgradeError))
    }
}

/// The receiver side, parked in a request's extensions by the serve loop for a request
/// with upgrade intent; [`on_upgrade`] takes it out. `http::Extensions` requires `Clone`,
/// and a `oneshot::Receiver` is single-owner, so it is held behind a shared cell (mirrors
/// hyper's own clone-able upgrade handle).
#[derive(Clone)]
pub(crate) struct Pending(
    pub(crate) std::sync::Arc<std::sync::Mutex<Option<oneshot::Receiver<Upgraded>>>>,
);

impl Pending {
    pub(crate) fn new(rx: oneshot::Receiver<Upgraded>) -> Self {
        Pending(std::sync::Arc::new(std::sync::Mutex::new(Some(rx))))
    }
}

/// Register interest in taking over this request's connection after a `101`. Returns the
/// future to await (once a `101` response is returned) for the raw [`Upgraded`] stream, or
/// `None` if the request had no upgrade intent (nothing to take over — or it was already
/// taken). Mirrors `hyper::upgrade::on`.
pub fn on_upgrade<B>(req: &mut http::Request<B>) -> Option<OnUpgrade> {
    req.extensions()
        .get::<Pending>()
        .and_then(|p| p.0.lock().unwrap().take())
        .map(OnUpgrade)
}
