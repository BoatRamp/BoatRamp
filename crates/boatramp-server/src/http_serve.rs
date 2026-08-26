//! The unified serving front door: every accepted connection — plaintext or TLS,
//! HTTP/1.1 or HTTP/2 — is driven by [`boatramp_http::serve_connection`], boatramp's
//! own hand-rolled h1+h2 stack. This is what replaced hyper/`axum_server` on the
//! serving path (hyper stays only as the reverse-proxy *client*).
//!
//! The pieces:
//! - [`RouterHandler`] bridges the dispatcher to the axum [`Router`] (a tower
//!   `Service`): it swaps body types and attaches the peer, nothing else. It is
//!   **protocol-agnostic** — it never strips hop-by-hop headers, because each codec
//!   owns its own framing rules (the h1 loop reframes and preserves a `101`
//!   upgrade's `Connection`/`Upgrade` verbatim; the h2 codec drops the
//!   connection-specific headers HTTP/2 forbids). One bridge feeds both.
//! - [`serve_tls`] terminates TLS ourselves (rustls) and serves the negotiated
//!   protocol; it also transparently completes ACME `acme-tls/1` challenge
//!   handshakes. [`ReloadableTls`] lets the ACME renewal loop hot-swap the served
//!   certificate live, the way `axum_server`'s `RustlsConfig::reload` did.
//! - [`serve_plaintext`] is the same accept→`serve_connection` loop without TLS
//!   (the `:80` HTTP→HTTPS redirect listener).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::Router;
use boatramp_http::{
    Body as HttpBody, BodyError, Handler, Request as HttpRequest, Response as HttpResponse,
};
use futures::StreamExt as _;
use http_body_util::BodyStream;
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// The ALPN identifier for the ACME TLS-ALPN-01 challenge (RFC 8737). A challenge
/// connection negotiates only this; a completed challenge handshake carries no
/// request, so [`serve_tls`] drops it rather than handing it to the h1/h2 driver.
const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// The ALPN protocols our HTTPS listeners advertise, in server-preference order:
/// HTTP/2 first, then HTTP/1.1. (`serve_connection` also sniffs the h2 preface, so
/// a client that negotiates neither still gets the right codec — ALPN is the fast
/// path, the sniff is the backstop.)
pub fn alpn_h1_h2() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

/// A [`Router`] plus the optional hot-path handle, flowed through the serve loops as
/// one unit. A bare `Router` converts in with **no** fast path (`From<Router>`), so
/// auxiliary listeners (the `:80` HTTP→HTTPS redirect, ACME challenge) are unchanged;
/// the main site listeners pass `(router, fast)` (via `From<(Router, FastServe)>`) to
/// enable the bypass. Cheap to clone (an `Arc`-y `Router` clone + an `Option`).
#[derive(Clone)]
pub struct ServeInput {
    router: Router,
    fast: Option<crate::FastServe>,
}

impl From<Router> for ServeInput {
    fn from(router: Router) -> Self {
        Self { router, fast: None }
    }
}

impl From<(Router, crate::FastServe)> for ServeInput {
    fn from((router, fast): (Router, crate::FastServe)) -> Self {
        Self {
            router,
            fast: Some(fast),
        }
    }
}

/// Bridges [`boatramp_http`]'s serving surface to the axum [`Router`] (a tower
/// `Service`). Both codecs produce a native `http::Request`, so the bridge only
/// swaps the body type and attaches the peer address; method / URI / headers pass
/// through untouched. Constructed once per connection. Carries the optional
/// [`FastServe`](crate::FastServe) hot-path handle: an eligible plain site GET/HEAD is
/// dispatched straight to `serve_by_host`, skipping the axum router + middleware
/// composition; everything else falls through to the router unchanged.
pub struct RouterHandler {
    serve: ServeInput,
    peer: SocketAddr,
}

impl RouterHandler {
    pub fn new(serve: impl Into<ServeInput>, peer: SocketAddr) -> Self {
        Self {
            serve: serve.into(),
            peer,
        }
    }
}

impl Handler for RouterHandler {
    async fn handle(&self, req: HttpRequest) -> HttpResponse {
        // Wrap the streaming request body as an axum body (cheap; `ReqBody` is an
        // `http_body::Body`) and attach the peer as `ConnectInfo` (IP rules / rate
        // limiting / access logs read it). Nothing else is rebuilt.
        let mut request = req.map(axum::body::Body::new);
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(self.peer));

        // Hot path: an eligible plain site GET/HEAD skips the axum router + middleware
        // future-composition (~15–20% of per-core CPU, profiled) and dispatches straight
        // to `serve_by_host`. `FastServe::dispatch` still applies the request-id +
        // access-log/metrics guarantees, and rate-limit / visitor-auth / host-routing /
        // preview-auth / DV all run inside `serve_by_host_inner` — so the bypass can never
        // skip a security check. Everything else (and every build without a fast handle)
        // falls through to the router, byte-identical to before.
        let resp = match &self.serve.fast {
            Some(fast) if fast.eligible(&request) => fast.dispatch(request, self.peer).await,
            _ => {
                // Call the router as a tower Service (axum's Router is always ready).
                use tower_service::Service as _;
                let mut router = self.serve.router.clone();
                match router.call(request).await {
                    Ok(r) => r,
                    Err(_) => return boatramp_http::response(502, b"bad gateway".to_vec()),
                }
            }
        };
        let (parts, body) = resp.into_parts();
        // Hand the router's body to the codec as a pull `Stream` it polls itself —
        // no producer task, no channel, no buffering (unbounded bodies stream too).
        // Data frames pass through; a mid-stream body error (an upstream that dropped)
        // becomes a `BodyError` so the codec aborts the response instead of framing a
        // truncated body as complete; trailer/empty frames are dropped. We do NOT
        // strip hop-by-hop headers here: the h1 loop reframes them (and preserves a
        // `101` upgrade's verbatim), and the h2 codec drops the ones it forbids.
        let chunks = BodyStream::new(body).filter_map(|frame| {
            std::future::ready(match frame {
                Ok(f) => f.into_data().ok().filter(|b| !b.is_empty()).map(Ok),
                Err(_) => Some(Err(BodyError)),
            })
        });
        axum::http::Response::from_parts(parts, HttpBody::try_stream(chunks))
    }
}

/// Serve one accepted connection (plaintext or already-TLS-terminated) by driving
/// it through the unified [`boatramp_http::serve_connection`] dispatcher, bridged
/// into `router`. A clean close is silent; an unexpected IO error is logged at
/// debug. Generic over the IO so a raw `TcpStream`, a rewound stream, or a
/// `TlsStream` all serve identically.
pub async fn serve_router_conn<IO>(io: IO, peer: SocketAddr, serve: impl Into<ServeInput>)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if let Err(err) = boatramp_http::serve_connection(io, RouterHandler::new(serve, peer)).await {
        tracing::debug!(%peer, %err, "connection served with error");
    }
}

/// Serve one TLS-terminated connection, routing on the **negotiated ALPN** rather
/// than re-sniffing the stream: ALPN already told us the protocol, so we hand the
/// decrypted stream straight to the h2 mux driver or the h1 loop with no preface
/// sniff and no [`Rewind`] wrapper (that wrapper would otherwise sit on the write
/// path and break the h2 writer's vectored `IoSlice` fast-path). A completed
/// `acme-tls/1` challenge handshake carries no request and is dropped. A connection
/// that negotiated no ALPN falls back to the sniffing dispatcher.
async fn serve_tls_stream(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    peer: SocketAddr,
    serve: ServeInput,
) {
    let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let handler = RouterHandler::new(serve, peer);
    let result = match alpn.as_deref() {
        // The challenge handshake alone satisfies the CA — nothing to serve.
        Some(p) if p == ACME_TLS_ALPN => {
            tracing::debug!(%peer, "completed an ACME tls-alpn-01 challenge");
            return;
        }
        Some(b"h2") => boatramp_http::h2::serve_connection_mux(stream, handler).await,
        Some(b"http/1.1") => boatramp_http::h1::serve_connection(stream, handler).await,
        // No ALPN negotiated (a bare TLS client): let the dispatcher sniff h2c-vs-h1.
        _ => boatramp_http::serve_connection(stream, handler).await,
    };
    if let Err(err) = result {
        tracing::debug!(%peer, %err, "TLS connection served with error");
    }
}

/// A rustls [`ServerConfig`] the accept loop reads afresh per connection, so a
/// background task (ACME renewal) can hot-swap the served certificate without a
/// restart — the same capability `axum_server`'s `RustlsConfig` gave us. Reads are
/// a single lock-free atomic load ([`ArcSwap`]).
#[derive(Clone)]
pub struct ReloadableTls(Arc<ArcSwap<ServerConfig>>);

impl ReloadableTls {
    /// Wrap a config that will be served (and may later be [`reload`](Self::reload)ed).
    pub fn new(config: ServerConfig) -> Self {
        Self(Arc::new(ArcSwap::from_pointee(config)))
    }

    /// Atomically replace the served config; connections accepted after this use it,
    /// in-flight ones are unaffected.
    pub fn reload(&self, config: ServerConfig) {
        self.0.store(Arc::new(config));
    }

    fn current(&self) -> Arc<ServerConfig> {
        self.0.load_full()
    }
}

impl From<ServerConfig> for ReloadableTls {
    fn from(config: ServerConfig) -> Self {
        Self::new(config)
    }
}

/// How long the serve loops wait for in-flight connections to finish after the
/// shutdown signal before dropping them — matches the plaintext drain deadline.
const DRAIN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Serve HTTPS on `addr`: accept TCP, terminate TLS with the (reloadable) rustls
/// config, and drive the negotiated protocol through [`serve_router_conn`]. An
/// ACME `acme-tls/1` challenge handshake completes and is dropped (it carries no
/// request). Returns once `shutdown` resolves, after a bounded drain of in-flight
/// connections. The config SHOULD advertise ALPN `h2`/`http/1.1` ([`alpn_h1_h2`]);
/// an ACME config additionally carries `acme-tls/1`.
pub async fn serve_tls<S>(
    addr: SocketAddr,
    tls: ReloadableTls,
    serve: impl Into<ServeInput>,
    shutdown: S,
) -> std::io::Result<()>
where
    S: Future<Output = ()> + Send,
{
    let listener = TcpListener::bind(addr).await?;
    serve_tls_listener(listener, tls, serve, shutdown).await
}

/// [`serve_tls`] on an already-bound [`TcpListener`] — for callers that must learn
/// the bound port first (an ephemeral `:0` bind) or that inherit the socket
/// (systemd activation, tests).
pub async fn serve_tls_listener<S>(
    listener: TcpListener,
    tls: ReloadableTls,
    serve: impl Into<ServeInput>,
    shutdown: S,
) -> std::io::Result<()>
where
    S: Future<Output = ()> + Send,
{
    if let Ok(addr) = listener.local_addr() {
        tracing::info!(%addr, "serving HTTPS (boatramp-http)");
    }
    let serve = serve.into();
    let inflight = Arc::new(AtomicUsize::new(0));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (mut tcp, peer) = match accepted {
                    Ok(v) => v,
                    Err(err) => {
                        tracing::debug!(%err, "TLS serve: accept error");
                        continue;
                    }
                };
                crate::disable_nagle(&mut tcp);
                let acceptor = TlsAcceptor::from(tls.current());
                let serve = serve.clone();
                let inflight = inflight.clone();
                inflight.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    match acceptor.accept(tcp).await {
                        Ok(stream) => serve_tls_stream(stream, peer, serve).await,
                        Err(err) => tracing::debug!(%peer, %err, "TLS handshake failed"),
                    }
                    inflight.fetch_sub(1, Ordering::SeqCst);
                });
            }
        }
    }
    drain(&inflight).await;
    Ok(())
}

/// Serve plaintext HTTP on `addr` through the unified dispatcher (h1, or h2c via
/// the preface sniff), bridged into `router`. Used by the `:80` HTTP→HTTPS
/// redirect listener. Returns once `shutdown` resolves, after a bounded drain.
pub async fn serve_plaintext<S>(
    addr: SocketAddr,
    serve: impl Into<ServeInput>,
    shutdown: S,
) -> std::io::Result<()>
where
    S: Future<Output = ()> + Send,
{
    let listener = TcpListener::bind(addr).await?;
    serve_plaintext_listener(listener, serve, shutdown).await
}

/// [`serve_plaintext`] on an already-bound [`TcpListener`] (see
/// [`serve_tls_listener`]).
pub async fn serve_plaintext_listener<S>(
    listener: TcpListener,
    serve: impl Into<ServeInput>,
    shutdown: S,
) -> std::io::Result<()>
where
    S: Future<Output = ()> + Send,
{
    let serve = serve.into();
    let inflight = Arc::new(AtomicUsize::new(0));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (mut tcp, peer) = match accepted {
                    Ok(v) => v,
                    Err(err) => {
                        tracing::debug!(%err, "plaintext serve: accept error");
                        continue;
                    }
                };
                crate::disable_nagle(&mut tcp);
                let serve = serve.clone();
                let inflight = inflight.clone();
                inflight.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    serve_router_conn(tcp, peer, serve).await;
                    inflight.fetch_sub(1, Ordering::SeqCst);
                });
            }
        }
    }
    drain(&inflight).await;
    Ok(())
}

/// Wait for in-flight connections to drop to zero, or the [`DRAIN_DEADLINE`],
/// whichever comes first (then the caller returns and any stragglers are dropped).
async fn drain(inflight: &AtomicUsize) {
    let deadline = tokio::time::Instant::now() + DRAIN_DEADLINE;
    while inflight.load(Ordering::SeqCst) > 0 {
        if tokio::time::Instant::now() >= deadline {
            tracing::warn!("TLS/plaintext drain deadline exceeded; dropping in-flight connections");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
