//! Opt-in HTTP/2 serve fast-path (feature `h2-mux`, gated at runtime by the
//! `BOATRAMP_H2_MUX` env var). Terminates TLS ourselves and serves h2 connections
//! with `boatramp-h2`'s concurrent multiplexed driver — which beats hyper (and
//! Envoy) on `tls-proxy-h2` — while h1 falls back to hyper. Each h2 request is
//! bridged into the same axum [`Router`] the normal pipeline serves, so routing /
//! gateway proxying / handlers are unchanged.
//!
//! The response body is streamed into the driver over a bounded channel (bounded
//! memory + TTFB). hyper remains both the h1 path and the default (this loop is
//! only entered when the operator opts in), so nothing streaming-heavy regresses
//! unless explicitly enabled.
//!
//! ## Router-bypass fast-path
//!
//! Both this path and hyper pay the full axum middleware stack, which is the last
//! few percent of the gap to hyper's native h2 serving. For a request that is an
//! *unambiguous pure gateway proxy* — resolved by the **same** conservative
//! eligibility oracle the h1 splice path uses ([`crate::splice::classify_gateway`],
//! so a site's access rules / redirects / handlers / streams can never be
//! bypassed) — the bridge calls [`crate::dispatch_gateway`] directly, skipping the
//! router. Any doubt (an access rule, a compute-backed upstream, a redirect, a
//! handler, a stream, anything the oracle won't vouch for) falls through to the
//! full router unchanged. Toggle off with `BOATRAMP_H2_MUX_BYPASS=0`.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::http;
use axum::Router;
use boatramp_core::deploy::DeployStore;
use boatramp_core::security::SecurityPosture;
use boatramp_h2::{serve_connection_mux, Body as MuxBody, Handler, Request as MuxRequest, Response as MuxResponse};
use bytes::Bytes;
use http_body_util::BodyExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::splice::SpliceCtx;

/// Hop-by-hop response headers, illegal in HTTP/2, stripped before framing.
/// `content-length` is deliberately kept — the body is streamed, so a fixed-length
/// upstream response passes its `content-length` straight through.
const HOP_BY_HOP: &[http::HeaderName] = &[
    http::header::CONNECTION,
    http::header::TRANSFER_ENCODING,
    http::header::UPGRADE,
];

/// Whether the router-bypass fast-path is enabled (default on when the `h2-mux`
/// path is active; set `BOATRAMP_H2_MUX_BYPASS=0` to force every request through
/// the full router, e.g. to A/B the bypass). Read once — env is process-static.
fn bypass_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        !matches!(
            std::env::var("BOATRAMP_H2_MUX_BYPASS").ok().as_deref(),
            Some("0") | Some("false") | Some("off")
        )
    })
}

/// Bridges the mux driver to the axum [`Router`] (a tower `Service`). The driver
/// produces native `http::Request`/`Response`, so the bridge just swaps body types
/// and reuses the parts — no per-request header re-marshaling. Cloned per connection.
struct RouterHandler {
    router: Router,
    peer: SocketAddr,
    /// Classifier context for the router-bypass fast-path (store + posture + daemon),
    /// identical to the one the h1 splice path uses.
    ctx: SpliceCtx,
}

impl Handler for RouterHandler {
    async fn handle(&self, req: MuxRequest) -> MuxResponse {
        // Router-bypass fast-path: for an unambiguous pure gateway-proxy request,
        // forward straight to `dispatch_gateway`, skipping the axum middleware. The
        // eligibility oracle is shared verbatim with the h1 splice path, so a site's
        // access rules / redirects / handlers / streams are honored identically and
        // can never be bypassed. Any doubt returns the request for the full router.
        let req = match self.try_gateway_bypass(req).await {
            Ok(resp) => return resp,
            Err(req) => req,
        };

        // The request is already an `http::Request`; just wrap its `Bytes` body as an
        // axum body (cheap, ref-counted) and attach the peer as `ConnectInfo` (IP
        // rules / rate limiting / access logs). Method / URI / headers pass through
        // untouched — no rebuild.
        let mut request = req.map(axum::body::Body::from);
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(self.peer));

        // Call the router as a tower Service (axum's Router is always ready).
        use tower_service::Service as _;
        let mut router = self.router.clone();
        let resp = match router.call(request).await {
            Ok(r) => r,
            Err(_) => return boatramp_h2::response(502, b"bad gateway".to_vec()),
        };
        bridge_response(resp)
    }
}

impl RouterHandler {
    /// Try the router-bypass fast-path. `Ok(response)` when the request is an
    /// unambiguous pure gateway proxy (dispatched directly); `Err(req)` hands the
    /// request back for the full router path. Only static (non-compute) upstreams
    /// are dispatched here — a compute-backed upstream needs live replica-pool
    /// resolution the router owns, so it falls back.
    async fn try_gateway_bypass(&self, req: MuxRequest) -> Result<MuxResponse, MuxRequest> {
        if !bypass_enabled() {
            return Err(req);
        }
        // Request-derived routing inputs. The mux path is always TLS, so the scheme
        // is `"https"`; the h2 authority is carried in the `host` header (mapped from
        // `:authority` by the driver), and the URI is origin-form (`:path`).
        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(crate::splice::strip_port)
            .unwrap_or("")
            .to_string();
        let path = req.uri().path().to_string();
        let target_path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| path.clone());
        let method = req.method().as_str();

        let Some(m) =
            crate::splice::classify_gateway(method, "https", &host, &path, &target_path, &self.ctx)
                .await
        else {
            return Err(req);
        };
        // Compute-backed upstreams resolve their pool from live replica endpoints
        // (wake-from-zero, region tags) — that is the router's job; fall back.
        if m.upstream.compute.is_some() {
            return Err(req);
        }

        // Consume the request into an axum request, carrying the peer + the resolved
        // security posture `dispatch_gateway` reads for the SSRF address gate (the
        // router injects both via layers; the bypass injects them by hand).
        let mut request = req.map(axum::body::Body::from);
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(self.peer));
        request.extensions_mut().insert(self.ctx.posture);

        let resp = crate::dispatch_gateway(
            request,
            &m.site,
            &m.upstream_name,
            &m.upstream,
            &path,
            self.peer.ip(),
            None,
            None,
        )
        .await;
        Ok(bridge_response(resp))
    }
}

/// Convert an axum [`Response`](axum::response::Response) into a mux [`MuxResponse`]:
/// strip HTTP/2-illegal hop-by-hop headers and stream the body into the driver over
/// a bounded channel (no buffering, no copy; the channel closing signals END_STREAM,
/// its capacity backpressures the upstream pull). Shared by the router path and the
/// gateway-bypass fast-path so both frame responses identically.
fn bridge_response(resp: axum::response::Response) -> MuxResponse {
    let (mut parts, mut body) = resp.into_parts();
    for name in HOP_BY_HOP {
        parts.headers.remove(name);
    }
    parts.headers.remove("keep-alive");
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    tokio::spawn(async move {
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else { break };
            if let Ok(data) = frame.into_data() {
                if !data.is_empty() && tx.send(data).await.is_err() {
                    break; // the h2 stream was reset — stop pulling
                }
            }
        }
    });
    http::Response::from_parts(parts, MuxBody::Stream(rx))
}

/// Build a TLS acceptor advertising ALPN `h2` (preferred) then `http/1.1`.
fn acceptor(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> std::io::Result<TlsAcceptor> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Serve HTTPS on `addr`, terminating TLS and routing by negotiated ALPN: `h2`
/// connections go to the mux driver bridged into `router`; everything else falls back
/// to hyper HTTP/1. Returns when `shutdown` resolves.
///
/// `deploy` / `posture` / `daemon` are the store, resolved security posture (SSRF
/// gate), and live daemon runtime the router-bypass fast-path classifies against —
/// exactly the inputs the h1 splice path uses, so the two paths' eligibility can
/// never drift.
#[allow(clippy::too_many_arguments)]
pub async fn serve_tls_mux<S>(
    addr: SocketAddr,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    router: Router,
    deploy: DeployStore,
    posture: SecurityPosture,
    daemon: Option<Arc<crate::DaemonRuntime>>,
    shutdown: S,
) -> std::io::Result<()>
where
    S: Future<Output = ()> + Send,
{
    let acceptor = acceptor(certs, key)?;
    let listener = TcpListener::bind(addr).await?;
    let ctx = SpliceCtx {
        deploy,
        posture,
        daemon,
    };
    tracing::info!(%addr, bypass = bypass_enabled(), "serving HTTPS via the h2-mux fast-path (h1 falls back to hyper)");
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (mut tcp, peer) = match accepted {
                    Ok(v) => v,
                    Err(err) => {
                        tracing::debug!(%err, "h2-mux serve: accept error");
                        continue;
                    }
                };
                crate::disable_nagle(&mut tcp);
                let acceptor = acceptor.clone();
                let router = router.clone();
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let tls = match acceptor.accept(tcp).await {
                        Ok(t) => t,
                        Err(err) => {
                            tracing::debug!(%peer, %err, "h2-mux: TLS handshake failed");
                            return;
                        }
                    };
                    let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                    if is_h2 {
                        let handler = RouterHandler { router, peer, ctx };
                        if let Err(err) = serve_connection_mux(tls, handler).await {
                            tracing::debug!(%peer, %err, "h2-mux connection ended");
                        }
                    } else {
                        serve_h1_fallback(tls, peer, router).await;
                    }
                });
            }
        }
    }
}

/// Serve one non-h2 (ALPN `http/1.1`) TLS connection with the router over hyper
/// HTTP/1 — the same primitive `axum::serve` uses — injecting the peer as
/// `ConnectInfo` and enabling upgrades (WebSocket routes).
async fn serve_h1_fallback<IO>(io: IO, peer: SocketAddr, router: Router)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = hyper_util::rt::TokioIo::new(io);
    let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
        req.extensions_mut().insert(axum::extract::ConnectInfo(peer));
        let mut router = router.clone();
        async move {
            use tower_service::Service as _;
            router.call(req).await
        }
    });
    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc)
        .with_upgrades()
        .await
    {
        tracing::debug!(%peer, %err, "h2-mux h1-fallback connection served with error");
    }
}
