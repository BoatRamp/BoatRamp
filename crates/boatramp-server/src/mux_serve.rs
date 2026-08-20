//! Opt-in HTTP/2 serve fast-path (feature `h2-mux`, gated at runtime by the
//! `BOATRAMP_H2_MUX` env var). Terminates TLS ourselves and serves h2 connections
//! with `boatramp-h2`'s concurrent multiplexed driver — which beats hyper (and
//! Envoy) on `tls-proxy-h2` — while h1 falls back to hyper. Each h2 request is
//! bridged into the same axum [`Router`] the normal pipeline serves, so routing /
//! gateway proxying / handlers are unchanged.
//!
//! The router's response body is handed to the driver as a **pull `Stream` polled
//! directly** in the driver's per-stream task — no intermediate channel and no
//! per-response producer task. Measured on lighthouse (100 KiB TLS h2 proxy), that
//! direct path lifts the integrated mux +9–16 % over a channel-pumped bridge and
//! brings it to parity-or-better with hyper at every concurrency, while streaming
//! (bounded memory + TTFB) and covering unbounded bodies. hyper remains both the h1
//! path and the default (this loop is only entered when the operator opts in).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::http;
use axum::Router;
use boatramp_h2::{
    serve_connection_mux, Body as MuxBody, BodyError as MuxBodyError, Handler,
    Request as MuxRequest, Response as MuxResponse,
};
use futures::StreamExt as _;
use http_body_util::BodyStream;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Hop-by-hop response headers, illegal in HTTP/2, stripped before framing.
/// `content-length` is deliberately kept — the body is streamed, so a fixed-length
/// upstream response passes its `content-length` straight through.
const HOP_BY_HOP: &[http::HeaderName] = &[
    http::header::CONNECTION,
    http::header::TRANSFER_ENCODING,
    http::header::UPGRADE,
];

/// Bridges the mux driver to the axum [`Router`] (a tower `Service`). The driver
/// produces native `http::Request`/`Response`, so the bridge just swaps body types
/// and reuses the parts — no per-request header re-marshaling. Cloned per connection.
struct RouterHandler {
    router: Router,
    peer: SocketAddr,
}

impl Handler for RouterHandler {
    async fn handle(&self, req: MuxRequest) -> MuxResponse {
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
        let (mut parts, body) = resp.into_parts();
        for name in HOP_BY_HOP {
            parts.headers.remove(name);
        }
        parts.headers.remove("keep-alive");
        // Hand the router's body to the driver as a pull `Stream` it polls itself —
        // no producer task, no channel, no buffering (so unbounded bodies stream too).
        // Data frames pass through; a body error (an upstream that dropped mid-stream)
        // becomes a `BodyError` so the driver RST_STREAMs the client instead of framing
        // a truncated body as complete; trailer/empty frames are dropped.
        let chunks = BodyStream::new(body).filter_map(|frame| {
            std::future::ready(match frame {
                Ok(f) => f
                    .into_data()
                    .ok()
                    .filter(|b| !b.is_empty())
                    .map(Ok),
                Err(_) => Some(Err(MuxBodyError)),
            })
        });
        http::Response::from_parts(parts, MuxBody::try_stream(chunks))
    }
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
pub async fn serve_tls_mux<S>(
    addr: SocketAddr,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    router: Router,
    shutdown: S,
) -> std::io::Result<()>
where
    S: Future<Output = ()> + Send,
{
    let acceptor = acceptor(certs, key)?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "serving HTTPS via the h2-mux fast-path (h1 falls back to hyper)");
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
                        let handler = RouterHandler { router, peer };
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
