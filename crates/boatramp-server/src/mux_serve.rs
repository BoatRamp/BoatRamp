//! Opt-in HTTP/2 serve fast-path (feature `h2-mux`, gated at runtime by the
//! `BOATRAMP_H2_MUX` env var). Terminates TLS ourselves and serves h2 connections
//! with `boatramp-h2`'s concurrent multiplexed driver — which beats hyper (and
//! Envoy) on `tls-proxy-h2` — while h1 falls back to hyper. Each h2 request is
//! bridged into the same axum [`Router`] the normal pipeline serves, so routing /
//! gateway proxying / handlers are unchanged.
//!
//! The response body is buffered before framing (fine for bounded + proxy bodies;
//! true streaming is a follow-up). hyper remains both the h1 path and the default
//! (this loop is only entered when the operator opts in), so nothing streaming-heavy
//! regresses unless explicitly enabled.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::http;
use axum::Router;
use boatramp_h2::{serve_connection_mux, Body as MuxBody, Handler, Request as MuxRequest, Response as MuxResponse};
use bytes::Bytes;
use http_body_util::BodyExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Response headers that must not (or need not) be copied onto the h2 response: hop-by
/// hop headers are illegal in HTTP/2, and `content-length` is re-derived by the mux
/// driver from the buffered body.
fn droppable_response_header(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"connection")
        || name.eq_ignore_ascii_case(b"keep-alive")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
        || name.eq_ignore_ascii_case(b"upgrade")
        || name.eq_ignore_ascii_case(b"content-length")
}

/// Bridges the mux driver's simple request/response to the axum [`Router`] (a tower
/// `Service`). Cloned per connection; `Router` is cheap to clone.
struct RouterHandler {
    router: Router,
    peer: SocketAddr,
}

impl Handler for RouterHandler {
    async fn handle(&self, req: MuxRequest) -> MuxResponse {
        // Rebuild an http::Request the router can route: method + path + h2 headers,
        // with the :authority carried as Host (the gateway resolves upstreams by it)
        // and the peer as ConnectInfo (IP rules / rate limiting / access logs).
        let method = http::Method::from_bytes(&req.method).unwrap_or(http::Method::GET);
        let path = String::from_utf8_lossy(&req.path).into_owned();
        let mut builder = http::Request::builder()
            .method(method)
            .uri(path)
            .version(http::Version::HTTP_2);
        for (n, v) in &req.headers {
            builder = builder.header(n.as_slice(), v.as_slice());
        }
        if let Some(authority) = &req.authority {
            builder = builder.header(http::header::HOST, authority.as_slice());
        }
        let body = axum::body::Body::from(Bytes::from(req.body));
        let mut request = match builder.body(body) {
            Ok(r) => r,
            Err(_) => return MuxResponse::with_body(400, b"bad request".to_vec()),
        };
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(self.peer));

        // Call the router as a tower Service (axum's Router is always ready).
        use tower_service::Service as _;
        let mut router = self.router.clone();
        let resp = match router.call(request).await {
            Ok(r) => r,
            Err(_) => return MuxResponse::with_body(502, b"bad gateway".to_vec()),
        };
        let (parts, body) = resp.into_parts();
        // Buffer the body (streaming is a follow-up).
        let bytes = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => return MuxResponse::with_body(502, b"bad gateway".to_vec()),
        };
        let headers = parts
            .headers
            .iter()
            .filter(|(n, _)| !droppable_response_header(n.as_str().as_bytes()))
            .map(|(n, v)| (n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        MuxResponse {
            status: parts.status.as_u16(),
            headers,
            body: MuxBody::Bytes(bytes.to_vec()),
        }
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
