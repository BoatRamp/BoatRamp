//! HTTP/3 (QUIC) serving.
//!
//! A third listener transport in front of the **same** axum [`Router`]: a quinn
//! QUIC endpoint terminates TLS 1.3 (ALPN `h3`) and the `h3` layer turns each
//! request stream into an `http::Request`, runs it through the router as a
//! `tower::Service`, and streams the response back. The serving logic is shared
//! with the TCP path, so the whole pipeline is already covered by the
//! conformance suite; only the QUIC handshake itself is exercised in live testing.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header::ALT_SVC, HeaderValue, Request, Response};
use axum::Router;
use bytes::Buf;
use futures::StreamExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tower::ServiceExt;

/// A failure serving HTTP/3 (QUIC).
#[derive(Debug, thiserror::Error)]
pub enum Http3Error {
    /// The rustls config has no QUIC-compatible initial cipher suite.
    #[error("QUIC TLS config: {0}")]
    QuicTls(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
    /// A TLS configuration error.
    #[error("TLS config: {0}")]
    Rustls(#[from] rustls::Error),
    /// Binding the QUIC endpoint failed.
    #[error("QUIC endpoint I/O: {0}")]
    Io(#[from] std::io::Error),
    /// A QUIC connection error.
    #[error("QUIC connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// An HTTP/3 connection error.
    #[error("HTTP/3 protocol: {0}")]
    H3(#[from] h3::error::ConnectionError),
}

/// Wrap `router` so every response carries an `Alt-Svc` header advertising the
/// HTTP/3 listener on `port`. Without it the h3 endpoint is
/// served but clients never discover it — they keep using HTTP/1.1/2 over TCP.
/// Apply only to the TLS/TCP path that has a paired h3 listener.
pub fn advertise_http3(router: Router, port: u16) -> Router {
    let value = format!("h3=\":{port}\"; ma=86400");
    router.layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let value = value.clone();
            async move {
                let mut resp = next.run(req).await;
                if let Ok(v) = HeaderValue::from_str(&value) {
                    resp.headers_mut().insert(ALT_SVC, v);
                }
                resp
            }
        },
    ))
}

/// Convert a rustls [`ServerConfig`](rustls::ServerConfig) (whose ALPN must
/// already include `h3`) into a quinn server config for the QUIC listener. The
/// config may carry a dynamic [`ResolvesServerCert`](rustls::server::ResolvesServerCert)
/// — that's how the ACME path serves rotating certs over h3.
pub fn quinn_server_config(
    rustls_config: rustls::ServerConfig,
) -> Result<quinn::ServerConfig, Http3Error> {
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic)))
}

/// Bind a QUIC [`Endpoint`](quinn::Endpoint) for HTTP/3 on `addr`. The caller can
/// later hot-swap the cert via [`quinn::Endpoint::set_server_config`] (on ACME
/// renewal) and serve it with [`serve_http3_endpoint`].
pub fn http3_endpoint(
    addr: SocketAddr,
    server_config: quinn::ServerConfig,
) -> Result<quinn::Endpoint, Http3Error> {
    Ok(quinn::Endpoint::server(server_config, addr)?)
}

/// Accept HTTP/3 connections on `endpoint`, routing each through `router`, until
/// a shutdown signal — then drain gracefully (send peers `CONNECTION_CLOSE`
/// rather than vanishing on process exit) with a bounded `wait_idle`.
pub async fn serve_http3_endpoint(
    endpoint: quinn::Endpoint,
    router: Router,
) -> Result<(), Http3Error> {
    if let Ok(addr) = endpoint.local_addr() {
        tracing::info!(%addr, "serving HTTP/3 (QUIC)");
    }
    let shutdown = crate::shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let router = router.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(incoming, router).await {
                        tracing::debug!(error = %err, "http/3 connection ended");
                    }
                });
            }
            _ = &mut shutdown => {
                tracing::info!("HTTP/3 listener draining");
                break;
            }
        }
    }
    endpoint.close(0u32.into(), b"shutdown");
    // Bounded so a stuck peer can't wedge shutdown.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), endpoint.wait_idle()).await;
    Ok(())
}

/// Serve `router` over HTTP/3 on `addr` (UDP) with a **static** `cert_chain`/`key`
/// (the `--tls custom` path). Shares the port with the TCP HTTPS listener (TCP
/// and UDP are distinct). For dynamic ACME certs use [`http3_endpoint`] +
/// [`serve_http3_endpoint`] so the cert can be swapped on renewal.
pub async fn serve_http3(
    addr: SocketAddr,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    router: Router,
) -> Result<(), Http3Error> {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    // QUIC mandates exactly the `h3` ALPN on this listener.
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let endpoint = http3_endpoint(addr, quinn_server_config(tls)?)?;
    serve_http3_endpoint(endpoint, router).await
}

async fn handle_connection(incoming: quinn::Incoming, router: Router) -> Result<(), Http3Error> {
    let conn = incoming.await?;
    let peer = conn.remote_address();
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                // h3 0.0.8: accept() yields a resolver; resolving it decodes the
                // request head and hands back the bidirectional stream.
                let (req, mut stream) = match resolver.resolve_request().await {
                    Ok(parts) => parts,
                    Err(err) => {
                        tracing::debug!(error = %err, "http/3 request resolve failed");
                        continue;
                    }
                };
                let router = router.clone();
                tokio::spawn(async move {
                    // Reassemble the request body from the QUIC stream.
                    let mut body = Vec::new();
                    loop {
                        match stream.recv_data().await {
                            Ok(Some(mut chunk)) => {
                                let bytes = chunk.copy_to_bytes(chunk.remaining());
                                body.extend_from_slice(&bytes);
                            }
                            Ok(None) => break,
                            Err(err) => {
                                tracing::debug!(error = %err, "http/3 body read failed");
                                return;
                            }
                        }
                    }

                    // Run the same pipeline as the TCP path, with the peer addr
                    // so access control / IP rules / logs see the real client.
                    let (parts, _) = req.into_parts();
                    let mut request = Request::from_parts(parts, Body::from(body));
                    request.extensions_mut().insert(ConnectInfo(peer));
                    let response = match router.clone().oneshot(request).await {
                        Ok(response) => response,
                        Err(err) => {
                            tracing::debug!(error = %err, "http/3 routing failed");
                            return;
                        }
                    };

                    let (parts, body) = response.into_parts();
                    if let Err(err) = stream.send_response(Response::from_parts(parts, ())).await {
                        tracing::debug!(error = %err, "http/3 send_response failed");
                        return;
                    }
                    let mut data = body.into_data_stream();
                    while let Some(chunk) = data.next().await {
                        match chunk {
                            Ok(bytes) => {
                                if let Err(err) = stream.send_data(bytes).await {
                                    tracing::debug!(error = %err, "http/3 send_data failed");
                                    return;
                                }
                            }
                            Err(err) => {
                                tracing::debug!(error = %err, "http/3 body stream error");
                                return;
                            }
                        }
                    }
                    let _ = stream.finish().await;
                });
            }
            Ok(None) => return Ok(()),
            Err(err) => return Err(err.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;

    #[tokio::test]
    async fn advertise_http3_sets_alt_svc() {
        let app = advertise_http3(Router::new().route("/", get(|| async { "ok" })), 8443);
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let alt = resp
            .headers()
            .get(ALT_SVC)
            .expect("Alt-Svc present")
            .to_str()
            .unwrap();
        assert!(
            alt.contains("h3=\":8443\""),
            "advertises h3 on the port: {alt}"
        );
    }
}
