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

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Request, Response, header::ALT_SVC};
use bytes::Buf;
use futures::StreamExt;
use rand_chacha::ChaCha20Rng;
// `rand_chacha` re-exports `rand_core` (`pub use rand_core;`), so the CSPRNG traits come from the
// one dep — no separate `rand_core` dependency.
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tower::ServiceExt;

/// The QUIC listener handle built by [`http3_endpoint`] and driven by
/// [`serve_http3_endpoint`]. Re-exported so a caller (e.g. the serve-path tail helper
/// in the `boatramp` binary, which does not depend on `quinn` directly) can NAME the
/// type to pass it around as `Option<Http3Endpoint>`.
pub use quinn::Endpoint as Http3Endpoint;

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
    /// Seeding the routable-CID CSPRNG from OS entropy failed at endpoint construction
    /// (security-review F2). Fail closed at startup rather than ever issuing a low-entropy /
    /// all-zero-tailed CID, which would collide CIDs and corrupt Anycast routing + linkability.
    #[error("seeding the routable QUIC Connection-ID CSPRNG from OS entropy failed: {0}")]
    CidRng(String),
}

/// The `Alt-Svc` header value advertising the h3 listener on `port`. Shared by the
/// router layer ([`advertise_http3`]) and the serve hot-path bypass
/// ([`FastServe::advertise_http3`](crate::FastServe::advertise_http3)) so the two can
/// never drift on the advertised max-age.
pub(crate) fn alt_svc_value(port: u16) -> String {
    format!("h3=\":{port}\"; ma=86400")
}

/// Wrap `router` so every response carries an `Alt-Svc` header advertising the
/// HTTP/3 listener on `port`. Without it the h3 endpoint is
/// served but clients never discover it — they keep using HTTP/1.1/2 over TCP.
/// Apply only to the TLS/TCP path that has a paired h3 listener.
pub fn advertise_http3(router: Router, port: u16) -> Router {
    let value = alt_svc_value(port);
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
///
/// `anycast_node_id` wires PLAN-anycast AC-3: `Some(id)` installs a
/// [`NodeCidGenerator`] so every QUIC Connection ID this endpoint issues carries
/// `id` in its first byte, letting an Anycast-aware L4 load balancer steer each
/// connection's packets back to the node that owns it (QUIC otherwise rehashes
/// mid-connection onto another node under ECMP). `None` keeps quinn's default
/// (random) CIDs via [`quinn::Endpoint::server`] — so a non-Anycast / single node
/// serves H3 exactly as before.
pub fn http3_endpoint(
    addr: SocketAddr,
    server_config: quinn::ServerConfig,
    anycast_node_id: Option<u8>,
) -> Result<quinn::Endpoint, Http3Error> {
    let Some(node_id) = anycast_node_id else {
        // Default (non-Anycast): random CIDs, default endpoint config.
        return Ok(quinn::Endpoint::server(server_config, addr)?);
    };
    // Anycast: a per-node CID generator so the LB can steer QUIC by the node id in
    // the Connection ID. The generator lives on the `EndpointConfig`, so the cert
    // hot-swap (`set_server_config`) on renewal leaves the routable CIDs intact.
    //
    // Validate CSPRNG seeding ONCE here (startup) and surface a clean startup error: quinn's
    // cid_generator factory below returns a `Box`, not a `Result`, so it cannot itself report a
    // seeding failure. Fail closed rather than ever issue a degenerate CID (security-review F2).
    NodeCidGenerator::new(node_id)?;
    let mut endpoint_config = quinn::EndpointConfig::default();
    // quinn invokes this factory exactly once — when it builds the endpoint's single CID generator
    // (quinn-proto `Endpoint::new`), i.e. at startup, right below. Each generator re-seeds
    // independently from OS entropy, so it is collision-safe even if quinn ever called the factory
    // more than once. The `.expect` can only fire if OS entropy vanished in the microseconds since
    // the check above — a hard startup failure, which is the intended fail-closed behavior.
    endpoint_config.cid_generator(move || {
        Box::new(
            NodeCidGenerator::new(node_id)
                .expect("routable QUIC CID CSPRNG seeding (validated at startup)"),
        )
    });
    let socket = std::net::UdpSocket::bind(addr)?;
    let runtime =
        quinn::default_runtime().ok_or_else(|| std::io::Error::other("no async runtime found"))?;
    Ok(quinn::Endpoint::new(
        endpoint_config,
        Some(server_config),
        socket,
        runtime,
    )?)
}

/// The length (bytes) of a routable Connection ID issued by [`NodeCidGenerator`].
/// Matches quinn's default 8-byte CID, so Anycast steering adds no wire overhead.
pub const ANYCAST_CID_LEN: usize = 8;

/// The byte offset of the node id inside a routable Connection ID — **byte 0**.
/// This is the LB-steering contract (AC-3): an Anycast-aware L4 load balancer
/// routes a QUIC short-header packet to the node whose id equals the first byte of
/// the packet's Destination Connection ID.
pub const ANYCAST_NODE_ID_OFFSET: usize = 0;

/// A quinn [`ConnectionIdGenerator`](quinn::ConnectionIdGenerator) that encodes a
/// stable **node id** in the first byte of every Connection ID it issues, so an
/// Anycast-aware L4 load balancer can steer each QUIC connection's packets back to
/// the node that owns it (PLAN-anycast AC-3).
///
/// # Wire layout (the operator/LB contract)
///
/// Each CID is [`ANYCAST_CID_LEN`] (8) bytes:
///
/// ```text
///   byte:  0        1   2   3   4   5   6   7
///         ┌──────┬───────────────────────────┐
///         │ node │        random (7 B)        │
///         │  id  │     per-connection entropy │
///         └──────┴───────────────────────────┘
/// ```
///
/// - **Byte 0** is the node id (`0..=255`) — the steering selector. Configure the
///   L4 LB to hash/route QUIC short-header (1-RTT) packets on the **first byte of
///   the Destination Connection ID**. See [`node_id_from_cid`].
/// - **Bytes 1..8** are cryptographic-grade random, so each connection's CID is
///   unique and unpredictable (56 bits of entropy). Only the node-id byte is
///   stable across a node's connections — the intended, documented QUIC-LB
///   tradeoff that makes routable steering possible.
///
/// The handshake's *initial* packets use a client-chosen (random) Destination CID,
/// so the first packet lands on whichever node ECMP picks; that node then issues
/// its own node-id-tagged CID, and every subsequent packet is steerable back to it.
/// This is the standard draft-ietf-quic-load-balancers "routable CID" approach.
pub struct NodeCidGenerator {
    node_id: u8,
    /// A ChaCha20 CSPRNG seeded ONCE at construction (security-review F2). Every `generate_cid`
    /// fills the 7 random CID bytes from this userspace stream — no per-CID `getrandom` syscall
    /// (so it also sidesteps the privsep per-syscall seccomp concern) and never an all-zero
    /// fallback tail.
    rng: ChaCha20Rng,
}

impl NodeCidGenerator {
    /// A generator that stamps `node_id` into byte 0 of every issued CID and fills the remaining
    /// 7 bytes from a ChaCha20 CSPRNG seeded HERE from OS entropy (a single `getrandom` read, at
    /// construction — not per CID).
    ///
    /// Fails closed (`Http3Error::CidRng`) if the OS entropy source is unavailable; the caller
    /// surfaces that as a startup error ([`http3_endpoint`]). We never fall back to a low-entropy
    /// or all-zero CID tail: two connections sharing a tail would collide on the
    /// node-id-plus-tail CID, which corrupts the Anycast LB's per-connection routing and makes
    /// every connection trivially linkable.
    pub fn new(node_id: u8) -> Result<Self, Http3Error> {
        // ChaCha20's seed is 32 bytes. One OS-entropy read, at construction only.
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| Http3Error::CidRng(e.to_string()))?;
        Ok(Self {
            node_id,
            rng: ChaCha20Rng::from_seed(seed),
        })
    }
}

impl quinn::ConnectionIdGenerator for NodeCidGenerator {
    fn generate_cid(&mut self) -> quinn::ConnectionId {
        let mut bytes = [0u8; ANYCAST_CID_LEN];
        bytes[ANYCAST_NODE_ID_OFFSET] = self.node_id;
        // Pure userspace CSPRNG draw: infallible (unlike the old per-CID `getrandom`), so there is
        // no all-zero fallback path and no per-CID syscall — same cryptographic quality, faster.
        self.rng.fill_bytes(&mut bytes[1..]);
        quinn::ConnectionId::new(&bytes)
    }

    fn cid_len(&self) -> usize {
        ANYCAST_CID_LEN
    }

    fn cid_lifetime(&self) -> Option<std::time::Duration> {
        None
    }
}

/// Decode the node id an Anycast-aware LB steers on from a routable Connection ID:
/// the **first byte** ([`ANYCAST_NODE_ID_OFFSET`]). This is exactly the selector an
/// external L4 steerer reads off the wire (AC-3); exposed so the encoding has one
/// authoritative decoder (used by the round-trip test and any in-process routing).
/// `None` only for an empty CID.
#[must_use]
pub fn node_id_from_cid(cid: &[u8]) -> Option<u8> {
    cid.first().copied()
}

/// Accept HTTP/3 connections on `endpoint`, routing each through `router`, until
/// `shutdown` resolves — then drain gracefully (send peers `CONNECTION_CLOSE`
/// rather than vanishing on process exit) with a bounded `wait_idle`.
///
/// `shutdown` is the serve loop's graceful-shutdown future — the same
/// [`drain_aware_shutdown`](crate::drain_aware_shutdown) the TCP listener uses, so
/// the QUIC listener also keeps accepting through the Anycast drain delay (AC-1)
/// before it stops.
pub async fn serve_http3_endpoint<S>(
    endpoint: quinn::Endpoint,
    router: Router,
    shutdown: S,
) -> Result<(), Http3Error>
where
    S: std::future::Future<Output = ()> + Send,
{
    if let Ok(addr) = endpoint.local_addr() {
        tracing::info!(%addr, "serving HTTP/3 (QUIC)");
    }
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
    // Static-cert convenience path: no Anycast node id (default random CIDs).
    let endpoint = http3_endpoint(addr, quinn_server_config(tls)?, None)?;
    serve_http3_endpoint(endpoint, router, crate::shutdown_signal()).await
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
    use quinn::ConnectionIdGenerator as _;

    /// AC-3: the routable CID generator encodes the node id in byte 0 and keeps
    /// the rest random, and [`node_id_from_cid`] decodes it — the round trip that
    /// the LB-steering contract depends on. Security-review F2: the random tail is
    /// NEVER all-zero (the old `getrandom`-failure fallback), and successive CIDs
    /// carry distinct tails.
    #[test]
    fn node_cid_generator_encodes_and_decodes_the_node_id() {
        for node_id in [0u8, 1, 7, 42, 200, 255] {
            // Construction seeds the CSPRNG from OS entropy — fail-closed, so it is a `Result`.
            let mut cidgen = NodeCidGenerator::new(node_id).expect("CSPRNG seeds at construction");
            let cid = cidgen.generate_cid();
            assert_eq!(cid.len(), ANYCAST_CID_LEN, "fixed 8-byte CID");
            assert_eq!(cidgen.cid_len(), ANYCAST_CID_LEN);
            assert_eq!(
                node_id_from_cid(&cid),
                Some(node_id),
                "byte 0 carries the node id the LB steers on"
            );
            // F2: the 7-byte tail is never all-zero (no degenerate fallback).
            assert_ne!(
                &cid[1..],
                &[0u8; ANYCAST_CID_LEN - 1],
                "the random tail is never the all-zero fallback"
            );
            // Two CIDs from the same node share the node-id byte but differ in the
            // random tail (per-connection entropy).
            let cid2 = cidgen.generate_cid();
            assert_eq!(node_id_from_cid(&cid2), Some(node_id));
            assert_ne!(
                &cid[1..],
                &cid2[1..],
                "the 7 random bytes differ between connections"
            );
        }
    }

    /// Security-review F2: the construction path (which seeds the CSPRNG) succeeds under a working
    /// OS entropy source, and two INDEPENDENT generators for the same node id produce distinct
    /// tails — i.e. each seeds independently (no shared/fixed seed that would collide CIDs across
    /// generators). Forcing a seed FAILURE is not portably testable; it surfaces as
    /// `Http3Error::CidRng` from `new`, which `http3_endpoint` propagates as a startup error.
    #[test]
    fn node_cid_generator_construction_seeds_independently() {
        let mut a = NodeCidGenerator::new(9).expect("gen A seeds");
        let mut b = NodeCidGenerator::new(9).expect("gen B seeds");
        let ca = a.generate_cid();
        let cb = b.generate_cid();
        assert_eq!(node_id_from_cid(&ca), Some(9));
        assert_eq!(node_id_from_cid(&cb), Some(9));
        assert_ne!(
            &ca[1..],
            &cb[1..],
            "two independently-seeded generators do not share a CID tail"
        );
    }

    /// Build a throwaway self-signed `h3` quinn server config for the bind tests.
    #[cfg(test)]
    fn test_quic_config() -> quinn::ServerConfig {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        quinn_server_config(tls).unwrap()
    }

    /// A non-Anycast node (`None`) still binds and serves H3 — the default path is
    /// unchanged — and an Anycast node (`Some`) binds too (routable CIDs on).
    #[tokio::test]
    async fn http3_endpoint_binds_with_and_without_an_anycast_node_id() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let plain = http3_endpoint(addr, test_quic_config(), None).expect("non-Anycast H3 binds");
        assert!(
            plain.local_addr().is_ok(),
            "default (random-CID) endpoint is live"
        );

        let anycast = http3_endpoint(addr, test_quic_config(), Some(5)).expect("Anycast H3 binds");
        assert!(
            anycast.local_addr().is_ok(),
            "routable-CID endpoint is live too"
        );
    }

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
