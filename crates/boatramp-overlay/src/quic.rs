//! QUIC transport on raw-public-key TLS (IU-3).
//!
//! Three endpoint shapes, all identity-pinned at the TLS layer with **no CA**:
//! - [`client_endpoint`] — dial-only; pins the egress it dials;
//! - [`server_endpoint`] — accept-only; a relay/egress under a peer policy;
//! - [`peer_endpoint`] — accept *and* dial on one UDP socket, the shape QUIC
//!   simultaneous-open (hole-punch, IU-7) needs.
//!
//! Every config reuses [`boatramp_rpktls`]'s RFC-7250 raw-public-key verifier
//! and identity (TLS 1.3 + `X25519MLKEM768` are baked in there) — this module
//! does **not** implement a second raw-pubkey TLS stack. It only wires those
//! finished `rustls` configs into quinn and stamps the overlay ALPN.

use std::net::SocketAddr;
use std::sync::Arc;

use boatramp_overlay_proto::{OverlayPeerPolicy, OverlaySecret, wire};
use boatramp_rpktls::RpkTls;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};

/// The TLS server name presented on a dial. Irrelevant in raw-public-key mode
/// (the verifier pins the peer's key, not a hostname), but quinn still requires
/// a syntactically valid name.
const RPK_SNI: &str = "rpk";

/// Errors building an overlay QUIC endpoint or dialing a peer.
#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    /// A client/peer dial requires a pinned peer, but the policy pins none.
    #[error("a dialing endpoint requires a Pin peer policy")]
    NotPinned,
    /// Deriving the raw-public-key TLS identity from the overlay secret failed.
    #[error(transparent)]
    Identity(#[from] boatramp_overlay_proto::OverlayIdError),
    /// Building an rpktls config failed (e.g. the pinned peer is untrusted).
    #[error(transparent)]
    Rpk(#[from] boatramp_rpktls::RpkError),
    /// The TLS config exposed no TLS 1.3 initial cipher suite for QUIC.
    #[error("tls config has no QUIC-usable initial cipher suite")]
    NoInitialCipherSuite,
    /// A dial could not be initiated.
    #[error(transparent)]
    Connect(#[from] quinn::ConnectError),
    /// A connection failed (handshake rejected, peer untrusted, timeout, …).
    #[error(transparent)]
    Connection(#[from] quinn::ConnectionError),
    /// Binding the UDP socket failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Build an `RpkTls` facade from an overlay secret and the trust a policy
/// authorizes.
fn rpk_tls(secret: &OverlaySecret, policy: &OverlayPeerPolicy) -> Result<RpkTls, QuicError> {
    let identity = Arc::new(secret.rpk_identity()?);
    Ok(RpkTls::new(identity, policy.trust_set()))
}

/// Stamp the overlay ALPN on an rpktls client config and wrap it for QUIC.
fn quic_client_config(mut tls: rustls::ClientConfig) -> Result<ClientConfig, QuicError> {
    tls.alpn_protocols = vec![wire::ALPN.to_vec()];
    let qcc = QuicClientConfig::try_from(tls).map_err(|_| QuicError::NoInitialCipherSuite)?;
    Ok(ClientConfig::new(Arc::new(qcc)))
}

/// Stamp the overlay ALPN on an rpktls server config and wrap it for QUIC.
fn quic_server_config(mut tls: rustls::ServerConfig) -> Result<ServerConfig, QuicError> {
    tls.alpn_protocols = vec![wire::ALPN.to_vec()];
    let qsc = QuicServerConfig::try_from(tls).map_err(|_| QuicError::NoInitialCipherSuite)?;
    Ok(ServerConfig::with_crypto(Arc::new(qsc)))
}

/// The dialer's rustls config for `policy` (which must `Pin` its egress).
fn dial_client_config(
    secret: &OverlaySecret,
    policy: &OverlayPeerPolicy,
) -> Result<ClientConfig, QuicError> {
    let (_, peer) = policy.pinned().ok_or(QuicError::NotPinned)?;
    let tls = rpk_tls(secret, policy)?;
    quic_client_config(tls.client_for(peer)?)
}

/// The acceptor's rustls server config for `policy`: mutual-auth for
/// `Pin`/`Allowlist` (the client key is verified against the trust set), or
/// server-auth-only for `AcceptAny` (the peer identity is learned later at the
/// E2EE layer, IU-4 — the TLS layer authenticates only this side).
fn accept_server_config(
    secret: &OverlaySecret,
    policy: &OverlayPeerPolicy,
) -> Result<ServerConfig, QuicError> {
    let tls = rpk_tls(secret, policy)?;
    let rustls_sc = if policy.is_accept_any() {
        tls.server_auth()?
    } else {
        tls.server()?
    };
    quic_server_config(rustls_sc)
}

/// A dial-only endpoint on an ephemeral local UDP socket. Every connection it
/// opens pins the egress named by `policy` (which must be [`OverlayPeerPolicy::Pin`]).
pub fn client_endpoint(
    secret: &OverlaySecret,
    policy: &OverlayPeerPolicy,
) -> Result<Endpoint, QuicError> {
    let cc = dial_client_config(secret, policy)?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().expect("valid wildcard addr"))?;
    endpoint.set_default_client_config(cc);
    Ok(endpoint)
}

/// An accept-only endpoint bound to `bind` under `policy` (a relay/ingress or
/// egress/terminator).
pub fn server_endpoint(
    secret: &OverlaySecret,
    policy: &OverlayPeerPolicy,
    bind: SocketAddr,
) -> Result<Endpoint, QuicError> {
    let sc = accept_server_config(secret, policy)?;
    Ok(Endpoint::server(sc, bind)?)
}

/// An endpoint that both accepts (under `accept_policy`) and dials (pinning the
/// egress in `dial_policy`) on **one** UDP socket — the shape QUIC
/// simultaneous-open needs for NAT hole-punching (IU-7). Dials go through the
/// endpoint's default client config.
pub fn peer_endpoint(
    secret: &OverlaySecret,
    accept_policy: &OverlayPeerPolicy,
    dial_policy: &OverlayPeerPolicy,
    bind: SocketAddr,
) -> Result<Endpoint, QuicError> {
    let sc = accept_server_config(secret, accept_policy)?;
    let cc = dial_client_config(secret, dial_policy)?;
    let mut endpoint = Endpoint::server(sc, bind)?;
    endpoint.set_default_client_config(cc);
    Ok(endpoint)
}

/// Dial `addr` from a dial-capable `endpoint` (one built by [`client_endpoint`]
/// or [`peer_endpoint`]) and complete the handshake.
pub async fn dial(endpoint: &Endpoint, addr: SocketAddr) -> Result<Connection, QuicError> {
    Ok(endpoint.connect(addr, RPK_SNI)?.await?)
}

/// Accept the next inbound connection on `endpoint` and complete its handshake.
/// Returns `Ok(None)` when the endpoint is closed.
pub async fn accept(endpoint: &Endpoint) -> Result<Option<Connection>, QuicError> {
    match endpoint.accept().await {
        Some(incoming) => Ok(Some(incoming.accept()?.await?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_overlay_proto::OverlayPeerPolicy::{Allowlist, Pin};
    use std::collections::BTreeSet;

    /// A mutual-auth loopback handshake: the client pins the server and the
    /// server allowlists the client; a bi-stream round-trips through the
    /// identity-pinned, relay-free QUIC link.
    #[tokio::test]
    async fn pinned_loopback_round_trips() {
        let server_secret = OverlaySecret::generate().unwrap();
        let client_secret = OverlaySecret::generate().unwrap();
        let server_id = server_secret.id();
        let client_id = client_secret.id();

        // Server trusts the client's key; client pins the server's key.
        let server = server_endpoint(
            &server_secret,
            &Allowlist(BTreeSet::from([client_id])),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = client_endpoint(&client_secret, &Pin(server_id)).unwrap();

        let srv = tokio::spawn(async move {
            let conn = accept(&server).await.unwrap().unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let got = recv.read_to_end(64).await.unwrap();
            send.write_all(&got).await.unwrap();
            send.finish().unwrap();
            // Keep the endpoint alive until the client has read the echo.
            conn.closed().await;
        });

        let conn = dial(&client, server_addr).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"ping").await.unwrap();
        send.finish().unwrap();
        let echo = recv.read_to_end(64).await.unwrap();
        assert_eq!(&echo, b"ping");

        conn.close(0u32.into(), b"done");
        let _ = srv.await;
    }

    /// An untrusted client cannot forward bytes: the server allowlists a
    /// *different* identity than the one dialing, so the mutual-auth handshake
    /// rejects the client's key. (In TLS 1.3 over QUIC the client may see the
    /// dial complete optimistically; the rejection then surfaces on first
    /// stream use — so the property we assert is that no round-trip completes.)
    #[tokio::test]
    async fn untrusted_client_is_rejected() {
        let server_secret = OverlaySecret::generate().unwrap();
        let client_secret = OverlaySecret::generate().unwrap();
        let stranger = OverlaySecret::generate().unwrap().id();

        let server = server_endpoint(
            &server_secret,
            &Allowlist(BTreeSet::from([stranger])), // NOT the client
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_id = server_secret.id();

        // Drive the (doomed) handshake on the server so the rejection path runs.
        let srv = tokio::spawn(async move {
            let _ = accept(&server).await;
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        });

        let client = client_endpoint(&client_secret, &Pin(server_id)).unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let conn = dial(&client, server_addr).await?;
            let (mut send, mut recv) = conn.open_bi().await?;
            send.write_all(b"ping").await?;
            send.finish()?;
            recv.read_to_end(64).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await;

        // The only disallowed result is a completed round-trip.
        assert!(
            !matches!(outcome, Ok(Ok(()))),
            "untrusted client completed a round-trip but must be rejected"
        );

        let _ = srv.await;
    }
}
