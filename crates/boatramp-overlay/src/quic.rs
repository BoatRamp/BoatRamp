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
use boatramp_rpktls::{RpkTls, TrustSet};
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

/// A dial-only endpoint that pins the server (`policy` must [`OverlayPeerPolicy::Pin`]) but presents
/// **no client certificate** — for dialing a server-auth-only acceptor (an `AcceptAny` egress whose
/// peer identity is instead learned at the E2EE layer). This is the relay→egress hop: the relay is
/// blind and unauthenticated to the egress at the TLS layer.
pub fn client_endpoint_server_auth(policy: &OverlayPeerPolicy) -> Result<Endpoint, QuicError> {
    let (_, peer) = policy.pinned().ok_or(QuicError::NotPinned)?;
    let mut tls = boatramp_rpktls::client_config_server_auth(policy.trust_set(), peer)?;
    tls.alpn_protocols = vec![wire::ALPN.to_vec()];
    let qcc = QuicClientConfig::try_from(tls).map_err(|_| QuicError::NoInitialCipherSuite)?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().expect("valid wildcard addr"))?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(qcc)));
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

/// Like [`server_endpoint`], but also returns the **live** [`TrustSet`] the acceptor's
/// client-cert verifier reads at handshake time — so the control plane can RETAIN a handle
/// and admit a newly-enrolled key into it at runtime (overlay enrollment). The returned set
/// and the endpoint's verifier share the same inner `Arc`, so a later [`TrustSet::insert`] is
/// honored live on the next handshake with **no** endpoint rebuild. For an `Allowlist`
/// (mutual-pin) relay the set IS the TLS-layer gate; for the permissive `AcceptAny`
/// (capability-only) relay it is the empty server-auth-only set — admitting a key records the
/// overlay's live membership in it while the capability gate stays the data-plane authorization.
pub fn server_endpoint_with_trust(
    secret: &OverlaySecret,
    policy: &OverlayPeerPolicy,
    bind: SocketAddr,
) -> Result<(Endpoint, TrustSet), QuicError> {
    let identity = Arc::new(secret.rpk_identity()?);
    let tls = RpkTls::new(identity, policy.trust_set());
    let rustls_sc = if policy.is_accept_any() {
        tls.server_auth()?
    } else {
        tls.server()?
    };
    let sc = quic_server_config(rustls_sc)?;
    // Clone shares the inner Arc<RwLock<…>> with the verifier `tls.server()`/`server_auth()`
    // just baked in, so a runtime `insert` is seen live by that acceptor.
    let trust = tls.trust().clone();
    Ok((Endpoint::server(sc, bind)?, trust))
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

/// A **mesh** endpoint built directly from an existing [`RpkTls`] — identity plus a **live**
/// [`boatramp_rpktls::TrustSet`] — rather than an [`OverlaySecret`] + [`OverlayPeerPolicy`]. It
/// accepts mutual-authenticated peer connections (every dialing peer's key is verified against the
/// live trust set) and is the base socket for [`dial_mesh_peer`]. This is the IU-9 seam: boatramp's
/// own cluster mesh rides overlay QUIC while reusing its existing mesh identity + trust **verbatim**,
/// so a replicated join / rotation / revocation is honored live with no second identity domain.
pub fn mesh_endpoint(tls: &RpkTls, bind: SocketAddr) -> Result<Endpoint, QuicError> {
    let sc = quic_server_config(tls.server()?)?;
    Ok(Endpoint::server(sc, bind)?)
}

/// Dial mesh `peer` (a cluster `NodeId`) at `addr` over a [`mesh_endpoint`], pinning the connection
/// to that peer's trusted key(s) from the live trust set carried by `tls`. An untrusted or unknown
/// peer fails the mutual-auth handshake rather than completing an unauthenticated dial.
pub async fn dial_mesh_peer(
    endpoint: &Endpoint,
    tls: &RpkTls,
    peer: boatramp_rpktls::PeerId,
    addr: SocketAddr,
) -> Result<Connection, QuicError> {
    let cc = quic_client_config(tls.client_for(peer)?)?;
    Ok(endpoint.connect_with(cc, addr, RPK_SNI)?.await?)
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

    /// The IU-9 mesh seam: two mutually-trusting mesh identities (an `RpkTls` each over a shared
    /// trust set, exactly as `boatramp-cluster` holds them) form a mutual-authenticated overlay
    /// QUIC link via `mesh_endpoint` + `dial_mesh_peer`, and a bi-stream round-trips.
    #[tokio::test]
    async fn mesh_endpoints_round_trip_over_shared_trust() {
        use boatramp_rpktls::{RpkIdentity, RpkTls, TrustSet};
        use std::collections::BTreeMap;
        use std::sync::Arc;

        // Node 1 and node 2, both in one trust set (NodeId -> SPKI).
        let id1 = Arc::new(RpkIdentity::generate().unwrap());
        let id2 = Arc::new(RpkIdentity::generate().unwrap());
        let trust = TrustSet::from_map(BTreeMap::from([
            (1u64, id1.public_key().to_vec()),
            (2u64, id2.public_key().to_vec()),
        ]));
        let tls1 = RpkTls::new(id1, trust.clone());
        let tls2 = RpkTls::new(id2, trust);

        let server = mesh_endpoint(&tls2, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let dialer = mesh_endpoint(&tls1, "127.0.0.1:0".parse().unwrap()).unwrap();

        let srv = tokio::spawn(async move {
            let conn = accept(&server).await.unwrap().unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let got = recv.read_to_end(64).await.unwrap();
            send.write_all(&got).await.unwrap();
            send.finish().unwrap();
            conn.closed().await;
        });

        // Node 1 dials node 2 (by id) over its mesh endpoint.
        let conn = dial_mesh_peer(&dialer, &tls1, 2, server_addr)
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"mesh-ping").await.unwrap();
        send.finish().unwrap();
        let echo = recv.read_to_end(64).await.unwrap();
        assert_eq!(&echo, b"mesh-ping");
        conn.close(0u32.into(), b"done");
        let _ = srv.await;
    }

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

    /// The trust set RETAINED from [`server_endpoint_with_trust`] is LIVE: a mutual-pin relay
    /// that did not initially trust a client admits it at runtime via [`TrustSet::insert`], and a
    /// subsequent handshake as that key is then accepted with no endpoint rebuild — the overlay
    /// enrollment admit seam. The control plane holds exactly this handle.
    #[tokio::test]
    async fn retained_trust_set_admits_a_key_live() {
        let server_secret = OverlaySecret::generate().unwrap();
        let seeded = OverlaySecret::generate().unwrap().id(); // some other allowlisted peer
        let client_secret = OverlaySecret::generate().unwrap();
        let client_id = client_secret.id();
        let server_id = server_secret.id();

        // The relay trusts only `seeded` at bring-up — NOT the enrolling client.
        let (server, trust) = server_endpoint_with_trust(
            &server_secret,
            &Allowlist(BTreeSet::from([seeded])),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        assert!(
            trust.peer_for_key(&client_id.to_spki()).is_none(),
            "the client must not be trusted before enrollment"
        );

        // ADMIT the client's key into the live set (what the enroll handler does).
        trust.insert(99u64, client_id.to_spki());
        assert!(
            trust.peer_for_key(&client_id.to_spki()).is_some(),
            "the admitted key must be in the relay's live trust set"
        );

        let srv = tokio::spawn(async move {
            let conn = accept(&server).await.unwrap().unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let got = recv.read_to_end(64).await.unwrap();
            send.write_all(&got).await.unwrap();
            send.finish().unwrap();
            conn.closed().await;
        });

        // A fresh handshake as the just-admitted key is accepted (mutual auth over the live set).
        let client = client_endpoint(&client_secret, &Pin(server_id)).unwrap();
        let conn = dial(&client, server_addr).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"enrolled").await.unwrap();
        send.finish().unwrap();
        let echo = recv.read_to_end(64).await.unwrap();
        assert_eq!(&echo, b"enrolled");

        conn.close(0u32.into(), b"done");
        let _ = srv.await;
    }
}
