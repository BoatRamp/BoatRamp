//! Node roles (IU-8): the relay-path composition of dial + E2EE + transport.
//!
//! Three roles make up a forwarded flow:
//! - **client-edge** ([`forward_flow`]) — dials the relay, presents the dial capability, establishes
//!   the end-to-end E2EE session with the egress, and splices the local connection over it;
//! - **relay/ingress** ([`forward_relay`]) — capability-gates the dial against the trust root and the
//!   dialing peer's TLS-proven identity, then forwards the (sealed) stream to the egress **blind**;
//! - **egress/terminator** ([`terminate_one`]) — completes the E2EE handshake (learning the client
//!   identity), then bridges the session to the backend service.
//!
//! This first vertical splices E2EE records straight over the QUIC bi-stream. The resumable circuit
//! pump (IU-5) is wired into the data path with direct-path promotion (IU-7), where its rebind is
//! what makes promotion lossless. A future `forward_flow_fd` C-ABI seam (adopting an OS socket fd)
//! for a native OS client library can wrap [`forward_flow`]; the `boatramp forward` CLI (IU-10)
//! calls [`forward_flow`] directly with the accepted connection.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use std::sync::Arc;
use std::time::Duration;

use boatramp_core::cose::TokenPublicKey;
use boatramp_overlay_proto::circuit::{DEFAULT_SEGMENT, DEFAULT_WINDOW};
use boatramp_overlay_proto::dial::{DialRequest, DialVerdict, authorize_dial};
use boatramp_overlay_proto::e2ee::{Opener, Role, Sealer};
use boatramp_overlay_proto::ice::Signal;
use boatramp_overlay_proto::identity::{OverlayId, OverlaySecret};
use boatramp_overlay_proto::peer_policy::OverlayPeerPolicy;
use boatramp_overlay_proto::wire;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio::time::timeout;

use crate::circuit::{CircuitError, LinkHalves, run_circuit_duplex};
use crate::direct::{PathMode, negotiate_direct};
use crate::e2ee::{SpliceError, establish, read_lp, splice, write_lp};
use crate::ice::gather;
use crate::quic::{self, QuicError};

/// Buffer for the in-memory pipe that connects the E2EE splice to the circuit pump (the pump
/// carries the splice's sealed-record byte stream over the link).
const SEALED_PIPE_BUF: usize = 256 * 1024;

/// How long the promotion attempt (candidate exchange + hole-punch) may take before the flow stays
/// on the relay.
const PROMOTE_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on a dial request/verdict JSON message.
const MAX_DIAL_MSG: usize = 16 * 1024;

/// A forwarded-flow failure.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error(transparent)]
    Quic(#[from] QuicError),
    #[error(transparent)]
    Connection(#[from] quinn::ConnectionError),
    #[error("open/accept stream: {0}")]
    Stream(String),
    #[error("transport io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Splice(#[from] SpliceError),
    #[error(transparent)]
    Circuit(#[from] CircuitError),
    #[error("a direct path was required (DirectOnly) but could not be established")]
    DirectUnavailable,
    #[error("dial wire: {0}")]
    Json(#[from] serde_json::Error),
    #[error("dial message too large: {0} bytes")]
    TooLarge(usize),
    #[error("dial refused: {0:?}")]
    DialRejected(boatramp_overlay_proto::dial::DialReject),
    #[error("no raw-public-key peer identity on the connection")]
    NoPeerIdentity,
    #[error("peer identity: {0}")]
    Identity(#[from] boatramp_overlay_proto::OverlayIdError),
    #[error("service `{0}` does not resolve to an egress")]
    UnresolvedService(String),
}

/// Current unix time (seconds).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn write_msg<T: Serialize>(w: &mut (impl AsyncWrite + Unpin), v: &T) -> Result<(), NetError> {
    let bytes = serde_json::to_vec(v)?;
    w.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

async fn read_msg<T: DeserializeOwned>(r: &mut (impl AsyncRead + Unpin)) -> Result<T, NetError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_DIAL_MSG {
        return Err(NetError::TooLarge(n));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

/// The raw-public-key identity the peer presented at the TLS layer (its SPKI = the overlay id).
fn peer_identity(conn: &Connection) -> Result<OverlayId, NetError> {
    let any = conn.peer_identity().ok_or(NetError::NoPeerIdentity)?;
    let certs = any
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| NetError::NoPeerIdentity)?;
    let first = certs.first().ok_or(NetError::NoPeerIdentity)?;
    Ok(OverlayId::from_spki(first.as_ref())?)
}

/// Client-edge: forward `local` over the overlay. Dials the relay (`relay` must be a
/// [`crate::quic::client_endpoint`] pinning the relay), presents `request`, and on acceptance
/// establishes the end-to-end E2EE session with `egress_id` and splices `local` over it.
pub async fn forward_flow<L>(
    local: L,
    relay: &Endpoint,
    relay_addr: SocketAddr,
    secret: &OverlaySecret,
    egress_id: OverlayId,
    request: DialRequest,
    path_mode: PathMode,
) -> Result<(), NetError>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    let conn = quic::dial(relay, relay_addr).await?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| NetError::Stream(e.to_string()))?;

    write_msg(&mut send, &request).await?;
    match read_msg::<DialVerdict>(&mut recv).await? {
        DialVerdict::Accept { .. } => {}
        DialVerdict::Reject(reason) => return Err(NetError::DialRejected(reason)),
    }

    // End-to-end E2EE with the egress (the relay forwards the sealed stream blind).
    let (session, _egress) = establish(
        &mut send,
        &mut recv,
        secret,
        Role::Initiator,
        Some(egress_id),
        None,
    )
    .await?;
    // Zero-trust egress: present the dial capability END-TO-END, sealed inside the E2EE channel, so
    // the egress authorizes against its own trust root and the cryptographically-proven client
    // identity — the relay's gate is only a best-effort DoS filter, never the authz boundary.
    let (mut sealer, opener) = session.split();
    let control = serde_json::to_vec(&request)?;
    write_lp(
        &mut send,
        &sealer
            .seal(&control)
            .map_err(|e| NetError::Splice(e.into()))?,
    )
    .await?;

    let (lr, lw) = tokio::io::split(local);
    let owned = OverlaySecret::from_seed_hex(&secret.seed_hex())?;
    run_spliced_circuit_promotable(
        sealer,
        opener,
        lr,
        lw,
        recv,
        send,
        owned,
        egress_id,
        Role::Initiator,
        path_mode,
        relay_addr,
    )
    .await
}

/// The wildcard bind of the same address family as `toward`.
fn wildcard_for(toward: SocketAddr) -> SocketAddr {
    if toward.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    }
}

/// Receive the peer's candidate set from the signaling channel within `deadline`.
async fn recv_candidates(
    signaling: &mut mpsc::Receiver<Vec<u8>>,
    deadline: Duration,
) -> Option<boatramp_overlay_proto::ice::CandidateSet> {
    let msg = timeout(deadline, signaling.recv()).await.ok()??;
    match Signal::decode(&msg).ok()? {
        // Sanitize the peer-supplied set at this untrusted boundary (LOW-1): cap the count and drop
        // undialable addresses before it can steer the hole-punch.
        Signal::Candidates(set) => Some(set.sanitized()),
        Signal::Observed(_) => None,
    }
}

/// Promotion task (IU-7): gather candidates, exchange them over the sealed signaling channel,
/// hole-punch a direct link pinned to `peer_id`, prime it with the promote marker, and rebind the
/// circuit pump onto it. Holds the direct connection as the drain handle until the flow ends. A
/// no-op under `Relay`; fails closed under `DirectOnly`; falls back to the relay under `PreferDirect`.
#[allow(clippy::too_many_arguments)]
async fn promote(
    secret: OverlaySecret,
    peer_id: OverlayId,
    role: Role,
    path_mode: PathMode,
    toward: SocketAddr,
    sig_out: mpsc::Sender<Vec<u8>>,
    mut sig_in: mpsc::Receiver<Vec<u8>>,
    rebind: mpsc::Sender<LinkHalves>,
    direct_slot: Arc<Mutex<Option<Connection>>>,
) -> Result<(), NetError> {
    if !path_mode.attempts_direct() {
        return Ok(()); // Relay: never leave the relay
    }
    let fallback = |mode: PathMode| {
        if mode == PathMode::DirectOnly {
            Err(NetError::DirectUnavailable)
        } else {
            Ok(())
        }
    };

    // A peer_endpoint mutually pinned to the peer, for the hole-punch.
    let pin = OverlayPeerPolicy::Pin(peer_id);
    let endpoint = quic::peer_endpoint(&secret, &pin, &pin, wildcard_for(toward))?;
    let local_port = endpoint.local_addr()?.port();

    // Exchange candidates over the sealed signaling channel.
    let local = gather(local_port, toward, None, None)?;
    let encoded = Signal::Candidates(local)
        .encode()
        .map_err(|e| NetError::Stream(e.to_string()))?;
    let _ = sig_out.send(encoded).await;
    let Some(peer_candidates) = recv_candidates(&mut sig_in, PROMOTE_TIMEOUT).await else {
        return fallback(path_mode);
    };

    // Hole-punch an authenticated direct link.
    let Some(conn) = negotiate_direct(&endpoint, &peer_candidates, role, PROMOTE_TIMEOUT).await
    else {
        return fallback(path_mode);
    };

    // Open/accept the promotion bi-stream, priming it with the marker (deadlock MUST #1: quinn
    // surfaces an opened bi-stream to the peer only on first write).
    let halves = match role {
        Role::Initiator => {
            let (mut s, r) = conn
                .open_bi()
                .await
                .map_err(|e| NetError::Stream(e.to_string()))?;
            s.write_all(wire::PROMOTE_MARKER)
                .await
                .map_err(|e| NetError::Stream(e.to_string()))?;
            LinkHalves::new(r, s)
        }
        Role::Responder => {
            let (s, mut r) = conn
                .accept_bi()
                .await
                .map_err(|e| NetError::Stream(e.to_string()))?;
            let mut marker = vec![0u8; wire::PROMOTE_MARKER.len()];
            if r.read_exact(&mut marker).await.is_err() || marker != wire::PROMOTE_MARKER {
                return fallback(path_mode);
            }
            LinkHalves::new(r, s)
        }
    };

    // Rebind the pump onto the direct link (lossless swap; the relay link is then abandoned).
    if rebind.send(halves).await.is_err() {
        return Ok(()); // the pump has already finished — flow ending
    }
    // Keep the direct connection alive for the flow's duration (deadlock MUST #2). The runner holds
    // this slot through the splice + pump and closes it once they finish — so the pump's bi-stream
    // stays valid and the final Fin flushes, without lingering on quinn's ~30s idle timeout.
    *direct_slot.lock().await = Some(conn);
    Ok(())
}

/// Run the E2EE splice over the resumable circuit pump (which carries the sealed records over the
/// link), with a concurrent promotion task (IU-7) that may hole-punch a direct link and rebind the
/// pump onto it. The pump is **inline** so the rebind is lossless. Three tasks joined: splice, pump,
/// and promotion — `try_join!` so a `DirectOnly` promotion failure tears the flow down.
#[allow(clippy::too_many_arguments)]
async fn run_spliced_circuit_promotable<AR, AW>(
    sealer: Sealer,
    opener: Opener,
    app_r: AR,
    app_w: AW,
    link_recv: RecvStream,
    link_send: SendStream,
    secret: OverlaySecret,
    peer_id: OverlayId,
    role: Role,
    path_mode: PathMode,
    toward: SocketAddr,
) -> Result<(), NetError>
where
    AR: AsyncRead + Unpin,
    AW: AsyncWrite + Unpin,
{
    let (splice_side, pump_side) = tokio::io::duplex(SEALED_PIPE_BUF);
    let (ss_r, ss_w) = tokio::io::split(splice_side);
    let (ps_r, ps_w) = tokio::io::split(pump_side);
    let (rebind_tx, rebind_rx) = mpsc::channel::<LinkHalves>(1);
    // Real signaling: the splice <-> the promotion task carry the ICE exchange.
    let (sig_out_tx, sig_out_rx) = mpsc::channel::<Vec<u8>>(16);
    let (sig_in_tx, sig_in_rx) = mpsc::channel::<Vec<u8>>(16);

    let splice_fut = splice(
        sealer, opener, app_r, app_w, ss_w, ss_r, sig_out_rx, sig_in_tx,
    );
    let pump_fut = run_circuit_duplex(
        ps_r,
        ps_w,
        LinkHalves::new(link_recv, link_send),
        rebind_rx,
        wire::DEFAULT_REBIND_GRACE,
        DEFAULT_WINDOW,
        DEFAULT_SEGMENT,
    );
    // Holds the promoted direct connection alive for the flow's duration; closed below once the
    // splice + pump finish, so a promoted flow does not linger on quinn's idle timeout.
    let direct_slot: Arc<Mutex<Option<Connection>>> = Arc::new(Mutex::new(None));
    let promo_fut = promote(
        secret,
        peer_id,
        role,
        path_mode,
        toward,
        sig_out_tx,
        sig_in_rx,
        rebind_tx,
        direct_slot.clone(),
    );

    // Splice/pump errors propagate; a DirectOnly promotion failure also tears the flow down.
    tokio::try_join!(
        async { splice_fut.await.map_err(NetError::from) },
        async { pump_fut.await.map_err(NetError::from) },
        promo_fut,
    )?;
    if let Some(conn) = direct_slot.lock().await.take() {
        conn.close(0u32.into(), b"flow complete");
    }
    Ok(())
}

/// Relay/ingress: accept one client connection, capability-gate the dial, and forward the sealed
/// stream to the egress **blind**. `resolve` maps a requested service to its egress
/// `(addr, identity, encryption_required)`; `trust_root` verifies the dial capability.
pub async fn forward_relay<F>(
    client: Connection,
    trust_root: &TokenPublicKey,
    resolve: F,
) -> Result<(), NetError>
where
    F: Fn(&str) -> Option<(SocketAddr, OverlayId, bool)>,
{
    let (mut client_send, mut client_recv) = client
        .accept_bi()
        .await
        .map_err(|e| NetError::Stream(e.to_string()))?;

    let request: DialRequest = read_msg(&mut client_recv).await?;
    let client_id = peer_identity(&client)?;

    let Some((egress_addr, egress_id, enc_required)) = resolve(&request.service) else {
        write_msg(
            &mut client_send,
            &DialVerdict::Reject(boatramp_overlay_proto::dial::DialReject::ServiceNotAuthorized),
        )
        .await?;
        let _ = timeout(wire::DIRECT_DRAIN, client.closed()).await;
        return Err(NetError::UnresolvedService(request.service));
    };

    let verdict = authorize_dial(&request, &client_id, trust_root, now_unix(), enc_required);
    write_msg(&mut client_send, &verdict).await?;
    if !matches!(verdict, DialVerdict::Accept { .. }) {
        // Hold the connection so the Reject verdict delivers before it drops (bounded).
        let _ = timeout(wire::DIRECT_DRAIN, client.closed()).await;
        return Ok(()); // refused — the client has its reason
    }

    // Dial the egress (server-auth only — the relay is blind, unauthenticated to the egress; the
    // egress authenticates the CLIENT via the forwarded E2EE handshake) and bridge the two
    // bi-streams blind (the handshake + sealed records flow through untouched).
    let egress_ep = quic::client_endpoint_server_auth(&OverlayPeerPolicy::Pin(egress_id))?;
    let egress_conn = quic::dial(&egress_ep, egress_addr).await?;
    let (egress_send, egress_recv) = egress_conn
        .open_bi()
        .await
        .map_err(|e| NetError::Stream(e.to_string()))?;

    bridge(client_recv, client_send, egress_recv, egress_send).await?;
    // Hold the client connection until it drains the echo and closes (bounded) — so quinn's driver
    // delivers the finished streams before this connection drops.
    let _ = timeout(wire::DIRECT_DRAIN, client.closed()).await;
    Ok(())
}

/// Forward bytes in both directions between the client and egress streams, blind.
async fn bridge(
    mut client_recv: quinn::RecvStream,
    mut client_send: quinn::SendStream,
    mut egress_recv: quinn::RecvStream,
    mut egress_send: quinn::SendStream,
) -> Result<(), NetError> {
    let c2e = async {
        tokio::io::copy(&mut client_recv, &mut egress_send).await?;
        egress_send.finish().ok();
        Ok::<(), std::io::Error>(())
    };
    let e2c = async {
        tokio::io::copy(&mut egress_recv, &mut client_send).await?;
        client_send.finish().ok();
        Ok::<(), std::io::Error>(())
    };
    tokio::try_join!(c2e, e2c)?;
    Ok(())
}

/// Egress/terminator: complete the E2EE handshake on the accepted connection (learning the client
/// identity), **independently authorize** the dial capability the client presents end-to-end, then
/// bridge the session to the backend its requested service resolves to.
///
/// Zero-trust (Security HIGH-1): the egress never trusts the relay's gate as its authorization
/// boundary. After the handshake it reads the overlay-dial capability the client seals into the
/// E2EE channel and verifies it HERE — against its own `trust_root` and the cryptographically
/// proven (E2EE-learned) `client_id` — **before** connecting the backend. A relay that skips,
/// forges, or is bypassed around its gate cannot reach the backend: the capability is signed by the
/// trust root and holder-bound to the client's key, and it rides the sealed channel the relay is
/// blind to, so the relay can neither mint nor read it.
///
/// Service-anchored (Security HIGH-A): `resolve_backend` is the egress's OWN service→backend map
/// (its deployment config). The requested `request.service` is resolved to a backend HERE; a service
/// this egress does not front resolves to `None` and is refused, so `authorize_dial`'s
/// `scope == request.service` check binds the capability scope to a service the egress actually
/// serves — a capability for a different service cannot be redeemed here even under a misrouting
/// relay, because `request.service` must be one this egress fronts AND the scope must authorize it.
pub async fn terminate_one<F>(
    conn: Connection,
    secret: &OverlaySecret,
    resolve_backend: F,
    trust_root: &TokenPublicKey,
    encryption_required: bool,
    path_mode: PathMode,
) -> Result<(), NetError>
where
    F: Fn(&str) -> Option<SocketAddr>,
{
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| NetError::Stream(e.to_string()))?;

    // The E2EE handshake learns the client identity (the responder does not pin it in advance); it
    // is the identity the dial capability must be holder-bound to, and that direct-path promotion
    // pins its link to.
    let (session, client_id) =
        establish(&mut send, &mut recv, secret, Role::Responder, None, None).await?;
    let (sealer, mut opener) = session.split();

    // Zero-trust authz: open the sealed dial capability the client presents end-to-end (the first
    // record after the handshake) and verify it against the trust root + the E2EE-proven client
    // identity — not on the relay's say-so — before touching the backend.
    let sealed = read_lp(&mut recv, MAX_DIAL_MSG).await?.ok_or_else(|| {
        NetError::Stream("client closed before presenting the dial capability".into())
    })?;
    let control = opener
        .open(&sealed)
        .map_err(|e| NetError::Splice(e.into()))?;
    let request: DialRequest = serde_json::from_slice(&control)?;
    // HIGH-A: anchor authorization to the services THIS egress actually fronts. Resolve the requested
    // service to a backend from the egress's own map; an unmapped service is refused here, so
    // `authorize_dial`'s `scope == request.service` check binds the capability scope to a service the
    // egress serves — never a string the client simply typed.
    let Some(backend_addr) = resolve_backend(&request.service) else {
        let _ = timeout(wire::DIRECT_DRAIN, conn.closed()).await;
        return Err(NetError::DialRejected(
            boatramp_overlay_proto::dial::DialReject::ServiceNotAuthorized,
        ));
    };
    match authorize_dial(
        &request,
        &client_id,
        trust_root,
        now_unix(),
        encryption_required,
    ) {
        DialVerdict::Accept { .. } => {}
        DialVerdict::Reject(reason) => {
            let _ = timeout(wire::DIRECT_DRAIN, conn.closed()).await;
            return Err(NetError::DialRejected(reason));
        }
    }

    let backend = tokio::net::TcpStream::connect(backend_addr).await?;
    let (br, bw) = backend.into_split();
    let owned = OverlaySecret::from_seed_hex(&secret.seed_hex())?;
    // Toward: the relay we were reached through — the routing hint for our host candidate.
    let toward = conn.remote_address();
    run_spliced_circuit_promotable(
        sealer,
        opener,
        br,
        bw,
        recv,
        send,
        owned,
        client_id,
        Role::Responder,
        path_mode,
        toward,
    )
    .await?;
    // Hold the (relay) connection open until it has drained the final records and closes (bounded),
    // so a relay-path flow's last bytes are delivered before this connection drops.
    let _ = timeout(wire::DIRECT_DRAIN, conn.closed()).await;
    Ok(())
}

/// Relay/ingress **serve loop** (IU-8): accept client connections on `endpoint` and, per connection,
/// capability-gate the dial against `trust_root` and forward the sealed stream to the egress
/// `resolve` maps the requested service to — **blind**. Runs until the endpoint is closed; each
/// connection is handled on its own task, so one slow flow never blocks the accept loop. This is the
/// server side of [`forward_flow`]: `boatramp serve` stands one of these up so a remote
/// `boatramp forward` can actually reach the cluster.
pub async fn run_forwarding_router<F>(endpoint: Endpoint, trust_root: TokenPublicKey, resolve: F)
where
    F: Fn(&str) -> Option<(SocketAddr, OverlayId, bool)> + Clone + Send + Sync + 'static,
{
    while let Ok(Some(conn)) = quic::accept(&endpoint).await {
        let trust_root = trust_root.clone();
        let resolve = resolve.clone();
        tokio::spawn(async move {
            if let Err(e) = forward_relay(conn, &trust_root, resolve).await {
                tracing::debug!(error = %e, "overlay relay: flow ended with error");
            }
        });
    }
}

/// Egress/terminator **serve loop** (IU-8): accept connections on `endpoint` (reached through a
/// relay, or dialed directly once promoted) and terminate each over the backend its requested
/// service resolves to via `resolve_backend` (this egress's own service→backend map). Every dial is
/// independently authorized against `trust_root` + the E2EE-proven client identity (zero-trust,
/// HIGH-1) and anchored to a served service (HIGH-A). Runs until the endpoint is closed.
pub async fn run_egress_router<F>(
    endpoint: Endpoint,
    secret: OverlaySecret,
    resolve_backend: F,
    trust_root: TokenPublicKey,
    encryption_required: bool,
    path_mode: PathMode,
) where
    F: Fn(&str) -> Option<SocketAddr> + Clone + Send + Sync + 'static,
{
    let seed = secret.seed_hex();
    while let Ok(Some(conn)) = quic::accept(&endpoint).await {
        // Each terminator needs its own OverlaySecret (not Clone — it holds a zeroized seed); rebuild
        // from the one seed, so every connection presents the same egress identity.
        let Ok(secret) = OverlaySecret::from_seed_hex(&seed) else {
            continue;
        };
        let resolve_backend = resolve_backend.clone();
        let trust_root = trust_root.clone();
        tokio::spawn(async move {
            if let Err(e) = terminate_one(
                conn,
                &secret,
                resolve_backend,
                &trust_root,
                encryption_required,
                path_mode,
            )
            .await
            {
                tracing::debug!(error = %e, "overlay egress: flow ended with error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::cose::mint_overlay_dial;
    use boatramp_overlay_proto::peer_policy::OverlayPeerPolicy::{AcceptAny, Allowlist, Pin};
    use std::collections::BTreeSet;
    use tokio::io::AsyncWriteExt;

    /// Full relay-path vertical: client → relay (capability-gated) → egress → TCP backend echo,
    /// end-to-end E2EE through the blind relay. A bad-scope token is refused.
    #[tokio::test]
    async fn relay_path_vertical_forwards_capability_gated_e2ee() {
        let root = OverlaySecret::generate().unwrap(); // dial-token trust root
        let client = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let egress = OverlaySecret::generate().unwrap();
        let (client_id, relay_id, egress_id) = (client.id(), relay.id(), egress.id());

        // --- backend echo (TCP) ---
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        // --- egress (QUIC accept-any; E2EE learns the client) ---
        let egress_ep =
            quic::server_endpoint(&egress, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
        let egress_addr = egress_ep.local_addr().unwrap();
        {
            let egress = OverlaySecret::from_seed_hex(&egress.seed_hex()).unwrap();
            let egress_root = root.id().to_public();
            tokio::spawn(async move {
                while let Ok(Some(conn)) = quic::accept(&egress_ep).await {
                    let egress = OverlaySecret::from_seed_hex(&egress.seed_hex()).unwrap();
                    let egress_root = egress_root.clone();
                    tokio::spawn(async move {
                        let _ = terminate_one(
                            conn,
                            &egress,
                            |s: &str| (s == "svc/echo").then_some(backend_addr),
                            &egress_root,
                            true,
                            PathMode::Relay,
                        )
                        .await;
                    });
                }
            });
        }

        // --- relay (QUIC mutual-auth; allowlists the client so it learns its id) ---
        let relay_ep = quic::server_endpoint(
            &relay,
            &Allowlist(BTreeSet::from([client_id])),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let relay_addr = relay_ep.local_addr().unwrap();
        let root_pub = root.id().to_public();
        tokio::spawn(async move {
            while let Ok(Some(conn)) = quic::accept(&relay_ep).await {
                let root_pub = root_pub.clone();
                tokio::spawn(async move {
                    let resolve =
                        |svc: &str| (svc == "svc/echo").then_some((egress_addr, egress_id, true));
                    let _ = forward_relay(conn, &root_pub, resolve).await;
                });
            }
        });

        // --- client-edge: mint a dial token (root signs; holder = client; scope = svc/echo) ---
        let token = mint_overlay_dial(
            &client.id().to_public(),
            "svc/echo",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();

        let client_seed = client.seed_hex();
        let client_ep = quic::client_endpoint(&client, &Pin(relay_id)).unwrap();
        let (mut app, app_far) = tokio::io::duplex(64 * 1024);
        let fwd = tokio::spawn(async move {
            forward_flow(
                app_far,
                &client_ep,
                relay_addr,
                &client,
                egress_id,
                DialRequest {
                    service: "svc/echo".into(),
                    token,
                    e2ee: true,
                },
                PathMode::Relay,
            )
            .await
        });

        // Drive: write, half-close, read the echo back.
        app.write_all(b"ping over the overlay").await.unwrap();
        app.shutdown().await.unwrap();
        let mut got = Vec::new();
        app.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ping over the overlay");
        let _ = fwd.await;

        // --- a token scoped to a DIFFERENT service is refused by the relay gate ---
        let client2 = OverlaySecret::from_seed_hex(&client_seed).unwrap();
        let bad = mint_overlay_dial(
            &client2.id().to_public(),
            "svc/other",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        let client_ep2 = quic::client_endpoint(&client2, &Pin(relay_id)).unwrap();
        let (_app2, app2_far) = tokio::io::duplex(64 * 1024);
        let rejected = forward_flow(
            app2_far,
            &client_ep2,
            relay_addr,
            &client2,
            egress_id,
            DialRequest {
                service: "svc/echo".into(), // asks echo, but the token authorizes svc/other
                token: bad,
                e2ee: true,
            },
            PathMode::Relay,
        )
        .await;
        assert!(
            matches!(rejected, Err(NetError::DialRejected(_))),
            "an out-of-scope token must be refused at the gate, got {rejected:?}"
        );
    }

    /// §6 promotion proof: a `PreferDirect` flow starts over the relay, both ends promote onto a
    /// hole-punched direct link, and the flow SURVIVES the relay being severed — which it can only
    /// do if it is no longer riding the relay. (On loopback the direct dial always succeeds.)
    #[tokio::test]
    async fn flow_promotes_to_direct_and_survives_relay_severance() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let egress = OverlaySecret::generate().unwrap();
        let (client_id, relay_id, egress_id) = (client.id(), relay.id(), egress.id());

        // Backend echo.
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        // Egress (PreferDirect — it will accept the hole-punch).
        let egress_ep =
            quic::server_endpoint(&egress, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
        let egress_addr = egress_ep.local_addr().unwrap();
        let egress_root = root.id().to_public();
        tokio::spawn(async move {
            while let Ok(Some(conn)) = quic::accept(&egress_ep).await {
                let egress = OverlaySecret::from_seed_hex(&egress.seed_hex()).unwrap();
                let egress_root = egress_root.clone();
                tokio::spawn(async move {
                    let _ = terminate_one(
                        conn,
                        &egress,
                        |s: &str| (s == "svc/echo").then_some(backend_addr),
                        &egress_root,
                        true,
                        PathMode::PreferDirect,
                    )
                    .await;
                });
            }
        });

        // Relay — hold a handle so we can SEVER it mid-flow.
        let relay_ep = quic::server_endpoint(
            &relay,
            &Allowlist(BTreeSet::from([client_id])),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let relay_addr = relay_ep.local_addr().unwrap();
        let relay_handle = relay_ep.clone();
        let root_pub = root.id().to_public();
        tokio::spawn(async move {
            while let Ok(Some(conn)) = quic::accept(&relay_ep).await {
                let root_pub = root_pub.clone();
                tokio::spawn(async move {
                    let resolve =
                        |svc: &str| (svc == "svc/echo").then_some((egress_addr, egress_id, true));
                    let _ = forward_relay(conn, &root_pub, resolve).await;
                });
            }
        });

        let token = mint_overlay_dial(
            &client.id().to_public(),
            "svc/echo",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        let client_ep = quic::client_endpoint(&client, &Pin(relay_id)).unwrap();
        let (mut app, app_far) = tokio::io::duplex(64 * 1024);
        let fwd = tokio::spawn(async move {
            forward_flow(
                app_far,
                &client_ep,
                relay_addr,
                &client,
                egress_id,
                DialRequest {
                    service: "svc/echo".into(),
                    token,
                    e2ee: true,
                },
                PathMode::PreferDirect,
            )
            .await
        });

        // Round 1: the flow is up (over the relay, or already promoting).
        app.write_all(b"first").await.unwrap();
        let mut r1 = [0u8; 5];
        tokio::time::timeout(std::time::Duration::from_secs(5), app.read_exact(&mut r1))
            .await
            .expect("round 1 echo in time")
            .unwrap();
        assert_eq!(&r1, b"first");

        // Give promotion time to gather, exchange candidates, hole-punch, and rebind both pumps.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // SEVER the relay: close its endpoint and every connection through it.
        relay_handle.close(0u32.into(), b"severed");

        // Round 2: if the flow survives with the relay gone, it promoted onto the direct link.
        app.write_all(b"second").await.unwrap();
        let mut r2 = [0u8; 6];
        tokio::time::timeout(std::time::Duration::from_secs(5), app.read_exact(&mut r2))
            .await
            .expect("round 2 echo must still arrive over the DIRECT link after relay severance")
            .unwrap();
        assert_eq!(&r2, b"second");

        drop(app); // end the flow
        let _ = fwd.await;
    }

    /// Zero-trust egress proof (Security HIGH-1): a COMPROMISED relay that rubber-stamps every dial
    /// (never runs the gate) still cannot get an unauthorized flow to the backend. The egress
    /// verifies the sealed capability itself — against the trust root and the E2EE-proven client
    /// identity — and refuses an out-of-scope token, so the backend is never even connected.
    #[tokio::test]
    async fn egress_refuses_unauthorized_dial_even_when_the_relay_does_not_gate() {
        use tokio::io::AsyncWriteExt;

        let root = OverlaySecret::generate().unwrap(); // dial-token trust root
        let client = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let egress = OverlaySecret::generate().unwrap();
        let (client_id, relay_id, egress_id) = (client.id(), relay.id(), egress.id());

        // Backend: a listener that MUST never be connected (the egress refuses first). It signals
        // on the channel the instant anything connects — the test asserts that never happens.
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let (hit_tx, mut hit_rx) = mpsc::channel::<()>(1);
        tokio::spawn(async move {
            if backend.accept().await.is_ok() {
                let _ = hit_tx.send(()).await;
            }
        });

        // Egress: zero-trust — trust_root = root, encryption required.
        let egress_ep =
            quic::server_endpoint(&egress, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
        let egress_addr = egress_ep.local_addr().unwrap();
        let egress_root = root.id().to_public();
        tokio::spawn(async move {
            while let Ok(Some(conn)) = quic::accept(&egress_ep).await {
                let egress = OverlaySecret::from_seed_hex(&egress.seed_hex()).unwrap();
                let egress_root = egress_root.clone();
                tokio::spawn(async move {
                    let _ = terminate_one(
                        conn,
                        &egress,
                        |s: &str| (s == "svc/echo").then_some(backend_addr),
                        &egress_root,
                        true,
                        PathMode::Relay,
                    )
                    .await;
                });
            }
        });

        // A COMPROMISED relay: it accepts ANY dial WITHOUT gating (no `authorize_dial`), then
        // bridges the stream to the egress blind. This is the whole point — the relay is not the
        // authorization boundary.
        let relay_ep = quic::server_endpoint(
            &relay,
            &Allowlist(BTreeSet::from([client_id])),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let relay_addr = relay_ep.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok(Some(conn)) = quic::accept(&relay_ep).await {
                tokio::spawn(async move {
                    let Ok((mut cs, mut cr)) = conn.accept_bi().await else {
                        return;
                    };
                    let Ok(_req) = read_msg::<DialRequest>(&mut cr).await else {
                        return;
                    };
                    // Rubber-stamp: Accept, unconditionally, with no capability check at all.
                    if write_msg(&mut cs, &DialVerdict::Accept { scope: "*".into() })
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let Ok(ep) =
                        quic::client_endpoint_server_auth(&OverlayPeerPolicy::Pin(egress_id))
                    else {
                        return;
                    };
                    let Ok(ec) = quic::dial(&ep, egress_addr).await else {
                        return;
                    };
                    let Ok((es, er)) = ec.open_bi().await else {
                        return;
                    };
                    let _ = bridge(cr, cs, er, es).await;
                });
            }
        });

        // The client holds a token scoped to `svc/other`, but asks for `svc/echo` — out of scope.
        let token = mint_overlay_dial(
            &client.id().to_public(),
            "svc/other",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        let client_ep = quic::client_endpoint(&client, &Pin(relay_id)).unwrap();
        let (mut app, app_far) = tokio::io::duplex(64 * 1024);
        let fwd = tokio::spawn(async move {
            forward_flow(
                app_far,
                &client_ep,
                relay_addr,
                &client,
                egress_id,
                DialRequest {
                    service: "svc/echo".into(),
                    token,
                    e2ee: true,
                },
                PathMode::Relay,
            )
            .await
        });

        // Push bytes at it; the egress must refuse before the backend is ever connected.
        let _ = app.write_all(b"unauthorized").await;

        // The backend must NEVER be connected: nothing arrives on the hit channel.
        let connected =
            tokio::time::timeout(std::time::Duration::from_secs(3), hit_rx.recv()).await;
        assert!(
            connected.is_err(),
            "the backend must never be connected for an unauthorized dial that only the compromised relay let through"
        );

        // And the client's flow fails — the egress tore it down.
        drop(app);
        let outcome = fwd.await.unwrap();
        assert!(
            outcome.is_err(),
            "an unauthorized flow must fail at the zero-trust egress, got {outcome:?}"
        );
    }

    /// Egress service-anchor proof (Security HIGH-A): the egress authorizes the capability against
    /// the service IT fronts, not a string the client types. A client holding a VALID capability for
    /// `svc/echo` cannot reach a `svc/db` egress by naming `svc/echo` — even when a compromised relay
    /// misroutes the flow to that egress. The backend is never connected.
    #[tokio::test]
    async fn egress_binds_scope_to_its_own_service_not_the_client_claim() {
        use tokio::io::AsyncWriteExt;

        let root = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let egress = OverlaySecret::generate().unwrap();
        let (client_id, relay_id, egress_id) = (client.id(), relay.id(), egress.id());

        // The db-egress backend MUST never be connected.
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let (hit_tx, mut hit_rx) = mpsc::channel::<()>(1);
        tokio::spawn(async move {
            if backend.accept().await.is_ok() {
                let _ = hit_tx.send(()).await;
            }
        });

        // This egress fronts `svc/db` — NOT `svc/echo`.
        let egress_ep =
            quic::server_endpoint(&egress, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
        let egress_addr = egress_ep.local_addr().unwrap();
        let egress_root = root.id().to_public();
        tokio::spawn(async move {
            while let Ok(Some(conn)) = quic::accept(&egress_ep).await {
                let egress = OverlaySecret::from_seed_hex(&egress.seed_hex()).unwrap();
                let egress_root = egress_root.clone();
                tokio::spawn(async move {
                    let _ = terminate_one(
                        conn,
                        &egress,
                        |s: &str| (s == "svc/db").then_some(backend_addr), // the service THIS egress fronts
                        &egress_root,
                        true,
                        PathMode::Relay,
                    )
                    .await;
                });
            }
        });

        // A relay that MISROUTES: it gates the dial honestly (the svc/echo cap is valid for svc/echo)
        // but forwards to the svc/db egress (a compromise/misconfig). The dial passes the relay gate.
        let relay_ep = quic::server_endpoint(
            &relay,
            &Allowlist(BTreeSet::from([client_id])),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let relay_addr = relay_ep.local_addr().unwrap();
        let relay_root = root.id().to_public();
        tokio::spawn(async move {
            while let Ok(Some(conn)) = quic::accept(&relay_ep).await {
                let relay_root = relay_root.clone();
                tokio::spawn(async move {
                    let Ok((mut cs, mut cr)) = conn.accept_bi().await else {
                        return;
                    };
                    let Ok(req) = read_msg::<DialRequest>(&mut cr).await else {
                        return;
                    };
                    let Ok(cid) = peer_identity(&conn) else {
                        return;
                    };
                    // Honest gate: the svc/echo cap IS valid for svc/echo.
                    let verdict = authorize_dial(&req, &cid, &relay_root, now_unix(), true);
                    if write_msg(&mut cs, &verdict).await.is_err()
                        || !matches!(verdict, DialVerdict::Accept { .. })
                    {
                        return;
                    }
                    // ...but it dials the WRONG egress (svc/db) for a svc/echo request.
                    let Ok(ep) =
                        quic::client_endpoint_server_auth(&OverlayPeerPolicy::Pin(egress_id))
                    else {
                        return;
                    };
                    let Ok(ec) = quic::dial(&ep, egress_addr).await else {
                        return;
                    };
                    let Ok((es, er)) = ec.open_bi().await else {
                        return;
                    };
                    let _ = bridge(cr, cs, er, es).await;
                });
            }
        });

        // A VALID capability scoped to svc/echo; the client asks for svc/echo.
        let token = mint_overlay_dial(
            &client.id().to_public(),
            "svc/echo",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        let client_ep = quic::client_endpoint(&client, &Pin(relay_id)).unwrap();
        let (mut app, app_far) = tokio::io::duplex(64 * 1024);
        let fwd = tokio::spawn(async move {
            forward_flow(
                app_far,
                &client_ep,
                relay_addr,
                &client,
                egress_id,
                DialRequest {
                    service: "svc/echo".into(),
                    token,
                    e2ee: true,
                },
                PathMode::Relay,
            )
            .await
        });

        let _ = app.write_all(b"wrong egress").await;

        // The svc/db backend must NEVER be connected — the egress anchors scope to svc/db.
        let connected =
            tokio::time::timeout(std::time::Duration::from_secs(3), hit_rx.recv()).await;
        assert!(
            connected.is_err(),
            "a svc/echo capability must not reach a svc/db egress even via a misrouting relay"
        );
        drop(app);
        let outcome = fwd.await.unwrap();
        assert!(
            outcome.is_err(),
            "the flow must fail at the service-anchored egress, got {outcome:?}"
        );
    }

    /// §5 "Done" over the SERVED roles: `forward_flow` (client-edge) → `run_forwarding_router` (a
    /// served relay/ingress) → `run_egress_router` (a served egress) → a TCP backend, capability-
    /// gated and relay-blind — the full deployable vertical through the actual serve loops, not an
    /// ad-hoc per-connection harness. This is what `boatramp serve` stands up for a remote
    /// `boatramp forward` to reach an in-cluster service.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn served_relay_and_egress_routers_forward_a_capability_gated_flow() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let egress = OverlaySecret::generate().unwrap();
        let (client_id, relay_id, egress_id) = (client.id(), relay.id(), egress.id());
        let root_pub = root.id().to_public();

        // Backend echo (the in-cluster service `svc/db` fronts).
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        // Served EGRESS: accept-any endpoint + the egress router fronting svc/db -> backend.
        let egress_ep =
            quic::server_endpoint(&egress, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
        let egress_addr = egress_ep.local_addr().unwrap();
        {
            let root_pub = root_pub.clone();
            tokio::spawn(run_egress_router(
                egress_ep,
                egress,
                move |s: &str| (s == "svc/db").then_some(backend_addr),
                root_pub,
                true,
                PathMode::Relay,
            ));
        }

        // Served RELAY/ingress: allowlist the client + the relay router resolving svc/db -> egress.
        let relay_ep = quic::server_endpoint(
            &relay,
            &Allowlist(BTreeSet::from([client_id])),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let relay_addr = relay_ep.local_addr().unwrap();
        tokio::spawn(run_forwarding_router(relay_ep, root_pub, move |s: &str| {
            (s == "svc/db").then_some((egress_addr, egress_id, true))
        }));

        // Client-edge: a valid svc/db capability; dial through the served relay.
        let token = mint_overlay_dial(
            &client.id().to_public(),
            "svc/db",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        let client_ep = quic::client_endpoint(&client, &Pin(relay_id)).unwrap();
        let (mut app, app_far) = tokio::io::duplex(64 * 1024);
        let fwd = tokio::spawn(async move {
            forward_flow(
                app_far,
                &client_ep,
                relay_addr,
                &client,
                egress_id,
                DialRequest {
                    service: "svc/db".into(),
                    token,
                    e2ee: true,
                },
                PathMode::Relay,
            )
            .await
        });

        // Drive the end-to-end round-trip through the served routers.
        app.write_all(b"reach the in-cluster service")
            .await
            .unwrap();
        app.shutdown().await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            app.read_to_end(&mut got),
        )
        .await
        .expect("served relay+egress deliver the echo in time")
        .unwrap();
        assert_eq!(got, b"reach the in-cluster service");
        let _ = fwd.await;
    }
}
