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

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use std::sync::Arc;
use std::time::Duration;

use boatramp_core::cose::{TokenPublicKey, verify_overlay_publish};
use boatramp_overlay_proto::circuit::{DEFAULT_SEGMENT, DEFAULT_WINDOW};
use boatramp_overlay_proto::dial::{
    DialReject, DialRequest, DialVerdict, authorize_dial, authorize_dial_capability_only,
};
use boatramp_overlay_proto::e2ee::{Opener, Role, Sealer};
use boatramp_overlay_proto::ice::Signal;
use boatramp_overlay_proto::identity::{OverlayId, OverlaySecret};
use boatramp_overlay_proto::peer_policy::OverlayPeerPolicy;
use boatramp_overlay_proto::wire;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, Semaphore, mpsc};
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

/// How long a terminator/relay waits for the client to complete the handshake and present its dial
/// control message before abandoning the connection (MEDIUM-B). Bounds a slow-loris: a connection
/// that completes TLS but stalls before (or during) the sealed-capability exchange cannot park a
/// task — holding derived session keys — indefinitely. Generous (a real handshake + first message is
/// milliseconds); the data phase, once authorized, runs with no such deadline.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Max concurrently in-flight flows a serve loop ([`run_egress_router`]/[`run_forwarding_router`])
/// admits (MEDIUM-B). Bounds the task/connection count a flood — unauthenticated at the egress —
/// can pin; the accept loop backpressures past this. High enough not to throttle a busy node.
const MAX_INFLIGHT_FLOWS: usize = 1024;

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
    #[error("service registration refused by the relay: {0:?}")]
    RegistrationRejected(RegisterReject),
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

/// How a relay authenticates dialing clients at the transport layer (Security Blocker #1 / Option A).
/// The posture is set EXPLICITLY from `[overlay] client_auth` — never inferred from an empty
/// allowlist (that empty→open inference was the fail-closed→fail-open-on-omission footgun the
/// reviewer flagged).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayClientAuth {
    /// The relay required + pinned the client's raw-public-key cert (an `Allowlist` endpoint), so it
    /// has a proven client identity and enforces holder-binding too — a strictly-more-restrictive
    /// pre-filter layered on top of the capability gate.
    MutualPin,
    /// The relay accepts any client key at TLS (`AcceptAny`) and has NO proven client identity, so it
    /// gates on the capability alone (signature/expiry/kind/scope/encryption) and defers holder-binding
    /// to the egress's E2EE-proven re-authz. A dial with no valid, in-scope capability is still refused
    /// here (never a blind forwarder).
    CapabilityOnly,
}

/// Capability-gate a dial request at the relay under its client-auth posture. Mutual-pin binds the
/// dialing peer's TLS-proven identity (a strictly-more-restrictive pre-filter); capability-only gates
/// on the capability alone (signature/expiry/kind/scope/encryption) and defers holder-binding to the
/// terminator's E2EE-proven re-authz. In BOTH cases a dial with no valid, in-scope, unexpired
/// capability is refused here. Shared by the egress-forwarding ([`forward_relay`]) and
/// exposer-forwarding ([`forward_resolved`]) paths so the gate can never drift between them.
fn gate_dial(
    request: &DialRequest,
    client: &Connection,
    trust_root: &TokenPublicKey,
    client_auth: RelayClientAuth,
    enc_required: bool,
) -> Result<DialVerdict, NetError> {
    Ok(match client_auth {
        RelayClientAuth::MutualPin => {
            let client_id = peer_identity(client)?;
            authorize_dial(request, &client_id, trust_root, now_unix(), enc_required)
        }
        RelayClientAuth::CapabilityOnly => {
            authorize_dial_capability_only(request, trust_root, now_unix(), enc_required)
        }
    })
}

/// Relay/ingress: accept one client connection, capability-gate the dial, and forward the sealed
/// stream to the egress **blind**. `resolve` maps a requested service to its egress
/// `(addr, identity, encryption_required)`; `trust_root` verifies the dial capability. `client_auth`
/// selects whether the relay can also prove holder-binding (mutual-pin) or defers it to the egress
/// (capability-only); in BOTH cases a dial with no valid in-scope capability is refused here.
pub async fn forward_relay<F>(
    client: Connection,
    trust_root: &TokenPublicKey,
    client_auth: RelayClientAuth,
    resolve: F,
) -> Result<(), NetError>
where
    F: Fn(&str) -> Option<(SocketAddr, OverlayId, bool)>,
{
    // Bound the accept + dial-request read with a deadline (MEDIUM-B): a client that opens a stream
    // but stalls before sending its request cannot park a relay task. (Defense in depth under
    // mutual-pin; load-bearing under capability-only, where any key may connect.)
    let (mut client_send, client_recv, request) = timeout(HANDSHAKE_TIMEOUT, async {
        let (client_send, mut client_recv) = client
            .accept_bi()
            .await
            .map_err(|e| NetError::Stream(e.to_string()))?;
        let request: DialRequest = read_msg(&mut client_recv).await?;
        Ok::<_, NetError>((client_send, client_recv, request))
    })
    .await
    .map_err(|_| NetError::Stream("relay dial-request timed out".into()))??;

    // The client never names an egress ADDRESS — only a service string. `resolve` maps it to the
    // FIXED, operator-configured egress set; an unmapped service is refused and no dial is made. This
    // is what keeps the relay from being an open proxy / SSRF primitive (Security condition 3).
    let Some((egress_addr, egress_id, enc_required)) = resolve(&request.service) else {
        write_msg(
            &mut client_send,
            &DialVerdict::Reject(boatramp_overlay_proto::dial::DialReject::ServiceNotAuthorized),
        )
        .await?;
        let _ = timeout(wire::DIRECT_DRAIN, client.closed()).await;
        return Err(NetError::UnresolvedService(request.service));
    };

    // Capability gate (shared with the reverse-ingress forwarding path via `gate_dial`). Mutual-pin
    // additionally binds the proven TLS client id (a stronger pre-filter); capability-only has no
    // client cert, so it defers holder-binding to the egress but STILL refuses a dial with no valid,
    // in-scope, unexpired capability (CONDITION 1 — not a blind forwarder).
    let verdict = gate_dial(&request, &client, trust_root, client_auth, enc_required)?;
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
    // Bound the bi-stream accept with a deadline (MEDIUM-B): the egress is reachable unauthenticated at
    // the TLS layer, so a connection that completes TLS but never opens a stream must not park a task.
    let (send, recv) = timeout(HANDSHAKE_TIMEOUT, conn.accept_bi())
        .await
        .map_err(|_| NetError::Stream("terminator accept-bi timed out".into()))?
        .map_err(|e| NetError::Stream(e.to_string()))?;
    // Toward: the relay we were reached through — the routing hint for our host candidate (promotion).
    let toward = conn.remote_address();
    let result = terminate_stream(
        send,
        recv,
        secret,
        resolve_backend,
        trust_root,
        encryption_required,
        path_mode,
        toward,
    )
    .await;
    // Hold the (relay) connection open until it has drained the final records and closes (bounded), so
    // a relay-path flow's last bytes are delivered before this connection drops.
    let _ = timeout(wire::DIRECT_DRAIN, conn.closed()).await;
    result
}

/// Terminate ONE accepted overlay flow (its bi-stream already accepted) over a backend: complete the
/// E2EE handshake on the stream (learning the client identity), **independently authorize** the dial
/// capability the client presents end-to-end (zero-trust, HIGH-1), anchor it to a served service
/// (HIGH-A), and splice the session to the backend. The post-`accept_bi` body shared by the
/// egress/terminator ([`terminate_one`], over a dialed-in connection) and the reverse-ingress exposer
/// ([`run_published_service`], over a per-flow stream accepted on its parked outbound relay
/// connection) — so the two share ONE authorization + splice path and can never drift.
///
/// Zero-trust (HIGH-1): the terminator never trusts the relay's gate as its authorization boundary.
/// It reads the overlay-dial capability the client seals into the E2EE channel and verifies it HERE,
/// against `trust_root` and the cryptographically proven (E2EE-learned) `client_id`, before connecting
/// the backend. For the reverse-ingress exposer this is especially load-bearing: a compromised relay
/// that bridges a stream to the exposer still cannot reach the local backend without a client dial
/// capability the exposer itself verifies.
#[allow(clippy::too_many_arguments)]
async fn terminate_stream<F>(
    mut send: SendStream,
    mut recv: RecvStream,
    secret: &OverlaySecret,
    resolve_backend: F,
    trust_root: &TokenPublicKey,
    encryption_required: bool,
    path_mode: PathMode,
    toward: SocketAddr,
) -> Result<(), NetError>
where
    F: Fn(&str) -> Option<SocketAddr>,
{
    // Bound the pre-authorization phase (E2EE handshake + the sealed dial-capability exchange) with a
    // deadline (MEDIUM-B): a connection that stalls here must not park a task holding derived session
    // keys indefinitely. The data phase, once authorized, runs with no deadline.
    let (send, recv, sealer, opener, client_id, request) = timeout(HANDSHAKE_TIMEOUT, async move {
        // The E2EE handshake learns the client identity (the responder does not pin it in
        // advance); it is the identity the dial capability must be holder-bound to, and that
        // direct-path promotion pins its link to.
        let (session, client_id) =
            establish(&mut send, &mut recv, secret, Role::Responder, None, None).await?;
        let (sealer, mut opener) = session.split();
        // Zero-trust: open the sealed dial capability the client presents end-to-end (the first
        // record after the handshake); it is verified below against the trust root + the
        // E2EE-proven client identity — not on the relay's say-so — before touching the backend.
        let sealed = read_lp(&mut recv, MAX_DIAL_MSG).await?.ok_or_else(|| {
            NetError::Stream("client closed before presenting the dial capability".into())
        })?;
        let control = opener
            .open(&sealed)
            .map_err(|e| NetError::Splice(e.into()))?;
        let request: DialRequest = serde_json::from_slice(&control)?;
        Ok::<_, NetError>((send, recv, sealer, opener, client_id, request))
    })
    .await
    .map_err(|_| NetError::Stream("handshake/dial-capability timed out".into()))??;

    // HIGH-A: anchor authorization to the services THIS terminator actually fronts. Resolve the
    // requested service to a backend from its own map; an unmapped service is refused here, so
    // `authorize_dial`'s `scope == request.service` check binds the capability scope to a service this
    // terminator serves — never a string the client simply typed.
    let Some(backend_addr) = resolve_backend(&request.service) else {
        return Err(NetError::DialRejected(DialReject::ServiceNotAuthorized));
    };
    match authorize_dial(
        &request,
        &client_id,
        trust_root,
        now_unix(),
        encryption_required,
    ) {
        DialVerdict::Accept { .. } => {}
        DialVerdict::Reject(reason) => return Err(NetError::DialRejected(reason)),
    }

    let backend = tokio::net::TcpStream::connect(backend_addr).await?;
    let (br, bw) = backend.into_split();
    let owned = OverlaySecret::from_seed_hex(&secret.seed_hex())?;
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
    .await
}

/// Relay/ingress **serve loop** (IU-8): accept client connections on `endpoint` and, per connection,
/// capability-gate the dial against `trust_root` and forward the sealed stream to the egress
/// `resolve` maps the requested service to — **blind**. `client_auth` carries the relay's EXPLICIT
/// transport posture (mutual-pin vs capability-only, Security Blocker #1); it must agree with the
/// `endpoint`'s own peer policy (`Allowlist` ⇒ `MutualPin`, `AcceptAny` ⇒ `CapabilityOnly`). Runs
/// until the endpoint is closed; each connection is handled on its own task, so one slow flow never
/// blocks the accept loop. This is the server side of [`forward_flow`].
pub async fn run_forwarding_router<F>(
    endpoint: Endpoint,
    trust_root: TokenPublicKey,
    client_auth: RelayClientAuth,
    resolve: F,
) where
    F: Fn(&str) -> Option<(SocketAddr, OverlayId, bool)> + Clone + Send + Sync + 'static,
{
    // Bound concurrent in-flight flows (MEDIUM-B): the accept loop waits for a permit, so a flood
    // cannot pin unbounded tasks; a permit is held for the connection's lifetime.
    let limiter = Arc::new(Semaphore::new(MAX_INFLIGHT_FLOWS));
    loop {
        let Ok(permit) = Arc::clone(&limiter).acquire_owned().await else {
            return;
        };
        let Ok(Some(conn)) = quic::accept(&endpoint).await else {
            return;
        };
        let trust_root = trust_root.clone();
        let resolve = resolve.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = forward_relay(conn, &trust_root, client_auth, resolve).await {
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
    // Bound concurrent in-flight terminations (MEDIUM-B): the egress is reachable unauthenticated at
    // the TLS layer, so the accept loop waits for a permit before admitting a connection — a flood
    // cannot pin unbounded tasks/session-state. A permit is held for the connection's lifetime.
    let limiter = Arc::new(Semaphore::new(MAX_INFLIGHT_FLOWS));
    loop {
        let Ok(permit) = Arc::clone(&limiter).acquire_owned().await else {
            return;
        };
        let Ok(Some(conn)) = quic::accept(&endpoint).await else {
            return;
        };
        // Each terminator needs its own OverlaySecret (not Clone — it holds a zeroized seed); rebuild
        // from the one seed, so every connection presents the same egress identity.
        let Ok(secret) = OverlaySecret::from_seed_hex(&seed) else {
            continue;
        };
        let resolve_backend = resolve_backend.clone();
        let trust_root = trust_root.clone();
        tokio::spawn(async move {
            let _permit = permit;
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

// ======================================================================================
// Reverse ingress (`boatramp expose`): publish a LOCAL service INTO the cluster overlay.
//
// The structural inversion of forward: today the relay DIALS a dialable egress. For expose, the
// exposer is behind NAT and undialable, so it DIALS the relay OUTBOUND and holds the connection open;
// the relay parks it in a registry keyed by service; on each inbound `forward svc/<name>` the relay
// opens a per-flow bi-stream DOWN the parked connection and bridges it to the client flow, blind.
// E2EE stays end-to-end forward-client↔exposer (client = Initiator, exposer = Responder via
// `terminate_stream`); reverse flows pin `PathMode::Relay` (a NAT'd exposer is undialable — no
// promotion). The relay proves the exposer's holder-binding AT REGISTRATION (there is no downstream
// party to defer to) via the E2EE handshake, working even under capability-only (AcceptAny) TLS.
// ======================================================================================

/// The discriminator value marking a [`RegisterRequest`] frame, so the relay can tell a registration
/// from a bare [`DialRequest`] on the first control frame without changing the forward-client wire.
const REGISTER_TAG: &str = "overlay-register";

/// What an exposer sends as the FIRST control frame on its registration bi-stream (before the E2EE
/// possession handshake). Distinguished from a forward client's bare [`DialRequest`] by the required
/// `register` discriminator (a `DialRequest` has no such field, nor a `publish_cap`).
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
struct RegisterRequest {
    /// Always [`REGISTER_TAG`].
    register: String,
    /// The EXACT service name to publish (must equal the publish capability's scope).
    service: String,
    /// The holder-bound overlay-publish capability (COSE), minted offline by the cluster root.
    publish_cap: String,
}

/// Why a service registration was refused (returned to the exposer; mirrors [`DialReject`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum RegisterReject {
    /// The publish capability did not verify (bad signature, expired, wrong kind).
    InvalidCapability(String),
    /// The capability's scope does not name the service being registered.
    ScopeMismatch,
    /// The capability's holder is not the registering exposer's E2EE-proven identity (a stolen
    /// capability), or the holder key is not an overlay (Ed25519) identity.
    HolderMismatch,
    /// A live exposer already publishes this name (first-live-claim-wins; never a silent takeover).
    NameTaken,
}

/// The relay's verdict on a registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
enum RegisterResult {
    Ok,
    Rejected(RegisterReject),
}

/// The first control frame on a relay bi-stream.
enum IngressFrame {
    /// An exposer registering a service (reverse ingress).
    Register(RegisterRequest),
    /// A forward client dialing a service.
    Dial(DialRequest),
}

/// Read and classify the first control frame: a registration (exposer) vs a dial (forward client).
/// The bare-`DialRequest` wire the existing client-edge sends is unchanged — a `Register` frame is
/// distinguished by its required `register` discriminator (tried first; it never matches a dial, and a
/// dial never matches it).
async fn read_ingress_frame(r: &mut (impl AsyncRead + Unpin)) -> Result<IngressFrame, NetError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_DIAL_MSG {
        return Err(NetError::TooLarge(n));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    if let Ok(reg) = serde_json::from_slice::<RegisterRequest>(&buf)
        && reg.register == REGISTER_TAG
    {
        return Ok(IngressFrame::Register(reg));
    }
    Ok(IngressFrame::Dial(serde_json::from_slice(&buf)?))
}

/// One parked exposer registration.
struct ExposerEntry {
    /// The parked connection to the exposer (it dialed OUT; its register task holds it open). An
    /// `open_bi` on a clone surfaces a new accepted stream at the exposer's serve loop.
    conn: Connection,
    /// The exposer's E2EE-proven overlay identity (equals the publish capability's `cnf`). Diagnostic.
    #[allow(dead_code)]
    exposer_id: OverlayId,
    /// The publish capability's expiry (Unix seconds): a registration never outlives its capability,
    /// even before the connection itself drops.
    expires_at: u64,
}

/// A relay-side registry of live reverse-ingress exposers: one parked, holder-verified QUIC connection
/// per published service name. The forwarding router resolves a `svc/<name>` a client dials to a
/// registered exposer connection and opens a per-flow bi-stream DOWN it — it NEVER dials a client-named
/// address, so the not-an-open-proxy property holds exactly as for the static-egress path. In-memory
/// and single-node for increment 1 (KV-backed multi-replica registration + heartbeat/TTL reaping are
/// later increments). Cheap to clone (an `Arc` handle).
#[derive(Clone, Default)]
pub struct ExposerRegistry {
    inner: Arc<Mutex<BTreeMap<String, ExposerEntry>>>,
}

impl ExposerRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `entry` is still serving at `now`: its connection is open AND its capability unexpired.
    fn entry_live(entry: &ExposerEntry, now: u64) -> bool {
        entry.conn.close_reason().is_none() && now < entry.expires_at
    }

    /// Resolve a service name to a LIVE exposer connection, pruning a dead/expired entry. `None` if no
    /// exposer is currently publishing it.
    pub async fn resolve(&self, service: &str, now: u64) -> Option<Connection> {
        let mut map = self.inner.lock().await;
        match map.get(service) {
            Some(e) if Self::entry_live(e, now) => Some(e.conn.clone()),
            Some(_) => {
                map.remove(service); // prune the dead/expired entry
                None
            }
            None => None,
        }
    }

    /// Whether a live exposer currently publishes `service` (test/diagnostic helper).
    pub async fn is_registered(&self, service: &str, now: u64) -> bool {
        self.resolve(service, now).await.is_some()
    }

    /// Try to claim `service` for `entry` (FIRST-LIVE-CLAIM-WINS): refuse if a LIVE registration for
    /// the name already exists — even with a valid capability, never a silent takeover. A dead/expired
    /// entry is replaced. Returns `true` on success.
    async fn try_claim(&self, service: &str, entry: ExposerEntry, now: u64) -> bool {
        let mut map = self.inner.lock().await;
        if let Some(existing) = map.get(service)
            && Self::entry_live(existing, now)
        {
            return false; // the name is held by a live exposer
        }
        map.insert(service.to_string(), entry);
        true
    }

    /// Release `service` IFF the stored entry is still `conn` — so a newer registration (a different
    /// connection that re-claimed the name) is never clobbered when an older task's connection
    /// finally closes.
    async fn release(&self, service: &str, conn: &Connection) {
        let mut map = self.inner.lock().await;
        if let Some(existing) = map.get(service)
            && existing.conn.stable_id() == conn.stable_id()
        {
            map.remove(service);
        }
    }
}

/// Relay reverse-ingress: admit one exposer registration. The E2EE handshake (learning the exposer's
/// proven identity) runs FIRST — so every verdict below is a clean [`RegisterResult`] the exposer
/// reads after its own handshake — then the relay binds the proven identity to the publish
/// capability's holder (the load-bearing holder-binding), enforces scope + first-live-claim-wins, and
/// PARKS the connection in `registry` until it drops.
///
/// SECURITY (the load-bearing control, Security-reviewed): expose has NO downstream party to defer
/// holder-binding to (the exposer is terminal), so the RELAY proves the exposer's identity at
/// registration. The E2EE handshake cryptographically proves the exposer controls SOME overlay key
/// (`proven`); the relay then requires `verified.holder == proven` — exactly the holder-binding the
/// dial gate applies, so a stolen publish capability presented by a different identity is refused. This
/// works under capability-only (AcceptAny) TLS because the proof is at the E2EE layer, not the TLS
/// layer. Name-collision is first-live-claim-wins; the relay only ever opens streams down a
/// registered, capability-verified exposer connection (never a client-named address).
/// Send a registration rejection to the exposer, drain the connection (bounded), and return the
/// refusal as an error for the relay's logs.
async fn refuse_registration(
    send: &mut SendStream,
    conn: &Connection,
    reason: RegisterReject,
) -> Result<(), NetError> {
    let _ = write_msg(send, &RegisterResult::Rejected(reason.clone())).await;
    let _ = timeout(wire::DIRECT_DRAIN, conn.closed()).await;
    Err(NetError::RegistrationRejected(reason))
}

async fn register_exposer(
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    req: RegisterRequest,
    relay_secret: &OverlaySecret,
    trust_root: &TokenPublicKey,
    registry: &ExposerRegistry,
) -> Result<(), NetError> {
    let now = now_unix();

    // Complete the E2EE handshake first, LEARNING the exposer's cryptographically-proven identity
    // (expect = None). Bounding it (MEDIUM-B): a half-open registration must not park a relay task.
    let proven = timeout(HANDSHAKE_TIMEOUT, async {
        let (_session, peer) = establish(
            &mut send,
            &mut recv,
            relay_secret,
            Role::Responder,
            None,
            None,
        )
        .await?;
        Ok::<OverlayId, NetError>(peer)
    })
    .await
    .map_err(|_| NetError::Stream("registration handshake timed out".into()))??;

    // Verify the publish capability (signature + expiry + `br_kind == "overlay-publish"`).
    let verified = match verify_overlay_publish(&req.publish_cap, trust_root, now) {
        Ok(v) => v,
        Err(e) => {
            return refuse_registration(
                &mut send,
                &conn,
                RegisterReject::InvalidCapability(e.to_string()),
            )
            .await;
        }
    };
    // The scope must name EXACTLY the service being registered (no wildcard for a publish capability).
    if verified.scope != req.service {
        return refuse_registration(&mut send, &conn, RegisterReject::ScopeMismatch).await;
    }
    // HOLDER BINDING: the E2EE-proven identity must BE the capability's holder — a stolen capability
    // presented by a different key is refused (and a non-Ed25519 holder key can never match).
    if verified.holder != proven.to_hex() {
        return refuse_registration(&mut send, &conn, RegisterReject::HolderMismatch).await;
    }
    // Claim the name (first-live-claim-wins): a second live registration of a published name is
    // refused, never a silent takeover.
    let entry = ExposerEntry {
        conn: conn.clone(),
        exposer_id: proven,
        expires_at: verified.exp,
    };
    if !registry.try_claim(&req.service, entry, now).await {
        return refuse_registration(&mut send, &conn, RegisterReject::NameTaken).await;
    }

    // Acknowledge, then hold the registration until the connection drops (then free the name).
    write_msg(&mut send, &RegisterResult::Ok).await?;
    tracing::info!(service = %req.service, exposer = ?proven, "overlay relay: exposer registered");
    conn.closed().await;
    registry.release(&req.service, &conn).await;
    Ok(())
}

/// Relay forwarding for a dial, resolved against the exposer registry FIRST, then the static egress
/// map. Mirrors [`forward_relay`] (same capability gate via [`gate_dial`], same blind [`bridge`]) but
/// also bridges to a registered reverse-ingress exposer by opening a per-flow bi-stream down its parked
/// connection. The client only ever names a SERVICE; both targets are relay-controlled, so the
/// not-an-open-proxy property holds for the exposer path exactly as for the egress path.
#[allow(clippy::too_many_arguments)]
async fn forward_resolved<F>(
    client: Connection,
    mut client_send: SendStream,
    client_recv: RecvStream,
    request: DialRequest,
    trust_root: &TokenPublicKey,
    client_auth: RelayClientAuth,
    registry: &ExposerRegistry,
    resolve: &F,
) -> Result<(), NetError>
where
    F: Fn(&str) -> Option<(SocketAddr, OverlayId, bool)>,
{
    enum Target {
        Exposer(Connection),
        Egress(SocketAddr, OverlayId),
    }
    // A registered exposer wins; else a statically-configured egress; else refuse (no open proxy).
    let (target, enc_required) =
        if let Some(conn) = registry.resolve(&request.service, now_unix()).await {
            (Target::Exposer(conn), true) // reverse ingress is always end-to-end E2EE client↔exposer
        } else if let Some((addr, id, enc)) = resolve(&request.service) {
            (Target::Egress(addr, id), enc)
        } else {
            write_msg(
                &mut client_send,
                &DialVerdict::Reject(DialReject::ServiceNotAuthorized),
            )
            .await?;
            let _ = timeout(wire::DIRECT_DRAIN, client.closed()).await;
            return Err(NetError::UnresolvedService(request.service));
        };

    let verdict = gate_dial(&request, &client, trust_root, client_auth, enc_required)?;
    write_msg(&mut client_send, &verdict).await?;
    if !matches!(verdict, DialVerdict::Accept { .. }) {
        let _ = timeout(wire::DIRECT_DRAIN, client.closed()).await;
        return Ok(()); // refused — the client has its reason
    }

    match target {
        // Reverse ingress: open a per-flow stream DOWN the parked exposer connection and bridge blind.
        Target::Exposer(exposer_conn) => {
            let (es, er) = exposer_conn
                .open_bi()
                .await
                .map_err(|e| NetError::Stream(e.to_string()))?;
            bridge(client_recv, client_send, er, es).await?;
        }
        // Static egress: dial it server-auth-only (blind) and bridge, exactly as `forward_relay`.
        Target::Egress(egress_addr, egress_id) => {
            let egress_ep = quic::client_endpoint_server_auth(&OverlayPeerPolicy::Pin(egress_id))?;
            let egress_conn = quic::dial(&egress_ep, egress_addr).await?;
            let (es, er) = egress_conn
                .open_bi()
                .await
                .map_err(|e| NetError::Stream(e.to_string()))?;
            bridge(client_recv, client_send, er, es).await?;
        }
    }
    let _ = timeout(wire::DIRECT_DRAIN, client.closed()).await;
    Ok(())
}

/// Relay/ingress **serve loop** supporting reverse ingress. Like [`run_forwarding_router`], but also
/// accepts exposer REGISTRATIONS (`boatramp expose`) and parks them in `registry`, so a forward client
/// dialing a registered `svc/<name>` is bridged DOWN the parked connection (relay-blind) rather than
/// dialed to a configured egress. The first control frame on each connection selects the path — a
/// `Register` frame (exposer) vs a `DialRequest` (forward client). Used when a relay opts into
/// accepting exposed services; `secret` is the relay's identity for the registration handshake.
pub async fn run_ingress_router<F>(
    endpoint: Endpoint,
    secret: OverlaySecret,
    trust_root: TokenPublicKey,
    client_auth: RelayClientAuth,
    registry: ExposerRegistry,
    resolve: F,
) where
    F: Fn(&str) -> Option<(SocketAddr, OverlayId, bool)> + Clone + Send + Sync + 'static,
{
    let seed = secret.seed_hex();
    let limiter = Arc::new(Semaphore::new(MAX_INFLIGHT_FLOWS));
    loop {
        let Ok(permit) = Arc::clone(&limiter).acquire_owned().await else {
            return;
        };
        let Ok(Some(conn)) = quic::accept(&endpoint).await else {
            return;
        };
        // Each registration handshake needs its own OverlaySecret (not Clone — a zeroized seed).
        let Ok(relay_secret) = OverlaySecret::from_seed_hex(&seed) else {
            continue;
        };
        let trust_root = trust_root.clone();
        let resolve = resolve.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_ingress_connection(
                conn,
                &relay_secret,
                &trust_root,
                client_auth,
                &registry,
                &resolve,
            )
            .await
            {
                tracing::debug!(error = %e, "overlay relay: ingress connection ended with error");
            }
        });
    }
}

/// Accept the first bi-stream + control frame on an ingress connection and dispatch to the
/// registration (exposer) or forwarding (client) path.
async fn handle_ingress_connection<F>(
    conn: Connection,
    relay_secret: &OverlaySecret,
    trust_root: &TokenPublicKey,
    client_auth: RelayClientAuth,
    registry: &ExposerRegistry,
    resolve: &F,
) -> Result<(), NetError>
where
    F: Fn(&str) -> Option<(SocketAddr, OverlayId, bool)>,
{
    let (send, mut recv) = timeout(HANDSHAKE_TIMEOUT, conn.accept_bi())
        .await
        .map_err(|_| NetError::Stream("ingress accept-bi timed out".into()))?
        .map_err(|e| NetError::Stream(e.to_string()))?;
    let frame = timeout(HANDSHAKE_TIMEOUT, read_ingress_frame(&mut recv))
        .await
        .map_err(|_| NetError::Stream("ingress first-frame timed out".into()))??;
    match frame {
        IngressFrame::Register(req) => {
            register_exposer(conn, send, recv, req, relay_secret, trust_root, registry).await
        }
        IngressFrame::Dial(req) => {
            forward_resolved(
                conn,
                send,
                recv,
                req,
                trust_root,
                client_auth,
                registry,
                resolve,
            )
            .await
        }
    }
}

/// Reverse-ingress **exposer** (the `boatramp expose` runtime): dial the relay OUTBOUND, register
/// `service` (proving holder-binding to the relay via the E2EE handshake), then hold the connection
/// open and terminate each inbound per-flow stream the relay opens down it over the local backend.
/// E2EE stays end-to-end client↔exposer (the exposer is the Responder in [`terminate_stream`]); the
/// relay is blind. The path is pinned to the relay (`PathMode::Relay`) — a NAT'd exposer is undialable,
/// so there is no direct-path promotion. `ready` fires ONCE, the instant registration succeeds and
/// before serving begins — the CLI uses it to print the "published" banner only after a confirmed
/// registration (a rejected name / expired capability fails loudly first). Returns when the relay
/// connection drops (the service is no longer published) or on a registration failure.
#[allow(clippy::too_many_arguments)]
pub async fn run_published_service<F, R>(
    relay: &Endpoint,
    relay_addr: SocketAddr,
    relay_id: OverlayId,
    secret: &OverlaySecret,
    service: String,
    publish_cap: String,
    resolve_backend: F,
    trust_root: TokenPublicKey,
    encryption_required: bool,
    ready: R,
) -> Result<(), NetError>
where
    F: Fn(&str) -> Option<SocketAddr> + Clone + Send + Sync + 'static,
    R: FnOnce(),
{
    let conn = quic::dial(relay, relay_addr).await?;

    // --- registration ---
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| NetError::Stream(e.to_string()))?;
    write_msg(
        &mut send,
        &RegisterRequest {
            register: REGISTER_TAG.to_string(),
            service: service.clone(),
            publish_cap,
        },
    )
    .await?;
    // Prove possession of the publish capability's holder key to the relay: the Initiator signs its
    // KEM offer with THIS identity's key, and pins the relay (`expect = relay_id`). A relay that is
    // not `relay_id` fails the handshake here.
    timeout(HANDSHAKE_TIMEOUT, async {
        establish(
            &mut send,
            &mut recv,
            secret,
            Role::Initiator,
            Some(relay_id),
            None,
        )
        .await
    })
    .await
    .map_err(|_| NetError::Stream("registration handshake timed out".into()))??;
    match read_msg::<RegisterResult>(&mut recv).await? {
        RegisterResult::Ok => {}
        RegisterResult::Rejected(reason) => return Err(NetError::RegistrationRejected(reason)),
    }
    ready();

    // --- serve: terminate each inbound per-flow stream over the local backend ---
    let trust_root = Arc::new(trust_root);
    let seed = secret.seed_hex();
    let toward = conn.remote_address();
    let limiter = Arc::new(Semaphore::new(MAX_INFLIGHT_FLOWS));
    loop {
        let Ok(permit) = Arc::clone(&limiter).acquire_owned().await else {
            break;
        };
        let (flow_send, flow_recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(_) => break, // the relay connection dropped — the service is no longer published
        };
        // Each flow needs its own OverlaySecret (not Clone — a zeroized seed).
        let Ok(flow_secret) = OverlaySecret::from_seed_hex(&seed) else {
            continue;
        };
        let resolve_backend = resolve_backend.clone();
        let trust_root = Arc::clone(&trust_root);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = terminate_stream(
                flow_send,
                flow_recv,
                &flow_secret,
                resolve_backend,
                &trust_root,
                encryption_required,
                PathMode::Relay,
                toward,
            )
            .await
            {
                tracing::debug!(error = %e, "overlay expose: flow ended with error");
            }
        });
    }
    Ok(())
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
                    let _ =
                        forward_relay(conn, &root_pub, RelayClientAuth::MutualPin, resolve).await;
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
                    let _ =
                        forward_relay(conn, &root_pub, RelayClientAuth::MutualPin, resolve).await;
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
        tokio::spawn(run_forwarding_router(
            relay_ep,
            root_pub,
            RelayClientAuth::MutualPin,
            move |s: &str| (s == "svc/db").then_some((egress_addr, egress_id, true)),
        ));

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

    /// Security Blocker #1, CONDITION 1: a **capability-only** relay still runs the capability gate —
    /// a dial carrying no valid capability is refused AT THE RELAY (`InvalidCapability`) and never
    /// forwarded to the egress. The relay is not a blind forwarder; this is what stops unauthenticated
    /// flood amplification. (The relay rejects before the egress-dial code runs, so the bogus egress
    /// address below is never dialed — a hang/connect error would fail this test instead.)
    #[tokio::test]
    async fn capability_only_relay_refuses_a_dial_with_no_capability() {
        let root = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let egress_id = OverlaySecret::generate().unwrap().id();
        let bogus: SocketAddr = "127.0.0.1:9".parse().unwrap(); // discard port; must never be dialed

        // Relay in capability-only mode: AcceptAny TLS (no allowlist, no pre-enrollment).
        let relay_ep =
            quic::server_endpoint(&relay, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
        let relay_addr = relay_ep.local_addr().unwrap();
        let root_pub = root.id().to_public();
        tokio::spawn(async move {
            if let Ok(Some(conn)) = quic::accept(&relay_ep).await {
                let resolve =
                    move |svc: &str| (svc == "svc/db").then_some((bogus, egress_id, true));
                let _ =
                    forward_relay(conn, &root_pub, RelayClientAuth::CapabilityOnly, resolve).await;
            }
        });

        // Capability-only relay is server-auth-only at TLS — dial without a client cert.
        let client_ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (_app, app_far) = tokio::io::duplex(64 * 1024);
        let res = forward_flow(
            app_far,
            &client_ep,
            relay_addr,
            &client,
            egress_id,
            DialRequest {
                service: "svc/db".into(),
                token: "not-a-valid-cose-capability".into(),
                e2ee: true,
            },
            PathMode::Relay,
        )
        .await;
        assert!(
            matches!(
                res,
                Err(NetError::DialRejected(
                    boatramp_overlay_proto::dial::DialReject::InvalidCapability(_)
                ))
            ),
            "a capability-only relay must refuse a no-/bad-capability dial at the relay, got {res:?}"
        );
    }

    /// Security Blocker #1, CONDITION 3 (SSRF / open-proxy): the client names a SERVICE, never an
    /// address — `DialRequest` carries no address field. The relay maps the service to its FIXED,
    /// operator-configured egress set via `resolve`; an unmapped service is refused and no egress is
    /// dialed, EVEN with a wildcard-scoped capability that authorizes any service. So a relay can
    /// never be driven to dial a client-chosen target.
    #[tokio::test]
    async fn capability_only_relay_is_not_an_open_proxy_for_an_unconfigured_service() {
        let root = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let egress_id = OverlaySecret::generate().unwrap().id();
        let configured: SocketAddr = "127.0.0.1:9".parse().unwrap();

        let relay_ep =
            quic::server_endpoint(&relay, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
        let relay_addr = relay_ep.local_addr().unwrap();
        let root_pub = root.id().to_public();
        tokio::spawn(async move {
            if let Ok(Some(conn)) = quic::accept(&relay_ep).await {
                // The relay only knows `svc/db` → its fixed egress. It knows no other service.
                let resolve =
                    move |svc: &str| (svc == "svc/db").then_some((configured, egress_id, true));
                let _ =
                    forward_relay(conn, &root_pub, RelayClientAuth::CapabilityOnly, resolve).await;
            }
        });

        // A VALID wildcard-scoped capability — authorizes ANY service — yet the relay still refuses an
        // unconfigured service name (resolve returns None), proving the egress set, not the client, is
        // authoritative over the dial target.
        let token = mint_overlay_dial(
            &client.id().to_public(),
            "*",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        // Capability-only relay is server-auth-only at TLS — dial without a client cert.
        let client_ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (_app, app_far) = tokio::io::duplex(64 * 1024);
        let res = forward_flow(
            app_far,
            &client_ep,
            relay_addr,
            &client,
            egress_id,
            DialRequest {
                service: "evil/arbitrary-target".into(),
                token,
                e2ee: true,
            },
            PathMode::Relay,
        )
        .await;
        assert!(
            matches!(
                res,
                Err(NetError::DialRejected(
                    boatramp_overlay_proto::dial::DialReject::ServiceNotAuthorized
                ))
            ),
            "the relay must refuse an unconfigured service even with a wildcard cap, got {res:?}"
        );
    }

    // ---- Reverse ingress (`boatramp expose`) ----

    /// Spin up a capability-only relay that ACCEPTS exposers, with an EMPTY static egress map — so the
    /// registry is the only forwarding source (any reachable service was published, never configured).
    fn spawn_ingress_relay(
        relay: &OverlaySecret,
        root_pub: TokenPublicKey,
        registry: ExposerRegistry,
    ) -> SocketAddr {
        let relay_ep =
            quic::server_endpoint(relay, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = relay_ep.local_addr().unwrap();
        let relay_secret = OverlaySecret::from_seed_hex(&relay.seed_hex()).unwrap();
        tokio::spawn(run_ingress_router(
            relay_ep,
            relay_secret,
            root_pub,
            RelayClientAuth::CapabilityOnly,
            registry,
            |_s: &str| None::<(SocketAddr, OverlayId, bool)>,
        ));
        addr
    }

    /// A TCP echo backend; returns its address.
    async fn spawn_echo_backend() -> SocketAddr {
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    /// Run the exposer runtime for `service` → `backend` against a relay, returning the future (so a
    /// test can either spawn it to stay live, or await it to assert a registration failure).
    async fn run_exposer(
        exposer: &OverlaySecret,
        relay_addr: SocketAddr,
        relay_id: OverlayId,
        service: &str,
        publish_cap: String,
        backend: SocketAddr,
        trust_root: TokenPublicKey,
    ) -> Result<(), NetError> {
        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let svc = service.to_string();
        let svc_for_backend = svc.clone();
        run_published_service(
            &ep,
            relay_addr,
            relay_id,
            exposer,
            svc,
            publish_cap,
            move |s: &str| (s == svc_for_backend.as_str()).then_some(backend),
            trust_root,
            true,
            || {},
        )
        .await
    }

    /// Wait (bounded) until `service` is live in the registry.
    async fn await_registered(registry: &ExposerRegistry, service: &str) -> bool {
        for _ in 0..100 {
            if registry.is_registered(service, now_unix()).await {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        false
    }

    /// Reverse-ingress "done": a LOCAL service PUBLISHED into the cluster via `run_published_service`
    /// (the exposer dials the relay OUTBOUND, registers under a holder-proven publish capability) is
    /// reachable by a cluster-side `forward_flow svc/db` through the SAME relay's `run_ingress_router`
    /// — the relay opens a per-flow stream DOWN the parked connection and bridges it to the client,
    /// blind. End-to-end E2EE client↔exposer, capability-gated at BOTH the dial (client) and the
    /// publish (exposer). This is the whole inversion, over the served roles.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn expose_registers_and_a_forward_reaches_the_published_backend() {
        use boatramp_core::cose::mint_overlay_publish;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root = OverlaySecret::generate().unwrap(); // dial + publish trust root
        let client = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let exposer = OverlaySecret::generate().unwrap();
        let (relay_id, exposer_id) = (relay.id(), exposer.id());
        let root_pub = root.id().to_public();

        let backend_addr = spawn_echo_backend().await;
        let registry = ExposerRegistry::new();
        let relay_addr = spawn_ingress_relay(&relay, root_pub.clone(), registry.clone());

        // Exposer publishes svc/db (holder = the exposer's own identity).
        let publish_cap = mint_overlay_publish(
            &exposer.id().to_public(),
            "svc/db",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        {
            let exposer = OverlaySecret::from_seed_hex(&exposer.seed_hex()).unwrap();
            let root_pub = root_pub.clone();
            tokio::spawn(async move {
                let _ = run_exposer(
                    &exposer,
                    relay_addr,
                    relay_id,
                    "svc/db",
                    publish_cap,
                    backend_addr,
                    root_pub,
                )
                .await;
            });
        }
        assert!(
            await_registered(&registry, "svc/db").await,
            "the exposer must register svc/db with the relay"
        );

        // Forward client: capability-gated dial to svc/db, pinning the EXPOSER as the E2EE peer.
        let dial_cap = mint_overlay_dial(
            &client.id().to_public(),
            "svc/db",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        let client_ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (mut app, app_far) = tokio::io::duplex(64 * 1024);
        let fwd = tokio::spawn(async move {
            forward_flow(
                app_far,
                &client_ep,
                relay_addr,
                &client,
                exposer_id,
                DialRequest {
                    service: "svc/db".into(),
                    token: dial_cap,
                    e2ee: true,
                },
                PathMode::Relay,
            )
            .await
        });
        app.write_all(b"reach the exposed local service")
            .await
            .unwrap();
        app.shutdown().await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            app.read_to_end(&mut got),
        )
        .await
        .expect("the exposed backend echoes through the registry in time")
        .unwrap();
        assert_eq!(got, b"reach the exposed local service");
        let _ = fwd.await;
    }

    /// Negative (a): a registration with NO valid / WRONG-service publish capability is refused. A cap
    /// whose scope names a different service → `ScopeMismatch`; a bogus (unsigned) cap →
    /// `InvalidCapability`. (Without the scope/verify checks this would register, so the gate is
    /// load-bearing — the relay would otherwise publish an unauthorized name.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn register_with_a_wrong_scope_or_bogus_publish_cap_is_refused() {
        use boatramp_core::cose::mint_overlay_publish;

        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let exposer = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let root_pub = root.id().to_public();
        let backend_addr = spawn_echo_backend().await;
        let registry = ExposerRegistry::new();
        let relay_addr = spawn_ingress_relay(&relay, root_pub.clone(), registry.clone());

        // (a1) A VALID cap, but scoped to svc/other while registering svc/db.
        let wrong_scope = mint_overlay_publish(
            &exposer.id().to_public(),
            "svc/other",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        let res = run_exposer(
            &exposer,
            relay_addr,
            relay_id,
            "svc/db",
            wrong_scope,
            backend_addr,
            root_pub.clone(),
        )
        .await;
        assert!(
            matches!(
                res,
                Err(NetError::RegistrationRejected(
                    RegisterReject::ScopeMismatch
                ))
            ),
            "a publish cap scoped to a different service must be refused, got {res:?}"
        );

        // (a2) A bogus (unsigned) publish cap.
        let res2 = run_exposer(
            &exposer,
            relay_addr,
            relay_id,
            "svc/db",
            "not-a-cose-publish-capability".into(),
            backend_addr,
            root_pub.clone(),
        )
        .await;
        assert!(
            matches!(
                res2,
                Err(NetError::RegistrationRejected(
                    RegisterReject::InvalidCapability(_)
                ))
            ),
            "a bogus publish cap must be refused, got {res2:?}"
        );
        // Neither registration landed → the name is NOT published.
        assert!(
            !registry.is_registered("svc/db", now_unix()).await,
            "a refused registration must not publish the name"
        );
    }

    /// Negative (b), the HOLDER-BINDING core: a VALID publish cap minted for holder X, but presented by
    /// a DIFFERENT identity Y (a stolen capability), is refused. The relay's E2EE handshake proves Y's
    /// identity; `verified.holder (X) != proven (Y)` → `HolderMismatch`. Without the holder check a
    /// stolen cap would let any identity publish the name — this is the load-bearing control.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn register_with_a_stolen_cap_whose_holder_is_not_the_presenter_is_refused() {
        use boatramp_core::cose::mint_overlay_publish;

        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let holder = OverlaySecret::generate().unwrap(); // the cap is minted FOR this identity
        let thief = OverlaySecret::generate().unwrap(); // but THIS identity presents it
        let relay_id = relay.id();
        let root_pub = root.id().to_public();
        let backend_addr = spawn_echo_backend().await;
        let registry = ExposerRegistry::new();
        let relay_addr = spawn_ingress_relay(&relay, root_pub.clone(), registry.clone());

        // A legitimately-minted cap, holder = `holder`, scope svc/db.
        let stolen = mint_overlay_publish(
            &holder.id().to_public(),
            "svc/db",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        // `thief` presents it — the handshake proves `thief`, which is not the cap's holder.
        let res = run_exposer(
            &thief,
            relay_addr,
            relay_id,
            "svc/db",
            stolen,
            backend_addr,
            root_pub,
        )
        .await;
        assert!(
            matches!(
                res,
                Err(NetError::RegistrationRejected(
                    RegisterReject::HolderMismatch
                ))
            ),
            "a stolen publish cap presented by a non-holder identity must be refused, got {res:?}"
        );
        assert!(
            !registry.is_registered("svc/db", now_unix()).await,
            "a stolen-cap registration must not publish the name"
        );
    }

    /// Negative (c), name-collision: while one holder's registration is LIVE, a SECOND register of the
    /// same name — even with its OWN valid, holder-bound publish cap — is refused (`NameTaken`),
    /// first-live-claim-wins, never a silent takeover.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_second_live_registration_of_a_published_name_is_refused() {
        use boatramp_core::cose::mint_overlay_publish;

        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let exposer1 = OverlaySecret::generate().unwrap();
        let exposer2 = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let root_pub = root.id().to_public();
        let backend_addr = spawn_echo_backend().await;
        let registry = ExposerRegistry::new();
        let relay_addr = spawn_ingress_relay(&relay, root_pub.clone(), registry.clone());

        let cap1 = mint_overlay_publish(
            &exposer1.id().to_public(),
            "svc/db",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        let cap2 = mint_overlay_publish(
            &exposer2.id().to_public(),
            "svc/db",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();

        // First exposer registers and STAYS live.
        {
            let exposer1 = OverlaySecret::from_seed_hex(&exposer1.seed_hex()).unwrap();
            let root_pub = root_pub.clone();
            tokio::spawn(async move {
                let _ = run_exposer(
                    &exposer1,
                    relay_addr,
                    relay_id,
                    "svc/db",
                    cap1,
                    backend_addr,
                    root_pub,
                )
                .await;
            });
        }
        assert!(
            await_registered(&registry, "svc/db").await,
            "the first exposer must register svc/db"
        );

        // Second exposer, its OWN valid cap, same name, while the first is live → NameTaken.
        let res = run_exposer(
            &exposer2,
            relay_addr,
            relay_id,
            "svc/db",
            cap2,
            backend_addr,
            root_pub,
        )
        .await;
        assert!(
            matches!(
                res,
                Err(NetError::RegistrationRejected(RegisterReject::NameTaken))
            ),
            "a second live registration of a published name must be refused, got {res:?}"
        );
    }

    /// Negative (d), not-an-open-proxy: a forward to a name that is neither registered NOR statically
    /// configured is refused (`ServiceNotAuthorized`) — EVEN with a valid wildcard dial cap. The relay
    /// never opens a stream to a client-named target; only a registered, cap-verified exposer (or a
    /// configured egress) is reachable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn forward_to_an_unregistered_name_is_refused_no_open_proxy() {
        let root = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let egress_id = OverlaySecret::generate().unwrap().id();
        let root_pub = root.id().to_public();
        let registry = ExposerRegistry::new(); // nothing registered
        let relay_addr = spawn_ingress_relay(&relay, root_pub, registry);

        // A VALID WILDCARD dial cap — authorizes any service — yet the relay refuses an unknown name.
        let token = mint_overlay_dial(
            &client.id().to_public(),
            "*",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        let client_ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (_app, app_far) = tokio::io::duplex(64 * 1024);
        let res = forward_flow(
            app_far,
            &client_ep,
            relay_addr,
            &client,
            egress_id,
            DialRequest {
                service: "svc/never-published".into(),
                token,
                e2ee: true,
            },
            PathMode::Relay,
        )
        .await;
        assert!(
            matches!(
                res,
                Err(NetError::DialRejected(DialReject::ServiceNotAuthorized))
            ),
            "a forward to an unregistered name must be refused (no open proxy), got {res:?}"
        );
    }
}
