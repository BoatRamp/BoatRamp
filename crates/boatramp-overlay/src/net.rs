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

#[cfg(feature = "server")]
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use std::sync::Arc;
use std::time::Duration;

// `TokenPublicKey` is the dial trust-root both the client-edge terminator (`terminate_stream`, via
// `run_published_service`) and the server-side gate verify against; `verify_overlay_publish` is only
// the relay's registration path (`register_exposer`), so it is server-gated.
use boatramp_core::cose::TokenPublicKey;
#[cfg(feature = "server")]
use boatramp_core::cose::verify_overlay_publish;
use boatramp_overlay_proto::circuit::{DEFAULT_SEGMENT, DEFAULT_WINDOW};
// `authorize_dial` is shared (the client-edge terminator re-authorizes end-to-end); the
// capability-only variant is only the relay's `gate_dial`, so it is server-gated.
#[cfg(feature = "server")]
use boatramp_overlay_proto::dial::authorize_dial_capability_only;
use boatramp_overlay_proto::dial::{DialReject, DialRequest, DialVerdict, authorize_dial};
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
    #[error("pairing rendezvous refused by the relay: {0:?}")]
    PairRejected(PairReject),
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
/// Only the relay's dial gate (mutual-pin) and registration path read it, so it is server-gated.
#[cfg(feature = "server")]
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
    let (session, _egress, _sas) = establish(
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
#[cfg(feature = "server")]
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
#[cfg(feature = "server")]
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
#[cfg(feature = "server")]
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
#[cfg(feature = "server")]
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
#[cfg(feature = "server")]
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
        let (session, client_id, _sas) =
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
#[cfg(feature = "server")]
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
#[cfg(feature = "server")]
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
#[cfg(feature = "server")]
enum IngressFrame {
    /// An exposer registering a service (reverse ingress).
    Register(RegisterRequest),
    /// An accepter parking a pairing rendezvous (overlay follow-up #2, inc2).
    PairPark(PairParkRequest),
    /// A dialer redeeming a parked pairing rendezvous.
    PairRedeem(PairRedeemRequest),
    /// A forward client dialing a service.
    Dial(DialRequest),
}

/// Read and classify the first control frame: a registration (exposer) vs a dial (forward client).
/// The bare-`DialRequest` wire the existing client-edge sends is unchanged — a `Register` frame is
/// distinguished by its required `register` discriminator (tried first; it never matches a dial, and a
/// dial never matches it).
#[cfg(feature = "server")]
async fn read_ingress_frame(r: &mut (impl AsyncRead + Unpin)) -> Result<IngressFrame, NetError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_DIAL_MSG {
        return Err(NetError::TooLarge(n));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    // Try each discriminated frame first (each carries a required tag field a bare DialRequest lacks,
    // and vice versa); the bare-DialRequest wire the existing client-edge sends is unchanged.
    if let Ok(reg) = serde_json::from_slice::<RegisterRequest>(&buf)
        && reg.register == REGISTER_TAG
    {
        return Ok(IngressFrame::Register(reg));
    }
    if let Ok(park) = serde_json::from_slice::<PairParkRequest>(&buf)
        && park.pair_park == PAIR_PARK_TAG
    {
        return Ok(IngressFrame::PairPark(park));
    }
    if let Ok(redeem) = serde_json::from_slice::<PairRedeemRequest>(&buf)
        && redeem.pair_redeem == PAIR_REDEEM_TAG
    {
        return Ok(IngressFrame::PairRedeem(redeem));
    }
    Ok(IngressFrame::Dial(serde_json::from_slice(&buf)?))
}

/// One parked exposer registration.
#[cfg(feature = "server")]
struct ExposerEntry {
    /// The parked connection to the exposer (it dialed OUT; its register task holds it open). An
    /// `open_bi` on a clone surfaces a new accepted stream at the exposer's serve loop.
    conn: Connection,
    /// The exposer's E2EE-proven overlay identity, set ONCE at registration from the holder-binding
    /// (`register_exposer` requires `verified.holder == proven`, so this equals the publish
    /// capability's signed `cnf`). THE load-bearing pinning value: the control plane publishes THIS as
    /// the directory's `egress_id` over its authenticated response, and a forward client pins it as its
    /// E2EE `expect`. The data-plane relay never rewrites it, so it cannot influence what a forward
    /// client pins (see [`ExposerRegistry::exposer_id`]).
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
#[cfg(feature = "server")]
#[derive(Clone, Default)]
pub struct ExposerRegistry {
    inner: Arc<Mutex<BTreeMap<String, ExposerEntry>>>,
}

#[cfg(feature = "server")]
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

    /// The holder-bound overlay identity of the LIVE exposer publishing `service` (the value verified
    /// AT REGISTRATION via the holder-binding), or `None` if no live exposer publishes it.
    ///
    /// THE pinning seam (increment 2). The co-located control plane shares this registry and returns
    /// this identity as the `egress_id` of `POST /api/overlay/dial` for an exposed service, over its
    /// AUTHENTICATED response; the forward client pins THAT id as its E2EE `expect`. The value is set
    /// once at registration from the E2EE-proven, signature-bound holder key and is never rewritten on
    /// the data path — so the QUIC relay (the data plane) cannot influence what a forward client pins.
    /// If the relay later cross-wires a flow to a DIFFERENT exposer, the client's E2EE handshake fails
    /// closed (`IdentityMismatch`); it is never a silent cross-wire.
    pub async fn exposer_id(&self, service: &str, now: u64) -> Option<OverlayId> {
        let map = self.inner.lock().await;
        match map.get(service) {
            Some(e) if Self::entry_live(e, now) => Some(e.exposer_id),
            _ => None,
        }
    }

    /// Every LIVE exposer as `(service, exposer_id)` at `now` — the holder-bound identities the relay
    /// verified at registration. The control plane merges these into the service directory
    /// (`GET /api/overlay/services`); each entry's `exposer_id` is the id a forward client pins (see
    /// [`ExposerRegistry::exposer_id`]). Service-ordered (the map is a `BTreeMap`).
    pub async fn live_exposers(&self, now: u64) -> Vec<(String, OverlayId)> {
        let map = self.inner.lock().await;
        map.iter()
            .filter(|(_, e)| Self::entry_live(e, now))
            .map(|(svc, e)| (svc.clone(), e.exposer_id))
            .collect()
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
#[cfg(feature = "server")]
async fn refuse_registration(
    send: &mut SendStream,
    conn: &Connection,
    reason: RegisterReject,
) -> Result<(), NetError> {
    let _ = write_msg(send, &RegisterResult::Rejected(reason.clone())).await;
    let _ = timeout(wire::DIRECT_DRAIN, conn.closed()).await;
    Err(NetError::RegistrationRejected(reason))
}

#[cfg(feature = "server")]
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
        let (_session, peer, _sas) = establish(
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
#[cfg(feature = "server")]
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
#[cfg(feature = "server")]
pub async fn run_ingress_router<F>(
    endpoint: Endpoint,
    secret: OverlaySecret,
    trust_root: TokenPublicKey,
    client_auth: RelayClientAuth,
    registry: ExposerRegistry,
    rendezvous: PairRendezvous,
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
        let rendezvous = rendezvous.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_ingress_connection(
                conn,
                &relay_secret,
                &trust_root,
                client_auth,
                &registry,
                &rendezvous,
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
/// registration (exposer), pairing-rendezvous (park/redeem), or forwarding (client) path.
#[cfg(feature = "server")]
#[allow(clippy::too_many_arguments)]
async fn handle_ingress_connection<F>(
    conn: Connection,
    relay_secret: &OverlaySecret,
    trust_root: &TokenPublicKey,
    client_auth: RelayClientAuth,
    registry: &ExposerRegistry,
    rendezvous: &PairRendezvous,
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
        IngressFrame::PairPark(req) => park_rendezvous(conn, send, recv, req, rendezvous).await,
        IngressFrame::PairRedeem(req) => redeem_rendezvous(conn, send, recv, req, rendezvous).await,
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

// ======================================================================================
// Pairing rendezvous (`boatramp overlay pair` over the relay): meet two NAT'd peers blind.
//
// The structural SIBLING of reverse ingress. Two peers that cannot direct-dial each other both dial
// the SAME cluster relay OUTBOUND under a shared single-use `bropair1` rendezvous id: the ACCEPTER
// parks (the relay holds its connection, keyed by the id), the DIALER redeems (the relay matches the
// two, opens a per-flow bi-stream DOWN the parked connection, and bridges it to the dialer's stream,
// BLIND). The commit-then-reveal SAS pairing handshake (`pair::pair_handshake`) then runs end-to-end
// over the bridge — accepter = Responder, dialer = Initiator — UNCHANGED, so the relay holds no keys/
// nonces/SAS and a tampering/misrouting relay is still caught by the SAS divergence it defends against.
//
// Hardening: the rendezvous id is SINGLE-USE (a redeem CONSUMES the parked entry; a second redeem
// finds nothing) and short-TTL (a parked entry expires in minutes, and a never-redeemed park is reaped
// so it cannot hold a slot); the ingress accept loop's `MAX_INFLIGHT_FLOWS` Semaphore bounds concurrent
// rendezvous exactly as it bounds forward/expose flows, and `HANDSHAKE_TIMEOUT` bounds the pre-park
// first-frame phase (a half-open connection cannot park a slot). The `Overlay·Admin` gate lives on the
// control-plane MINT (who may obtain a rendezvous), never on redemption — the unpaired peer is by
// design not membership-gated; the SAS backstops it.
// ======================================================================================

/// The discriminator marking a [`PairParkRequest`] frame (the accepter PARKING at the relay), so the
/// ingress router tells it from a `Register`/`Dial`/`PairRedeem` first frame without changing the wire.
const PAIR_PARK_TAG: &str = "overlay-pair-park";
/// The discriminator marking a [`PairRedeemRequest`] frame (the dialer REDEEMING a parked rendezvous).
const PAIR_REDEEM_TAG: &str = "overlay-pair-redeem";

/// How long a parked pairing rendezvous lives at the relay before it is reaped (minutes): long enough
/// for an operator to share the `bropair1` code and the peer to redeem it, short enough that a leaked/
/// abandoned code cannot stand open. Bounds a never-redeemed park's hold on a `MAX_INFLIGHT_FLOWS`
/// Semaphore slot (the park connection is force-closed once this elapses with no redeem).
#[cfg(feature = "server")]
const PAIR_RENDEZVOUS_TTL_SECS: u64 = 300;

/// What a peer sends as the FIRST control frame to PARK a pairing rendezvous (the accepter side).
/// Distinguished from a `DialRequest`/`RegisterRequest`/`PairRedeemRequest` by its required
/// `pair_park` discriminator (a dial/register/redeem frame never carries it, and vice versa).
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
struct PairParkRequest {
    /// Always [`PAIR_PARK_TAG`].
    pair_park: String,
    /// The rendezvous id (the relay's registry key) — the core of a `bropair1` code.
    code: Vec<u8>,
}

/// What a peer sends as the FIRST control frame to REDEEM a parked pairing rendezvous (the dialer
/// side). The relay matches `code` to a parked accepter and bridges the two streams blind; the
/// remaining bytes on THIS stream are the end-to-end pairing handshake, which the relay forwards
/// untouched.
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
struct PairRedeemRequest {
    /// Always [`PAIR_REDEEM_TAG`].
    pair_redeem: String,
    /// The rendezvous id to redeem — must match a live parked entry.
    code: Vec<u8>,
}

/// Why a pairing park/redeem was refused by the relay (returned to the peer).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum PairReject {
    /// A live rendezvous is ALREADY parked under this id (first-park-wins; never a silent takeover) —
    /// returned to a PARK.
    CodeInUse,
    /// No live parked rendezvous for this id — never parked, already redeemed (single-use), or expired
    /// — returned to a REDEEM.
    UnknownOrSpent,
}

/// The relay's verdict on a pairing park/redeem (the first frame back to the peer).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
enum PairResult {
    /// Parked / matched — proceed to the handshake.
    Ok,
    /// Refused — the peer has its reason.
    Rejected(PairReject),
}

/// Client-side: PARK at `relay` for a pairing rendezvous under `code` (the accepter). Dials the relay
/// (server-auth, pinning it — the parker is NOT membership-gated), sends the park request, and on the
/// relay's `Ok` accepts the ONE bridged pairing stream the relay opens DOWN this connection when a
/// dialer redeems the code. Returns the held [`Connection`] (keep it alive for the handshake) plus the
/// bridged `(send, recv)` to run `pair_handshake(Responder)` over. The wait for a redeemer is bounded
/// by the relay's rendezvous TTL (it force-closes the parked connection when the TTL elapses with no
/// redeem, surfacing here as a connection error).
pub async fn pair_relay_park(
    relay: &Endpoint,
    relay_addr: SocketAddr,
    code: Vec<u8>,
) -> Result<(Connection, SendStream, RecvStream), NetError> {
    let conn = quic::dial(relay, relay_addr).await?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| NetError::Stream(e.to_string()))?;
    write_msg(
        &mut send,
        &PairParkRequest {
            pair_park: PAIR_PARK_TAG.to_string(),
            code,
        },
    )
    .await?;
    match read_msg::<PairResult>(&mut recv).await? {
        PairResult::Ok => {}
        PairResult::Rejected(reason) => return Err(NetError::PairRejected(reason)),
    }
    // The relay opens the bridged pairing stream down this connection only once a dialer redeems the
    // code; `accept_bi` unblocks on the relay's first bridged write (the dialer's handshake offer).
    let (bridged_send, bridged_recv) = conn
        .accept_bi()
        .await
        .map_err(|e| NetError::Stream(e.to_string()))?;
    Ok((conn, bridged_send, bridged_recv))
}

/// Client-side: REDEEM a parked pairing rendezvous `code` at `relay` (the dialer). Dials the relay
/// (server-auth, pinning it), sends the redeem request, and on the relay's `Ok` returns the held
/// [`Connection`] + the `(send, recv)` the relay bridges to the parked accepter — run
/// `pair_handshake(Initiator)` over them. A refusal (`UnknownOrSpent`) is single-use/TTL/typo —
/// fail-closed.
pub async fn pair_relay_redeem(
    relay: &Endpoint,
    relay_addr: SocketAddr,
    code: Vec<u8>,
) -> Result<(Connection, SendStream, RecvStream), NetError> {
    let conn = quic::dial(relay, relay_addr).await?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| NetError::Stream(e.to_string()))?;
    write_msg(
        &mut send,
        &PairRedeemRequest {
            pair_redeem: PAIR_REDEEM_TAG.to_string(),
            code,
        },
    )
    .await?;
    match read_msg::<PairResult>(&mut recv).await? {
        PairResult::Ok => {}
        PairResult::Rejected(reason) => return Err(NetError::PairRejected(reason)),
    }
    Ok((conn, send, recv))
}

/// One parked pairing rendezvous.
#[cfg(feature = "server")]
struct PairEntry {
    /// The parked accepter connection (it dialed OUT; its park task holds it open). A `redeem` opens a
    /// per-flow bi-stream down a clone and bridges the dialer to it, blind.
    conn: Connection,
    /// When this parked rendezvous expires (Unix seconds): single-use TTL — a redeem after this, or of
    /// an already-consumed id, finds nothing.
    expires_at: u64,
}

/// A relay-side registry of parked pairing rendezvous, keyed by the single-use rendezvous id. The
/// SIBLING of [`ExposerRegistry`]: a parked peer is an OUTBOUND-dialed, held connection, and a redeem
/// opens a per-flow bi-stream DOWN it and bridges blind — the relay never dials a peer-named address,
/// so the not-an-open-proxy property holds. Unlike the exposer registry a rendezvous is SINGLE-USE
/// (consumed on redeem) and short-TTL; in-memory and single-node for this increment (KV-durable
/// restart-survival is a later increment). Cheap to clone (an `Arc` handle).
#[cfg(feature = "server")]
#[derive(Clone, Default)]
pub struct PairRendezvous {
    inner: Arc<Mutex<BTreeMap<Vec<u8>, PairEntry>>>,
}

#[cfg(feature = "server")]
impl PairRendezvous {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `entry` is still a live rendezvous at `now`: its connection is open AND unexpired.
    fn entry_live(entry: &PairEntry, now: u64) -> bool {
        entry.conn.close_reason().is_none() && now < entry.expires_at
    }

    /// Try to PARK `conn` under `code` until `expires_at` (FIRST-PARK-WINS): refuse if a LIVE entry
    /// already holds the id — never a silent takeover. A dead/expired entry is replaced. `true` on
    /// success.
    async fn try_park(&self, code: Vec<u8>, conn: Connection, expires_at: u64, now: u64) -> bool {
        let mut map = self.inner.lock().await;
        if let Some(existing) = map.get(&code)
            && Self::entry_live(existing, now)
        {
            return false; // a live rendezvous already holds this id
        }
        map.insert(code, PairEntry { conn, expires_at });
        true
    }

    /// REDEEM (CONSUME — single-use) the live parked connection for `code`, REMOVING it so a second
    /// redeem of the same id finds nothing. `None` if no live parked entry exists (never parked,
    /// already redeemed, or expired); a dead/expired entry is pruned.
    async fn redeem(&self, code: &[u8], now: u64) -> Option<Connection> {
        let mut map = self.inner.lock().await;
        match map.get(code) {
            Some(e) if Self::entry_live(e, now) => map.remove(code).map(|e| e.conn),
            Some(_) => {
                map.remove(code); // prune the dead/expired entry
                None
            }
            None => None,
        }
    }

    /// Release `code` IFF the stored entry is still `conn` — so a newer re-park of the id (or a redeem
    /// that already consumed it) is never clobbered when the older park task finally exits.
    async fn release(&self, code: &[u8], conn: &Connection) {
        let mut map = self.inner.lock().await;
        if let Some(existing) = map.get(code)
            && existing.conn.stable_id() == conn.stable_id()
        {
            map.remove(code);
        }
    }

    /// Whether a live rendezvous is currently parked under `code` at `now` (test/diagnostic helper).
    pub async fn is_parked(&self, code: &[u8], now: u64) -> bool {
        let map = self.inner.lock().await;
        map.get(code).is_some_and(|e| Self::entry_live(e, now))
    }
}

/// Relay pairing: PARK one accepter under its rendezvous id. No relay E2EE handshake — the relay is
/// blind; the rendezvous id (the `bropair1` code's core) is the only credential, and the SAS backstops
/// the pairing. Parks the connection, acks, then HOLDS it (bounded by the rendezvous TTL) so a redeem
/// can open the bridged pairing stream down it; on the TTL with no redeem it force-closes the parked
/// connection (freeing the Semaphore slot the accept loop holds) and releases the id.
#[cfg(feature = "server")]
async fn park_rendezvous(
    conn: Connection,
    mut send: SendStream,
    _recv: RecvStream,
    req: PairParkRequest,
    registry: &PairRendezvous,
) -> Result<(), NetError> {
    if req.code.is_empty() {
        let _ = write_msg(&mut send, &PairResult::Rejected(PairReject::CodeInUse)).await;
        return Err(NetError::Stream("empty pairing rendezvous id".into()));
    }
    let now = now_unix();
    let expires_at = now.saturating_add(PAIR_RENDEZVOUS_TTL_SECS);
    if !registry
        .try_park(req.code.clone(), conn.clone(), expires_at, now)
        .await
    {
        // A live rendezvous already holds this id — first-park-wins, never a silent takeover.
        let _ = write_msg(&mut send, &PairResult::Rejected(PairReject::CodeInUse)).await;
        let _ = timeout(wire::DIRECT_DRAIN, conn.closed()).await;
        return Err(NetError::PairRejected(PairReject::CodeInUse));
    }
    write_msg(&mut send, &PairResult::Ok).await?;
    tracing::info!("overlay relay: pairing rendezvous parked");
    // Hold until the connection drops (the accepter finished the bridged handshake and closed, or
    // aborted) OR the TTL elapses with no redeem — then force-close to free the accept-loop slot.
    if timeout(
        std::time::Duration::from_secs(PAIR_RENDEZVOUS_TTL_SECS),
        conn.closed(),
    )
    .await
    .is_err()
    {
        conn.close(0u32.into(), b"pair rendezvous expired");
    }
    registry.release(&req.code, &conn).await;
    Ok(())
}

/// Relay pairing: REDEEM a parked rendezvous for the dialer. Matches `code` to a live parked accepter
/// connection (CONSUMING it — single-use), opens a per-flow bi-stream DOWN the parked connection, and
/// bridges the dialer's stream to it BLIND. The end-to-end pairing handshake flows through untouched;
/// the relay holds no keys/nonces/SAS. An unmatched id is refused (`UnknownOrSpent`).
#[cfg(feature = "server")]
async fn redeem_rendezvous(
    client: Connection,
    mut client_send: SendStream,
    client_recv: RecvStream,
    req: PairRedeemRequest,
    registry: &PairRendezvous,
) -> Result<(), NetError> {
    let Some(parked) = registry.redeem(&req.code, now_unix()).await else {
        write_msg(
            &mut client_send,
            &PairResult::Rejected(PairReject::UnknownOrSpent),
        )
        .await?;
        let _ = timeout(wire::DIRECT_DRAIN, client.closed()).await;
        return Err(NetError::PairRejected(PairReject::UnknownOrSpent));
    };
    // Open a per-flow bi-stream DOWN the parked accepter connection; bridge the dialer to it, blind.
    let (parked_send, parked_recv) = parked
        .open_bi()
        .await
        .map_err(|e| NetError::Stream(e.to_string()))?;
    write_msg(&mut client_send, &PairResult::Ok).await?;
    tracing::info!("overlay relay: pairing rendezvous matched (bridging blind)");
    bridge(client_recv, client_send, parked_recv, parked_send).await?;
    let _ = timeout(wire::DIRECT_DRAIN, client.closed()).await;
    Ok(())
}

// The integration tests drive full relay↔egress↔client verticals, so they exercise the server roles
// and build only when the `server` feature is on (the usual `--all-features` / `--features server`
// test run). A client-only `cargo test -p boatramp-overlay` compiles the lib and skips them.
#[cfg(all(test, feature = "server"))]
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
        spawn_ingress_relay_with_rendezvous(relay, root_pub, registry, PairRendezvous::new())
    }

    /// As [`spawn_ingress_relay`], but with a caller-supplied [`PairRendezvous`] so the pairing tests
    /// can share + inspect the relay's rendezvous registry.
    fn spawn_ingress_relay_with_rendezvous(
        relay: &OverlaySecret,
        root_pub: TokenPublicKey,
        registry: ExposerRegistry,
        rendezvous: PairRendezvous,
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
            rendezvous,
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

    // ---- The PINNING constraint (increment 2): the forward client pins the exposer identity the
    // control plane published (the registration-verified `exposer_id`), delivered over the
    // AUTHENTICATED control-plane response — never a data-plane relay-asserted value. ----

    /// PINNING (a): a (zero-flag) forward to an exposed service pins the CONTROL-PLANE-returned
    /// exposer id and reaches the exposer. The exposer registers svc/db under a holder-bound publish
    /// capability; the forward client pins the id the shared `ExposerRegistry` resolves for svc/db —
    /// which is EXACTLY the `egress_id` the authenticated `POST /api/overlay/dial` returns (the
    /// co-located control plane shares this registry) — and the flow reaches the exposed backend.
    /// Proves the registration-verified `exposer_id` is the correct E2EE pin, end-to-end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn exposed_forward_pins_the_control_plane_exposer_id_and_reaches_it() {
        use boatramp_core::cose::mint_overlay_publish;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let exposer = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let root_pub = root.id().to_public();

        let backend_addr = spawn_echo_backend().await;
        let registry = ExposerRegistry::new();
        let relay_addr = spawn_ingress_relay(&relay, root_pub.clone(), registry.clone());

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
            "the exposer must register svc/db"
        );

        // Source the pin EXACTLY as the authenticated control plane does — from the SHARED registry.
        // This value IS the `egress_id` `POST /api/overlay/dial` returns for the exposed service.
        let pinned = registry
            .exposer_id("svc/db", now_unix())
            .await
            .expect("the directory resolves the exposed service to its holder-bound exposer id");

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
                pinned,
                DialRequest {
                    service: "svc/db".into(),
                    token: dial_cap,
                    e2ee: true,
                },
                PathMode::Relay,
            )
            .await
        });
        app.write_all(b"reach the control-plane-pinned exposer")
            .await
            .unwrap();
        app.shutdown().await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            app.read_to_end(&mut got),
        )
        .await
        .expect("the control-plane-pinned exposer echoes in time")
        .unwrap();
        assert_eq!(got, b"reach the control-plane-pinned exposer");
        let _ = fwd.await;
    }

    /// PINNING (b): a relay that CROSS-WIRES a flow to a DIFFERENT exposer than the directory
    /// published fails the client's E2EE pin — fail-closed, never a silent cross-wire. Exposer A
    /// registers svc/db, so the shared registry (the directory source) publishes A's holder-bound id.
    /// A SEPARATE, MISROUTING relay accepts the client's svc/db dial but bridges blind to a DIFFERENT
    /// exposer B serving the same backend. A **positive control** proves the relay really reaches B
    /// (pinning the DATA-PLANE target B succeeds — which is exactly the silent cross-wire we must
    /// prevent); then pinning the CONTROL-PLANE-published id (A, from the registry) makes the client's
    /// E2EE handshake with B fail `IdentityMismatch`. So a forward MUST pin the control-plane id, and
    /// the QUIC data plane can never substitute the peer. (Were the pinned id taken from the relay/
    /// data path instead of the authenticated control-plane response, the cross-wire would succeed —
    /// which is precisely the impersonation this test rules out.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_relay_cross_wiring_to_a_different_exposer_fails_the_e2ee_pin() {
        use boatramp_core::cose::mint_overlay_publish;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let ingress = OverlaySecret::generate().unwrap(); // the honest ingress relay A registers with
        let misrelay = OverlaySecret::generate().unwrap(); // the MISROUTING relay the client dials
        let exposer_a = OverlaySecret::generate().unwrap();
        let exposer_b = OverlaySecret::generate().unwrap();
        let (ingress_id, misrelay_id, exposer_b_id) = (ingress.id(), misrelay.id(), exposer_b.id());
        let root_pub = root.id().to_public();

        let backend_addr = spawn_echo_backend().await;

        // Exposer A registers svc/db with the HONEST ingress relay → the registry (the DIRECTORY
        // SOURCE) publishes A's holder-bound id for svc/db.
        let registry = ExposerRegistry::new();
        let ingress_addr = spawn_ingress_relay(&ingress, root_pub.clone(), registry.clone());
        let publish_cap = mint_overlay_publish(
            &exposer_a.id().to_public(),
            "svc/db",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        {
            let exposer_a = OverlaySecret::from_seed_hex(&exposer_a.seed_hex()).unwrap();
            let root_pub = root_pub.clone();
            tokio::spawn(async move {
                let _ = run_exposer(
                    &exposer_a,
                    ingress_addr,
                    ingress_id,
                    "svc/db",
                    publish_cap,
                    backend_addr,
                    root_pub,
                )
                .await;
            });
        }
        assert!(await_registered(&registry, "svc/db").await);
        let published = registry
            .exposer_id("svc/db", now_unix())
            .await
            .expect("the directory published svc/db → exposer A");
        assert_eq!(
            published,
            exposer_a.id(),
            "the directory publishes exposer A's holder-bound id"
        );

        // Exposer B: a DIFFERENT identity serving the SAME backend for svc/db (a plain egress).
        let egress_ep =
            quic::server_endpoint(&exposer_b, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
        let exposer_b_addr = egress_ep.local_addr().unwrap();
        {
            let exposer_b = OverlaySecret::from_seed_hex(&exposer_b.seed_hex()).unwrap();
            let root_pub = root_pub.clone();
            tokio::spawn(run_egress_router(
                egress_ep,
                exposer_b,
                move |s: &str| (s == "svc/db").then_some(backend_addr),
                root_pub,
                true,
                PathMode::Relay,
            ));
        }

        // A MISROUTING relay: it accepts the client's svc/db dial but bridges blind to exposer B, NOT
        // to the registered exposer A the directory published.
        let misrelay_ep =
            quic::server_endpoint(&misrelay, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
        let misrelay_addr = misrelay_ep.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok(Some(conn)) = quic::accept(&misrelay_ep).await {
                tokio::spawn(async move {
                    let Ok((mut cs, mut cr)) = conn.accept_bi().await else {
                        return;
                    };
                    let Ok(_req) = read_msg::<DialRequest>(&mut cr).await else {
                        return;
                    };
                    if write_msg(&mut cs, &DialVerdict::Accept { scope: "*".into() })
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let Ok(ep) = quic::client_endpoint_server_auth(&Pin(exposer_b_id)) else {
                        return;
                    };
                    let Ok(ec) = quic::dial(&ep, exposer_b_addr).await else {
                        return;
                    };
                    let Ok((es, er)) = ec.open_bi().await else {
                        return;
                    };
                    let _ = bridge(cr, cs, er, es).await;
                });
            }
        });

        let dial_cap = mint_overlay_dial(
            &client.id().to_public(),
            "svc/db",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        let client_seed = client.seed_hex();

        // Positive control — pin the DATA-PLANE target (exposer B's id). The flow SUCCEEDS: the relay
        // really reaches B, so pinning B (a value the data plane could assert) would be a SILENT
        // cross-wire. This is the attack the control-plane pin must prevent.
        {
            let client = OverlaySecret::from_seed_hex(&client_seed).unwrap();
            let client_ep = quic::client_endpoint_server_auth(&Pin(misrelay_id)).unwrap();
            let (mut app, app_far) = tokio::io::duplex(64 * 1024);
            let dial_cap = dial_cap.clone();
            let fwd = tokio::spawn(async move {
                forward_flow(
                    app_far,
                    &client_ep,
                    misrelay_addr,
                    &client,
                    exposer_b_id,
                    DialRequest {
                        service: "svc/db".into(),
                        token: dial_cap,
                        e2ee: true,
                    },
                    PathMode::Relay,
                )
                .await
            });
            app.write_all(b"the data-plane target would echo if pinned")
                .await
                .unwrap();
            app.shutdown().await.unwrap();
            let mut got = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                app.read_to_end(&mut got),
            )
            .await
            .expect("the data-plane target echoes — the relay really reaches exposer B")
            .unwrap();
            assert_eq!(got, b"the data-plane target would echo if pinned");
            let _ = fwd.await;
        }

        // The real property — pin the CONTROL-PLANE-published id (A). The client's E2EE handshake with
        // B (whom the relay cross-wired to) fails CLOSED on the pin: IdentityMismatch, no bytes cross.
        {
            let client = OverlaySecret::from_seed_hex(&client_seed).unwrap();
            let client_ep = quic::client_endpoint_server_auth(&Pin(misrelay_id)).unwrap();
            let (mut app, app_far) = tokio::io::duplex(64 * 1024);
            let fwd = tokio::spawn(async move {
                forward_flow(
                    app_far,
                    &client_ep,
                    misrelay_addr,
                    &client,
                    published, // the control-plane-published id (A), not the data-plane target (B)
                    DialRequest {
                        service: "svc/db".into(),
                        token: dial_cap,
                        e2ee: true,
                    },
                    PathMode::Relay,
                )
                .await
            });
            let _ = app
                .write_all(b"must never reach a cross-wired exposer")
                .await;
            drop(app);
            let outcome = fwd.await.unwrap();
            let err = outcome.expect_err(
                "pinning the control-plane id MUST fail closed when the relay cross-wires to a \
                 different exposer",
            );
            assert!(
                matches!(err, NetError::Splice(_)),
                "the failure must be the E2EE pin (not a transport/dial error), got {err:?}"
            );
            assert!(
                err.to_string().contains("pinned identity"),
                "the failure must be an IdentityMismatch (fail-closed E2EE pin), got: {err}"
            );
        }
    }

    // ---- Pairing rendezvous (overlay follow-up #2, inc2) ----

    use crate::pair::pair_handshake;
    use boatramp_overlay_proto::e2ee::Role;

    /// Wait (bounded) until a rendezvous `code` is live in the relay's registry.
    async fn await_parked(rendezvous: &PairRendezvous, code: &[u8]) -> bool {
        for _ in 0..100 {
            if rendezvous.is_parked(code, now_unix()).await {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        false
    }

    const PAIR_DL: std::time::Duration = std::time::Duration::from_secs(10);

    /// Full rendezvous "done": two peers that never direct-dial each other meet THROUGH the relay —
    /// the accepter PARKS a `bropair1` rendezvous id, the dialer REDEEMS it, the relay matches + bridges
    /// BLIND, and the commit-then-reveal SAS pairing handshake runs end-to-end over the bridge. Both
    /// derive the SAME SAS and learn each other's E2EE-proven identity (the inc1 handshake assertions,
    /// now over the relay-bridged transport). This is the whole increment, over the served relay role.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_peers_pair_through_the_relay_rendezvous_and_derive_the_same_sas() {
        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let accepter = OverlaySecret::generate().unwrap();
        let dialer = OverlaySecret::generate().unwrap();
        let (relay_id, accepter_id, dialer_id) = (relay.id(), accepter.id(), dialer.id());
        let root_pub = root.id().to_public();

        let rendezvous = PairRendezvous::new();
        let relay_addr = spawn_ingress_relay_with_rendezvous(
            &relay,
            root_pub,
            ExposerRegistry::new(),
            rendezvous.clone(),
        );
        let code = vec![0xABu8; 16];

        // Accepter: park the code, then run the handshake as Responder over the bridged stream.
        let code_a = code.clone();
        let acc = tokio::spawn(async move {
            let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
            let (conn, mut send, mut recv) =
                pair_relay_park(&ep, relay_addr, code_a).await.unwrap();
            let out = pair_handshake(&mut send, &mut recv, &accepter, Role::Responder, PAIR_DL)
                .await
                .unwrap();
            conn.closed().await; // hold the parked connection until the dialer finishes
            out
        });

        assert!(
            await_parked(&rendezvous, &code).await,
            "the accepter must park the rendezvous at the relay"
        );

        // Dialer: redeem the code, then run the handshake as Initiator over the matched stream.
        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (dconn, mut dsend, mut drecv) = pair_relay_redeem(&ep, relay_addr, code.clone())
            .await
            .unwrap();
        let (sas_d, peer_d) =
            pair_handshake(&mut dsend, &mut drecv, &dialer, Role::Initiator, PAIR_DL)
                .await
                .unwrap();
        dconn.close(0u32.into(), b"paired");

        let (sas_a, peer_a) = acc.await.unwrap();
        assert_eq!(sas_a.bits(), sas_d.bits(), "both ends derive the same SAS");
        assert_eq!(sas_a.words(), sas_d.words());
        assert_eq!(
            peer_a, dialer_id,
            "the accepter learned the dialer's proven id"
        );
        assert_eq!(
            peer_d, accepter_id,
            "the dialer learned the accepter's proven id"
        );
        // Single-use: the matched rendezvous was consumed on redeem.
        assert!(
            !rendezvous.is_parked(&code, now_unix()).await,
            "a redeemed rendezvous must be consumed (single-use)"
        );
    }

    /// Single-use (mutation-RED against dropping the `map.remove` in `PairRendezvous::redeem`): a
    /// SECOND redeem of an already-redeemed rendezvous id is refused `UnknownOrSpent` — the parked
    /// entry was consumed by the first redeem, never re-served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_second_redeem_of_a_spent_pairing_code_is_refused() {
        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let accepter = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let root_pub = root.id().to_public();

        let rendezvous = PairRendezvous::new();
        let relay_addr = spawn_ingress_relay_with_rendezvous(
            &relay,
            root_pub,
            ExposerRegistry::new(),
            rendezvous.clone(),
        );
        let code = vec![0x11u8; 16];

        let code_a = code.clone();
        let acc = tokio::spawn(async move {
            let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
            let (conn, mut send, mut recv) =
                pair_relay_park(&ep, relay_addr, code_a).await.unwrap();
            let _ = pair_handshake(&mut send, &mut recv, &accepter, Role::Responder, PAIR_DL).await;
            conn.closed().await;
        });
        assert!(await_parked(&rendezvous, &code).await);

        // First redeem consumes the rendezvous.
        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let first = pair_relay_redeem(&ep, relay_addr, code.clone()).await;
        assert!(
            first.is_ok(),
            "the first redeem must match the parked rendezvous"
        );

        // Second redeem of the SAME id finds nothing — refused.
        let ep2 = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let second = pair_relay_redeem(&ep2, relay_addr, code.clone()).await;
        assert!(
            matches!(
                second,
                Err(NetError::PairRejected(PairReject::UnknownOrSpent))
            ),
            "a second redeem of a spent rendezvous must be refused, got {second:?}"
        );
        let _ = acc.await;
    }

    /// Registry invariants (mutation-RED, no transport): single-use consumption, the short TTL, and
    /// first-park-wins. `redeem` with `now >= expires_at` finds nothing (TTL), a redeem CONSUMES a live
    /// entry so a second finds nothing (single-use), and a second LIVE park of a held id is refused
    /// (first-park-wins — never a silent takeover). Drives the registry directly with explicit `now`.
    #[tokio::test]
    async fn pairing_rendezvous_registry_enforces_single_use_ttl_and_first_park_wins() {
        // A throwaway, still-open connection just to key the registry (never bridged in this unit
        // test). Both endpoints + both connection handles are held alive for the test's duration, so
        // the returned connection reports `close_reason().is_none()` (live).
        async fn dummy_conn() -> Connection {
            let secret = OverlaySecret::generate().unwrap();
            let server =
                quic::server_endpoint(&secret, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
            let addr = server.local_addr().unwrap();
            let (conn_tx, conn_rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                let srv_conn = quic::accept(&server).await.unwrap().unwrap();
                let _ = conn_tx.send(srv_conn.clone());
                let _hold = (server, srv_conn); // keep the server endpoint + conn alive
                std::future::pending::<()>().await;
            });
            let client = quic::pair_dial_endpoint().unwrap();
            let client_conn = quic::dial(&client, addr).await.unwrap();
            tokio::spawn(async move {
                let _hold = (client, client_conn); // keep the client endpoint + conn alive
                std::future::pending::<()>().await;
            });
            conn_rx.await.unwrap()
        }

        let reg = PairRendezvous::new();
        let code = vec![0x42u8; 16];

        // TTL: a parked entry is not live at/after its expiry, so a redeem then finds nothing.
        let c1 = dummy_conn().await;
        assert!(reg.try_park(code.clone(), c1, 100, 50).await, "fresh park");
        assert!(reg.is_parked(&code, 99).await, "parked before expiry");
        assert!(!reg.is_parked(&code, 100).await, "NOT live at expiry (TTL)");
        assert!(
            reg.redeem(&code, 100).await.is_none(),
            "an expired rendezvous must not be redeemable (TTL)"
        );

        // Single-use: a redeem of a live entry CONSUMES it; a second redeem finds nothing.
        let c2 = dummy_conn().await;
        assert!(
            reg.try_park(code.clone(), c2, 1000, 50).await,
            "re-park after prune"
        );
        assert!(
            reg.redeem(&code, 60).await.is_some(),
            "first redeem matches"
        );
        assert!(
            reg.redeem(&code, 60).await.is_none(),
            "a consumed rendezvous must not be redeemable again (single-use)"
        );

        // First-park-wins: a second LIVE park of a held id is refused (never a silent takeover).
        let c3 = dummy_conn().await;
        assert!(
            reg.try_park(code.clone(), c3, 1000, 50).await,
            "park the id"
        );
        let c4 = dummy_conn().await;
        assert!(
            !reg.try_park(code.clone(), c4, 1000, 60).await,
            "a second live park of a held id must be refused (first-park-wins)"
        );
    }

    /// Relay-blind: the relay bridges CIPHERTEXT ONLY. A capturing relay tees every bridged byte in
    /// both directions; after the two peers pair end-to-end over it, the derived SAS (words + digits +
    /// raw bits) appears NOWHERE in the captured stream — the relay holds no keys/nonces/SAS and cannot
    /// recover it. (The SAS is never transmitted; the revealed nonces that derive it ride SEALED phase-B
    /// records. A mutation that leaked either in cleartext over the bridge would surface them here.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_pairing_relay_bridges_ciphertext_only_never_the_sas() {
        use std::collections::HashMap;

        let relay = OverlaySecret::generate().unwrap();
        let accepter = OverlaySecret::generate().unwrap();
        let dialer = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let code = vec![0x5Au8; 16];

        // A capturing relay: park connections keyed by code; on a redeem, open a stream down the parked
        // connection and bridge both directions while TEEING every byte into `capture`.
        let relay_ep =
            quic::server_endpoint(&relay, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
        let relay_addr = relay_ep.local_addr().unwrap();
        let capture: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let parked: Arc<Mutex<HashMap<Vec<u8>, Connection>>> = Arc::new(Mutex::new(HashMap::new()));
        {
            let capture = capture.clone();
            tokio::spawn(async move {
                while let Ok(Some(conn)) = quic::accept(&relay_ep).await {
                    let parked = parked.clone();
                    let capture = capture.clone();
                    tokio::spawn(async move {
                        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                        let frame = read_ingress_frame(&mut recv).await.unwrap();
                        match frame {
                            IngressFrame::PairPark(req) => {
                                parked.lock().await.insert(req.code, conn.clone());
                                write_msg(&mut send, &PairResult::Ok).await.unwrap();
                                conn.closed().await; // hold the parked connection open
                            }
                            IngressFrame::PairRedeem(req) => {
                                // Find the parked accepter (bounded retry for arrival ordering).
                                let mut target = None;
                                for _ in 0..100 {
                                    if let Some(c) = parked.lock().await.get(&req.code).cloned() {
                                        target = Some(c);
                                        break;
                                    }
                                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                                }
                                let target = target.expect("a parked accepter for the code");
                                let (mut ps, mut pr) = target.open_bi().await.unwrap();
                                write_msg(&mut send, &PairResult::Ok).await.unwrap();
                                // Blind TEE-bridge: copy both ways, appending every byte to `capture`.
                                let cap_c2e = capture.clone();
                                let c2e = async {
                                    let mut buf = [0u8; 8192];
                                    while let Ok(Some(n)) = recv.read(&mut buf).await {
                                        if n == 0 {
                                            break;
                                        }
                                        cap_c2e.lock().await.extend_from_slice(&buf[..n]);
                                        if ps.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                    let _ = ps.finish();
                                };
                                let cap_e2c = capture.clone();
                                let e2c = async {
                                    let mut buf = [0u8; 8192];
                                    while let Ok(Some(n)) = pr.read(&mut buf).await {
                                        if n == 0 {
                                            break;
                                        }
                                        cap_e2c.lock().await.extend_from_slice(&buf[..n]);
                                        if send.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                    let _ = send.finish();
                                };
                                tokio::join!(c2e, e2c);
                            }
                            _ => {}
                        }
                    });
                }
            });
        }

        let code_a = code.clone();
        let acc = tokio::spawn(async move {
            let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
            let (conn, mut send, mut recv) =
                pair_relay_park(&ep, relay_addr, code_a).await.unwrap();
            let out = pair_handshake(&mut send, &mut recv, &accepter, Role::Responder, PAIR_DL)
                .await
                .unwrap();
            conn.closed().await;
            out
        });
        // Give the accepter time to park before redeeming.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (dconn, mut dsend, mut drecv) = pair_relay_redeem(&ep, relay_addr, code.clone())
            .await
            .unwrap();
        let (sas_d, _peer_d) =
            pair_handshake(&mut dsend, &mut drecv, &dialer, Role::Initiator, PAIR_DL)
                .await
                .unwrap();
        dconn.close(0u32.into(), b"paired");
        let (sas_a, _peer_a) = acc.await.unwrap();

        assert_eq!(
            sas_a.bits(),
            sas_d.bits(),
            "pairing completed through the capturing relay"
        );
        let seen = capture.lock().await.clone();
        assert!(
            !seen.is_empty(),
            "the relay must have bridged the handshake bytes"
        );
        // The derived SAS — in any rendering — never crosses the wire, so it is absent from what the
        // relay saw. A relay that could read the handshake would be able to surface these.
        for needle in [sas_d.words(), sas_d.digits()] {
            assert!(
                !contains_subslice(&seen, needle.as_bytes()),
                "the relay must NOT see the SAS `{needle}` in the bridged ciphertext"
            );
        }
        assert!(
            !contains_subslice(&seen, sas_d.bits()),
            "the relay must NOT see the raw SAS bits in the bridged ciphertext"
        );
    }

    /// Whether `haystack` contains `needle` as a contiguous subslice.
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Tampering/misrouting relay → the SAS diverges (the inc1 MITM guarantee, now over the rendezvous
    /// transport). An ACTIVE relay that cannot relay ciphertext (it has no session keys) can only run
    /// TWO separate pairing legs — Initiator toward the parked accepter, Responder toward the dialer.
    /// The accepter and the dialer then derive SAS codes from two DIFFERENT transcripts, so the
    /// out-of-band comparison DIVERGES and the humans catch the man-in-the-middle. Each also proves it
    /// paired with the relay M (not the other peer), so neither pins the intended partner.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_mitm_rendezvous_relay_makes_the_two_peers_sas_diverge() {
        let mitm = OverlaySecret::generate().unwrap();
        let accepter = OverlaySecret::generate().unwrap();
        let dialer = OverlaySecret::generate().unwrap();
        let (mitm_id, mitm_pub_seed) = (mitm.id(), mitm.seed_hex().to_string());
        let relay_id = mitm_id; // the peers pin the relay (= the MITM) at TLS; the SAS is their only cross-check
        let (accepter_id, dialer_id) = (accepter.id(), dialer.id());
        let code = vec![0x77u8; 16];

        let relay_ep =
            quic::server_endpoint(&mitm, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
        let relay_addr = relay_ep.local_addr().unwrap();
        // The MITM relay: park the accepter, run a pairing leg with it AS A PEER (Initiator); on a
        // redeem, run a SECOND pairing leg with the dialer (Responder). It bridges NOTHING (it cannot —
        // it has no session keys), so the two legs are independent handshakes.
        {
            let parked: Arc<Mutex<std::collections::HashMap<Vec<u8>, Connection>>> =
                Arc::new(Mutex::new(std::collections::HashMap::new()));
            tokio::spawn(async move {
                while let Ok(Some(conn)) = quic::accept(&relay_ep).await {
                    let parked = parked.clone();
                    let mitm_seed = mitm_pub_seed.clone();
                    tokio::spawn(async move {
                        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                        match read_ingress_frame(&mut recv).await.unwrap() {
                            IngressFrame::PairPark(req) => {
                                parked.lock().await.insert(req.code, conn.clone());
                                write_msg(&mut send, &PairResult::Ok).await.unwrap();
                                // Leg A: M dials a stream down the parked accepter conn and pairs with it
                                // as the Initiator.
                                let (mut ps, mut pr) = conn.open_bi().await.unwrap();
                                let m = OverlaySecret::from_seed_hex(&mitm_seed).unwrap();
                                let _ =
                                    pair_handshake(&mut ps, &mut pr, &m, Role::Initiator, PAIR_DL)
                                        .await;
                                conn.closed().await;
                            }
                            IngressFrame::PairRedeem(_req) => {
                                write_msg(&mut send, &PairResult::Ok).await.unwrap();
                                // Leg B: M pairs with the dialer as the Responder over the dialer stream.
                                let m = OverlaySecret::from_seed_hex(&mitm_seed).unwrap();
                                let _ = pair_handshake(
                                    &mut send,
                                    &mut recv,
                                    &m,
                                    Role::Responder,
                                    PAIR_DL,
                                )
                                .await;
                                conn.closed().await;
                            }
                            _ => {}
                        }
                    });
                }
            });
        }

        // Accepter parks and pairs (Responder) with whoever opens the bridged stream — which is M.
        let code_a = code.clone();
        let acc = tokio::spawn(async move {
            let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
            let (conn, mut send, mut recv) =
                pair_relay_park(&ep, relay_addr, code_a).await.unwrap();
            let out = pair_handshake(&mut send, &mut recv, &accepter, Role::Responder, PAIR_DL)
                .await
                .unwrap();
            conn.closed().await;
            out
        });
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // Dialer redeems and pairs (Initiator) — also with M.
        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (dconn, mut dsend, mut drecv) = pair_relay_redeem(&ep, relay_addr, code.clone())
            .await
            .unwrap();
        let (sas_d, peer_d) =
            pair_handshake(&mut dsend, &mut drecv, &dialer, Role::Initiator, PAIR_DL)
                .await
                .unwrap();
        dconn.close(0u32.into(), b"done");
        let (sas_a, peer_a) = acc.await.unwrap();

        // Each paired with M, not the intended partner — so neither learned the other's id.
        assert_eq!(
            peer_a, mitm_id,
            "the accepter paired with the MITM relay, not the dialer"
        );
        assert_eq!(
            peer_d, mitm_id,
            "the dialer paired with the MITM relay, not the accepter"
        );
        assert_ne!(mitm_id, accepter_id);
        assert_ne!(mitm_id, dialer_id);
        // The two human-visible SAS codes DIVERGE — the out-of-band comparison catches the MITM.
        assert_ne!(
            sas_a.bits(),
            sas_d.bits(),
            "an active MITM rendezvous relay yields diverging SAS codes — the comparison catches it"
        );
    }
}
