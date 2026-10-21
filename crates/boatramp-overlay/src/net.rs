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
use std::collections::{BTreeMap, HashMap, VecDeque};
#[cfg(feature = "server")]
use std::net::IpAddr;
use std::net::SocketAddr;
#[cfg(feature = "server")]
use std::sync::Mutex as StdMutex;
use std::time::{SystemTime, UNIX_EPOCH};

use std::sync::Arc;
use std::time::Duration;

// `TokenPublicKey` is the dial trust-root both the client-edge terminator (`terminate_stream`, via
// `run_published_service`) and the server-side gate verify against; `verify_overlay_publish`/
// `verify_overlay_pairing_park` are only the relay's registration/park paths (`register_exposer`/
// `park_rendezvous`), so they are server-gated.
use boatramp_core::cose::TokenPublicKey;
#[cfg(feature = "server")]
use boatramp_core::cose::{verify_overlay_pairing_park, verify_overlay_publish};
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
// The human-typeable short-code alias (overlay follow-up #2, inc3): the mint/alias-table side
// (`PairShortCodes`) is relay-only — the client redeem path sends the plain digit string it already
// has (see `pair_relay_redeem_short`), so it never needs the type itself.
#[cfg(feature = "server")]
use boatramp_overlay_proto::pair_code::ShortCode;
use boatramp_overlay_proto::wire;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(feature = "server")]
use tokio::sync::OwnedSemaphorePermit;
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

/// Max concurrently in-flight PRE-CLASSIFICATION ingress connections — the [`run_ingress_router`]
/// accept-loop bound (HIGH-1). A connection holds a handshake slot only for `accept_bi` + reading the
/// first control frame (bounded by [`HANDSHAKE_TIMEOUT`]), then swaps to the budget its frame KIND
/// draws from and releases this slot. Distinct from the flow budget so the swap is clean; generous
/// (= the flow budget) because the hold is short.
#[cfg(feature = "server")]
const MAX_INFLIGHT_HANDSHAKES: usize = MAX_INFLIGHT_FLOWS;

/// Max concurrently PARKED pairing rendezvous — a SEPARATE budget from the forward/expose
/// [`MAX_INFLIGHT_FLOWS`] flows (HIGH-1). PARK is the first UNAUTHENTICATED path to a multi-minute
/// permit hold (≤ the rendezvous TTL; register/dial are capability-gated before their hold), so a PARK
/// must never draw from the production flow budget — otherwise an unauthenticated park flood starves
/// forward dials + exposer registrations. Deliberately ≪ the flow budget: a relay serves at most a
/// handful of concurrent human-driven pairings, so 64 is ample for real use yet cannot dominate.
#[cfg(feature = "server")]
const PAIR_MAX_PARKED: usize = 64;

/// Max concurrent parked rendezvous per SOURCE IP (HIGH-1 secondary bound). One host rarely parks more
/// than one or two rendezvous at once, so a small per-IP cap stops a single source from eating the
/// whole [`PAIR_MAX_PARKED`] budget. (Peers behind one NAT share a public IP; this caps CONCURRENT —
/// not total — parks, each ≤ the TTL, a reasonable secondary floor beneath the global budget.)
#[cfg(feature = "server")]
const PAIR_MAX_PARKED_PER_IP: u32 = 3;

/// Max concurrent exposer REGISTRATIONS (`IngressFrame::Register` → [`register_exposer`]) — a
/// SEPARATE budget from the forward/redeem [`MAX_INFLIGHT_FLOWS`] flows (expose inc3 part 3a). A
/// registration is LONG-LIVED (held for as long as the service stays published) while a forward
/// dial/redeem is short-lived; sharing one pool lets either workload starve the other (a node
/// exposing many services could block production forward-dials, or a dial burst could block a new
/// registration). Unlike [`PAIR_MAX_PARKED`] this is NOT an unauthenticated-DoS bound — `register_exposer`
/// verifies a holder-bound publish capability BEFORE the long hold — so this is a fairness /
/// resource-isolation split between two AUTHENTICATED workloads, not a flood gate (no per-IP cap is
/// needed here). A node legitimately exposes at most a few hundred services even in a large fleet;
/// 256 is comfortably large for that real use yet small enough, relative to the 1024-flow budget, that
/// a registration burst cannot be mistaken for — or crowd out resources meant for — forward-dial
/// capacity.
#[cfg(feature = "server")]
const MAX_REGISTERED_EXPOSERS: usize = 256;

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
    /// A dialer redeeming a parked pairing rendezvous via its human-typeable short-code alias
    /// (overlay follow-up #2 inc3).
    PairRedeemShort(PairRedeemShortRequest),
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
    if let Ok(redeem_short) = serde_json::from_slice::<PairRedeemShortRequest>(&buf)
        && redeem_short.pair_redeem_short == PAIR_REDEEM_SHORT_TAG
    {
        return Ok(IngressFrame::PairRedeemShort(redeem_short));
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
#[allow(clippy::too_many_arguments)]
pub async fn run_ingress_router<F>(
    endpoint: Endpoint,
    secret: OverlaySecret,
    trust_root: TokenPublicKey,
    client_auth: RelayClientAuth,
    registry: ExposerRegistry,
    rendezvous: PairRendezvous,
    short_codes: PairShortCodes,
    short_code_digits: usize,
    resolve: F,
    pairing_park: PairingParkMode,
) where
    F: Fn(&str) -> Option<(SocketAddr, OverlayId, bool)> + Clone + Send + Sync + 'static,
{
    run_ingress_router_with_budgets(
        endpoint,
        secret,
        trust_root,
        client_auth,
        registry,
        rendezvous,
        short_codes,
        short_code_digits,
        resolve,
        IngressBudgets::DEFAULT,
        pairing_park,
    )
    .await;
}

/// The admission budgets a [`run_ingress_router`] loop enforces. The KEY separation (HIGH-1) is that
/// PARK draws from `parked` (+ the per-IP cap), NEVER from `flows` — so an unauthenticated park flood
/// can never exhaust the forward/expose flow budget. A SECOND separation (expose inc3 part 3a, fairness
/// between two authenticated workloads rather than a DoS bound) is that a long-lived exposer
/// REGISTRATION draws from `register`, NEVER from `flows` — so a registration burst can never starve
/// short-lived forward dials/redeems, and vice-versa. Parameterized so tests can drive the separation
/// with tiny budgets; production uses [`IngressBudgets::DEFAULT`].
#[cfg(feature = "server")]
#[derive(Clone, Copy)]
struct IngressBudgets {
    /// Concurrent pre-classification connections (the accept-loop bound; short, ≤ `HANDSHAKE_TIMEOUT`).
    handshakes: usize,
    /// Concurrent forward/redeem FLOWS (`Dial`/`PairRedeem`) — SEPARATE from `register` (never drawn
    /// on by a `Register`).
    flows: usize,
    /// Concurrent exposer REGISTRATIONS (`Register`) — SEPARATE from `flows` (never drawn on by a
    /// `Dial`/`PairRedeem`). Long-lived (held for the service's published lifetime) vs the short-lived
    /// `flows` workload, so the two pools must not be shared.
    register: usize,
    /// Concurrent PARKED rendezvous (`PairPark`) — SEPARATE from `flows` and `register`.
    parked: usize,
    /// Concurrent parked rendezvous per source IP.
    parked_per_ip: u32,
}

#[cfg(feature = "server")]
impl IngressBudgets {
    const DEFAULT: Self = Self {
        handshakes: MAX_INFLIGHT_HANDSHAKES,
        flows: MAX_INFLIGHT_FLOWS,
        register: MAX_REGISTERED_EXPOSERS,
        parked: PAIR_MAX_PARKED,
        parked_per_ip: PAIR_MAX_PARKED_PER_IP,
    };
}

/// [`run_ingress_router`] with explicit [`IngressBudgets`]. The accept loop holds a short HANDSHAKE
/// slot per connection (released the instant the frame is classified and swapped to its own budget):
/// `PairPark` → the SEPARATE `parked` budget (+ per-IP cap), held for the park's ≤TTL life;
/// `Register` → the SEPARATE `register` budget, held for the service's published life;
/// `Dial`/`PairRedeem` → the `flows` budget, held for the flow's life. So a park never draws from — and
/// a park flood can never starve — the forward/expose flow budget (HIGH-1); and a registration never
/// draws from — and a registration burst can never starve — the SAME flow budget either way (expose
/// inc3 part 3a).
#[cfg(feature = "server")]
#[allow(clippy::too_many_arguments)]
async fn run_ingress_router_with_budgets<F>(
    endpoint: Endpoint,
    secret: OverlaySecret,
    trust_root: TokenPublicKey,
    client_auth: RelayClientAuth,
    registry: ExposerRegistry,
    rendezvous: PairRendezvous,
    short_codes: PairShortCodes,
    short_code_digits: usize,
    resolve: F,
    budgets: IngressBudgets,
    pairing_park: PairingParkMode,
) where
    F: Fn(&str) -> Option<(SocketAddr, OverlayId, bool)> + Clone + Send + Sync + 'static,
{
    let seed = secret.seed_hex();
    let handshake_limiter = Arc::new(Semaphore::new(budgets.handshakes));
    let flow_limiter = Arc::new(Semaphore::new(budgets.flows));
    let register_limiter = Arc::new(Semaphore::new(budgets.register));
    let park_limiter = Arc::new(Semaphore::new(budgets.parked));
    let park_by_ip: Arc<StdMutex<HashMap<IpAddr, u32>>> = Arc::new(StdMutex::new(HashMap::new()));
    // The short-code guess-rate limiter is NOT a concurrency budget (it never gates admission by
    // slot count) — it is a separate, orthogonal rolling-window failure-rate gate shared across every
    // short-redeem on this router, so it lives outside `IngressBudgets`.
    let guess_limiter = Arc::new(PairGuessLimiter::default_production());
    loop {
        let Ok(hs_permit) = Arc::clone(&handshake_limiter).acquire_owned().await else {
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
        let short_codes = short_codes.clone();
        let guess_limiter = Arc::clone(&guess_limiter);
        let flow_limiter = Arc::clone(&flow_limiter);
        let register_limiter = Arc::clone(&register_limiter);
        let park_limiter = Arc::clone(&park_limiter);
        let park_by_ip = Arc::clone(&park_by_ip);
        tokio::spawn(async move {
            if let Err(e) = handle_ingress_connection(
                conn,
                hs_permit,
                &relay_secret,
                &trust_root,
                client_auth,
                &registry,
                &rendezvous,
                &short_codes,
                &guess_limiter,
                short_code_digits,
                flow_limiter,
                register_limiter,
                park_limiter,
                park_by_ip,
                budgets.parked_per_ip,
                pairing_park,
                &resolve,
            )
            .await
            {
                tracing::debug!(error = %e, "overlay relay: ingress connection ended with error");
            }
        });
    }
}

/// Accept the first bi-stream + control frame on an ingress connection (holding the short handshake
/// slot `hs_permit`), then SWAP to the budget the frame kind draws from — releasing the handshake slot
/// — and dispatch. `PairPark` takes a SEPARATE park budget (never the flow budget, HIGH-1); `Register`
/// takes a SEPARATE register budget (never the flow budget, expose inc3 part 3a — a long-lived
/// registration must not starve short-lived flows, nor vice-versa); `Dial`/`PairRedeem` take the flow
/// budget.
#[cfg(feature = "server")]
#[allow(clippy::too_many_arguments)]
async fn handle_ingress_connection<F>(
    conn: Connection,
    hs_permit: OwnedSemaphorePermit,
    relay_secret: &OverlaySecret,
    trust_root: &TokenPublicKey,
    client_auth: RelayClientAuth,
    registry: &ExposerRegistry,
    rendezvous: &PairRendezvous,
    short_codes: &PairShortCodes,
    guess_limiter: &PairGuessLimiter,
    short_code_digits: usize,
    flow_limiter: Arc<Semaphore>,
    register_limiter: Arc<Semaphore>,
    park_limiter: Arc<Semaphore>,
    park_by_ip: Arc<StdMutex<HashMap<IpAddr, u32>>>,
    parked_per_ip: u32,
    pairing_park: PairingParkMode,
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
    // Swap the handshake slot for the frame's own budget. PARK takes the SEPARATE park budget;
    // REGISTER takes the SEPARATE register budget; every other flow kind takes the flow budget. The
    // handshake slot is released the instant the swap is made.
    match frame {
        IngressFrame::PairPark(req) => {
            park_admit_and_run(
                conn,
                send,
                recv,
                req,
                rendezvous,
                hs_permit,
                &park_limiter,
                &park_by_ip,
                parked_per_ip,
                pairing_park,
                relay_secret,
                trust_root,
            )
            .await
        }
        IngressFrame::Register(req) => {
            // Invariant (expose inc3 part 3a): a Register NEVER draws from `flow_limiter` — it has its
            // own budget, so a node exposing many services can never starve forward dials/redeems.
            let _register = register_limiter
                .acquire_owned()
                .await
                .map_err(|_| NetError::Stream("ingress register budget closed".into()))?;
            drop(hs_permit);
            register_exposer(conn, send, recv, req, relay_secret, trust_root, registry).await
        }
        IngressFrame::PairRedeem(req) => {
            let _flow = flow_limiter
                .acquire_owned()
                .await
                .map_err(|_| NetError::Stream("ingress flow budget closed".into()))?;
            drop(hs_permit);
            redeem_rendezvous(conn, send, recv, req, rendezvous).await
        }
        IngressFrame::PairRedeemShort(req) => {
            // Reuses the SAME flow budget as `PairRedeem`/`Dial` (never a fresh/unbounded path) — the
            // inc2 HIGH-1 separation (park/register never drawn on by a flow) is preserved unchanged.
            let _flow = flow_limiter
                .acquire_owned()
                .await
                .map_err(|_| NetError::Stream("ingress flow budget closed".into()))?;
            drop(hs_permit);
            redeem_rendezvous_short(
                conn,
                send,
                recv,
                req,
                rendezvous,
                short_codes,
                guess_limiter,
                short_code_digits,
            )
            .await
        }
        IngressFrame::Dial(req) => {
            let _flow = flow_limiter
                .acquire_owned()
                .await
                .map_err(|_| NetError::Stream("ingress flow budget closed".into()))?;
            drop(hs_permit);
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

/// A relay's per-relay operator choice for the pairing PARK service (`[overlay] pairing_park`,
/// default [`PairingParkMode::Open`]): OPEN keeps today's behavior unchanged (unauthenticated park,
/// bounded by the existing park budget + per-IP cap, the SAS as the trust anchor); AUTHENTICATED
/// additionally requires the parking peer to present a holder-bound `overlay-pairing-park` capability
/// and prove possession — EXACTLY the holder-binding [`register_exposer`] applies to an
/// overlay-publish capability — before the connection is parked. REDEEM is unauthenticated in BOTH
/// modes (the unpaired dialer is, by design, not membership-gated; the SAS backstops it).
#[cfg(feature = "server")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PairingParkMode {
    /// Unauthenticated park (today's behavior) — the DEFAULT.
    #[default]
    Open,
    /// Park requires a holder-bound `overlay-pairing-park` capability + a proven-possession match.
    Authenticated,
}

/// The discriminator marking a [`PairParkRequest`] frame (the accepter PARKING at the relay), so the
/// ingress router tells it from a `Register`/`Dial`/`PairRedeem` first frame without changing the wire.
const PAIR_PARK_TAG: &str = "overlay-pair-park";
/// The discriminator marking a [`PairRedeemRequest`] frame (the dialer REDEEMING a parked rendezvous).
const PAIR_REDEEM_TAG: &str = "overlay-pair-redeem";
/// The discriminator marking a [`PairRedeemShortRequest`] frame (the dialer redeeming a parked
/// rendezvous via its human-typeable SHORT-CODE alias — overlay follow-up #2 inc3).
const PAIR_REDEEM_SHORT_TAG: &str = "overlay-pair-redeem-short";

/// How long a parked pairing rendezvous lives at the relay before it is reaped (minutes): long enough
/// for an operator to share the `bropair1` code and the peer to redeem it, short enough that a leaked/
/// abandoned code cannot stand open. Bounds a never-redeemed park's hold on a `MAX_INFLIGHT_FLOWS`
/// Semaphore slot (the park connection is force-closed once this elapses with no redeem).
#[cfg(feature = "server")]
const PAIR_RENDEZVOUS_TTL_SECS: u64 = 300;

/// Rolling window (seconds) the short-code guess-rate limiter counts FAILED short-redeems over
/// (`W` in the design math): `F_ip`/`F_global` failures within this many trailing seconds trip the
/// per-IP/global lockout. 60s — long enough to catch a burst, short enough that an honest operator's
/// later retry (after fixing a typo) is not punished for long.
#[cfg(feature = "server")]
const PAIR_SHORT_GUESS_WINDOW_SECS: u64 = 60;
/// Per-source-IP cap on FAILED short-redeems within [`PAIR_SHORT_GUESS_WINDOW_SECS`] — the
/// LOAD-BEARING bound (`F_ip` in the design math): `10` failed attempts gives `10 · 2^-26.6` chance of
/// an online hit per window at the default 8-digit code, far below the 24-bit SAS's own
/// per-online-attempt strength. A SUCCESSFUL redeem never increments this (an honest first try never
/// trips it).
#[cfg(feature = "server")]
const PAIR_SHORT_GUESS_MAX_PER_IP: u32 = 10;
/// Global cap on FAILED short-redeems within [`PAIR_SHORT_GUESS_WINDOW_SECS`] across ALL sources — a
/// backstop (`F_global`) against a distributed guessing swarm that stays under the per-IP cap on any
/// single source.
#[cfg(feature = "server")]
const PAIR_SHORT_GUESS_MAX_GLOBAL: u32 = 30;
/// Bounded retries [`PairShortCodes::insert_unique`] spends regenerating a fresh random short code
/// when a draw collides with a LIVE entry, before giving up (an exhausted-retries error — the mint
/// path surfaces this as a `500`, never a silent weaker code).
#[cfg(feature = "server")]
const PAIR_SHORT_CODE_MINT_RETRIES: u32 = 8;

/// What a peer sends as the FIRST control frame to PARK a pairing rendezvous (the accepter side).
/// Distinguished from a `DialRequest`/`RegisterRequest`/`PairRedeemRequest` by its required
/// `pair_park` discriminator (a dial/register/redeem frame never carries it, and vice versa).
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
struct PairParkRequest {
    /// Always [`PAIR_PARK_TAG`].
    pair_park: String,
    /// The rendezvous id (the relay's registry key) — the core of a `bropair1` code.
    code: Vec<u8>,
    /// The holder-bound `overlay-pairing-park` capability (COSE), presented ONLY when the relay's
    /// operator-chosen [`PairingParkMode`] is `Authenticated` (an OPEN-mode relay never reads this).
    /// Absent (the default, `#[serde(default)]`) in open mode — the existing wire is unchanged.
    #[serde(default)]
    park_cap: Option<String>,
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

/// What a peer sends as the FIRST control frame to REDEEM a parked pairing rendezvous via its
/// human-typeable SHORT-CODE alias (overlay follow-up #2 inc3) — the dialer side, exactly like
/// [`PairRedeemRequest`] but keyed on the low-entropy alias instead of the full 128-bit rendezvous id.
/// The relay resolves `code` to the aliased rendezvous id (via [`PairShortCodes::resolve_and_take`])
/// and then runs the EXACT SAME [`PairRendezvous::redeem`] + blind bridge as a full-id redeem — so
/// single-use/TTL/consume semantics live in exactly one place.
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
struct PairRedeemShortRequest {
    /// Always [`PAIR_REDEEM_SHORT_TAG`].
    pair_redeem_short: String,
    /// The short-code digit string (separators already stripped by the caller) to resolve.
    code: String,
}

/// Why a pairing park/redeem was refused by the relay (returned to the peer).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum PairReject {
    /// The rendezvous id was empty or not exactly `PAIR_RENDEZVOUS_ID_LEN` bytes (a malformed code —
    /// distinct from a collision, so an empty/garbage code is never reported as `CodeInUse`).
    InvalidCode,
    /// A live rendezvous is ALREADY parked under this id (first-park-wins; never a silent takeover) —
    /// returned to a PARK.
    CodeInUse,
    /// The relay's parked-rendezvous budget (global or per-source-IP) is full — returned to a PARK.
    /// Unauthenticated PARK is bounded SEPARATELY from the forward/expose flow budget (HIGH-1).
    TooManyParked,
    /// No live parked rendezvous for this id — never parked, already redeemed (single-use), or expired
    /// — returned to a REDEEM. ALSO returned for a short-code miss (no distinguishing oracle between a
    /// wrong guess and an already-spent/unknown one — see [`PairReject::TooManyAttempts`] for the
    /// SEPARATE short-code rate-limit rejection).
    UnknownOrSpent,
    /// The source (by IP, or the relay-wide backstop) has exceeded the short-code guess-rate limit
    /// within the rolling window — returned ONLY to a short-code REDEEM, checked BEFORE the code is
    /// even resolved (so an over-budget source is refused even for a code that would otherwise hit).
    TooManyAttempts,
    /// AUTHENTICATED park only: no `park_cap` was presented, or it failed to verify (bad signature,
    /// expired, wrong `br_kind`) — mirrors [`RegisterReject::InvalidCapability`]. Carries a short
    /// description for the peer's own logs.
    InvalidCapability(String),
    /// AUTHENTICATED park only: the presented capability's holder is not the parking peer's
    /// E2EE-proven identity (a stolen/misdirected capability) — mirrors
    /// [`RegisterReject::HolderMismatch`], the load-bearing holder-binding control.
    HolderMismatch,
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
            park_cap: None, // open mode — unchanged wire
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

/// Client-side: PARK at `relay` for a pairing rendezvous under `code` in AUTHENTICATED mode (overlay
/// pairing-park per-relay operator config): presents a holder-bound `overlay-pairing-park` capability
/// and proves possession of it to the relay via the E2EE handshake — mirrors
/// [`run_published_service`]'s registration possession proof EXACTLY — BEFORE the relay parks the
/// connection. `secret` is the accepter's own overlay identity (the capability's holder); `relay_id`
/// pins the relay (a MITM relay fails the handshake), exactly as the exposer registration path pins
/// it. Otherwise identical to [`pair_relay_park`]: on the relay's `Ok` it accepts the ONE bridged
/// pairing stream the relay opens down this connection when a dialer redeems the code. A relay that
/// refuses the capability (missing / invalid / wrong-holder) surfaces as
/// `NetError::PairRejected(PairReject::InvalidCapability(_) | PairReject::HolderMismatch)`.
pub async fn pair_relay_park_authenticated(
    relay: &Endpoint,
    relay_addr: SocketAddr,
    relay_id: OverlayId,
    code: Vec<u8>,
    secret: &OverlaySecret,
    park_cap: String,
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
            park_cap: Some(park_cap),
        },
    )
    .await?;
    // Prove possession of the pairing-park capability's holder key to the relay (mirrors the exposer
    // registration handshake): sign the KEM offer with THIS identity's key, pinning the relay.
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
    .map_err(|_| NetError::Stream("pairing-park handshake timed out".into()))??;
    match read_msg::<PairResult>(&mut recv).await? {
        PairResult::Ok => {}
        PairResult::Rejected(reason) => return Err(NetError::PairRejected(reason)),
    }
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

/// Client-side: REDEEM a parked pairing rendezvous via its human-typeable SHORT-CODE alias (overlay
/// follow-up #2 inc3) at `relay` (the dialer). `code` is the bare digit string (separators already
/// stripped — e.g. via [`boatramp_overlay_proto::pair_code::ShortCode::normalize`]). Otherwise
/// identical to [`pair_relay_redeem`]: dials the relay, sends the short-redeem request, and on the
/// relay's `Ok` returns the held [`Connection`] + the bridged `(send, recv)` to run
/// `pair_handshake(Initiator)` over. The low entropy of a short code is backstopped at the relay by a
/// guess-rate limiter — a refusal may be a genuine miss, an already-spent code, OR the caller's
/// source having exceeded the guess-rate limit (`TooManyAttempts`); all fail-closed.
pub async fn pair_relay_redeem_short(
    relay: &Endpoint,
    relay_addr: SocketAddr,
    code: String,
) -> Result<(Connection, SendStream, RecvStream), NetError> {
    let conn = quic::dial(relay, relay_addr).await?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| NetError::Stream(e.to_string()))?;
    write_msg(
        &mut send,
        &PairRedeemShortRequest {
            pair_redeem_short: PAIR_REDEEM_SHORT_TAG.to_string(),
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

/// An RAII reservation of one per-source-IP parked-rendezvous slot: decrements the source's count on
/// drop, so the per-IP cap tracks CONCURRENT parks exactly over the park's lifetime.
#[cfg(feature = "server")]
struct ParkIpGuard {
    map: Arc<StdMutex<HashMap<IpAddr, u32>>>,
    ip: IpAddr,
}

#[cfg(feature = "server")]
impl Drop for ParkIpGuard {
    fn drop(&mut self) {
        let Ok(mut m) = self.map.lock() else { return };
        if let Some(c) = m.get_mut(&self.ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

/// Reserve one parked-rendezvous slot for `ip` if the source is under `cap`, returning an RAII guard
/// that releases it on drop. `None` when the source already holds `cap` concurrent parks. A sync
/// `std::sync::Mutex` (held only for the tiny increment/decrement — never across an `.await`) so the
/// guard's `Drop` can release it.
#[cfg(feature = "server")]
fn try_reserve_park_ip(
    map: &Arc<StdMutex<HashMap<IpAddr, u32>>>,
    ip: IpAddr,
    cap: u32,
) -> Option<ParkIpGuard> {
    let mut m = map.lock().ok()?;
    let c = m.entry(ip).or_insert(0);
    if *c >= cap {
        return None;
    }
    *c += 1;
    drop(m);
    Some(ParkIpGuard {
        map: Arc::clone(map),
        ip,
    })
}

/// Admit a PARK onto the SEPARATE park budget, then run it (HIGH-1). Rejects — releasing the handshake
/// slot and NEVER touching the forward/expose flow budget — a malformed id (`InvalidCode`), a source
/// over its per-IP cap, or a full global park budget (both `TooManyParked`). On admission it swaps the
/// handshake slot for the park permit + the per-IP reservation (both held for the park's life).
#[cfg(feature = "server")]
#[allow(clippy::too_many_arguments)]
async fn park_admit_and_run(
    conn: Connection,
    mut send: SendStream,
    recv: RecvStream,
    req: PairParkRequest,
    registry: &PairRendezvous,
    hs_permit: OwnedSemaphorePermit,
    park_limiter: &Arc<Semaphore>,
    park_by_ip: &Arc<StdMutex<HashMap<IpAddr, u32>>>,
    parked_per_ip: u32,
    pairing_park: PairingParkMode,
    relay_secret: &OverlaySecret,
    trust_root: &TokenPublicKey,
) -> Result<(), NetError> {
    // INFO-2 — a rendezvous id is exactly PAIR_RENDEZVOUS_ID_LEN bytes; an empty/garbage id is an
    // `InvalidCode` (never reported as a collision), and bounding the key size bounds a flood's map.
    if req.code.len() != boatramp_overlay_proto::PAIR_RENDEZVOUS_ID_LEN {
        let _ = write_msg(&mut send, &PairResult::Rejected(PairReject::InvalidCode)).await;
        let _ = timeout(wire::DIRECT_DRAIN, conn.closed()).await;
        return Err(NetError::PairRejected(PairReject::InvalidCode));
    }
    // Per-source-IP concurrent-park cap (secondary bound): one source cannot eat the whole budget.
    let ip = conn.remote_address().ip();
    let Some(ip_guard) = try_reserve_park_ip(park_by_ip, ip, parked_per_ip) else {
        let _ = write_msg(&mut send, &PairResult::Rejected(PairReject::TooManyParked)).await;
        let _ = timeout(wire::DIRECT_DRAIN, conn.closed()).await;
        return Err(NetError::PairRejected(PairReject::TooManyParked));
    };
    // The SEPARATE park budget (HIGH-1): `try_acquire` — never block (a blocked park would pile up on
    // the handshake budget) — so a full budget rejects cleanly instead of waiting.
    let Ok(park_permit) = Arc::clone(park_limiter).try_acquire_owned() else {
        let _ = write_msg(&mut send, &PairResult::Rejected(PairReject::TooManyParked)).await;
        let _ = timeout(wire::DIRECT_DRAIN, conn.closed()).await;
        return Err(NetError::PairRejected(PairReject::TooManyParked));
    };
    // Admitted: release the handshake slot — the park now holds ONLY the park budget + the per-IP slot.
    drop(hs_permit);
    park_rendezvous(
        conn,
        send,
        recv,
        req,
        registry,
        park_permit,
        ip_guard,
        pairing_park,
        relay_secret,
        trust_root,
    )
    .await
}

/// Relay pairing: PARK one accepter under its rendezvous id. In OPEN mode (the default) there is NO
/// relay E2EE handshake at this stage — the relay is blind; the rendezvous id (the `bropair1` code's
/// core) is the only credential, and the SAS backstops the pairing. In AUTHENTICATED mode (the
/// operator's per-relay choice), the parking peer must present a holder-bound `overlay-pairing-park`
/// capability that verifies (checked FIRST — cheap and local, so a capless/bogus park never waits on
/// a handshake) and then complete an E2EE possession handshake whose proven identity equals the
/// capability's holder — EXACTLY the holder-binding [`register_exposer`] applies to an overlay-publish
/// capability — before the connection is ever parked. Admission (budget + per-IP + code-length)
/// already passed in [`park_admit_and_run`]; here it (authenticates if required, then) parks the
/// connection, acks, then HOLDS it (bounded by the rendezvous TTL) so a redeem can open the bridged
/// pairing stream down it. The `_park_permit` + `_ip_guard` are held for the whole park (including the
/// authentication phase) and released the instant it ends; on the TTL with no redeem the parked
/// connection is force-closed and the id released.
#[cfg(feature = "server")]
#[allow(clippy::too_many_arguments)]
async fn park_rendezvous(
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    req: PairParkRequest,
    registry: &PairRendezvous,
    park_permit: OwnedSemaphorePermit,
    ip_guard: ParkIpGuard,
    pairing_park: PairingParkMode,
    relay_secret: &OverlaySecret,
    trust_root: &TokenPublicKey,
) -> Result<(), NetError> {
    // Hold the park budget + per-IP reservation for the whole park; both release on return.
    let _park_permit = park_permit;
    let _ip_guard = ip_guard;
    let now = now_unix();

    if pairing_park == PairingParkMode::Authenticated {
        // AUTHENTICATED PARK (owner decision: per-relay open-vs-authenticated pairing-park). Verify the
        // presented capability FIRST — a cheap, purely local signature/expiry/kind check — so a parker
        // with no cap at all (or an obviously-bogus one) is refused INSTANTLY, never left waiting on a
        // handshake that will never arrive (an absent-cap park must not hold a budget slot for
        // HANDSHAKE_TIMEOUT). Only once the capability verifies does the relay run the E2EE possession
        // handshake and require its holder to equal the E2EE-proven identity — EXACTLY the holder-
        // binding mechanism `register_exposer` applies to an overlay-publish capability (same
        // `establish(Role::Responder, expect=None)` → compare `verified.holder == proven`).
        let Some(cap) = req.park_cap.as_deref() else {
            let reason = PairReject::InvalidCapability(
                "this relay requires an overlay-pairing-park capability".into(),
            );
            let _ = write_msg(&mut send, &PairResult::Rejected(reason.clone())).await;
            let _ = timeout(wire::DIRECT_DRAIN, conn.closed()).await;
            return Err(NetError::PairRejected(reason));
        };
        let verified = match verify_overlay_pairing_park(cap, trust_root, now) {
            Ok(v) => v,
            Err(e) => {
                let reason = PairReject::InvalidCapability(e.to_string());
                let _ = write_msg(&mut send, &PairResult::Rejected(reason.clone())).await;
                let _ = timeout(wire::DIRECT_DRAIN, conn.closed()).await;
                return Err(NetError::PairRejected(reason));
            }
        };
        let proven = match timeout(HANDSHAKE_TIMEOUT, async {
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
        {
            Ok(Ok(peer)) => peer,
            _ => {
                let reason = PairReject::InvalidCapability(
                    "pairing-park possession handshake failed or timed out".into(),
                );
                let _ = write_msg(&mut send, &PairResult::Rejected(reason.clone())).await;
                let _ = timeout(wire::DIRECT_DRAIN, conn.closed()).await;
                return Err(NetError::PairRejected(reason));
            }
        };
        // HOLDER BINDING: the E2EE-proven identity must BE the capability's holder — a stolen/
        // misdirected capability presented by a different key is refused.
        if verified.holder != proven.to_hex() {
            let _ = write_msg(&mut send, &PairResult::Rejected(PairReject::HolderMismatch)).await;
            let _ = timeout(wire::DIRECT_DRAIN, conn.closed()).await;
            return Err(NetError::PairRejected(PairReject::HolderMismatch));
        }
    }

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
    // aborted) OR the TTL elapses with no redeem — then force-close to free the park-budget slot.
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
    // INFO-2 — a rendezvous id is exactly PAIR_RENDEZVOUS_ID_LEN bytes; reject a malformed one up front
    // (distinct from `UnknownOrSpent`) rather than treating it as a miss.
    if req.code.len() != boatramp_overlay_proto::PAIR_RENDEZVOUS_ID_LEN {
        write_msg(
            &mut client_send,
            &PairResult::Rejected(PairReject::InvalidCode),
        )
        .await?;
        let _ = timeout(wire::DIRECT_DRAIN, client.closed()).await;
        return Err(NetError::PairRejected(PairReject::InvalidCode));
    }
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

// ======================================================================================
// Pairing SHORT CODES (overlay follow-up #2, inc3): a human-typeable alias for a `bropair1`
// rendezvous.
//
// The `bropair1…` bech32m code is LONG — awkward to read aloud or type on a second device. A SHORT
// code (default 8 decimal digits, grouped `NNNN-NNNN`) is easy to share, but LOW-ENTROPY
// (`10^digits`), so it is used ONLY by the dialer/redeem side (the accepter still parks the full
// 128-bit id — no low-entropy surface on park) and the relay MUST rate-limit + lock out online
// guessing. The short code is an INDEPENDENT random ALIAS that resolves to the strong rendezvous id —
// NEVER a truncation/derivation of it (leaking a short code reveals nothing about the strong id, and
// the full `bropair1` path stays full-entropy and unthrottled). `PairShortCodes` is a sibling
// alias-table alongside [`PairRendezvous`]; the short path resolves short→id then calls the EXISTING
// [`PairRendezvous::redeem`] — single-use/consume/TTL logic stays in exactly ONE place.
// ======================================================================================

/// One short-code alias: which (strong) rendezvous id it resolves to, and when the alias itself
/// expires (mirrors the aliased [`PairEntry`]'s TTL — the two are minted together).
#[cfg(feature = "server")]
struct ShortEntry {
    /// The aliased rendezvous id — resolved then handed to the EXISTING [`PairRendezvous::redeem`].
    rendezvous_id: Vec<u8>,
    /// When this alias expires (Unix seconds); a resolve past this is treated as a miss and pruned.
    expires_at: u64,
}

/// A failure minting a [`ShortCode`] alias.
#[cfg(feature = "server")]
#[derive(Debug, thiserror::Error)]
pub enum PairShortCodeError {
    /// The short code itself could not be built (digit count out of range / value overflow).
    #[error(transparent)]
    Code(#[from] boatramp_overlay_proto::pair_code::ShortCodeError),
    /// Every draw within the bounded retry budget collided with a LIVE alias — give up rather than
    /// loop forever or silently mint a weaker (shorter/predictable) code.
    #[error("exhausted short-code collision retries")]
    ExhaustedRetries,
    /// The platform entropy source faulted while drawing randomness for a mint (Security LOW-2:
    /// fails CLOSED — a mint NEVER falls back to a zeroed/predictable draw).
    #[error("random number generation failed")]
    Rng,
}

/// A relay-side alias table mapping a human-typeable [`ShortCode`] to the strong rendezvous id it
/// resolves to. The SIBLING of [`PairRendezvous`] (same `Arc<Mutex<BTreeMap<..>>>` shape), but it
/// holds no connection — only the alias — so dropping/consuming an alias never affects the parked
/// connection itself; only [`PairRendezvous::redeem`] does that. Cheap to clone (an `Arc` handle).
#[cfg(feature = "server")]
#[derive(Clone, Default)]
pub struct PairShortCodes {
    inner: Arc<Mutex<BTreeMap<String, ShortEntry>>>,
}

#[cfg(feature = "server")]
impl PairShortCodes {
    /// An empty alias table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn entry_live(entry: &ShortEntry, now: u64) -> bool {
        now < entry.expires_at
    }

    /// Mint + park a NEW short-code alias for `rendezvous_id`, expiring at `expires_at`. `draw`
    /// supplies raw randomness per attempt (injectable for deterministic tests — `Ok(..)` always;
    /// production mints via [`PairShortCodes::mint`], which wires real platform entropy and can
    /// propagate a genuine RNG fault through `draw`'s `Err`, failing this CLOSED rather than minting
    /// off a zeroed/predictable draw): a draw colliding with a LIVE alias is regenerated, up to
    /// [`PAIR_SHORT_CODE_MINT_RETRIES`] times, before giving up — a dead/expired alias is silently
    /// reused (never a park-style rejection; a short code is minted fresh each time, so there is no
    /// "first-wins" semantic to preserve).
    pub async fn insert_unique<R: FnMut() -> Result<u64, PairShortCodeError>>(
        &self,
        mut draw: R,
        digits: usize,
        rendezvous_id: Vec<u8>,
        expires_at: u64,
        now: u64,
    ) -> Result<ShortCode, PairShortCodeError> {
        let modulus = 10u64.checked_pow(digits as u32).ok_or(
            boatramp_overlay_proto::pair_code::ShortCodeError::DigitsOutOfRange { digits },
        )?;
        for _ in 0..PAIR_SHORT_CODE_MINT_RETRIES {
            let value = draw()? % modulus;
            let code = ShortCode::from_value(value, digits)?;
            let mut map = self.inner.lock().await;
            let collides = map
                .get(code.digits())
                .is_some_and(|e| Self::entry_live(e, now));
            if !collides {
                map.insert(
                    code.digits().to_string(),
                    ShortEntry {
                        rendezvous_id,
                        expires_at,
                    },
                );
                return Ok(code);
            }
        }
        Err(PairShortCodeError::ExhaustedRetries)
    }

    /// [`PairShortCodes::insert_unique`] wired to real platform randomness
    /// ([`aws_lc_rs::rand::SystemRandom`] — the one platform RNG this crate already uses for the
    /// pairing nonces, `crate::pair`). The production mint entry point; tests needing a deterministic
    /// or colliding draw call `insert_unique` directly. FAILS CLOSED on a platform entropy-source
    /// fault (Security LOW-2) — propagates [`PairShortCodeError::Rng`] rather than minting off a
    /// zeroed (predictable) draw.
    pub async fn mint(
        &self,
        digits: usize,
        rendezvous_id: Vec<u8>,
        expires_at: u64,
        now: u64,
    ) -> Result<ShortCode, PairShortCodeError> {
        use aws_lc_rs::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        self.insert_unique(
            || {
                let mut buf = [0u8; 8];
                rng.fill(&mut buf).map_err(|_| PairShortCodeError::Rng)?;
                Ok(u64::from_le_bytes(buf))
            },
            digits,
            rendezvous_id,
            expires_at,
            now,
        )
        .await
    }

    /// Resolve `digits` to its aliased rendezvous id, CONSUMING the alias (single-use — mirrors
    /// [`PairRendezvous::redeem`]'s remove-on-hit). `None` on a miss (never minted, already resolved,
    /// or expired); an expired entry is pruned.
    pub async fn resolve_and_take(&self, digits: &str, now: u64) -> Option<Vec<u8>> {
        let mut map = self.inner.lock().await;
        match map.get(digits) {
            Some(e) if Self::entry_live(e, now) => map.remove(digits).map(|e| e.rendezvous_id),
            Some(_) => {
                map.remove(digits); // prune the dead/expired alias
                None
            }
            None => None,
        }
    }

    /// Whether a live alias currently exists for `digits` at `now` (test/diagnostic helper).
    pub async fn is_active(&self, digits: &str, now: u64) -> bool {
        let map = self.inner.lock().await;
        map.get(digits).is_some_and(|e| Self::entry_live(e, now))
    }
}

/// A rolling-window counter of FAILED short-redeem attempts, per source IP, mirroring the existing
/// [`ParkIpGuard`]'s sync-`std::sync::Mutex`-never-across-`.await` pattern (lazy prune on access —
/// no background reaper task). Two tiers: a per-IP cap (`F_ip`, the LOAD-BEARING bound) and a global
/// backstop (`F_global`) against a distributed guessing swarm that stays under the per-IP cap on any
/// single source. A SUCCESSFUL redeem never records a failure — an honest first try never trips
/// either cap.
#[cfg(feature = "server")]
struct PairGuessLimiter {
    window_secs: u64,
    max_per_ip: u32,
    max_global: u32,
    by_ip: StdMutex<HashMap<IpAddr, VecDeque<u64>>>,
    global: StdMutex<VecDeque<u64>>,
}

#[cfg(feature = "server")]
impl PairGuessLimiter {
    /// A limiter with the given rolling window + per-IP/global failure caps.
    fn new(window_secs: u64, max_per_ip: u32, max_global: u32) -> Self {
        Self {
            window_secs,
            max_per_ip,
            max_global,
            by_ip: StdMutex::new(HashMap::new()),
            global: StdMutex::new(VecDeque::new()),
        }
    }

    /// The production limiter: [`PAIR_SHORT_GUESS_WINDOW_SECS`] /
    /// [`PAIR_SHORT_GUESS_MAX_PER_IP`] / [`PAIR_SHORT_GUESS_MAX_GLOBAL`].
    fn default_production() -> Self {
        Self::new(
            PAIR_SHORT_GUESS_WINDOW_SECS,
            PAIR_SHORT_GUESS_MAX_PER_IP,
            PAIR_SHORT_GUESS_MAX_GLOBAL,
        )
    }

    /// Whether a NEW short-redeem attempt from `ip` at `now` is admitted — under BOTH the per-IP and
    /// global rolling-window failure caps. MUST be checked BEFORE resolving the code (never after),
    /// so a source already over budget is refused even for a code that WOULD otherwise hit. Lazily
    /// prunes failures older than the rolling window first (never across an `.await` — both locks are
    /// plain `std::sync::Mutex`, held only for this synchronous prune+compare).
    ///
    /// SECURITY (HIGH-1 fix): this is READ-ONLY with respect to `by_ip` MEMBERSHIP — it never inserts
    /// a key for a source that has recorded no failure (`get_mut`, never `entry(..).or_default()`),
    /// and it EVICTS the key once its deque prunes to empty. Only [`PairGuessLimiter::record_failure`]
    /// may insert a key. Without this, every admitted-but-never-failing source (e.g. a flood of
    /// malformed-length requests from fresh IPs, before the HIGH-1 call-order fix below) would leave a
    /// PERMANENT entry in `by_ip` — unbounded memory growth, a relay OOM.
    fn admit(&self, ip: IpAddr, now: u64) -> bool {
        let cutoff = now.saturating_sub(self.window_secs);
        {
            let Ok(mut g) = self.global.lock() else {
                return false;
            };
            g.retain(|&t| t > cutoff);
            if g.len() as u32 >= self.max_global {
                return false;
            }
        }
        let Ok(mut by_ip) = self.by_ip.lock() else {
            return false;
        };
        let count = match by_ip.get_mut(&ip) {
            Some(deque) => {
                deque.retain(|&t| t > cutoff);
                let n = deque.len();
                if n == 0 {
                    // Evict: a source with no in-window failures left carries no state (mirrors
                    // `ParkIpGuard`'s `if *c == 0 { remove }`).
                    by_ip.remove(&ip);
                }
                n
            }
            None => 0,
        };
        (count as u32) < self.max_per_ip
    }

    /// Record a FAILED short-redeem attempt from `ip` at `now`. Called ONLY on a miss — a successful
    /// resolve must NEVER call this (an honest first try never trips the limiter). This is the ONLY
    /// method that may insert a `by_ip` key (see [`PairGuessLimiter::admit`]'s HIGH-1 note).
    fn record_failure(&self, ip: IpAddr, now: u64) {
        if let Ok(mut g) = self.global.lock() {
            let cutoff = now.saturating_sub(self.window_secs);
            g.retain(|&t| t > cutoff);
            g.push_back(now);
        }
        if let Ok(mut by_ip) = self.by_ip.lock() {
            let cutoff = now.saturating_sub(self.window_secs);
            let entry = by_ip.entry(ip).or_default();
            entry.retain(|&t| t > cutoff);
            entry.push_back(now);
        }
    }
}

/// Relay pairing: REDEEM a parked rendezvous for the dialer via its human-typeable SHORT-CODE alias
/// (overlay follow-up #2 inc3). Order (load-bearing, Security HIGH-1): a length/digit mismatch
/// against this relay's configured `short_code_digits` is checked FIRST and rejected `InvalidCode`
/// WITHOUT ever consulting the guess limiter — a malformed (non-guess) request must never touch it,
/// so a flood of malformed frames from fresh source IPs cannot grow its per-IP map. Only once the
/// request is well-formed is the guess-rate LOCKOUT checked — still BEFORE the code is resolved, so
/// an over-budget source is refused even for a code that would otherwise hit. Only a well-formed code
/// that MISSES resolution counts as a failed attempt (a successful resolve counts nothing). Short→id
/// resolution hands off to the EXISTING [`PairRendezvous::redeem`] + [`bridge`] — single-use/TTL/
/// consume and the blind bridge stay in exactly the same place the full-`bropair1` path uses.
#[cfg(feature = "server")]
#[allow(clippy::too_many_arguments)]
async fn redeem_rendezvous_short(
    client: Connection,
    mut client_send: SendStream,
    client_recv: RecvStream,
    req: PairRedeemShortRequest,
    registry: &PairRendezvous,
    short_codes: &PairShortCodes,
    guess_limiter: &PairGuessLimiter,
    short_code_digits: usize,
) -> Result<(), NetError> {
    let now = now_unix();
    let ip = client.remote_address().ip();
    // A malformed-length (or non-digit) request is structurally invalid, not a guess — reject it
    // BEFORE even consulting the guess limiter (Security HIGH-1): the limiter must never be touched
    // by a non-guess request, so a flood of malformed frames from fresh source IPs cannot exercise
    // ANY limiter code path (`admit` itself is also hardened — see its doc comment — but a malformed
    // frame should never reach it in the first place).
    if req.code.len() != short_code_digits || !req.code.bytes().all(|b| b.is_ascii_digit()) {
        write_msg(
            &mut client_send,
            &PairResult::Rejected(PairReject::InvalidCode),
        )
        .await?;
        let _ = timeout(wire::DIRECT_DRAIN, client.closed()).await;
        return Err(NetError::PairRejected(PairReject::InvalidCode));
    }
    // Lockout next — still BEFORE resolving the code (mutation-RED guard: drop this check and a guess
    // over budget would still succeed against a live code).
    if !guess_limiter.admit(ip, now) {
        write_msg(
            &mut client_send,
            &PairResult::Rejected(PairReject::TooManyAttempts),
        )
        .await?;
        let _ = timeout(wire::DIRECT_DRAIN, client.closed()).await;
        return Err(NetError::PairRejected(PairReject::TooManyAttempts));
    }
    let Some(rendezvous_id) = short_codes.resolve_and_take(&req.code, now).await else {
        // A genuine miss: count it, and return the SAME reject a spent/unknown FULL id would — no
        // oracle distinguishing a wrong guess from an already-consumed code.
        guess_limiter.record_failure(ip, now);
        write_msg(
            &mut client_send,
            &PairResult::Rejected(PairReject::UnknownOrSpent),
        )
        .await?;
        let _ = timeout(wire::DIRECT_DRAIN, client.closed()).await;
        return Err(NetError::PairRejected(PairReject::UnknownOrSpent));
    };
    // Resolved short→id: hand off to the EXISTING full-id redeem (single-use/consume/TTL stays in
    // ONE place). A successful short-resolve does NOT count as a failure even if this second step
    // somehow misses (e.g. a racing full-id redeem won first) — the short code itself was genuine.
    let Some(parked) = registry.redeem(&rendezvous_id, now).await else {
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
    tracing::info!("overlay relay: pairing rendezvous matched via short code (bridging blind)");
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
    /// can share + inspect the relay's rendezvous registry. Production admission budgets, a fresh
    /// [`PairShortCodes`] table, and the default short-code digit count.
    fn spawn_ingress_relay_with_rendezvous(
        relay: &OverlaySecret,
        root_pub: TokenPublicKey,
        registry: ExposerRegistry,
        rendezvous: PairRendezvous,
    ) -> SocketAddr {
        spawn_ingress_relay_with_short_codes(
            relay,
            root_pub,
            registry,
            rendezvous,
            PairShortCodes::new(),
            boatramp_overlay_proto::PAIR_SHORT_CODE_DIGITS_DEFAULT,
        )
    }

    /// As [`spawn_ingress_relay_with_rendezvous`], but with a caller-supplied [`PairShortCodes`] alias
    /// table (+ digit count) so the short-code tests can mint + inspect aliases directly. Production
    /// admission budgets.
    fn spawn_ingress_relay_with_short_codes(
        relay: &OverlaySecret,
        root_pub: TokenPublicKey,
        registry: ExposerRegistry,
        rendezvous: PairRendezvous,
        short_codes: PairShortCodes,
        short_code_digits: usize,
    ) -> SocketAddr {
        spawn_ingress_relay_with_budgets(
            relay,
            root_pub,
            registry,
            rendezvous,
            short_codes,
            short_code_digits,
            IngressBudgets::DEFAULT,
        )
    }

    /// As [`spawn_ingress_relay_with_short_codes`], but with explicit [`IngressBudgets`] so the HIGH-1
    /// tests can drive the park-vs-flow budget separation and the per-IP cap with tiny budgets.
    #[allow(clippy::too_many_arguments)]
    fn spawn_ingress_relay_with_budgets(
        relay: &OverlaySecret,
        root_pub: TokenPublicKey,
        registry: ExposerRegistry,
        rendezvous: PairRendezvous,
        short_codes: PairShortCodes,
        short_code_digits: usize,
        budgets: IngressBudgets,
    ) -> SocketAddr {
        spawn_ingress_relay_with_pairing_park_mode(
            relay,
            root_pub,
            registry,
            rendezvous,
            short_codes,
            short_code_digits,
            budgets,
            PairingParkMode::Open,
        )
    }

    /// As [`spawn_ingress_relay_with_budgets`], but with an explicit [`PairingParkMode`] so the
    /// authenticated-pairing-park tests can stand up a relay that requires the capability.
    #[allow(clippy::too_many_arguments)]
    fn spawn_ingress_relay_with_pairing_park_mode(
        relay: &OverlaySecret,
        root_pub: TokenPublicKey,
        registry: ExposerRegistry,
        rendezvous: PairRendezvous,
        short_codes: PairShortCodes,
        short_code_digits: usize,
        budgets: IngressBudgets,
        pairing_park: PairingParkMode,
    ) -> SocketAddr {
        let relay_ep =
            quic::server_endpoint(relay, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = relay_ep.local_addr().unwrap();
        let relay_secret = OverlaySecret::from_seed_hex(&relay.seed_hex()).unwrap();
        tokio::spawn(run_ingress_router_with_budgets(
            relay_ep,
            relay_secret,
            root_pub,
            RelayClientAuth::CapabilityOnly,
            registry,
            rendezvous,
            short_codes,
            short_code_digits,
            |_s: &str| None::<(SocketAddr, OverlayId, bool)>,
            budgets,
            pairing_park,
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

    // ---- Overlay pairing PARK: open-vs-authenticated per-relay operator config ----

    /// Baseline (today's behavior, UNCHANGED): a relay explicitly configured for OPEN pairing-park
    /// admits a park presenting NO capability at all — exactly as before this feature existed.
    /// MUTATION-RED: if the `pairing_park == Authenticated` guard were dropped (always requiring a
    /// cap), an open-mode relay would refuse this uncapped park → RED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn open_mode_park_is_unauthenticated_as_before() {
        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let root_pub = root.id().to_public();

        let rendezvous = PairRendezvous::new();
        let relay_addr = spawn_ingress_relay_with_pairing_park_mode(
            &relay,
            root_pub,
            ExposerRegistry::new(),
            rendezvous.clone(),
            PairShortCodes::new(),
            boatramp_overlay_proto::PAIR_SHORT_CODE_DIGITS_DEFAULT,
            IngressBudgets::DEFAULT,
            PairingParkMode::Open,
        );
        let code = vec![0x11u8; 16];

        // Park in the background (it only RETURNS once a dialer redeems — `accept_bi` blocks until
        // then — so the admission itself is proven by the registry going live, not by this future
        // resolving).
        let code_a = code.clone();
        tokio::spawn(async move {
            let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
            let _ = pair_relay_park(&ep, relay_addr, code_a).await;
        });
        assert!(
            await_parked(&rendezvous, &code).await,
            "an OPEN-mode relay must admit an uncapped park into its registry"
        );
    }

    /// The load-bearing AUTHENTICATED-park gate: a relay configured for AUTHENTICATED pairing-park
    /// REFUSES a park presenting no capability (`InvalidCapability`), and ADMITS a park presenting a
    /// VALID holder-bound capability + a matching possession proof — with the redeem side STILL
    /// unauthenticated (the SAS backstops it in both modes). MUTATION-RED: skip the cap verify in the
    /// authenticated park path (treat any/no capability as valid) → the no-cap park would ADMIT
    /// instead of refuse → RED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn authenticated_park_requires_a_valid_pairing_park_cap() {
        use boatramp_core::cose::mint_overlay_pairing_park;

        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let accepter = OverlaySecret::generate().unwrap();
        let dialer = OverlaySecret::generate().unwrap();
        let (relay_id, accepter_id) = (relay.id(), accepter.id());
        let root_pub = root.id().to_public();

        let rendezvous = PairRendezvous::new();
        let relay_addr = spawn_ingress_relay_with_pairing_park_mode(
            &relay,
            root_pub,
            ExposerRegistry::new(),
            rendezvous.clone(),
            PairShortCodes::new(),
            boatramp_overlay_proto::PAIR_SHORT_CODE_DIGITS_DEFAULT,
            IngressBudgets::DEFAULT,
            PairingParkMode::Authenticated,
        );

        // (a) NO capability presented → refused `InvalidCapability`, instantly (no cap ⇒ no handshake
        // need even be attempted) — never silently admitted.
        let no_cap_code = vec![0x22u8; 16];
        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let res = pair_relay_park(&ep, relay_addr, no_cap_code.clone()).await;
        assert!(
            matches!(
                res,
                Err(NetError::PairRejected(PairReject::InvalidCapability(_)))
            ),
            "an AUTHENTICATED relay must refuse an uncapped park, got {res:?}"
        );
        assert!(
            !rendezvous.is_parked(&no_cap_code, now_unix()).await,
            "a refused park must never be registered"
        );

        // (b) A VALID holder-bound cap, presented by its OWN holder + a matching possession proof,
        // is ADMITTED. Full round trip through to a successful (still-unauthenticated) REDEEM.
        let cap =
            mint_overlay_pairing_park(&accepter.id().to_public(), 300, now_unix(), &root.signer())
                .await
                .unwrap();
        let code = vec![0x33u8; 16];
        let code_a = code.clone();
        let acc = tokio::spawn(async move {
            let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
            let (conn, mut send, mut recv) =
                pair_relay_park_authenticated(&ep, relay_addr, relay_id, code_a, &accepter, cap)
                    .await
                    .unwrap();
            let out = pair_handshake(&mut send, &mut recv, &accepter, Role::Responder, PAIR_DL)
                .await
                .unwrap();
            conn.closed().await;
            out
        });
        assert!(
            await_parked(&rendezvous, &code).await,
            "a validly-capped park must be admitted and registered"
        );
        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (dconn, mut dsend, mut drecv) = pair_relay_redeem(&ep, relay_addr, code.clone())
            .await
            .expect("REDEEM stays unauthenticated even against an AUTHENTICATED-park relay");
        let (_sas_d, peer_d) =
            pair_handshake(&mut dsend, &mut drecv, &dialer, Role::Initiator, PAIR_DL)
                .await
                .unwrap();
        dconn.close(0u32.into(), b"paired");
        let (_sas_a, peer_a) = acc.await.unwrap();
        assert_eq!(peer_a, dialer.id());
        assert_eq!(peer_d, accepter_id);
    }

    /// Holder-binding (the load-bearing control, mirrors `register_with_a_stolen_cap_whose_holder_is_
    /// not_the_presenter_is_refused`): a VALID pairing-park cap minted for holder X, but presented
    /// (with a real possession proof) by a DIFFERENT identity Y, is refused `HolderMismatch`. The
    /// relay's E2EE handshake proves Y's identity; `verified.holder (X) != proven (Y)` → refused.
    /// MUTATION-RED: drop the `verified.holder != proven` check → the stolen cap would be accepted →
    /// RED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn authenticated_park_rejects_a_cap_bound_to_a_different_key() {
        use boatramp_core::cose::mint_overlay_pairing_park;

        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let holder = OverlaySecret::generate().unwrap(); // the cap is minted FOR this identity
        let thief = OverlaySecret::generate().unwrap(); // but THIS identity presents it
        let relay_id = relay.id();
        let root_pub = root.id().to_public();

        let rendezvous = PairRendezvous::new();
        let relay_addr = spawn_ingress_relay_with_pairing_park_mode(
            &relay,
            root_pub,
            ExposerRegistry::new(),
            rendezvous.clone(),
            PairShortCodes::new(),
            boatramp_overlay_proto::PAIR_SHORT_CODE_DIGITS_DEFAULT,
            IngressBudgets::DEFAULT,
            PairingParkMode::Authenticated,
        );

        let stolen =
            mint_overlay_pairing_park(&holder.id().to_public(), 300, now_unix(), &root.signer())
                .await
                .unwrap();
        let code = vec![0x44u8; 16];
        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let res =
            pair_relay_park_authenticated(&ep, relay_addr, relay_id, code.clone(), &thief, stolen)
                .await;
        assert!(
            matches!(res, Err(NetError::PairRejected(PairReject::HolderMismatch))),
            "a cap minted for a different holder must be refused, got {res:?}"
        );
        assert!(
            !rendezvous.is_parked(&code, now_unix()).await,
            "a holder-mismatched park must never be registered"
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

    // ---- HIGH-1: park budget is SEPARATE from the forward/expose flow budget ----

    /// Anti-hollow (HIGH-1): an unauthenticated PARK flood CANNOT starve the forward/expose flow
    /// budget. With `flows = parked = 1`, a held park fills the PARK budget; a forward dial STILL
    /// succeeds (returns its verdict) because it draws from the SEPARATE flow budget. MUTATION-RED:
    /// make a park draw from the flow budget (`flow_limiter` in place of `park_limiter` in
    /// `park_admit_and_run`) and the held park consumes the one flow slot → the forward dial never
    /// gets a flow permit → `handle_ingress_connection` never reads its request → `forward_flow` hangs
    /// → the timeout below fires → RED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_park_flood_does_not_starve_the_forward_flow_budget() {
        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let root_pub = root.id().to_public();

        let rendezvous = PairRendezvous::new();
        // flows = parked = 1: the single park fills the PARK budget; the forward must draw from the
        // (untouched) flow budget. handshakes = 8 so the accept loop is never the bottleneck.
        let relay_addr = spawn_ingress_relay_with_budgets(
            &relay,
            root_pub,
            ExposerRegistry::new(),
            rendezvous.clone(),
            PairShortCodes::new(),
            boatramp_overlay_proto::PAIR_SHORT_CODE_DIGITS_DEFAULT,
            IngressBudgets {
                handshakes: 8,
                flows: 1,
                register: 8,
                parked: 1,
                parked_per_ip: 4,
            },
        );
        let code = vec![0xC0u8; 16];

        // Hold a park (never redeemed): it occupies the one PARK slot for its TTL.
        let code_a = code.clone();
        let _park = tokio::spawn(async move {
            let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
            let _ = pair_relay_park(&ep, relay_addr, code_a).await; // blocks waiting for a redeem
        });
        assert!(
            await_parked(&rendezvous, &code).await,
            "the park must occupy the PARK budget"
        );

        // A forward dial to an UNCONFIGURED service: with the separate budgets it still gets a flow
        // permit and the relay returns ServiceNotAuthorized — promptly, well within the timeout.
        let token = mint_overlay_dial(
            &client.id().to_public(),
            "svc/none",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        let egress_id = OverlaySecret::generate().unwrap().id();
        let client_ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (_app, app_far) = tokio::io::duplex(64 * 1024);
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            forward_flow(
                app_far,
                &client_ep,
                relay_addr,
                &client,
                egress_id,
                DialRequest {
                    service: "svc/none".into(),
                    token,
                    e2ee: true,
                },
                PathMode::Relay,
            ),
        )
        .await
        .expect("the forward dial must get a flow permit despite the saturated PARK budget");
        assert!(
            matches!(
                res,
                Err(NetError::DialRejected(DialReject::ServiceNotAuthorized))
            ),
            "the forward dial draws from the separate flow budget and is handled, got {res:?}"
        );
    }

    // ---- expose inc3 part 3a: the register budget is SEPARATE from the forward/redeem flow budget ----

    /// Anti-hollow: an exposer REGISTRATION flood cannot starve the forward/redeem flow budget. With
    /// `flows = register = 1`, one held registration fills the REGISTER budget; a forward dial to an
    /// unconfigured service STILL succeeds (returns its verdict) because it draws from the SEPARATE
    /// flow budget. MUTATION-RED: route `Register` back onto `flow_limiter` (in place of
    /// `register_limiter`) in `handle_ingress_connection` — the held registration then consumes the one
    /// flow permit → the forward dial never gets a flow permit → `handle_ingress_connection` never
    /// reads its request → `forward_flow` hangs → the timeout below fires → RED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_register_flood_does_not_starve_the_forward_flow_budget() {
        use boatramp_core::cose::mint_overlay_publish;

        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let exposer = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let root_pub = root.id().to_public();

        let backend_addr = spawn_echo_backend().await;
        let registry = ExposerRegistry::new();
        // flows = register = 1: the one held registration fills the REGISTER budget; the forward dial
        // must draw from the (untouched) flow budget. handshakes = 8 so the accept loop is never the
        // bottleneck; parked is irrelevant here.
        let relay_addr = spawn_ingress_relay_with_budgets(
            &relay,
            root_pub.clone(),
            registry.clone(),
            PairRendezvous::new(),
            PairShortCodes::new(),
            boatramp_overlay_proto::PAIR_SHORT_CODE_DIGITS_DEFAULT,
            IngressBudgets {
                handshakes: 8,
                flows: 1,
                register: 1,
                parked: 8,
                parked_per_ip: 4,
            },
        );

        // Exposer registers svc/held and stays registered (never unregisters) — it occupies the one
        // REGISTER slot for the test's duration.
        let publish_cap = mint_overlay_publish(
            &exposer.id().to_public(),
            "svc/held",
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
                    "svc/held",
                    publish_cap,
                    backend_addr,
                    root_pub,
                )
                .await;
            });
        }
        assert!(
            await_registered(&registry, "svc/held").await,
            "the registration must occupy the REGISTER budget"
        );

        // A forward dial to an UNCONFIGURED service: with the separate budgets it still gets a flow
        // permit and the relay returns ServiceNotAuthorized — promptly, well within the timeout.
        let token = mint_overlay_dial(
            &client.id().to_public(),
            "svc/none",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        let egress_id = OverlaySecret::generate().unwrap().id();
        let client_ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (_app, app_far) = tokio::io::duplex(64 * 1024);
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            forward_flow(
                app_far,
                &client_ep,
                relay_addr,
                &client,
                egress_id,
                DialRequest {
                    service: "svc/none".into(),
                    token,
                    e2ee: true,
                },
                PathMode::Relay,
            ),
        )
        .await
        .expect("the forward dial must get a flow permit despite the saturated REGISTER budget");
        assert!(
            matches!(
                res,
                Err(NetError::DialRejected(DialReject::ServiceNotAuthorized))
            ),
            "the forward dial draws from the separate flow budget and is handled, got {res:?}"
        );
    }

    /// Symmetric direction: a FORWARD-FLOW flood cannot starve a new exposer registration either. With
    /// `flows = 1` and one forward flow held open (confirmed live by an actual echo round-trip through
    /// the bridged backend, so the flow permit is DEFINITELY held — not a timing guess), a SECOND
    /// exposer's registration still admits promptly because it draws from the separate `register`
    /// budget (sized here for both exposers). MUTATION-RED: route `Register` onto `flow_limiter` —
    /// exposer A's OWN registration then competes for the single flow permit (and, going first, wins
    /// it, holding it for its published lifetime) — so the forward dial to svc/a can never acquire a
    /// flow permit, the bridge never establishes, and the echo round-trip's bounded timeout elapses →
    /// the assertion below fails → RED. (With the fix, `Register` never touches `flow_limiter` at all,
    /// so this contention cannot happen regardless of ordering.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_forward_flow_flood_does_not_starve_a_new_registration() {
        use boatramp_core::cose::mint_overlay_publish;
        use tokio::io::AsyncReadExt;

        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let exposer_a = OverlaySecret::generate().unwrap();
        let exposer_b = OverlaySecret::generate().unwrap();
        let (relay_id, exposer_a_id) = (relay.id(), exposer_a.id());
        let root_pub = root.id().to_public();

        let backend_addr = spawn_echo_backend().await;
        let registry = ExposerRegistry::new();
        // flows = 1, register = 2: the one held forward flow fills the ENTIRE flow budget; a second
        // exposer must still register because it draws from the separate register budget.
        let relay_addr = spawn_ingress_relay_with_budgets(
            &relay,
            root_pub.clone(),
            registry.clone(),
            PairRendezvous::new(),
            PairShortCodes::new(),
            boatramp_overlay_proto::PAIR_SHORT_CODE_DIGITS_DEFAULT,
            IngressBudgets {
                handshakes: 8,
                flows: 1,
                register: 2,
                parked: 8,
                parked_per_ip: 4,
            },
        );

        // Exposer A publishes svc/a (1 of the 2 register slots).
        let publish_cap_a = mint_overlay_publish(
            &exposer_a.id().to_public(),
            "svc/a",
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
                    relay_addr,
                    relay_id,
                    "svc/a",
                    publish_cap_a,
                    backend_addr,
                    root_pub,
                )
                .await;
            });
        }
        assert!(
            await_registered(&registry, "svc/a").await,
            "exposer A must register svc/a"
        );

        // Forward-dial svc/a and hold the flow open — confirmed live by an actual echo round-trip, so
        // the flow permit (budget = 1) is DEFINITELY held by the time exposer B tries to register.
        let dial_cap = mint_overlay_dial(
            &client.id().to_public(),
            "svc/a",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        let client_ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (mut app, app_far) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = forward_flow(
                app_far,
                &client_ep,
                relay_addr,
                &client,
                exposer_a_id,
                DialRequest {
                    service: "svc/a".into(),
                    token: dial_cap,
                    e2ee: true,
                },
                PathMode::Relay,
            )
            .await;
        });
        app.write_all(b"x").await.unwrap();
        let mut echoed = [0u8; 1];
        tokio::time::timeout(
            std::time::Duration::from_secs(8),
            app.read_exact(&mut echoed),
        )
        .await
        .expect("the forward flow must establish and bridge to the backend")
        .unwrap();
        assert_eq!(&echoed, b"x", "the flow must echo through the real backend");

        // Exposer B registers svc/b WHILE the flow budget is fully saturated by the held flow above —
        // never shut down, so its one flow permit stays held.
        let publish_cap_b = mint_overlay_publish(
            &exposer_b.id().to_public(),
            "svc/b",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        {
            let exposer_b = OverlaySecret::from_seed_hex(&exposer_b.seed_hex()).unwrap();
            tokio::spawn(async move {
                let _ = run_exposer(
                    &exposer_b,
                    relay_addr,
                    relay_id,
                    "svc/b",
                    publish_cap_b,
                    backend_addr,
                    root_pub,
                )
                .await;
            });
        }
        assert!(
            await_registered(&registry, "svc/b").await,
            "exposer B must still register svc/b despite the saturated flow budget"
        );
    }

    /// Per-source-IP cap (HIGH-1 secondary bound): a single source cannot park more than
    /// `parked_per_ip` concurrent rendezvous. With the cap at 2, two held parks from loopback succeed,
    /// and the THIRD from the same IP is refused `TooManyParked`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_per_source_ip_park_cap_rejects_beyond_the_limit() {
        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let root_pub = root.id().to_public();

        let rendezvous = PairRendezvous::new();
        // Global budget is generous (8) so the per-IP cap (2) is the binding constraint.
        let relay_addr = spawn_ingress_relay_with_budgets(
            &relay,
            root_pub,
            ExposerRegistry::new(),
            rendezvous.clone(),
            PairShortCodes::new(),
            boatramp_overlay_proto::PAIR_SHORT_CODE_DIGITS_DEFAULT,
            IngressBudgets {
                handshakes: 8,
                flows: 8,
                register: 8,
                parked: 8,
                parked_per_ip: 2,
            },
        );

        // Two distinct codes parked from loopback (both held, never redeemed) — within the cap.
        for i in 0..2u8 {
            let code = vec![i; 16];
            let _held = tokio::spawn(async move {
                let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
                let _ = pair_relay_park(&ep, relay_addr, code).await;
            });
        }
        // Wait until both are live in the registry.
        for i in 0..2u8 {
            assert!(
                await_parked(&rendezvous, &[i; 16]).await,
                "park #{i} from loopback must be admitted (under the per-IP cap)"
            );
        }

        // The THIRD park from the SAME IP is refused — the per-IP cap, not the global budget.
        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let third = pair_relay_park(&ep, relay_addr, vec![99u8; 16]).await;
        assert!(
            matches!(
                third,
                Err(NetError::PairRejected(PairReject::TooManyParked))
            ),
            "the 3rd concurrent park from one IP must be refused TooManyParked, got {third:?}"
        );
    }

    /// INFO-2: a wrong-length rendezvous id is rejected `InvalidCode` at BOTH park and redeem — never
    /// parked, never treated as a collision or a miss. (Bounds a flood's registry-key size too.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_wrong_length_rendezvous_code_is_rejected_on_park_and_redeem() {
        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let root_pub = root.id().to_public();

        let rendezvous = PairRendezvous::new();
        let relay_addr = spawn_ingress_relay_with_rendezvous(
            &relay,
            root_pub,
            ExposerRegistry::new(),
            rendezvous,
        );

        // PARK with a 3-byte (not 16) id → InvalidCode.
        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let park = pair_relay_park(&ep, relay_addr, vec![1, 2, 3]).await;
        assert!(
            matches!(park, Err(NetError::PairRejected(PairReject::InvalidCode))),
            "a wrong-length id must be refused InvalidCode on park, got {park:?}"
        );

        // REDEEM with a wrong-length id → InvalidCode (distinct from UnknownOrSpent).
        let ep2 = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let redeem = pair_relay_redeem(&ep2, relay_addr, vec![1, 2, 3]).await;
        assert!(
            matches!(redeem, Err(NetError::PairRejected(PairReject::InvalidCode))),
            "a wrong-length id must be refused InvalidCode on redeem, got {redeem:?}"
        );
    }

    // ---- Pairing SHORT CODES (overlay follow-up #2 inc3) ----

    /// Anti-hollow (mint collision uniqueness): with an injected deterministic draw that repeats the
    /// SAME value on the first call of each mint, minting twice yields two DISTINCT active short
    /// codes — the second mint's first draw collides with the still-live first code, forcing a
    /// regenerate. MUTATION-RED: drop the `collides` check in `PairShortCodes::insert_unique` (always
    /// insert on the first draw) and the second mint would silently reuse the SAME code, clobbering
    /// the first alias's mapping — `assert_ne!` below goes RED.
    #[tokio::test]
    async fn short_code_mint_regenerates_on_collision_and_yields_distinct_codes() {
        let codes = PairShortCodes::new();
        let digits = 8;
        let now = 1_000;
        let expires = now + 300;

        let first = codes
            .insert_unique(|| Ok(12_345_678), digits, vec![1u8; 16], expires, now)
            .await
            .unwrap();

        // The second mint's draw sequence repeats the FIRST code's value once (the collision), then a
        // distinct one on retry — modeling a real RNG that happens to draw the same value, then a
        // fresh one on the next try.
        let mut calls = 0u32;
        let second = codes
            .insert_unique(
                || {
                    calls += 1;
                    Ok(if calls == 1 { 12_345_678 } else { 87_654_321 })
                },
                digits,
                vec![2u8; 16],
                expires,
                now,
            )
            .await
            .unwrap();

        assert_ne!(
            first.digits(),
            second.digits(),
            "a draw colliding with a LIVE alias must regenerate to a DISTINCT code"
        );
        assert!(codes.is_active(first.digits(), now).await);
        assert!(codes.is_active(second.digits(), now).await);
    }

    /// Anti-hollow (exhausted retries): a draw that ALWAYS collides (every attempt returns the same
    /// value as an already-live alias) exhausts the bounded retry budget and errors — it never loops
    /// forever, nor silently returns a colliding/weaker code.
    #[tokio::test]
    async fn short_code_mint_errors_after_exhausting_collision_retries() {
        let codes = PairShortCodes::new();
        let digits = 8;
        let now = 1_000;
        let expires = now + 300;
        let _first = codes
            .insert_unique(|| Ok(11_111_111), digits, vec![1u8; 16], expires, now)
            .await
            .unwrap();
        let result = codes
            .insert_unique(|| Ok(11_111_111), digits, vec![2u8; 16], expires, now)
            .await;
        assert!(
            matches!(result, Err(PairShortCodeError::ExhaustedRetries)),
            "an always-colliding draw must exhaust retries and error, got {result:?}"
        );
    }

    /// Anti-hollow (Security LOW-2, fail-closed RNG): a draw that fails (models a platform
    /// entropy-source fault) must propagate the error — `insert_unique` must NEVER substitute a
    /// zeroed/predictable value and proceed. MUTATION-RED: swallow the draw error (e.g.
    /// `draw().unwrap_or(0)`) and this would instead mint `"00000000"` — the `matches!` below goes RED.
    #[tokio::test]
    async fn short_code_mint_fails_closed_on_an_rng_fault() {
        let codes = PairShortCodes::new();
        let result = codes
            .insert_unique(
                || Err(PairShortCodeError::Rng),
                8,
                vec![1u8; 16],
                1_300,
                1_000,
            )
            .await;
        assert!(
            matches!(result, Err(PairShortCodeError::Rng)),
            "a failing draw must propagate the error, never a zeroed/predictable fallback, got {result:?}"
        );
        // Nothing was minted — no alias of any kind exists.
        assert!(!codes.is_active("00000000", 1_000).await);
    }

    /// Resolve-and-take semantics (unit, no transport): a live alias resolves ONCE (consuming it,
    /// mirroring `PairRendezvous::redeem`'s remove-on-hit) and an expired alias is a miss (pruned).
    #[tokio::test]
    async fn short_codes_resolve_and_take_is_single_use_and_ttl_bound() {
        let codes = PairShortCodes::new();
        let code = codes
            .insert_unique(|| Ok(42), 8, vec![9u8; 16], 100, 50)
            .await
            .unwrap();
        // Live before expiry; resolves to the aliased id and is consumed.
        assert!(codes.is_active(code.digits(), 99).await);
        assert_eq!(
            codes.resolve_and_take(code.digits(), 99).await,
            Some(vec![9u8; 16])
        );
        assert_eq!(
            codes.resolve_and_take(code.digits(), 99).await,
            None,
            "a second resolve of the same alias must find nothing (single-use)"
        );

        // A fresh alias past its expiry is a miss (TTL), even though never resolved.
        let expired = codes
            .insert_unique(|| Ok(43), 8, vec![7u8; 16], 100, 50)
            .await
            .unwrap();
        assert_eq!(codes.resolve_and_take(expired.digits(), 100).await, None);
    }

    /// Full vertical: a human-typeable short code mints, redeems through the relay, and bridges the
    /// SAME way the `bropair1` path does — the SAS pairing handshake completes end-to-end and both
    /// sides derive the identical SAS.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_peers_pair_through_the_short_code_rendezvous_and_derive_the_same_sas() {
        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let accepter = OverlaySecret::generate().unwrap();
        let dialer = OverlaySecret::generate().unwrap();
        let (relay_id, accepter_id, dialer_id) = (relay.id(), accepter.id(), dialer.id());
        let root_pub = root.id().to_public();
        let digits = boatramp_overlay_proto::PAIR_SHORT_CODE_DIGITS_DEFAULT;

        let rendezvous = PairRendezvous::new();
        let short_codes = PairShortCodes::new();
        let relay_addr = spawn_ingress_relay_with_short_codes(
            &relay,
            root_pub,
            ExposerRegistry::new(),
            rendezvous.clone(),
            short_codes.clone(),
            digits,
        );
        let code = vec![0x5Cu8; 16];

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
        assert!(await_parked(&rendezvous, &code).await);

        let now = now_unix();
        let short = short_codes
            .mint(digits, code.clone(), now + 300, now)
            .await
            .unwrap();

        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (dconn, mut dsend, mut drecv) =
            pair_relay_redeem_short(&ep, relay_addr, short.digits().to_string())
                .await
                .unwrap();
        let (sas_d, peer_d) =
            pair_handshake(&mut dsend, &mut drecv, &dialer, Role::Initiator, PAIR_DL)
                .await
                .unwrap();
        dconn.close(0u32.into(), b"paired");

        let (sas_a, peer_a) = acc.await.unwrap();
        assert_eq!(sas_a.bits(), sas_d.bits(), "both ends derive the same SAS");
        assert_eq!(peer_a, dialer_id);
        assert_eq!(peer_d, accepter_id);
    }

    /// Single-use via the short path (rides the existing spent-redeem test): a short-redeem consumes
    /// BOTH the alias and the underlying rendezvous — a second short-redeem of the SAME alias finds
    /// nothing, the SAME `UnknownOrSpent` reject an already-spent FULL id gets.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_short_redeem_consumes_the_underlying_rendezvous_single_use() {
        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let accepter = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let root_pub = root.id().to_public();
        let digits = boatramp_overlay_proto::PAIR_SHORT_CODE_DIGITS_DEFAULT;

        let rendezvous = PairRendezvous::new();
        let short_codes = PairShortCodes::new();
        let relay_addr = spawn_ingress_relay_with_short_codes(
            &relay,
            root_pub,
            ExposerRegistry::new(),
            rendezvous.clone(),
            short_codes.clone(),
            digits,
        );

        let code = vec![0x5Eu8; 16];
        let code_a = code.clone();
        let acc = tokio::spawn(async move {
            let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
            let (conn, mut send, mut recv) =
                pair_relay_park(&ep, relay_addr, code_a).await.unwrap();
            let _ = pair_handshake(&mut send, &mut recv, &accepter, Role::Responder, PAIR_DL).await;
            conn.closed().await;
        });
        assert!(await_parked(&rendezvous, &code).await);
        let now = now_unix();
        let short = short_codes
            .mint(digits, code.clone(), now + 300, now)
            .await
            .unwrap();
        let digits_str = short.digits().to_string();

        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let first = pair_relay_redeem_short(&ep, relay_addr, digits_str.clone()).await;
        assert!(
            first.is_ok(),
            "the first short-redeem must match the parked rendezvous, got {first:?}"
        );

        let ep2 = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let second = pair_relay_redeem_short(&ep2, relay_addr, digits_str).await;
        assert!(
            matches!(
                second,
                Err(NetError::PairRejected(PairReject::UnknownOrSpent))
            ),
            "a second short-redeem of an already-consumed alias must be refused, got {second:?}"
        );
        assert!(
            !rendezvous.is_parked(&code, now_unix()).await,
            "the short path must consume the UNDERLYING rendezvous (rides PairRendezvous::redeem)"
        );
        let _ = acc.await;
    }

    /// Anti-hollow (Security HIGH-1, unbounded `by_ip` memory growth): a source that is only ever
    /// `admit`-checked and never fails (models a flood of malformed-length short-redeems from fresh
    /// IPs, which — after the HIGH-1 order fix — never even reach the limiter, but this pins `admit`
    /// itself too) must NEVER leave a key in `by_ip`; and a key [`PairGuessLimiter::record_failure`]
    /// DOES create is evicted once its rolling window rolls off (the next `admit` for that same IP
    /// prunes its deque to empty and removes the key) — so the map stays bounded by sources with an
    /// actual IN-WINDOW failure, never growing without limit. MUTATION-RED: revert `admit` to
    /// `by_ip.entry(ip).or_default()` (inserting on every call) and the first assertion goes RED.
    #[test]
    fn guess_limiter_by_ip_map_stays_bounded_and_evicts_on_window_roll_off() {
        use std::net::Ipv4Addr;

        let limiter = PairGuessLimiter::new(60, 10, 30);

        // N `admit`-only calls from DISTINCT source IPs, none of which ever fails, must leave `by_ip`
        // EMPTY — `admit` is read-only with respect to map membership.
        for i in 0..20u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            assert!(
                limiter.admit(ip, 1_000),
                "a clean source must always be admitted"
            );
        }
        assert_eq!(
            limiter.by_ip.lock().unwrap().len(),
            0,
            "admit() alone (no record_failure) must NEVER insert/retain a per-IP key"
        );

        // A key `record_failure` DOES create persists while in-window, then is evicted once the
        // window rolls off.
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
        limiter.record_failure(ip, 1_000);
        assert_eq!(
            limiter.by_ip.lock().unwrap().len(),
            1,
            "a failure must be recorded"
        );
        assert!(
            limiter.admit(ip, 1_059),
            "still within the 60s window (1 failure < the cap of 10)"
        );
        assert_eq!(
            limiter.by_ip.lock().unwrap().len(),
            1,
            "the key persists while the recorded failure is still in-window"
        );
        assert!(limiter.admit(ip, 1_061), "past the window — admitted again");
        assert_eq!(
            limiter.by_ip.lock().unwrap().len(),
            0,
            "a key created by record_failure must be evicted once its window rolls off"
        );
    }

    /// Anti-hollow (no distinguishing oracle + only-misses-count): a WRONG short-redeem guess returns
    /// the SAME `UnknownOrSpent` reject a spent/unknown id gets, and repeating it counts against the
    /// per-IP guess budget — after `PAIR_SHORT_GUESS_MAX_PER_IP` such misses, the NEXT attempt is
    /// locked out `TooManyAttempts` EVEN THOUGH it presents the correct, still-live short code (the
    /// lockout check runs BEFORE the code is resolved). MUTATION-RED: drop the pre-resolve lockout
    /// check in `redeem_rendezvous_short` and the final (correct-code) attempt below would succeed
    /// despite the exhausted budget — the last assertion goes RED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn short_redeem_lockout_after_f_ip_failures_blocks_even_a_live_code() {
        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let accepter = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let root_pub = root.id().to_public();
        let digits = boatramp_overlay_proto::PAIR_SHORT_CODE_DIGITS_DEFAULT;

        let rendezvous = PairRendezvous::new();
        let short_codes = PairShortCodes::new();
        let relay_addr = spawn_ingress_relay_with_short_codes(
            &relay,
            root_pub,
            ExposerRegistry::new(),
            rendezvous.clone(),
            short_codes.clone(),
            digits,
        );

        let code = vec![0x9Au8; 16];
        let code_a = code.clone();
        let acc = tokio::spawn(async move {
            let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
            let (conn, mut send, mut recv) =
                pair_relay_park(&ep, relay_addr, code_a).await.unwrap();
            let _ = pair_handshake(&mut send, &mut recv, &accepter, Role::Responder, PAIR_DL).await;
            conn.closed().await;
        });
        assert!(await_parked(&rendezvous, &code).await);
        let now = now_unix();
        let short = short_codes
            .mint(digits, code.clone(), now + 300, now)
            .await
            .unwrap();
        let correct = short.digits().to_string();
        // A same-length, guaranteed-different digit string (bump the last digit, wrapping).
        let wrong = {
            let mut chars: Vec<char> = correct.chars().collect();
            let last = chars.last_mut().unwrap();
            let d = last.to_digit(10).unwrap();
            *last = std::char::from_digit((d + 1) % 10, 10).unwrap();
            chars.into_iter().collect::<String>()
        };

        // F_ip wrong-code attempts from this source — each a genuine miss, each counted.
        for i in 0..PAIR_SHORT_GUESS_MAX_PER_IP {
            let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
            let res = pair_relay_redeem_short(&ep, relay_addr, wrong.clone()).await;
            assert!(
                matches!(res, Err(NetError::PairRejected(PairReject::UnknownOrSpent))),
                "attempt {i}: a wrong guess must be refused UnknownOrSpent, got {res:?}"
            );
        }

        // The source is now over budget: even the CORRECT, still-live short code is refused —
        // checked BEFORE resolution, so the alias is untouched by the refusal.
        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let res = pair_relay_redeem_short(&ep, relay_addr, correct).await;
        assert!(
            matches!(
                res,
                Err(NetError::PairRejected(PairReject::TooManyAttempts))
            ),
            "the source must be locked out after {PAIR_SHORT_GUESS_MAX_PER_IP} failed attempts, got {res:?}"
        );
        assert!(
            short_codes.is_active(short.digits(), now_unix()).await,
            "the live alias must be untouched — the lockout refused the attempt before resolving it"
        );
        let _ = acc.await;
    }

    /// Anti-hollow (Security HIGH-1, call-order): a MALFORMED-LENGTH short-redeem is refused
    /// `InvalidCode` — even from a source ALREADY locked out — proving the length/digit validation
    /// runs BEFORE (and independently of) the guess-rate limiter, so a flood of malformed frames can
    /// never reach (or grow state in) the limiter at all. MUTATION-RED: move the
    /// `guess_limiter.admit(...)` check back before the length/digit validation in
    /// `redeem_rendezvous_short`, and this already-locked-out source's malformed request would instead
    /// be refused `TooManyAttempts` — the assertion below goes RED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_malformed_length_short_redeem_is_refused_invalid_code_even_when_locked_out() {
        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let accepter = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let root_pub = root.id().to_public();
        let digits = boatramp_overlay_proto::PAIR_SHORT_CODE_DIGITS_DEFAULT;

        let rendezvous = PairRendezvous::new();
        let short_codes = PairShortCodes::new();
        let relay_addr = spawn_ingress_relay_with_short_codes(
            &relay,
            root_pub,
            ExposerRegistry::new(),
            rendezvous.clone(),
            short_codes.clone(),
            digits,
        );

        let code = vec![0x9Bu8; 16];
        let code_a = code.clone();
        let acc = tokio::spawn(async move {
            let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
            let (conn, mut send, mut recv) =
                pair_relay_park(&ep, relay_addr, code_a).await.unwrap();
            let _ = pair_handshake(&mut send, &mut recv, &accepter, Role::Responder, PAIR_DL).await;
            conn.closed().await;
        });
        assert!(await_parked(&rendezvous, &code).await);

        // Drive this source over the per-IP budget with well-formed-length WRONG guesses.
        let wrong = "0".repeat(digits);
        for i in 0..PAIR_SHORT_GUESS_MAX_PER_IP {
            let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
            let res = pair_relay_redeem_short(&ep, relay_addr, wrong.clone()).await;
            assert!(
                matches!(res, Err(NetError::PairRejected(PairReject::UnknownOrSpent))),
                "attempt {i}: a wrong guess must be refused UnknownOrSpent, got {res:?}"
            );
        }
        // Confirm the source really is locked out now (sanity, mirrors the sibling lockout test).
        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let locked = pair_relay_redeem_short(&ep, relay_addr, wrong.clone()).await;
        assert!(matches!(
            locked,
            Err(NetError::PairRejected(PairReject::TooManyAttempts))
        ));

        // A MALFORMED-LENGTH request from this SAME (locked-out) source is still `InvalidCode` — the
        // length check runs first and the limiter is never consulted for it.
        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let malformed = "1".repeat(digits - 1); // one digit short
        let res = pair_relay_redeem_short(&ep, relay_addr, malformed).await;
        assert!(
            matches!(res, Err(NetError::PairRejected(PairReject::InvalidCode))),
            "a malformed-length request must be InvalidCode even when the source is locked out, got {res:?}"
        );
        let _ = acc.await;
    }

    /// Anti-hollow (successes never count): `PAIR_SHORT_GUESS_MAX_PER_IP + 1` back-to-back CORRECT
    /// short-redeems (each a distinct, freshly-parked + freshly-minted alias) ALL succeed — if a
    /// successful resolve incorrectly incremented the guess-rate limiter, the
    /// `(PAIR_SHORT_GUESS_MAX_PER_IP + 1)`-th would be refused `TooManyAttempts` despite being correct.
    /// MUTATION-RED: increment the limiter on a HIT (in addition to a miss) in
    /// `redeem_rendezvous_short` and the final iteration's assertion goes RED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn successful_short_redeems_never_count_against_the_guess_limiter() {
        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let root_pub = root.id().to_public();
        let digits = boatramp_overlay_proto::PAIR_SHORT_CODE_DIGITS_DEFAULT;

        let rendezvous = PairRendezvous::new();
        let short_codes = PairShortCodes::new();
        let relay_addr = spawn_ingress_relay_with_short_codes(
            &relay,
            root_pub,
            ExposerRegistry::new(),
            rendezvous.clone(),
            short_codes.clone(),
            digits,
        );

        for i in 0..(PAIR_SHORT_GUESS_MAX_PER_IP + 1) {
            let code = vec![(i + 1) as u8; 16];
            let code_a = code.clone();
            // Fire-and-forget (mirrors the existing `_park` flood-test style), but hand the parked
            // `Connection` back over a oneshot so the test can close it explicitly right after the
            // redeem below — otherwise this source's PARK-budget slot (`PAIR_MAX_PARKED_PER_IP`)
            // would stay held until the idle timeout, exhausting it well before 11 iterations.
            let (parked_tx, parked_rx) = tokio::sync::oneshot::channel();
            let _park = tokio::spawn(async move {
                let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
                let (conn, _send, _recv) = pair_relay_park(&ep, relay_addr, code_a).await.unwrap();
                let _ = parked_tx.send(conn.clone());
                conn.closed().await;
            });
            assert!(
                await_parked(&rendezvous, &code).await,
                "iteration {i}: the park must land"
            );

            let now = now_unix();
            let short = short_codes
                .mint(digits, code.clone(), now + 300, now)
                .await
                .unwrap();

            let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
            let res = pair_relay_redeem_short(&ep, relay_addr, short.digits().to_string()).await;
            assert!(
                res.is_ok(),
                "iteration {i}: a correct short-redeem must succeed (successes never count), got {res:?}"
            );
            if let Ok((conn, _send, _recv)) = res {
                conn.close(0u32.into(), b"done");
            }
            // Release this iteration's park-budget slot immediately (its rendezvous is already
            // consumed) rather than waiting out the idle timeout.
            if let Ok(parked_conn) = parked_rx.await {
                parked_conn.close(0u32.into(), b"redeemed");
            }
        }
    }

    /// Anti-hollow (budget separation / "not a fresh path"): `PairRedeemShort` draws from the SAME
    /// `flow_limiter` as `Dial`/`PairRedeem` — with `flows = 1`, one short-redeem's matched connection
    /// (held open) fills the ENTIRE flow budget, so a concurrent forward dial CANNOT get a flow permit
    /// while it is held (bounded-wait refusal below proves real contention — i.e. the short path is
    /// genuinely capped by the shared budget, not sailing past it on its own pool). Releasing the held
    /// connection frees the permit and the forward dial completes promptly — the sharing is fair
    /// queueing, not a permanent lockout. MUTATION-RED: give `PairRedeemShort` its own semaphore
    /// (never drawing from `flow_limiter`) and the forward dial would succeed IMMEDIATELY even while
    /// "held" — the first (bounded-timeout) assertion goes RED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_short_redeem_draws_from_the_shared_flow_budget_not_an_unbounded_path() {
        let root = OverlaySecret::generate().unwrap();
        let relay = OverlaySecret::generate().unwrap();
        let accepter = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let root_pub = root.id().to_public();
        let digits = boatramp_overlay_proto::PAIR_SHORT_CODE_DIGITS_DEFAULT;

        let rendezvous = PairRendezvous::new();
        let short_codes = PairShortCodes::new();
        // flows = 1: the single short-redeem below fills the ENTIRE flow budget. handshakes/parked are
        // generous so neither is the bottleneck.
        let relay_addr = spawn_ingress_relay_with_budgets(
            &relay,
            root_pub.clone(),
            ExposerRegistry::new(),
            rendezvous.clone(),
            short_codes.clone(),
            digits,
            IngressBudgets {
                handshakes: 8,
                flows: 1,
                register: 8,
                parked: 8,
                parked_per_ip: 4,
            },
        );

        let code = vec![0xF0u8; 16];
        let code_a = code.clone();
        let acc = tokio::spawn(async move {
            let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
            let (conn, mut send, mut recv) =
                pair_relay_park(&ep, relay_addr, code_a).await.unwrap();
            let _ = pair_handshake(&mut send, &mut recv, &accepter, Role::Responder, PAIR_DL).await;
            conn.closed().await;
        });
        assert!(await_parked(&rendezvous, &code).await);
        let now = now_unix();
        let short = short_codes
            .mint(digits, code.clone(), now + 300, now)
            .await
            .unwrap();
        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (held_conn, _hs, _hr) =
            pair_relay_redeem_short(&ep, relay_addr, short.digits().to_string())
                .await
                .expect("the short-redeem must match the live parked rendezvous");

        let token = mint_overlay_dial(
            &client.id().to_public(),
            "svc/none",
            3600,
            now_unix(),
            &root.signer(),
        )
        .await
        .unwrap();
        let egress_id = OverlaySecret::generate().unwrap().id();

        // While the short-redeem's connection is held, a forward dial CANNOT get a flow permit —
        // bounded wait, so this proves real contention rather than hanging forever.
        let client_ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (_app, app_far) = tokio::io::duplex(64 * 1024);
        let blocked = tokio::time::timeout(
            std::time::Duration::from_millis(800),
            forward_flow(
                app_far,
                &client_ep,
                relay_addr,
                &client,
                egress_id,
                DialRequest {
                    service: "svc/none".into(),
                    token: token.clone(),
                    e2ee: true,
                },
                PathMode::Relay,
            ),
        )
        .await;
        assert!(
            blocked.is_err(),
            "a forward dial must NOT get a flow permit while the short-redeem holds the only one"
        );

        // Release the held short-redeem connection — the forward dial now gets its permit.
        held_conn.close(0u32.into(), b"release");
        let client_ep2 = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (_app2, app_far2) = tokio::io::duplex(64 * 1024);
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            forward_flow(
                app_far2,
                &client_ep2,
                relay_addr,
                &client,
                egress_id,
                DialRequest {
                    service: "svc/none".into(),
                    token,
                    e2ee: true,
                },
                PathMode::Relay,
            ),
        )
        .await
        .expect("the forward dial must succeed once the short-redeem releases the flow permit");
        assert!(
            matches!(
                res,
                Err(NetError::DialRejected(DialReject::ServiceNotAuthorized))
            ),
            "got {res:?}"
        );
        let _ = acc.await;
    }

    /// Blindness (rides [`the_pairing_relay_bridges_ciphertext_only_never_the_sas`]): a capturing relay
    /// tees every bridged byte, but the pairing still runs over the SHORT-redeem entry point — the
    /// derived SAS (words + digits + raw bits) appears NOWHERE in what the relay saw, exactly as the
    /// full `bropair1` path. The relay-blind bridge is the SAME code regardless of which entry point
    /// matched the parked connection, so this also stands in for the design note that a short-code
    /// hit is only ever a race-to-redeem — the SAS still catches a misrouting/tampering relay.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_short_redeem_relay_also_bridges_ciphertext_only_never_the_sas() {
        use std::collections::HashMap;

        let relay = OverlaySecret::generate().unwrap();
        let accepter = OverlaySecret::generate().unwrap();
        let dialer = OverlaySecret::generate().unwrap();
        let relay_id = relay.id();
        let code = vec![0x5Du8; 16];

        // A capturing relay: park connections keyed by code; on a SHORT-redeem, open a stream down the
        // (sole) parked connection and bridge both directions while TEEING every byte into `capture`.
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
                            IngressFrame::PairRedeemShort(_req) => {
                                // A single parked accepter in this test — the short-code→id resolution
                                // itself is covered by the dedicated resolve/collision/lockout tests
                                // above; this test is solely about the BRIDGE's blindness.
                                let mut target = None;
                                for _ in 0..100 {
                                    if let Some(c) = parked.lock().await.values().next().cloned() {
                                        target = Some(c);
                                        break;
                                    }
                                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                                }
                                let target = target.expect("a parked accepter");
                                let (mut ps, mut pr) = target.open_bi().await.unwrap();
                                write_msg(&mut send, &PairResult::Ok).await.unwrap();
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
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let ep = quic::client_endpoint_server_auth(&Pin(relay_id)).unwrap();
        let (dconn, mut dsend, mut drecv) =
            pair_relay_redeem_short(&ep, relay_addr, "ignored-by-this-mock".to_string())
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
            "pairing completed through the capturing relay over the short-redeem entry"
        );
        let seen = capture.lock().await.clone();
        assert!(
            !seen.is_empty(),
            "the relay must have bridged the handshake bytes"
        );
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
}
