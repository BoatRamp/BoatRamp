//! Server-side session driver — Stage 3 of the duplex/resumable session primitive
//! (`PLAN-session-primitive`).
//!
//! [`ServerSessionController`] implements the handler-crate [`SessionController`] over the KV
//! [`SessionStore`](crate::session_store), **scoped to one session** (its `(project, id)`): the
//! guest's `send`/`checkpoint`/`close` land in the store for exactly that session — the guest names
//! no id, so cross-session/cross-tenant reach is structurally absent. The [`controller`] builder
//! hands it to `Bindings::with_session` for a re-entry.
//!
//! The re-entry loop itself — dedup the inbound frame, load the resume checkpoint, bind this
//! controller + the verified principal's tenancy (so frame-triggered `sql`/`orm` is host-scoped),
//! and invoke the guest `session-handler` export via `engine.dispatch_session` — is wired to the
//! SSE-out + POST-in routes in the serving layer ([`crate::session_serve`], Stage 4). Frames are
//! opaque bytes throughout.

use std::sync::Arc;

use boatramp_core::time::now_unix_ms;
use boatramp_handlers::SessionController;

use crate::session_store::{SessionStore, StoreError};

/// Map a store error to the handler-crate session error the guest sees. `NotFound` (the session was
/// reaped / never opened) surfaces as `Closed` — the client should stop, not retry.
fn to_handler_err(err: StoreError) -> boatramp_handlers::SessionError {
    use boatramp_core::session::SessionError as Core;
    use boatramp_handlers::SessionError as H;
    match err {
        StoreError::Session(Core::FrameTooLarge) => H::FrameTooLarge,
        StoreError::Session(Core::BufferFull) => H::BufferFull,
        StoreError::Session(Core::Closed) => H::Closed,
        StoreError::NotFound => H::Closed,
        // Neither a principal mismatch nor the project-full cap can be reached through the controller
        // (which is bound to one already-open `(project, id)`); both surface at open/re-entry
        // admission in the serving layer. Map them for completeness.
        StoreError::PrincipalMismatch => H::AccessDenied,
        StoreError::ProjectSessionsFull => H::Other("project session limit reached".into()),
        StoreError::Kv(m) => H::Other(format!("session store: {m}")),
        StoreError::Corrupt(m) => H::Other(format!("session record: {m}")),
    }
}

/// A [`SessionController`] bound to one `(project, id)`, backing every call with the KV store.
pub(crate) struct ServerSessionController {
    store: SessionStore,
    project: String,
    id: String,
}

impl ServerSessionController {
    pub(crate) fn new(
        store: SessionStore,
        project: impl Into<String>,
        id: impl Into<String>,
    ) -> Self {
        Self {
            store,
            project: project.into(),
            id: id.into(),
        }
    }
}

#[async_trait::async_trait]
impl SessionController for ServerSessionController {
    async fn send(&self, payload: Vec<u8>) -> Result<u64, boatramp_handlers::SessionError> {
        self.store
            .send(&self.project, &self.id, payload, now_unix_ms())
            .await
            .map_err(to_handler_err)
    }

    async fn checkpoint(&self, snapshot: Vec<u8>) -> Result<(), boatramp_handlers::SessionError> {
        self.store
            .checkpoint(&self.project, &self.id, snapshot, now_unix_ms())
            .await
            .map_err(to_handler_err)
    }

    async fn close(&self, reason: String) -> Result<(), boatramp_handlers::SessionError> {
        self.store
            .close(&self.project, &self.id, &reason, now_unix_ms())
            .await
            .map_err(to_handler_err)
    }
}

/// Build the scoped controller for `(project, id)` as an `Arc<dyn SessionController>` to bind into a
/// session invocation's `Bindings::with_session`.
pub(crate) fn controller(
    store: SessionStore,
    project: &str,
    id: &str,
) -> Arc<dyn SessionController> {
    Arc::new(ServerSessionController::new(store, project, id))
}

// ---- socket-driven session controller (cap-req 08) ------------------------------------------------

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(feature = "tcp-egress")]
use std::time::Duration;
#[cfg(feature = "tcp-egress")]
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

/// Upper bound on the opaque `promote-connection` preamble (cap-req 22): the bytes the host writes to
/// the authorized upstream before splicing (e.g. a replayed `LOGIN`). A protocol auth line is small;
/// this bounds a runaway guest while comfortably fitting a replayed credential exchange.
#[cfg(feature = "tcp-egress")]
pub(crate) const MAX_PROMOTE_PREAMBLE_BYTES: usize = 64 * 1024;

/// Splice copy-buffer size per direction (cap-req 22) — the duplex relay moves bounded chunks each
/// way, flushing after each so an interactive protocol (IMAP) stays responsive.
#[cfg(feature = "tcp-egress")]
const SPLICE_BUF: usize = 32 * 1024;

/// Idle bound for a promoted duplex splice (cap-req 22): tear it down after this long with NO bytes
/// in EITHER direction, so a silently-dead peer (no FIN) is reaped. Generous enough for an IMAP IDLE
/// connection (which re-arms well within 29 min); the absolute `max_conn_duration` still caps overall.
#[cfg(feature = "tcp-egress")]
const PROMOTED_SPLICE_IDLE: Duration = Duration::from_secs(1740);

/// The boxed async write half of a listener socket, shared between the connection driver and each
/// re-entry's [`SocketSessionController`]. The `tokio::sync::Mutex` serializes guest `send`s (which run
/// one re-entry at a time anyway) and lets the driver hand the same socket to successive re-entries.
pub(crate) type SharedSocketWrite =
    Arc<tokio::sync::Mutex<Box<dyn tokio::io::AsyncWrite + Send + Unpin>>>;

/// Per-connection state a [`SocketSessionController`] shares across the connection's re-entries
/// (cap-req 08): the socket write half, the in-memory resume checkpoint, the closed flag, and the
/// outbound cursor. The driver owns these and clones the `Arc`s into a fresh controller per re-entry.
#[derive(Clone)]
pub(crate) struct SocketSessionState {
    write: SharedSocketWrite,
    checkpoint: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    closed: Arc<AtomicBool>,
    cursor: Arc<AtomicU64>,
    /// The ONE-SHOT promotion request (cap-req 22): set by the controller's `promote` during a
    /// re-entry (carrying the already-dialed, gate-authorized upstream + the held splice permit),
    /// taken by the connection driver AFTER the re-entry returns to run the persistent splice.
    /// `std::sync::Mutex` (not tokio) — only ever a quick set/take, never held across an `.await`.
    #[cfg(feature = "tcp-egress")]
    promotion: Arc<std::sync::Mutex<Option<Promotion>>>,
}

impl SocketSessionState {
    pub(crate) fn new(write: SharedSocketWrite) -> Self {
        Self {
            write,
            checkpoint: Arc::new(std::sync::Mutex::new(None)),
            closed: Arc::new(AtomicBool::new(false)),
            cursor: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "tcp-egress")]
            promotion: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Record a promotion request (cap-req 22) — the controller calls this once the upstream is
    /// dialed + authorized. Returns `false` (so the caller drops the dialed upstream + splice permit,
    /// fail-closed) if the session is already closed or a promotion is already pending (double
    /// promote). The driver takes it with [`take_promotion`](Self::take_promotion) after the re-entry.
    #[cfg(feature = "tcp-egress")]
    pub(crate) fn set_promotion(&self, promo: Promotion) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        let Ok(mut g) = self.promotion.lock() else {
            return false;
        };
        if g.is_some() {
            return false;
        }
        *g = Some(promo);
        true
    }

    /// Whether a promotion has already been requested on this connection (guards a double promote
    /// within one re-entry before the driver takes it).
    #[cfg(feature = "tcp-egress")]
    pub(crate) fn is_promotion_pending(&self) -> bool {
        self.promotion.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Take the pending promotion request, if any (the driver's post-re-entry check).
    #[cfg(feature = "tcp-egress")]
    pub(crate) fn take_promotion(&self) -> Option<Promotion> {
        self.promotion.lock().ok().and_then(|mut g| g.take())
    }

    /// Reclaim the socket write half for the splice (cap-req 22), replacing it with a sink so the
    /// shared cell stays valid. Sound because promotion ends the re-entry model: no controller will
    /// `send` again on this connection, so nothing else races for the writer.
    #[cfg(feature = "tcp-egress")]
    pub(crate) async fn take_write_half(&self) -> Box<dyn tokio::io::AsyncWrite + Send + Unpin> {
        let mut w = self.write.lock().await;
        std::mem::replace(&mut *w, Box::new(tokio::io::sink()))
    }
    /// The current resume checkpoint (the `resumed` for the next re-entry's batch).
    pub(crate) fn checkpoint_snapshot(&self) -> Option<Vec<u8>> {
        self.checkpoint.lock().ok().and_then(|c| c.clone())
    }
    /// Whether the guest has closed the session (end the driver loop).
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Best-effort shut the socket write half (the driver's exit path, when the guest did not itself
    /// `close`). Idempotent with the controller's `close`.
    pub(crate) async fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        let mut w = self.write.lock().await;
        let _ = w.shutdown().await;
    }
}

/// A [`SessionController`] for a session driven over a raw listener socket (cap-req 08). Unlike
/// [`ServerSessionController`] (KV-backed, HTTP transport), the socket itself is the ordered outbound
/// channel: `send` writes the frame straight to the socket (TCP owns ordering/acking, so no KV outbound
/// buffer/cursor/SSE producer is involved); `checkpoint` stashes the resume snapshot in an in-memory
/// per-connection cell (the socket is node-local — it can't migrate nodes or survive a restart, so KV
/// durability buys nothing and in-memory avoids ANY guest-state-at-rest surface); `close` shuts the
/// socket and ends the driver loop. Frames stay opaque bytes; the per-frame + per-checkpoint byte caps
/// are enforced here (defense against a runaway guest).
pub(crate) struct SocketSessionController {
    state: SocketSessionState,
    max_frame_bytes: usize,
    max_checkpoint_bytes: usize,
    /// Promote support (cap-req 22): `Some` ⇒ this listener can escalate to a persistent splice via
    /// the reused egress gate; `None` (no `tcp-egress` feature / posture) ⇒ `promote` fail-closes
    /// `not-authorized`. The dialer + splice-ceiling gate are built once per connection by the driver.
    #[cfg(feature = "tcp-egress")]
    promote: Option<PromoteCtx>,
}

impl SocketSessionController {
    pub(crate) fn new(
        state: SocketSessionState,
        max_frame_bytes: usize,
        max_checkpoint_bytes: usize,
    ) -> Self {
        Self {
            state,
            max_frame_bytes,
            max_checkpoint_bytes,
            #[cfg(feature = "tcp-egress")]
            promote: None,
        }
    }

    /// Attach promote-connection support (cap-req 22) — the egress dialer (reusing the SAME gate as
    /// `tcp-egress`) + the node-global persistent-splice ceiling. Built once per connection and
    /// cloned into each re-entry's controller by the driver.
    #[cfg(feature = "tcp-egress")]
    pub(crate) fn with_promote(mut self, ctx: PromoteCtx) -> Self {
        self.promote = Some(ctx);
        self
    }
}

/// Everything the socket controller needs to service a `promote-connection` (cap-req 22): the
/// gate-reusing egress dialer scoped to this listener's `egress_allowlist`, the node-global
/// persistent-splice ceiling, and the preamble cap. Built once per connection (see
/// `dispatch_session_connection`) and cloned cheaply into each re-entry's controller.
#[cfg(feature = "tcp-egress")]
#[derive(Clone)]
pub(crate) struct PromoteCtx {
    pub dialer: Arc<boatramp_handlers::EgressDialer>,
    pub splice_gate: Arc<tokio::sync::Semaphore>,
    pub max_preamble_bytes: usize,
}

/// A recorded, already-authorized promotion (cap-req 22): the split halves of the host-dialed
/// upstream (DECRYPTED application bytes), the preamble to write before splicing, and the held
/// node-global splice permit (released when this drops — i.e. when the splice ends).
#[cfg(feature = "tcp-egress")]
pub(crate) struct Promotion {
    pub upstream_read: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    pub upstream_write: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    pub preamble: Vec<u8>,
    /// Held for the splice's whole life; dropping it releases the node-global promoted-splice budget.
    pub _splice_permit: tokio::sync::OwnedSemaphorePermit,
}

/// Map a reused-egress-gate error to the guest-facing `PromoteError` (cap-req 22). A gate refusal is
/// UNDIFFERENTIATED (`NotAuthorized`) so the guest can't probe which check failed or map topology;
/// dial failures are coarse + client-safe (the `EgressError` reasons are already sanitized).
#[cfg(feature = "tcp-egress")]
fn map_egress_err(e: boatramp_handlers::EgressError) -> boatramp_handlers::PromoteError {
    use boatramp_handlers::{EgressError as E, PromoteError as P};
    match e {
        E::RefusedByGate => P::NotAuthorized,
        E::DnsFailure => P::UpstreamUnreachable("dns".into()),
        E::ConnectTimeout => P::UpstreamUnreachable("connect timeout".into()),
        E::ConnectFailed(m) | E::TlsFailure(m) | E::Other(m) => P::UpstreamUnreachable(m),
        E::UnsupportedVerifyMode => P::UpstreamUnreachable("tls".into()),
    }
}

#[async_trait::async_trait]
impl SessionController for SocketSessionController {
    async fn send(&self, payload: Vec<u8>) -> Result<u64, boatramp_handlers::SessionError> {
        use boatramp_handlers::SessionError as E;
        if self.state.closed.load(Ordering::Acquire) {
            return Err(E::Closed);
        }
        if payload.len() > self.max_frame_bytes {
            return Err(E::FrameTooLarge);
        }
        let mut w = self.state.write.lock().await;
        w.write_all(&payload)
            .await
            .map_err(|e| E::Other(format!("session socket write: {e}")))?;
        w.flush()
            .await
            .map_err(|e| E::Other(format!("session socket flush: {e}")))?;
        Ok(self.state.cursor.fetch_add(1, Ordering::Relaxed) + 1)
    }

    async fn checkpoint(&self, snapshot: Vec<u8>) -> Result<(), boatramp_handlers::SessionError> {
        use boatramp_handlers::SessionError as E;
        if self.state.closed.load(Ordering::Acquire) {
            return Err(E::Closed);
        }
        if snapshot.len() > self.max_checkpoint_bytes {
            return Err(E::Other(format!(
                "session checkpoint exceeds the {}-byte cap",
                self.max_checkpoint_bytes
            )));
        }
        if let Ok(mut c) = self.state.checkpoint.lock() {
            *c = Some(snapshot);
        }
        Ok(())
    }

    async fn close(&self, _reason: String) -> Result<(), boatramp_handlers::SessionError> {
        // Mark closed first so an in-flight/subsequent send fails closed, then best-effort shut the
        // socket write half (the driver loop also observes `is_closed()` and ends).
        self.state.closed.store(true, Ordering::Release);
        let mut w = self.state.write.lock().await;
        let _ = w.shutdown().await;
        Ok(())
    }

    async fn promote(
        &self,
        req: boatramp_handlers::PromoteRequest,
    ) -> Result<(), boatramp_handlers::PromoteError> {
        use boatramp_handlers::PromoteError as P;
        // Fail-closed up front: a closed connection cannot be (re-)spliced.
        if self.state.is_closed() {
            return Err(P::NotPromotable);
        }
        #[cfg(feature = "tcp-egress")]
        {
            // Already promoting on this connection (double promote within one re-entry) — fail-closed.
            if self.state.is_promotion_pending() {
                return Err(P::NotPromotable);
            }
            // No dialer ⇒ the `tcp-egress` posture is off / not wired for this listener ⇒ the guest
            // could not dial this upstream at all ⇒ undifferentiated `not-authorized` (fail-closed).
            let Some(ctx) = &self.promote else {
                return Err(P::NotAuthorized);
            };
            if req.preamble.len() > ctx.max_preamble_bytes {
                return Err(P::PreambleTooLarge);
            }
            // Acquire the node-global splice permit BEFORE dialing: a ceiling refusal must cost no
            // dial, and the permit is then held for the splice's whole life (inside `Promotion`).
            let Ok(permit) = Arc::clone(&ctx.splice_gate).try_acquire_owned() else {
                return Err(P::Capacity);
            };
            // Dial the upstream through the EXACT reused egress/connect gate (posture + this
            // listener's `egress_allowlist` + SSRF floor + DNS-rebinding choke). NOT a new bypass.
            let tls = match req.tls {
                boatramp_handlers::PromoteTls::Plaintext => boatramp_handlers::DialTls::Plaintext,
                boatramp_handlers::PromoteTls::ImplicitTls => {
                    boatramp_handlers::DialTls::ImplicitTls {
                        sni: req.sni.clone().unwrap_or_else(|| req.host.clone()),
                    }
                }
            };
            let (upstream_read, upstream_write) =
                match ctx.dialer.dial(&req.host, req.port, tls).await {
                    Ok(halves) => halves,
                    Err(e) => {
                        drop(permit); // release the splice slot — the dial did not take it
                        return Err(map_egress_err(e));
                    }
                };
            let promo = Promotion {
                upstream_read,
                upstream_write,
                preamble: req.preamble,
                _splice_permit: permit,
            };
            // Hand it to the driver. A lost race (closed/double-promote since the checks above) drops
            // `promo` here — closing the freshly-dialed upstream + releasing the permit (fail-closed).
            if self.state.set_promotion(promo) {
                Ok(())
            } else {
                Err(P::NotPromotable)
            }
        }
        #[cfg(not(feature = "tcp-egress"))]
        {
            // No outbound egress capability compiled in — there is no authorized way to dial an
            // upstream, so promote is unreachable here. Fail-closed, undifferentiated.
            let _ = req;
            Err(P::NotAuthorized)
        }
    }
}

/// Drive a PROMOTED connection's persistent duplex splice (cap-req 22): write the guest's preamble to
/// the (already gate-authorized) upstream, then relay client <-> upstream both ways until either side
/// closes, the connection's absolute `deadline` fires, or the splice idles out. Runs in the listener's
/// own per-connection task — NOT the session re-entry pool and NOT the shared async lane (the last
/// re-entry future already completed, releasing its session-socket permit, before this begins). The
/// node-global splice permit lives inside `promo` and releases when this returns. Teardown is
/// deterministic: returning drops every half (closing both sockets) and the two pump futures.
#[cfg(feature = "tcp-egress")]
pub(crate) async fn run_promoted_splice<R>(
    client_read: R,
    client_write: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    promo: Promotion,
    deadline: tokio::time::Instant,
    peer: &str,
) -> Result<(), String>
where
    R: tokio::io::AsyncRead + Send + Unpin + 'static,
{
    let Promotion {
        upstream_read,
        mut upstream_write,
        preamble,
        _splice_permit,
    } = promo;

    // Write the preamble to the upstream BEFORE splicing (e.g. the replayed, client-tagged LOGIN).
    // Bounded by the idle budget so a wedged upstream can't pin the task. A failure here means the
    // upstream died before the splice — tear down (returning closes both sides).
    if !preamble.is_empty() {
        match tokio::time::timeout(PROMOTED_SPLICE_IDLE, upstream_write.write_all(&preamble)).await
        {
            Ok(Ok(())) => {
                let _ = tokio::time::timeout(PROMOTED_SPLICE_IDLE, upstream_write.flush()).await;
            }
            _ => {
                tracing::debug!(%peer, "promoted splice: upstream preamble write failed; closing");
                return Ok(());
            }
        }
    }

    // Shared last-activity clock across both directions for the idle watchdog.
    let last = Arc::new(AtomicU64::new(now_unix_ms()));
    let c2u = pump_half(client_read, upstream_write, Arc::clone(&last));
    let u2c = pump_half(upstream_read, client_write, Arc::clone(&last));
    tokio::pin!(c2u, u2c);

    // Re-arm the idle check each loop; the absolute deadline is a hard backstop.
    let idle_tick = PROMOTED_SPLICE_IDLE
        .min(Duration::from_secs(30))
        .max(Duration::from_millis(50));
    loop {
        tokio::select! {
            _ = &mut c2u => { tracing::debug!(%peer, "promoted splice: client->upstream ended; closing"); break; }
            _ = &mut u2c => { tracing::debug!(%peer, "promoted splice: upstream->client ended; closing"); break; }
            _ = tokio::time::sleep_until(deadline) => {
                tracing::debug!(%peer, "promoted splice: hit max_conn_duration; closing");
                break;
            }
            _ = tokio::time::sleep(idle_tick) => {
                let quiet = now_unix_ms().saturating_sub(last.load(Ordering::Relaxed));
                if quiet >= PROMOTED_SPLICE_IDLE.as_millis() as u64 {
                    tracing::debug!(%peer, "promoted splice: idle timeout; closing");
                    break;
                }
            }
        }
    }
    // Returning drops `upstream_*` / `client_*` (both sockets close) + `_splice_permit` (budget freed).
    Ok(())
}

/// One direction of the duplex splice: copy `r -> w` in bounded chunks, flushing after each so an
/// interactive protocol stays responsive, updating the shared activity clock. Ends on EOF (0-byte
/// read) — best-effort shutting the write half — or any read/write error.
#[cfg(feature = "tcp-egress")]
async fn pump_half<Rd, Wr>(mut r: Rd, mut w: Wr, last: Arc<AtomicU64>) -> std::io::Result<()>
where
    Rd: tokio::io::AsyncRead + Unpin,
    Wr: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; SPLICE_BUF];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        last.store(now_unix_ms(), Ordering::Relaxed);
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::session::SessionLimits;

    fn store() -> SessionStore {
        SessionStore::new(Arc::new(MemoryKv::new()), SessionLimits::default())
    }

    // ---- cap-req 22: promote-connection fail-closed branches -------------------------------------

    fn promote_req() -> boatramp_handlers::PromoteRequest {
        boatramp_handlers::PromoteRequest {
            host: "upstream.invalid".into(),
            port: 143,
            tls: boatramp_handlers::PromoteTls::Plaintext,
            sni: None,
            preamble: Vec::new(),
        }
    }

    fn socket_state() -> SocketSessionState {
        let (_client, server) = tokio::io::duplex(64);
        let (_sr, sw) = tokio::io::split(server);
        SocketSessionState::new(Arc::new(tokio::sync::Mutex::new(Box::new(sw))))
    }

    // The DEFAULT `SessionController::promote` (e.g. the KV/SSE `ServerSessionController`) refuses —
    // only a socket-driven listener session can be spliced. Fail-closed by construction.
    #[tokio::test]
    async fn non_socket_controller_refuses_promote() {
        let ctl = ServerSessionController::new(store(), "acme", "sess");
        assert!(matches!(
            SessionController::promote(&ctl, promote_req()).await,
            Err(boatramp_handlers::PromoteError::NotPromotable)
        ));
    }

    // A socket controller with NO promote context (the `tcp-egress` posture off / not wired) refuses
    // UNDIFFERENTIATED `not-authorized` — the guest could not have dialed the upstream at all.
    #[tokio::test]
    async fn socket_controller_without_dialer_is_not_authorized() {
        let ctl = SocketSessionController::new(socket_state(), 8, 8);
        assert!(matches!(
            SessionController::promote(&ctl, promote_req()).await,
            Err(boatramp_handlers::PromoteError::NotAuthorized)
        ));
    }

    // A closed session cannot be promoted (fail-closed up front, before any dial).
    #[tokio::test]
    async fn closed_session_is_not_promotable() {
        let state = socket_state();
        let ctl = SocketSessionController::new(state.clone(), 8, 8);
        ctl.close("done".into()).await.unwrap();
        assert!(matches!(
            SessionController::promote(&ctl, promote_req()).await,
            Err(boatramp_handlers::PromoteError::NotPromotable)
        ));
    }

    // The promotion cell is one-shot: a second `set_promotion` is refused (so a racing double-promote
    // drops its freshly-dialed upstream + splice permit), `take_promotion` yields it exactly once, and
    // `take_write_half` reclaims the socket writer (replacing it with a sink).
    #[cfg(feature = "tcp-egress")]
    #[tokio::test]
    async fn promotion_cell_is_one_shot_and_write_half_reclaims() {
        let state = socket_state();
        let gate = Arc::new(tokio::sync::Semaphore::new(2));
        let mk = |g: &Arc<tokio::sync::Semaphore>| Promotion {
            upstream_read: Box::new(tokio::io::empty()),
            upstream_write: Box::new(tokio::io::sink()),
            preamble: b"pre".to_vec(),
            _splice_permit: Arc::clone(g).try_acquire_owned().unwrap(),
        };
        assert!(state.set_promotion(mk(&gate)));
        assert!(state.is_promotion_pending());
        // Already pending ⇒ a second set is refused (fail-closed against double promote).
        assert!(!state.set_promotion(mk(&gate)));
        let taken = state.take_promotion().expect("one pending promotion");
        assert_eq!(taken.preamble, b"pre");
        assert!(
            state.take_promotion().is_none(),
            "the cell is drained after a take"
        );
        // The write half can be reclaimed for the splice.
        let _writer = state.take_write_half().await;
    }

    #[tokio::test]
    async fn controller_routes_send_checkpoint_close_to_its_session() {
        let s = store();
        s.open("acme", "sess", "GET /a", None, now_unix_ms())
            .await
            .unwrap();
        let ctl = ServerSessionController::new(s.clone(), "acme", "sess");
        assert_eq!(ctl.send(b"hello".to_vec()).await.unwrap(), 1);
        ctl.checkpoint(b"cp".to_vec()).await.unwrap();
        // The outbound frame + checkpoint landed in the store for this session.
        assert_eq!(s.frames_since("acme", "sess", 0).await.unwrap().len(), 1);
        assert_eq!(
            s.resumed("acme", "sess").await.unwrap(),
            Some(b"cp".to_vec())
        );
        // Close, then a send fails closed (mapped from the store's `Closed`).
        ctl.close("done".into()).await.unwrap();
        assert!(matches!(
            ctl.send(b"x".to_vec()).await,
            Err(boatramp_handlers::SessionError::Closed)
        ));
    }

    #[tokio::test]
    async fn a_reaped_session_surfaces_as_closed() {
        let s = store();
        let ctl = ServerSessionController::new(s.clone(), "acme", "ghost");
        // No open → NotFound → the guest sees Closed (stop, don't retry).
        assert!(matches!(
            ctl.send(b"x".to_vec()).await,
            Err(boatramp_handlers::SessionError::Closed)
        ));
    }

    // cap-req 08: the socket controller routes `send`→socket bytes, `checkpoint`→the in-mem cell, and
    // `close`→shutdown (after which send fails closed); frame/checkpoint caps are enforced.
    #[tokio::test]
    async fn socket_controller_routes_send_checkpoint_close() {
        use tokio::io::AsyncReadExt;
        let (client, server) = tokio::io::duplex(64 * 1024);
        // The controller writes the "server→client" direction; read it from the `client` end.
        let (mut client_read, _client_write) = tokio::io::split(client);
        let (_server_read, server_write) = tokio::io::split(server);
        let state =
            SocketSessionState::new(Arc::new(tokio::sync::Mutex::new(Box::new(server_write))));
        let ctl = SocketSessionController::new(state.clone(), 8, 8);

        // send → bytes on the wire + a monotonic cursor.
        assert_eq!(ctl.send(b"hi".to_vec()).await.unwrap(), 1);
        assert_eq!(ctl.send(b"yo".to_vec()).await.unwrap(), 2);
        let mut buf = [0u8; 4];
        client_read.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hiyo");

        // frame cap enforced (max_frame_bytes = 8).
        assert!(matches!(
            ctl.send(vec![0u8; 9]).await,
            Err(boatramp_handlers::SessionError::FrameTooLarge)
        ));

        // checkpoint → the shared in-mem cell (not KV); cap enforced.
        ctl.checkpoint(b"cp".to_vec()).await.unwrap();
        assert_eq!(state.checkpoint_snapshot(), Some(b"cp".to_vec()));
        assert!(ctl.checkpoint(vec![0u8; 9]).await.is_err());

        // close → closed flag set; a subsequent send fails closed.
        assert!(!state.is_closed());
        ctl.close("done".into()).await.unwrap();
        assert!(state.is_closed());
        assert!(matches!(
            ctl.send(b"x".to_vec()).await,
            Err(boatramp_handlers::SessionError::Closed)
        ));
    }

    // cap-req 17: the host-side half of the connect-time dispatch's idempotency contract. The
    // connect dispatch's `SessionBatch.resumed` is built from `state.checkpoint_snapshot()`
    // (`crates/boatramp-server/src/lib.rs`, `dispatch_session_connection`) — a FRESH connection's
    // state must therefore read back `None` (the "not yet greeted" marker a server-speaks-first
    // guest checks), and once the guest checkpoints its `greeted` flag, that SAME cell is what any
    // LATER re-entry on this connection — a normal inbound frame, or a would-be redelivered connect
    // dispatch — would see. Since the host never swaps `state` mid-connection (it is cloned, not
    // replaced, into each re-entry's controller), a second "not yet greeted" `resumed: None` batch on
    // one connection is structurally unreachable: double-greet would require a brand-new
    // `SocketSessionState`, i.e. a genuinely new connection. No wasm needed to prove this half.
    #[tokio::test]
    async fn fresh_socket_state_is_unresumed_and_a_checkpointed_greeted_flag_persists() {
        let (_client, server) = tokio::io::duplex(64);
        let (_server_read, server_write) = tokio::io::split(server);
        let state =
            SocketSessionState::new(Arc::new(tokio::sync::Mutex::new(Box::new(server_write))));

        // A fresh connection's checkpoint is `None` — exactly the `resumed` the connect-time batch
        // carries, i.e. "not yet greeted" from the guest's point of view.
        assert_eq!(state.checkpoint_snapshot(), None);

        // The guest greets on this (connect-time) re-entry and checkpoints `greeted = true` (one
        // byte, mirroring `examples/handlers/session-greet`).
        let ctl = SocketSessionController::new(state.clone(), 64, 8);
        ctl.checkpoint(vec![1]).await.unwrap();

        // A would-be REDELIVERED connect dispatch builds its batch from this SAME state, so its
        // `resumed` is now `Some([1])` — already greeted, never `None` again on this connection.
        assert_eq!(state.checkpoint_snapshot(), Some(vec![1]));
    }
}
