//! KV-backed **session store** — Stage 3 of the duplex/resumable session primitive
//! (`PLAN-session-primitive`). It persists the pure delivery model
//! ([`SessionState`](boatramp_core::session::SessionState)) plus its binding metadata (the verified
//! principal, project, route) under a `session/<project>/<id>` key in the control-plane KV, so the
//! event-driven re-entry driver + the SSE/POST serving layer are crash-safe and (with a lease, a
//! later step) multi-node: between re-entries the *only* session state is here.
//!
//! Each mutation is **load-modify-save** through the KV — correct + durable, and the simplest thing
//! that proves the semantics survive a persistence round-trip. The performance refinement discussed
//! for high-frequency token streaming (a node-local in-memory outbound buffer + coarse KV
//! checkpoints, rather than a KV write per outbound frame) is a **measured Stage-6 optimization**:
//! it changes the *cadence* of persistence, not the record or the operations here.
//!
//! The session id is namespaced under the verified principal's project, so a guest/client can never
//! address another tenant's session (cross-tenant reach is structurally absent). Frames are opaque
//! bytes — the store never parses one.

// A few store primitives (`open`, `principal`, `gc_if_expired`, `frames_since`) are retained as
// tested building blocks that the serving layer doesn't call directly — it uses `open_or_verify`,
// `poll`, `seen`, `send`/`ack`/`record_inbound`/`checkpoint`/`resumed`/`close`, and the
// scheduler-driven `reap_expired`. The allow keeps those test-only primitives from warning.
#![allow(dead_code)]

use std::sync::Arc;

use boatramp_core::kv::KvStore;
use boatramp_core::session::{Cursor, OutboundFrame, SessionError, SessionLimits, SessionState};
use serde::{Deserialize, Serialize};

/// The persisted per-session record: the delivery [`SessionState`] plus its host-bound metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SessionRecord {
    id: String,
    project: String,
    /// The route the session was opened on (for diagnostics + re-entry routing).
    route: String,
    /// The verified principal bound at open (opaque/sealed bytes), carried across re-entries so the
    /// driver rebuilds the identical `HostTenancy` for frame-triggered `sql`/`orm`. `None` = a
    /// `none`-tenancy (anonymous) session.
    principal: Option<Vec<u8>>,
    /// The pure delivery state (cursors, outbound buffer, dedup window, checkpoint, lifetime).
    state: SessionState,
}

/// The `session/<project>/<id>` KV key. Project + id are host-stamped (never guest-forgeable), so
/// the key prefix is the tenant boundary.
fn session_key(project: &str, id: &str) -> String {
    format!("session/{project}/{id}")
}

/// The `session/<project>/` key prefix — every session record for one project (the reaper's scan
/// scope + the per-project live-session count).
fn project_prefix(project: &str) -> String {
    format!("session/{project}/")
}

/// Backstop cap on the number of **live** (unreaped) session records per project, so a burst of
/// fresh opens can't outrun the idle-TTL reaper and grow the KV without bound. Checked only when
/// opening a genuinely new id (a reconnect/POST to an existing session never counts). Generous —
/// a real streaming app runs well under it; a Stage-7 posture knob will make it tunable.
const MAX_SESSIONS_PER_PROJECT: usize = 8192;

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StoreError {
    /// The KV backend errored.
    #[error("session kv error: {0}")]
    Kv(String),
    /// No session with that (project, id) — expired, closed+reaped, or never opened.
    #[error("session not found")]
    NotFound,
    /// A delivery-model rule refused the operation (frame too large / buffer full / closed).
    #[error(transparent)]
    Session(#[from] SessionError),
    /// The stored record could not be (de)serialized — a corrupt/incompatible record.
    #[error("session record corrupt: {0}")]
    Corrupt(String),
    /// A caller tried to (re)open / drive a session id already bound to a **different** verified
    /// principal — a within-project session-hijack attempt. Fail-closed (the caller is refused, the
    /// bound session is untouched). Cross-*tenant* reach is already structurally impossible (the key
    /// is namespaced under the caller's own project), so this guards the within-project case.
    #[error("session principal mismatch")]
    PrincipalMismatch,
    /// The project is at [`MAX_SESSIONS_PER_PROJECT`] live sessions — opening a **new** id is refused
    /// (backpressure) until the reaper frees room, so a burst of opens can't grow the KV unbounded.
    #[error("project session limit reached")]
    ProjectSessionsFull,
}

/// One SSE-producer poll's result (see [`SessionStore::poll`]): the tail frames past the client's
/// cursor, plus the session's terminal status so the producer can end the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionPoll {
    /// Buffered outbound frames with `cursor > after`, in order.
    pub frames: Vec<OutboundFrame>,
    /// `Some(reason)` once the session is closed (emit a final `close` event, then end).
    pub closed: Option<String>,
    /// Whether the session is idle past its TTL / closed (end the stream; it may be reaped).
    pub expired: bool,
}

/// Persists + mutates sessions in the control-plane KV. Cheap to clone (holds an `Arc`).
#[derive(Clone)]
pub(crate) struct SessionStore {
    kv: Arc<dyn KvStore>,
    limits: SessionLimits,
}

impl SessionStore {
    pub(crate) fn new(kv: Arc<dyn KvStore>, limits: SessionLimits) -> Self {
        Self { kv, limits }
    }

    /// The host/operator caps applied to every session (frame size, buffer, dedup window, TTL).
    pub(crate) fn limits(&self) -> &SessionLimits {
        &self.limits
    }

    async fn load(&self, project: &str, id: &str) -> Result<Option<SessionRecord>, StoreError> {
        match self
            .kv
            .get(&session_key(project, id))
            .await
            .map_err(|e| StoreError::Kv(e.to_string()))?
        {
            Some(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).map_err(|e| StoreError::Corrupt(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    async fn put(&self, rec: &SessionRecord) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(rec).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        self.kv
            .put(&session_key(&rec.project, &rec.id), bytes)
            .await
            .map_err(|e| StoreError::Kv(e.to_string()))
    }

    async fn require(&self, project: &str, id: &str) -> Result<SessionRecord, StoreError> {
        self.load(project, id).await?.ok_or(StoreError::NotFound)
    }

    /// Open a session bound to the verified `principal`. Idempotent: a re-open of an existing id is
    /// a no-op (never clobbers live state), so a client retrying the open is safe.
    pub(crate) async fn open(
        &self,
        project: &str,
        id: &str,
        route: &str,
        principal: Option<Vec<u8>>,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        if self.load(project, id).await?.is_some() {
            return Ok(());
        }
        self.put(&SessionRecord {
            id: id.to_string(),
            project: project.to_string(),
            route: route.to_string(),
            principal,
            state: SessionState::new(now_ms),
        })
        .await
    }

    /// Open a session binding `principal`, **or** — if the id already exists — verify the caller's
    /// `principal` matches the bound one, refusing a mismatch ([`StoreError::PrincipalMismatch`]).
    /// This is the session-open/re-entry admission the serving layer runs before every `GET`
    /// (SSE-out) and `POST` (inbound frame): the first caller binds the id to its verified principal,
    /// and any later caller on the same id must present the same principal. A fresh id is opened.
    ///
    /// The `(project, id)` key is already namespaced under the caller's own project, so this can only
    /// ever guard a *within-project* collision — cross-tenant reach is structurally absent. Load →
    /// (verify | put) is not a single atomic CAS (the KV offers none), but the only racer that could
    /// interleave carries the *same* principal in the legitimate case; a mismatched principal is
    /// refused regardless of ordering, and the honest client simply retries its own open.
    pub(crate) async fn open_or_verify(
        &self,
        project: &str,
        id: &str,
        route: &str,
        principal: Option<Vec<u8>>,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        match self.load(project, id).await? {
            Some(rec) => {
                if rec.principal == principal {
                    Ok(())
                } else {
                    Err(StoreError::PrincipalMismatch)
                }
            }
            None => {
                // Opening a genuinely new id: enforce the per-project backstop cap so a flood of
                // fresh opens can't outrun the reaper. (Paid only on new opens, never reconnects.)
                let live = self
                    .kv
                    .list_prefix(&project_prefix(project))
                    .await
                    .map_err(|e| StoreError::Kv(e.to_string()))?
                    .len();
                if live >= MAX_SESSIONS_PER_PROJECT {
                    return Err(StoreError::ProjectSessionsFull);
                }
                self.put(&SessionRecord {
                    id: id.to_string(),
                    project: project.to_string(),
                    route: route.to_string(),
                    principal,
                    state: SessionState::new(now_ms),
                })
                .await
            }
        }
    }

    /// The opaque sealed principal bound at open — compared **for equality** to admit a re-open /
    /// re-entry (a mismatch is a within-project hijack, refused). It is never parsed back into a
    /// `HostTenancy`: a frame re-entry re-resolves the principal from its own request
    /// (`resolve_session_principal`) and host-scopes `sql`/`orm` from that, identically to a normal
    /// handler — the seal is only the identity the re-entry must match.
    pub(crate) async fn principal(
        &self,
        project: &str,
        id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.require(project, id).await?.principal)
    }

    /// Enqueue an outbound frame; returns its host-assigned cursor.
    pub(crate) async fn send(
        &self,
        project: &str,
        id: &str,
        payload: Vec<u8>,
        now_ms: u64,
    ) -> Result<Cursor, StoreError> {
        let mut rec = self.require(project, id).await?;
        let cursor = rec.state.enqueue_outbound(payload, &self.limits, now_ms)?;
        self.put(&rec).await?;
        Ok(cursor)
    }

    /// Record a client ack up to `cursor` (advances monotonically + GCs the acked buffer).
    pub(crate) async fn ack(
        &self,
        project: &str,
        id: &str,
        cursor: Cursor,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let mut rec = self.require(project, id).await?;
        rec.state.ack(cursor, now_ms);
        self.put(&rec).await
    }

    /// Record an inbound frame's idempotency key. `Ok(true)` = new (deliver to the guest), `Ok(false)`
    /// = duplicate within the dedup window (drop — a retried POST).
    pub(crate) async fn record_inbound(
        &self,
        project: &str,
        id: &str,
        idem_key: &str,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let mut rec = self.require(project, id).await?;
        let fresh = rec.state.record_inbound(idem_key, &self.limits, now_ms)?;
        self.put(&rec).await?;
        Ok(fresh)
    }

    /// Whether the session is closed — the serving layer refuses an inbound `POST` on a closed
    /// session with `410 Gone` up front, rather than letting the guest's `send` fail mid-re-entry.
    pub(crate) async fn is_closed(&self, project: &str, id: &str) -> Result<bool, StoreError> {
        Ok(self.require(project, id).await?.state.is_closed())
    }

    /// Whether an inbound idempotency `key` is already within the dedup window (a duplicate to drop),
    /// **without recording it**. The serving layer checks this before a re-entry and commits the key
    /// (via [`record_inbound`](Self::record_inbound)) only after a *successful* dispatch, so a
    /// trapped re-entry redelivers the frame (at-least-once) instead of silently dropping it.
    pub(crate) async fn seen(
        &self,
        project: &str,
        id: &str,
        idem_key: &str,
    ) -> Result<bool, StoreError> {
        Ok(self
            .require(project, id)
            .await?
            .state
            .contains_inbound(idem_key))
    }

    /// Set the resumable checkpoint (a durable persistence point), capped at
    /// [`SessionLimits::max_checkpoint_bytes`] so a guest can't grow the persisted record unbounded.
    pub(crate) async fn checkpoint(
        &self,
        project: &str,
        id: &str,
        snapshot: Vec<u8>,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        if snapshot.len() > self.limits.max_checkpoint_bytes {
            return Err(StoreError::Session(SessionError::FrameTooLarge));
        }
        let mut rec = self.require(project, id).await?;
        rec.state.set_checkpoint(snapshot, now_ms);
        self.put(&rec).await
    }

    /// The last checkpoint (handed to the guest as `resumed` on re-entry).
    pub(crate) async fn resumed(
        &self,
        project: &str,
        id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .require(project, id)
            .await?
            .state
            .resumed()
            .map(<[u8]>::to_vec))
    }

    /// The buffered outbound frames with `cursor > after`, in order — what a reconnecting client
    /// resumes (its `Last-Event-ID`/cursor is `after`).
    pub(crate) async fn frames_since(
        &self,
        project: &str,
        id: &str,
        after: Cursor,
    ) -> Result<Vec<OutboundFrame>, StoreError> {
        Ok(self
            .require(project, id)
            .await?
            .state
            .frames_since(after)
            .cloned()
            .collect())
    }

    /// One SSE-producer poll in a single KV load: the buffered outbound frames with `cursor > after`
    /// (in order), plus whether the session is `closed` (and why) and whether it has `expired`. The
    /// serving layer drains the frames, emits a final `close` event on `closed`, and ends the stream
    /// on `closed`/`expired` (the client reconnects with its `Last-Event-ID` if it still wants it).
    pub(crate) async fn poll(
        &self,
        project: &str,
        id: &str,
        after: Cursor,
        now_ms: u64,
    ) -> Result<SessionPoll, StoreError> {
        let rec = self.require(project, id).await?;
        Ok(SessionPoll {
            frames: rec.state.frames_since(after).cloned().collect(),
            closed: rec.state.close_reason().map(str::to_string),
            expired: rec.state.is_expired(&self.limits, now_ms),
        })
    }

    /// Close the session with a reason (idempotent; a no-op if already reaped).
    pub(crate) async fn close(
        &self,
        project: &str,
        id: &str,
        reason: &str,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        if let Some(mut rec) = self.load(project, id).await? {
            rec.state.close(reason, now_ms);
            self.put(&rec).await?;
        }
        Ok(())
    }

    /// Reap every expired session record for `project` (idle past the TTL, or closed): scan the
    /// project's key prefix and delete each expired record. Returns how many were reaped. Driven by
    /// the scheduler tick (throttled per project) so the KV can't accumulate dead sessions — the
    /// enforcement side of the idle-TTL, paired with the per-project open cap ([`open_or_verify`]).
    ///
    /// Not a CAS (the KV offers none): if a session is reactivated between this load and its delete
    /// it may be reaped a tick early — benign and self-healing (the client reconnects with its
    /// `Last-Event-ID`), the same accepted no-CAS tradeoff as [`open_or_verify`]. Idempotent, so a
    /// multi-node double-reap is harmless.
    pub(crate) async fn reap_expired(
        &self,
        project: &str,
        now_ms: u64,
    ) -> Result<usize, StoreError> {
        let keys = self
            .kv
            .list_prefix(&project_prefix(project))
            .await
            .map_err(|e| StoreError::Kv(e.to_string()))?;
        let mut reaped = 0;
        for key in keys {
            // Load by the raw key (the id may itself contain `/`, e.g. a preview-scoped id), and
            // delete iff expired. A record that vanished between list + load is already gone.
            let Some(bytes) = self
                .kv
                .get(&key)
                .await
                .map_err(|e| StoreError::Kv(e.to_string()))?
            else {
                continue;
            };
            let rec: SessionRecord =
                serde_json::from_slice(&bytes).map_err(|e| StoreError::Corrupt(e.to_string()))?;
            if rec.state.is_expired(&self.limits, now_ms) {
                self.kv
                    .delete(&key)
                    .await
                    .map_err(|e| StoreError::Kv(e.to_string()))?;
                reaped += 1;
            }
        }
        Ok(reaped)
    }

    /// Reap the session iff it is expired (idle past the TTL, or closed) — deletes its KV record.
    /// Returns whether it was reaped. Retained for direct single-session reaping + the store tests.
    pub(crate) async fn gc_if_expired(
        &self,
        project: &str,
        id: &str,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        if let Some(rec) = self.load(project, id).await? {
            if rec.state.is_expired(&self.limits, now_ms) {
                self.kv
                    .delete(&session_key(project, id))
                    .await
                    .map_err(|e| StoreError::Kv(e.to_string()))?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::kv::MemoryKv;

    fn store() -> SessionStore {
        SessionStore::new(
            Arc::new(MemoryKv::new()),
            SessionLimits {
                max_buffered_outbound: 4,
                max_frame_bytes: 16,
                dedup_window: 2,
                max_checkpoint_bytes: 16,
                idle_ttl_ms: 1_000,
            },
        )
    }

    #[tokio::test]
    async fn open_send_ack_survive_the_kv_round_trip() {
        let s = store();
        s.open("acme", "sess1", "GET /agent", Some(b"princ".to_vec()), 10)
            .await
            .unwrap();
        // Re-open is idempotent (a client retry doesn't clobber).
        s.open("acme", "sess1", "GET /agent", None, 11)
            .await
            .unwrap();
        assert_eq!(
            s.principal("acme", "sess1").await.unwrap(),
            Some(b"princ".to_vec())
        );

        assert_eq!(s.send("acme", "sess1", b"a".to_vec(), 12).await.unwrap(), 1);
        assert_eq!(s.send("acme", "sess1", b"b".to_vec(), 13).await.unwrap(), 2);
        // A reconnecting client that saw cursor 1 resumes with 2 (persisted through the KV).
        let tail = s.frames_since("acme", "sess1", 1).await.unwrap();
        assert_eq!(tail.iter().map(|f| f.cursor).collect::<Vec<_>>(), vec![2]);
        s.ack("acme", "sess1", 2, 14).await.unwrap();
        assert!(s.frames_since("acme", "sess1", 0).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn inbound_dedup_and_checkpoint_persist() {
        let s = store();
        s.open("acme", "s", "GET /a", None, 0).await.unwrap();
        assert!(s.record_inbound("acme", "s", "k1", 1).await.unwrap()); // new
        assert!(!s.record_inbound("acme", "s", "k1", 2).await.unwrap()); // dup
        s.checkpoint("acme", "s", b"snapshot".to_vec(), 3)
            .await
            .unwrap();
        assert_eq!(
            s.resumed("acme", "s").await.unwrap(),
            Some(b"snapshot".to_vec())
        );
    }

    #[tokio::test]
    async fn caps_and_missing_and_closed_fail_closed() {
        let s = store();
        // A missing session is NotFound, not a silent success.
        assert!(matches!(
            s.send("acme", "ghost", b"x".to_vec(), 0).await,
            Err(StoreError::NotFound)
        ));
        s.open("acme", "s", "GET /a", None, 0).await.unwrap();
        // Frame-size cap (max 16 bytes).
        assert!(matches!(
            s.send("acme", "s", vec![0u8; 17], 1).await,
            Err(StoreError::Session(SessionError::FrameTooLarge))
        ));
        // Close then no more sends.
        s.close("acme", "s", "done", 2).await.unwrap();
        assert!(matches!(
            s.send("acme", "s", b"x".to_vec(), 3).await,
            Err(StoreError::Session(SessionError::Closed))
        ));
    }

    #[tokio::test]
    async fn open_or_verify_binds_then_refuses_a_different_principal() {
        let s = store();
        // First caller binds the id to its principal.
        s.open_or_verify("acme", "s", "GET /a", Some(b"alice".to_vec()), 0)
            .await
            .unwrap();
        // Same principal re-opening is a no-op success (reconnect / POST after open).
        s.open_or_verify("acme", "s", "GET /a", Some(b"alice".to_vec()), 1)
            .await
            .unwrap();
        // A different principal on the same id is refused (within-project hijack).
        assert!(matches!(
            s.open_or_verify("acme", "s", "GET /a", Some(b"mallory".to_vec()), 2)
                .await,
            Err(StoreError::PrincipalMismatch)
        ));
        // The bound principal is untouched by the refused attempt.
        assert_eq!(
            s.principal("acme", "s").await.unwrap(),
            Some(b"alice".to_vec())
        );
        // An anonymous (None) session is a distinct binding from a principal'd one.
        s.open_or_verify("acme", "anon", "GET /a", None, 3)
            .await
            .unwrap();
        assert!(matches!(
            s.open_or_verify("acme", "anon", "GET /a", Some(b"x".to_vec()), 4)
                .await,
            Err(StoreError::PrincipalMismatch)
        ));
    }

    #[tokio::test]
    async fn seen_checks_without_recording_and_checkpoint_is_capped() {
        let s = store(); // dedup_window 2, max_checkpoint_bytes 16
        s.open("acme", "s", "GET /a", None, 0).await.unwrap();
        // `seen` is a pure read: it never records, so repeated checks stay false until `record_inbound`.
        assert!(!s.seen("acme", "s", "k1").await.unwrap());
        assert!(!s.seen("acme", "s", "k1").await.unwrap());
        assert!(s.record_inbound("acme", "s", "k1", 1).await.unwrap());
        assert!(s.seen("acme", "s", "k1").await.unwrap());
        // A checkpoint over the cap is refused (fail-closed), under it persists.
        assert!(matches!(
            s.checkpoint("acme", "s", vec![0u8; 17], 2).await,
            Err(StoreError::Session(SessionError::FrameTooLarge))
        ));
        s.checkpoint("acme", "s", vec![0u8; 16], 3).await.unwrap();
        assert_eq!(s.resumed("acme", "s").await.unwrap(), Some(vec![0u8; 16]));
    }

    #[tokio::test]
    async fn reap_expired_deletes_only_idle_records_across_the_project() {
        let s = store(); // idle_ttl_ms 1_000
        s.open("acme", "live", "GET /a", None, 0).await.unwrap();
        s.open("acme", "idle", "GET /a", None, 0).await.unwrap();
        // Keep `live` active at t=2000; `idle` stays untouched (last_active 0).
        s.send("acme", "live", b"x".to_vec(), 2_000).await.unwrap();
        // Reap at t=2000: only `idle` (0 + 1000 < 2000) is gone; `live` survives.
        assert_eq!(s.reap_expired("acme", 2_000).await.unwrap(), 1);
        assert!(matches!(
            s.principal("acme", "idle").await,
            Err(StoreError::NotFound)
        ));
        assert!(s.principal("acme", "live").await.is_ok());
        // A different project is never touched by acme's reap.
        s.open("globex", "idle", "GET /a", None, 0).await.unwrap();
        assert_eq!(s.reap_expired("acme", 9_999).await.unwrap(), 1); // only acme/live now
        assert!(s.principal("globex", "idle").await.is_ok());
    }

    #[tokio::test]
    async fn poll_returns_tail_frames_then_reports_closed() {
        let s = store();
        s.open("acme", "s", "GET /a", None, 0).await.unwrap();
        s.send("acme", "s", b"one".to_vec(), 1).await.unwrap();
        s.send("acme", "s", b"two".to_vec(), 2).await.unwrap();
        // A client at cursor 1 polls and sees only frame 2, still open.
        let p = s.poll("acme", "s", 1, 3).await.unwrap();
        assert_eq!(
            p.frames.iter().map(|f| f.cursor).collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(p.closed, None);
        assert!(!p.expired);
        // After close the poll reports the reason (buffer dropped) and expiry.
        s.close("acme", "s", "bye", 4).await.unwrap();
        let p = s.poll("acme", "s", 0, 5).await.unwrap();
        assert!(p.frames.is_empty());
        assert_eq!(p.closed.as_deref(), Some("bye"));
        assert!(p.expired);
    }

    #[tokio::test]
    async fn keyspace_isolates_projects_and_gc_reaps() {
        let s = store();
        s.open("acme", "s", "GET /a", None, 0).await.unwrap();
        s.open("globex", "s", "GET /a", None, 0).await.unwrap();
        s.send("acme", "s", b"acme-only".to_vec(), 1).await.unwrap();
        // Same id, different project → independent (no cross-tenant bleed).
        assert!(s.frames_since("globex", "s", 0).await.unwrap().is_empty());
        assert_eq!(s.frames_since("acme", "s", 0).await.unwrap().len(), 1);
        // GC reaps only once idle past the TTL (1000ms).
        assert!(!s.gc_if_expired("acme", "s", 500).await.unwrap());
        assert!(s.gc_if_expired("acme", "s", 2_000).await.unwrap());
        assert!(matches!(
            s.send("acme", "s", b"x".to_vec(), 2_001).await,
            Err(StoreError::NotFound)
        ));
    }
}
