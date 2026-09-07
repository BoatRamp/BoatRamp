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

// The store's consumers — the event-driven re-entry driver (Stage 3) and the SSE/POST serving
// layer (Stage 4) — land next; until then its API is exercised only by the unit tests below. The
// allow is removed when the driver wires it in.
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

    /// The verified principal bound at open — the driver rebuilds `HostTenancy` from it so
    /// frame-triggered `sql`/`orm` is host-scoped identically to a normal handler.
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

    /// Set the resumable checkpoint (a durable persistence point).
    pub(crate) async fn checkpoint(
        &self,
        project: &str,
        id: &str,
        snapshot: Vec<u8>,
        now_ms: u64,
    ) -> Result<(), StoreError> {
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

    /// Reap the session iff it is expired (idle past the TTL, or closed) — deletes its KV record.
    /// Returns whether it was reaped. The GC loop calls this over `list`ed session keys.
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
