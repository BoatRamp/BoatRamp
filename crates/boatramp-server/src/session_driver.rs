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
use tokio::io::AsyncWriteExt;

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
}

impl SocketSessionState {
    pub(crate) fn new(write: SharedSocketWrite) -> Self {
        Self {
            write,
            checkpoint: Arc::new(std::sync::Mutex::new(None)),
            closed: Arc::new(AtomicBool::new(false)),
            cursor: Arc::new(AtomicU64::new(0)),
        }
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
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::session::SessionLimits;

    fn store() -> SessionStore {
        SessionStore::new(Arc::new(MemoryKv::new()), SessionLimits::default())
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
}
