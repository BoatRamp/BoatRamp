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
        // A principal mismatch can't be reached through the controller (which is bound to one
        // verified `(project, id)`); it surfaces at open/re-entry admission in the serving layer. Map
        // it to `AccessDenied` for completeness.
        StoreError::PrincipalMismatch => H::AccessDenied,
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
}
