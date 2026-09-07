//! Host binding for the guest `session` capability (`boatramp:handlers/session`) — the import half
//! of the duplex/resumable session primitive (`PLAN-session-primitive`). A session handler imports
//! `send`/`checkpoint`/`close`, which this delegates to an object-safe [`SessionController`] that
//! the server backs with the KV [`SessionStore`](../../../boatramp_server) + the re-entry driver.
//!
//! Intrinsically scoped to the *current* session: the controller is bound host-side to one
//! session (id + verified principal), so the guest names no id and cannot address another session
//! — cross-session/cross-tenant reach is structurally absent, like the `admin` binding's project
//! scoping. Frames are opaque bytes; the binding never parses one.

// `SessionHost`/`add_to_linker` are wired into the engine linker by the re-entry dispatch (next
// step); until then they're exercised only by the unit tests below. The allow is removed then.
#![allow(dead_code)]

use std::sync::Arc;

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/session-import-host",
        async: {
            only_imports: ["send", "checkpoint", "close"],
        },
    });
}

use generated::boatramp::handlers::{session as session_iface, session_types};

/// Why a session host call failed (host-native; mapped to the WIT `session-error`).
#[derive(Debug)]
pub enum SessionError {
    /// The `session` capability was not granted to this component.
    AccessDenied,
    /// The frame exceeded the host's per-frame byte cap.
    FrameTooLarge,
    /// The unacked outbound buffer is full — backpressure.
    BufferFull,
    /// The session is closed.
    Closed,
    /// Any other backend error.
    Other(String),
}

fn to_wit(err: SessionError) -> session_types::SessionError {
    match err {
        SessionError::AccessDenied => session_types::SessionError::AccessDenied,
        SessionError::FrameTooLarge => session_types::SessionError::FrameTooLarge,
        SessionError::BufferFull => session_types::SessionError::BufferFull,
        SessionError::Closed => session_types::SessionError::Closed,
        SessionError::Other(m) => session_types::SessionError::Other(m),
    }
}

/// The server-side session controller a binding delegates to. Bound host-side to the **current**
/// session (its id + verified principal), so the guest addresses no id. The server implements this
/// over the KV session store; every call persists through it (crash-safe re-entry).
#[async_trait::async_trait]
pub trait SessionController: Send + Sync {
    /// Enqueue an outbound frame (host → client); returns its host-assigned cursor.
    async fn send(&self, payload: Vec<u8>) -> Result<u64, SessionError>;
    /// Set the resumable checkpoint (host persists it; replayed on the next re-entry).
    async fn checkpoint(&self, snapshot: Vec<u8>) -> Result<(), SessionError>;
    /// End the session with a reason; the client is notified.
    async fn close(&self, reason: String) -> Result<(), SessionError>;
}

/// A `session` grant: the controller bound to the current session. Its presence *is* the grant
/// (deny-by-default — an ungranted handler has no binding and every call is `access-denied`).
#[derive(Clone)]
pub struct SessionBinding {
    pub(crate) controller: Arc<dyn SessionController>,
}

/// Per-invocation view over the (optional) session grant.
pub struct SessionHost<'a> {
    binding: Option<&'a SessionBinding>,
}

impl<'a> SessionHost<'a> {
    pub fn new(binding: Option<&'a SessionBinding>) -> Self {
        Self { binding }
    }

    /// The controller, or `access-denied` when the capability is ungranted. Returns an owned `Arc`
    /// so no borrow of `self` is held across the subsequent `.await`.
    fn controller(&self) -> Result<Arc<dyn SessionController>, session_types::SessionError> {
        Ok(self
            .binding
            .ok_or(session_types::SessionError::AccessDenied)?
            .controller
            .clone())
    }
}

impl session_iface::Host for SessionHost<'_> {
    async fn send(&mut self, payload: Vec<u8>) -> Result<u64, session_types::SessionError> {
        let controller = self.controller()?;
        controller.send(payload).await.map_err(to_wit)
    }

    async fn checkpoint(&mut self, snapshot: Vec<u8>) -> Result<(), session_types::SessionError> {
        let controller = self.controller()?;
        controller.checkpoint(snapshot).await.map_err(to_wit)
    }

    async fn close(&mut self, reason: String) -> Result<(), session_types::SessionError> {
        let controller = self.controller()?;
        controller.close(reason).await.map_err(to_wit)
    }
}

/// Add the `session` interface to `linker`, resolving the per-invocation [`SessionHost`] via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> SessionHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    session_iface::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::session_iface::Host;
    use super::*;
    use std::sync::Mutex;

    /// A controller that records its calls (and always succeeds).
    #[derive(Default)]
    struct RecordingController {
        calls: Mutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl SessionController for RecordingController {
        async fn send(&self, payload: Vec<u8>) -> Result<u64, SessionError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("send:{}", payload.len()));
            Ok(1)
        }
        async fn checkpoint(&self, snapshot: Vec<u8>) -> Result<(), SessionError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("checkpoint:{}", snapshot.len()));
            Ok(())
        }
        async fn close(&self, reason: String) -> Result<(), SessionError> {
            self.calls.lock().unwrap().push(format!("close:{reason}"));
            Ok(())
        }
    }

    #[tokio::test]
    async fn granted_host_delegates_to_the_controller() {
        let binding = SessionBinding {
            controller: Arc::new(RecordingController::default()),
        };
        let mut host = SessionHost::new(Some(&binding));
        assert_eq!(host.send(b"abc".to_vec()).await.unwrap(), 1);
        host.checkpoint(b"snap".to_vec()).await.unwrap();
        host.close("done".into()).await.unwrap();
        // (the controller recorded send:3 / checkpoint:4 / close:done)
    }

    #[tokio::test]
    async fn ungranted_host_is_access_denied() {
        let mut host = SessionHost::new(None);
        assert!(matches!(
            host.send(b"x".to_vec()).await,
            Err(session_types::SessionError::AccessDenied)
        ));
        assert!(matches!(
            host.checkpoint(b"x".to_vec()).await,
            Err(session_types::SessionError::AccessDenied)
        ));
        assert!(matches!(
            host.close("x".into()).await,
            Err(session_types::SessionError::AccessDenied)
        ));
    }
}
