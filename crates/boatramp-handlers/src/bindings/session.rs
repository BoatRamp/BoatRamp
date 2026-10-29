//! Host binding for the guest `session` capability (`boatramp:handlers/session`) — the import half
//! of the duplex/resumable session primitive (`PLAN-session-primitive`). A session handler imports
//! `send`/`checkpoint`/`close`, which this delegates to an object-safe [`SessionController`] that
//! the server backs with the KV [`SessionStore`](../../../boatramp_server) + the re-entry driver.
//!
//! Intrinsically scoped to the *current* session: the controller is bound host-side to one
//! session (id + verified principal), so the guest names no id and cannot address another session
//! — cross-session/cross-tenant reach is structurally absent, like the `admin` binding's project
//! scoping. Frames are opaque bytes; the binding never parses one.

use std::sync::Arc;

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/session-import-host",
        imports: { default: async },
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

/// How the host terminates TLS to a promote upstream (host-native mirror of the WIT `promote-tls`,
/// mailroom cap-req #22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromoteTls {
    /// Raw TCP — no host crypto on the upstream leg.
    Plaintext,
    /// Implicit TLS at connect (legacy IMAPS/POP3S/SMTPS) — the host terminates TLS strict and
    /// splices the decrypted application bytes.
    ImplicitTls,
}

/// A request to promote the current socket-driven session connection to a persistent duplex splice
/// to a guest-named upstream (mailroom cap-req #22). The host dials through the SAME egress/connect
/// gate `tcp-egress` uses — this request names nothing the guest could not already dial.
#[derive(Debug, Clone)]
pub struct PromoteRequest {
    /// The upstream host (DNS name or IP literal) the guest names.
    pub host: String,
    /// The upstream TCP port.
    pub port: u16,
    /// Whether the host terminates TLS to the upstream.
    pub tls: PromoteTls,
    /// SNI / cert-verification hostname for `ImplicitTls` (defaults to `host` when `None`).
    pub sni: Option<String>,
    /// Opaque bytes written to the upstream BEFORE the splice begins (e.g. a replayed authenticated
    /// login reusing the client's own protocol tag). Bounded host-side.
    pub preamble: Vec<u8>,
}

/// Why a promote failed (host-native; mapped to the WIT `promote-error`). Gate refusals are
/// UNDIFFERENTIATED (`NotAuthorized`) — no topology probing.
#[derive(Debug)]
pub enum PromoteError {
    /// Refused by the reused egress/connect gate (posture off / ungranted / not allowlisted / SSRF
    /// floor). Undifferentiated — promote adds no new reach.
    NotAuthorized,
    /// The dial to the authorized upstream failed (DNS / connect / TLS). Coarse, client-safe reason.
    UpstreamUnreachable(String),
    /// Not a socket-driven listener session, already promoted, or already closed. Fail-closed.
    NotPromotable,
    /// The node is at its persistent-splice ceiling — retryable.
    Capacity,
    /// The preamble exceeded the host's cap.
    PreambleTooLarge,
    /// Any other host-side failure (client-safe).
    Other(String),
}

fn to_wit_promote(err: PromoteError) -> session_types::PromoteError {
    match err {
        PromoteError::NotAuthorized => session_types::PromoteError::NotAuthorized,
        PromoteError::UpstreamUnreachable(m) => session_types::PromoteError::UpstreamUnreachable(m),
        PromoteError::NotPromotable => session_types::PromoteError::NotPromotable,
        PromoteError::Capacity => session_types::PromoteError::Capacity,
        PromoteError::PreambleTooLarge => session_types::PromoteError::PreambleTooLarge,
        PromoteError::Other(m) => session_types::PromoteError::Other(m),
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

    /// Promote the current connection to a persistent duplex splice to the named upstream (mailroom
    /// cap-req #22). The DEFAULT impl refuses with [`PromoteError::NotPromotable`] — only the
    /// socket-driven listener controller (which owns a real client socket to splice) overrides it,
    /// so the KV/SSE HTTP-session transport and any other controller fail-closed by construction.
    async fn promote(&self, _req: PromoteRequest) -> Result<(), PromoteError> {
        Err(PromoteError::NotPromotable)
    }
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

    async fn promote_connection(
        &mut self,
        host: String,
        port: u16,
        tls: session_types::PromoteTls,
        sni: Option<String>,
        preamble: Vec<u8>,
    ) -> Result<(), session_types::PromoteError> {
        // Ungranted ⇒ `not-authorized` (undifferentiated — a guest can't tell "no session grant"
        // from "egress gate refused"), matching the fail-closed posture of the gate itself.
        let Some(binding) = self.binding else {
            return Err(session_types::PromoteError::NotAuthorized);
        };
        let controller = binding.controller.clone();
        let req = PromoteRequest {
            host,
            port,
            tls: match tls {
                session_types::PromoteTls::Plaintext => PromoteTls::Plaintext,
                session_types::PromoteTls::ImplicitTls => PromoteTls::ImplicitTls,
            },
            sni,
            preamble,
        };
        controller.promote(req).await.map_err(to_wit_promote)
    }
}

/// Add the `session` interface to `linker`, resolving the per-invocation [`SessionHost`] via `host`.
struct LinkData;
impl wasmtime::component::HasData for LinkData {
    type Data<'a> = SessionHost<'a>;
}

pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: fn(&mut T) -> SessionHost<'_>,
) -> wasmtime::Result<()> {
    session_iface::add_to_linker::<T, LinkData>(linker, host)
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
