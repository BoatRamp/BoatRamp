//! The host-side egress **SELF-REGISTER** binding (`boatramp:handlers/egress-register`,
//! PLAN-egress-runtime-authz #12, Surface 2): the guest-facing companion to the control-plane
//! `HandlerPolicy·Write` overlay edit. A GRANTED, posture-ON guest REPLACE-SETs the `host:port`s its
//! OWN workload may dial; the HOST persists them to the SAME `handlers.egress_allow` site-config
//! overlay the control-plane PUT edits, SCOPED to THIS invocation's own per-workload key. No
//! control-plane token ever crosses to the guest.
//!
//! # Self-scoped (the load-bearing capability invariant)
//! The guest passes ONLY the host set — NEVER a key. The host-held [`EgressRegisterWriter`] carries the
//! per-workload key baked at `build_bindings` (the handler/cron `route`, the consumer `topic`, the
//! session's creating route) — the SAME key the dial's own egress-overlay union reads — so a guest can
//! set ONLY its own workload's egress and can never name (or reach) another workload's overlay.
//!
//! # Fail-closed gate
//! 1. **Node posture `allow_guest_egress_register`** (carried as `posture_enabled`, OFF by default):
//!    off ⇒ `access-denied`. Deny-by-default per grant too — the binding is `None` when ungranted.
//! 2. **Register-time validation** (in the writer): every entry's `host:port` grammar + the SSRF floor
//!    is checked BEFORE any persist (all-or-nothing); the UNCHANGED dial-time floor stays authoritative.
//!
//! # STORE-RESIDENT state (the host-view-rebuild footgun)
//! wasmtime REBUILDS this host view on EVERY host call, so the writer + posture live in the
//! store-resident [`EgressRegisterBinding`] (a field of `HostState.bindings`), BORROWED by the per-call
//! [`EgressRegisterHost`] view. `set-egress` is stateless (it persists to the control-plane store), so
//! there is no mutable per-call view state to reset — nothing is kept on the view.

use std::sync::Arc;

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/egress-register-host",
        imports: { default: async },
    });
}

use generated::boatramp::handlers::egress_register;

/// Why a host-side egress self-register persist failed (host-internal; the binding maps it to the WIT
/// `egress-register-error`). The posture / grant deny is decided by the binding, never the writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressRegisterWriteError {
    /// An entry is not a well-formed `host:port` / `ip:port` / `CIDR:port`, or it fails the SSRF floor
    /// at register (a non-global / internal / metadata target). Carries the offending entry. Nothing
    /// is persisted (all-or-nothing on validation).
    InvalidEntry(String),
    /// The overlay could not be persisted (a transient control-plane store error). Nothing partial.
    Backend(String),
}

/// The host-held WRITER that REPLACE-SETs a workload's egress overlay. Implemented by the server (which
/// owns the site-config store); injected into the binding with the per-workload key + `(project, site)`
/// already BAKED, so the guest can never influence the scope. `set_egress` validates every entry's
/// grammar + the SSRF floor BEFORE persisting (all-or-nothing), then atomically read-modify-writes THIS
/// workload's `egress_allow` entry (an empty list de-registers).
#[async_trait::async_trait]
pub trait EgressRegisterWriter: Send + Sync {
    /// REPLACE-SET this workload's overlay to exactly `hosts` (host-scoped to the baked workload key).
    async fn set_egress(&self, hosts: Vec<String>) -> Result<(), EgressRegisterWriteError>;
    /// The baked per-workload key this writer is scoped to (for the mutation-gate assertion + logs).
    fn workload_key(&self) -> &str;
}

/// Store-resident binding (a field of `HostState.bindings`): the host-held writer, baked to THIS
/// invocation's per-workload key. Borrowed (not owned) by the per-call [`EgressRegisterHost`] view.
/// The node posture (`allow_guest_egress_register`) is NOT carried here — it is applied by the view
/// from the invocation's `HostState`, exactly like `DnsPublishHost`'s posture.
#[derive(Clone)]
pub struct EgressRegisterBinding {
    writer: Arc<dyn EgressRegisterWriter>,
}

impl EgressRegisterBinding {
    /// Grant the capability, backed by the host-held `writer` (baked to THIS invocation's workload key).
    #[must_use]
    pub fn new(writer: Arc<dyn EgressRegisterWriter>) -> Self {
        Self { writer }
    }
    /// The baked per-workload key the write targets (and the dial reads) — same source, drift-proof.
    #[must_use]
    pub fn workload_key(&self) -> &str {
        self.writer.workload_key()
    }
}

/// The per-invocation host view (REBUILT on every host call — holds only a BORROW of the store-resident
/// binding + the node posture copied from `HostState`; no mutable per-call state).
pub struct EgressRegisterHost<'a> {
    binding: Option<&'a EgressRegisterBinding>,
    /// The node posture `allow_guest_egress_register` (from `HostState`). OFF ⇒ `access-denied`.
    posture_enabled: bool,
}

impl<'a> EgressRegisterHost<'a> {
    /// Build the per-call view borrowing the store-resident binding (`None` ⇒ ungranted ⇒ deny-all)
    /// and the node posture (off ⇒ deny-all).
    #[must_use]
    pub fn new(binding: Option<&'a EgressRegisterBinding>, posture_enabled: bool) -> Self {
        Self {
            binding,
            posture_enabled,
        }
    }
}

impl egress_register::Host for EgressRegisterHost<'_> {
    async fn set_egress(
        &mut self,
        hosts: Vec<String>,
    ) -> Result<(), egress_register::EgressRegisterError> {
        // Fail-closed: posture off ⇒ `access-denied`, nothing written.
        if !self.posture_enabled {
            return Err(egress_register::EgressRegisterError::AccessDenied);
        }
        // Fail-closed: ungranted (binding `None`) ⇒ `access-denied`, nothing written.
        let Some(b) = self.binding else {
            return Err(egress_register::EgressRegisterError::AccessDenied);
        };
        // Delegate to the host-held writer (baked to THIS workload's key — the guest supplied no key):
        // it validates every entry's grammar + the SSRF floor BEFORE persisting (all-or-nothing), then
        // replace-sets the overlay. The UNCHANGED dial-time floor stays authoritative regardless.
        match b.writer.set_egress(hosts).await {
            Ok(()) => Ok(()),
            Err(EgressRegisterWriteError::InvalidEntry(e)) => {
                Err(egress_register::EgressRegisterError::InvalidEntry(e))
            }
            Err(EgressRegisterWriteError::Backend(e)) => {
                Err(egress_register::EgressRegisterError::Backend(e))
            }
        }
    }
}

/// Add the `egress-register` interface to `linker`, resolving the per-invocation
/// [`EgressRegisterHost`] view via `host`.
struct LinkData;
impl wasmtime::component::HasData for LinkData {
    type Data<'a> = EgressRegisterHost<'a>;
}

/// Link the `boatramp:handlers/egress-register` import, resolving the per-invocation view via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: fn(&mut T) -> EgressRegisterHost<'_>,
) -> wasmtime::Result<()> {
    egress_register::add_to_linker::<T, LinkData>(linker, host)
}

#[cfg(test)]
mod tests {
    use super::egress_register::Host;
    use super::*;
    use std::sync::Mutex;

    /// A stub writer recording its calls, so a test can assert the binding did (or did NOT) delegate.
    struct StubWriter {
        key: String,
        calls: Mutex<Vec<Vec<String>>>,
    }
    impl StubWriter {
        fn new(key: &str) -> Arc<Self> {
            Arc::new(Self {
                key: key.to_string(),
                calls: Mutex::new(Vec::new()),
            })
        }
        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }
    #[async_trait::async_trait]
    impl EgressRegisterWriter for StubWriter {
        async fn set_egress(&self, hosts: Vec<String>) -> Result<(), EgressRegisterWriteError> {
            self.calls.lock().unwrap().push(hosts);
            Ok(())
        }
        fn workload_key(&self) -> &str {
            &self.key
        }
    }

    /// Gate 7b (posture-off / ungranted ⇒ deny-by-default): the binding refuses with `access-denied`
    /// and NEVER delegates to the writer (nothing is persisted) when the binding is absent or the
    /// posture is off; only a granted + posture-on call reaches the writer.
    #[tokio::test]
    async fn posture_off_or_ungranted_denies_without_writing() {
        let w = StubWriter::new("/fetch");
        let binding = EgressRegisterBinding::new(w.clone());
        assert_eq!(
            binding.workload_key(),
            "/fetch",
            "the binding exposes its baked key"
        );

        // (a) ungranted (binding None), posture on ⇒ access-denied.
        let mut ungranted = EgressRegisterHost::new(None, true);
        assert!(
            matches!(
                ungranted.set_egress(vec!["imap.x:993".into()]).await,
                Err(egress_register::EgressRegisterError::AccessDenied)
            ),
            "ungranted must be access-denied"
        );

        // (b) granted but posture OFF ⇒ access-denied, and the writer is NEVER called.
        let mut host_off = EgressRegisterHost::new(Some(&binding), false);
        assert!(
            matches!(
                host_off.set_egress(vec!["imap.x:993".into()]).await,
                Err(egress_register::EgressRegisterError::AccessDenied)
            ),
            "posture off must be access-denied"
        );
        assert_eq!(
            w.call_count(),
            0,
            "posture off must NOT delegate to the writer (nothing persisted)"
        );

        // (c) granted + posture ON ⇒ the call reaches the writer exactly once, scoped to its baked key.
        let mut host_on = EgressRegisterHost::new(Some(&binding), true);
        host_on
            .set_egress(vec!["imap.x:993".into()])
            .await
            .expect("granted + posture on succeeds");
        assert_eq!(w.call_count(), 1, "granted + posture on delegates once");
    }
}
