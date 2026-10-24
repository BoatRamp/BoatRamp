//! The `tcp-connection-context` capability host binding (`boatramp:handlers/tcp-connection-context`,
//! mailroom cap-req #16): a host-owned listener guest reads the CURRENT wire security of its
//! connection, so an IMAP/SMTP guest can refuse AUTH/credentials over plaintext and advertise
//! STARTTLS only before an upgrade.
//!
//! Unlike the OUTBOUND [`tcp_egress`](super::tcp_egress) binding this carries no streams and does no
//! I/O — it is a pure, sync read of a per-connection flag. Bound host-side to THIS connection (the
//! guest names no id, like [`target_context`](super::target_context) / `tenancy.current-principal`).
//!
//! # Fail-closed
//! The host returns [`TransportSecurity::Tls`] ONLY when the wire is actually TLS-protected. A
//! non-listener invocation has no [`ConnectionSecurity`] handle and reads as
//! [`TransportSecurity::Plaintext`] — never a false `tls` — so a guest gating AUTH on `tls-active`
//! stays safe under any ambiguity.
//!
//! # STARTTLS live flip
//! For an implicit-TLS listener the handle is created [`ConnectionSecurity::tls`] and never changes.
//! For a STARTTLS listener it starts [`ConnectionSecurity::starttls_pending`] and the host's STARTTLS
//! pump calls [`ConnectionSecurity::mark_tls_active`] the instant the in-band upgrade completes —
//! with `Release` ordering, BEFORE the first decrypted byte is forwarded to the guest — so a guest
//! reading the state while handling any post-upgrade byte always observes `tls`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/tcp-connection-context-host",
    });
}

use generated::boatramp::handlers::tcp_connection_context;
pub use tcp_connection_context::TransportSecurity;

// Wire-security encoding for the lock-free per-connection flag.
const SEC_PLAINTEXT: u8 = 0;
const SEC_TLS: u8 = 1;
const SEC_STARTTLS_PENDING: u8 = 2;

/// A cheap, cloneable handle to ONE listener connection's live wire-security state (mailroom cap-req
/// #16). The serve accept loop creates one per accepted connection and threads a clone into the
/// engine dispatch (which exposes it through this binding) and — for a STARTTLS listener — into the
/// pump (which flips it to TLS on upgrade). Reads are fail-closed via [`ConnContextHost`].
#[derive(Clone)]
pub struct ConnectionSecurity(Arc<AtomicU8>);

impl ConnectionSecurity {
    /// Implicit TLS from connect (e.g. :993 / :465) — TLS for the connection's whole life.
    pub fn tls() -> Self {
        Self(Arc::new(AtomicU8::new(SEC_TLS)))
    }

    /// A plaintext listener — no TLS, none negotiable.
    pub fn plaintext() -> Self {
        Self(Arc::new(AtomicU8::new(SEC_PLAINTEXT)))
    }

    /// A STARTTLS-capable listener before the in-band upgrade (plaintext on the wire for now).
    pub fn starttls_pending() -> Self {
        Self(Arc::new(AtomicU8::new(SEC_STARTTLS_PENDING)))
    }

    /// Mark the wire TLS-active (the in-band STARTTLS upgrade completed). `Release` so the store
    /// happens-before any subsequently-forwarded decrypted byte the guest will read (paired with the
    /// `Acquire` load in [`current`](Self::current)).
    pub fn mark_tls_active(&self) {
        self.0.store(SEC_TLS, Ordering::Release);
    }

    /// The current state as the WIT enum. An unknown encoding fails closed to `plaintext`.
    fn current(&self) -> TransportSecurity {
        match self.0.load(Ordering::Acquire) {
            SEC_TLS => TransportSecurity::Tls,
            SEC_STARTTLS_PENDING => TransportSecurity::StarttlsPending,
            _ => TransportSecurity::Plaintext,
        }
    }
}

/// Per-invocation view: the connection's security handle, or `None` for a non-listener invocation
/// (which fail-closes to `plaintext`).
pub struct ConnContextHost {
    security: Option<ConnectionSecurity>,
}

impl ConnContextHost {
    /// Build a view from the invocation's connection-security handle (`None` ⇒ not a listener).
    pub fn new(security: Option<ConnectionSecurity>) -> Self {
        Self { security }
    }
}

impl tcp_connection_context::Host for ConnContextHost {
    fn security(&mut self) -> TransportSecurity {
        // Fail-closed: no handle (non-listener invocation) ⇒ plaintext, never a false `tls`.
        self.security
            .as_ref()
            .map_or(TransportSecurity::Plaintext, ConnectionSecurity::current)
    }

    fn tls_active(&mut self) -> bool {
        matches!(self.security(), TransportSecurity::Tls)
    }
}

/// Add the `tcp-connection-context` interface to `linker`, resolving the per-invocation
/// [`ConnContextHost`] view via `host`.
struct LinkData;
impl wasmtime::component::HasData for LinkData {
    type Data<'a> = ConnContextHost;
}

pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: fn(&mut T) -> ConnContextHost,
) -> wasmtime::Result<()> {
    tcp_connection_context::add_to_linker::<T, LinkData>(linker, host)
}

#[cfg(test)]
mod tests {
    use super::tcp_connection_context::Host;
    use super::*;

    #[test]
    fn no_handle_fails_closed_to_plaintext() {
        let mut host = ConnContextHost::new(None);
        assert!(matches!(host.security(), TransportSecurity::Plaintext));
        assert!(!host.tls_active());
    }

    #[test]
    fn implicit_tls_reads_tls() {
        let mut host = ConnContextHost::new(Some(ConnectionSecurity::tls()));
        assert!(matches!(host.security(), TransportSecurity::Tls));
        assert!(host.tls_active());
    }

    #[test]
    fn plaintext_listener_reads_plaintext() {
        let mut host = ConnContextHost::new(Some(ConnectionSecurity::plaintext()));
        assert!(matches!(host.security(), TransportSecurity::Plaintext));
        assert!(!host.tls_active());
    }

    #[test]
    fn starttls_pending_flips_to_tls_on_upgrade() {
        let sec = ConnectionSecurity::starttls_pending();
        let mut host = ConnContextHost::new(Some(sec.clone()));
        // Before the upgrade: pending, NOT TLS-active (a guest must refuse AUTH here).
        assert!(matches!(
            host.security(),
            TransportSecurity::StarttlsPending
        ));
        assert!(!host.tls_active());
        // The pump completes the in-band upgrade.
        sec.mark_tls_active();
        // After: the SAME handle (shared via the Arc) now reads TLS.
        assert!(matches!(host.security(), TransportSecurity::Tls));
        assert!(host.tls_active());
    }
}
