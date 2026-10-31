//! The server-side wiring seam for the guest `dns-publish` (write) capability (cap-req #24 WS3).
//!
//! The HOST gate (posture + per-grant writable-zone allowlist + budget + audit + the central
//! `validate_writable` guardrail) lives in [`boatramp_handlers::DnsPublishHost`]. This module supplies
//! the two things the host binding needs that are owned a layer up:
//!
//! 1. **The provider source** — which host-held [`DnsProvider`] credential writes a given project's
//!    DNS, and the zone it is authoritative over. The concrete provider factory + the operator DNS
//!    config live in the top-level `boatramp` crate (which owns `boatramp-acme`'s adapters and the
//!    sealed credentials), so it is INSTALLED into this `OnceLock` seam at boot via
//!    [`install_provider_source`] — mirroring [`crate::dns_resolve_override`]. **Absent (the default)
//!    ⇒ the binding is never attached, so every guest `dns-publish` call is `access-denied`
//!    (fail-closed).** A guest can never reach a provider the operator did not wire.
//! 2. **The audit sink** — the redacted mutation log. The default is the tracing sink; a future
//!    refinement can route it to a durable audit store.
//!
//! The per-grant writable-zone allowlist (`dns_publish_zones`) is deploy-record config, threaded from
//! the handler/function/consumer config at the bindings-build site — NOT here (it is least-privilege
//! guest config, not an operator credential).

#![cfg(feature = "dns-publish")]

use std::sync::{Arc, OnceLock};

use boatramp_handlers::{DnsProvider, DnsPublishAuditSink, TracingDnsPublishSink};

/// The host-held DNS writer for a granted `dns-publish` guest, plus the zone it is authoritative over
/// (passed to the central guardrail so an apex `NS` is refused). The provider's adapter credential is
/// host-held and never crosses to the guest.
pub struct DnsPublishGrant {
    /// The host-held writer (an operator-configured `boatramp-acme` adapter — Cloudflare, Route 53, …).
    pub provider: Arc<dyn DnsProvider>,
    /// The apex of the zone the provider is authoritative over (e.g. `example.com`).
    pub zone_root: String,
}

/// Resolves the host-held DNS writer for a `(project, site)`. Installed by the top-level `boatramp`
/// crate, which owns the DNS-provider config + sealed credentials. `None` ⇒ no provider is configured
/// for that scope ⇒ the `dns-publish` binding is not attached ⇒ every guest call is `access-denied`
/// (fail-closed). The returned rows are host-trusted operator config, never guest-influenced.
pub trait DnsPublishProviderSource: Send + Sync {
    /// The writer + authoritative zone for `(project, site)`, or `None` if none is configured.
    fn provider_for(&self, project: &str, site: &str) -> Option<DnsPublishGrant>;
}

/// The installed provider source. `None` (unset, or explicitly installed as `None`) ⇒ fail-closed.
static SOURCE: OnceLock<Option<Arc<dyn DnsPublishProviderSource>>> = OnceLock::new();

/// Install the `dns-publish` provider source ONCE at boot (before any guest invocation). A later call
/// is ignored (`OnceLock`). Operator/serve config only — never guest-settable. Installing `None` keeps
/// the capability fail-closed (no provider ⇒ no binding).
pub fn install_provider_source(source: Option<Arc<dyn DnsPublishProviderSource>>) {
    let _ = SOURCE.set(source);
}

/// The installed provider source, if any. `None` ⇒ fail-closed (binding not attached).
pub(crate) fn provider_source() -> Option<&'static Arc<dyn DnsPublishProviderSource>> {
    SOURCE.get().and_then(Option::as_ref)
}

/// The default redacted audit sink for guest DNS mutations (a `tracing` event per mutation; name +
/// type + provider + outcome, never the rdata value or any credential).
pub(crate) fn default_audit_sink() -> Arc<dyn DnsPublishAuditSink> {
    Arc::new(TracingDnsPublishSink)
}

/// Attach the `dns-publish` binding to `bindings` when (and only when) the component is granted the
/// capability AND an operator provider source resolves a writer for this `(project, site)`. The
/// per-grant `writable_zones` (own-name allowlist, empty ⇒ deny-all) is the deploy-record config. Every
/// gate beyond this (posture, allowlist, budget, guardrail, audit) is enforced by the host binding, so
/// this attach is purely "make the writer reachable"; an un-granted or un-sourced component simply has
/// no binding and the host fail-closes to `access-denied`. Returns `bindings` unchanged when not
/// granted / not sourced.
pub(crate) fn maybe_attach(
    bindings: boatramp_handlers::Bindings,
    granted: bool,
    project: &str,
    site: &str,
    writable_zones: &[String],
    ns_targets: &[String],
) -> boatramp_handlers::Bindings {
    if !granted {
        return bindings;
    }
    let Some(source) = provider_source() else {
        return bindings;
    };
    let Some(grant) = source.provider_for(project, site) else {
        return bindings;
    };
    bindings.with_dns_publish(
        grant.provider,
        grant.zone_root,
        writable_zones.to_vec(),
        // The per-grant NS-target allowlist for a sub-zone NS delegation (MEDIUM-3). Deploy-record
        // config, mirrored from the handler/function/consumer config exactly like `writable_zones`.
        ns_targets.to_vec(),
        default_audit_sink(),
    )
}
