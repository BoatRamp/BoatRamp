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

use boatramp_core::secret_store::TenantDnsCredStore;
use boatramp_handlers::{
    DnsProvider, DnsPublishAuditSink, RuntimeDnsProviderFactory, RuntimeDnsProviderKind,
    RuntimeDnsRegistry, TracingDnsPublishSink,
};

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

/// The concrete [`RuntimeDnsProviderFactory`] (cap-req #31): builds a live `boatramp-acme` adapter from
/// an UNSEALED, already-VALIDATED credential field bundle (the host binding validated required/shape
/// before sealing). Covers the FULL serve-static adapter set. The zone is the `zone_root` except where
/// the provider addresses it by an opaque id field (`zone_id` / `hosted_zone_id`). Field values reach
/// the adapter but never cross back to the guest or into a log.
struct AcmeRuntimeDnsProviderFactory;

/// Read a required field from the validated bundle (present by construction; `Err` is defense-in-depth).
fn field<'a>(
    fields: &'a std::collections::BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, String> {
    fields
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("missing field {name}"))
}

impl RuntimeDnsProviderFactory for AcmeRuntimeDnsProviderFactory {
    fn build(
        &self,
        kind: RuntimeDnsProviderKind,
        fields: &std::collections::BTreeMap<String, String>,
        zone_root: &str,
    ) -> Result<Arc<dyn DnsProvider>, String> {
        use boatramp_acme as acme;
        let zone = zone_root.to_string();
        Ok(match kind {
            RuntimeDnsProviderKind::Cloudflare => Arc::new(acme::cloudflare::CloudflareDns::new(
                field(fields, "zone_id")?.to_string(),
                field(fields, "token")?.to_string(),
            )),
            RuntimeDnsProviderKind::Route53 => {
                Arc::new(acme::route53::Route53Dns::from_static_creds(
                    field(fields, "access_key_id")?,
                    field(fields, "secret_access_key")?,
                    field(fields, "region")?,
                    fields.get("session_token").map(String::as_str),
                    field(fields, "hosted_zone_id")?.to_string(),
                ))
            }
            RuntimeDnsProviderKind::Oci => Arc::new(
                acme::oci::OciDns::new(
                    field(fields, "region")?,
                    zone,
                    field(fields, "key_id")?.to_string(),
                    field(fields, "private_key_pem")?,
                )
                .map_err(|e| e.to_string())?,
            ),
            RuntimeDnsProviderKind::Akamai => Arc::new(acme::akamai::AkamaiDns::new(
                field(fields, "host")?.to_string(),
                field(fields, "client_token")?.to_string(),
                field(fields, "client_secret")?.to_string(),
                field(fields, "access_token")?.to_string(),
                zone,
            )),
            RuntimeDnsProviderKind::Dnsimple => Arc::new(acme::dnsimple::DnsimpleDns::new(
                field(fields, "account_id")?.to_string(),
                zone,
                field(fields, "token")?.to_string(),
            )),
            RuntimeDnsProviderKind::Gcp => Arc::new(acme::gcp_dns::GcpDns::new(
                field(fields, "project")?.to_string(),
                zone,
                field(fields, "access_token")?.to_string(),
            )),
            RuntimeDnsProviderKind::Azure => Arc::new(acme::azure_dns::AzureDns::new(
                field(fields, "subscription_id")?.to_string(),
                field(fields, "resource_group")?.to_string(),
                zone,
                field(fields, "access_token")?.to_string(),
            )),
            RuntimeDnsProviderKind::DigitalOcean => Arc::new(
                acme::digitalocean::DigitalOceanDns::new(zone, field(fields, "token")?.to_string()),
            ),
            RuntimeDnsProviderKind::Hetzner => Arc::new(acme::hetzner::HetznerDns::new(
                zone,
                field(fields, "token")?.to_string(),
            )),
            RuntimeDnsProviderKind::Ns1 => Arc::new(acme::ns1::Ns1Dns::new(
                zone,
                field(fields, "api_key")?.to_string(),
            )),
        })
    }
}

/// The installed RUNTIME per-tenant DNS-credential source (cap-req #31): the host-sealed store + the
/// provider factory. Installed once at boot from the node (`HandlerRuntime::set_dns_cred_store`) when a
/// `[secrets]` envelope is configured. `None` (unset) ⇒ fail-closed: no runtime registry is attached, so
/// every `register`/`unregister` is `access-denied`.
struct DnsPublishRuntimeSource {
    store: TenantDnsCredStore,
    factory: Arc<dyn RuntimeDnsProviderFactory>,
}

static RUNTIME_SOURCE: OnceLock<DnsPublishRuntimeSource> = OnceLock::new();

/// Install the runtime per-tenant DNS-credential source ONCE at boot (cap-req #31), from the node's
/// sealed [`TenantDnsCredStore`] + the acme-backed provider factory. A later call is ignored
/// (`OnceLock`). Not calling it (no `[secrets]` envelope) keeps the runtime path fail-closed.
pub fn install_dns_cred_source(store: TenantDnsCredStore) {
    let _ = RUNTIME_SOURCE.set(DnsPublishRuntimeSource {
        store,
        factory: Arc::new(AcmeRuntimeDnsProviderFactory),
    });
    tracing::info!(
        target: "boatramp::dns::publish",
        "dns-publish: runtime per-tenant credential source INSTALLED (cap-req #31) — the node posture \
         `allow_guest_dynamic_dns_publish` + a per-component `dynamic_dns_zones` allowlist + the \
         resolved tenant still gate every register/route",
    );
}

/// Build the per-invocation [`RuntimeDnsRegistry`] for `(project, resolved_tenant)` when the runtime
/// source is installed, a tenant resolved, and `dynamic_dns_zones` is non-empty. `None` ⇒ no runtime
/// path for this invocation (fail-closed — no envelope, no tenant, or no registerable zones).
fn runtime_registry(
    project: &str,
    resolved_tenant: Option<&str>,
    dynamic_dns_zones: &[String],
) -> Option<RuntimeDnsRegistry> {
    if dynamic_dns_zones.is_empty() {
        return None;
    }
    let tenant = resolved_tenant?;
    let source = RUNTIME_SOURCE.get()?;
    Some(RuntimeDnsRegistry::new(
        source.store.clone(),
        source.factory.clone(),
        project,
        tenant,
        dynamic_dns_zones.to_vec(),
    ))
}

/// Attach the `dns-publish` binding to `bindings` when (and only when) the component is granted the
/// capability AND an operator provider source resolves a writer for this `(project, site)`. The
/// per-grant `writable_zones` (own-name allowlist, empty ⇒ deny-all) is the deploy-record config. Every
/// gate beyond this (posture, allowlist, budget, guardrail, audit) is enforced by the host binding, so
/// this attach is purely "make the writer reachable"; an un-granted or un-sourced component simply has
/// no binding and the host fail-closes to `access-denied`. Returns `bindings` unchanged when not
/// granted / not sourced.
#[allow(clippy::too_many_arguments)]
pub(crate) fn maybe_attach(
    bindings: boatramp_handlers::Bindings,
    granted: bool,
    project: &str,
    site: &str,
    resolved_tenant: Option<&str>,
    writable_zones: &[String],
    dynamic_dns_zones: &[String],
    ns_targets: &[String],
) -> boatramp_handlers::Bindings {
    if !granted {
        return bindings;
    }
    // OPERATOR serve-static path (cap-req #24, UNCHANGED): attach the host-held writer when a provider
    // source resolves one for this `(project, site)`.
    let operator_grant = provider_source().and_then(|source| source.provider_for(project, site));
    // RUNTIME per-tenant path (cap-req #31): attach the sealed-credential registry when the runtime
    // source is installed, a single tenant resolved, and this component names registerable zones.
    let runtime = runtime_registry(project, resolved_tenant, dynamic_dns_zones);
    // Nothing to attach ⇒ the host fail-closes to `access-denied` (unchanged).
    if operator_grant.is_none() && runtime.is_none() {
        return bindings;
    }
    let audit = default_audit_sink();
    let mut bindings = bindings;
    if let Some(grant) = operator_grant {
        bindings = bindings.with_dns_publish(
            grant.provider,
            grant.zone_root,
            writable_zones.to_vec(),
            // The per-grant NS-target allowlist for a sub-zone NS delegation (MEDIUM-3). Deploy-record
            // config, mirrored from the handler/function/consumer config exactly like `writable_zones`.
            ns_targets.to_vec(),
            audit.clone(),
        );
    }
    if let Some(runtime) = runtime {
        bindings = bindings.with_dns_publish_runtime(runtime, audit);
    }
    bindings
}
