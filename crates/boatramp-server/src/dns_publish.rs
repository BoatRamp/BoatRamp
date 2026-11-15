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

/// Max distinct OAuth-adapter instances the factory caches (gcp/azure). A crude bound: when full the
/// cache is cleared (a cleared entry just re-exchanges — never a correctness issue).
const MAX_OAUTH_ADAPTER_CACHE: usize = 512;

/// The concrete [`RuntimeDnsProviderFactory`] (cap-req #31): builds a live `boatramp-acme` adapter from
/// an UNSEALED, already-VALIDATED credential field bundle (the host binding validated required/shape
/// before sealing). Covers the FULL serve-static adapter set. The zone is the `zone_root` except where
/// the provider addresses it by an opaque id field (`zone_id` / `hosted_zone_id`) or, for GCP, a
/// `managed_zone` resource name. Field values reach the adapter but never cross back to the guest or
/// into a log.
///
/// For GCP/Azure — which exchange a LONG-LIVED credential for a cached SHORT-LIVED token — the factory
/// caches the built ADAPTER INSTANCE (so its internal token cache persists across calls), keyed by a
/// SHA-256 of `(cache_scope, zone_root, kind, credential bundle)`. `cache_scope` embeds `(project,
/// tenant)`, so a cached adapter — and therefore its minted token — is NEVER shared across tenants; the
/// cred is in the key, so a rotation yields a fresh adapter.
struct AcmeRuntimeDnsProviderFactory {
    oauth_adapters: std::sync::Mutex<std::collections::HashMap<[u8; 32], Arc<dyn DnsProvider>>>,
}

impl AcmeRuntimeDnsProviderFactory {
    fn new() -> Self {
        Self {
            oauth_adapters: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

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

/// The per-tenancy adapter-cache key: a SHA-256 over the tenancy scope + zone-root + kind + the whole
/// credential bundle. The tenancy scope guarantees no cross-tenant reuse; the bundle guarantees a
/// rotated credential gets a fresh adapter.
fn oauth_cache_key(
    cache_scope: &str,
    zone_root: &str,
    kind: RuntimeDnsProviderKind,
    fields: &std::collections::BTreeMap<String, String>,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for part in [
        cache_scope.as_bytes(),
        zone_root.as_bytes(),
        kind.as_str().as_bytes(),
    ] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    for (k, v) in fields {
        h.update((k.len() as u64).to_le_bytes());
        h.update(k.as_bytes());
        h.update((v.len() as u64).to_le_bytes());
        h.update(v.as_bytes());
    }
    h.finalize().into()
}

/// Build a STATELESS adapter (every provider except gcp/azure) — a fresh instance per call is cheap and
/// holds no minted-token state.
fn build_stateless(
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
        RuntimeDnsProviderKind::Route53 => Arc::new(acme::route53::Route53Dns::from_static_creds(
            field(fields, "access_key_id")?,
            field(fields, "secret_access_key")?,
            field(fields, "region")?,
            fields.get("session_token").map(String::as_str),
            field(fields, "hosted_zone_id")?.to_string(),
        )),
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
        RuntimeDnsProviderKind::DigitalOcean => Arc::new(acme::digitalocean::DigitalOceanDns::new(
            zone,
            field(fields, "token")?.to_string(),
        )),
        RuntimeDnsProviderKind::Hetzner => Arc::new(acme::hetzner::HetznerDns::new(
            zone,
            field(fields, "token")?.to_string(),
        )),
        RuntimeDnsProviderKind::Ns1 => Arc::new(acme::ns1::Ns1Dns::new(
            zone,
            field(fields, "api_key")?.to_string(),
        )),
        // gcp/azure are built by `build_oauth` (cached), never here.
        RuntimeDnsProviderKind::Gcp | RuntimeDnsProviderKind::Azure => {
            return Err("oauth provider built on the wrong path".into());
        }
    })
}

/// Build a GCP/Azure adapter from the LONG-LIVED credential bundle (it exchanges host-side for a cached
/// short-lived token). GCP: a service-account JSON + the `managed_zone` resource name. Azure: a service
/// principal + subscription/resource-group scoping the DNS zone (= `zone_root`).
fn build_oauth(
    kind: RuntimeDnsProviderKind,
    fields: &std::collections::BTreeMap<String, String>,
    zone_root: &str,
) -> Result<Arc<dyn DnsProvider>, String> {
    use boatramp_acme as acme;
    Ok(match kind {
        RuntimeDnsProviderKind::Gcp => Arc::new(
            acme::gcp_dns::GcpDns::from_service_account(
                field(fields, "managed_zone")?.to_string(),
                field(fields, "service_account_json")?,
            )
            .map_err(|e| e.to_string())?,
        ),
        RuntimeDnsProviderKind::Azure => {
            Arc::new(acme::azure_dns::AzureDns::from_service_principal(
                field(fields, "tenant_id")?,
                field(fields, "client_id")?.to_string(),
                field(fields, "client_secret")?.to_string(),
                field(fields, "subscription_id")?.to_string(),
                field(fields, "resource_group")?.to_string(),
                zone_root.to_string(),
            ))
        }
        _ => return Err("not an oauth provider".into()),
    })
}

impl RuntimeDnsProviderFactory for AcmeRuntimeDnsProviderFactory {
    fn build(
        &self,
        kind: RuntimeDnsProviderKind,
        fields: &std::collections::BTreeMap<String, String>,
        zone_root: &str,
        cache_scope: &str,
    ) -> Result<Arc<dyn DnsProvider>, String> {
        if !matches!(
            kind,
            RuntimeDnsProviderKind::Gcp | RuntimeDnsProviderKind::Azure
        ) {
            return build_stateless(kind, fields, zone_root);
        }
        // gcp/azure: reuse the cached adapter instance for this exact (tenancy, zone, cred) so its
        // minted token is reused — but keyed on the tenancy scope, so NEVER shared across tenants.
        let key = oauth_cache_key(cache_scope, zone_root, kind, fields);
        let mut cache = self
            .oauth_adapters
            .lock()
            .map_err(|_| "dns adapter cache poisoned".to_string())?;
        if let Some(existing) = cache.get(&key) {
            return Ok(existing.clone());
        }
        // Build while holding the lock (construction is synchronous — JSON parse + signer, no I/O).
        let adapter = build_oauth(kind, fields, zone_root)?;
        if cache.len() >= MAX_OAUTH_ADAPTER_CACHE {
            cache.clear();
        }
        cache.insert(key, adapter.clone());
        Ok(adapter)
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
        factory: Arc::new(AcmeRuntimeDnsProviderFactory::new()),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway RSA key (PKCS#8) + a valid service-account JSON, for the factory cache test.
    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA5SrFVYD26w2NArwi\n\
6uNqb0rEKalyCAaSLeURe7sWG6FSMY1SoZ0klwDoVzTw83Sg6UWOlP7ZULzP43F1\n\
dfBy5QIDAQABAkEA4t+KBxEq4h9DN67r3qCP8WgSdbBjzOA8faUmvtjDlUsrcPrr\n\
97v9jcBeflXcw/uG8pQ1p+tWJDOKA+UN3oECzQIhAPe0thijPyMLOQEX2K3LFLtK\n\
Z0oHkKqFyXt7kZmDUlMvAiEA7Ncl7GYtqI5ZjalxU/SB5a7sL+6KqJcK1lXgvnKU\n\
pisCIAF7SzuKfm4vOwAOrHUdqdoU79k5glwCwNnEO3K3nl5xAiBSLNgwrMc8y59Q\n\
4rC6k4Saf9XdT6P2mOmeso9XJQRknwIgG689c5E5fvq9T4eam9dBCNJup4IgI6VT\n\
sAmaXlKwnv8=\n\
-----END PRIVATE KEY-----\n";

    fn gcp_fields() -> std::collections::BTreeMap<String, String> {
        let sa = serde_json::json!({
            "client_email": "dns@proj.iam.gserviceaccount.com",
            "private_key": TEST_KEY_PEM,
            "project_id": "proj",
        })
        .to_string();
        std::collections::BTreeMap::from([
            ("service_account_json".to_string(), sa),
            ("managed_zone".to_string(), "mz-1".to_string()),
        ])
    }

    /// Security review: the OAuth adapter cache (whose instances hold the minted token) is keyed on the
    /// tenancy scope, so it is reused WITHIN a tenant but NEVER shared across tenants.
    #[test]
    fn oauth_adapter_cache_is_per_tenancy_and_never_crosses_tenants() {
        let factory = AcmeRuntimeDnsProviderFactory::new();
        let fields = gcp_fields();
        let a1 = factory
            .build(
                RuntimeDnsProviderKind::Gcp,
                &fields,
                "acme.com",
                "proj\u{1f}tenant-a",
            )
            .unwrap();
        let a2 = factory
            .build(
                RuntimeDnsProviderKind::Gcp,
                &fields,
                "acme.com",
                "proj\u{1f}tenant-a",
            )
            .unwrap();
        // Same tenancy + zone + cred ⇒ the SAME cached adapter (its minted token is reused).
        assert!(
            Arc::ptr_eq(&a1, &a2),
            "same tenancy reuses the cached adapter"
        );
        // A DIFFERENT tenant ⇒ a DIFFERENT adapter instance (no shared minted token across tenants).
        let b = factory
            .build(
                RuntimeDnsProviderKind::Gcp,
                &fields,
                "acme.com",
                "proj\u{1f}tenant-b",
            )
            .unwrap();
        assert!(
            !Arc::ptr_eq(&a1, &b),
            "a different tenant must get a different adapter (token cache isolation)"
        );
    }

    /// A malformed GCP service-account JSON reaching the factory (defense-in-depth beyond the host
    /// binding's register-time validation) is a build error, not a panic.
    #[test]
    fn gcp_factory_rejects_malformed_service_account() {
        let factory = AcmeRuntimeDnsProviderFactory::new();
        let fields = std::collections::BTreeMap::from([
            ("service_account_json".to_string(), "{bad".to_string()),
            ("managed_zone".to_string(), "mz".to_string()),
        ]);
        assert!(
            factory
                .build(RuntimeDnsProviderKind::Gcp, &fields, "acme.com", "p\u{1f}t")
                .is_err()
        );
    }
}
