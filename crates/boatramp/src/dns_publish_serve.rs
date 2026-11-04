//! Serve-boot wiring for the guest **`dns-publish` (write)** capability (cap-req #24 WS3; the #25
//! serve-wiring fix).
//!
//! v0.51.0 shipped the guest capability + the 3-layer gate + the 11 `boatramp-acme` provider adapters,
//! but NOTHING installed a provider source into the serve binding seam
//! ([`boatramp_server::dns_publish::install_provider_source`]). So `provider_source()` was always
//! `None`, [`maybe_attach`](boatramp_server::dns_publish) attached no binding, and EVERY guest
//! `dns-publish` call fail-closed to `access-denied` — in dev AND production. (`--acme-dns-provider`
//! wires a provider for ACME CERT issuance only, a separate authority; it never reached the guest
//! capability.) This module is the missing install: `boatramp serve`, at boot, builds an operator-
//! configured host-held writer (reusing the SAME adapters + creds-from-env as `--acme-dns-provider`)
//! and installs it as the process-wide provider source — mirroring [`crate::dns_resolve_override`]'s
//! install shape for the READ capability (`dns-resolve`).
//!
//! # Config surface (mirrors `--acme-dns-provider`)
//! - `--dns-publish-provider <manual|cloudflare|route53|oci|…>` / `BOATRAMP_DNS_PUBLISH_PROVIDER` /
//!   `[serve.dns_publish].provider` — which provider adapter writes guest DNS. **UNSET (the default)
//!   ⇒ NO provider is wired ⇒ fail-closed** (`Ok(None)`; unchanged behavior for an operator who does
//!   not opt in). This is the one deliberate difference from `--acme-dns-provider` (which defaults to
//!   `manual` because ACME always needs a provider): `dns-publish` must default to OFF so compiling
//!   the capability in grants nothing by itself.
//! - `--dns-publish-zone-root <apex>` / `BOATRAMP_DNS_PUBLISH_ZONE_ROOT` /
//!   `[serve.dns_publish].zone_root` — the authoritative zone apex the credential writes, passed to
//!   the central `validate_writable` guardrail so an apex `NS` is refused. Required once a provider is
//!   set.
//! - Credentials: from the ENVIRONMENT only (the established "no secrets in config" posture), via the
//!   SAME per-provider env vars `--acme-dns-provider` reads ([`crate::acme_dns::build_provider`]).
//!
//! The per-grant writable-zone allowlist (`dns_publish_zones`) is DEPLOY-record config (least-privilege
//! guest config), threaded at the bindings-build site in `boatramp-server` — NOT here (this module
//! only supplies the host-held WRITER + the authoritative zone it is trusted over).
//!
//! # `manual` ⇒ an offline, credential-free proof
//! `--dns-publish-provider manual` installs [`boatramp_acme::dns::ManualDnsProvider`], which performs
//! NO network calls — it records/echoes the records a granted guest asks to write. Combined with the
//! node posture `allow_guest_dns_publish` (off by default; an operator override turns it on), this
//! lets an OFFLINE proof capture a guest's writes end-to-end with no real DNS provider — the shape the
//! serve-path e2e gate drives.

#![cfg(all(feature = "dns-publish", feature = "acme-dns"))]

use std::sync::Arc;

use boatramp_acme::dns::DnsProvider;
use boatramp_server::dns_publish::{DnsPublishGrant, DnsPublishProviderSource};

use crate::serve::Error;

/// `boatramp serve`'s installed `dns-publish` provider source: a single operator-configured host-held
/// writer + the authoritative zone it writes, resolved for EVERY `(project, site)` on this node
/// (node-global, exactly as `--acme-dns-provider` is node-global for ACME issuance). The per-grant
/// writable-zone allowlist (`dns_publish_zones`) — the real per-guest least-privilege bound — is
/// applied a layer up in the host binding, so one node-global writer here is correct. The adapter
/// credential is host-held and never crosses to the guest.
pub struct ServeDnsPublishSource {
    /// The host-held writer (an operator-configured `boatramp-acme` adapter — Manual, Cloudflare,
    /// Route 53, …), built from environment credentials.
    provider: Arc<dyn DnsProvider>,
    /// The apex of the zone the provider is authoritative over (e.g. `example.com`), passed to the
    /// central `validate_writable` guardrail so an apex `NS` is refused. Not guest-supplied.
    zone_root: String,
}

impl ServeDnsPublishSource {
    /// The operator-chosen provider's stable name (`manual` / `cloudflare` / …), for the boot log.
    fn provider_name(&self) -> &'static str {
        self.provider.name()
    }
}

// Manual `Debug` (the provider trait object is not `Debug`): prints the provider NAME + zone root
// only — never any credential (the provider's adapter credential is host-held and must not leak into
// logs/panics). Lets this source ride in a `Result`/`Option` that needs `Debug` (e.g. test asserts).
impl std::fmt::Debug for ServeDnsPublishSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeDnsPublishSource")
            .field("provider", &self.provider.name())
            .field("zone_root", &self.zone_root)
            .finish()
    }
}

impl DnsPublishProviderSource for ServeDnsPublishSource {
    fn provider_for(&self, _project: &str, _site: &str) -> Option<DnsPublishGrant> {
        // Node-global: the one operator-configured writer serves every project/site. Tenancy is NOT
        // enforced here — it is the per-handler `dns_publish_zones` own-name allowlist (empty ⇒
        // deny-all) + the posture gate, both enforced in the host binding, that bound each guest.
        Some(DnsPublishGrant {
            provider: Arc::clone(&self.provider),
            zone_root: self.zone_root.clone(),
        })
    }
}

/// Resolve the operator's `dns-publish` provider config (the caller already applied flag/env >
/// `[serve.dns_publish]` precedence), build the host-held writer via the SAME adapter + creds-from-env
/// path as `--acme-dns-provider` ([`crate::acme_dns::build_provider`]), and return the provider source.
///
/// `Ok(None)` ⇒ no provider configured (`provider` is `None`) — the fail-closed default, nothing is
/// wired. `Err(DnsPublishNoZoneRoot)` ⇒ a provider was named without the required zone root.
pub async fn build_dns_publish_source(
    provider: Option<&str>,
    zone_root: Option<&str>,
) -> Result<Option<Arc<ServeDnsPublishSource>>, Error> {
    let Some(provider) = provider else {
        // UNSET ⇒ fail-closed default: no writer wired ⇒ every guest dns-publish is `access-denied`.
        return Ok(None);
    };
    let kind = crate::serve::parse_dns_provider(provider)?;
    let zone_root = zone_root.ok_or(Error::DnsPublishNoZoneRoot)?.to_string();
    let writer: Arc<dyn DnsProvider> = crate::acme_dns::build_provider(kind).await?.into();
    Ok(Some(Arc::new(ServeDnsPublishSource {
        provider: writer,
        zone_root,
    })))
}

/// A `dns-publish` provider source backed by the multi-zone `[serve.dns_providers]` registry (cap-req
/// #27). The registry IS a [`DnsProvider`] that routes each write by the record's owner name to the
/// longest-suffix zone, so one node-global grant serves every project/site: the per-record routing —
/// including the apex-NS guardrail's per-zone apex (via [`DnsProvider::resolve_zone_root`]) — happens
/// inside the provider, not here. The grant's `zone_root` is therefore left empty (the registry never
/// consults it; it resolves the apex per record). The per-grant `dns_publish_zones` own-name allowlist +
/// the posture gate still bound every guest write, a layer up.
pub struct RegistryDnsPublishSource {
    provider: Arc<dyn DnsProvider>,
}

impl std::fmt::Debug for RegistryDnsPublishSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryDnsPublishSource")
            .field("provider", &self.provider.name())
            .finish()
    }
}

impl DnsPublishProviderSource for RegistryDnsPublishSource {
    fn provider_for(&self, _project: &str, _site: &str) -> Option<DnsPublishGrant> {
        Some(DnsPublishGrant {
            provider: Arc::clone(&self.provider),
            // Unused for a routing provider: it resolves the authoritative apex per record via
            // `resolve_zone_root`, so the single `zone_root` fallback is never consulted. Empty is safe
            // (it can never equal a real owner name, so it never triggers a false apex-NS refusal).
            zone_root: String::new(),
        })
    }
}

/// Install the registry-backed `dns-publish` provider source (cap-req #27, the `list` opt-in). Called
/// from the post-KV serve pass once the `[serve.dns_providers]` registry is resolved. Emits the SAME
/// stable `DNS-PUBLISH SERVE-INSTALL CALLED` boot marker as the single-env install (it means "a guest
/// dns-publish provider source was installed").
pub fn install_dns_publish_registry_source(
    registry: Arc<boatramp_acme::routing::RoutingDnsProvider>,
) {
    let zones = registry.zones();
    let source = Arc::new(RegistryDnsPublishSource {
        provider: registry as Arc<dyn DnsProvider>,
    });
    boatramp_server::dns_publish::install_provider_source(Some(
        source as Arc<dyn DnsPublishProviderSource>,
    ));
    tracing::info!(
        target: "boatramp::dns::publish",
        zones = ?zones,
        "dns-publish: guest DNS-write provider source INSTALLED from the [serve.dns_providers] \
         multi-zone registry (operator opt-in, --dns-publish-provider list) — DNS-PUBLISH \
         SERVE-INSTALL CALLED; the node posture `allow_guest_dns_publish` + a per-handler \
         `dns_publish_zones` allowlist still gate every guest write",
    );
}

/// Install the operator-configured `dns-publish` provider source ONCE at serve boot — the one-call fix
/// for cap-req #25 (the dead seam v0.51.0 shipped). A no-op (fail-closed, nothing installed) when no
/// provider is configured. Mirrors [`crate::dns_resolve_override`]'s `install_override`. Call once,
/// before any guest invocation (both serve paths reach it before the mode fork).
pub async fn install_dns_publish_source(
    provider: Option<&str>,
    zone_root: Option<&str>,
) -> Result<(), Error> {
    match build_dns_publish_source(provider, zone_root).await? {
        Some(source) => {
            // Capture the log fields before the source is moved into the install seam.
            let provider_name = source.provider_name();
            let zone_root = source.zone_root.clone();
            boatramp_server::dns_publish::install_provider_source(Some(
                source as Arc<dyn DnsPublishProviderSource>,
            ));
            // The `DNS-PUBLISH SERVE-INSTALL CALLED` token is a STABLE boot marker: it is emitted ONLY
            // from this install path, so a subprocess boot-smoke
            // (`crates/boatramp/tests/dns_publish_serve_install_boot.rs`) can grep serve's early boot
            // log to prove `boatramp serve` actually CALLS `install_dns_publish_source` at run() — the
            // one-line call-site whose ABSENCE is exactly how #24 shipped inert. Deleting that call
            // line (or regressing it to not install) drops this marker and fails the gate. Keep the
            // token verbatim if you reword the message.
            tracing::info!(
                target: "boatramp::dns::publish",
                provider = provider_name,
                zone_root = %zone_root,
                "dns-publish: guest DNS-write provider source INSTALLED (operator opt-in) — \
                 DNS-PUBLISH SERVE-INSTALL CALLED; the node posture `allow_guest_dns_publish` + a \
                 per-handler `dns_publish_zones` allowlist still gate every guest write",
            );
        }
        None => {
            // Fail-closed default: no provider configured ⇒ nothing installed ⇒ every guest
            // dns-publish call is `access-denied`. Explicitly left uninstalled (unchanged behavior).
            tracing::debug!(
                target: "boatramp::dns::publish",
                "dns-publish: no provider configured (--dns-publish-provider / \
                 [serve.dns_publish].provider unset) — guest DNS-write stays fail-closed \
                 (access-denied)",
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // NB: `install_dns_publish_source` is NOT unit-tested here because it writes a PROCESS-WIDE
    // `OnceLock` in `boatramp-server` (install-once); the end-to-end install→dispatch→capture property
    // is proven by the serve-path gate `boatramp-server/tests/dns_publish_serve_wiring_live.rs`. These
    // tests cover the pure builder: config resolution, the fail-closed default, and provider_for.

    /// UNSET provider ⇒ `Ok(None)` ⇒ fail-closed default: serve wires NOTHING, so every guest
    /// dns-publish call stays `access-denied` (the unchanged default for an operator who does not opt
    /// in). The headline invariant — compiling the capability in must grant no one by itself.
    #[tokio::test]
    async fn unset_provider_is_fail_closed_none() {
        let built = build_dns_publish_source(None, None).await.unwrap();
        assert!(
            built.is_none(),
            "an unconfigured dns-publish provider must wire NOTHING (fail-closed default)"
        );
        // A zone root with no provider is still None (no provider to wire).
        let built = build_dns_publish_source(None, Some("example.com"))
            .await
            .unwrap();
        assert!(built.is_none());
    }

    /// `manual` builds a credential-free source whose `provider_for` resolves the operator's writer +
    /// zone root for EVERY `(project, site)` (node-global). The provider is the Manual adapter.
    #[tokio::test]
    async fn manual_provider_builds_node_global_source() {
        let source = build_dns_publish_source(Some("manual"), Some("app.example.com"))
            .await
            .unwrap()
            .expect("manual provider is credential-free and builds a source");
        assert_eq!(source.provider_name(), "manual");

        // Node-global: every project/site resolves the same writer + authoritative zone.
        for (project, site) in [("alpha", "www"), ("beta", "api"), ("default", "")] {
            let grant = source
                .provider_for(project, site)
                .expect("the node-global source resolves a writer for every (project, site)");
            assert_eq!(grant.zone_root, "app.example.com");
            assert_eq!(grant.provider.name(), "manual");
        }
    }

    /// A provider named WITHOUT a zone root is a hard error (the apex-NS guardrail needs the apex).
    #[tokio::test]
    async fn provider_without_zone_root_is_an_error() {
        let err = build_dns_publish_source(Some("manual"), None)
            .await
            .expect_err("a provider without a zone root must be rejected");
        assert!(matches!(err, Error::DnsPublishNoZoneRoot), "got {err:?}");
    }

    /// An unrecognised provider name is rejected with the SAME grammar as `--acme-dns-provider`.
    #[tokio::test]
    async fn unknown_provider_is_rejected() {
        let err = build_dns_publish_source(Some("not-a-provider"), Some("example.com"))
            .await
            .expect_err("an unknown provider name must be rejected");
        assert!(matches!(err, Error::UnknownDnsProvider(_)), "got {err:?}");
    }
}
