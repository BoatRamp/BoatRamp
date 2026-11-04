//! Build a [`RoutingDnsProvider`] from the `[serve.dns_providers]` list (cap-req #27).
//!
//! This is the multi-zone generalization of [`crate::acme_dns::build_provider`]: instead of ONE
//! provider seeded from process-global env vars, it resolves N per-zone providers, each field a
//! `type:value` config pointer resolved independently against the control-plane KV + `[secrets]`
//! envelope ([`boatramp_node::dns_provider_ref`]). The resulting [`RoutingDnsProvider`] IS a
//! [`DnsProvider`], so it drops into every seam that threads one `Arc<dyn DnsProvider>` — both the ACME
//! DNS-01 issuer and the guest `dns-publish` writer route by owner name through it.
//!
//! Only compiled under `acme-dns` (it constructs the `boatramp-acme` adapters, which that feature
//! pulls). The config structs + the pointer resolver live in `boatramp-node` and compile in the lean
//! lane regardless; this builder is the adapter-construction seam.

#![cfg(feature = "acme-dns")]

use std::sync::Arc;

use boatramp_acme::dns::DnsProvider;
use boatramp_acme::routing::RoutingDnsProvider;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use boatramp_core::project::ProjectRef;
use boatramp_node::config::{DnsProviderConfig, DnsProviderKind};
use boatramp_node::dns_provider_ref::resolve_config_ref;

use crate::serve::Error;

/// The sealed-ref resolution context, shared across a provider's fields (so the KV/envelope/posture are
/// threaded once). `boatramp:` refs resolve under the reserved default project — the node/operator
/// scope, exactly like the base S3 credential (#505); never guest input.
struct Resolver<'a> {
    kv: &'a Arc<dyn KvStore>,
    envelope: &'a Option<Arc<dyn KeyEnvelope>>,
    allow_env_secret_refs: bool,
    env: boatramp_core::env::SystemEnv,
}

impl Resolver<'_> {
    /// Resolve one field value (already-present pointer string) → resolved plaintext, mapping a
    /// resolution failure into a startup [`Error`].
    async fn resolve(&self, field: &str, value: &str, is_secret: bool) -> Result<String, Error> {
        resolve_config_ref(
            field,
            value,
            is_secret,
            ProjectRef::DEFAULT,
            self.kv,
            self.envelope,
            self.allow_env_secret_refs,
            &self.env,
        )
        .await
        .map(boatramp_node::dns_provider_ref::ResolvedValue::into_string)
        .map_err(|e| Error::DnsProvidersConfig(e.to_string()))
    }

    /// Resolve a REQUIRED field: error if absent, else resolve its pointer.
    async fn required(
        &self,
        label: &str,
        kind: &str,
        field: &str,
        value: Option<&str>,
        is_secret: bool,
    ) -> Result<String, Error> {
        let value = value.ok_or_else(|| {
            Error::DnsProvidersConfig(format!(
                "provider {label:?} (kind {kind}): field `{field}` is required"
            ))
        })?;
        self.resolve(field, value, is_secret).await
    }
}

/// Build the per-zone provider for one `[serve.dns_providers]` entry, resolving every field pointer.
async fn build_adapter(
    cfg: &DnsProviderConfig,
    kind: DnsProviderKind,
    r: &Resolver<'_>,
) -> Result<Arc<dyn DnsProvider>, Error> {
    let label = cfg.name.as_str();
    // The stable kind token, for error messages (matches the flag/config grammar).
    let kname = kind.as_str();
    // Borrow an optional field pointer as `Option<&str>` (a free fn, not a closure, so the returned
    // borrow's lifetime ties to the argument rather than the closure).
    fn s(o: &Option<String>) -> Option<&str> {
        o.as_deref()
    }

    Ok(match kind {
        DnsProviderKind::Manual => Arc::new(boatramp_acme::dns::ManualDnsProvider::new()),
        DnsProviderKind::Cloudflare => {
            let zone_id = r
                .required(label, kname, "zone_id", s(&cfg.zone_id), false)
                .await?;
            let token = r
                .required(label, kname, "token", s(&cfg.token), true)
                .await?;
            Arc::new(
                boatramp_acme::cloudflare::CloudflareDns::new(zone_id, token)
                    .with_proxied(cfg.proxied.unwrap_or(false)),
            )
        }
        DnsProviderKind::Route53 => {
            // Route 53 credentials come from the AWS provider chain (env / profile / IMDS), not a
            // pointer field — only the (non-secret) hosted-zone id is config.
            let hosted_zone_id = r
                .required(
                    label,
                    kname,
                    "hosted_zone_id",
                    s(&cfg.hosted_zone_id),
                    false,
                )
                .await?;
            Arc::new(boatramp_acme::route53::Route53Dns::from_env(hosted_zone_id).await)
        }
        DnsProviderKind::Oci => {
            let region = r
                .required(label, kname, "region", s(&cfg.region), false)
                .await?;
            let zone = r
                .required(label, kname, "zone", s(&cfg.zone), false)
                .await?;
            let key_id = r
                .required(label, kname, "key_id", s(&cfg.key_id), false)
                .await?;
            // The private key stays a FILE (as the env path does): resolve the pointer to a path, read
            // the PEM at startup. The path is non-secret; the file content is the secret, never in config.
            let key_path = r
                .required(
                    label,
                    kname,
                    "private_key_file",
                    s(&cfg.private_key_file),
                    false,
                )
                .await?;
            let pem = std::fs::read_to_string(&key_path).map_err(|e| {
                Error::DnsProvidersConfig(format!(
                    "provider {label:?}: reading private_key_file {key_path:?}: {e}"
                ))
            })?;
            Arc::new(
                boatramp_acme::oci::OciDns::new(&region, zone, key_id, &pem)
                    .map_err(|e| Error::DnsProvidersConfig(format!("provider {label:?}: {e}")))?,
            )
        }
        DnsProviderKind::DigitalOcean => {
            let domain = r
                .required(label, kname, "domain", s(&cfg.domain), false)
                .await?;
            let token = r
                .required(label, kname, "token", s(&cfg.token), true)
                .await?;
            Arc::new(boatramp_acme::digitalocean::DigitalOceanDns::new(
                domain, token,
            ))
        }
        DnsProviderKind::Hetzner => {
            let zone = r
                .required(label, kname, "zone", s(&cfg.zone), false)
                .await?;
            let token = r
                .required(label, kname, "token", s(&cfg.token), true)
                .await?;
            Arc::new(boatramp_acme::hetzner::HetznerDns::new(zone, token))
        }
        DnsProviderKind::Ns1 => {
            let zone = r
                .required(label, kname, "zone", s(&cfg.zone), false)
                .await?;
            let api_key = r
                .required(label, kname, "api_key", s(&cfg.api_key), true)
                .await?;
            Arc::new(boatramp_acme::ns1::Ns1Dns::new(zone, api_key))
        }
        DnsProviderKind::Dnsimple => {
            let account_id = r
                .required(label, kname, "account_id", s(&cfg.account_id), false)
                .await?;
            let zone = r
                .required(label, kname, "zone", s(&cfg.zone), false)
                .await?;
            let token = r
                .required(label, kname, "token", s(&cfg.token), true)
                .await?;
            Arc::new(boatramp_acme::dnsimple::DnsimpleDns::new(
                account_id, zone, token,
            ))
        }
        DnsProviderKind::GcpDns => {
            let project = r
                .required(label, kname, "project", s(&cfg.project), false)
                .await?;
            let zone = r
                .required(label, kname, "zone", s(&cfg.zone), false)
                .await?;
            let access_token = r
                .required(label, kname, "access_token", s(&cfg.access_token), true)
                .await?;
            Arc::new(boatramp_acme::gcp_dns::GcpDns::new(
                project,
                zone,
                access_token,
            ))
        }
        DnsProviderKind::AzureDns => {
            let subscription_id = r
                .required(
                    label,
                    kname,
                    "subscription_id",
                    s(&cfg.subscription_id),
                    false,
                )
                .await?;
            let resource_group = r
                .required(
                    label,
                    kname,
                    "resource_group",
                    s(&cfg.resource_group),
                    false,
                )
                .await?;
            let zone = r
                .required(label, kname, "zone", s(&cfg.zone), false)
                .await?;
            let access_token = r
                .required(label, kname, "access_token", s(&cfg.access_token), true)
                .await?;
            Arc::new(boatramp_acme::azure_dns::AzureDns::new(
                subscription_id,
                resource_group,
                zone,
                access_token,
            ))
        }
        DnsProviderKind::Akamai => {
            let host = r
                .required(label, kname, "host", s(&cfg.host), false)
                .await?;
            let client_token = r
                .required(label, kname, "client_token", s(&cfg.client_token), true)
                .await?;
            let client_secret = r
                .required(label, kname, "client_secret", s(&cfg.client_secret), true)
                .await?;
            let access_token = r
                .required(label, kname, "access_token", s(&cfg.access_token), true)
                .await?;
            let zone = r
                .required(label, kname, "zone", s(&cfg.zone), false)
                .await?;
            Arc::new(boatramp_acme::akamai::AkamaiDns::new(
                host,
                client_token,
                client_secret,
                access_token,
                zone,
            ))
        }
    })
}

/// Build the [`RoutingDnsProvider`] from `providers`, resolving every field pointer against the sealed
/// store / env / literal (cap-req #27). `None` ⇒ the list is empty (the caller uses the single-env path
/// instead). A missing required field, a refused plaintext secret, a `boatramp:` ref with no envelope,
/// an unreadable OCI key file, or a duplicate/illegal `zone_root` is a fail-closed startup [`Error`].
pub async fn build_routing_registry(
    providers: &[DnsProviderConfig],
    kv: Arc<dyn KvStore>,
    envelope: Option<Arc<dyn KeyEnvelope>>,
    allow_env_secret_refs: bool,
) -> Result<Option<Arc<RoutingDnsProvider>>, Error> {
    if providers.is_empty() {
        return Ok(None);
    }
    let resolver = Resolver {
        kv: &kv,
        envelope: &envelope,
        allow_env_secret_refs,
        env: boatramp_core::env::SystemEnv,
    };
    let mut entries: Vec<(String, String, Arc<dyn DnsProvider>)> =
        Vec::with_capacity(providers.len());
    for cfg in providers {
        let kind = cfg.kind.ok_or_else(|| {
            Error::DnsProvidersConfig(format!(
                "provider {:?}: `kind` is required (one of manual | cloudflare | route53 | oci | \
                 digitalocean | hetzner | ns1 | dnsimple | gcp-dns | azure-dns | akamai)",
                cfg.name
            ))
        })?;
        if cfg.zone_root.trim().is_empty() {
            return Err(Error::DnsProvidersConfig(format!(
                "provider {:?}: `zone_root` is required (the authoritative zone apex)",
                cfg.name
            )));
        }
        let provider = build_adapter(cfg, kind, &resolver).await?;
        entries.push((cfg.name.clone(), cfg.zone_root.clone(), provider));
    }
    let registry =
        RoutingDnsProvider::new(entries).map_err(|e| Error::DnsProvidersConfig(e.to_string()))?;
    tracing::info!(
        zones = ?registry.zones(),
        count = registry.len(),
        "dns_providers: multi-zone DNS provider registry built (cap-req #27)",
    );
    Ok(Some(Arc::new(registry)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::kv::MemoryKv;

    fn provider(name: &str, kind: DnsProviderKind, zone_root: &str) -> DnsProviderConfig {
        DnsProviderConfig {
            name: name.to_string(),
            kind: Some(kind),
            zone_root: zone_root.to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn empty_list_is_none() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let got = build_routing_registry(&[], kv, None, false).await.unwrap();
        assert!(
            got.is_none(),
            "empty dns_providers ⇒ None ⇒ single-env path"
        );
    }

    #[tokio::test]
    async fn manual_multi_zone_builds_and_routes() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let providers = vec![
            provider("a", DnsProviderKind::Manual, "mailroom.pro"),
            provider("b", DnsProviderKind::Manual, "cariello.name"),
        ];
        let registry = build_routing_registry(&providers, kv, None, false)
            .await
            .unwrap()
            .expect("two manual zones build a registry");
        assert_eq!(registry.len(), 2);
        assert_eq!(
            registry.resolve_zone_root("mx.mailroom.pro"),
            boatramp_acme::ZoneResolution::Zone("mailroom.pro".to_string())
        );
        assert_eq!(
            registry.resolve_zone_root("www.cariello.name"),
            boatramp_acme::ZoneResolution::Zone("cariello.name".to_string())
        );
    }

    #[tokio::test]
    async fn cloudflare_literal_secret_is_refused() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let mut p = provider("cf", DnsProviderKind::Cloudflare, "example.com");
        p.zone_id = Some("741f56".to_string());
        p.token = Some("plaintext-secret-token".to_string()); // a raw literal in a SECRET field
        let err = build_routing_registry(&[p], kv, None, true)
            .await
            .expect_err("a plaintext secret literal must be refused");
        assert!(matches!(err, Error::DnsProvidersConfig(_)), "got {err:?}");
        let msg = err.to_string();
        assert!(
            msg.contains("token") && msg.contains("secret"),
            "clear error: {msg}"
        );
    }

    #[tokio::test]
    async fn cloudflare_boatramp_ref_with_no_envelope_fails_closed() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let mut p = provider("cf", DnsProviderKind::Cloudflare, "example.com");
        p.zone_id = Some("741f56".to_string());
        p.token = Some("boatramp:CF_TOKEN".to_string());
        let err = build_routing_registry(&[p], kv, None, true)
            .await
            .expect_err("a boatramp: ref with no envelope must fail closed");
        assert!(matches!(err, Error::DnsProvidersConfig(_)));
        assert!(
            err.to_string().contains("envelope"),
            "fail-closed error names the missing envelope"
        );
    }

    #[tokio::test]
    async fn missing_required_field_is_refused() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        // Cloudflare with no zone_id.
        let mut p = provider("cf", DnsProviderKind::Cloudflare, "example.com");
        p.token = Some("env:CF_TOKEN".to_string());
        let err = build_routing_registry(&[p], kv, None, true)
            .await
            .expect_err("missing zone_id refused");
        assert!(
            err.to_string().contains("zone_id"),
            "names the missing field: {err}"
        );
    }

    #[tokio::test]
    async fn missing_kind_is_refused() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let mut p = provider("x", DnsProviderKind::Manual, "example.com");
        p.kind = None;
        let err = build_routing_registry(&[p], kv, None, false)
            .await
            .expect_err("missing kind refused");
        assert!(err.to_string().contains("kind"));
    }
}
