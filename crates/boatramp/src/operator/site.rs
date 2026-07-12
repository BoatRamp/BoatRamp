//! K5 — the **`Site` reconciler** (GitOps): a declarative `Site` custom resource
//! is reconciled into a boatramp site via the control-plane API. Apply → ensure
//! the site config (its domains) exists on the target cluster; a **finalizer**
//! deletes the site on teardown, so `kubectl delete site …` cleans up the routing.
//!
//! The target cluster is `spec.cluster`, or the sole `BoatRampCluster` in the
//! namespace. Reaching it reuses the membership executor's **pinned pod-0 channel**
//! (`spec.adminTokenSecret` + `spec.rootPubkey` — an RPK-TLS client authenticated to
//! the root); without them the reconciler reports "no admin token".

use std::sync::Arc;
use std::time::Duration;

use boatramp_core::config::SiteConfig;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{finalizer, Event};
use kube::{Client, ResourceExt};
use serde_json::json;

use super::crd::{BoatRampCluster, Site, SiteStatus};
use super::{executor, Error, Result};

/// The finalizer that guarantees a `Site` deletes its cluster-side state before
/// the object is removed.
const FINALIZER: &str = "boatramp.dev/site-cleanup";

/// Shared reconcile context.
pub struct Ctx {
    pub client: Client,
}

/// Build the boatramp `SiteConfig` a `Site` CR declares: split its flat domain
/// list into a primary + exact aliases + `*.` wildcards. Pure — unit-tested.
pub fn site_config_from_domains(domains: &[String]) -> SiteConfig {
    let mut cfg = SiteConfig::default();
    let (wildcards, exact): (Vec<String>, Vec<String>) = domains
        .iter()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .partition(|d| d.starts_with("*."));
    cfg.domains.wildcards = wildcards;
    let mut exact = exact.into_iter();
    cfg.domains.primary = exact.next();
    cfg.domains.aliases = exact.collect();
    cfg
}

/// Reconcile one `Site` — dispatched through a finalizer so teardown is
/// guaranteed. Requeues periodically to keep the cluster-side config converged.
pub async fn reconcile(site: Arc<Site>, ctx: Arc<Ctx>) -> Result<Action> {
    let ns = site.namespace().unwrap_or_else(|| "default".to_string());
    let api: Api<Site> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, site, |event| async {
        match event {
            Event::Apply(s) => apply(&ctx.client, &ns, &s).await,
            Event::Cleanup(s) => cleanup(&ctx.client, &ns, &s).await,
        }
    })
    .await
    .map_err(|e| Error::Other(format!("site finalizer: {e}")))
}

/// Resolve the target cluster: `spec.cluster`, or — if unset — the sole
/// `BoatRampCluster` in the namespace (error if ambiguous / none).
async fn resolve_cluster(
    client: &Client,
    ns: &str,
    name: Option<&str>,
) -> Result<BoatRampCluster> {
    let api: Api<BoatRampCluster> = Api::namespaced(client.clone(), ns);
    if let Some(name) = name {
        return Ok(api.get(name).await?);
    }
    let mut list = api.list(&ListParams::default()).await?.items;
    match list.len() {
        1 => Ok(list.remove(0)),
        0 => Err(Error::Other(format!(
            "no BoatRampCluster in namespace {ns} — set the Site's spec.cluster"
        ))),
        n => Err(Error::Other(format!(
            "{n} BoatRampClusters in {ns} — set the Site's spec.cluster"
        ))),
    }
}

/// Apply: PUT the site config (its domains) to the cluster's control plane over
/// the pinned pod-0 channel.
async fn apply(client: &Client, ns: &str, site: &Site) -> Result<Action> {
    let brc = resolve_cluster(client, ns, site.spec.cluster.as_deref()).await?;
    let name = site.name_any();
    match executor::pinned_admin_pod0(client, ns, &brc).await? {
        Some((http, base, token)) => {
            let cfg = site_config_from_domains(&site.spec.domains);
            http.put(format!("{base}/api/sites/{name}/config"))
                .bearer_auth(&token)
                .json(&cfg)
                .send()
                .await?
                .error_for_status()?;
            set_phase(client, ns, &name, "Ready").await?;
        }
        None => set_phase(client, ns, &name, "Pending: cluster has no adminTokenSecret").await?,
    }
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Cleanup (finalizer): DELETE the site from the cluster so its routing frees up.
/// A missing cluster/token is not fatal — the object still deletes.
async fn cleanup(client: &Client, ns: &str, site: &Site) -> Result<Action> {
    let name = site.name_any();
    if let Ok(brc) = resolve_cluster(client, ns, site.spec.cluster.as_deref()).await {
        if let Ok(Some((http, base, token))) = executor::pinned_admin_pod0(client, ns, &brc).await {
            let _ = http
                .delete(format!("{base}/api/sites/{name}"))
                .bearer_auth(&token)
                .send()
                .await
                .and_then(|r| r.error_for_status());
        }
    }
    Ok(Action::await_change())
}

/// Patch the `Site` status phase (best-effort).
async fn set_phase(client: &Client, ns: &str, name: &str, phase: &str) -> Result<()> {
    let api: Api<Site> = Api::namespaced(client.clone(), ns);
    let status = json!({ "status": SiteStatus { phase: Some(phase.to_string()) } });
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(&status))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_split_into_primary_aliases_and_wildcards() {
        let cfg = site_config_from_domains(&[
            "example.com".into(),
            "www.example.com".into(),
            "*.preview.example.com".into(),
        ]);
        assert_eq!(cfg.domains.primary.as_deref(), Some("example.com"));
        assert_eq!(cfg.domains.aliases, vec!["www.example.com".to_string()]);
        assert_eq!(cfg.domains.wildcards, vec!["*.preview.example.com".to_string()]);
        // Schema version comes from the default (pinned at v1).
        assert_eq!(cfg.version, boatramp_core::SCHEMA_VERSION);
    }

    #[test]
    fn empty_domains_yield_an_empty_config() {
        let cfg = site_config_from_domains(&[]);
        assert!(cfg.domains.primary.is_none());
        assert!(cfg.domains.aliases.is_empty());
        assert!(cfg.domains.wildcards.is_empty());
    }
}
