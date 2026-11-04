//! `boatramp project prune` — GC a project's **provably-orphaned** control-plane state.
//!
//! The owner-requested companion to `project rm`/`clone`: where `rm` tears a WHOLE project
//! down and `clone --force` can COMMINGLE a foreign project's state into an existing one, this
//! verb reclaims the orphans a commingle (or a routine config edit) leaves behind — WITHOUT
//! touching anything live. It is the scalpel to `rm`'s guillotine.
//!
//! # The provable-orphan contract (the security gate)
//!
//! This is a DESTRUCTIVE control-plane op, so the entire design is conservative /
//! **fail-closed**: a key is pruned ONLY when the store can PROVE nothing live references it.
//! When orphan-hood cannot be proven, the key is KEPT.
//!
//! - **PRESENT** = the project's own control-plane keys, scoped by
//!   [`project_owned_prefixes`](crate::project_export::project_owned_prefixes) (the C1
//!   cross-tenant-isolation boundary), MINUS
//!   [`sealed_secret_prefixes`](crate::project_export::sealed_secret_prefixes) — which are
//!   NEVER classified, let alone pruned.
//! - **REFERENCED** = everything the project's live serve state legitimately needs: a site with
//!   a resolvable current config or an active deployment pointer, and — within such a live site
//!   — every host its current config actually answers to.
//! - **PRUNABLE** = PRESENT − REFERENCED, i.e. the provable orphans:
//!   1. **Dead-site leftovers** — the per-site routing/config keys (`site/`, `current-principal/`,
//!      `history/`, `sitecontexts/`, `alias/`, `domainverify/`) of a site that has NO resolvable
//!      config body AND NO `current/` deployment pointer. Such a site serves nothing (a dangling
//!      `site/` pointer whose body was GC'd, or a commingled site whose config never landed). A
//!      `current/` pointer makes a site live — it is the liveness anchor and is itself never pruned.
//!      (`dnsmanaged/` is deliberately NOT in this set — see below.)
//!   2. **Foreign, provably-dead domain-verification entries** within a LIVE site — a
//!      `domainverify/<site>/<host>` whose `<host>` is NOT one the site's CURRENT config answers to
//!      AND whose stored challenge is **unverified AND expired** (the motivating case: a `--force`
//!      clone commingle, or a `deploy apply` that rewrote the site's domains, leaving an old host's
//!      stale, never-completed verification challenge behind). A VERIFIED record is a proven
//!      ownership proof (removing it is `domain rm`, not GC) and an UNEXPIRED pending challenge is a
//!      live verify-before-attach in flight; both are KEPT (Security review Finding B).
//!
//! # What this verb deliberately does NOT prune (and why)
//!
//! - **The managed-DNS ledger (`dnsmanaged/<site>/<host>`)** — NEVER classified, let alone pruned
//!   (Security review Finding A). Each ledger entry records an EXTERNAL DNS record boatramp
//!   published at a provider; its lifecycle is owned by the auto-DNS reconcile sweep, which
//!   **retracts the provider record THEN removes the ledger** (see
//!   [`DeployStore::remove_managed_dns`](crate::deploy::DeployStore::remove_managed_dns) /
//!   [`list_managed_dns`](crate::deploy::DeployStore::list_managed_dns)). A raw prune-delete of the
//!   ledger would strand the external record at the provider (a leaked dangling hostname the
//!   reconcile GC can then never reclaim, because it reclaims from the ledger). So prune leaves
//!   every `dnsmanaged/` key alone — the reconcile sweep retracts-then-removes a stale/foreign one
//!   correctly — for BOTH a dead site and a live site's foreign host.
//! - **Sealed secrets / managed-SQL credentials** ([`sealed_secret_prefixes`]) — excluded
//!   STRUCTURALLY, before any key is classified. Losing one is unrecoverable; they are never
//!   "unreferenced" in a way this verb may act on.
//! - **Another project's keys / the global keyspace** — the scan is confined to
//!   `project/<p>/…`; a global routing record (`domain/`, `wildcard/`), a TLS key (`cert/`), the
//!   node `daemonconfig/`, and every other project's `project/<other>/…` are physically out of
//!   scope. This is the same C1 boundary the project export enforces.
//! - **`graphql/<p>/…` subgraph SDLs and `hapq/<p>/…` persisted APQ** — these ARE in PRESENT,
//!   but a registered subgraph is a LIVE member of the composed supergraph and an APQ entry is a
//!   LIVE trusted-operation safelist row; neither is provably orphaned from the control-plane
//!   layer (a function-backed subgraph legitimately has no backend record, and a client may
//!   present an APQ hash at any time). Removing a subgraph is `graphql unpublish`, not GC — so
//!   they are KEPT, fail-closed.
//! - **Global content-addressed bodies** (deploy blobs, manifests, orphaned `siteconfig/<hash>`)
//!   — these are shared, node-wide, dedup-across-projects CAS. Reclaiming them is the node-global
//!   `boatramp prune` (`System·Admin`); folding that into this `Project·Admin`-gated, per-project
//!   verb would both downgrade a node-wide destructive op below its gate and reach outside the
//!   project's keyspace. The companion `boatramp prune` is the right tool and the CLI points to it.
//! - **Project config, managed-DB declarations, functions, compute** — live project resources,
//!   not provably orphaned; torn down only by their own explicit verbs.
//!
//! The pure classification helpers here ([`host_is_answered_by`], [`PruneReason`]) carry no I/O so
//! they can be unit-tested in isolation; [`DeployStore::prune_project`](crate::deploy::DeployStore::prune_project)
//! walks the live KV to apply them.

use serde::{Deserialize, Serialize};

use crate::config::SiteConfig;
use crate::host::Host;

/// Why a single key was classified as a provable orphan. A CLOSED vocabulary — the human-facing
/// `detail` string carries the specifics (which site, which host).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PruneReason {
    /// A per-site routing/config key whose site has no resolvable config body and no active
    /// deployment pointer — the site serves nothing, so the key is a dead leftover.
    DeadSite,
    /// A `domainverify/<site>/<host>` challenge for a host the site's CURRENT config does not answer
    /// to AND whose stored record is **unverified AND expired** — a stale/foreign, never-completed
    /// domain-verification challenge (e.g. a `--force` clone commingle leftover, or a host dropped by
    /// a later `deploy apply`). A verified ownership proof or an unexpired pending challenge for a
    /// not-in-config host is KEPT, never classified here (Security review Finding B).
    ForeignDomainVerify,
}

impl PruneReason {
    /// A short stable token for the human/JSON rendering.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeadSite => "dead-site",
            Self::ForeignDomainVerify => "foreign-domain-verify",
        }
    }
}

/// One provably-orphaned control-plane KV key, with the reason it is an orphan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunableKey {
    /// The full KV key (always under `project/<project>/…`).
    pub key: String,
    /// The classification reason (the CLOSED vocabulary).
    pub reason: PruneReason,
    /// A human explanation naming the specific site / host.
    pub detail: String,
}

/// The plan + outcome of a `project prune`: the set of provable orphans, the live sites that
/// anchored the REFERENCED set (for transparency), and — once executed — how many keys were
/// removed. In **dry-run** (the default), `applied` is `false` and `removed` is `0`; `prunable`
/// still lists exactly what an `--apply` would delete. In **apply**, `applied` is `true`,
/// `removed` equals `prunable.len()`, and `prunable` lists exactly what was removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectPrunePlan {
    /// The project this plan is for.
    pub project: String,
    /// The provably-orphaned keys, sorted by key for a stable report.
    pub prunable: Vec<PrunableKey>,
    /// The project's LIVE sites (a resolvable config or an active deployment) — kept, surfaced so
    /// the operator can see what anchored the referenced set.
    pub live_sites: Vec<String>,
    /// `false` for a dry-run (nothing changed); `true` after `--apply`.
    pub applied: bool,
    /// Keys actually removed (`0` for a dry-run; `prunable.len()` after a successful apply).
    pub removed: usize,
}

impl ProjectPrunePlan {
    /// Whether the plan found nothing to prune (a clean project).
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.prunable.is_empty()
    }

    /// The number of orphans found (regardless of whether they were removed).
    #[must_use]
    pub fn orphan_count(&self) -> usize {
        self.prunable.len()
    }
}

/// Whether `host` (a raw host taken from a `domainverify`/`dnsmanaged` KV key segment) is one the
/// site's `config` legitimately answers to — the fail-closed "keep it" test. A host counts as
/// answered-for when it:
///   - exactly matches a configured exact host (primary or alias), the base of a configured
///     wildcard, or a per-host tenant-context key; OR
///   - is the apex of, or a subdomain under, a configured wildcard suffix.
///
/// All comparisons are done in the verification normalization ([`Host::verification`]: trim,
/// strip trailing dots, strip a leading `*.`, lowercase), so a `*.example.com` wildcard and its
/// `example.com` apex, a `www.example.com` alias, and the raw key segment all compare on equal
/// footing — and a `dnsmanaged` key that preserved its `*.` still matches its configured wildcard.
/// Returns `true` (KEEP) on any match; only a host that matches NOTHING is a prunable foreign host.
#[must_use]
pub fn host_is_answered_by(host: &str, config: &SiteConfig) -> bool {
    let needle = Host::new(host).verification();
    if needle.is_empty() {
        // A malformed/empty host segment is not provably foreign — keep it (fail-closed).
        return true;
    }

    // Exact hosts (primary + aliases) and the config's wildcards, each in verification form.
    // A wildcard `*.example.com` verifies to its apex `example.com`.
    let mut exact: Vec<String> = config
        .domains
        .exact_hosts()
        .map(|h| Host::new(h).verification())
        .collect();
    // The wildcard SUFFIXES a subdomain can match under (`example.com` for `*.example.com`).
    let mut wildcard_suffixes: Vec<String> = Vec::new();
    for w in &config.domains.wildcards {
        let v = Host::new(w).verification();
        if !v.is_empty() {
            exact.push(v.clone());
            wildcard_suffixes.push(v);
        }
    }
    // Per-host tenant-context keys also bind the site to a host (an exact host or a wildcard
    // pattern), so they count as answered-for.
    for ctx_host in config.domains.contexts.keys() {
        let v = Host::new(ctx_host).verification();
        if v.is_empty() {
            continue;
        }
        if ctx_host.trim_start().starts_with("*.") {
            wildcard_suffixes.push(v.clone());
        }
        exact.push(v);
    }

    if exact.iter().any(|h| h == &needle) {
        return true;
    }
    wildcard_suffixes
        .iter()
        .any(|suffix| needle == *suffix || needle.ends_with(&format!(".{suffix}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DomainConfig, SiteConfig};
    use std::collections::BTreeMap;

    fn config_with(
        primary: Option<&str>,
        aliases: &[&str],
        wildcards: &[&str],
        contexts: &[(&str, &str)],
    ) -> SiteConfig {
        SiteConfig {
            domains: DomainConfig {
                primary: primary.map(str::to_string),
                aliases: aliases.iter().map(ToString::to_string).collect(),
                wildcards: wildcards.iter().map(ToString::to_string).collect(),
                canonical_redirect: false,
                contexts: contexts
                    .iter()
                    .map(|(h, t)| (h.to_string(), t.to_string()))
                    .collect::<BTreeMap<_, _>>(),
            },
            ..Default::default()
        }
    }

    #[test]
    fn exact_primary_and_alias_hosts_are_answered() {
        let cfg = config_with(Some("example.com"), &["www.example.com"], &[], &[]);
        assert!(host_is_answered_by("example.com", &cfg));
        assert!(host_is_answered_by("www.example.com", &cfg));
        // Case / trailing dot are normalized away.
        assert!(host_is_answered_by("WWW.Example.com.", &cfg));
    }

    #[test]
    fn a_foreign_host_is_not_answered() {
        let cfg = config_with(Some("example.com"), &["www.example.com"], &[], &[]);
        assert!(!host_is_answered_by("foreign.example.net", &cfg));
        assert!(!host_is_answered_by("evil.com", &cfg));
    }

    #[test]
    fn wildcard_apex_and_subdomains_are_answered_but_a_sibling_is_not() {
        let cfg = config_with(None, &[], &["*.example.com"], &[]);
        // The apex (a wildcard verifies to its apex) and any subdomain match.
        assert!(host_is_answered_by("example.com", &cfg));
        assert!(host_is_answered_by("shop.example.com", &cfg));
        assert!(host_is_answered_by("a.b.example.com", &cfg));
        // A `dnsmanaged` key preserves the `*.`; it still matches its own wildcard.
        assert!(host_is_answered_by("*.example.com", &cfg));
        // A different apex is foreign even though it shares a label.
        assert!(!host_is_answered_by("example.com.evil.com", &cfg));
        assert!(!host_is_answered_by("notexample.com", &cfg));
    }

    #[test]
    fn a_tenant_context_host_is_answered() {
        let cfg = config_with(
            Some("example.com"),
            &[],
            &[],
            &[("tenant-a.example.org", "a")],
        );
        assert!(host_is_answered_by("tenant-a.example.org", &cfg));
        assert!(!host_is_answered_by("tenant-b.example.org", &cfg));
    }

    #[test]
    fn a_site_with_no_domains_answers_nothing() {
        let cfg = SiteConfig::default();
        assert!(!host_is_answered_by("anything.example.com", &cfg));
    }

    #[test]
    fn an_empty_host_segment_is_kept_fail_closed() {
        let cfg = config_with(Some("example.com"), &[], &[], &[]);
        // A malformed/empty host is not provably foreign.
        assert!(host_is_answered_by("", &cfg));
        assert!(host_is_answered_by("   ", &cfg));
    }

    #[test]
    fn prune_reason_tokens_are_stable() {
        assert_eq!(PruneReason::DeadSite.as_str(), "dead-site");
        assert_eq!(
            PruneReason::ForeignDomainVerify.as_str(),
            "foreign-domain-verify"
        );
    }
}
