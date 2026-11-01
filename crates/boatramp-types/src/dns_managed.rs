//! Ledger of DNS records boatramp created on the operator's behalf, so they can
//! be **retracted** when a custom domain is detached (`domain rm`) or its site
//! deleted. Persisted in the control-plane KV under
//! `project/<proj>/dnsmanaged/<site>/<host>` (project-scoped, 0.2.0).
//!
//! The record set is stored string-typed (a serializable mirror of the acme
//! `DnsRecord`) so this crate needn't depend on `boatramp-acme`; the retraction
//! side rebuilds the provider named here and deletes each record.
//!
//! **One entry per RAW host, wildcard preserved.** The ledger is keyed and
//! identified by [`Host::domain_entry`](crate::host::Host::domain_entry) —
//! case/dot-folded but, unlike the *verification* key
//! ([`domain_verify::normalize_host`](crate::domain_verify::normalize_host)),
//! NEVER stripping a leading `*.`. A wildcard and its apex base **share one
//! verification record** (control of the zone covers both), but they are
//! **independently tracked, pointed, and retracted** DNS records here — so
//! dropping just `*.example.com` from a site's config retracts exactly that
//! record while `example.com` stays pointed, with no risk of one overwriting
//! the other out of the ledger while its record stays live untracked.

use serde::{Deserialize, Serialize};

/// KV key for the managed-records ledger of `host` under `site`. The host is
/// case/dot-folded via [`Host::domain_entry`](crate::host::Host::domain_entry)
/// — **preserving** a leading `*.` (a wildcard and its apex are distinct,
/// independently-tracked ledger entries; see the module docs). `project` is a
/// bare `&str` (this crate is wasm-clean).
pub fn dnsmanaged_key(project: &str, site: &str, host: &str) -> String {
    format!(
        "project/{project}/dnsmanaged/{site}/{}",
        crate::host::Host::new(host).domain_entry()
    )
}

/// The KV key prefix for a site's managed-record ledgers (for enumeration).
pub fn dnsmanaged_site_prefix(project: &str, site: &str) -> String {
    format!("project/{project}/dnsmanaged/{site}/")
}

/// The KV key prefix for **every** managed-record ledger in a project (every
/// site). Mirrors `domain_verification_project_prefix`'s role for
/// [`crate`]'s verification ledger: it lets the reconcile sweep find a ledger
/// entry whose site has since been fully deleted (so it no longer appears in
/// `DeployStore::all_sites_all`) and still retract it — the ledger, unlike a
/// site's config, is never swept by `delete_site`.
pub fn dnsmanaged_project_prefix(project: &str) -> String {
    format!("project/{project}/dnsmanaged/")
}

/// One DNS record boatramp created — a serializable mirror of the acme
/// `DnsRecord` (kept string-typed to avoid a dependency cycle).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRecord {
    /// Record type token: `A` / `AAAA` / `CNAME` / `TXT`.
    pub kind: String,
    /// Fully-qualified record name.
    pub name: String,
    /// Record value (address, target host, or TXT payload).
    pub value: String,
    /// Time-to-live in seconds.
    pub ttl: u32,
}

/// The records boatramp manages for one host, plus the provider that owns them
/// (so a retraction rebuilds the same provider). Persisted per `(site, host)` —
/// one entry per RAW host (wildcard preserved; see the module docs), so a
/// wildcard and its apex base are tracked, pointed, and retracted separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManagedDns {
    /// Schema version, pinned at [`crate::SCHEMA_VERSION`].
    pub version: u32,
    /// The host these records point at the server (case/dot-folded, wildcard
    /// **preserved** — see the module docs).
    pub host: String,
    /// The DNS provider that owns them (the `--provider` spelling, e.g.
    /// `cloudflare`, `digitalocean`).
    pub provider: String,
    /// The records to retract when the host is detached.
    pub records: Vec<ManagedRecord>,
    /// Unix seconds the records were last written.
    pub updated_at_unix: u64,
}

impl Default for ManagedDns {
    fn default() -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            host: String::new(),
            provider: String::new(),
            records: Vec::new(),
            updated_at_unix: 0,
        }
    }
}

impl ManagedDns {
    /// A ledger entry for `host` managed by `provider`, carrying `records`.
    /// `host` is case/dot-folded, wildcard **preserved** (see the module docs).
    pub fn new(host: &str, provider: &str, records: Vec<ManagedRecord>, now_unix: u64) -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            host: crate::host::Host::new(host).domain_entry(),
            provider: provider.to_string(),
            records,
            updated_at_unix: now_unix,
        }
    }

    /// Parse from the KV JSON representation.
    pub fn from_json(bytes: &[u8]) -> Result<Self, crate::error::ConfigError> {
        serde_json::from_slice(bytes)
            .map_err(|err| crate::error::ConfigError::parse(err.to_string()))
    }

    /// Serialize to JSON for KV storage.
    pub fn to_json(&self) -> Result<Vec<u8>, crate::error::ConfigError> {
        serde_json::to_vec(self).map_err(|err| crate::error::ConfigError::parse(err.to_string()))
    }
}

/// The DNS reconcile actions for one site's custom domains.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReconcilePlan {
    /// Verified + attached hosts to (re)assert the A/CNAME for (idempotent).
    pub to_point: Vec<String>,
    /// Hosts with a ledger entry but no longer attached — retract their records.
    pub to_retract: Vec<String>,
}

/// Plan the leader-only DNS reconcile for one site. `verified` is the set of
/// hosts currently verified + attached to the site; `managed` is the set of
/// hosts that already have a ledger entry. Every verified host is (re)pointed
/// (upsert is idempotent, so this self-heals drift); every managed-but-no-longer-
/// verified host is retracted.
///
/// Hosts are compared **per RAW host** — case/dot-folded via
/// [`Host::domain_entry`](crate::host::Host::domain_entry), but a leading `*.`
/// is **preserved**, never folded onto its apex. A wildcard and its apex base
/// are therefore DISTINCT plan entries: dropping only the wildcard from
/// `verified` (apex still verified+attached) retracts exactly the wildcard's
/// ledger entry, never silently drops it from tracking while its DNS record
/// stays live (the collapsed-comparison design this replaced could lose track
/// of a whole record on a subset shrink — see the ledger's module docs).
pub fn plan_reconcile(verified: &[String], managed: &[String]) -> ReconcilePlan {
    use std::collections::BTreeSet;
    let fold = |h: &String| crate::host::Host::new(h).domain_entry();
    let verified: BTreeSet<String> = verified.iter().map(fold).collect();
    let managed: BTreeSet<String> = managed.iter().map(fold).collect();
    ReconcilePlan {
        to_point: verified.iter().cloned().collect(),
        to_retract: managed.difference(&verified).cloned().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_folds_case_and_dots_but_preserves_the_wildcard() {
        assert_eq!(
            dnsmanaged_key("default", "blog", "*.WWW.Example.com."),
            "project/default/dnsmanaged/blog/*.www.example.com"
        );
        // The apex (no `*.`) is a DIFFERENT key from its wildcard.
        assert_eq!(
            dnsmanaged_key("default", "blog", "WWW.Example.com."),
            "project/default/dnsmanaged/blog/www.example.com"
        );
        assert_eq!(
            dnsmanaged_site_prefix("default", "blog"),
            "project/default/dnsmanaged/blog/"
        );
    }

    #[test]
    fn json_roundtrip() {
        let ledger = ManagedDns::new(
            "www.example.com",
            "cloudflare",
            vec![ManagedRecord {
                kind: "A".into(),
                name: "www.example.com".into(),
                value: "203.0.113.7".into(),
                ttl: 300,
            }],
            42,
        );
        let bytes = ledger.to_json().unwrap();
        assert_eq!(ManagedDns::from_json(&bytes).unwrap(), ledger);
    }

    #[test]
    fn new_folds_the_host_but_preserves_the_wildcard() {
        let ledger = ManagedDns::new("*.Example.com", "route53", Vec::new(), 1);
        assert_eq!(ledger.host, "*.example.com");
        assert_eq!(ledger.version, crate::SCHEMA_VERSION);
        assert_eq!(ledger.provider, "route53");
    }

    #[test]
    fn plan_points_verified_and_retracts_orphans() {
        let plan = plan_reconcile(
            &["a.example.com".into(), "b.example.com".into()],
            &["b.example.com".into(), "old.example.com".into()],
        );
        assert_eq!(plan.to_point, vec!["a.example.com", "b.example.com"]);
        assert_eq!(plan.to_retract, vec!["old.example.com"]);
    }

    /// Security-review MEDIUM(2) fix: a wildcard and its apex base are DISTINCT
    /// plan entries, never collapsed — the design this replaced could silently
    /// lose track of (while leaving live) a record on a subset shrink.
    #[test]
    fn plan_treats_wildcard_and_apex_as_distinct() {
        let plan = plan_reconcile(&["*.Example.com".into(), "example.com".into()], &[]);
        let mut to_point = plan.to_point.clone();
        to_point.sort();
        assert_eq!(to_point, vec!["*.example.com", "example.com"]);
        assert!(plan.to_retract.is_empty());
    }

    /// The exact subset-shrink scenario: a wildcard is dropped from `verified`
    /// (e.g. a declarative `apply` that only re-adds the apex alias) while the
    /// apex stays verified+attached and managed. The wildcard's ledger entry
    /// must be retracted; the apex must NOT be touched.
    #[test]
    fn plan_retracts_only_the_dropped_wildcard_when_the_apex_survives() {
        let plan = plan_reconcile(
            &["example.com".into()],
            &["*.example.com".into(), "example.com".into()],
        );
        assert_eq!(plan.to_point, vec!["example.com"]);
        assert_eq!(plan.to_retract, vec!["*.example.com"]);
    }
}
