//! Ledger of DNS records boatramp created on the operator's behalf, so they can
//! be **retracted** when a custom domain is detached (`domain rm`) or its site
//! deleted. Persisted in the control-plane KV under `dnsmanaged/<site>/<host>`.
//!
//! The record set is stored string-typed (a serializable mirror of the acme
//! `DnsRecord`) so this crate needn't depend on `boatramp-acme`; the retraction
//! side rebuilds the provider named here and deletes each record.

use serde::{Deserialize, Serialize};

/// KV key for the managed-records ledger of `host` under `site`. The host is
/// normalized (lowercased, no `*.`/trailing dot), matching the verification key.
pub fn dnsmanaged_key(site: &str, host: &str) -> String {
    format!(
        "dnsmanaged/{site}/{}",
        crate::domain_verify::normalize_host(host)
    )
}

/// The KV key prefix for a site's managed-record ledgers (for enumeration).
pub fn dnsmanaged_site_prefix(site: &str) -> String {
    format!("dnsmanaged/{site}/")
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
/// (so a retraction rebuilds the same provider). Persisted per `(site, host)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManagedDns {
    /// Schema version, pinned at [`crate::SCHEMA_VERSION`].
    pub version: u32,
    /// The host these records point at the server (normalized).
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
    pub fn new(host: &str, provider: &str, records: Vec<ManagedRecord>, now_unix: u64) -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            host: crate::domain_verify::normalize_host(host),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_normalizes_the_host() {
        assert_eq!(
            dnsmanaged_key("blog", "*.WWW.Example.com."),
            "dnsmanaged/blog/www.example.com"
        );
        assert_eq!(dnsmanaged_site_prefix("blog"), "dnsmanaged/blog/");
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
    fn new_normalizes_host_and_pins_version() {
        let ledger = ManagedDns::new("*.Example.com", "route53", Vec::new(), 1);
        assert_eq!(ledger.host, "example.com");
        assert_eq!(ledger.version, crate::SCHEMA_VERSION);
        assert_eq!(ledger.provider, "route53");
    }
}
