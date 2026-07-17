//! The DNS-provider abstraction: a small record model + an async trait that
//! cloud providers implement, plus the naming and ACME DNS-01 challenge math
//! (pure, network-free, fully tested). A [`ManualDnsProvider`] is always
//! available — it records the changes an operator must apply by hand, so the
//! whole flow works with no cloud credentials.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use async_trait::async_trait;

/// The DNS record types boatramp needs: address records for the wildcard
/// preview host, `CNAME` to point it at another name, and `TXT` for the ACME
/// DNS-01 challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    A,
    Aaaa,
    Cname,
    Txt,
}

impl RecordKind {
    /// The DNS type token (`A`, `AAAA`, `CNAME`, `TXT`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Txt => "TXT",
        }
    }
}

impl std::fmt::Display for RecordKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single DNS record to upsert or delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub kind: RecordKind,
    /// Fully-qualified record name (no trailing dot), e.g.
    /// `*.deploy.example.com` or `_acme-challenge.example.com`.
    pub name: String,
    /// The record value: an IP, a target host, or the TXT payload.
    pub value: String,
    /// Time-to-live in seconds.
    pub ttl: u32,
}

/// Why a DNS operation failed.
#[derive(Debug, Clone)]
pub enum DnsError {
    /// Bad/absent credentials or configuration.
    Config(String),
    /// The provider's API rejected the request or was unreachable.
    Backend(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(m) => write!(f, "dns config error: {m}"),
            Self::Backend(m) => write!(f, "dns backend error: {m}"),
        }
    }
}

impl std::error::Error for DnsError {}

/// A DNS zone editor. Implementations are per-provider (Cloudflare, Route 53,
/// Oracle Cloud, …); the manual one just records what an operator must do.
///
/// `upsert` must be **idempotent** (create-or-replace the record), so a retried
/// ACME challenge or a re-run auto-config converges rather than duplicating.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Create or replace `record`.
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError>;
    /// Remove `record` (best-effort; absent is success).
    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError>;
}

/// The wildcard host that serves a site's by-id previews: `*.deploy.{host}`.
/// One wildcard cert for this name covers every `<id>.deploy.{host}` preview.
/// The label is `deploy` (not `_deploy`): an underscore is valid in a DNS name
/// but **illegal in a TLS certificate SAN**, so a CA would refuse a
/// `*._deploy.x` wildcard.
pub fn preview_wildcard(site_host: &str) -> String {
    format!("*.deploy.{site_host}")
}

/// The ACME DNS-01 challenge record name for `domain`. A wildcard authorization
/// (`*.x`) is validated at the base name, so the leading `*.` is stripped:
/// `*.deploy.example.com` → `_acme-challenge.deploy.example.com` (the underscore
/// in `_acme-challenge` is fine — it's a TXT record name, not a cert SAN).
pub fn acme_challenge_name(domain: &str) -> String {
    let base = domain.strip_prefix("*.").unwrap_or(domain);
    format!("_acme-challenge.{base}")
}

/// The DNS-01 TXT record value for an ACME `key_authorization`:
/// base64url(SHA-256(key_authorization)), unpadded (RFC 8555 §8.4).
pub fn dns01_txt_value(key_authorization: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(key_authorization.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Where a site's preview wildcard host should point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewTarget {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    /// Point at another hostname (e.g. a load balancer) via `CNAME`.
    Cname(String),
}

/// The DNS record that points `name` at `target` — the record kind follows the
/// target (address → `A`/`AAAA`, hostname → `CNAME`).
fn record_at(name: String, target: &PreviewTarget, ttl: u32) -> DnsRecord {
    match target {
        PreviewTarget::Ipv4(ip) => DnsRecord {
            kind: RecordKind::A,
            name,
            value: ip.to_string(),
            ttl,
        },
        PreviewTarget::Ipv6(ip) => DnsRecord {
            kind: RecordKind::Aaaa,
            name,
            value: ip.to_string(),
            ttl,
        },
        PreviewTarget::Cname(target) => DnsRecord {
            kind: RecordKind::Cname,
            name,
            value: target.clone(),
            ttl,
        },
    }
}

/// The single DNS record that makes a site's preview wildcard host resolve to
/// `target` (the "auto-config" record).
pub fn preview_record(site_host: &str, target: &PreviewTarget, ttl: u32) -> DnsRecord {
    record_at(preview_wildcard(site_host), target, ttl)
}

/// The single DNS record that points a **verified custom host** (an apex or a
/// sub-domain) at `target` — the custom-domain analogue of [`preview_record`].
/// `host` becomes the record name verbatim (a trailing dot is trimmed); the kind
/// follows the target. A `CNAME` is invalid at a true apex, so point apex hosts
/// at an address target (`A`/`AAAA`).
pub fn domain_record(host: &str, target: &PreviewTarget, ttl: u32) -> DnsRecord {
    record_at(host.trim_end_matches('.').to_string(), target, ttl)
}

/// Which operation a [`ManualDnsProvider`] recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOp {
    Upsert,
    Delete,
}

/// A [`DnsProvider`] that performs no network calls — it logs and records the
/// changes the operator must apply themselves. The universal fallback when no
/// cloud provider is configured, and the test double for the ACME flow.
#[derive(Default)]
pub struct ManualDnsProvider {
    ops: Mutex<Vec<(DnsOp, DnsRecord)>>,
}

impl ManualDnsProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// The operations recorded so far (for inspection / tests).
    pub fn recorded(&self) -> Vec<(DnsOp, DnsRecord)> {
        self.ops.lock().unwrap().clone()
    }
}

#[async_trait]
impl DnsProvider for ManualDnsProvider {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        tracing::info!(
            target: "boatramp::dns",
            op = "upsert", kind = record.kind.as_str(), name = %record.name,
            value = %record.value, ttl = record.ttl,
            "manual DNS: create this record"
        );
        self.ops
            .lock()
            .unwrap()
            .push((DnsOp::Upsert, record.clone()));
        Ok(())
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        tracing::info!(
            target: "boatramp::dns",
            op = "delete", kind = record.kind.as_str(), name = %record.name,
            "manual DNS: remove this record"
        );
        self.ops
            .lock()
            .unwrap()
            .push((DnsOp::Delete, record.clone()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_wildcard_and_challenge_naming() {
        assert_eq!(preview_wildcard("example.com"), "*.deploy.example.com");
        // The challenge name strips the wildcard label and prefixes the base.
        assert_eq!(
            acme_challenge_name("*.deploy.example.com"),
            "_acme-challenge.deploy.example.com"
        );
        // A non-wildcard domain is prefixed directly.
        assert_eq!(
            acme_challenge_name("example.com"),
            "_acme-challenge.example.com"
        );
    }

    #[test]
    fn dns01_value_is_base64url_sha256_unpadded() {
        // RFC 8555 §8.4 worked example: the SHA-256 of the key authorization,
        // base64url without padding. Verify determinism + the no-pad/url-safe
        // alphabet (no '+', '/', or '=').
        let value = dns01_txt_value("token.thumbprint");
        assert_eq!(value, dns01_txt_value("token.thumbprint"));
        assert!(!value.contains('+') && !value.contains('/') && !value.contains('='));
        // SHA-256 → 32 bytes → 43 base64url chars unpadded.
        assert_eq!(value.len(), 43);
    }

    #[test]
    fn preview_record_picks_kind_by_target() {
        let a = preview_record(
            "example.com",
            &PreviewTarget::Ipv4("203.0.113.7".parse().unwrap()),
            120,
        );
        assert_eq!(a.kind, RecordKind::A);
        assert_eq!(a.name, "*.deploy.example.com");
        assert_eq!(a.value, "203.0.113.7");

        let c = preview_record(
            "example.com",
            &PreviewTarget::Cname("lb.example.net".into()),
            300,
        );
        assert_eq!(c.kind, RecordKind::Cname);
        assert_eq!(c.value, "lb.example.net");
    }

    #[test]
    fn domain_record_points_an_exact_host() {
        // Apex host at an address → A at the apex name (no wildcard prefix).
        let a = domain_record(
            "example.com",
            &PreviewTarget::Ipv4("203.0.113.7".parse().unwrap()),
            300,
        );
        assert_eq!(a.kind, RecordKind::A);
        assert_eq!(a.name, "example.com");
        assert_eq!(a.value, "203.0.113.7");

        // Sub-domain at a hostname → CNAME; a trailing dot on the host is trimmed.
        let c = domain_record(
            "www.example.com.",
            &PreviewTarget::Cname("lb.example.net".into()),
            60,
        );
        assert_eq!(c.kind, RecordKind::Cname);
        assert_eq!(c.name, "www.example.com");
        assert_eq!(c.value, "lb.example.net");
    }

    #[tokio::test]
    async fn manual_provider_records_ops() {
        let provider = ManualDnsProvider::new();
        let record = DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.example.com".into(),
            value: "abc".into(),
            ttl: 60,
        };
        provider.upsert(&record).await.unwrap();
        provider.delete(&record).await.unwrap();
        let ops = provider.recorded();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].0, DnsOp::Upsert);
        assert_eq!(ops[1].0, DnsOp::Delete);
        assert_eq!(ops[0].1.name, "_acme-challenge.example.com");
    }
}
