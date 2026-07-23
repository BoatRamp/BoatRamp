//! The [`Host`] type: one home for the routing-host normalizations that were
//! scattered across three crates (`canon_host` in core, `canon_domain_entry` in
//! the server, `normalize_host` here) with subtly different — and deliberately
//! distinct — wildcard/case rules that all feed KV keys and DNS record names.
//!
//! Each rule is reproduced **exactly** as a named method so a reader picks the
//! semantic explicitly and every serialized boundary stays byte-for-byte:
//! [`Host::routing_key`] and [`Host::domain_entry`] *preserve* a `*.` wildcard
//! (a wildcard route is not its apex), while [`Host::verification`] *strips* it
//! (a wildcard is verified at its base domain, like ACME). Collapsing the two
//! is the trap — they are not interchangeable.

use crate::domain_verify::DNS_RECORD_PREFIX;

/// A routing host: a `Host`-header value, a configured domain, or a wildcard
/// like `*.example.com`. Borrows the raw string and projects the several
/// distinct canonical forms the codebase needs; construction is free
/// (normalization happens per projection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Host<'a>(&'a str);

impl<'a> Host<'a> {
    /// Wrap a raw host string. No normalization happens here — pick a projection.
    pub fn new(raw: &'a str) -> Self {
        Self(raw)
    }

    /// The raw, un-normalized host as given.
    pub fn as_raw(&self) -> &'a str {
        self.0
    }

    /// Routing-key normalization (was `canon_host`): trim, strip trailing dots,
    /// lowercase — **preserving** any leading `*.`. Backs the `domain/<host>`
    /// and `wildcard/<suffix>` routing keys.
    pub fn routing_key(&self) -> String {
        self.0.trim().trim_end_matches('.').to_ascii_lowercase()
    }

    /// Domain-entry normalization (was `canon_domain_entry`): normalize the base
    /// then re-prepend `*.` for a wildcard, else identical to
    /// [`routing_key`](Self::routing_key). Kept as its own method to reproduce
    /// the config-canonicalization path byte-for-byte.
    pub fn domain_entry(&self) -> String {
        match self.0.strip_prefix("*.") {
            Some(base) => format!(
                "*.{}",
                base.trim().trim_end_matches('.').to_ascii_lowercase()
            ),
            None => self.routing_key(),
        }
    }

    /// Verification normalization (was `normalize_host`): trim, strip trailing
    /// dots, **strip** any leading `*.`, lowercase — so a wildcard and its apex
    /// share one verification key / TXT record. Backs `domainverify/<site>/<host>`.
    pub fn verification(&self) -> String {
        let host = self.0.trim().trim_end_matches('.');
        host.strip_prefix("*.").unwrap_or(host).to_ascii_lowercase()
    }

    /// Whether this is a wildcard host (`*.example.com`).
    pub fn is_wildcard(&self) -> bool {
        self.0.trim().starts_with("*.")
    }

    /// The ACME/DNS-01 TXT record name for this host (verification-normalized).
    pub fn dns_record_name(&self) -> String {
        format!("{DNS_RECORD_PREFIX}.{}", self.verification())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_strips_wildcard_and_normalizes() {
        // Oracle: the cases the former `normalize_host` guaranteed.
        assert_eq!(Host::new("*.Example.COM.").verification(), "example.com");
        assert_eq!(
            Host::new("  www.example.com  ").verification(),
            "www.example.com"
        );
        assert_eq!(Host::new("EXAMPLE.com").verification(), "example.com");
    }

    #[test]
    fn routing_key_preserves_wildcard() {
        // Oracle: the cases the former `canon_host` guaranteed.
        assert_eq!(Host::new("*.Example.com").routing_key(), "*.example.com");
        assert_eq!(Host::new("Example.COM.").routing_key(), "example.com");
        assert_eq!(
            Host::new("  app.example.com  ").routing_key(),
            "app.example.com"
        );
    }

    #[test]
    fn domain_entry_matches_routing_for_wellformed_hosts() {
        // Oracle: the former `canon_domain_entry` — equal to routing_key on
        // well-formed input, wildcard preserved either way.
        for host in ["*.Example.com", "example.com.", "  API.example.com  "] {
            assert_eq!(
                Host::new(host).domain_entry(),
                Host::new(host).routing_key()
            );
        }
    }

    #[test]
    fn routing_and_verification_diverge_only_on_the_wildcard() {
        let h = Host::new("*.example.com");
        assert_eq!(h.routing_key(), "*.example.com");
        assert_eq!(h.verification(), "example.com");
        assert!(h.is_wildcard());
    }

    #[test]
    fn dns_record_name_uses_the_verification_form() {
        assert_eq!(
            Host::new("*.Example.com").dns_record_name(),
            format!("{DNS_RECORD_PREFIX}.example.com"),
        );
    }
}
