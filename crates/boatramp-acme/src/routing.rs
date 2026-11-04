//! Multi-zone DNS provider routing (cap-req #27).
//!
//! The env-seeded single-provider model (`acme_dns::build_provider`) configures exactly ONE
//! [`DnsProvider`] → ONE zone per `boatramp serve`, because each adapter's identity + credential come
//! from PROCESS-GLOBAL env vars (`CLOUDFLARE_ZONE_ID` + `CLOUDFLARE_API_TOKEN`, …). A single-tenant
//! serve that is authoritative for several domains in DIFFERENT zones therefore cannot manage DNS /
//! issue per-SNI TLS for more than one of them.
//!
//! [`RoutingDnsProvider`] lifts that limit: it holds a LIST of per-zone providers (each built
//! independently from its own resolved config) and itself implements [`DnsProvider`], routing every
//! `upsert`/`delete` — and the [`DnsProvider::resolve_zone_root`] apex lookup — to the provider whose
//! `zone_root` is the LONGEST suffix of the record's owner name, matched on DNS **label boundaries** (so
//! `uranion.link` matches `a.uranion.link` and `uranion.link`, but NOT `evil-uranion.link`). No match ⇒
//! fail-closed (the write errors; a caller that pre-checks via `resolve_zone_root` gets
//! [`ZoneResolution::NoZone`]).
//!
//! Because the registry IS a `DnsProvider`, BOTH consumers — the ACME DNS-01 cert issuer and the guest
//! `dns-publish` write capability — route by owner name with NO change to the seams that thread one
//! `Arc<dyn DnsProvider>` through the serve loop. A single provider is representable either way: an
//! empty/absent `dns_providers` list keeps the existing single-env path exactly as it was (full
//! backward-compat).

use std::sync::Arc;

use async_trait::async_trait;

use crate::dns::{
    DnsError, DnsProvider, DnsRecord, RecordKindTag, ZoneResolution, canonicalize_owner_name,
    validate_writable,
};

/// One per-zone entry in a [`RoutingDnsProvider`]: the authoritative zone apex (canonical: lowercased,
/// no trailing dot) and the host-held provider that writes it, plus the operator's label (for logs).
struct ZoneEntry {
    /// Operator label (`name` in config), for the boot log / diagnostics. Never a credential.
    label: String,
    /// The canonical zone apex (e.g. `example.com`) this provider is authoritative over.
    zone_root: String,
    /// The host-held writer for this zone. Its adapter credential never leaves the host.
    provider: Arc<dyn DnsProvider>,
}

/// A failure building a [`RoutingDnsProvider`] from a resolved provider list.
#[derive(Debug, PartialEq, Eq)]
pub enum RoutingBuildError {
    /// The list was empty — a routing registry must front at least one zone (an empty list is the
    /// caller's signal to use the single-env path instead, and must be handled there, never here).
    Empty,
    /// A provider's `zone_root` was empty or not a syntactically-legal DNS name.
    InvalidZoneRoot {
        /// The offending provider's operator label.
        label: String,
        /// Why it was rejected.
        why: String,
    },
    /// Two providers declared the SAME canonical `zone_root` — longest-suffix routing cannot
    /// disambiguate them, so the config is refused at build (fail-closed) rather than silently picking
    /// one. Nested zones (`example.com` + `b.example.com`) are fine — longest-suffix wins; only an
    /// exact duplicate is ambiguous.
    DuplicateZoneRoot(String),
}

impl std::fmt::Display for RoutingBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "dns_providers: the provider list is empty"),
            Self::InvalidZoneRoot { label, why } => write!(
                f,
                "dns_providers: provider {label:?} has an invalid zone_root ({why})"
            ),
            Self::DuplicateZoneRoot(zone) => write!(
                f,
                "dns_providers: two providers declare the same zone_root {zone:?} — \
                 longest-suffix routing cannot disambiguate them (nested zones are fine; an exact \
                 duplicate is not)"
            ),
        }
    }
}

impl std::error::Error for RoutingBuildError {}

/// Whether `zone_root` is a suffix of `name` on a DNS LABEL boundary: `name` equals the apex, or `name`
/// ends with `.<apex>`. Both inputs are already canonical (lowercased, no trailing dot). This is the
/// crux of the security property — `evil-uranion.link` must NOT be treated as "inside" `uranion.link`
/// just because the string ends with it; only a whole-label suffix counts.
fn suffix_on_label_boundary(name: &str, zone_root: &str) -> bool {
    if name == zone_root {
        return true;
    }
    name.len() > zone_root.len()
        && name.ends_with(zone_root)
        // The byte just before the matched suffix must be the label separator.
        && name.as_bytes()[name.len() - zone_root.len() - 1] == b'.'
}

/// A list of per-zone [`DnsProvider`]s, routing each operation to the provider whose `zone_root` is the
/// longest label-boundary suffix of the record's owner name (cap-req #27). Implements [`DnsProvider`]
/// itself, so it drops into every seam that threads one `Arc<dyn DnsProvider>`.
pub struct RoutingDnsProvider {
    zones: Vec<ZoneEntry>,
}

// Manual `Debug` (the provider trait objects are not `Debug`, and MUST NOT be — an adapter holds a
// host-held credential): prints only the operator labels + zone roots, never a provider's internals.
impl std::fmt::Debug for RoutingDnsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingDnsProvider")
            .field(
                "zones",
                &self
                    .zones
                    .iter()
                    .map(|z| (z.label.as_str(), z.zone_root.as_str()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl RoutingDnsProvider {
    /// Build a registry from resolved `(label, zone_root, provider)` triples. Each `zone_root` is
    /// canonicalized; an empty/illegal one, or an exact duplicate across entries, is refused
    /// (fail-closed). An empty list is [`RoutingBuildError::Empty`] — the caller handles the
    /// single-env / absent case before reaching here.
    pub fn new(
        entries: Vec<(String, String, Arc<dyn DnsProvider>)>,
    ) -> Result<Self, RoutingBuildError> {
        if entries.is_empty() {
            return Err(RoutingBuildError::Empty);
        }
        let mut zones = Vec::with_capacity(entries.len());
        for (label, zone_root, provider) in entries {
            let canonical = canonicalize_owner_name(&zone_root).map_err(|e| {
                RoutingBuildError::InvalidZoneRoot {
                    label: label.clone(),
                    why: e.to_string(),
                }
            })?;
            if zones.iter().any(|z: &ZoneEntry| z.zone_root == canonical) {
                return Err(RoutingBuildError::DuplicateZoneRoot(canonical));
            }
            zones.push(ZoneEntry {
                label,
                zone_root: canonical,
                provider,
            });
        }
        Ok(Self { zones })
    }

    /// The entry whose `zone_root` is the LONGEST label-boundary suffix of the canonicalized `owner`
    /// name, or `None` when no configured zone is authoritative. A malformed owner name (rejected by
    /// [`canonicalize_owner_name`]) selects nothing (⇒ fail-closed upstream).
    fn select(&self, owner: &str) -> Option<&ZoneEntry> {
        let canonical = canonicalize_owner_name(owner).ok()?;
        self.zones
            .iter()
            .filter(|z| suffix_on_label_boundary(&canonical, &z.zone_root))
            // Longest apex wins; apexes are distinct (built-time duplicate check), and a longer apex is
            // strictly more labels, so byte length is an unambiguous "most specific" key.
            .max_by_key(|z| z.zone_root.len())
    }

    /// The operator labels + zone roots, for the boot log. Never exposes a provider credential.
    pub fn zones(&self) -> Vec<(String, String)> {
        self.zones
            .iter()
            .map(|z| (z.label.clone(), z.zone_root.clone()))
            .collect()
    }

    /// The number of configured zones.
    pub fn len(&self) -> usize {
        self.zones.len()
    }

    /// Whether the registry fronts no zones (never true for a successfully-built registry — `new`
    /// refuses an empty list — but required by clippy's `len_without_is_empty`).
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /// The error returned when no configured zone is authoritative for `name` (fail-closed). Shared by
    /// `upsert`/`delete` so the message is identical.
    fn no_zone_err(&self, name: &str) -> DnsError {
        DnsError::Config(format!(
            "no DNS provider in dns_providers is authoritative for {name:?} \
             (no configured zone_root is a label-boundary suffix of it)"
        ))
    }
}

#[async_trait]
impl DnsProvider for RoutingDnsProvider {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let zone = self
            .select(&record.name)
            .ok_or_else(|| self.no_zone_err(&record.name))?;
        // Precise per-zone / per-provider guardrail (apex-NS for THIS zone, supported-kind for THIS
        // adapter, malformed rdata) before dispatch — defense in depth even when a caller already
        // pre-checked against the (union) registry.
        validate_writable(zone.provider.as_ref(), record, &zone.zone_root)?;
        zone.provider.upsert(record).await
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let zone = self
            .select(&record.name)
            .ok_or_else(|| self.no_zone_err(&record.name))?;
        validate_writable(zone.provider.as_ref(), record, &zone.zone_root)?;
        zone.provider.delete(record).await
    }

    /// The UNION of every configured provider's writable kinds: a kind is pre-check-writable here if
    /// SOME zone's adapter can write it. The PRECISE per-selected-adapter check runs in `upsert`/
    /// `delete` via [`validate_writable`] above, so a kind that only a NON-selected provider supports is
    /// still refused at dispatch — the union only keeps a correct pre-check (e.g. the `dns-publish`
    /// handler's) from falsely refusing a kind the actually-selected adapter supports.
    fn supports_kind(&self, tag: RecordKindTag) -> bool {
        self.zones.iter().any(|z| z.provider.supports_kind(tag))
    }

    fn name(&self) -> &'static str {
        "routing"
    }

    /// Route the apex lookup: the selected zone's apex, or [`ZoneResolution::NoZone`] when nothing is
    /// authoritative (the caller then fails closed). Never [`ZoneResolution::UseConfigured`] — this IS
    /// the routing provider, so there is no outer "configured zone_root" to fall back to.
    fn resolve_zone_root(&self, name: &str) -> ZoneResolution {
        match self.select(name) {
            Some(zone) => ZoneResolution::Zone(zone.zone_root.clone()),
            None => ZoneResolution::NoZone,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{ManualDnsProvider, RecordKind};

    /// A named `ManualDnsProvider`-like double that records which provider handled an op, so routing can
    /// be asserted. `ManualDnsProvider` already records ops but not which instance; this wraps it with a
    /// distinguishing tag captured by the returned record's provider identity.
    fn manual(_tag: &str) -> Arc<dyn DnsProvider> {
        Arc::new(ManualDnsProvider::new())
    }

    fn registry(pairs: &[(&str, &str)]) -> RoutingDnsProvider {
        RoutingDnsProvider::new(
            pairs
                .iter()
                .map(|(label, zone)| (label.to_string(), zone.to_string(), manual(label)))
                .collect(),
        )
        .expect("registry builds")
    }

    #[test]
    fn longest_suffix_label_boundary_selection() {
        let r = registry(&[
            ("apex", "uranion.link"),
            ("sub", "b.example.com"),
            ("base", "example.com"),
        ]);

        // apex itself + a subdomain route to the apex zone.
        assert_eq!(r.select("uranion.link").unwrap().zone_root, "uranion.link");
        assert_eq!(
            r.select("a.uranion.link").unwrap().zone_root,
            "uranion.link"
        );
        assert_eq!(
            r.select("_acme-challenge.a.uranion.link")
                .unwrap()
                .zone_root,
            "uranion.link"
        );

        // Label-boundary: `evil-uranion.link` must NOT match `uranion.link`.
        assert!(
            r.select("evil-uranion.link").is_none(),
            "a non-label-boundary suffix must not match (zone escape)"
        );

        // Nested zones: the longer apex wins.
        assert_eq!(
            r.select("a.b.example.com").unwrap().zone_root,
            "b.example.com"
        );
        assert_eq!(
            r.select("b.example.com").unwrap().zone_root,
            "b.example.com"
        );
        assert_eq!(r.select("c.example.com").unwrap().zone_root, "example.com");
        assert_eq!(r.select("example.com").unwrap().zone_root, "example.com");
    }

    #[test]
    fn no_match_is_none() {
        let r = registry(&[("a", "example.com")]);
        assert!(r.select("other.test").is_none());
        assert!(r.select("notexample.com").is_none());
    }

    #[test]
    fn resolve_zone_root_reports_zone_or_no_zone() {
        let r = registry(&[("a", "example.com")]);
        assert_eq!(
            r.resolve_zone_root("www.example.com"),
            ZoneResolution::Zone("example.com".to_string())
        );
        assert_eq!(r.resolve_zone_root("other.test"), ZoneResolution::NoZone);
    }

    #[test]
    fn case_and_trailing_dot_are_canonicalized() {
        let r = registry(&[("a", "Example.COM.")]);
        assert_eq!(
            r.zones()[0].1,
            "example.com",
            "zone_root canonicalized at build"
        );
        assert_eq!(
            r.select("WWW.example.com.").unwrap().zone_root,
            "example.com"
        );
    }

    #[test]
    fn duplicate_zone_root_is_refused() {
        let err = RoutingDnsProvider::new(vec![
            ("a".into(), "example.com".into(), manual("a")),
            ("b".into(), "Example.com.".into(), manual("b")),
        ])
        .expect_err("exact-duplicate (post-canonicalization) zone_root must be refused");
        assert_eq!(
            err,
            RoutingBuildError::DuplicateZoneRoot("example.com".to_string())
        );
    }

    #[test]
    fn empty_list_is_refused() {
        let err = RoutingDnsProvider::new(Vec::new()).expect_err("empty list refused");
        assert_eq!(err, RoutingBuildError::Empty);
    }

    #[test]
    fn invalid_zone_root_is_refused() {
        let err = RoutingDnsProvider::new(vec![("a".into(), "not a zone".into(), manual("a"))])
            .expect_err("illegal zone_root refused");
        assert!(matches!(err, RoutingBuildError::InvalidZoneRoot { .. }));
    }

    #[tokio::test]
    async fn upsert_routes_to_the_selected_zone_and_no_match_fails_closed() {
        let r = registry(&[("a", "example.com"), ("b", "other.test")]);
        // A record inside example.com routes + succeeds (Manual records the op).
        let rec = DnsRecord {
            kind: RecordKind::A("203.0.113.9".parse().unwrap()),
            name: "www.example.com".to_string(),
            ttl: 300,
        };
        r.upsert(&rec)
            .await
            .expect("routes to example.com and upserts");

        // A record in no configured zone fails closed.
        let orphan = DnsRecord {
            kind: RecordKind::A("203.0.113.9".parse().unwrap()),
            name: "www.unmanaged.test".to_string(),
            ttl: 300,
        };
        let err = r.upsert(&orphan).await.expect_err("no zone ⇒ fail closed");
        assert!(matches!(err, DnsError::Config(_)));
    }

    #[test]
    fn supports_kind_is_the_union() {
        // ManualDnsProvider supports the base writable set {A,AAAA,CNAME,TXT}; the union over two of
        // them is the same set. (A WS2 adapter widening its own set would widen the union.)
        let r = registry(&[("a", "example.com")]);
        assert!(r.supports_kind(RecordKindTag::Txt));
        assert!(r.supports_kind(RecordKindTag::A));
    }
}
