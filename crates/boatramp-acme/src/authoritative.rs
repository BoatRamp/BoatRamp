//! Authoritative-nameserver DNS-01 propagation pre-check.
//!
//! The recursive [`HickoryTxtResolver`](crate::acme::HickoryTxtResolver) asks the host's recursive
//! resolver whether the `_acme-challenge` TXT is live. The problem (field-reported on a Cloudflare
//! zone): a recursive resolver **negative-caches** the empty answer for the zone's SOA-minimum /
//! negative TTL, so even after the provider's authoritative nameservers start serving the TXT the
//! pre-check keeps seeing "not live" until that cache expires — burning the whole propagation budget
//! and leaning on the CA's own retry.
//!
//! [`AuthoritativeTxtResolver`] fixes this the way lego/certbot do: find the zone apex (walk up via
//! SOA), fetch the zone's authoritative nameserver set + their addresses, and query the TXT
//! **directly against those nameservers** (no recursion, no shared negative cache). It follows a
//! CNAME-delegated `_acme-challenge` to the zone that actually serves the record. Every step
//! **fails forward**: if authoritative discovery or a direct query can't run, it falls back to the
//! recursive resolver, which (per the driver) falls back to a blind wait — so issuance is never worse
//! than the recursive-only pre-check it replaces.
//!
//! The orchestration (CNAME-follow → zone-walk → NS→addrs → direct query → fail-forward) is
//! unit-tested against a fake `DnsBackend`; the hickory backend that performs the real queries is a
//! thin wrapper, exercised by the field-validated end-to-end path and the `pebble_dns01` test.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

use async_trait::async_trait;

use crate::acme::{AcmeError, HickoryTxtResolver};
use crate::dns::{DnsError, TxtResolver};

/// Loop guard for following a CNAME-delegated `_acme-challenge` chain.
const MAX_CNAME_HOPS: usize = 10;

/// The low-level DNS queries the authoritative pre-check needs, behind a seam so the orchestration is
/// testable with a fake. The real implementation ([`HickoryDnsBackend`]) runs these over hickory.
#[async_trait]
trait DnsBackend: Send + Sync {
    /// Follow the CNAME chain starting at `name` (bounded by [`MAX_CNAME_HOPS`]), returning the final
    /// target. If `name` is not a CNAME it returns `name` (canonicalized). Uses a **recursive**
    /// resolver — this is discovery, not the authoritative readiness check.
    async fn resolve_cname_chain(&self, name: &str) -> Result<String, DnsError>;

    /// The zone apex authoritative for `name` — the owner of the SOA found by walking up the name.
    /// `Ok(None)` if no SOA is found (not determinable). Recursive resolver.
    async fn find_zone(&self, name: &str) -> Result<Option<String>, DnsError>;

    /// The authoritative nameserver socket addresses for `zone`: its NS names resolved to their A and
    /// AAAA addresses (port 53). Recursive resolver (so glue is followed). May be empty if none
    /// resolved — the caller treats empty as "can't reach the authority" and falls forward.
    async fn authoritative_ns_addrs(&self, zone: &str) -> Result<Vec<SocketAddr>, DnsError>;

    /// The TXT values visible for `name` when queried **directly** at `nameservers` (authoritative, no
    /// recursion) — the union across the nameservers that answered. An empty vec means the
    /// nameservers answered but the record is not present yet (NOT an error).
    async fn txt_direct(
        &self,
        name: &str,
        nameservers: &[SocketAddr],
    ) -> Result<Vec<String>, DnsError>;
}

/// A resolved zone for a challenge name, cached across the poll loop of one issuance (the zone apex
/// and its authoritative nameservers don't change mid-issuance, so we discover them once).
#[derive(Clone)]
struct Zone {
    /// The name whose TXT we actually query — `name` itself, or the final CNAME target.
    target: String,
    /// The zone's authoritative nameserver addresses to query directly.
    nameservers: Vec<SocketAddr>,
}

/// A [`TxtResolver`] that confirms the `_acme-challenge` TXT is live at the zone's **authoritative**
/// nameservers, falling forward to a recursive resolver when authoritative discovery can't run.
///
/// Wire it as the default pre-check resolver (see [`AuthoritativeTxtResolver::system`]); it is a
/// drop-in `TxtResolver`, so the driver's readiness predicate (`txt_record_visible` /
/// [`wait_for_propagation`](crate::acme::wait_for_propagation)) is unchanged — a positive observation
/// here is proof an authoritative nameserver is serving the unique challenge value.
pub struct AuthoritativeTxtResolver {
    /// The authoritative-discovery backend. `None` ⇒ the discovery resolver couldn't be built, so
    /// every lookup goes straight to the recursive `fallback` (still better than a blind wait).
    backend: Option<Box<dyn DnsBackend>>,
    /// The recursive-resolver fallback (and the final evidence source when authoritative discovery
    /// fails). This is the pre-fix behaviour — so the authoritative path can only ever help.
    fallback: Box<dyn TxtResolver>,
    /// Per-challenge-name discovery cache, so the SOA/NS walk runs once per issuance, not per poll.
    cache: Mutex<HashMap<String, Zone>>,
}

impl AuthoritativeTxtResolver {
    /// Build the default resolver: a hickory authoritative-discovery backend plus a recursive
    /// [`HickoryTxtResolver`] fallback, both from the host's system configuration (honouring
    /// `BOATRAMP_ACME_PROPAGATION_RESOLVER`).
    ///
    /// Fails only when **no** recursive resolver can be built at all (no usable resolver config) — the
    /// caller then drops to a blind propagation wait. If the recursive resolver builds but the
    /// discovery resolver does not, the authoritative path is simply disabled and every lookup uses
    /// the recursive fallback (the pre-fix behaviour).
    pub fn system() -> Result<Self, AcmeError> {
        // The recursive fallback is required: without it there is no readiness evidence at all, so we
        // surface the error and the driver blind-waits (never worse than before).
        let fallback = HickoryTxtResolver::system()?;
        // The authoritative-discovery resolver is best-effort: if it can't be built we keep the
        // recursive fallback rather than failing issuance.
        let backend: Option<Box<dyn DnsBackend>> = match HickoryDnsBackend::system() {
            Ok(backend) => Some(Box::new(backend)),
            Err(err) => {
                tracing::warn!(
                    target: "boatramp::acme", %err,
                    "could not build the authoritative-NS discovery resolver; the DNS-01 pre-check \
                     will use the recursive resolver only"
                );
                None
            }
        };
        Ok(Self {
            backend,
            fallback: Box::new(fallback),
            cache: Mutex::new(HashMap::new()),
        })
    }

    #[cfg(test)]
    fn from_parts(backend: Box<dyn DnsBackend>, fallback: Box<dyn TxtResolver>) -> Self {
        Self {
            backend: Some(backend),
            fallback,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cached_zone(&self, name: &str) -> Option<Zone> {
        self.cache.lock().ok().and_then(|c| c.get(name).cloned())
    }

    fn store_zone(&self, name: &str, zone: Zone) {
        if let Ok(mut c) = self.cache.lock() {
            c.insert(name.to_string(), zone);
        }
    }

    /// The authoritative readiness lookup. `Ok(values)` is a real authoritative answer (an empty vec
    /// means the nameservers answered but the record is not present yet — still an answer). `Err(why)`
    /// signals "couldn't run the authoritative check" and triggers the recursive fallback.
    async fn lookup_authoritative(&self, name: &str) -> Result<Vec<String>, String> {
        let backend = self
            .backend
            .as_deref()
            .ok_or("no authoritative discovery resolver")?;

        // Discovery (CNAME-follow → zone apex → authoritative NS addresses) runs once per challenge
        // name and is cached for the rest of the poll loop.
        let zone = match self.cached_zone(name) {
            Some(zone) => zone,
            None => {
                let target = backend
                    .resolve_cname_chain(name)
                    .await
                    .map_err(|e| format!("following the CNAME chain for {name}: {e}"))?;
                let apex = backend
                    .find_zone(&target)
                    .await
                    .map_err(|e| format!("finding the zone apex for {target}: {e}"))?
                    .ok_or_else(|| format!("no SOA / zone apex found for {target}"))?;
                let nameservers = backend
                    .authoritative_ns_addrs(&apex)
                    .await
                    .map_err(|e| format!("resolving authoritative nameservers for {apex}: {e}"))?;
                if nameservers.is_empty() {
                    return Err(format!(
                        "no authoritative nameserver addresses resolved for zone {apex}"
                    ));
                }
                let zone = Zone {
                    target,
                    nameservers,
                };
                self.store_zone(name, zone.clone());
                zone
            }
        };

        // The readiness check proper: query the record directly at the authoritative nameservers.
        backend
            .txt_direct(&zone.target, &zone.nameservers)
            .await
            .map_err(|e| format!("querying TXT at the authoritative nameservers: {e}"))
    }
}

#[async_trait]
impl TxtResolver for AuthoritativeTxtResolver {
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        match self.lookup_authoritative(name).await {
            Ok(values) => Ok(values),
            Err(reason) => {
                tracing::debug!(
                    target: "boatramp::acme", %name, %reason,
                    "authoritative-NS pre-check unavailable; falling back to the recursive resolver"
                );
                self.fallback.lookup_txt(name).await
            }
        }
    }
}

/// The hickory implementation of [`DnsBackend`]: a recursive resolver for discovery, plus a fresh
/// authoritative resolver per direct query (so no shared negative cache lingers between polls).
struct HickoryDnsBackend {
    /// Recursive resolver for SOA / NS / A / AAAA / CNAME discovery.
    discovery: hickory_resolver::TokioResolver,
}

impl HickoryDnsBackend {
    fn system() -> Result<Self, AcmeError> {
        Ok(Self {
            discovery: crate::acme::build_system_resolver()?,
        })
    }
}

/// Parse a DNS name as a fully-qualified hickory [`Name`](hickory_resolver::proto::rr::Name).
/// `from_str_relaxed` tolerates the underscore labels (`_acme-challenge`) the strict IDNA parser
/// rejects.
fn parse_fqdn(name: &str) -> Result<hickory_resolver::proto::rr::Name, DnsError> {
    use hickory_resolver::proto::rr::Name;
    let mut n = Name::from_str_relaxed(name)
        .map_err(|e| DnsError::Backend(format!("parsing DNS name {name:?}: {e}")))?;
    n.set_fqdn(true);
    Ok(n)
}

/// A hickory [`Name`](hickory_resolver::proto::rr::Name) as a bare string (ASCII, no trailing dot) —
/// the form the rest of the crate uses for owner names.
fn name_to_string(name: &hickory_resolver::proto::rr::Name) -> String {
    name.to_ascii().trim_end_matches('.').to_string()
}

#[async_trait]
impl DnsBackend for HickoryDnsBackend {
    async fn resolve_cname_chain(&self, name: &str) -> Result<String, DnsError> {
        use hickory_resolver::proto::rr::{RData, RecordType};
        let mut current = parse_fqdn(name)?;
        for _ in 0..MAX_CNAME_HOPS {
            match self
                .discovery
                .lookup(current.clone(), RecordType::CNAME)
                .await
            {
                Ok(lookup) => {
                    let next = lookup.answers().iter().find_map(|r| match &r.data {
                        RData::CNAME(cname) => Some(cname.0.clone()),
                        _ => None,
                    });
                    match next {
                        Some(target) => current = target,
                        // No CNAME at this name ⇒ end of the chain.
                        None => break,
                    }
                }
                // No CNAME record ⇒ not a delegation; the name itself is the target.
                Err(err) if err.is_no_records_found() => break,
                Err(err) => return Err(DnsError::Backend(err.to_string())),
            }
        }
        Ok(name_to_string(&current))
    }

    async fn find_zone(&self, name: &str) -> Result<Option<String>, DnsError> {
        use hickory_resolver::proto::rr::{RData, RecordType};
        let mut current = parse_fqdn(name)?;
        loop {
            if current.is_root() || current.num_labels() == 0 {
                return Ok(None);
            }
            match self
                .discovery
                .lookup(current.clone(), RecordType::SOA)
                .await
            {
                Ok(lookup) => {
                    // The SOA may land in the answer section (querying the apex itself) or the
                    // authority section (querying a sub-name). Its OWNER is the zone apex.
                    let owner = lookup
                        .answers()
                        .iter()
                        .chain(lookup.authorities().iter())
                        .find_map(|r| match &r.data {
                            RData::SOA(_) => Some(r.name.clone()),
                            _ => None,
                        });
                    if let Some(owner) = owner {
                        return Ok(Some(name_to_string(&owner)));
                    }
                    // No SOA surfaced here — strip the leftmost label and walk up toward the apex.
                }
                // NODATA / NXDOMAIN for this sub-name — keep walking up.
                Err(err) if err.is_no_records_found() => {}
                Err(err) => return Err(DnsError::Backend(err.to_string())),
            }
            current = current.base_name();
        }
    }

    async fn authoritative_ns_addrs(&self, zone: &str) -> Result<Vec<SocketAddr>, DnsError> {
        use hickory_resolver::proto::rr::{RData, RecordType};
        let zname = parse_fqdn(zone)?;
        let ns_names: Vec<hickory_resolver::proto::rr::Name> =
            match self.discovery.lookup(zname, RecordType::NS).await {
                Ok(lookup) => lookup
                    .answers()
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::NS(ns) => Some(ns.0.clone()),
                        _ => None,
                    })
                    .collect(),
                Err(err) if err.is_no_records_found() => Vec::new(),
                Err(err) => return Err(DnsError::Backend(err.to_string())),
            };

        let mut addrs: Vec<SocketAddr> = Vec::new();
        for ns in ns_names {
            // Resolve each nameserver to its A and AAAA addresses. A single unresolvable nameserver is
            // not fatal — we query whichever authoritative servers we can reach.
            if let Ok(lookup) = self.discovery.ipv4_lookup(ns.clone()).await {
                for r in lookup.answers() {
                    if let RData::A(a) = &r.data {
                        addrs.push(SocketAddr::new(IpAddr::V4(a.0), 53));
                    }
                }
            }
            if let Ok(lookup) = self.discovery.ipv6_lookup(ns.clone()).await {
                for r in lookup.answers() {
                    if let RData::AAAA(a) = &r.data {
                        addrs.push(SocketAddr::new(IpAddr::V6(a.0), 53));
                    }
                }
            }
        }
        addrs.sort();
        addrs.dedup();
        Ok(addrs)
    }

    async fn txt_direct(
        &self,
        name: &str,
        nameservers: &[SocketAddr],
    ) -> Result<Vec<String>, DnsError> {
        // A fresh resolver pointed at exactly the authoritative nameservers. Built per call so no
        // negative answer cached from an earlier poll can mask a record that just went live.
        let resolver = HickoryTxtResolver::with_nameservers(nameservers)
            .map_err(|e| DnsError::Backend(format!("building authoritative resolver: {e}")))?;
        resolver.lookup_txt(name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TOKEN: &str = "the-unique-challenge-value";
    const CHALLENGE: &str = "_acme-challenge.deploy.example.com";

    /// Observable state shared with a [`FakeBackend`], so a test can read what it did after boxing it
    /// behind `dyn DnsBackend` (no downcasting).
    #[derive(Clone, Default)]
    struct BackendObs {
        direct_queries: Arc<AtomicUsize>,
        cname_calls: Arc<AtomicUsize>,
        zone_calls: Arc<AtomicUsize>,
        ns_calls: Arc<AtomicUsize>,
        last_txt_name: Arc<Mutex<Option<String>>>,
        last_txt_ns: Arc<Mutex<Vec<SocketAddr>>>,
    }

    /// A scripted [`DnsBackend`]: becomes "visible" only after `visible_after` direct queries, can be
    /// told to fail any step (fail-forward), and records what it was asked via a shared [`BackendObs`].
    #[derive(Default)]
    struct FakeBackend {
        /// CNAME target `resolve_cname_chain` returns (None ⇒ return the name unchanged).
        cname_target: Option<String>,
        /// Zone apex `find_zone` reports (None ⇒ "no zone" → fail-forward).
        zone: Option<String>,
        /// Authoritative NS addresses `authoritative_ns_addrs` reports.
        ns: Vec<SocketAddr>,
        /// `txt_direct` returns the token only once this many direct queries have run.
        visible_after: usize,
        /// Force a specific step to error, to drive fail-forward.
        fail_cname: bool,
        fail_zone: bool,
        fail_ns: bool,
        fail_txt: bool,
        obs: BackendObs,
    }

    #[async_trait]
    impl DnsBackend for FakeBackend {
        async fn resolve_cname_chain(&self, name: &str) -> Result<String, DnsError> {
            self.obs.cname_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_cname {
                return Err(DnsError::Backend("cname blew up".into()));
            }
            Ok(self
                .cname_target
                .clone()
                .unwrap_or_else(|| name.to_string()))
        }
        async fn find_zone(&self, _name: &str) -> Result<Option<String>, DnsError> {
            self.obs.zone_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_zone {
                return Err(DnsError::Backend("zone blew up".into()));
            }
            Ok(self.zone.clone())
        }
        async fn authoritative_ns_addrs(&self, _zone: &str) -> Result<Vec<SocketAddr>, DnsError> {
            self.obs.ns_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_ns {
                return Err(DnsError::Backend("ns blew up".into()));
            }
            Ok(self.ns.clone())
        }
        async fn txt_direct(
            &self,
            name: &str,
            nameservers: &[SocketAddr],
        ) -> Result<Vec<String>, DnsError> {
            let n = self.obs.direct_queries.fetch_add(1, Ordering::SeqCst) + 1;
            *self.obs.last_txt_name.lock().unwrap() = Some(name.to_string());
            *self.obs.last_txt_ns.lock().unwrap() = nameservers.to_vec();
            if self.fail_txt {
                return Err(DnsError::Backend("txt blew up".into()));
            }
            if n >= self.visible_after {
                Ok(vec![TOKEN.to_string()])
            } else {
                Ok(Vec::new()) // nameservers reachable, record not live yet
            }
        }
    }

    /// A recording recursive fallback: counts consultations and returns a fixed answer.
    struct FakeFallback {
        calls: Arc<AtomicUsize>,
        answer: Vec<String>,
    }
    #[async_trait]
    impl TxtResolver for FakeFallback {
        async fn lookup_txt(&self, _name: &str) -> Result<Vec<String>, DnsError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.answer.clone())
        }
    }

    fn ns_addrs() -> Vec<SocketAddr> {
        vec![
            "203.0.113.53:53".parse().unwrap(),
            "[2001:db8::53]:53".parse().unwrap(),
        ]
    }

    /// Wire `backend` + a fallback returning `fallback_answer` into a resolver, handing back the shared
    /// observation handles so a test can assert what each tier did.
    fn wire(
        backend: FakeBackend,
        fallback_answer: Vec<String>,
    ) -> (AuthoritativeTxtResolver, BackendObs, Arc<AtomicUsize>) {
        let obs = backend.obs.clone();
        let fb_calls = Arc::new(AtomicUsize::new(0));
        let resolver = AuthoritativeTxtResolver::from_parts(
            Box::new(backend),
            Box::new(FakeFallback {
                calls: Arc::clone(&fb_calls),
                answer: fallback_answer,
            }),
        );
        (resolver, obs, fb_calls)
    }

    /// The happy path: discovery finds the zone + authoritative NS, and the direct query sees the
    /// token on the first poll — the authoritative NS is queried, the recursive fallback is not.
    #[tokio::test]
    async fn observes_token_at_authoritative_ns_without_fallback() {
        let (resolver, obs, fb_calls) = wire(
            FakeBackend {
                zone: Some("example.com".into()),
                ns: ns_addrs(),
                visible_after: 1,
                ..Default::default()
            },
            vec![], // a recursive resolver would still negative-cache "empty" here
        );

        let values = resolver.lookup_txt(CHALLENGE).await.unwrap();
        assert_eq!(
            values,
            vec![TOKEN.to_string()],
            "the token must be observed"
        );
        assert_eq!(obs.direct_queries.load(Ordering::SeqCst), 1);
        assert_eq!(
            *obs.last_txt_ns.lock().unwrap(),
            ns_addrs(),
            "queried the discovered authoritative nameservers"
        );
        assert_eq!(
            fb_calls.load(Ordering::SeqCst),
            0,
            "the recursive fallback must NOT be consulted on the authoritative happy path"
        );
    }

    /// The authoritative NS answers but the record is not live yet: empty (Pending), NOT a fallback —
    /// the authoritative server is the source of truth, so its "not there" is final for this poll and
    /// the (possibly negative-caching) recursive resolver is not consulted.
    #[tokio::test]
    async fn authoritative_empty_is_pending_not_fallback() {
        let (resolver, _obs, fb_calls) = wire(
            FakeBackend {
                zone: Some("example.com".into()),
                ns: ns_addrs(),
                visible_after: 3, // not live on the first query
                ..Default::default()
            },
            vec![TOKEN.to_string()], // would be a false "ready" if wrongly consulted
        );

        let values = resolver.lookup_txt(CHALLENGE).await.unwrap();
        assert!(
            values.is_empty(),
            "authoritative NS has no record yet ⇒ Pending"
        );
        assert_eq!(
            fb_calls.load(Ordering::SeqCst),
            0,
            "a reachable-but-empty authoritative answer must not fall back to the recursive resolver"
        );
    }

    /// Discovery is cached: a second poll reuses the zone + NS (one CNAME/zone/NS discovery); only the
    /// direct query repeats — and the token becomes visible on the later poll.
    #[tokio::test]
    async fn discovery_is_cached_across_polls() {
        let (resolver, obs, _fb) = wire(
            FakeBackend {
                zone: Some("example.com".into()),
                ns: ns_addrs(),
                visible_after: 2, // live on the 2nd direct query
                ..Default::default()
            },
            vec![],
        );

        assert!(resolver.lookup_txt(CHALLENGE).await.unwrap().is_empty());
        assert_eq!(
            resolver.lookup_txt(CHALLENGE).await.unwrap(),
            vec![TOKEN.to_string()]
        );

        assert_eq!(obs.direct_queries.load(Ordering::SeqCst), 2, "two polls");
        assert_eq!(
            obs.cname_calls.load(Ordering::SeqCst),
            1,
            "CNAME discovery ran once"
        );
        assert_eq!(
            obs.zone_calls.load(Ordering::SeqCst),
            1,
            "zone walk ran once"
        );
        assert_eq!(
            obs.ns_calls.load(Ordering::SeqCst),
            1,
            "NS resolution ran once"
        );
    }

    /// CNAME delegation: `_acme-challenge.<host>` is a CNAME to another zone; the TXT is queried at the
    /// TARGET name against the target zone's authoritative nameservers.
    #[tokio::test]
    async fn follows_cname_delegation_to_the_target() {
        let target = "_acme-challenge.deploy.example.com.acme-delegated.net";
        let (resolver, obs, _fb) = wire(
            FakeBackend {
                cname_target: Some(target.into()),
                zone: Some("acme-delegated.net".into()),
                ns: ns_addrs(),
                visible_after: 1,
                ..Default::default()
            },
            vec![],
        );

        assert_eq!(
            resolver.lookup_txt(CHALLENGE).await.unwrap(),
            vec![TOKEN.to_string()]
        );
        assert_eq!(
            obs.last_txt_name.lock().unwrap().as_deref(),
            Some(target),
            "the TXT must be queried at the CNAME target, not the original challenge name"
        );
    }

    /// Fail-forward: whenever discovery or the direct query cannot run, the lookup falls back to the
    /// recursive resolver rather than erroring — issuance never regresses. One case per failure mode.
    #[tokio::test]
    async fn fails_forward_to_recursive_on_any_failure() {
        let base = || FakeBackend {
            zone: Some("example.com".into()),
            ns: ns_addrs(),
            visible_after: 1,
            ..Default::default()
        };
        let cases: Vec<(&str, FakeBackend)> = vec![
            (
                "no zone",
                FakeBackend {
                    zone: None,
                    ..base()
                },
            ),
            (
                "cname error",
                FakeBackend {
                    fail_cname: true,
                    ..base()
                },
            ),
            (
                "zone error",
                FakeBackend {
                    fail_zone: true,
                    ..base()
                },
            ),
            (
                "ns error",
                FakeBackend {
                    fail_ns: true,
                    ..base()
                },
            ),
            (
                "empty ns",
                FakeBackend {
                    ns: vec![],
                    ..base()
                },
            ),
            (
                "txt error",
                FakeBackend {
                    fail_txt: true,
                    ..base()
                },
            ),
        ];
        for (label, backend) in cases {
            let (resolver, _obs, fb_calls) = wire(backend, vec![TOKEN.to_string()]);
            let values = resolver.lookup_txt(CHALLENGE).await.unwrap();
            assert_eq!(
                values,
                vec![TOKEN.to_string()],
                "[{label}] must return the recursive fallback's answer"
            );
            assert_eq!(
                fb_calls.load(Ordering::SeqCst),
                1,
                "[{label}] must consult the recursive fallback exactly once"
            );
        }
    }

    /// With no authoritative backend at all (discovery resolver couldn't be built), every lookup goes
    /// straight to the recursive fallback — the pre-fix behaviour, never worse.
    #[tokio::test]
    async fn no_backend_uses_recursive_fallback() {
        let fb_calls = Arc::new(AtomicUsize::new(0));
        let resolver = AuthoritativeTxtResolver {
            backend: None,
            fallback: Box::new(FakeFallback {
                calls: Arc::clone(&fb_calls),
                answer: vec![TOKEN.to_string()],
            }),
            cache: Mutex::new(HashMap::new()),
        };
        assert_eq!(
            resolver.lookup_txt(CHALLENGE).await.unwrap(),
            vec![TOKEN.to_string()]
        );
        assert_eq!(fb_calls.load(Ordering::SeqCst), 1);
    }
}
