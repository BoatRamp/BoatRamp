//! The hickory-backed [`DnsResolver`] for the guest-facing `dns-resolve` capability (mailroom cap-req
//! #20). Lives server-side because hickory-resolver is a boatramp-server dependency (boatramp-handlers
//! stays resolver-free — it only defines the trait + the SSRF-floored binding). The resolver, with its
//! own positive/negative cache, is built ONCE process-wide (a `OnceLock`) and shared by every guest
//! invocation that is granted `dns-resolve` — DNS is global, so one cached resolver is correct.
//!
//! The SSRF floor on resolved ADDRESSES is NOT here — it is applied in the handlers-side binding
//! ([`boatramp_handlers::DnsResolveHost::resolve_addr`]) against the invocation's `allow_private_egress`
//! posture, so the one SSRF predicate (`is_global_ip`) governs both this and `tcp-egress`.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use boatramp_handlers::{DnsResolveError, DnsResolver, MxRecord};

use crate::dns_resolve_override::{DnsResolveOverrideConfig, StaticMx};

/// The hickory resolver, built once and shared. `TokioResolver` is internally `Arc`-backed and
/// `Clone`, and caches lookups, so concurrent guest resolves share one cache.
struct HickoryDnsResolver {
    inner: hickory_resolver::TokioResolver,
}

/// Response-cache size (number of cached DNS responses) for the shared `dns-resolve` resolver
/// (senior-architect review, pairs with the per-invocation resolve budget cap-req #20). A mail relay
/// resolving MX + A/AAAA for many distinct recipient domains thrashes a small cache, so set a
/// generous explicit value rather than depend on the library default (which has varied across
/// hickory versions). `u64` to match `ResolverOpts::cache_size`.
const DNS_RESOLVER_CACHE_SIZE: u64 = 32_768;

impl HickoryDnsResolver {
    /// Build the resolver from the system config (resolv.conf), falling back to the default public
    /// config — the same fallible-builder chain the `domain-verify-dns` probe uses. Both arms set an
    /// explicit larger response-cache size ([`DNS_RESOLVER_CACHE_SIZE`]) via the builder's
    /// `options_mut()` (hickory-resolver 0.26) so a high-cardinality mail relay doesn't thrash it.
    fn build() -> Result<Self, String> {
        use hickory_resolver::Resolver;
        use hickory_resolver::config::ResolverConfig;
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        let inner = hickory_resolver::TokioResolver::builder_tokio()
            .map(|mut b| {
                b.options_mut().cache_size = DNS_RESOLVER_CACHE_SIZE;
                b
            })
            .and_then(hickory_resolver::ResolverBuilder::build)
            .or_else(|_| {
                let mut b = Resolver::builder_with_config(
                    ResolverConfig::default(),
                    TokioRuntimeProvider::default(),
                );
                b.options_mut().cache_size = DNS_RESOLVER_CACHE_SIZE;
                b.build()
            })
            .map_err(|e| format!("building the DNS resolver: {e}"))?;
        Ok(Self { inner })
    }

    /// Build a resolver pointed at a CUSTOM upstream nameserver (`host:port`, UDP+TCP) instead of the
    /// system config — the dev/test `[handlers.dns_resolve_override].upstream` path. Deterministic
    /// config (no resolv.conf), so a build failure is a genuine environment problem. Same explicit
    /// cache size as [`build`](Self::build).
    fn build_with_upstream(upstream: &str) -> Result<Self, String> {
        use hickory_resolver::Resolver;
        use hickory_resolver::config::{NameServerConfig, ResolverConfig};
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        let socket: SocketAddr = upstream
            .parse()
            .map_err(|e| format!("parsing dns upstream '{upstream}': {e}"))?;
        let mut ns = NameServerConfig::udp_and_tcp(socket.ip());
        // `udp_and_tcp` defaults each connection to port 53; honor the configured port.
        for conn in &mut ns.connections {
            conn.port = socket.port();
        }
        let config = ResolverConfig::from_parts(None, Vec::new(), vec![ns]);
        let mut b = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
        b.options_mut().cache_size = DNS_RESOLVER_CACHE_SIZE;
        b.build()
            .map(|inner| Self { inner })
            .map_err(|e| format!("building the dns upstream resolver '{upstream}': {e}"))
    }
}

/// Normalize a DNS name for the static-override map key: trim surrounding whitespace, drop a trailing
/// dot (FQDN form), lowercase (DNS names are case-insensitive).
fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// A [`DnsResolver`] that answers from an operator-configured STATIC map FIRST (the dev/test override,
/// cap-req #21 residual) and, on a miss, delegates to `fallthrough` (the system or custom-upstream
/// hickory resolver) when one is present — else [`DnsResolveError::NotFound`]. A static hit returns
/// WITHOUT any network I/O, which is exactly what makes a fully-offline direct-MX relay proof possible.
/// `fallthrough = None` makes the map AUTHORITATIVE (a miss is `NotFound`), the shape a hermetic test
/// uses to prove nothing but the map was consulted.
struct StaticResolver {
    /// name → A/AAAA addresses (combined, as `resolve_addr` returns them).
    addrs: BTreeMap<String, Vec<IpAddr>>,
    /// name → MX records (sorted ascending by preference at build time).
    mx: BTreeMap<String, Vec<MxRecord>>,
    fallthrough: Option<Arc<dyn DnsResolver>>,
}

impl StaticResolver {
    /// Build the static map from the override config, with the given miss-delegate.
    fn from_config(
        cfg: &DnsResolveOverrideConfig,
        fallthrough: Option<Arc<dyn DnsResolver>>,
    ) -> Self {
        let mut addrs: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
        let mut mx: BTreeMap<String, Vec<MxRecord>> = BTreeMap::new();
        for rec in &cfg.records {
            let key = normalize_name(&rec.name);
            if !rec.addrs.is_empty() {
                addrs
                    .entry(key.clone())
                    .or_default()
                    .extend(rec.addrs.iter().copied());
            }
            if !rec.mx.is_empty() {
                let entry = mx.entry(key).or_default();
                for StaticMx {
                    preference,
                    exchange,
                } in &rec.mx
                {
                    entry.push(MxRecord {
                        preference: *preference,
                        exchange: exchange.trim().trim_end_matches('.').to_string(),
                    });
                }
            }
            // `rec.txt` is intentionally not consulted: the consumer-lane `DnsResolver` trait exposes
            // only MX + address resolution (no resolve-txt), so TXT overrides are inert today.
        }
        for records in mx.values_mut() {
            records.sort_by_key(|r| r.preference);
        }
        Self {
            addrs,
            mx,
            fallthrough,
        }
    }
}

#[async_trait::async_trait]
impl DnsResolver for StaticResolver {
    async fn resolve_mx(&self, domain: &str) -> Result<Vec<MxRecord>, DnsResolveError> {
        if let Some(records) = self.mx.get(&normalize_name(domain)) {
            // A configured (non-empty) MX set answers authoritatively — no network.
            return Ok(records.clone());
        }
        match &self.fallthrough {
            Some(f) => f.resolve_mx(domain).await,
            None => Err(DnsResolveError::NotFound),
        }
    }

    async fn resolve_addr(&self, host: &str) -> Result<Vec<IpAddr>, DnsResolveError> {
        if let Some(addrs) = self.addrs.get(&normalize_name(host)) {
            return Ok(addrs.clone());
        }
        match &self.fallthrough {
            Some(f) => f.resolve_addr(host).await,
            None => Err(DnsResolveError::NotFound),
        }
    }
}

/// Build the consumer-lane resolver for a given override posture. With no active override this is the
/// plain system resolver — byte-for-byte the historical path. With one, it is a [`StaticResolver`]
/// (static answers first) whose miss-delegate is either a custom-upstream resolver (when `upstream` is
/// set) or the system resolver. A fallthrough build failure degrades the OVERRIDE to an
/// [`UnavailableResolver`] (logged), never a panic.
fn build_resolver(override_cfg: Option<&DnsResolveOverrideConfig>) -> Arc<dyn DnsResolver> {
    match override_cfg {
        None => match HickoryDnsResolver::build() {
            Ok(r) => Arc::new(r),
            Err(e) => {
                tracing::error!(error = %e, "dns-resolve: failed to build the shared DNS resolver");
                Arc::new(UnavailableResolver)
            }
        },
        Some(cfg) => {
            let fallthrough: Result<HickoryDnsResolver, String> = match &cfg.upstream {
                Some(upstream) => HickoryDnsResolver::build_with_upstream(upstream),
                None => HickoryDnsResolver::build(),
            };
            match fallthrough {
                Ok(r) => Arc::new(StaticResolver::from_config(
                    cfg,
                    Some(Arc::new(r) as Arc<dyn DnsResolver>),
                )),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "dns-resolve: override fallthrough resolver failed to build; static answers \
                         will still be served, every other name is unavailable"
                    );
                    // Still honor the static map; a non-static name reports `failed`, never a panic.
                    Arc::new(StaticResolver::from_config(
                        cfg,
                        Some(Arc::new(UnavailableResolver) as Arc<dyn DnsResolver>),
                    ))
                }
            }
        }
    }
}

/// A basic syntactic check so a clearly-bad name is `invalid-name` rather than a generic failure.
fn validate_name(name: &str) -> Result<(), DnsResolveError> {
    let n = name.trim();
    if n.is_empty() || n.len() > 253 || n.contains(char::is_whitespace) {
        return Err(DnsResolveError::InvalidName(
            "not a syntactically valid domain/host".to_string(),
        ));
    }
    Ok(())
}

#[async_trait::async_trait]
impl DnsResolver for HickoryDnsResolver {
    async fn resolve_mx(&self, domain: &str) -> Result<Vec<MxRecord>, DnsResolveError> {
        use hickory_resolver::proto::rr::RData;
        let domain = domain.trim();
        validate_name(domain)?;
        let lookup = match self.inner.mx_lookup(domain).await {
            Ok(l) => l,
            Err(e) if e.is_no_records_found() => return Err(DnsResolveError::NotFound),
            // COARSE reason to the guest (security-review LOW-1): hickory's raw error can echo the
            // host's configured nameserver address / resolv.conf / OS detail. Log it host-side; the
            // guest gets a fixed string, mirroring `tcp-egress`'s `DnsFailure`.
            Err(e) => {
                tracing::debug!(error = %e, %domain, "dns-resolve: mx lookup failed");
                return Err(DnsResolveError::Failed("mx lookup failed".to_string()));
            }
        };
        let mut records: Vec<MxRecord> = lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                // hickory-proto 0.26 exposes MX `preference`/`exchange` as public fields (the same
                // move that made TXT `txt_data` a field — see the domain-verify resolver).
                RData::MX(mx) => Some(MxRecord {
                    preference: mx.preference,
                    // `Name` renders with a trailing dot (FQDN); strip it for a clean exchange host.
                    exchange: mx.exchange.to_string().trim_end_matches('.').to_string(),
                }),
                _ => None,
            })
            .collect();
        if records.is_empty() {
            return Err(DnsResolveError::NotFound);
        }
        records.sort_by_key(|r| r.preference);
        Ok(records)
    }

    async fn resolve_addr(&self, host: &str) -> Result<Vec<IpAddr>, DnsResolveError> {
        let host = host.trim();
        validate_name(host)?;
        let lookup = match self.inner.lookup_ip(host).await {
            Ok(l) => l,
            Err(e) if e.is_no_records_found() => return Err(DnsResolveError::NotFound),
            // COARSE reason (security-review LOW-1) — see `resolve_mx`.
            Err(e) => {
                tracing::debug!(error = %e, %host, "dns-resolve: addr lookup failed");
                return Err(DnsResolveError::Failed("addr lookup failed".to_string()));
            }
        };
        let addrs: Vec<IpAddr> = lookup.iter().collect();
        if addrs.is_empty() {
            return Err(DnsResolveError::NotFound);
        }
        Ok(addrs)
    }
}

/// A resolver that always fails to build (the `OnceLock` init saw a broken DNS environment). Returns
/// a COARSE `failed` for every call (the real build error is logged host-side at init — never echoed
/// to the guest, security-review LOW-1) rather than panicking a guest invocation.
struct UnavailableResolver;

#[async_trait::async_trait]
impl DnsResolver for UnavailableResolver {
    async fn resolve_mx(&self, _domain: &str) -> Result<Vec<MxRecord>, DnsResolveError> {
        Err(DnsResolveError::Failed(
            "dns resolver unavailable".to_string(),
        ))
    }
    async fn resolve_addr(&self, _host: &str) -> Result<Vec<IpAddr>, DnsResolveError> {
        Err(DnsResolveError::Failed(
            "dns resolver unavailable".to_string(),
        ))
    }
}

static SHARED: OnceLock<Arc<dyn DnsResolver>> = OnceLock::new();

/// The process-wide shared DNS resolver for the `dns-resolve` capability (built on first use, cached).
/// Must be called from within a Tokio runtime (every guest invocation is). A build failure yields an
/// [`UnavailableResolver`] (every resolve ⇒ `failed`) rather than an unwrap panic.
///
/// When an operator installed a DEV/TEST override ([`crate::dns_resolve_override`]) BEFORE first use,
/// the shared resolver serves its static answers first (and routes misses to the configured upstream).
/// With NO active override this is the plain system resolver — byte-for-byte the historical path.
pub fn shared_resolver() -> Arc<dyn DnsResolver> {
    SHARED
        .get_or_init(|| build_resolver(crate::dns_resolve_override::installed_override()))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_resolve_override::{DnsResolveOverrideConfig, StaticMx, StaticRecord};

    /// A delegate that MUST never be called — if a static hit ever touches it, the test panics. Proves
    /// the static answer is served without consulting any fallthrough (and therefore no network).
    struct ExplodingResolver;
    #[async_trait::async_trait]
    impl DnsResolver for ExplodingResolver {
        async fn resolve_mx(&self, _domain: &str) -> Result<Vec<MxRecord>, DnsResolveError> {
            panic!("fallthrough resolver was consulted for a static-map hit");
        }
        async fn resolve_addr(&self, _host: &str) -> Result<Vec<IpAddr>, DnsResolveError> {
            panic!("fallthrough resolver was consulted for a static-map hit");
        }
    }

    fn override_cfg() -> DnsResolveOverrideConfig {
        DnsResolveOverrideConfig {
            records: vec![
                StaticRecord {
                    name: "Example.COM.".into(), // mixed case + trailing dot → normalized on lookup
                    mx: vec![
                        StaticMx {
                            preference: 20,
                            exchange: "b.mx.example.com.".into(), // trailing dot stripped
                        },
                        StaticMx {
                            preference: 10,
                            exchange: "a.mx.example.com".into(),
                        },
                    ],
                    ..Default::default()
                },
                StaticRecord {
                    name: "a.mx.example.com".into(),
                    addrs: vec![
                        "93.184.216.34".parse().unwrap(),
                        "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
                    ],
                    ..Default::default()
                },
            ],
            upstream: None,
        }
    }

    /// HERMETIC (cap-req #21 was blocked on exactly this): a static override answers the consumer-lane
    /// resolve with the INJECTED records and NO fallthrough is ever consulted — so no system resolver,
    /// no `/etc/resolv.conf`, no network. `fallthrough = Some(ExplodingResolver)` turns any accidental
    /// delegation into a panic, and the assertions pin the exact injected answer (mutation-sensitive:
    /// drop the map lookup, return the wrong family, or skip the preference sort and it goes RED).
    #[tokio::test]
    async fn static_override_answers_offline_without_touching_the_network() {
        let resolver = StaticResolver::from_config(
            &override_cfg(),
            Some(Arc::new(ExplodingResolver) as Arc<dyn DnsResolver>),
        );

        // MX: case-insensitive + trailing-dot-insensitive match, sorted ascending by preference, with
        // the exchange's trailing dot stripped.
        let mx = resolver.resolve_mx("example.com").await.unwrap();
        assert_eq!(
            mx,
            vec![
                MxRecord {
                    preference: 10,
                    exchange: "a.mx.example.com".into(),
                },
                MxRecord {
                    preference: 20,
                    exchange: "b.mx.example.com".into(),
                },
            ],
        );

        // A/AAAA: the combined injected addresses come back verbatim.
        let addrs = resolver.resolve_addr("A.MX.Example.com.").await.unwrap();
        assert_eq!(
            addrs,
            vec![
                "93.184.216.34".parse::<IpAddr>().unwrap(),
                "2606:2800:220:1:248:1893:25c8:1946"
                    .parse::<IpAddr>()
                    .unwrap(),
            ],
        );
    }

    /// With no fallthrough the static map is AUTHORITATIVE: a name it does not cover is `not-found`
    /// (never a silent network lookup). Guards against a regression where a miss leaks to the system
    /// resolver in a build meant to be hermetic.
    #[tokio::test]
    async fn static_override_miss_is_not_found_when_authoritative() {
        let resolver = StaticResolver::from_config(&override_cfg(), None);
        assert!(matches!(
            resolver.resolve_mx("not-configured.test").await,
            Err(DnsResolveError::NotFound)
        ));
        assert!(matches!(
            resolver.resolve_addr("not-configured.test").await,
            Err(DnsResolveError::NotFound)
        ));
    }

    /// A static MISS delegates to the fallthrough (the additive-overlay posture an operator who sets
    /// only a couple of overrides on top of the real resolver relies on).
    #[tokio::test]
    async fn static_override_miss_delegates_to_fallthrough() {
        struct StubFallthrough;
        #[async_trait::async_trait]
        impl DnsResolver for StubFallthrough {
            async fn resolve_mx(&self, _domain: &str) -> Result<Vec<MxRecord>, DnsResolveError> {
                Ok(vec![MxRecord {
                    preference: 5,
                    exchange: "fallthrough.example".into(),
                }])
            }
            async fn resolve_addr(&self, _host: &str) -> Result<Vec<IpAddr>, DnsResolveError> {
                Ok(vec!["203.0.113.7".parse().unwrap()])
            }
        }
        let resolver = StaticResolver::from_config(
            &override_cfg(),
            Some(Arc::new(StubFallthrough) as Arc<dyn DnsResolver>),
        );
        let mx = resolver.resolve_mx("other.example").await.unwrap();
        assert_eq!(mx[0].exchange, "fallthrough.example");
        let addrs = resolver.resolve_addr("other.example").await.unwrap();
        assert_eq!(addrs, vec!["203.0.113.7".parse::<IpAddr>().unwrap()]);
    }

    /// `build_resolver(None)` is the DEFAULT path — a plain hickory system resolver, not a
    /// `StaticResolver`. (We can't assert the concrete type through `dyn`, but building it must
    /// succeed and the override module must report no active override by default.)
    #[tokio::test]
    async fn no_override_builds_the_default_resolver() {
        assert!(crate::dns_resolve_override::installed_override().is_none());
        let _resolver = build_resolver(None); // must not panic / must build
    }

    /// End-to-end: the PRODUCTION builder `build_resolver(Some(cfg))` wraps the static map over a real
    /// hickory fallthrough, and a configured name is still answered from the map (a map hit never
    /// queries the fallthrough, so this resolves offline even though the fallthrough is a live
    /// system/upstream resolver). Proves the whole config→resolver seam, not just the map in isolation.
    #[tokio::test]
    async fn build_resolver_with_override_serves_static_answer() {
        let resolver = build_resolver(Some(&override_cfg()));
        let mx = resolver.resolve_mx("example.com").await.unwrap();
        assert_eq!(mx.first().map(|r| r.preference), Some(10));
        assert_eq!(mx[0].exchange, "a.mx.example.com");
        let addrs = resolver.resolve_addr("a.mx.example.com").await.unwrap();
        assert!(addrs.contains(&"93.184.216.34".parse::<IpAddr>().unwrap()));
    }

    /// A custom upstream parses into a resolver (the `[handlers.dns_resolve_override].upstream` path).
    /// We only assert construction — querying it would need a live nameserver, which the static-map
    /// test deliberately avoids.
    #[tokio::test]
    async fn custom_upstream_builds() {
        HickoryDnsResolver::build_with_upstream("127.0.0.1:5353")
            .expect("a syntactically valid upstream builds");
        assert!(HickoryDnsResolver::build_with_upstream("not-a-socket-addr").is_err());
    }
}
