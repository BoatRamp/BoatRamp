//! The hickory-backed [`DnsResolver`] for the guest-facing `dns-resolve` capability (mailroom cap-req
//! #20). Lives server-side because hickory-resolver is a boatramp-server dependency (boatramp-handlers
//! stays resolver-free — it only defines the trait + the SSRF-floored binding). The resolver, with its
//! own positive/negative cache, is built ONCE process-wide (a `OnceLock`) and shared by every guest
//! invocation that is granted `dns-resolve` — DNS is global, so one cached resolver is correct.
//!
//! The SSRF floor on resolved ADDRESSES is NOT here — it is applied in the handlers-side binding
//! ([`boatramp_handlers::DnsResolveHost::resolve_addr`]) against the invocation's `allow_private_egress`
//! posture, so the one SSRF predicate (`is_global_ip`) governs both this and `tcp-egress`.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use boatramp_handlers::{DnsResolveError, DnsResolver, MxRecord};

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
pub fn shared_resolver() -> Arc<dyn DnsResolver> {
    SHARED
        .get_or_init(|| match HickoryDnsResolver::build() {
            Ok(r) => Arc::new(r),
            Err(e) => {
                tracing::error!(error = %e, "dns-resolve: failed to build the shared DNS resolver");
                Arc::new(UnavailableResolver)
            }
        })
        .clone()
}
