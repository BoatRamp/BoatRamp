//! The host-side DNS resolver binding (`boatramp:handlers/dns-resolve`, mailroom cap-req #20): the
//! DNS half of the egress story. `tcp-egress` (#15) dials a KNOWN host; this lets a guest FIND the
//! host to dial — a domain's MX records, or a hostname's addresses — without holding `wasi:sockets`
//! or running a resolver itself. The host resolves (with its own cache) via an injected
//! [`DnsResolver`] backend (the real one is hickory, server-side, so this crate stays resolver-free).
//!
//! # Egress-class, gated + SSRF-floored (the security model)
//! A resolver IS outbound surface, so it is gated by the SAME posture as `tcp-egress`
//! (`allow_guest_tcp_egress`, carried here as `posture_enabled`): posture off ⇒ `access-denied`,
//! exactly like a dial. Deny-by-default per grant (the binding is `None` when `dns-resolve` was not
//! conferred). Unlike `tcp-egress` there is NO per-target allowlist — direct-MX relay must resolve
//! ARBITRARY recipient domains — so the load-bearing guard is the posture + the grant + an SSRF floor
//! on RESOLVED ADDRESSES: [`resolve_addr`](DnsResolveHost::resolve_addr) drops every
//! non-globally-routable address (via [`boatramp_core::access::is_global_ip`]) unless the operator
//! also set `allow_private_egress`, so it can never be an oracle for the metadata endpoint / internal
//! ranges. `resolve_mx` returns public MX hostnames; the follow-on dial to an MX host is itself the
//! SSRF-floored `tcp-egress` connect.

use std::net::IpAddr;
use std::sync::Arc;

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/dns-resolve-host",
        imports: { default: async },
    });
}

use generated::boatramp::handlers::dns_resolve;

/// One resolved MX record (host-facing; the binding maps it to the WIT `mx-record`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    /// Delivery preference (lower is tried first).
    pub preference: u16,
    /// The mail-exchange host.
    pub exchange: String,
}

/// Why a resolve failed (host-facing; the binding maps it to the WIT `dns-error`). `AccessDenied` is
/// NOT here — that is decided by the binding (grant + posture), never by the resolver backend.
#[derive(Debug, Clone)]
pub enum DnsResolveError {
    /// The name was not a syntactically valid domain/host.
    InvalidName(String),
    /// No records of the requested type (NXDOMAIN / empty answer).
    NotFound,
    /// Any other resolver failure (timeout, SERVFAIL, …) — a client-safe reason.
    Failed(String),
}

/// The injected resolver backend. The host (boatramp-server) provides a hickory implementation with
/// its own positive/negative cache; this crate never depends on a resolver library.
#[async_trait::async_trait]
pub trait DnsResolver: Send + Sync {
    /// Resolve `domain`'s MX records, sorted by ascending preference (RFC 5321 delivery order).
    async fn resolve_mx(&self, domain: &str) -> Result<Vec<MxRecord>, DnsResolveError>;
    /// Resolve `host`'s A/AAAA addresses (the SSRF floor is applied by the binding, not here).
    async fn resolve_addr(&self, host: &str) -> Result<Vec<IpAddr>, DnsResolveError>;
}

/// The per-invocation `dns-resolve` grant: the server-provided resolver. `None` ⇒ not granted.
#[derive(Clone)]
pub struct DnsResolveBinding {
    resolver: Arc<dyn DnsResolver>,
}

impl DnsResolveBinding {
    /// Build the grant around a resolver backend.
    pub fn new(resolver: Arc<dyn DnsResolver>) -> Self {
        Self { resolver }
    }
}

/// The per-invocation host view of the `dns-resolve` capability. Carries the grant plus the egress
/// POSTURE (`posture_enabled`, the `allow_guest_tcp_egress` flag) and the SSRF posture
/// (`allow_private`) read from the invocation's `HostState` — exactly like `TcpEgressHost`.
pub struct DnsResolveHost<'a> {
    binding: Option<&'a DnsResolveBinding>,
    posture_enabled: bool,
    allow_private: bool,
}

impl<'a> DnsResolveHost<'a> {
    pub fn new(
        binding: Option<&'a DnsResolveBinding>,
        posture_enabled: bool,
        allow_private: bool,
    ) -> Self {
        Self {
            binding,
            posture_enabled,
            allow_private,
        }
    }

    /// Enforce the capability: the grant must be present AND the egress posture on. Deny-by-default,
    /// fail-closed (posture off ⇒ denied, like a `tcp-egress` dial).
    fn admit(&self) -> Result<Arc<dyn DnsResolver>, dns_resolve::DnsError> {
        match self.binding {
            Some(b) if self.posture_enabled => Ok(b.resolver.clone()),
            _ => Err(dns_resolve::DnsError::AccessDenied),
        }
    }
}

/// Map the host-facing resolver error to the guest-visible wire error.
fn map_error(err: DnsResolveError) -> dns_resolve::DnsError {
    match err {
        DnsResolveError::InvalidName(m) => dns_resolve::DnsError::InvalidName(m),
        DnsResolveError::NotFound => dns_resolve::DnsError::NotFound,
        DnsResolveError::Failed(m) => dns_resolve::DnsError::Failed(m),
    }
}

impl dns_resolve::Host for DnsResolveHost<'_> {
    async fn resolve_mx(
        &mut self,
        domain: String,
    ) -> Result<Vec<dns_resolve::MxRecord>, dns_resolve::DnsError> {
        let resolver = self.admit()?;
        let mut records = resolver.resolve_mx(&domain).await.map_err(map_error)?;
        // Defensive: present in ascending-preference order even if a backend returned them unsorted.
        records.sort_by_key(|r| r.preference);
        Ok(records
            .into_iter()
            .map(|r| dns_resolve::MxRecord {
                preference: r.preference,
                exchange: r.exchange,
            })
            .collect())
    }

    async fn resolve_addr(&mut self, host: String) -> Result<Vec<String>, dns_resolve::DnsError> {
        let resolver = self.admit()?;
        let addrs = resolver.resolve_addr(&host).await.map_err(map_error)?;
        // SSRF floor: drop every non-globally-routable address unless the operator opted into private
        // egress. An all-private answer is `not-found` (never leak an internal target to the guest).
        let allow_private = self.allow_private;
        let kept: Vec<String> = addrs
            .into_iter()
            .filter(|ip| allow_private || boatramp_core::access::is_global_ip(*ip))
            .map(|ip| ip.to_string())
            .collect();
        if kept.is_empty() {
            return Err(dns_resolve::DnsError::NotFound);
        }
        Ok(kept)
    }
}

/// Add the `dns-resolve` interface to `linker`, resolving the per-invocation [`DnsResolveHost`] view
/// via `host`.
struct LinkData;
impl wasmtime::component::HasData for LinkData {
    type Data<'a> = DnsResolveHost<'a>;
}

pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: fn(&mut T) -> DnsResolveHost<'_>,
) -> wasmtime::Result<()> {
    dns_resolve::add_to_linker::<T, LinkData>(linker, host)
}

#[cfg(test)]
mod tests {
    use super::dns_resolve::Host;
    use super::*;

    struct StubResolver {
        mx: Vec<MxRecord>,
        addrs: Vec<IpAddr>,
    }

    #[async_trait::async_trait]
    impl DnsResolver for StubResolver {
        async fn resolve_mx(&self, _domain: &str) -> Result<Vec<MxRecord>, DnsResolveError> {
            Ok(self.mx.clone())
        }
        async fn resolve_addr(&self, _host: &str) -> Result<Vec<IpAddr>, DnsResolveError> {
            Ok(self.addrs.clone())
        }
    }

    fn binding(mx: Vec<MxRecord>, addrs: Vec<IpAddr>) -> DnsResolveBinding {
        DnsResolveBinding::new(Arc::new(StubResolver { mx, addrs }))
    }

    #[tokio::test]
    async fn ungranted_is_access_denied() {
        let mut host = DnsResolveHost::new(None, true, false);
        assert!(matches!(
            host.resolve_mx("example.com".into()).await,
            Err(dns_resolve::DnsError::AccessDenied)
        ));
        assert!(matches!(
            host.resolve_addr("example.com".into()).await,
            Err(dns_resolve::DnsError::AccessDenied)
        ));
    }

    #[tokio::test]
    async fn posture_off_is_access_denied_even_when_granted() {
        let b = binding(vec![], vec!["93.184.216.34".parse().unwrap()]);
        // granted (Some) but posture OFF ⇒ denied, fail-closed (resolution is egress-class).
        let mut host = DnsResolveHost::new(Some(&b), false, false);
        assert!(matches!(
            host.resolve_addr("example.com".into()).await,
            Err(dns_resolve::DnsError::AccessDenied)
        ));
    }

    #[tokio::test]
    async fn mx_is_sorted_by_preference() {
        let b = binding(
            vec![
                MxRecord {
                    preference: 20,
                    exchange: "b.mx.example.com".into(),
                },
                MxRecord {
                    preference: 10,
                    exchange: "a.mx.example.com".into(),
                },
            ],
            vec![],
        );
        let mut host = DnsResolveHost::new(Some(&b), true, false);
        let got = host.resolve_mx("example.com".into()).await.unwrap();
        assert_eq!(got[0].preference, 10, "lowest preference first");
        assert_eq!(got[1].preference, 20);
    }

    #[tokio::test]
    async fn resolve_addr_ssrf_floor_drops_private() {
        // A mix of a global and a private address; with allow_private=false only the global survives.
        let b = binding(
            vec![],
            vec![
                "93.184.216.34".parse().unwrap(),
                "10.0.0.5".parse().unwrap(),
            ],
        );
        let mut host = DnsResolveHost::new(Some(&b), true, false);
        let got = host.resolve_addr("example.com".into()).await.unwrap();
        assert_eq!(
            got,
            vec!["93.184.216.34".to_string()],
            "private address dropped"
        );
    }

    #[tokio::test]
    async fn resolve_addr_all_private_is_not_found() {
        let b = binding(
            vec![],
            vec!["127.0.0.1".parse().unwrap(), "10.0.0.5".parse().unwrap()],
        );
        let mut host = DnsResolveHost::new(Some(&b), true, false);
        assert!(
            matches!(
                host.resolve_addr("evil.internal".into()).await,
                Err(dns_resolve::DnsError::NotFound)
            ),
            "an all-private answer must be not-found, never leaked"
        );
    }

    #[tokio::test]
    async fn resolve_addr_allow_private_keeps_private() {
        let b = binding(vec![], vec!["10.0.0.5".parse().unwrap()]);
        // allow_private=true (operator opted in) ⇒ the private address is kept.
        let mut host = DnsResolveHost::new(Some(&b), true, true);
        let got = host.resolve_addr("db.internal".into()).await.unwrap();
        assert_eq!(got, vec!["10.0.0.5".to_string()]);
    }
}
