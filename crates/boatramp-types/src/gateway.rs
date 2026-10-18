//! Gateway: publishing a private/internal HTTP service through the edge.
//! The operator declares the backends boatramp may reach
//! (`upstreams`) and the routes that forward to them; a *declared upstream* is
//! the trust boundary that authorizes reaching a private address (the SSRF
//! guard stays public-only for everything else).
//!
//! This module is the wasm-clean config model + the pure route resolver and
//! path-rewrite logic; the streaming proxy that uses it lives in the server.

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::matcher::Pattern;

/// Site-scoped gateway configuration (off by default). Lives in `SiteConfig`
/// (the operator tier), not the deploy bundle — declaring an internal target is
/// an operator decision.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewayConfig {
    /// Declared backends, by name. Only addresses reachable *through* one of
    /// these may be private.
    pub upstreams: BTreeMap<String, Upstream>,
    /// Path routes; the first match forwards to its named upstream.
    pub routes: Vec<GatewayRoute>,
    /// **Site tier only:** path globs that a *project*-declared route may never shadow or capture
    /// (e.g. `/.well-known/**`, an auth-callback path). Enforced structurally when the two tiers'
    /// routes are merged ([`resolve_gateway`]) — a project route whose match falls under a reserved
    /// glob is skipped at serve, so even a bypassed declare-time check cannot let a tenant hijack a
    /// reserved path. Empty ⇒ nothing reserved (unchanged single-tier behavior).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reserved_paths: Vec<String>,
}

impl GatewayConfig {
    /// Whether any route is declared (the serving path skips the gateway stage
    /// otherwise).
    pub fn is_enabled(&self) -> bool {
        !self.routes.is_empty()
    }

    /// No upstreams and no routes — used by the project-tier `DeployConfig.gateway` skip-serializer
    /// so an unused gateway never lands in the (content-addressed) manifest.
    pub fn is_empty(&self) -> bool {
        self.upstreams.is_empty() && self.routes.is_empty()
    }

    /// The first route whose pattern matches `path` (patterns are cached by
    /// [`Pattern::compile`]).
    pub fn match_route(&self, path: &str) -> Option<&GatewayRoute> {
        self.routes.iter().find(|route| {
            Pattern::compile(&route.matches)
                .map(|pattern| pattern.is_match(path))
                .unwrap_or(false)
        })
    }
}

/// The **site operator's** ceilings on what the PROJECT gateway tier (`project.cfg`) may declare under
/// this site (two-tier gateway / cap-req 0.37.0). The site operator sets these on `SiteConfig`
/// (`Site·Write`); they bound the app author beneath the site, intersected with the global admin's
/// node-absolute [`SecurityPosture::gateway_egress_allow`](crate::security::SecurityPosture). A tier may
/// only NARROW within the tier above it. All-unset (the default) ⇒ no site-level ceiling (the IP bright
/// line + any node allowlist still apply).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewaySiteCaps {
    /// Max number of project-declared gateway upstreams. `None` ⇒ unbounded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_project_upstreams: Option<usize>,
    /// Max backends (pooled `targets` fan-out) a single project upstream may declare. `None` ⇒
    /// unbounded. Bounds a project fanning one upstream across many backends.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_backends: Option<usize>,
    /// Host globs a project **raw-target** upstream may reach (a project own-compute workload and a
    /// shared-site grant are exempt — their reach is already vouched for). Empty ⇒ no site-level host
    /// narrowing (only the public-only IP bright line applies). Matched case-insensitively; `*` matches
    /// one DNS label, `**` any suffix. The global-admin posture allowlist narrows this further.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub project_egress_hosts: Vec<String>,
}

impl GatewaySiteCaps {
    /// No ceiling set — the default (skip-serialized so an unused caps block never lands in config).
    pub fn is_empty(&self) -> bool {
        self.max_project_upstreams.is_none()
            && self.max_backends.is_none()
            && self.project_egress_hosts.is_empty()
    }
}

/// Whether `host` matches a gateway egress-host glob (case-insensitive): an exact host, a `*.suffix`
/// single-label wildcard, or `**.suffix` / a bare `**` any-suffix wildcard. Used by BOTH the
/// site-operator `project_egress_hosts` and the node-absolute posture allowlist — a project raw target
/// is permitted only if its host matches at least one glob in a non-empty allowlist.
pub fn gateway_host_matches(glob: &str, host: &str) -> bool {
    let glob = glob.trim().to_ascii_lowercase();
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if glob == "**" {
        return !host.is_empty();
    }
    if let Some(suffix) = glob.strip_prefix("**.") {
        // Any-depth suffix: `**.example.com` matches `example.com` and `a.b.example.com`.
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    if let Some(suffix) = glob.strip_prefix("*.") {
        // Single-label: `*.example.com` matches `api.example.com`, not `a.b.example.com` or the apex.
        return match host.strip_suffix(&format!(".{suffix}")) {
            Some(label) => !label.is_empty() && !label.contains('.'),
            None => false,
        };
    }
    glob == host
}

/// Whether `host` is permitted by an egress-host allowlist: an empty allowlist means "no narrowing"
/// (permitted), else `host` must match at least one glob.
pub fn gateway_host_allowed(allowlist: &[String], host: &str) -> bool {
    allowlist.is_empty() || allowlist.iter().any(|g| gateway_host_matches(g, host))
}

/// The **authoritative serve-time** egress check for a PROJECT raw-target gateway upstream (two-tier
/// gateway / 0.37.0): EVERY literal target host must satisfy BOTH the site operator's
/// `project_egress_hosts` and the global admin's node `gateway_egress_allow` (each empty ⇒ no
/// narrowing). A site operator may only narrow within the node floor, never past it — so a host must
/// clear both. Called only for a `ProjectRaw`-policy match (own-compute + shared grants are exempt —
/// their reach is vouched for by the tier that holds it). The IP bright line
/// ([`crate::security`]-independent, in the proxy) is layered on top of this.
pub fn project_raw_egress_allowed(
    up: &Upstream,
    site_allow: &[String],
    node_allow: &[String],
) -> bool {
    upstream_literal_hosts(up)
        .iter()
        .all(|h| gateway_host_allowed(site_allow, h) && gateway_host_allowed(node_allow, h))
}

/// Which tier owns a resolved gateway match — and therefore which target-space rule binds it at
/// serve time (the project tier may only reach its own compute + public hosts; the operator tier
/// authorizes private reach).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GatewayTier {
    /// A site/operator-declared route — OR a project route that referenced a `shared` site upstream
    /// (the reach was authorized by the operator, so the operator address policy applies).
    Operator,
    /// A project/app-author-declared route to a project-declared upstream (own compute / public).
    Project,
}

/// A resolved route match in the merged (project ∪ referenced-site) namespace.
pub struct GatewayMatch<'a> {
    /// Which tier's authority governs this match (operator routes win on a tie).
    pub tier: GatewayTier,
    /// The matched route's upstream name (for runtime state keying + dispatch).
    pub upstream_name: &'a str,
    /// The resolved upstream. For a reference this is the **site** struct — the project never gets a
    /// copy, so its target/host/TLS/creds stay opaque (RESTRICTION 3).
    pub upstream: &'a Upstream,
    /// True when a project route resolved to a `shared` site upstream (a reference, not a project
    /// upstream).
    pub via_reference: bool,
}

/// The outcome of resolving a request path against the two-tier gateway.
pub enum GatewayResolution<'a> {
    /// No gateway route matched — fall through to the rest of the serve pipeline (static/handlers).
    NoMatch,
    /// A route matched but its named upstream did not resolve (unknown name, or a project route
    /// naming a non-`shared` site upstream) — a config error; the caller returns `502`. Preserves the
    /// existing operator behavior for a dangling route.
    UnknownUpstream {
        /// The tier whose route matched.
        tier: GatewayTier,
        /// The unresolved upstream name.
        name: String,
    },
    /// A route matched and its upstream resolved.
    Matched(GatewayMatch<'a>),
}

/// Resolve `path` against the merged project+site gateway with **operator precedence** (RESTRICTION
/// 2), the **reserved-path hijack guard** (RESTRICTION 2), and **reference opacity** (RESTRICTION 3).
///
/// Order:
/// 1. **Operator routes first.** A matching `site` route wins (operator may serve any path, incl. a
///    reserved one — the operator owns it). Its upstream resolves against `site.upstreams`.
/// 2. **Reserved paths bar the project tier.** If no operator route matched and `path` falls under any
///    `site.reserved_paths` glob, the project tier may not serve it → `NoMatch` (falls through to
///    normal serving; a tenant route can never capture a reserved path).
/// 3. **Project routes.** The first matching `project` route resolves its upstream name in the merged
///    namespace: a `project`-declared upstream (→ [`GatewayTier::Project`]) first, else a `shared`
///    `site` upstream (→ a reference: [`GatewayTier::Operator`], `via_reference = true`, the site
///    struct returned opaquely). A name that is neither ⇒ `UnknownUpstream` (deny-by-default).
pub fn resolve_gateway<'a>(
    project: Option<&'a GatewayConfig>,
    site: Option<&'a GatewayConfig>,
    path: &str,
) -> GatewayResolution<'a> {
    // 1. Operator routes take precedence.
    if let Some(site) = site
        && let Some(route) = site.match_route(path)
    {
        return match site.upstreams.get(&route.upstream) {
            Some(up) => GatewayResolution::Matched(GatewayMatch {
                tier: GatewayTier::Operator,
                upstream_name: &route.upstream,
                upstream: up,
                via_reference: false,
            }),
            None => GatewayResolution::UnknownUpstream {
                tier: GatewayTier::Operator,
                name: route.upstream.clone(),
            },
        };
    }

    let Some(project) = project else {
        return GatewayResolution::NoMatch;
    };

    // 2. A reserved path is never served by a project route (operator territory) — structural, so a
    //    bypassed declare-time check still cannot let a tenant capture it.
    if let Some(site) = site
        && site.reserved_paths.iter().any(|r| {
            Pattern::compile(r)
                .map(|p| p.is_match(path))
                .unwrap_or(false)
        })
    {
        return GatewayResolution::NoMatch;
    }

    // 3. Project routes, resolved in the merged namespace.
    if let Some(route) = project.match_route(path) {
        if let Some(up) = project.upstreams.get(&route.upstream) {
            return GatewayResolution::Matched(GatewayMatch {
                tier: GatewayTier::Project,
                upstream_name: &route.upstream,
                upstream: up,
                via_reference: false,
            });
        }
        if let Some(site) = site
            && let Some(up) = site.upstreams.get(&route.upstream)
            && up.shared
        {
            // A reference: the reach was granted by the operator, so the operator policy governs,
            // and the project sees only the name (the returned `upstream` is the site struct).
            return GatewayResolution::Matched(GatewayMatch {
                tier: GatewayTier::Operator,
                upstream_name: &route.upstream,
                upstream: up,
                via_reference: true,
            });
        }
        return GatewayResolution::UnknownUpstream {
            tier: GatewayTier::Project,
            name: route.upstream.clone(),
        };
    }

    GatewayResolution::NoMatch
}

/// Validate a **site/operator** gateway: every route references a declared upstream, and every route
/// pattern + reserved-path glob compiles. (The private-upstream trust decision is the operator's to
/// make, bounded by the node posture at serve — not refused here.)
pub fn validate_site_gateway(site: &GatewayConfig) -> Result<(), crate::ConfigError> {
    for route in &site.routes {
        Pattern::compile(&route.matches)?;
        if !site.upstreams.contains_key(&route.upstream) {
            return Err(crate::ConfigError::parse(format!(
                "site gateway route `{}` references unknown upstream `{}`",
                route.matches, route.upstream
            )));
        }
    }
    for reserved in &site.reserved_paths {
        Pattern::compile(reserved)?;
    }
    Ok(())
}

/// Validate a **project/app-author** gateway against the invariant *a tier may only declare reach it
/// holds*. `site` (the operator gateway, if any) is consulted for `shared`-grant resolution.
///
/// Refuses: a project upstream marked `shared` (a project cannot grant); a project upstream whose
/// literal target host is a private/loopback/internal/metadata address (RESTRICTION 1 — DNS names
/// are allowed here and bounded at serve); a route referencing neither a project upstream nor a
/// `shared` site upstream (deny-by-default); and a project upstream name that collides with a shared
/// site upstream (ambiguous — fork 5, reject).
pub fn validate_project_gateway(
    project: &GatewayConfig,
    site: Option<&GatewayConfig>,
    caps: Option<&GatewaySiteCaps>,
) -> Result<(), crate::ConfigError> {
    // Site-operator ceilings (two-tier gateway / 0.37.0): count caps + the raw-target egress-host
    // allowlist. Only enforceable with the SiteConfig in hand (the apply/serve path); standalone deploy
    // validation (`caps = None`) defers to the apply + the authoritative serve-time check.
    if let Some(caps) = caps {
        if let Some(max) = caps.max_project_upstreams
            && project.upstreams.len() > max
        {
            return Err(crate::ConfigError::parse(format!(
                "project gateway declares {} upstreams, over the site ceiling of {max} \
                 (GatewaySiteCaps.max_project_upstreams)",
                project.upstreams.len()
            )));
        }
        if let Some(max) = caps.max_backends {
            for (name, up) in &project.upstreams {
                let backends = upstream_backend_count(up);
                if backends > max {
                    return Err(crate::ConfigError::parse(format!(
                        "project gateway upstream `{name}` declares {backends} backends, over the \
                         site ceiling of {max} (GatewaySiteCaps.max_backends)"
                    )));
                }
            }
        }
    }
    for (name, up) in &project.upstreams {
        if up.shared {
            return Err(crate::ConfigError::parse(format!(
                "project gateway upstream `{name}` sets `shared` — only a site/operator upstream may \
                 be a referenceable grant (a project cannot grant reach it does not hold)"
            )));
        }
        // Collision with a shared site upstream (ambiguous) — only checkable when the site config is
        // in hand (the CLI/serve path); standalone deploy validation has no SiteConfig.
        if site.is_some_and(|s| s.upstreams.get(name).is_some_and(|u| u.shared)) {
            return Err(crate::ConfigError::parse(format!(
                "project gateway upstream `{name}` collides with a shared site upstream of the same \
                 name — rename the project upstream, or drop it to reference the site grant"
            )));
        }
        // RESTRICTION 1 (declare-time fail-fast): a compute-by-name upstream is own-compute (allowed);
        // otherwise a literal private/internal host is refused. A DNS name passes here and is bounded
        // by the project-tier address gate at serve.
        if up.compute.is_none() {
            let egress = caps
                .map(|c| c.project_egress_hosts.as_slice())
                .unwrap_or(&[]);
            for host in upstream_literal_hosts(up) {
                if host_is_literal_private(&host) {
                    return Err(crate::ConfigError::parse(format!(
                        "project gateway upstream `{name}` targets a private/internal address \
                         `{host}` — the project tier may only reach its own compute, a public host, \
                         or a shared site upstream; declare the private backend as a site upstream \
                         and mark it `shared`"
                    )));
                }
                // Site egress-host allowlist (0.37.0): when the site operator sets one, a project
                // raw-target host must match it. A DNS name is screened here against the glob list;
                // the resolved IP + the node-absolute posture allowlist are the authoritative serve-
                // time check. Empty allowlist ⇒ no narrowing.
                if !gateway_host_allowed(egress, &host) {
                    return Err(crate::ConfigError::parse(format!(
                        "project gateway upstream `{name}` targets host `{host}`, which the site's \
                         GatewaySiteCaps.project_egress_hosts allowlist does not permit"
                    )));
                }
            }
        }
    }
    for route in &project.routes {
        Pattern::compile(&route.matches)?;
        let in_project = project.upstreams.contains_key(&route.upstream);
        // The route→upstream existence check needs the SiteConfig to resolve a `shared` reference, so
        // it only fires when `site` is in hand (CLI/serve). Standalone deploy validation (`site =
        // None`) leaves a name not declared in the project to be resolved — and denied-by-default if
        // ungranted — at serve (`resolve_gateway` → `UnknownUpstream`).
        if let Some(s) = site {
            let in_shared_site = s.upstreams.get(&route.upstream).is_some_and(|u| u.shared);
            if !in_project && !in_shared_site {
                return Err(crate::ConfigError::parse(format!(
                    "project gateway route `{}` references upstream `{}`, which is neither a project \
                     upstream nor a shared site upstream",
                    route.matches, route.upstream
                )));
            }
        }
    }
    Ok(())
}

/// How many backends an upstream declares (for the site `max_backends` fan-out cap): the pooled
/// `targets`, else 1 for a single `target`, else 0 (a compute-by-name upstream resolves its pool
/// dynamically from the workload's replicas — it declares none, so it is never capped here).
fn upstream_backend_count(up: &Upstream) -> usize {
    if !up.targets.is_empty() {
        up.targets.len()
    } else if !up.target.trim().is_empty() {
        1
    } else {
        0
    }
}

/// The literal target hosts of an upstream (its `target`, pooled `targets`, and `discover.host`), for
/// the declare-time private-address screen.
fn upstream_literal_hosts(up: &Upstream) -> Vec<String> {
    let mut hosts = Vec::new();
    if !up.target.trim().is_empty()
        && let Some(h) = extract_host(&up.target)
    {
        hosts.push(h);
    }
    for t in &up.targets {
        if let Some(h) = extract_host(t) {
            hosts.push(h);
        }
    }
    if let Some(d) = &up.discover
        && let Some(h) = extract_host(&d.host)
    {
        hosts.push(h);
    }
    hosts
}

/// Extract the host of an upstream target: `scheme://[user@]host[:port][/path]`, `host:port`, a bare
/// host, or a bracketed IPv6 literal. `None` when empty.
fn extract_host(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let after_scheme = match s.find("://") {
        Some(i) => &s[i + 3..],
        None => s,
    };
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal: `[::1]:port`.
        if let Some(end) = rest.find(']') {
            return Some(rest[..end].to_string());
        }
    }
    let host = authority.split(':').next().unwrap_or(authority);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Whether `host` parses as a non-public IP literal (private/loopback/link-local/ULA/unspecified/
/// CGNAT/metadata). A DNS name (not an IP literal) returns `false` — allowed at declare, bounded at
/// serve. This is the declare-time fail-fast screen; the serve-time address gate is authoritative.
fn host_is_literal_private(host: &str) -> bool {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => !ip_is_public(ip),
        Err(_) => false,
    }
}

fn ip_is_public(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || o[0] == 0
                // CGNAT 100.64.0.0/10
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40))
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                // ULA fc00::/7
                || (seg[0] & 0xfe00) == 0xfc00
                // link-local fe80::/10
                || (seg[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// A declared backend. `target` is `scheme://host:port[/base-path]`; the host
/// may be a private IP or internal name (that is what the declaration
/// authorizes). The cloud-metadata address is refused even here.
///
/// An upstream may name **one** backend (`target`) or a **pool** (`targets`)
/// load-balanced with health-based ejection + retry; with
/// `discover` set, the pool is filled from DNS.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Upstream {
    /// A single backend `http(s)://host:port[/base]`. Used when `targets` is
    /// empty and `discover` is unset (the common one-backend case).
    pub target: String,
    /// A pool of backends (G5). When non-empty, supersedes `target`; requests are
    /// load-balanced across the pool with per-backend health ejection.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// Load-balancing policy across the pool (G5). Default round-robin.
    #[serde(skip_serializing_if = "LbPolicy::is_default")]
    pub lb: LbPolicy,
    /// Per-backend region tags (backend URL → region) for [`LbPolicy::Nearest`]
    /// (FA-8). An untagged backend is region-neutral. Keys match the pool entries
    /// (static `targets`, or a DNS/compute-resolved endpoint URL).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub regions: BTreeMap<String, crate::geo::Region>,
    /// Operator region-distance table for [`LbPolicy::Nearest`] (FA-8). Default =
    /// binary nearness (same region `0`, any other far).
    #[serde(skip_serializing_if = "crate::geo::RegionMap::is_empty")]
    pub region_map: crate::geo::RegionMap,
    /// Request header carrying the client's region (e.g. `fly-region`,
    /// `cf-ipcountry`, `x-boatramp-client-region`) for [`LbPolicy::Nearest`]
    /// (FA-8). `None` ⇒ no client region, so Nearest degrades to health-first +
    /// original order (never a hard failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_region_header: Option<String>,
    /// Extra backends to try when an attempt fails to *connect* (G5). `0` = no
    /// retry (the request fails on the first backend's connect error). Capped at
    /// the pool size at run time. Only connect failures retry — a backend that
    /// answered (even 5xx) is not retried, since the request body is spent.
    #[serde(skip_serializing_if = "is_zero")]
    pub max_retries: u32,
    /// Passive health: eject a backend from the pool after this many consecutive
    /// failures, for `fail_timeout_ms` (G5). `None` = never eject (every backend
    /// is always a candidate).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passive_health: Option<PassiveHealth>,
    /// Active health: probe each backend out-of-band on a timer and take an
    /// unhealthy one out of rotation before any client traffic hits it (G5).
    /// `None` = no probing (only passive ejection, if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_health: Option<ActiveHealth>,
    /// Discover the pool from DNS instead of a static list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discover: Option<Discovery>,
    /// Resolve the pool **live from a compute workload's healthy replicas**:
    /// set to a workload name and the gateway routes
    /// to that workload's current replica endpoints, superseding `target`/
    /// `targets`/`discover`. The replicas are managed by the reconcile loop.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compute: Option<String>,
    /// Override the `Host` header sent upstream (many internal apps vhost).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_header: Option<String>,
    /// Strip this path prefix before forwarding (publish `/app/*` → upstream `/`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strip_prefix: Option<String>,
    /// Connect timeout (ms). `None` → reqwest default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,
    /// Overall request timeout (ms). `None` → no deadline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_timeout_ms: Option<u64>,
    /// Accept a self-signed / invalid upstream TLS cert (opt-in, logged loudly).
    #[serde(skip_serializing_if = "is_false")]
    pub tls_insecure: bool,
    /// Cap the per-connection upstream H1 read buffer, in bytes. Each upstream
    /// connection retains one, so at proxy fan-out this is the dominant memory
    /// term, traded against read-syscall overhead. `None` → the 32 KiB default
    /// (a good balance for typical API/CDN responses). Raise it for large responses
    /// at low concurrency (fewer, larger reads); lower it for very high fan-out on a
    /// memory-tight node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_buffer_bytes: Option<u64>,
    /// Header rewrites applied to the request before forwarding.
    #[serde(skip_serializing_if = "HeaderOps::is_empty")]
    pub header_up: HeaderOps,
    /// Header rewrites applied to the response before returning it.
    #[serde(skip_serializing_if = "HeaderOps::is_empty")]
    pub header_down: HeaderOps,
    /// **Site tier only:** expose this upstream's *name* as a referenceable grant into the project
    /// namespace, so a project route/upstream may forward to it by name. The project sees ONLY the
    /// name — never the target / host_header / TLS / credentials (reference opacity, like a secret
    /// reference hides the backend value). Must be `false` on a project-declared upstream (a project
    /// cannot grant reach it does not hold); validated at declare time.
    #[serde(default, skip_serializing_if = "is_false")]
    pub shared: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// Load-balancing policy across a backend pool (G5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LbPolicy {
    /// Pick the next backend in rotation (the default).
    #[default]
    RoundRobin,
    /// Pick a pseudo-random backend per request.
    Random,
    /// Route to the **nearest healthy** backend by region (FA-8): order the pool
    /// health-first, then by ascending distance from the client's region
    /// (`client_region_header`) to each backend's region (`regions` +
    /// `region_map`). Falls back to health-first order when no client region is
    /// known. Needs region tags to be meaningful; untagged backends are neutral.
    Nearest,
}

impl LbPolicy {
    fn is_default(&self) -> bool {
        matches!(self, Self::RoundRobin)
    }
}

/// Passive health-check policy: eject a failing backend for a cooldown (G5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PassiveHealth {
    /// Consecutive failures before a backend is ejected from the pool.
    pub max_fails: u32,
    /// How long an ejected backend stays out (ms) before it is retried.
    pub fail_timeout_ms: u64,
}

impl Default for PassiveHealth {
    fn default() -> Self {
        Self {
            max_fails: 3,
            fail_timeout_ms: 10_000,
        }
    }
}

/// Active health-check policy: probe each backend on a timer and take an
/// unhealthy one out of rotation proactively (G5). Complements passive ejection
/// — active probing catches a dead (or recovered) backend before client traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ActiveHealth {
    /// Probe path (a `GET` against each backend), e.g. `/healthz`.
    pub path: String,
    /// How often to probe each backend (ms).
    pub interval_ms: u64,
    /// Per-probe timeout (ms).
    pub timeout_ms: u64,
    /// Consecutive successful probes before a down backend is marked up again.
    pub healthy_threshold: u32,
    /// Consecutive failed probes before a backend is taken out of rotation.
    pub unhealthy_threshold: u32,
    /// The HTTP status a healthy probe must return.
    pub expected_status: u16,
}

impl Default for ActiveHealth {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            interval_ms: 10_000,
            timeout_ms: 2_000,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            expected_status: 200,
        }
    }
}

/// Discover an upstream's backend pool from DNS (G6): resolve `host` to its A/
/// AAAA records and form `scheme://<addr>:<port>` backends, refreshed every
/// `refresh_secs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Discovery {
    /// Hostname to resolve (its A/AAAA records become the pool).
    pub host: String,
    /// Port every resolved backend is reached on.
    pub port: u16,
    /// `http` or `https` for the resolved backends.
    pub scheme: String,
    /// Re-resolve at most this often (seconds).
    pub refresh_secs: u64,
}

impl Default for Discovery {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 0,
            scheme: "http".to_string(),
            refresh_secs: 30,
        }
    }
}

impl Upstream {
    /// The static backend list: the `targets` pool if non-empty, else the single
    /// `target` if set, else empty. (DNS-discovered backends are resolved
    /// separately by the serving layer; see `discover`.)
    pub fn static_backends(&self) -> Vec<&str> {
        if !self.targets.is_empty() {
            self.targets.iter().map(String::as_str).collect()
        } else if !self.target.is_empty() {
            vec![self.target.as_str()]
        } else {
            Vec::new()
        }
    }

    /// The path to forward upstream: `request_path` with `strip_prefix` removed
    /// when it matches on a path-segment boundary. Always begins with `/`.
    pub fn forward_path<'a>(&self, request_path: &'a str) -> Cow<'a, str> {
        let Some(prefix) = self.strip_prefix.as_deref() else {
            return Cow::Borrowed(request_path);
        };
        let prefix = prefix.trim_end_matches('/');
        if prefix.is_empty() {
            return Cow::Borrowed(request_path);
        }
        match request_path.strip_prefix(prefix) {
            // Exact prefix (`/app` on `/app`) → root.
            Some("") => Cow::Borrowed("/"),
            // Segment boundary (`/app` on `/app/x`) → the remainder.
            Some(rest) if rest.starts_with('/') => Cow::Borrowed(rest),
            // Partial-segment (`/app` on `/application`) → don't strip.
            _ => Cow::Borrowed(request_path),
        }
    }
}

/// Add/set + remove operations on a header set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HeaderOps {
    /// Insert/overwrite these headers (name → value).
    pub set: BTreeMap<String, String>,
    /// Remove these header names.
    pub remove: Vec<String>,
}

impl HeaderOps {
    /// Whether no operations are configured.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty() && self.remove.is_empty()
    }
}

/// A path route forwarding to a named upstream. Unlike the SPA-fallback rewrite,
/// a gateway route wins over static files (the operator declared it).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayRoute {
    /// Path glob ([`Pattern`]), like a rewrite `source`.
    #[serde(rename = "match")]
    pub matches: String,
    /// The upstream name in [`GatewayConfig::upstreams`].
    pub upstream: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(target: &str, strip: Option<&str>) -> Upstream {
        Upstream {
            target: target.to_string(),
            strip_prefix: strip.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn match_route_first_wins() {
        let cfg = GatewayConfig {
            upstreams: BTreeMap::from([
                ("api".to_string(), upstream("http://10.0.0.5:8080", None)),
                ("app".to_string(), upstream("http://10.0.0.6:3000", None)),
            ]),
            routes: vec![
                GatewayRoute {
                    matches: "/api/**".into(),
                    upstream: "api".into(),
                },
                GatewayRoute {
                    matches: "/**".into(),
                    upstream: "app".into(),
                },
            ],
            ..Default::default()
        };
        assert_eq!(cfg.match_route("/api/v1/x").unwrap().upstream, "api");
        assert_eq!(cfg.match_route("/anything").unwrap().upstream, "app");
        assert!(cfg.is_enabled());
        assert!(!GatewayConfig::default().is_enabled());
    }

    #[test]
    fn strip_prefix_only_on_segment_boundary() {
        let u = upstream("http://h:1", Some("/app"));
        assert_eq!(u.forward_path("/app"), "/");
        assert_eq!(u.forward_path("/app/foo/bar"), "/foo/bar");
        assert_eq!(u.forward_path("/application"), "/application"); // partial → no strip
        // A trailing slash on the prefix is tolerated.
        let u2 = upstream("http://h:1", Some("/app/"));
        assert_eq!(u2.forward_path("/app/x"), "/x");
        // No prefix → unchanged.
        let u3 = upstream("http://h:1", None);
        assert_eq!(u3.forward_path("/app/x"), "/app/x");
    }

    #[test]
    fn config_round_trips_through_json() {
        let cfg = GatewayConfig {
            upstreams: BTreeMap::from([(
                "api".to_string(),
                Upstream {
                    target: "https://10.0.0.5:8443/base".into(),
                    host_header: Some("internal.local".into()),
                    strip_prefix: Some("/api".into()),
                    connect_timeout_ms: Some(2000),
                    request_timeout_ms: Some(30000),
                    tls_insecure: true,
                    header_up: HeaderOps {
                        set: BTreeMap::from([("x-svc".to_string(), "boatramp".to_string())]),
                        remove: vec!["cookie".into()],
                    },
                    header_down: HeaderOps::default(),
                    ..Default::default()
                },
            )]),
            routes: vec![GatewayRoute {
                matches: "/api/**".into(),
                upstream: "api".into(),
            }],
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(serde_json::from_str::<GatewayConfig>(&json).unwrap(), cfg);
        // The route `match` field is renamed in the wire form.
        assert!(json.contains("\"match\":\"/api/**\""));
        // The single-backend upstream's pool resolution is the lone target.
        let single = &serde_json::from_str::<GatewayConfig>(&json)
            .unwrap()
            .upstreams["api"];
        assert_eq!(single.static_backends(), vec!["https://10.0.0.5:8443/base"]);
    }

    #[test]
    fn nearest_upstream_round_trips_with_region_config() {
        let up = Upstream {
            targets: vec!["http://a".into(), "http://b".into()],
            lb: LbPolicy::Nearest,
            regions: BTreeMap::from([
                ("http://a".to_string(), "us-east".to_string()),
                ("http://b".to_string(), "eu-west".to_string()),
            ]),
            region_map: crate::geo::RegionMap::from_edges([(
                "us-east".to_string(),
                "eu-west".to_string(),
                4,
            )]),
            client_region_header: Some("fly-region".into()),
            max_retries: 2,
            ..Default::default()
        };
        let json = serde_json::to_string(&up).unwrap();
        assert_eq!(serde_json::from_str::<Upstream>(&json).unwrap(), up);
        // Nearest is kebab-cased on the wire.
        assert!(json.contains("\"lb\":\"nearest\""));
        // A default (round-robin, region-agnostic) upstream omits all geo fields.
        let plain = serde_json::to_string(&Upstream {
            target: "http://x".into(),
            ..Default::default()
        })
        .unwrap();
        assert!(!plain.contains("region_map"));
        assert!(!plain.contains("client_region_header"));
        assert!(!plain.contains("\"regions\""));
    }

    #[test]
    fn pool_round_trips_and_resolves_backends() {
        let cfg = GatewayConfig {
            upstreams: BTreeMap::from([(
                "pool".to_string(),
                Upstream {
                    targets: vec!["http://10.0.0.5:8080".into(), "http://10.0.0.6:8080".into()],
                    lb: LbPolicy::Random,
                    max_retries: 2,
                    passive_health: Some(PassiveHealth {
                        max_fails: 5,
                        fail_timeout_ms: 30_000,
                    }),
                    ..Default::default()
                },
            )]),
            routes: vec![GatewayRoute {
                matches: "/**".into(),
                upstream: "pool".into(),
            }],
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back = serde_json::from_str::<GatewayConfig>(&json).unwrap();
        assert_eq!(back, cfg);
        // The pool supersedes `target`.
        assert_eq!(
            back.upstreams["pool"].static_backends(),
            vec!["http://10.0.0.5:8080", "http://10.0.0.6:8080"]
        );
        // kebab-case LB policy on the wire.
        assert!(json.contains("\"lb\":\"random\""));
    }

    #[test]
    fn dns_discovery_round_trips() {
        let u = Upstream {
            discover: Some(Discovery {
                host: "svc.internal".into(),
                port: 8080,
                scheme: "http".into(),
                refresh_secs: 15,
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&u).unwrap();
        assert_eq!(serde_json::from_str::<Upstream>(&json).unwrap(), u);
        // No static backends — the pool is DNS-resolved at serve time.
        assert!(u.static_backends().is_empty());
    }

    #[test]
    fn active_health_round_trips() {
        let u = Upstream {
            targets: vec!["http://10.0.0.1:80".into(), "http://10.0.0.2:80".into()],
            active_health: Some(ActiveHealth {
                path: "/healthz".into(),
                interval_ms: 5_000,
                timeout_ms: 1_000,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
                expected_status: 200,
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&u).unwrap();
        assert_eq!(serde_json::from_str::<Upstream>(&json).unwrap(), u);
        assert!(json.contains("\"path\":\"/healthz\""));
    }

    #[test]
    fn defaults_omit_new_fields_on_the_wire() {
        // A bare single-target upstream serializes without the G5/G6 fields.
        let json = serde_json::to_string(&upstream("http://h:1", None)).unwrap();
        for absent in [
            "targets",
            "lb",
            "max_retries",
            "passive_health",
            "active_health",
            "discover",
        ] {
            assert!(
                !json.contains(absent),
                "default upstream leaked {absent}: {json}"
            );
        }
    }

    // ---- Symmetric two-tier gateway (release 0.37.0) ----

    #[test]
    fn resolve_gateway_operator_precedence_and_reserved_paths() {
        let mut site = GatewayConfig::default();
        site.upstreams
            .insert("ops".into(), upstream("http://10.0.0.9:80", None));
        site.routes.push(GatewayRoute {
            matches: "/admin/**".into(),
            upstream: "ops".into(),
        });
        site.reserved_paths.push("/.well-known/**".into());

        let mut project = GatewayConfig::default();
        project.upstreams.insert(
            "web".into(),
            Upstream {
                compute: Some("web".into()),
                ..Default::default()
            },
        );
        // The project even TRIES to grab the reserved path — it must not win it.
        project.routes.push(GatewayRoute {
            matches: "/.well-known/**".into(),
            upstream: "web".into(),
        });
        project.routes.push(GatewayRoute {
            matches: "/**".into(),
            upstream: "web".into(),
        });

        // Operator route wins where it matches.
        match resolve_gateway(Some(&project), Some(&site), "/admin/x") {
            GatewayResolution::Matched(m) => {
                assert_eq!(m.tier, GatewayTier::Operator);
                assert_eq!(m.upstream_name, "ops");
            }
            _ => panic!("operator route must win"),
        }
        // Reserved path: the project route is structurally barred ⇒ falls through (NoMatch), NEVER
        // the project upstream — the anti-hijack guard.
        assert!(matches!(
            resolve_gateway(Some(&project), Some(&site), "/.well-known/acme"),
            GatewayResolution::NoMatch
        ));
        // A normal path resolves to the project tier.
        match resolve_gateway(Some(&project), Some(&site), "/hello") {
            GatewayResolution::Matched(m) => {
                assert_eq!(m.tier, GatewayTier::Project);
                assert!(!m.via_reference);
            }
            _ => panic!("project route must serve a normal path"),
        }
    }

    #[test]
    fn resolve_gateway_reference_is_operator_tier_and_opaque() {
        let mut site = GatewayConfig::default();
        site.upstreams.insert(
            "db".into(),
            Upstream {
                target: "http://10.0.0.5:5432".into(),
                shared: true,
                ..Default::default()
            },
        );
        let mut project = GatewayConfig::default();
        project.routes.push(GatewayRoute {
            matches: "/db/**".into(),
            upstream: "db".into(),
        });
        // A project route referencing a SHARED site upstream resolves as the operator tier (the
        // operator authorized the reach), via_reference, returning the SITE struct (opaque — the
        // project never copied it).
        match resolve_gateway(Some(&project), Some(&site), "/db/x") {
            GatewayResolution::Matched(m) => {
                assert_eq!(m.tier, GatewayTier::Operator);
                assert!(m.via_reference);
                assert_eq!(m.upstream.target, "http://10.0.0.5:5432");
            }
            _ => panic!("a shared reference must resolve"),
        }
        // A reference to a NON-shared site upstream is denied (deny-by-default).
        let mut site_unshared = GatewayConfig::default();
        site_unshared
            .upstreams
            .insert("db".into(), upstream("http://10.0.0.5:5432", None));
        assert!(matches!(
            resolve_gateway(Some(&project), Some(&site_unshared), "/db/x"),
            GatewayResolution::UnknownUpstream {
                tier: GatewayTier::Project,
                ..
            }
        ));
    }

    #[test]
    fn validate_project_gateway_enforces_the_target_space() {
        // own-compute: allowed.
        let mut p = GatewayConfig::default();
        p.upstreams.insert(
            "w".into(),
            Upstream {
                compute: Some("w".into()),
                ..Default::default()
            },
        );
        p.routes.push(GatewayRoute {
            matches: "/**".into(),
            upstream: "w".into(),
        });
        assert!(validate_project_gateway(&p, None, None).is_ok());

        // public host: allowed.
        let mut public = GatewayConfig::default();
        public
            .upstreams
            .insert("ext".into(), upstream("https://api.example.com", None));
        assert!(validate_project_gateway(&public, None, None).is_ok());

        // raw private / loopback / link-local-metadata: REFUSED (the bright line).
        for bad in [
            "http://10.0.0.5:8080",
            "http://127.0.0.1:9000",
            "http://169.254.169.254/latest",
            "http://[fd00::1]:80",
        ] {
            let mut g = GatewayConfig::default();
            g.upstreams.insert("bad".into(), upstream(bad, None));
            assert!(
                validate_project_gateway(&g, None, None).is_err(),
                "a project upstream to {bad} must be refused"
            );
        }

        // a project upstream marked `shared` is refused (a project cannot grant).
        let mut sh = GatewayConfig::default();
        sh.upstreams.insert(
            "x".into(),
            Upstream {
                target: "https://ok.example.com".into(),
                shared: true,
                ..Default::default()
            },
        );
        assert!(validate_project_gateway(&sh, None, None).is_err());

        // With a SiteConfig: a route to a shared site upstream is OK; to an absent name is refused.
        let mut site = GatewayConfig::default();
        site.upstreams.insert(
            "grant".into(),
            Upstream {
                target: "http://10.0.0.9:80".into(),
                shared: true,
                ..Default::default()
            },
        );
        let mut ref_ok = GatewayConfig::default();
        ref_ok.routes.push(GatewayRoute {
            matches: "/g/**".into(),
            upstream: "grant".into(),
        });
        assert!(validate_project_gateway(&ref_ok, Some(&site), None).is_ok());
        let mut ref_bad = GatewayConfig::default();
        ref_bad.routes.push(GatewayRoute {
            matches: "/g/**".into(),
            upstream: "absent".into(),
        });
        assert!(validate_project_gateway(&ref_bad, Some(&site), None).is_err());
    }

    #[test]
    fn validate_project_gateway_enforces_site_caps() {
        // max_project_upstreams: 2 upstreams over a cap of 1 → refused; a cap of 2 → ok.
        let mut p = GatewayConfig::default();
        p.upstreams
            .insert("a".into(), upstream("https://a.example.com", None));
        p.upstreams
            .insert("b".into(), upstream("https://b.example.com", None));
        let count1 = GatewaySiteCaps {
            max_project_upstreams: Some(1),
            ..Default::default()
        };
        assert!(validate_project_gateway(&p, None, Some(&count1)).is_err());
        let count2 = GatewaySiteCaps {
            max_project_upstreams: Some(2),
            ..Default::default()
        };
        assert!(validate_project_gateway(&p, None, Some(&count2)).is_ok());

        // max_backends: a pooled upstream with 3 targets over a cap of 2 → refused; 3 → ok.
        let mut pool = GatewayConfig::default();
        pool.upstreams.insert(
            "pool".into(),
            Upstream {
                targets: vec![
                    "https://1.example.com".into(),
                    "https://2.example.com".into(),
                    "https://3.example.com".into(),
                ],
                ..Default::default()
            },
        );
        let be2 = GatewaySiteCaps {
            max_backends: Some(2),
            ..Default::default()
        };
        assert!(validate_project_gateway(&pool, None, Some(&be2)).is_err());
        let be3 = GatewaySiteCaps {
            max_backends: Some(3),
            ..Default::default()
        };
        assert!(validate_project_gateway(&pool, None, Some(&be3)).is_ok());

        // project_egress_hosts: a raw host outside the allowlist → refused; inside → ok; own-compute
        // exempt.
        let allow = GatewaySiteCaps {
            project_egress_hosts: vec!["*.good.example".into()],
            ..Default::default()
        };
        let mut evil = GatewayConfig::default();
        evil.upstreams
            .insert("x".into(), upstream("https://evil.example.net", None));
        assert!(
            validate_project_gateway(&evil, None, Some(&allow)).is_err(),
            "a host outside the site egress allowlist is refused"
        );
        let mut good = GatewayConfig::default();
        good.upstreams
            .insert("x".into(), upstream("https://api.good.example", None));
        assert!(
            validate_project_gateway(&good, None, Some(&allow)).is_ok(),
            "a host matching the site allowlist glob is allowed"
        );
        let mut comp = GatewayConfig::default();
        comp.upstreams.insert(
            "w".into(),
            Upstream {
                compute: Some("w".into()),
                ..Default::default()
            },
        );
        assert!(
            validate_project_gateway(&comp, None, Some(&allow)).is_ok(),
            "own-compute is exempt from the egress-host allowlist"
        );

        // No caps ⇒ unbounded (back-compat).
        assert!(validate_project_gateway(&p, None, None).is_ok());
    }

    #[test]
    fn gateway_host_glob_matching() {
        assert!(gateway_host_matches("api.example.com", "API.Example.COM")); // exact, case-insensitive
        assert!(gateway_host_matches("*.example.com", "api.example.com")); // single label
        assert!(!gateway_host_matches("*.example.com", "a.b.example.com")); // not two labels
        assert!(!gateway_host_matches("*.example.com", "example.com")); // not the apex
        assert!(gateway_host_matches("**.example.com", "a.b.example.com")); // any depth
        assert!(gateway_host_matches("**.example.com", "example.com")); // incl. the apex
        assert!(gateway_host_matches("**", "anything.at.all"));
        assert!(!gateway_host_matches("good.com", "evil.com"));
        // empty allowlist ⇒ permitted (no narrowing); non-empty ⇒ must match.
        assert!(gateway_host_allowed(&[], "anything"));
        assert!(gateway_host_allowed(
            &["*.ok.com".to_string()],
            "api.ok.com"
        ));
        assert!(!gateway_host_allowed(
            &["*.ok.com".to_string()],
            "api.evil.com"
        ));
    }

    #[test]
    fn project_raw_egress_intersects_site_and_node() {
        let up = upstream("https://api.vendor.com", None);
        // Both empty ⇒ no narrowing ⇒ allowed.
        assert!(project_raw_egress_allowed(&up, &[], &[]));
        // One side narrows, the other empty ⇒ allowed (empty = no narrowing).
        assert!(project_raw_egress_allowed(
            &up,
            &["*.vendor.com".to_string()],
            &[]
        ));
        assert!(project_raw_egress_allowed(
            &up,
            &[],
            &["api.vendor.com".to_string()]
        ));
        // Site allows but node does NOT ⇒ REFUSED (must clear BOTH levels).
        assert!(!project_raw_egress_allowed(
            &up,
            &["*.vendor.com".to_string()],
            &["*.other.com".to_string()]
        ));
        // Node allows but site does NOT ⇒ REFUSED.
        assert!(!project_raw_egress_allowed(
            &up,
            &["*.other.com".to_string()],
            &["*.vendor.com".to_string()]
        ));
        // Pooled targets: ONE out-of-allowlist host refuses the whole upstream.
        let pool = Upstream {
            targets: vec!["https://a.vendor.com".into(), "https://evil.com".into()],
            ..Default::default()
        };
        assert!(!project_raw_egress_allowed(
            &pool,
            &["*.vendor.com".to_string()],
            &[]
        ));
    }
}
