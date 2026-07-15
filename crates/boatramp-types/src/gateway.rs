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
}

impl GatewayConfig {
    /// Whether any route is declared (the serving path skips the gateway stage
    /// otherwise).
    pub fn is_enabled(&self) -> bool {
        !self.routes.is_empty()
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
    /// Header rewrites applied to the request before forwarding.
    #[serde(skip_serializing_if = "HeaderOps::is_empty")]
    pub header_up: HeaderOps,
    /// Header rewrites applied to the response before returning it.
    #[serde(skip_serializing_if = "HeaderOps::is_empty")]
    pub header_down: HeaderOps,
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
        matches!(self, LbPolicy::RoundRobin)
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
}
