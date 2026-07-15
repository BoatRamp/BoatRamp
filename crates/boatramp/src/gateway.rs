//! The `gateway` subcommand: publish a private service through the edge.
//! Declares upstreams + routes in the site's `SiteConfig.gateway`
//! via the control-plane API. Per-route header rewrites are richer than the CLI
//! exposes — set those through the site config API directly.

use boatramp_core::gateway::{
    ActiveHealth, Discovery, GatewayConfig, GatewayRoute, LbPolicy, PassiveHealth, Upstream,
};
use clap::{Subcommand, ValueEnum};

/// CLI spelling of [`LbPolicy`].
#[derive(Debug, Clone, Copy, ValueEnum)]
enum LbArg {
    RoundRobin,
    Random,
    /// Route to the nearest healthy backend by region (FA-8); pair with
    /// `--client-region-header` + `--region URL=REGION`.
    Nearest,
}

impl From<LbArg> for LbPolicy {
    fn from(a: LbArg) -> Self {
        match a {
            LbArg::RoundRobin => LbPolicy::RoundRobin,
            LbArg::Random => LbPolicy::Random,
            LbArg::Nearest => LbPolicy::Nearest,
        }
    }
}

/// Parse a `--region URL=REGION` tag into a `(url, region)` pair.
fn parse_region_tag(tag: &str) -> Result<(String, String)> {
    let (url, region) = tag
        .split_once('=')
        .ok_or_else(|| Error::BadRegion(tag.to_string()))?;
    if url.is_empty() || region.is_empty() {
        return Err(Error::BadRegion(tag.to_string()));
    }
    Ok((url.to_string(), region.to_string()))
}

use crate::client;
use crate::config::ProjectConfig;

/// A failure running a `boatramp gateway` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the server/site target or a control-plane call failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// `upstream add` was given no backend source.
    #[error("give a positional target, one or more --backend, or --discover-host")]
    NoBackendSource,
    /// Only one of the two passive-health flags was given.
    #[error("passive health needs both --health-max-fails and --health-timeout-ms")]
    PassiveHealthIncomplete,
    /// `upstream rm` named an upstream that doesn't exist.
    #[error("no upstream named {0}")]
    NoUpstream(String),
    /// `route add` referenced an upstream that doesn't exist.
    #[error("no upstream named {0}; add it first")]
    UpstreamMissing(String),
    /// `route rm` named a route that doesn't exist.
    #[error("no route matching {0}")]
    NoRoute(String),
    /// A `--region` tag was not `URL=REGION`.
    #[error("bad --region {0:?}; expected URL=REGION")]
    BadRegion(String),
}

/// `gateway` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp gateway`.
#[derive(Debug, clap::Args)]
pub struct GatewayArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,
    /// Site to configure (overrides [deploy].site).
    #[arg(long, global = true)]
    site: Option<String>,

    #[command(subcommand)]
    command: GatewayCommand,
}

#[derive(Debug, Subcommand)]
// `Upstream` carries the full upstream-args variant; a large CLI command enum is
// fine and clearer than boxing a clap subcommand.
#[allow(clippy::large_enum_variant)]
enum GatewayCommand {
    /// List declared upstreams and routes.
    Ls,
    /// Manage upstreams (declared backends).
    #[command(subcommand)]
    Upstream(UpstreamCommand),
    /// Manage routes (path → upstream).
    #[command(subcommand)]
    Route(RouteCommand),
}

#[derive(Debug, Subcommand)]
// The `Add` variant carries the full upstream config (pool, LB, health,
// discovery, timeouts); a large CLI-args variant is fine and clearer than boxing.
#[allow(clippy::large_enum_variant)]
enum UpstreamCommand {
    /// Declare or replace an upstream. Give a single positional `target`, a pool
    /// of `--backend` URLs, or `--discover-host`/`--discover-port` for a
    /// DNS-discovered pool.
    Add {
        /// Upstream name (referenced by routes).
        name: String,
        /// Single backend `scheme://host:port[/base]` (host may be private).
        /// Omit when using `--backend` or `--discover-host`.
        target: Option<String>,
        /// Pool backend URL (repeatable) — load-balanced across the pool.
        /// Supersedes the positional `target`.
        #[arg(long = "backend", value_name = "URL")]
        backends: Vec<String>,
        /// Load-balancing policy across the pool.
        #[arg(long, value_enum, default_value_t = LbArg::RoundRobin)]
        lb: LbArg,
        /// Extra backends to try on a connect failure (body-less requests only).
        #[arg(long, default_value_t = 0)]
        max_retries: u32,
        /// Eject a backend after this many consecutive failures (with
        /// `--health-timeout-ms`).
        #[arg(long)]
        health_max_fails: Option<u32>,
        /// How long an ejected backend stays out (milliseconds).
        #[arg(long)]
        health_timeout_ms: Option<u64>,
        /// Enable **active** health probing with this probe path (e.g.
        /// `/healthz`); the other `--probe-*` flags tune it.
        #[arg(long)]
        probe_path: Option<String>,
        /// Active-probe interval (ms).
        #[arg(long)]
        probe_interval_ms: Option<u64>,
        /// Active-probe timeout (ms).
        #[arg(long)]
        probe_timeout_ms: Option<u64>,
        /// Consecutive failed probes before a backend leaves rotation.
        #[arg(long)]
        probe_unhealthy_threshold: Option<u32>,
        /// Consecutive OK probes before a down backend returns.
        #[arg(long)]
        probe_healthy_threshold: Option<u32>,
        /// HTTP status a healthy probe must return.
        #[arg(long)]
        probe_expected_status: Option<u16>,
        /// DNS-discover the pool: resolve this host's A/AAAA records.
        #[arg(long, requires = "discover_port")]
        discover_host: Option<String>,
        /// Port for DNS-discovered backends.
        #[arg(long)]
        discover_port: Option<u16>,
        /// Scheme for DNS-discovered backends.
        #[arg(long, default_value = "http")]
        discover_scheme: String,
        /// Re-resolve the discovered pool at most this often (seconds).
        #[arg(long, default_value_t = 30)]
        discover_refresh_secs: u64,
        /// Override the `Host` header sent upstream.
        #[arg(long)]
        host_header: Option<String>,
        /// Strip this path prefix before forwarding (`/app` → upstream `/`).
        #[arg(long)]
        strip_prefix: Option<String>,
        /// Connect timeout (milliseconds).
        #[arg(long)]
        connect_timeout_ms: Option<u64>,
        /// Overall request timeout (milliseconds).
        #[arg(long)]
        request_timeout_ms: Option<u64>,
        /// Accept a self-signed / invalid upstream TLS certificate.
        #[arg(long)]
        tls_insecure: bool,
        /// For `--lb nearest`: the request header carrying the client's region
        /// (set by the CDN/edge, e.g. `fly-region`, `cf-ipcountry`).
        #[arg(long)]
        client_region_header: Option<String>,
        /// For `--lb nearest`: tag a backend with a region as `URL=REGION`
        /// (repeatable). Untagged backends are region-neutral.
        #[arg(long = "region", value_name = "URL=REGION")]
        regions: Vec<String>,
    },
    /// Remove an upstream (and any routes that reference it).
    Rm {
        /// Upstream name.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum RouteCommand {
    /// Add (or move to the end) a route forwarding `match` to `upstream`.
    Add {
        /// Path glob (e.g. `/api/**`).
        #[arg(value_name = "MATCH")]
        matches: String,
        /// Upstream name to forward to.
        upstream: String,
    },
    /// Remove the route with this `match`.
    Rm {
        /// Path glob to remove.
        #[arg(value_name = "MATCH")]
        matches: String,
    },
}

/// Entry point for `boatramp gateway`.
pub async fn run(args: GatewayArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let http = client::http_client(client::token(config).as_deref());
    let mut site_config = client::fetch_site_config(&http, &server, &site).await?;
    let gateway = site_config
        .gateway
        .get_or_insert_with(GatewayConfig::default);

    match args.command {
        GatewayCommand::Ls => {
            print_gateway(gateway);
            return Ok(()); // read-only; no write-back
        }
        GatewayCommand::Upstream(UpstreamCommand::Add {
            name,
            target,
            backends,
            lb,
            max_retries,
            health_max_fails,
            health_timeout_ms,
            probe_path,
            probe_interval_ms,
            probe_timeout_ms,
            probe_unhealthy_threshold,
            probe_healthy_threshold,
            probe_expected_status,
            discover_host,
            discover_port,
            discover_scheme,
            discover_refresh_secs,
            host_header,
            strip_prefix,
            connect_timeout_ms,
            request_timeout_ms,
            tls_insecure,
            client_region_header,
            regions,
        }) => {
            let discover = discover_host.map(|host| Discovery {
                host,
                port: discover_port.unwrap_or(0),
                scheme: discover_scheme,
                refresh_secs: discover_refresh_secs,
            });
            // Exactly one backend source must be given.
            if target.is_none() && backends.is_empty() && discover.is_none() {
                return Err(Error::NoBackendSource);
            }
            let passive_health = match (health_max_fails, health_timeout_ms) {
                (Some(max_fails), Some(fail_timeout_ms)) => Some(PassiveHealth {
                    max_fails,
                    fail_timeout_ms,
                }),
                (None, None) => None,
                _ => return Err(Error::PassiveHealthIncomplete),
            };
            // `--probe-path` turns on active probing; the other --probe-* flags
            // override the defaults.
            let active_health = probe_path.map(|path| {
                let d = ActiveHealth::default();
                ActiveHealth {
                    path,
                    interval_ms: probe_interval_ms.unwrap_or(d.interval_ms),
                    timeout_ms: probe_timeout_ms.unwrap_or(d.timeout_ms),
                    healthy_threshold: probe_healthy_threshold.unwrap_or(d.healthy_threshold),
                    unhealthy_threshold: probe_unhealthy_threshold.unwrap_or(d.unhealthy_threshold),
                    expected_status: probe_expected_status.unwrap_or(d.expected_status),
                }
            });
            // Parse the `--region URL=REGION` tags into the per-backend map (FA-8).
            let region_tags = regions
                .iter()
                .map(|t| parse_region_tag(t))
                .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
            gateway.upstreams.insert(
                name.clone(),
                Upstream {
                    target: target.unwrap_or_default(),
                    targets: backends,
                    lb: lb.into(),
                    max_retries,
                    passive_health,
                    active_health,
                    discover,
                    host_header,
                    strip_prefix,
                    connect_timeout_ms,
                    request_timeout_ms,
                    tls_insecure,
                    regions: region_tags,
                    client_region_header,
                    ..Default::default()
                },
            );
            println!("upstream {name} set");
        }
        GatewayCommand::Upstream(UpstreamCommand::Rm { name }) => {
            if gateway.upstreams.remove(&name).is_none() {
                return Err(Error::NoUpstream(name));
            }
            // Drop routes that referenced it (now dangling).
            gateway.routes.retain(|r| r.upstream != name);
            println!("upstream {name} removed");
        }
        GatewayCommand::Route(RouteCommand::Add { matches, upstream }) => {
            if !gateway.upstreams.contains_key(&upstream) {
                return Err(Error::UpstreamMissing(upstream));
            }
            gateway.routes.retain(|r| r.matches != matches);
            gateway.routes.push(GatewayRoute { matches, upstream });
            println!("route added");
        }
        GatewayCommand::Route(RouteCommand::Rm { matches }) => {
            let before = gateway.routes.len();
            gateway.routes.retain(|r| r.matches != matches);
            if gateway.routes.len() == before {
                return Err(Error::NoRoute(matches));
            }
            println!("route removed");
        }
    }

    // Drop an empty gateway entirely so the site config stays clean.
    if site_config
        .gateway
        .as_ref()
        .is_some_and(|g| g.upstreams.is_empty() && g.routes.is_empty())
    {
        site_config.gateway = None;
    }
    client::put_site_config(&http, &server, &site, &site_config).await?;
    Ok(())
}

fn print_gateway(gateway: &GatewayConfig) {
    if gateway.upstreams.is_empty() && gateway.routes.is_empty() {
        println!("no gateway configured");
        return;
    }
    println!("upstreams:");
    for (name, up) in &gateway.upstreams {
        let mut notes = Vec::new();
        if let Some(h) = &up.host_header {
            notes.push(format!("host={h}"));
        }
        if let Some(p) = &up.strip_prefix {
            notes.push(format!("strip={p}"));
        }
        if !up.targets.is_empty() {
            notes.push(format!("lb={:?}", up.lb));
        }
        if up.max_retries > 0 {
            notes.push(format!("retries={}", up.max_retries));
        }
        if let Some(h) = &up.passive_health {
            notes.push(format!(
                "health={}fails/{}ms",
                h.max_fails, h.fail_timeout_ms
            ));
        }
        if let Some(a) = &up.active_health {
            notes.push(format!("probe={}@{}ms", a.path, a.interval_ms));
        }
        if up.tls_insecure {
            notes.push("tls_insecure".to_string());
        }
        let suffix = if notes.is_empty() {
            String::new()
        } else {
            format!("  ({})", notes.join(", "))
        };
        // Describe the backend source: a DNS-discovered pool, a static pool, or
        // the single target.
        let dest = if let Some(d) = &up.discover {
            format!("dns:{}:{} ({} backends)", d.host, d.port, d.scheme)
        } else if !up.targets.is_empty() {
            up.targets.join(", ")
        } else {
            up.target.clone()
        };
        println!("  {name} → {dest}{suffix}");
    }
    println!("routes:");
    for route in &gateway.routes {
        println!("  {} → {}", route.matches, route.upstream);
    }
}
