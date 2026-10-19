//! The `gateway` subcommand: publish a private service through the edge.
//! Declares upstreams + routes in the site's `SiteConfig.gateway`
//! via the control-plane API. Per-route header rewrites are richer than the CLI
//! exposes — set those through the site config API directly.

use boatramp_core::gateway::{
    ActiveHealth, Discovery, GatewayConfig, GatewayRoute, GatewaySiteCaps, LbPolicy, PassiveHealth,
    Upstream, validate_site_gateway,
};
use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

/// The declarative document for `gateway apply` / `gateway export` (0.37.0): a site's full gateway —
/// its upstreams + routes, plus the site-operator ceilings on the project tier (`GatewaySiteCaps`).
/// One round-trippable file so a site operator can version-control + `apply` the whole gateway, the
/// declarative analogue of the imperative `upstream add` / `route add` + the caps.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct GatewayDoc {
    /// Upstreams + routes (+ reserved_paths) — the `SiteConfig.gateway`.
    gateway: GatewayConfig,
    /// Site-operator ceilings on what the project tier may declare — the `SiteConfig.gateway_caps`.
    caps: GatewaySiteCaps,
}

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
            LbArg::RoundRobin => Self::RoundRobin,
            LbArg::Random => Self::Random,
            LbArg::Nearest => Self::Nearest,
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
    /// Reading/writing a `gateway apply`/`export` file failed.
    #[error("gateway file I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Decoding a `gateway apply` file failed.
    #[error("gateway file parse: {0}")]
    Parse(String),
    /// Serializing a `gateway export` document failed.
    #[error("gateway export encode: {0}")]
    Encode(String),
    /// The gateway config (from `apply` or an imperative mutation) failed validation.
    #[error("invalid gateway config: {0}")]
    Validate(#[from] boatramp_core::ConfigError),
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
    /// Declaratively apply a whole gateway (upstreams + routes + project ceilings) from a file,
    /// REPLACING the site's current gateway. The declarative analogue of the imperative commands.
    Apply {
        /// Path to the gateway document (RON or JSON — auto-detected by extension).
        #[arg(short = 'f', long, default_value = "gateway.cfg")]
        file: PathBuf,
        /// File format override (`.json` ⇒ JSON, else RON).
        #[arg(long, value_enum)]
        format: Option<crate::config::ConfigFormat>,
        /// Validate + show what would change, but do NOT write it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Export the site's current gateway (upstreams + routes + project ceilings) as a declarative
    /// document, to a file or stdout — round-trips with `apply`.
    Export {
        /// Write to this path; omit for stdout.
        #[arg(short = 'f', long)]
        file: Option<PathBuf>,
        /// Output format (`.json` path ⇒ JSON, else RON; defaults to RON for stdout).
        #[arg(long, value_enum)]
        format: Option<crate::config::ConfigFormat>,
    },
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
        /// Cap the per-connection upstream read buffer (bytes); default 32768.
        /// Higher trades memory for fewer read syscalls (throughput on large
        /// responses); lower trades syscalls for less memory. Matters most at high
        /// proxy concurrency.
        #[arg(long)]
        read_buffer_bytes: Option<u64>,
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
/// The result of a `gateway` subcommand, rendered by [`crate::output`].
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum GatewayOutput {
    /// `gateway ls` — the site's current gateway (upstreams + routes).
    Show { gateway: GatewayConfig },
    /// An upstream was created or replaced.
    UpstreamSet { name: String },
    /// An upstream (and any routes that referenced it) was removed.
    UpstreamRemoved { name: String },
    /// A route was added (any existing route with the same match was replaced).
    RouteAdded { matches: String, upstream: String },
    /// A route was removed.
    RouteRemoved { matches: String },
    /// `gateway export` — written to a file (`path`), or returned for stdout (`rendered` = the
    /// serialized doc, in the chosen `--format`; emitted verbatim in human mode).
    Exported {
        path: Option<PathBuf>,
        #[serde(skip)]
        rendered: String,
    },
    /// `gateway apply` — the declarative doc was applied to the site.
    Applied { site: String },
    /// `gateway apply --dry-run` — the would-be gateway (+ project ceilings), nothing written.
    DryRun { doc: GatewayDoc },
}

impl crate::output::Rendered for GatewayOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Show { gateway } => write_gateway(gateway, w),
            Self::UpstreamSet { name } => writeln!(w, "upstream {name} set"),
            Self::UpstreamRemoved { name } => writeln!(w, "upstream {name} removed"),
            // The human line stays terse (unchanged); the match/upstream ride the JSON shape.
            Self::RouteAdded { .. } => writeln!(w, "route added"),
            Self::RouteRemoved { .. } => writeln!(w, "route removed"),
            Self::Exported { path, rendered } => match path {
                Some(p) => writeln!(w, "gateway exported to {}", p.display()),
                // No file: the serialized doc is the pipeable result, written verbatim.
                None => write!(w, "{rendered}"),
            },
            Self::Applied { site } => writeln!(w, "gateway applied to site {site}"),
            Self::DryRun { doc } => {
                write_gateway(&doc.gateway, w)?;
                if !doc.caps.is_empty() {
                    writeln!(w, "project ceilings (GatewaySiteCaps): {:?}", doc.caps)?;
                }
                Ok(())
            }
        }
    }
}

pub async fn run(args: GatewayArgs, config: &ProjectConfig) -> Result<GatewayOutput> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    let mut site_config = cp.fetch_site_config(&site).await?;

    // Declarative apply/export operate on the WHOLE gateway document (not the in-place `&mut gateway`
    // the imperative commands mutate), so they are dispatched before the `get_or_insert` borrow.
    if let GatewayCommand::Export { file, format } = &args.command {
        return export_gateway(&site_config, file.clone(), *format);
    }
    if let GatewayCommand::Apply {
        file,
        format,
        dry_run,
    } = &args.command
    {
        return apply_gateway(&cp, &site, site_config, file.clone(), *format, *dry_run).await;
    }

    let gateway = site_config
        .gateway
        .get_or_insert_with(GatewayConfig::default);

    let out = match args.command {
        GatewayCommand::Ls => {
            // Read-only; no write-back.
            return Ok(GatewayOutput::Show {
                gateway: gateway.clone(),
            });
        }
        // Handled above (before the `get_or_insert` borrow).
        GatewayCommand::Apply { .. } | GatewayCommand::Export { .. } => unreachable!(),
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
            read_buffer_bytes,
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
                    read_buffer_bytes,
                    regions: region_tags,
                    client_region_header,
                    ..Default::default()
                },
            );
            GatewayOutput::UpstreamSet { name }
        }
        GatewayCommand::Upstream(UpstreamCommand::Rm { name }) => {
            if gateway.upstreams.remove(&name).is_none() {
                return Err(Error::NoUpstream(name));
            }
            // Drop routes that referenced it (now dangling).
            gateway.routes.retain(|r| r.upstream != name);
            GatewayOutput::UpstreamRemoved { name }
        }
        GatewayCommand::Route(RouteCommand::Add { matches, upstream }) => {
            if !gateway.upstreams.contains_key(&upstream) {
                return Err(Error::UpstreamMissing(upstream));
            }
            gateway.routes.retain(|r| r.matches != matches);
            let out = GatewayOutput::RouteAdded {
                matches: matches.clone(),
                upstream: upstream.clone(),
            };
            gateway.routes.push(GatewayRoute { matches, upstream });
            out
        }
        GatewayCommand::Route(RouteCommand::Rm { matches }) => {
            let before = gateway.routes.len();
            gateway.routes.retain(|r| r.matches != matches);
            if gateway.routes.len() == before {
                return Err(Error::NoRoute(matches));
            }
            GatewayOutput::RouteRemoved { matches }
        }
    };

    // Validate the mutated site gateway before writing it back (0.37.0): the same
    // `validate_site_gateway` the declarative `apply` runs, so an imperative `upstream add` / `route
    // add` can't persist a config `apply` would reject (e.g. a bad reserved-path glob).
    if let Some(gw) = site_config.gateway.as_ref() {
        validate_site_gateway(gw)?;
    }
    // Drop an empty gateway entirely so the site config stays clean.
    if site_config
        .gateway
        .as_ref()
        .is_some_and(|g| g.upstreams.is_empty() && g.routes.is_empty())
    {
        site_config.gateway = None;
    }
    cp.put_site_config(&site, &site_config).await?;
    Ok(out)
}

/// `gateway export`: serialize the site's current gateway + project ceilings as a [`GatewayDoc`] to
/// `file` (RON/JSON by extension), or return it for the dispatch layer to render (the serialized doc
/// to stdout in human mode). Read-only. The `--format` here selects the DOC's representation (RON/
/// JSON config file), independent of the global `--output-format`.
fn export_gateway(
    site_config: &boatramp_core::config::SiteConfig,
    file: Option<PathBuf>,
    format: Option<crate::config::ConfigFormat>,
) -> Result<GatewayOutput> {
    let doc = GatewayDoc {
        gateway: site_config.gateway.clone().unwrap_or_default(),
        caps: site_config.gateway_caps.clone(),
    };
    let fmt = match &file {
        Some(p) => crate::config::resolve_format(p, format),
        None => format.unwrap_or(crate::config::ConfigFormat::Ron),
    };
    let text = match fmt {
        crate::config::ConfigFormat::Ron => crate::config::ron_options()
            .to_string_pretty(&doc, ron::ser::PrettyConfig::default())
            .map_err(|e| Error::Encode(e.to_string()))?,
        crate::config::ConfigFormat::Json => {
            serde_json::to_string_pretty(&doc).map_err(|e| Error::Encode(e.to_string()))?
        }
    };
    match file {
        Some(p) => {
            std::fs::write(&p, text)?;
            Ok(GatewayOutput::Exported {
                path: Some(p),
                rendered: String::new(),
            })
        }
        // No file: the serialized doc is the pipeable result (rendered verbatim in human mode).
        None => Ok(GatewayOutput::Exported {
            path: None,
            rendered: text,
        }),
    }
}

/// `gateway apply`: read a [`GatewayDoc`] from `file`, VALIDATE it (`validate_site_gateway`), and
/// REPLACE the site's gateway + project ceilings with it. `dry_run` validates + previews without
/// writing. Declarative analogue of the imperative mutations.
async fn apply_gateway(
    cp: &client::ControlPlane,
    site: &str,
    mut site_config: boatramp_core::config::SiteConfig,
    file: PathBuf,
    format: Option<crate::config::ConfigFormat>,
    dry_run: bool,
) -> Result<GatewayOutput> {
    let fmt = crate::config::resolve_format(&file, format);
    let text = std::fs::read_to_string(&file)?;
    let doc: GatewayDoc = match fmt {
        crate::config::ConfigFormat::Ron => crate::config::ron_options()
            .from_str(&text)
            .map_err(|e| Error::Parse(e.to_string()))?,
        crate::config::ConfigFormat::Json => {
            serde_json::from_str(&text).map_err(|e| Error::Parse(e.to_string()))?
        }
    };
    // Validate the site gateway before applying (reserved-path globs, operator upstream refs, etc.).
    validate_site_gateway(&doc.gateway)?;
    if dry_run {
        return Ok(GatewayOutput::DryRun { doc });
    }
    // REPLACE the whole gateway + ceilings (declarative). An empty gateway drops the block.
    site_config.gateway = (!doc.gateway.is_empty()).then_some(doc.gateway);
    site_config.gateway_caps = doc.caps;
    cp.put_site_config(site, &site_config).await?;
    Ok(GatewayOutput::Applied {
        site: site.to_string(),
    })
}

fn write_gateway(gateway: &GatewayConfig, w: &mut dyn std::io::Write) -> std::io::Result<()> {
    if gateway.upstreams.is_empty() && gateway.routes.is_empty() {
        writeln!(w, "no gateway configured")?;
        return Ok(());
    }
    writeln!(w, "upstreams:")?;
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
        writeln!(w, "  {name} → {dest}{suffix}")?;
    }
    writeln!(w, "routes:")?;
    for route in &gateway.routes {
        writeln!(w, "  {} → {}", route.matches, route.upstream)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative gateway doc: an upstream + a route, a site-reserved path, and the
    /// project-tier ceilings — exercising every field `export` writes and `apply` reads back.
    fn sample_doc() -> GatewayDoc {
        let mut gateway = GatewayConfig::default();
        gateway.upstreams.insert(
            "api".to_string(),
            Upstream {
                target: "https://api.example.com".to_string(),
                ..Default::default()
            },
        );
        gateway.routes.push(GatewayRoute {
            matches: "/api/**".to_string(),
            upstream: "api".to_string(),
        });
        gateway.reserved_paths.push("/.well-known/**".to_string());
        GatewayDoc {
            gateway,
            caps: GatewaySiteCaps {
                max_project_upstreams: Some(3),
                max_backends: Some(4),
                project_egress_hosts: vec!["**.example.com".to_string()],
            },
        }
    }

    #[test]
    fn gateway_doc_round_trips_through_ron_and_json() {
        let doc = sample_doc();

        // RON — the `export` default and `.cfg`/`.ron` files.
        let ron_text = crate::config::ron_options()
            .to_string_pretty(&doc, ron::ser::PrettyConfig::default())
            .expect("serialize RON");
        let from_ron: GatewayDoc = crate::config::ron_options()
            .from_str(&ron_text)
            .expect("parse RON");
        assert_eq!(from_ron.gateway.upstreams.len(), 1);
        assert_eq!(from_ron.gateway.routes.len(), 1);
        assert_eq!(from_ron.gateway.reserved_paths, vec!["/.well-known/**"]);
        assert_eq!(from_ron.caps.max_project_upstreams, Some(3));
        assert_eq!(from_ron.caps.max_backends, Some(4));
        assert_eq!(from_ron.caps.project_egress_hosts, vec!["**.example.com"]);

        // JSON — `.json` files / `--format json`.
        let json_text = serde_json::to_string_pretty(&doc).expect("serialize JSON");
        let from_json: GatewayDoc = serde_json::from_str(&json_text).expect("parse JSON");
        assert_eq!(from_json.gateway.upstreams.len(), 1);
        assert_eq!(from_json.caps.max_backends, Some(4));

        // The round-tripped doc still passes the shared validator the `apply` path runs — so
        // export→apply is a faithful loop, not a config that drops or mutates under serialization.
        validate_site_gateway(&from_ron.gateway).expect("round-tripped gateway validates");
    }

    #[test]
    fn gateway_doc_rejects_unknown_fields() {
        // `deny_unknown_fields` keeps a typo'd key from silently dropping config on `apply`.
        let bad = r#"{"gateway":{"upstreams":{},"routes":[]},"caps":{},"bogus":1}"#;
        assert!(serde_json::from_str::<GatewayDoc>(bad).is_err());
    }
}
