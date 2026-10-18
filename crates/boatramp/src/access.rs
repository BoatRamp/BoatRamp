//! The `access` subcommand: configure a site's visitor access control —
//! HTTP Basic auth, IP allow/deny, rate limiting, and trusted proxies. Edits
//! the site's `SiteConfig.access` via the control-plane API.

use std::io::Read;

use boatramp_core::access::{BasicAuth, RateLimit};
use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `access` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A Basic-auth password was empty.
    #[error("empty password")]
    EmptyPassword,
    /// The rate-limit value was not greater than zero.
    #[error("rps must be > 0")]
    RpsZero,
    /// Resolving the target or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// Reading the password from stdin failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// `access` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp access`.
#[derive(Debug, clap::Args)]
pub struct AccessArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    /// Site to edit (overrides [deploy].site).
    #[arg(long, env = "BOATRAMP_SITE", global = true)]
    site: Option<String>,

    #[command(subcommand)]
    command: AccessCommand,
}

#[derive(Debug, Subcommand)]
enum AccessCommand {
    /// Show the site's current access-control policy.
    Show,
    /// Manage HTTP Basic auth credentials.
    BasicAuth {
        #[command(subcommand)]
        command: BasicAuthCommand,
    },
    /// Manage IP allow/deny rules (CIDR or bare address).
    Ip {
        #[command(subcommand)]
        command: IpCommand,
    },
    /// Configure per-client rate limiting.
    RateLimit {
        #[command(subcommand)]
        command: RateLimitCommand,
    },
    /// Manage trusted reverse-proxy CIDRs (for `X-Forwarded-For` trust).
    TrustedProxy {
        #[command(subcommand)]
        command: TrustedProxyCommand,
    },
    /// Configure the built-in WAF (user-agent rules + anomaly scoring).
    Waf {
        #[command(subcommand)]
        command: WafCommand,
    },
}

#[derive(Debug, Subcommand)]
enum WafCommand {
    /// Enable user-agent filtering, optionally setting the deny/allow lists
    /// (`--deny`/`--allow` **replace** the respective list when given).
    UserAgent {
        /// A user-agent substring/pattern to deny; repeatable.
        #[arg(long = "deny", value_name = "PATTERN")]
        deny: Vec<String>,
        /// A user-agent substring/pattern to always allow; repeatable.
        #[arg(long = "allow", value_name = "PATTERN")]
        allow: Vec<String>,
    },
    /// Disable user-agent filtering.
    UserAgentOff,
    /// Enable heuristic anomaly scoring, optionally setting the block threshold.
    Anomaly {
        /// Score at or above which a request is blocked.
        #[arg(long)]
        threshold: Option<u32>,
    },
    /// Disable anomaly scoring.
    AnomalyOff,
}

#[derive(Debug, Subcommand)]
enum BasicAuthCommand {
    /// Add or update a user. Password from `--password`, else read from stdin.
    Add {
        /// Username.
        user: String,
        /// Password (omit to read one line from stdin, e.g. via a pipe).
        #[arg(long)]
        password: Option<String>,
        /// Realm shown in the browser prompt.
        #[arg(long)]
        realm: Option<String>,
    },
    /// Remove a user.
    Rm {
        /// Username to remove.
        user: String,
    },
    /// Disable Basic auth entirely (remove all credentials).
    Clear,
}

#[derive(Debug, Subcommand)]
enum IpCommand {
    /// Add an allow rule (only listed clients may connect).
    Allow {
        /// CIDR or bare IP.
        cidr: String,
    },
    /// Add a deny rule (deny wins over allow).
    Deny {
        /// CIDR or bare IP.
        cidr: String,
    },
    /// Remove all IP rules.
    Clear,
}

#[derive(Debug, Subcommand)]
enum RateLimitCommand {
    /// Set the per-client limit (requests/second + optional burst).
    Set {
        /// Sustained requests per second.
        rps: u32,
        /// Burst capacity (defaults to `rps`).
        #[arg(long)]
        burst: Option<u32>,
    },
    /// Disable rate limiting.
    Off,
}

#[derive(Debug, Subcommand)]
enum TrustedProxyCommand {
    /// Trust a reverse proxy by CIDR (so its `X-Forwarded-For` is believed).
    Add {
        /// CIDR or bare IP.
        cidr: String,
    },
    /// Remove all trusted proxies.
    Clear,
}

/// The result of an `access` subcommand, rendered by [`crate::output`].
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum AccessOutput {
    /// `access show` — the site's current access-control policy.
    Show {
        access: boatramp_core::access::AccessConfig,
    },
    /// A Basic-auth user was added or updated.
    BasicAuthAdded { user: String, site: String },
    /// A Basic-auth user was removed.
    BasicAuthRemoved { user: String, site: String },
    /// Basic auth was disabled (all credentials removed).
    BasicAuthCleared { site: String },
    /// An IP allow rule was added.
    IpAllowed { cidr: String, site: String },
    /// An IP deny rule was added.
    IpDenied { cidr: String, site: String },
    /// All IP rules were removed.
    IpCleared { site: String },
    /// Rate limiting was set. `burst` is the value the human line shows
    /// (`burst.unwrap_or(rps)`).
    RateLimitSet { rps: u32, burst: u32, site: String },
    /// Rate limiting was disabled.
    RateLimitOff { site: String },
    /// A trusted reverse proxy was added.
    TrustedProxyAdded { cidr: String, site: String },
    /// All trusted proxies were removed.
    TrustedProxyCleared { site: String },
    /// WAF user-agent filtering was enabled.
    WafUserAgentEnabled { site: String },
    /// WAF user-agent filtering was disabled.
    WafUserAgentDisabled { site: String },
    /// WAF anomaly scoring was enabled; `threshold` is the resolved block threshold.
    WafAnomalyEnabled { site: String, threshold: u32 },
    /// WAF anomaly scoring was disabled.
    WafAnomalyDisabled { site: String },
}

impl crate::output::Rendered for AccessOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Show { access } => write_access(access, w),
            Self::BasicAuthAdded { user, site } => {
                writeln!(w, "added basic-auth user {user} to {site}")
            }
            Self::BasicAuthRemoved { user, site } => {
                writeln!(w, "removed basic-auth user {user} from {site}")
            }
            Self::BasicAuthCleared { site } => {
                writeln!(w, "disabled basic auth for {site}")
            }
            Self::IpAllowed { cidr, site } => writeln!(w, "allow {cidr} on {site}"),
            Self::IpDenied { cidr, site } => writeln!(w, "deny {cidr} on {site}"),
            Self::IpCleared { site } => writeln!(w, "cleared IP rules for {site}"),
            Self::RateLimitSet { rps, burst, site } => {
                writeln!(w, "rate limit {rps} req/s (burst {burst}) on {site}")
            }
            Self::RateLimitOff { site } => {
                writeln!(w, "disabled rate limiting for {site}")
            }
            Self::TrustedProxyAdded { cidr, site } => {
                writeln!(w, "trust proxy {cidr} on {site}")
            }
            Self::TrustedProxyCleared { site } => {
                writeln!(w, "cleared trusted proxies for {site}")
            }
            Self::WafUserAgentEnabled { site } => {
                writeln!(w, "waf: user-agent filtering enabled for {site}")
            }
            Self::WafUserAgentDisabled { site } => {
                writeln!(w, "waf: user-agent filtering disabled for {site}")
            }
            Self::WafAnomalyEnabled { site, threshold } => {
                writeln!(
                    w,
                    "waf: anomaly scoring enabled for {site} (threshold {threshold})"
                )
            }
            Self::WafAnomalyDisabled { site } => {
                writeln!(w, "waf: anomaly scoring disabled for {site}")
            }
        }
    }
}

/// Entry point for `boatramp access`.
pub async fn run(args: AccessArgs, config: &ProjectConfig) -> Result<AccessOutput> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    let mut site_config = cp.fetch_site_config(&site).await?;
    let access = &mut site_config.access;

    let out = match args.command {
        AccessCommand::Show => {
            // Read-only; no write-back.
            return Ok(AccessOutput::Show {
                access: access.clone(),
            });
        }
        AccessCommand::BasicAuth { command } => match command {
            BasicAuthCommand::Add {
                user,
                password,
                realm,
            } => {
                let password = match password {
                    Some(p) => p,
                    None => read_stdin_line()?,
                };
                if password.is_empty() {
                    return Err(Error::EmptyPassword);
                }
                let hash = boatramp_core::access::hash_password(&password);
                let basic = access.basic_auth.get_or_insert_with(|| BasicAuth {
                    realm: "Restricted".to_string(),
                    users: Default::default(),
                });
                if let Some(realm) = realm {
                    basic.realm = realm;
                }
                basic.users.insert(user.clone(), hash);
                AccessOutput::BasicAuthAdded {
                    user,
                    site: site.clone(),
                }
            }
            BasicAuthCommand::Rm { user } => {
                if let Some(basic) = &mut access.basic_auth {
                    basic.users.remove(&user);
                    if basic.users.is_empty() {
                        access.basic_auth = None;
                    }
                }
                AccessOutput::BasicAuthRemoved {
                    user,
                    site: site.clone(),
                }
            }
            BasicAuthCommand::Clear => {
                access.basic_auth = None;
                AccessOutput::BasicAuthCleared { site: site.clone() }
            }
        },
        AccessCommand::Ip { command } => match command {
            IpCommand::Allow { cidr } => {
                push_unique(&mut access.ip.allow, &cidr);
                AccessOutput::IpAllowed {
                    cidr,
                    site: site.clone(),
                }
            }
            IpCommand::Deny { cidr } => {
                push_unique(&mut access.ip.deny, &cidr);
                AccessOutput::IpDenied {
                    cidr,
                    site: site.clone(),
                }
            }
            IpCommand::Clear => {
                access.ip.allow.clear();
                access.ip.deny.clear();
                AccessOutput::IpCleared { site: site.clone() }
            }
        },
        AccessCommand::RateLimit { command } => match command {
            RateLimitCommand::Set { rps, burst } => {
                if rps == 0 {
                    return Err(Error::RpsZero);
                }
                access.rate_limit = Some(RateLimit {
                    rps,
                    burst: burst.unwrap_or(0),
                });
                AccessOutput::RateLimitSet {
                    rps,
                    burst: burst.unwrap_or(rps),
                    site: site.clone(),
                }
            }
            RateLimitCommand::Off => {
                access.rate_limit = None;
                AccessOutput::RateLimitOff { site: site.clone() }
            }
        },
        AccessCommand::TrustedProxy { command } => match command {
            TrustedProxyCommand::Add { cidr } => {
                push_unique(&mut access.trusted_proxies, &cidr);
                AccessOutput::TrustedProxyAdded {
                    cidr,
                    site: site.clone(),
                }
            }
            TrustedProxyCommand::Clear => {
                access.trusted_proxies.clear();
                AccessOutput::TrustedProxyCleared { site: site.clone() }
            }
        },
        AccessCommand::Waf { command } => match command {
            WafCommand::UserAgent { deny, allow } => {
                access.waf.user_agent.enabled = true;
                if !deny.is_empty() {
                    access.waf.user_agent.deny = deny;
                }
                if !allow.is_empty() {
                    access.waf.user_agent.allow = allow;
                }
                AccessOutput::WafUserAgentEnabled { site: site.clone() }
            }
            WafCommand::UserAgentOff => {
                access.waf.user_agent.enabled = false;
                AccessOutput::WafUserAgentDisabled { site: site.clone() }
            }
            WafCommand::Anomaly { threshold } => {
                access.waf.anomaly.enabled = true;
                if let Some(t) = threshold {
                    access.waf.anomaly.threshold = t;
                }
                AccessOutput::WafAnomalyEnabled {
                    site: site.clone(),
                    threshold: access.waf.anomaly.threshold,
                }
            }
            WafCommand::AnomalyOff => {
                access.waf.anomaly.enabled = false;
                AccessOutput::WafAnomalyDisabled { site: site.clone() }
            }
        },
    };

    cp.put_site_config(&site, &site_config).await?;
    Ok(out)
}

/// Append `value` if not already present.
fn push_unique(list: &mut Vec<String>, value: &str) {
    if !list.iter().any(|existing| existing == value) {
        list.push(value.to_string());
    }
}

/// Read a single trimmed line (or piped content) from stdin.
fn read_stdin_line() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf.trim().to_string())
}

/// Write a human-readable summary of an access policy to `w`.
fn write_access(
    access: &boatramp_core::access::AccessConfig,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    if !access.is_enforced() && access.trusted_proxies.is_empty() {
        writeln!(w, "no access control configured")?;
        return Ok(());
    }
    if let Some(basic) = &access.basic_auth {
        let users: Vec<&str> = basic.users.keys().map(String::as_str).collect();
        writeln!(
            w,
            "basic-auth   realm \"{}\", users: {}",
            basic.realm,
            users.join(", ")
        )?;
    }
    if !access.ip.allow.is_empty() {
        writeln!(w, "ip allow     {}", access.ip.allow.join(", "))?;
    }
    if !access.ip.deny.is_empty() {
        writeln!(w, "ip deny      {}", access.ip.deny.join(", "))?;
    }
    if let Some(rl) = &access.rate_limit {
        writeln!(
            w,
            "rate limit   {} req/s, burst {}",
            rl.rps,
            rl.burst_capacity()
        )?;
    }
    if !access.trusted_proxies.is_empty() {
        writeln!(w, "trusted px   {}", access.trusted_proxies.join(", "))?;
    }
    Ok(())
}
