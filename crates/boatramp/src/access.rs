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

/// Entry point for `boatramp access`.
pub async fn run(args: AccessArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let http = client::http_client(client::token(config).as_deref());
    let mut site_config = client::fetch_site_config(&http, &server, &site).await?;
    let access = &mut site_config.access;

    match args.command {
        AccessCommand::Show => {
            print_access(&site_config.access);
            return Ok(());
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
                println!("added basic-auth user {user} to {site}");
            }
            BasicAuthCommand::Rm { user } => {
                if let Some(basic) = &mut access.basic_auth {
                    basic.users.remove(&user);
                    if basic.users.is_empty() {
                        access.basic_auth = None;
                    }
                }
                println!("removed basic-auth user {user} from {site}");
            }
            BasicAuthCommand::Clear => {
                access.basic_auth = None;
                println!("disabled basic auth for {site}");
            }
        },
        AccessCommand::Ip { command } => match command {
            IpCommand::Allow { cidr } => {
                push_unique(&mut access.ip.allow, &cidr);
                println!("allow {cidr} on {site}");
            }
            IpCommand::Deny { cidr } => {
                push_unique(&mut access.ip.deny, &cidr);
                println!("deny {cidr} on {site}");
            }
            IpCommand::Clear => {
                access.ip.allow.clear();
                access.ip.deny.clear();
                println!("cleared IP rules for {site}");
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
                println!(
                    "rate limit {rps} req/s (burst {}) on {site}",
                    burst.unwrap_or(rps)
                );
            }
            RateLimitCommand::Off => {
                access.rate_limit = None;
                println!("disabled rate limiting for {site}");
            }
        },
        AccessCommand::TrustedProxy { command } => match command {
            TrustedProxyCommand::Add { cidr } => {
                push_unique(&mut access.trusted_proxies, &cidr);
                println!("trust proxy {cidr} on {site}");
            }
            TrustedProxyCommand::Clear => {
                access.trusted_proxies.clear();
                println!("cleared trusted proxies for {site}");
            }
        },
    }

    client::put_site_config(&http, &server, &site, &site_config).await?;
    Ok(())
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

/// Print a human-readable summary of an access policy.
fn print_access(access: &boatramp_core::access::AccessConfig) {
    if !access.is_enforced() && access.trusted_proxies.is_empty() {
        println!("no access control configured");
        return;
    }
    if let Some(basic) = &access.basic_auth {
        let users: Vec<&str> = basic.users.keys().map(String::as_str).collect();
        println!(
            "basic-auth   realm \"{}\", users: {}",
            basic.realm,
            users.join(", ")
        );
    }
    if !access.ip.allow.is_empty() {
        println!("ip allow     {}", access.ip.allow.join(", "));
    }
    if !access.ip.deny.is_empty() {
        println!("ip deny      {}", access.ip.deny.join(", "));
    }
    if let Some(rl) = &access.rate_limit {
        println!(
            "rate limit   {} req/s, burst {}",
            rl.rps,
            rl.burst_capacity()
        );
    }
    if !access.trusted_proxies.is_empty() {
        println!("trusted px   {}", access.trusted_proxies.join(", "));
    }
}
