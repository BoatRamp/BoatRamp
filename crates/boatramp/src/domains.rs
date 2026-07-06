//! The `domain` subcommand: attach/detach hostnames to a site for virtualhost
//! routing. Attaching a custom domain is gated on **ownership verification**:
//! `domain add` starts a challenge, `domain verify` proves it and
//! — only then — attaches the host to the site's `SiteConfig` (so it routes and
//! becomes eligible for ACME).

use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `domain` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A hostname's ownership challenge was not satisfied.
    #[error("verification failed: {detail}\n\n{instructions}")]
    VerificationFailed {
        detail: String,
        instructions: String,
    },
    /// Resolving the target or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
}

/// `domains` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp domain`.
#[derive(Debug, clap::Args)]
pub struct DomainArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    /// Site to edit (overrides [deploy].site).
    #[arg(long, env = "BOATRAMP_SITE", global = true)]
    site: Option<String>,

    #[command(subcommand)]
    command: DomainCommand,
}

#[derive(Debug, Subcommand)]
enum DomainCommand {
    /// Start ownership verification for a hostname (use `*.example.com` for a
    /// wildcard). Prints the challenge to publish; run `domain verify` after.
    Add {
        /// Hostname or `*.`-prefixed wildcard.
        host: String,
        /// Verification method: `http` (default) serves a token file; `dns`
        /// publishes a TXT record (needs a server built with `domain-verify-dns`).
        #[arg(long, default_value = "http")]
        method: String,
    },
    /// Check a hostname's verification challenge; on success it is attached.
    Verify {
        /// Hostname or `*.`-prefixed wildcard.
        host: String,
    },
    /// Detach a hostname and drop its verification.
    Rm {
        /// Hostname to remove.
        host: String,
    },
    /// List the site's hostnames and any pending verifications.
    Ls,
}

/// Entry point for `boatramp domain`.
pub async fn run(args: DomainArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let http = client::http_client(client::token(config).as_deref());

    match args.command {
        DomainCommand::Ls => ls(&http, &server, &site).await,
        DomainCommand::Add { host, method } => {
            let verification =
                client::start_domain_verification(&http, &server, &site, &host, Some(&method))
                    .await?;
            if verification.verified {
                println!("{host} is already verified for {site}");
                println!("run `boatramp domain verify {host}` to (re)attach it");
            } else {
                println!("started {} verification for {host}\n", verification.method);
                println!("{}", verification.instructions());
            }
            Ok(())
        }
        DomainCommand::Verify { host } => {
            let result = client::check_domain_verification(&http, &server, &site, &host).await?;
            if result.passed {
                if result.attached {
                    println!("verified {host} and attached it to {site}");
                } else {
                    println!("verified {host}");
                }
            } else {
                let detail = result
                    .detail
                    .unwrap_or_else(|| "challenge not satisfied yet".into());
                return Err(Error::VerificationFailed {
                    detail,
                    instructions: result.verification.instructions(),
                });
            }
            Ok(())
        }
        DomainCommand::Rm { host } => {
            let mut site_config = client::fetch_site_config(&http, &server, &site).await?;
            let domains = &mut site_config.domains;
            if domains.primary.as_deref() == Some(host.as_str()) {
                domains.primary = None;
            }
            domains.aliases.retain(|alias| alias != &host);
            domains.wildcards.retain(|wildcard| wildcard != &host);
            client::put_site_config(&http, &server, &site, &site_config).await?;
            client::remove_domain_verification(&http, &server, &site, &host).await?;
            println!("detached {host} from {site}");
            Ok(())
        }
    }
}

/// List attached hostnames plus any started-but-not-yet-attached verifications.
async fn ls(http: &reqwest::Client, server: &str, site: &str) -> Result<()> {
    let site_config = client::fetch_site_config(http, server, site).await?;
    let domains = &site_config.domains;
    let mut any = false;
    if let Some(primary) = &domains.primary {
        println!("{primary}  (primary)");
        any = true;
    }
    for alias in &domains.aliases {
        println!("{alias}");
        any = true;
    }
    for wildcard in &domains.wildcards {
        println!("{wildcard}  (wildcard)");
        any = true;
    }
    if !any {
        println!("no domains attached to {site}");
    }

    // Surface challenges that have been started but whose host isn't attached
    // yet (unverified, or verified-but-detached) so the operator knows what's
    // still pending a `domain verify`.
    let attached: std::collections::BTreeSet<String> = domains
        .exact_hosts()
        .map(str::to_string)
        .chain(domains.wildcards.iter().cloned())
        .map(|h| boatramp_core::domain_verify::normalize_host(&h))
        .collect();
    let pending: Vec<_> = client::list_domain_verifications(http, server, site)
        .await?
        .into_iter()
        .filter(|v| !attached.contains(&v.host))
        .collect();
    if !pending.is_empty() {
        println!("\npending verification:");
        for v in pending {
            let state = if v.verified {
                "verified — run `domain verify` to attach"
            } else {
                "unverified"
            };
            println!("  {}  ({}, {state})", v.host, v.method);
        }
    }
    Ok(())
}
