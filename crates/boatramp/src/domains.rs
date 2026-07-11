//! The `domain` subcommand: attach/detach hostnames to a site for virtualhost
//! routing. Attaching a custom domain is gated on **ownership verification**.
//!
//! `domain add` starts a challenge and, when there is no manual step left, goes
//! all the way — verifies and attaches in one command:
//!
//! * a host that **already resolves to this server** verifies over HTTP
//!   immediately (the server serves its own challenge token from the edge, so no
//!   prior deploy is needed — the fix for the attach chicken-and-egg);
//! * `--provider` publishes the DNS-TXT challenge for you, waits for it to
//!   resolve, and attaches.
//!
//! Otherwise (a live domain still pointing elsewhere, or `--no-wait`) it prints
//! the challenge to publish and you finish with `domain verify`. Attachment only
//! ever happens after ownership is proven — so the host routes and becomes
//! eligible for ACME.

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
    /// A `--provider` verification-dance problem (timeout, or the `acme-dns`
    /// feature is absent from this build).
    #[error("{0}")]
    Auto(String),
    /// Building the DNS provider for `--provider` failed (missing credential env var).
    #[cfg(feature = "acme-dns")]
    #[error(transparent)]
    Provider(#[from] crate::acme_dns::Error),
    /// Publishing the challenge TXT during `--provider` failed.
    #[cfg(feature = "acme-dns")]
    #[error(transparent)]
    Dns(#[from] boatramp_acme::DnsError),
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
    /// Verify ownership of a hostname and attach it to the site (use
    /// `*.example.com` for a wildcard).
    ///
    /// If the host already resolves to this server it is verified + attached in
    /// one step; otherwise the challenge to publish is printed and you finish
    /// with `domain verify`.
    Add {
        /// Hostname or `*.`-prefixed wildcard.
        host: String,
        /// Verification method: `http` (default) serves a token file; `dns`
        /// publishes a TXT record (needs a server built with `domain-verify-dns`).
        #[arg(long, default_value = "http")]
        method: String,
        /// Managed-DNS provider (e.g. `cloudflare`, `digitalocean`, `route53`).
        /// When set, boatramp publishes the `_boatramp-verify` TXT for you
        /// (credentials from the environment; needs a build with `acme-dns`),
        /// waits for it to resolve, and attaches — no manual DNS edit. Implies
        /// `--method dns` and writes only the `_boatramp-verify` TXT, never the
        /// host's A/CNAME (that stays an explicit, post-verify step).
        #[arg(long)]
        provider: Option<String>,
        /// Only start the challenge and print instructions — skip the immediate
        /// verify+attach. Use when the host doesn't resolve here yet.
        #[arg(long)]
        no_wait: bool,
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
        DomainCommand::Add {
            host,
            method,
            provider,
            no_wait,
        } => {
            // A managed-DNS provider does the whole dance (publish TXT → poll →
            // attach) itself.
            if let Some(provider) = provider.as_deref() {
                return add_auto(&http, &server, &site, &host, Some(provider)).await;
            }
            let verification =
                client::start_domain_verification(&http, &server, &site, &host, Some(&method))
                    .await?;
            if verification.verified {
                // Ownership already proven earlier — (re)attach it now.
                let result =
                    client::check_domain_verification(&http, &server, &site, &host).await?;
                if result.attached {
                    println!("{host} is already verified and attached to {site}");
                } else {
                    println!("{host} is already verified for {site}");
                    println!("run `boatramp domain verify {host}` to attach it");
                }
                return Ok(());
            }
            println!("started {} verification for {host}\n", verification.method);
            println!("{}", verification.instructions());

            // Auto-continue only when there's no manual step left: an HTTP
            // challenge for a host that already resolves here is served by this
            // server, so a single `domain add` verifies + attaches. A DNS
            // challenge (or `--no-wait`) always has a manual publish step, so we
            // stop after printing the instructions.
            let http_self_serve =
                verification.method == boatramp_core::domain_verify::VerificationMethod::Http;
            if no_wait || !http_self_serve {
                println!("\nthen run `boatramp domain verify {host}`");
                return Ok(());
            }
            println!("\nchecking whether {host} already resolves here…");
            match client::check_domain_verification(&http, &server, &site, &host).await {
                Ok(result) if result.passed && result.attached => {
                    println!("✓ verified {host} and attached it to {site}");
                }
                Ok(result) if result.passed => {
                    println!("✓ verified {host}; run `boatramp domain verify {host}` to attach");
                }
                Ok(result) => {
                    let detail = result
                        .detail
                        .unwrap_or_else(|| "not reachable here yet".into());
                    println!("not verified yet ({detail})");
                    println!("complete the step above, then run `boatramp domain verify {host}`");
                }
                // A probe/transport error before the host is set up is expected —
                // guide the operator on rather than failing the command.
                Err(_) => {
                    println!("not reachable here yet");
                    println!("complete the step above, then run `boatramp domain verify {host}`");
                }
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

/// The `--provider` verification dance: publish the DNS-TXT challenge through the
/// provider, poll the server's ownership check until the record resolves, and
/// attach. It writes **only** the `_boatramp-verify` TXT — never the host's
/// A/CNAME — so ownership is proven before anything is pointed at this server.
#[cfg(feature = "acme-dns")]
async fn add_auto(
    http: &crate::client::ApiClient,
    server: &str,
    site: &str,
    host: &str,
    provider: Option<&str>,
) -> Result<()> {
    use std::time::Duration;

    use boatramp_acme::{DnsRecord, RecordKind};
    use clap::ValueEnum;

    use crate::acme_dns::{build_provider, DnsProviderKind};

    let provider_name = provider
        .ok_or_else(|| Error::Auto("missing `--provider <name>` (e.g. cloudflare)".into()))?;
    let kind = DnsProviderKind::from_str(provider_name, true)
        .map_err(|e| Error::Auto(format!("unknown --provider `{provider_name}`: {e}")))?;

    // `--auto` publishes a DNS TXT, so it is always the `dns` method.
    let verification =
        client::start_domain_verification(http, server, site, host, Some("dns")).await?;
    if verification.verified {
        println!("{host} is already verified for {site}; run `domain verify {host}` to attach");
        return Ok(());
    }

    let provider = build_provider(kind).await?;
    let record = DnsRecord {
        kind: RecordKind::Txt,
        name: verification.dns_record_name(),
        value: verification.token.clone(),
        ttl: 60,
    };
    provider.upsert(&record).await?;
    println!(
        "published {} TXT for {host}; waiting for it to resolve...",
        verification.dns_record_name()
    );

    // Poll the server-side ownership check while the TXT propagates.
    const ATTEMPTS: usize = 10;
    const EVERY_SECS: u64 = 5;
    for attempt in 1..=ATTEMPTS {
        let result = client::check_domain_verification(http, server, site, host).await?;
        if result.passed {
            if result.attached {
                println!("verified {host} and attached it to {site}");
            } else {
                println!("verified {host} (run `domain verify {host}` to attach)");
            }
            // Ownership is recorded server-side now; retract the challenge TXT.
            let _ = provider.delete(&record).await;
            return Ok(());
        }
        if attempt < ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(EVERY_SECS)).await;
        }
    }

    // Timed out: leave the TXT so a later `domain verify` still succeeds.
    Err(Error::Auto(format!(
        "published the challenge but it did not resolve within {}s — DNS may still \
         be propagating; re-run `boatramp domain verify {host}` shortly",
        ATTEMPTS as u64 * EVERY_SECS
    )))
}

/// Without the `acme-dns` feature there is no bundled DNS provider to publish the
/// challenge with, so `--provider` is unavailable.
#[cfg(not(feature = "acme-dns"))]
async fn add_auto(
    _http: &crate::client::ApiClient,
    _server: &str,
    _site: &str,
    _host: &str,
    _provider: Option<&str>,
) -> Result<()> {
    Err(Error::Auto(
        "`--provider` requires a build with `--features acme-dns`".into(),
    ))
}

/// List attached hostnames plus any started-but-not-yet-attached verifications.
async fn ls(http: &crate::client::ApiClient, server: &str, site: &str) -> Result<()> {
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
