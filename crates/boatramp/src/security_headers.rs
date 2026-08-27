//! The `security-headers` subcommand: a site's response security policy
//! (`SiteConfig.security`) — HTTPS redirect, HSTS, CSP, and X-Frame-Options. This is
//! the **site**'s edge headers, distinct from `boatramp security` (the operator
//! posture). Edited over the control-plane API.

use boatramp_core::config::Hsts;
use clap::{Subcommand, ValueEnum};

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `security-headers` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the target or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
}

type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp security-headers`.
#[derive(Debug, clap::Args)]
pub struct SecurityHeadersArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    /// Site to edit (overrides [deploy].site).
    #[arg(long, env = "BOATRAMP_SITE", global = true)]
    site: Option<String>,

    #[command(subcommand)]
    command: SecurityHeadersCommand,
}

#[derive(Debug, Clone, ValueEnum)]
enum Toggle {
    On,
    Off,
}

#[derive(Debug, Subcommand)]
enum SecurityHeadersCommand {
    /// Show the site's current security-header policy.
    Show,
    /// Turn the HTTP→HTTPS redirect on or off.
    HttpsRedirect {
        /// `on` or `off`.
        state: Toggle,
    },
    /// Configure HSTS (`Strict-Transport-Security`).
    Hsts {
        #[command(subcommand)]
        command: HstsCommand,
    },
    /// Configure the `Content-Security-Policy` header.
    Csp {
        #[command(subcommand)]
        command: CspCommand,
    },
    /// Configure the `X-Frame-Options` header.
    FrameOptions {
        #[command(subcommand)]
        command: FrameCommand,
    },
}

#[derive(Debug, Subcommand)]
enum HstsCommand {
    /// Enable HSTS with the given max-age (and optional subdomain/preload flags).
    Set {
        /// `max-age` seconds (e.g. 31536000 for a year).
        #[arg(long, default_value_t = 31_536_000)]
        max_age: u64,
        /// Add `includeSubDomains`.
        #[arg(long)]
        include_subdomains: bool,
        /// Add `preload` (implies you meet the preload-list requirements).
        #[arg(long)]
        preload: bool,
    },
    /// Remove the HSTS header.
    Off,
}

#[derive(Debug, Subcommand)]
enum CspCommand {
    /// Set the Content-Security-Policy value.
    Set {
        /// The policy string (e.g. `default-src 'self'`).
        policy: String,
    },
    /// Remove the CSP header.
    Clear,
}

#[derive(Debug, Subcommand)]
enum FrameCommand {
    /// Set X-Frame-Options (`DENY` or `SAMEORIGIN`).
    Set {
        /// Header value.
        value: String,
    },
    /// Remove the X-Frame-Options header.
    Clear,
}

/// Entry point for `boatramp security-headers`.
pub async fn run(args: SecurityHeadersArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    let mut site_config = cp.fetch_site_config(&site).await?;
    let security = &mut site_config.security;

    match args.command {
        SecurityHeadersCommand::Show => {
            println!("security headers for {site}:");
            println!("  https_redirect: {}", security.https_redirect);
            match &security.hsts {
                None => println!("  hsts: off"),
                Some(h) => println!(
                    "  hsts: max-age={} include_subdomains={} preload={}",
                    h.max_age, h.include_subdomains, h.preload
                ),
            }
            println!("  csp: {}", security.csp.as_deref().unwrap_or("(unset)"));
            println!(
                "  frame_options: {}",
                security.frame_options.as_deref().unwrap_or("(unset)")
            );
            return Ok(());
        }
        SecurityHeadersCommand::HttpsRedirect { state } => {
            security.https_redirect = matches!(state, Toggle::On);
            println!(
                "https redirect {} for {site}",
                onoff(security.https_redirect)
            );
        }
        SecurityHeadersCommand::Hsts { command } => match command {
            HstsCommand::Set {
                max_age,
                include_subdomains,
                preload,
            } => {
                security.hsts = Some(Hsts {
                    max_age,
                    include_subdomains,
                    preload,
                });
                println!("hsts set for {site} (max-age {max_age})");
            }
            HstsCommand::Off => {
                security.hsts = None;
                println!("hsts off for {site}");
            }
        },
        SecurityHeadersCommand::Csp { command } => match command {
            CspCommand::Set { policy } => {
                security.csp = Some(policy);
                println!("csp set for {site}");
            }
            CspCommand::Clear => {
                security.csp = None;
                println!("csp cleared for {site}");
            }
        },
        SecurityHeadersCommand::FrameOptions { command } => match command {
            FrameCommand::Set { value } => {
                security.frame_options = Some(value.clone());
                println!("frame-options set to {value} for {site}");
            }
            FrameCommand::Clear => {
                security.frame_options = None;
                println!("frame-options cleared for {site}");
            }
        },
    }

    cp.put_site_config(&site, &site_config).await?;
    Ok(())
}

/// Render a bool as `on`/`off`.
fn onoff(v: bool) -> &'static str {
    if v {
        "on"
    } else {
        "off"
    }
}
