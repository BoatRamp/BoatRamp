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

/// The result of a `security-headers` subcommand, rendered by [`crate::output`].
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum SecurityHeadersOutput {
    /// `security-headers show` — the site's current policy.
    Show {
        site: String,
        https_redirect: bool,
        hsts: Option<Hsts>,
        csp: Option<String>,
        frame_options: Option<String>,
    },
    /// The HTTP→HTTPS redirect was toggled.
    HttpsRedirect { site: String, enabled: bool },
    /// HSTS was enabled with the given parameters.
    HstsSet {
        site: String,
        max_age: u64,
        include_subdomains: bool,
        preload: bool,
    },
    /// HSTS was removed.
    HstsOff { site: String },
    /// The Content-Security-Policy was set.
    CspSet { site: String },
    /// The Content-Security-Policy was removed.
    CspCleared { site: String },
    /// X-Frame-Options was set.
    FrameOptionsSet { site: String, value: String },
    /// X-Frame-Options was removed.
    FrameOptionsCleared { site: String },
}

impl crate::output::Rendered for SecurityHeadersOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Show {
                site,
                https_redirect,
                hsts,
                csp,
                frame_options,
            } => {
                writeln!(w, "security headers for {site}:")?;
                writeln!(w, "  https_redirect: {https_redirect}")?;
                match hsts {
                    None => writeln!(w, "  hsts: off")?,
                    Some(h) => writeln!(
                        w,
                        "  hsts: max-age={} include_subdomains={} preload={}",
                        h.max_age, h.include_subdomains, h.preload
                    )?,
                }
                writeln!(w, "  csp: {}", csp.as_deref().unwrap_or("(unset)"))?;
                writeln!(
                    w,
                    "  frame_options: {}",
                    frame_options.as_deref().unwrap_or("(unset)")
                )
            }
            Self::HttpsRedirect { site, enabled } => {
                writeln!(w, "https redirect {} for {site}", onoff(*enabled))
            }
            Self::HstsSet { site, max_age, .. } => {
                writeln!(w, "hsts set for {site} (max-age {max_age})")
            }
            Self::HstsOff { site } => writeln!(w, "hsts off for {site}"),
            Self::CspSet { site } => writeln!(w, "csp set for {site}"),
            Self::CspCleared { site } => writeln!(w, "csp cleared for {site}"),
            Self::FrameOptionsSet { site, value } => {
                writeln!(w, "frame-options set to {value} for {site}")
            }
            Self::FrameOptionsCleared { site } => {
                writeln!(w, "frame-options cleared for {site}")
            }
        }
    }
}

/// Entry point for `boatramp security-headers`.
pub async fn run(
    args: SecurityHeadersArgs,
    config: &ProjectConfig,
) -> Result<SecurityHeadersOutput> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    let mut site_config = cp.fetch_site_config(&site).await?;
    let security = &mut site_config.security;

    let out = match args.command {
        SecurityHeadersCommand::Show => {
            // Read-only; no write-back.
            return Ok(SecurityHeadersOutput::Show {
                https_redirect: security.https_redirect,
                hsts: security.hsts.clone(),
                csp: security.csp.clone(),
                frame_options: security.frame_options.clone(),
                site,
            });
        }
        SecurityHeadersCommand::HttpsRedirect { state } => {
            security.https_redirect = matches!(state, Toggle::On);
            SecurityHeadersOutput::HttpsRedirect {
                site: site.clone(),
                enabled: security.https_redirect,
            }
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
                SecurityHeadersOutput::HstsSet {
                    site: site.clone(),
                    max_age,
                    include_subdomains,
                    preload,
                }
            }
            HstsCommand::Off => {
                security.hsts = None;
                SecurityHeadersOutput::HstsOff { site: site.clone() }
            }
        },
        SecurityHeadersCommand::Csp { command } => match command {
            CspCommand::Set { policy } => {
                security.csp = Some(policy);
                SecurityHeadersOutput::CspSet { site: site.clone() }
            }
            CspCommand::Clear => {
                security.csp = None;
                SecurityHeadersOutput::CspCleared { site: site.clone() }
            }
        },
        SecurityHeadersCommand::FrameOptions { command } => match command {
            FrameCommand::Set { value } => {
                security.frame_options = Some(value.clone());
                SecurityHeadersOutput::FrameOptionsSet {
                    site: site.clone(),
                    value,
                }
            }
            FrameCommand::Clear => {
                security.frame_options = None;
                SecurityHeadersOutput::FrameOptionsCleared { site: site.clone() }
            }
        },
    };

    cp.put_site_config(&site, &site_config).await?;
    Ok(out)
}

/// Render a bool as `on`/`off`.
fn onoff(v: bool) -> &'static str {
    if v { "on" } else { "off" }
}
