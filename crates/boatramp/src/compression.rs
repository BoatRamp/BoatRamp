//! The `compression` subcommand: turn on/off on-the-fly response compression for a
//! site (`SiteConfig.compression`), edited over the control-plane API.

use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `compression` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the target or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
}

type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp compression`.
#[derive(Debug, clap::Args)]
pub struct CompressionArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    /// Site to edit (overrides [deploy].site).
    #[arg(long, env = "BOATRAMP_SITE", global = true)]
    site: Option<String>,

    #[command(subcommand)]
    command: CompressionCommand,
}

#[derive(Debug, Subcommand)]
enum CompressionCommand {
    /// Show the site's current compression policy.
    Show,
    /// Enable on-the-fly response compression.
    On {
        /// Only compress responses at least this many bytes.
        #[arg(long)]
        min_size: Option<u64>,
    },
    /// Disable response compression.
    Off,
}

/// The result of a `compression` subcommand, rendered by [`crate::output`].
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CompressionOutput {
    /// `compression show` — the site's current policy.
    Show {
        site: String,
        enabled: bool,
        min_size: u64,
    },
    /// Compression was enabled for the site.
    On { site: String, min_size: u64 },
    /// Compression was disabled for the site.
    Off { site: String },
}

impl crate::output::Rendered for CompressionOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Show {
                site,
                enabled,
                min_size,
            } => {
                if *enabled {
                    writeln!(w, "compression: on for {site} (min_size {min_size} bytes)")
                } else {
                    writeln!(w, "compression: off for {site}")
                }
            }
            Self::On { site, min_size } => {
                writeln!(w, "compression on for {site} (min_size {min_size} bytes)")
            }
            Self::Off { site } => writeln!(w, "compression off for {site}"),
        }
    }
}

/// Entry point for `boatramp compression`.
pub async fn run(args: CompressionArgs, config: &ProjectConfig) -> Result<CompressionOutput> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    let mut site_config = cp.fetch_site_config(&site).await?;

    let out = match args.command {
        CompressionCommand::Show => {
            // Read-only; no write-back.
            let c = &site_config.compression;
            return Ok(CompressionOutput::Show {
                enabled: c.enabled,
                min_size: c.min_size,
                site,
            });
        }
        CompressionCommand::On { min_size } => {
            site_config.compression.enabled = true;
            if let Some(n) = min_size {
                site_config.compression.min_size = n;
            }
            CompressionOutput::On {
                site: site.clone(),
                min_size: site_config.compression.min_size,
            }
        }
        CompressionCommand::Off => {
            site_config.compression.enabled = false;
            CompressionOutput::Off { site: site.clone() }
        }
    };

    cp.put_site_config(&site, &site_config).await?;
    Ok(out)
}
