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

/// Entry point for `boatramp compression`.
pub async fn run(args: CompressionArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    let mut site_config = cp.fetch_site_config(&site).await?;

    match args.command {
        CompressionCommand::Show => {
            let c = &site_config.compression;
            if c.enabled {
                println!("compression: on for {site} (min_size {} bytes)", c.min_size);
            } else {
                println!("compression: off for {site}");
            }
            return Ok(());
        }
        CompressionCommand::On { min_size } => {
            site_config.compression.enabled = true;
            if let Some(n) = min_size {
                site_config.compression.min_size = n;
            }
            println!(
                "compression on for {site} (min_size {} bytes)",
                site_config.compression.min_size
            );
        }
        CompressionCommand::Off => {
            site_config.compression.enabled = false;
            println!("compression off for {site}");
        }
    }

    cp.put_site_config(&site, &site_config).await?;
    Ok(())
}
