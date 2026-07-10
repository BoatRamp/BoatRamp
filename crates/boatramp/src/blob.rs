//! The `blob` subcommand: upload a file as a content-addressed blob and print
//! its hash. The general way to provision an artifact — a microVM kernel, a
//! prebuilt rootfs — that another command references by hash.

use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure running a `boatramp blob` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the server target from flags/config failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
}

/// `blob` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp blob`.
#[derive(Debug, clap::Args)]
pub struct BlobArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: BlobCommand,
}

#[derive(Debug, Subcommand)]
enum BlobCommand {
    /// Upload a file as a content-addressed blob; prints its hash (the key other
    /// commands reference, e.g. `compute set --kernel <hash>`).
    Put {
        /// File to upload.
        file: std::path::PathBuf,
    },
}

/// Entry point for `boatramp blob`.
pub async fn run(args: BlobArgs, config: &ProjectConfig) -> Result<()> {
    let server = client::resolve_server(args.server, config)?;
    let http = client::http_client(client::token(config).as_deref());

    match args.command {
        BlobCommand::Put { file } => {
            let hash = client::put_file_blob(&http, &server, &file).await?;
            println!("{hash}");
        }
    }
    Ok(())
}
