//! The `function` subcommand — the FaaS **function** surface (PLAN-faas).
//!
//! FA-1 ships the read view: list/show the derived site-scoped functions a site's
//! handlers/consumers/crons desugar to. `function invoke` / `deploy` land in
//! FA-3 / FA-7.

use serde::Deserialize;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `function` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum FunctionError {
    /// Resolving the target or a control-plane call failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// A control-plane HTTP request failed.
    #[error("control-plane request: {0}")]
    Http(#[from] reqwest::Error),
}

type Result<T> = std::result::Result<T, FunctionError>;

/// `function` — inspect the functions a site runs.
#[derive(Debug, clap::Args)]
pub struct FunctionArgs {
    #[command(subcommand)]
    command: FunctionCommand,
}

#[derive(Debug, clap::Subcommand)]
enum FunctionCommand {
    /// List functions (optionally for one site).
    Ls {
        /// Only this site.
        #[arg(long)]
        site: Option<String>,
        /// Server base URL (overrides config/env).
        #[arg(long)]
        server: Option<String>,
    },
    /// Show one function by its `<site>/<name>`.
    Get {
        /// The `<site>/<name>` shown by `function ls`.
        name: String,
        /// Server base URL (overrides config/env).
        #[arg(long)]
        server: Option<String>,
    },
}

/// A function as the server's `/api/functions` view reports it.
#[derive(Debug, Deserialize)]
struct FunctionSummary {
    name: String,
    runtime: String,
    version: String,
    triggers: Vec<String>,
}

/// Run the `function` subcommand.
pub async fn run(args: FunctionArgs, config: &ProjectConfig) -> Result<()> {
    match args.command {
        FunctionCommand::Ls { site, server } => {
            let funcs = fetch(server, site, config).await?;
            if funcs.is_empty() {
                println!("no functions");
                return Ok(());
            }
            for f in funcs {
                println!(
                    "{}  [{}]  {}  {}",
                    f.name,
                    f.runtime,
                    short(&f.version),
                    f.triggers.join(", ")
                );
            }
        }
        FunctionCommand::Get { name, server } => {
            let funcs = fetch(server, None, config).await?;
            match funcs.into_iter().find(|f| f.name == name) {
                Some(f) => {
                    println!("{}", f.name);
                    println!("  runtime: {}", f.runtime);
                    println!("  version: {}", f.version);
                    for t in &f.triggers {
                        println!("  trigger: {t}");
                    }
                }
                None => println!("no function {name:?}"),
            }
        }
    }
    Ok(())
}

/// Fetch the functions view (all sites, or one with `?site=`).
async fn fetch(
    server: Option<String>,
    site: Option<String>,
    config: &ProjectConfig,
) -> Result<Vec<FunctionSummary>> {
    let server = client::resolve_server(server, config)?;
    let http = client::http_client(client::token(config).as_deref());
    let url = match &site {
        Some(s) => format!("{server}/api/functions?site={s}"),
        None => format!("{server}/api/functions"),
    };
    Ok(http
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

/// Shorten a version id for display (drop the `sha256:` tag, keep 12 chars).
fn short(id: &str) -> &str {
    let id = id.strip_prefix("sha256:").unwrap_or(id);
    &id[..id.len().min(12)]
}
