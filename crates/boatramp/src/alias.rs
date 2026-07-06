//! The `alias` subcommand: manage named pointers (`staging`, `preview-pr-42`)
//! to deployments. Aliased deployments are retention-protected from `prune`.

use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `alias` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No deployment matched the supplied id or unique history prefix.
    #[error("no deployment matching {0}")]
    NoMatch(String),
    /// Resolving the target or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
}

/// `alias` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp alias`.
#[derive(Debug, clap::Args)]
pub struct AliasArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    /// Site to edit (overrides [deploy].site).
    #[arg(long, env = "BOATRAMP_SITE", global = true)]
    site: Option<String>,

    #[command(subcommand)]
    command: AliasCommand,
}

#[derive(Debug, Subcommand)]
enum AliasCommand {
    /// Point a named alias at a deployment id (or unique history prefix).
    Set {
        /// Alias name (e.g. `staging`).
        name: String,
        /// Deployment id, a unique history prefix, or a full content id.
        deployment: String,
    },
    /// Remove a named alias.
    Rm {
        /// Alias name to remove.
        name: String,
    },
    /// List the site's aliases.
    Ls,
}

/// Entry point for `boatramp alias`.
pub async fn run(args: AliasArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let http = client::http_client(client::token(config).as_deref());

    match args.command {
        AliasCommand::Ls => {
            let aliases = client::list_aliases(&http, &server, &site).await?;
            if aliases.is_empty() {
                println!("no aliases for {site}");
            }
            for (name, id) in &aliases {
                println!("{name}  ->  {}", short(id));
            }
        }
        AliasCommand::Set { name, deployment } => {
            // Resolve a history prefix to a full id so the server gets a real id.
            let list = client::fetch_deployments(&http, &server, &site).await?;
            let id =
                resolve_id(&list, &deployment).ok_or_else(|| Error::NoMatch(deployment.clone()))?;
            client::set_alias(&http, &server, &site, &name, &id).await?;
            println!("alias {name} -> {} for {site}", short(&id));
        }
        AliasCommand::Rm { name } => {
            client::remove_alias(&http, &server, &site, &name).await?;
            println!("removed alias {name} from {site}");
        }
    }
    Ok(())
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

/// Resolve a full id, a unique history prefix, or a full 64-hex content id.
fn resolve_id(list: &boatramp_core::deploy::DeploymentList, wanted: &str) -> Option<String> {
    if list.deployments.iter().any(|e| e.id == wanted) {
        return Some(wanted.to_string());
    }
    let mut matches = list.deployments.iter().filter(|e| e.id.starts_with(wanted));
    if let Some(first) = matches.next() {
        return matches.next().is_none().then(|| first.id.clone());
    }
    if wanted.len() == 64 && wanted.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(wanted.to_string());
    }
    None
}
