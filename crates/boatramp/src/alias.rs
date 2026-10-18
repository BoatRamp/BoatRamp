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

/// The result of an `alias` subcommand, rendered by [`crate::output`].
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum AliasOutput {
    /// `alias ls` — the site's named pointers (deployment ids full in JSON, shortened in the text).
    List {
        site: String,
        aliases: Vec<AliasEntry>,
    },
    /// An alias was set (or moved) to a deployment.
    Set {
        site: String,
        name: String,
        deployment: String,
    },
    /// An alias was removed.
    Removed { site: String, name: String },
}

/// One named pointer: `name -> deployment`.
#[derive(Debug, serde::Serialize)]
pub struct AliasEntry {
    pub name: String,
    pub deployment: String,
}

impl crate::output::Rendered for AliasOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::List { site, aliases } => {
                if aliases.is_empty() {
                    writeln!(w, "no aliases for {site}")?;
                }
                for a in aliases {
                    writeln!(w, "{}  ->  {}", a.name, short(&a.deployment))?;
                }
                Ok(())
            }
            Self::Set {
                site,
                name,
                deployment,
            } => writeln!(w, "alias {name} -> {} for {site}", short(deployment)),
            Self::Removed { site, name } => {
                writeln!(w, "removed alias {name} from {site}")
            }
        }
    }
}

/// Entry point for `boatramp alias`.
pub async fn run(args: AliasArgs, config: &ProjectConfig) -> Result<AliasOutput> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );

    let out = match args.command {
        AliasCommand::Ls => {
            let aliases = cp.list_aliases(&site).await?;
            AliasOutput::List {
                site,
                aliases: aliases
                    .into_iter()
                    .map(|(name, deployment)| AliasEntry { name, deployment })
                    .collect(),
            }
        }
        AliasCommand::Set { name, deployment } => {
            // Resolve a history prefix to a full id so the server gets a real id.
            let list = cp.fetch_deployments(&site).await?;
            let id =
                resolve_id(&list, &deployment).ok_or_else(|| Error::NoMatch(deployment.clone()))?;
            cp.set_alias(&site, &name, &id).await?;
            AliasOutput::Set {
                site,
                name,
                deployment: id,
            }
        }
        AliasCommand::Rm { name } => {
            cp.remove_alias(&site, &name).await?;
            AliasOutput::Removed { site, name }
        }
    };
    Ok(out)
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
