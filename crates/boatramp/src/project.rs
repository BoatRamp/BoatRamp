//! The `project` subcommand (0.2.0): manage **projects** — the owning Workspace above
//! sites/functions/compute. `create` / `ls` / `show` / `rm` over the control-plane
//! `/api/projects` surface. Scoping *other* commands to a project is the global
//! `--project` flag (resolved in `main`), not here.

use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `project` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// Serializing the create request failed.
    #[error("serializing the project request failed: {0}")]
    Serde(#[from] serde_json::Error),
}

/// `project` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp project`.
#[derive(Debug, clap::Args)]
pub struct ProjectArgs {
    /// boatramp server base URL (overrides `[deploy].server`).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: ProjectCommand,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    /// Create a new project.
    Create {
        /// The project slug (unique, no `/`).
        name: String,
        /// Human display name (defaults to the slug).
        #[arg(long)]
        display: Option<String>,
        /// Free-text description.
        #[arg(long)]
        description: Option<String>,
        /// Default region for the project's compute/replicas.
        #[arg(long)]
        region: Option<String>,
    },
    /// List all projects.
    Ls,
    /// Show one project's full record.
    Show {
        /// The project slug.
        name: String,
    },
    /// Delete an **empty** project (refused while it owns resources or is `default`).
    Rm {
        /// The project slug.
        name: String,
    },
}

/// Entry point for `boatramp project`.
pub async fn run(args: ProjectArgs, config: &ProjectConfig) -> Result<()> {
    let (server, http) = client::connect(args.server, config)?;
    // The `project` subcommand only calls project-collection endpoints (list/create/
    // get/delete), which are not site-scoped, so the resolved project is inert here —
    // passed only to satisfy the constructor.
    let cp = client::ControlPlane::new(server, http, client::resolve_project(config));

    match args.command {
        ProjectCommand::Create {
            name,
            display,
            description,
            region,
        } => {
            let mut body = serde_json::Map::new();
            body.insert("name".into(), serde_json::Value::String(name.clone()));
            if let Some(d) = display {
                body.insert("display".into(), serde_json::Value::String(d));
            }
            if let Some(d) = description {
                body.insert("description".into(), serde_json::Value::String(d));
            }
            if let Some(r) = region {
                body.insert("region".into(), serde_json::Value::String(r));
            }
            cp.create_project(&serde_json::Value::Object(body)).await?;
            println!("created project `{name}`");
        }
        ProjectCommand::Ls => {
            let projects = cp.list_projects().await?;
            if projects.is_empty() {
                println!("no projects");
            } else {
                for p in projects {
                    let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                    let display = p
                        .get("meta")
                        .and_then(|m| m.get("display"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty());
                    match display {
                        Some(d) => println!("{name}\t{d}"),
                        None => println!("{name}"),
                    }
                }
            }
        }
        ProjectCommand::Show { name } => {
            let project = cp.get_project(&name).await?;
            println!("{}", serde_json::to_string_pretty(&project)?);
        }
        ProjectCommand::Rm { name } => {
            cp.delete_project(&name).await?;
            println!("deleted project `{name}`");
        }
    }
    Ok(())
}
