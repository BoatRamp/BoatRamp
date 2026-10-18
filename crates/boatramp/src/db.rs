//! `boatramp db` — a **read-only** client for the declarative managed-database surface
//! (v0.6.0, #501 Stage B).
//!
//! `db ls | get <name> | status <name>` inspect the project's declared managed
//! databases. There is deliberately **NO `db create`** — the manifest `databases:`
//! block is the SOLE authoring surface (a create verb would compete as a second source
//! of truth). To declare / provision a managed database, add a `databases:` entry to
//! `apply.cfg` and run `boatramp apply`. Every declare/provision is `Project·Admin`
//! (server-gated); these read verbs are `Project·Read`.

use boatramp_core::compute::ApplyDatabase;

use crate::client::{self, ControlPlane};
use crate::config::ProjectConfig;

/// A failure in `boatramp db`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// Resolving the server / building the client failed.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// The `<name>` is not a safe URL path segment (validated client-side).
    #[error("{0}")]
    InvalidName(String),
}

/// `db` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// `boatramp db …` — inspect the project's declared managed databases (read-only).
#[derive(Debug, clap::Args)]
pub struct DbArgs {
    /// boatramp server base URL (overrides `[publish].server`).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: DbCommand,
}

/// The `db` subcommands — READ-ONLY only (no `create`; the manifest is the authoring
/// surface).
#[derive(Debug, clap::Subcommand)]
enum DbCommand {
    /// List the project's declared managed databases.
    Ls,
    /// Show one declared managed database's declaration.
    Get {
        /// The database binding name.
        name: String,
    },
    /// Show one declared managed database's read-only status (declaration + derived
    /// server workload handle).
    Status {
        /// The database binding name.
        name: String,
    },
}

/// Validate a `<name>` through the one canonical resource-identifier validator
/// (`kind = "database"`) before it is threaded into the request URL — the same rule the
/// server enforces — so a malformed name fails fast rather than an opaque server error.
fn validate_name(name: &str) -> Result<()> {
    boatramp_core::project::validate_resource_name("database", name).map_err(|e| {
        Error::InvalidName(format!(
            "{e}; {}",
            boatramp_core::project::INVALID_NAME_CURE
        ))
    })
}

/// The result of a `boatramp db` subcommand, rendered by [`crate::output`].
///
/// Each variant carries the actual declaration(s): the human view is a table, and
/// `--output-format json` serializes them structurally.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum DbOutput {
    /// `db ls` — the project's declared managed databases.
    Ls { databases: Vec<ApplyDatabase> },
    /// `db get <name>` — one declaration.
    // Boxed to keep this larger payload from dwarfing the other variants.
    Get { database: Box<ApplyDatabase> },
    /// `db status <name>` — the read-only status view (declaration + derived workload).
    Status {
        name: String,
        view: serde_json::Value,
    },
}

impl crate::output::Rendered for DbOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Ls { databases } => {
                if databases.is_empty() {
                    return writeln!(w, "no declared managed databases in this project");
                }
                write_header(w)?;
                for db in databases {
                    write_row(w, db)?;
                }
                Ok(())
            }
            Self::Get { database } => {
                write_header(w)?;
                write_row(w, database)
            }
            Self::Status { name, view } => {
                let workload = view.get("workload").and_then(|v| v.as_str()).unwrap_or("?");
                writeln!(w, "database `{name}`")?;
                writeln!(w, "  server workload: {workload}")?;
                writeln!(w, "  declared:        yes")
            }
        }
    }
}

/// Entry point for `boatramp db`.
pub async fn run(args: DbArgs, config: &ProjectConfig) -> Result<DbOutput> {
    let (server, http) = client::connect(args.server.clone(), config)?;
    let project = client::resolve_project(config);
    let cp = ControlPlane::new(server, http, project);
    match args.command {
        DbCommand::Ls => ls(&cp).await,
        DbCommand::Get { name } => {
            validate_name(&name)?;
            get(&cp, &name).await
        }
        DbCommand::Status { name } => {
            validate_name(&name)?;
            status(&cp, &name).await
        }
    }
}

/// `db ls` — list the declared managed databases.
async fn ls(cp: &ControlPlane) -> Result<DbOutput> {
    let databases = cp.list_databases().await?;
    Ok(DbOutput::Ls { databases })
}

/// `db get <name>` — show one declaration.
async fn get(cp: &ControlPlane, name: &str) -> Result<DbOutput> {
    let db = cp.get_database(name).await?;
    Ok(DbOutput::Get {
        database: Box::new(db),
    })
}

/// `db status <name>` — the read-only status view (declaration + derived workload).
async fn status(cp: &ControlPlane, name: &str) -> Result<DbOutput> {
    let view = cp.database_status(name).await?;
    Ok(DbOutput::Status {
        name: name.to_string(),
        view,
    })
}

/// The human table header (shared by `ls` and `get`).
fn write_header(w: &mut dyn std::io::Write) -> std::io::Result<()> {
    let (name, kind, tenant, scope, size) = ("NAME", "KIND", "TENANT", "SCOPE", "SIZE");
    writeln!(w, "{name:<24}  {kind:<10}  {tenant:<8}  {scope:<8}  {size}")
}

/// One human table row for a declared database.
fn write_row(w: &mut dyn std::io::Write, db: &ApplyDatabase) -> std::io::Result<()> {
    writeln!(
        w,
        "{:<24}  {:<10}  {:<8}  {:<8}  {:?}",
        db.name,
        format!("{:?}", db.kind).to_lowercase(),
        format!("{:?}", db.tenant).to_lowercase(),
        format!("{:?}", db.tenant_scope).to_lowercase(),
        db.size,
    )
}
