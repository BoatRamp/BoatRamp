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
    /// Rendering `--json` output failed.
    #[error("rendering the database view failed: {0}")]
    Render(#[source] serde_json::Error),
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

    /// Emit raw JSON instead of a human table.
    #[arg(long, global = true)]
    json: bool,

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
    boatramp_core::project::validate_resource_name("database", name)
        .map_err(|e| Error::InvalidName(e.to_string()))
}

/// Entry point for `boatramp db`.
pub async fn run(args: DbArgs, config: &ProjectConfig) -> Result<()> {
    let (server, http) = client::connect(args.server.clone(), config)?;
    let project = client::resolve_project(config);
    let cp = ControlPlane::new(server, http, project);
    match args.command {
        DbCommand::Ls => ls(&cp, args.json).await,
        DbCommand::Get { name } => {
            validate_name(&name)?;
            get(&cp, &name, args.json).await
        }
        DbCommand::Status { name } => {
            validate_name(&name)?;
            status(&cp, &name, args.json).await
        }
    }
}

/// `db ls` — list the declared managed databases.
async fn ls(cp: &ControlPlane, json: bool) -> Result<()> {
    let dbs = cp.list_databases().await?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&dbs).map_err(Error::Render)?
        );
        return Ok(());
    }
    if dbs.is_empty() {
        println!("no declared managed databases in this project");
        return Ok(());
    }
    print_header();
    for db in &dbs {
        print_row(db);
    }
    Ok(())
}

/// `db get <name>` — show one declaration.
async fn get(cp: &ControlPlane, name: &str, json: bool) -> Result<()> {
    let db = cp.get_database(name).await?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&db).map_err(Error::Render)?
        );
        return Ok(());
    }
    print_header();
    print_row(&db);
    Ok(())
}

/// `db status <name>` — the read-only status view (declaration + derived workload).
async fn status(cp: &ControlPlane, name: &str, json: bool) -> Result<()> {
    let view = cp.database_status(name).await?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&view).map_err(Error::Render)?
        );
        return Ok(());
    }
    let workload = view.get("workload").and_then(|v| v.as_str()).unwrap_or("?");
    println!("database `{name}`");
    println!("  server workload: {workload}");
    println!("  declared:        yes");
    Ok(())
}

/// The human table header (shared by `ls` and `get`).
fn print_header() {
    let (name, kind, tenant, scope, size) = ("NAME", "KIND", "TENANT", "SCOPE", "SIZE");
    println!("{name:<24}  {kind:<10}  {tenant:<8}  {scope:<8}  {size}");
}

/// One human table row for a declared database.
fn print_row(db: &ApplyDatabase) {
    println!(
        "{:<24}  {:<10}  {:<8}  {:<8}  {:?}",
        db.name,
        format!("{:?}", db.kind).to_lowercase(),
        format!("{:?}", db.tenant).to_lowercase(),
        format!("{:?}", db.tenant_scope).to_lowercase(),
        db.size,
    );
}
