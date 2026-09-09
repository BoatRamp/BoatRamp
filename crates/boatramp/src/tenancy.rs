//! The `tenancy` subcommand: manage a project's tenancy schema — the per-table
//! tenant-key map the host scope injector consults when scoping guest `sql`/`orm`
//! queries.
//!
//! The schema names each table's [`TableScope`](boatramp_core::tenancy::TableScope):
//! `tenant` (keyed on the project default tenant column), `tenant_keyed` (keyed on a
//! named column — e.g. the identity table on its own primary key), or `unscoped` (a
//! shared reference table, no tenant predicate). A table that appears in **no** entry
//! is **denied** — deny-by-default — so a query touching it is refused rather than
//! silently unscoped.
//!
//! Mutating the schema redraws the isolation boundary for every guest query, so the
//! server gates `apply`/`clear` at `Project·Admin` (never the deploy-grade publisher
//! right). Scoping follows the uniform project rule: the global `--project` /
//! `BOATRAMP_PROJECT` flag selects the tenant, exactly like `secrets` / `email`.
//!
//! The on-disk format is JSON (round-trips cleanly with `show`): `boatramp tenancy
//! show > schema.json`, edit, `boatramp tenancy apply schema.json`.

use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `tenancy` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the server / building the client failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// An HTTP request to the control plane failed (incl. a non-2xx status — e.g. a
    /// `403` when the token lacks `Project·Admin`).
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    /// Reading the schema file failed.
    #[error("reading schema file {path}: {source}")]
    Read {
        /// The path that could not be read.
        path: String,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The schema file was not valid JSON for a [`TenancySchema`].
    #[error("parsing schema file {path}: {source}")]
    Parse {
        /// The path whose contents did not parse.
        path: String,
        /// The underlying JSON error.
        #[source]
        source: serde_json::Error,
    },
    /// Serializing the fetched schema for display failed (should never happen).
    #[error("rendering schema: {0}")]
    Render(#[source] serde_json::Error),
}

/// `tenancy` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp tenancy`.
#[derive(Debug, clap::Args)]
pub struct TenancyArgs {
    /// boatramp server base URL (overrides [publish].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: TenancyCommand,
}

#[derive(Debug, Subcommand)]
enum TenancyCommand {
    /// Print the project's current tenancy schema as JSON. A project that declared
    /// none prints the default schema (`tenant_id`, no tables) — legacy single-column
    /// scoping.
    Show,
    /// Replace the project's tenancy schema from a JSON file (`Project·Admin`).
    Apply {
        /// Path to the schema JSON (as produced by `tenancy show`).
        file: std::path::PathBuf,
    },
    /// Clear the project's tenancy schema, reverting to legacy `Uniform` single-column
    /// scoping (`Project·Admin`). Idempotent.
    Clear,
}

/// Entry point for `boatramp tenancy`.
pub async fn run(args: TenancyArgs, config: &ProjectConfig) -> Result<()> {
    let (server, http) = client::connect(args.server.clone(), config)?;
    let project = client::resolve_project(config);
    let cp = client::ControlPlane::new(server, http, project.clone());

    match args.command {
        TenancyCommand::Show => {
            let schema = cp.get_project_tenancy().await?;
            let rendered = serde_json::to_string_pretty(&schema).map_err(Error::Render)?;
            println!("{rendered}");
        }
        TenancyCommand::Apply { file } => {
            let path = file.display().to_string();
            let bytes = std::fs::read(&file).map_err(|source| Error::Read {
                path: path.clone(),
                source,
            })?;
            let schema: boatramp_core::tenancy::TenancySchema = serde_json::from_slice(&bytes)
                .map_err(|source| Error::Parse {
                    path: path.clone(),
                    source,
                })?;
            cp.put_project_tenancy(&schema).await?;
            println!(
                "applied tenancy schema to project `{project}` ({} table(s))",
                schema.tables.len()
            );
        }
        TenancyCommand::Clear => {
            cp.clear_project_tenancy().await?;
            println!("cleared tenancy schema for project `{project}` (legacy Uniform scoping)");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// A minimal top-level parser mirroring `main`'s: the global `--project` flag +
    /// the `tenancy` subcommand, so we can arg-parse `boatramp tenancy …` in isolation.
    #[derive(Parser)]
    struct Cli {
        #[arg(long, global = true, env = "BOATRAMP_PROJECT")]
        project: Option<String>,
        #[command(subcommand)]
        cmd: Cmd,
    }
    #[derive(Subcommand)]
    enum Cmd {
        Tenancy(TenancyArgs),
    }

    fn parse(argv: &[&str]) -> std::result::Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("boatramp").chain(argv.iter().copied()))
    }

    #[test]
    fn subcommands_parse() {
        assert!(parse(&["tenancy", "show"]).is_ok());
        assert!(parse(&["tenancy", "apply", "schema.json"]).is_ok());
        assert!(parse(&["tenancy", "clear"]).is_ok());
        // `apply` needs a file argument.
        assert!(parse(&["tenancy", "apply"]).is_err());
    }

    #[test]
    fn the_global_project_flag_reaches_the_subcommand() {
        let cli = parse(&["tenancy", "--project", "acme", "show"]).expect("parses");
        assert_eq!(cli.project.as_deref(), Some("acme"));
        let cli = parse(&["tenancy", "show"]).expect("parses");
        assert_eq!(cli.project, None);
    }
}
