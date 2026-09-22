//! `boatramp sql` — operator SQL access to a **managed** database: apply a
//! migration script (`exec`) or run a single query (`query`). The server connects
//! using the database's sealed managed credential (resolved server-side — the
//! credential never reaches the client) and runs the SQL; admin-scoped.

use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// `sql` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// A `boatramp sql` failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the server target from flags/config failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// A control-plane HTTP request failed.
    #[error("control-plane request: {0}")]
    Http(#[from] reqwest::Error),
    /// (De)serializing JSON failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Reading the script file / stdin failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The control-plane returned an error response.
    #[error("{0}")]
    Server(String),
    /// The `--db` name is not a safe URL path segment (validated client-side, before
    /// building the request URL, so a malformed name fails fast with a clear message
    /// instead of an opaque server error or a `//`-collapsed path).
    #[error("{0}")]
    InvalidDb(String),
}

/// Validate a `--db` name through the one canonical resource-identifier validator
/// (`kind = "database"`) before it is threaded into the control-plane URL. Rejects an
/// empty/`//`-collapsing or path-separator-bearing name with the same rule the server
/// and config load enforce.
fn validate_db(db: &str) -> Result<()> {
    boatramp_core::project::validate_resource_name("database", db)
        .map_err(|err| Error::InvalidDb(err.to_string()))
}

/// Arguments for `boatramp sql`.
#[derive(Debug, clap::Args)]
pub struct SqlArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: SqlCommand,
}

#[derive(Debug, Subcommand)]
enum SqlCommand {
    /// Apply a migration **script** (multiple statements — `CREATE EXTENSION`,
    /// tables, RLS, chained DDL/DML) to a managed database. Reads from `--file` or
    /// standard input.
    Exec {
        /// The database binding name (`default` = the project's default database).
        #[arg(long, default_value = boatramp_core::project::DEFAULT_DB_NAME)]
        db: String,
        /// Read the script from this file instead of standard input.
        #[arg(long)]
        file: Option<std::path::PathBuf>,
    },
    /// Run one row-returning query against a managed database and print the result.
    Query {
        /// The SQL query (a single statement).
        sql: String,
        /// The database binding name (`default` = the project's default database).
        #[arg(long, default_value = boatramp_core::project::DEFAULT_DB_NAME)]
        db: String,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },
    /// Actively probe each replica of a managed database — a TCP reachability check
    /// that BYPASSES the stored-health gate `query` trips on. Distinguishes "the DB is
    /// actually down" from "the DB is up but the resolver won't serve it"
    /// (`REACHABLE=yes` + `HEALTHY=no`). Admin-scoped.
    Ping {
        /// The database binding name (`default` = the project's default database).
        #[arg(long, default_value = boatramp_core::project::DEFAULT_DB_NAME)]
        db: String,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Format {
    /// A bordered text table.
    Table,
    /// The raw `{columns, rows}` JSON.
    Json,
}

/// Entry point for `boatramp sql`.
pub async fn run(args: SqlArgs, config: &ProjectConfig) -> Result<()> {
    let server = client::resolve_server(args.server, config)?;
    let http = client::http_client(client::token(config).as_deref());
    // Honor the global `--project`: operator SQL is project-owned, so target
    // `projects/<proj>/sql` (or bare `sql` for the default project) — otherwise a
    // per-tenant managed DB under a non-default project can't be reached.
    let seg = client::project_seg(&client::resolve_project(config), "sql");

    match args.command {
        SqlCommand::Exec { db, file } => {
            validate_db(&db)?;
            let sql = match file {
                Some(path) => std::fs::read_to_string(path)?,
                None => {
                    use std::io::Read;
                    let mut s = String::new();
                    std::io::stdin().read_to_string(&mut s)?;
                    s
                }
            };
            let resp = http
                .post(format!("{server}/api/{seg}/{db}/exec"))
                .json(&serde_json::json!({ "sql": sql }))
                .send()
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(Error::Server(format!(
                    "sql exec failed: {status}: {}",
                    text.trim()
                )));
            }
            eprintln!("ok");
        }
        SqlCommand::Query { db, sql, format } => {
            validate_db(&db)?;
            let resp = http
                .post(format!("{server}/api/{seg}/{db}/query"))
                .json(&serde_json::json!({ "sql": sql }))
                .send()
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(Error::Server(format!(
                    "sql query failed: {status}: {}",
                    text.trim()
                )));
            }
            let out: serde_json::Value = resp.json().await?;
            match format {
                Format::Json => println!("{}", serde_json::to_string_pretty(&out)?),
                Format::Table => print_table(&out),
            }
        }
        SqlCommand::Ping { db } => {
            validate_db(&db)?;
            let resp = http
                .post(format!("{server}/api/{seg}/{db}/ping"))
                .send()
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(Error::Server(format!(
                    "sql ping failed: {status}: {}",
                    text.trim()
                )));
            }
            let replicas: Vec<serde_json::Value> = resp.json().await?;
            if replicas.is_empty() {
                println!("no replicas (the managed database has no compute replicas yet)");
                return Ok(());
            }
            println!(
                "{:<21}  {:<9}  {:<7}  PHASE",
                "ENDPOINT", "REACHABLE", "HEALTHY"
            );
            for r in &replicas {
                let endpoint = r["endpoint"].as_str().unwrap_or("?");
                let reachable = if r["tcp_reachable"].as_bool().unwrap_or(false) {
                    "yes"
                } else {
                    "NO"
                };
                let healthy = if r["healthy"].as_bool().unwrap_or(false) {
                    "yes"
                } else {
                    "NO"
                };
                let phase = r["phase"].as_str().unwrap_or("?");
                println!("{endpoint:<21}  {reachable:<9}  {healthy:<7}  {phase}");
            }
        }
    }
    Ok(())
}

/// Render a `{columns, rows}` query response as a bordered text table.
fn print_table(out: &serde_json::Value) {
    let headers: Vec<String> = out["columns"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|c| c.as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default();
    let mut widths: Vec<usize> = headers.iter().map(String::len).collect();
    let cells: Vec<Vec<String>> = out["rows"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|r| {
                    r.as_array()
                        .map(|cols| {
                            cols.iter()
                                .enumerate()
                                .map(|(i, v)| {
                                    let s = match v {
                                        serde_json::Value::String(s) => s.clone(),
                                        serde_json::Value::Null => String::new(),
                                        other => other.to_string(),
                                    };
                                    if i < widths.len() {
                                        widths[i] = widths[i].max(s.len());
                                    }
                                    s
                                })
                                .collect()
                        })
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default();

    let fmt_row = |vals: &[String]| -> String {
        vals.iter()
            .enumerate()
            .map(|(i, v)| format!("{:width$}", v, width = widths.get(i).copied().unwrap_or(0)))
            .collect::<Vec<_>>()
            .join(" | ")
    };
    println!("{}", fmt_row(&headers));
    println!(
        "{}",
        widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("-+-")
    );
    for row in &cells {
        println!("{}", fmt_row(row));
    }
    println!(
        "({} row{})",
        cells.len(),
        if cells.len() == 1 { "" } else { "s" }
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_db_accepts_default_and_rejects_unsafe_segments() {
        // The reserved default name and ordinary names pass; the legacy empty name and
        // any non-path-segment name fail client-side, before a URL is ever built.
        assert!(validate_db(boatramp_core::project::DEFAULT_DB_NAME).is_ok());
        assert!(validate_db("analytics").is_ok());
        for bad in ["", "a/b", "..", "a b", "proj*"] {
            assert!(validate_db(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn db_flag_defaults_to_the_reserved_default_name() {
        use clap::Parser;
        // A tiny harness mirroring how `main` wires `SqlArgs`, so the clap
        // `default_value` is exercised (it must be `default`, never `""`).
        #[derive(Parser)]
        struct Harness {
            #[command(subcommand)]
            command: SqlCommand,
        }
        let h = Harness::try_parse_from(["boatramp", "ping"]).expect("ping parses");
        match h.command {
            SqlCommand::Ping { db } => {
                assert_eq!(db, boatramp_core::project::DEFAULT_DB_NAME);
            }
            other => panic!("expected ping, got {other:?}"),
        }
    }
}
