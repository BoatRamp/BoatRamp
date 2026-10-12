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
    /// Loading/parsing the `--node-config` failed (`sql rehome-default`, offline).
    #[error(transparent)]
    Config(#[from] boatramp_node::config::ConfigError),
    /// The offline default-scope libsql re-home (`sql rehome-default`) refused or failed.
    #[error("sql rehome-default: {0}")]
    Rehome(String),
}

/// Validate a `--db` name through the one canonical resource-identifier validator
/// (`kind = "database"`) before it is threaded into the control-plane URL. Rejects an
/// empty/`//`-collapsing or path-separator-bearing name with the same rule the server
/// and config load enforce. For the empty-name case — the single most common upgrade
/// snag (the legacy default was the empty string) — the error carries a one-line cure
/// pointing at the new `default` name; every other invalid name keeps the plain reason.
fn validate_db(db: &str) -> Result<()> {
    boatramp_core::project::validate_resource_name("database", db).map_err(|err| {
        if db.is_empty() {
            Error::InvalidDb(format!(
                "{err}; {}",
                boatramp_core::project::EMPTY_DB_NAME_CURE
            ))
        } else {
            Error::InvalidDb(format!(
                "{err}; {}",
                boatramp_core::project::INVALID_NAME_CURE
            ))
        }
    })
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
    /// **Relocate** a site's libsql database, data intact — e.g. give the default
    /// database a real name, or move a named database. Local single-node only; a
    /// remote/sqld backend is refused. A destructive, admin-scoped maintenance op:
    /// it vacuums a consistent copy to the destination, verifies it, then removes the
    /// source. Refuses to overwrite an existing destination.
    Move {
        /// The **source** database binding name (`default` = the site's default database).
        #[arg(long, default_value = boatramp_core::project::DEFAULT_DB_NAME)]
        db: String,
        /// The **destination** binding name (must be a valid, non-existing database name).
        #[arg(long)]
        to: String,
        /// The site whose database is being relocated (falls back to `publish.site`).
        #[arg(long)]
        site: Option<String>,
    },
    /// **Default-scope re-home** a reserved-`default`-project site's libsql database (v0.31.0
    /// Finding 8), OFFLINE + node-local — the libsql half of the `boatramp migrate` default-scope
    /// re-key. Copy-verifies the pre-fix bare `{dir}/{site}.db` to the post-fix
    /// `{dir}/default/{site}.db` (`VACUUM INTO` → `integrity_check` → remove source + WAL/SHM), data
    /// intact, then a reopen via `database("default", site, …)` resolves the new two-segment path.
    ///
    /// **Local single-node only.** A node whose `handlers.bindings.sql` is a REMOTE sqld (`url = …`)
    /// is refused fail-closed, pointing at the manual namespace-migration operator step — an
    /// app-level remote move could lose writes racing the copy. Run with the node STOPPED (a
    /// maintenance op), before starting the new binary. Reads `--node-config` (not `--server`).
    RehomeDefault {
        /// The site whose default-project database is being re-homed.
        #[arg(long)]
        site: String,
        /// The database binding name to re-home (`default` = the site's default database).
        #[arg(long, default_value = boatramp_core::project::DEFAULT_DB_NAME)]
        db: String,
        /// Path to the node config (`boatramp.cfg` shape) whose `handlers.bindings.sql` + `[serve]`
        /// data_dir locate the libsql store. Defaults to `boatramp.cfg`.
        #[arg(long, default_value = "boatramp.cfg")]
        node_config: std::path::PathBuf,
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
    // `rehome-default` is OFFLINE + node-local (reads `--node-config`, builds the local libsql
    // backend, never a control-plane server) — handle it before resolving the server target.
    if let SqlCommand::RehomeDefault {
        site,
        db,
        node_config,
    } = args.command
    {
        return rehome_default(&site, &db, &node_config).await;
    }

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
        SqlCommand::Move { db, to, site } => {
            // Screen both endpoint names client-side, before a request is built — the
            // reserved default (`default`) is the one accepted "empty" spelling for the
            // source. The destination must be a real, valid name (never the empty/default).
            if db != boatramp_core::project::DEFAULT_DB_NAME {
                validate_db(&db)?;
            }
            validate_db(&to)?;
            // The move is per-(project, site, db). Resolve the site (flag → config), and
            // reuse the same project resolution the other sql subcommands use.
            let site = site
                .or_else(|| config.publish.site.clone())
                .ok_or_else(|| Error::InvalidDb("no site configured; pass --site".into()))?;
            let project = client::resolve_project(config);
            // `/api/sql-move` is a node-level (`system·admin`) maintenance op carrying the
            // tenant in the body — not the project-segmented `sql` path the other verbs use.
            let resp = http
                .post(format!("{server}/api/sql-move"))
                .json(&serde_json::json!({
                    "project": project,
                    "site": site,
                    "from": db,
                    "to": to,
                }))
                .send()
                .await?;
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if !status.is_success() {
                return Err(Error::Server(format!(
                    "sql move failed: {status}: {}",
                    body.trim()
                )));
            }
            // Print the server's JSON report ({status, from, to, integrity}).
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v)?),
                Err(_) => println!("{}", body.trim()),
            }
        }
        // Handled offline above (returned before the server target was resolved).
        SqlCommand::RehomeDefault { .. } => {
            unreachable!("handled offline before server resolution")
        }
    }
    Ok(())
}

/// Run the offline, node-local default-scope libsql re-home (`boatramp sql rehome-default`, v0.31.0
/// Finding 8). Loads `--node-config`, refuses fail-closed for a REMOTE sqld binding (pointing at the
/// manual namespace-migration operator step), else builds the LOCAL libsql backend and copy-verifies
/// the site's bare `{dir}/{site}.db` to its two-segment `{dir}/default/{site}.db` via the inherent
/// [`rehome_default_site_db`](boatramp_storage::LibsqlSqlBackends::rehome_default_site_db).
#[cfg(feature = "sql")]
async fn rehome_default(site: &str, db: &str, node_config: &std::path::Path) -> Result<()> {
    let config = boatramp_node::config::ServerConfig::load(node_config, None)?;
    let sql_cfg = config
        .handlers
        .as_ref()
        .and_then(|h| h.bindings.sql.as_ref());
    // REMOTE sqld (a `handlers.bindings.sql.url`): refuse fail-closed — an app-level namespace move
    // could lose writes racing the copy. Point at the manual operator step; never attempt it.
    if sql_cfg.and_then(|c| c.url.as_ref()).is_some() {
        return Err(Error::Rehome(
            "this node's libsql is a REMOTE sqld (handlers.bindings.sql.url is set); a default-scope \
             namespace relocation is a MANUAL operator step — create the new namespace \
             bramp-{dns_token(\"default/<site>\")}, copy, and cut over (see \
             docs/default-scope-migration.md). Refused fail-closed."
                .into(),
        ));
    }
    let data_dir = config
        .serve
        .as_ref()
        .and_then(|s| s.data_dir.clone())
        .unwrap_or_else(|| std::path::PathBuf::from("./data"));
    let dir = sql_cfg
        .and_then(|c| c.dir.clone())
        .unwrap_or_else(|| data_dir.join("handlers-sql"));
    let backends = boatramp_storage::LibsqlSqlBackends::local(dir);
    // The method folds `""`/`default` to the one canonical default DB, so pass `db` verbatim.
    let report = backends
        .rehome_default_site_db(site, db)
        .await
        .map_err(|e| Error::Rehome(e.to_string()))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "rehomed",
            "project": report.project,
            "site": report.site,
            "from": report.from,
            "to": report.to,
            "integrity": report.integrity,
        }))?
    );
    Ok(())
}

/// `boatramp sql rehome-default` is unavailable in a build without the libsql backend (`sql` feature).
#[cfg(not(feature = "sql"))]
async fn rehome_default(_site: &str, _db: &str, _node_config: &std::path::Path) -> Result<()> {
    Err(Error::Rehome(
        "`sql rehome-default` needs the libsql backend (rebuild with --features sql)".into(),
    ))
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
    fn empty_db_name_rejection_carries_the_cure() {
        // The empty-name case (the common v0.5.0 upgrade snag) appends the one-line cure
        // pointing at the new `default` name; other invalid names keep the plain reason.
        let Err(Error::InvalidDb(msg)) = validate_db("") else {
            panic!("empty --db must be rejected");
        };
        assert!(
            msg.contains(boatramp_core::project::EMPTY_DB_NAME_CURE),
            "empty-name error must carry the cure, got: {msg}"
        );
        // A different invalid name does NOT get the cure (it is not the empty-default case).
        let Err(Error::InvalidDb(other)) = validate_db("a/b") else {
            panic!("`a/b` must be rejected");
        };
        assert!(
            !other.contains(boatramp_core::project::EMPTY_DB_NAME_CURE),
            "a non-empty invalid name must not carry the empty-name cure, got: {other}"
        );
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

    #[test]
    fn move_parses_source_default_and_requires_destination() {
        use clap::Parser;
        #[derive(Parser)]
        struct Harness {
            #[command(subcommand)]
            command: SqlCommand,
        }
        // `--to` is required (no default); `--db` defaults to the reserved default.
        let h = Harness::try_parse_from(["boatramp", "move", "--to", "analytics"])
            .expect("move parses with just --to");
        match h.command {
            SqlCommand::Move { db, to, site } => {
                assert_eq!(db, boatramp_core::project::DEFAULT_DB_NAME);
                assert_eq!(to, "analytics");
                assert!(site.is_none());
            }
            other => panic!("expected move, got {other:?}"),
        }
        // Missing `--to` is a parse error.
        assert!(
            Harness::try_parse_from(["boatramp", "move"]).is_err(),
            "move requires --to"
        );
        // An invalid `--to` is rejected client-side by the same canonical validator
        // the server enforces (before any request is built).
        for bad in ["a/b", "..", "a b", "proj*"] {
            assert!(validate_db(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
