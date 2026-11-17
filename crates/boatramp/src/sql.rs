//! `boatramp sql` — operator SQL access to a **managed** database: run a single ad-hoc SQL
//! script (`exec`) or one query (`query`). The server connects using the database's sealed
//! managed credential (resolved server-side — the credential never reaches the client) and runs
//! the SQL; admin-scoped.
//!
//! **`exec` is the single-SCRIPT escape hatch, not the migration mechanism.** For an *ordered,
//! tracked* schema-migration set — applied in filename order, stop-on-first-failure, recorded in
//! the `schema_migrations` ledger so a re-run is a no-op — use
//! [`boatramp project migrate --dir migrations/ --db <db> apply`](crate::project_migrate). Reach
//! for `exec` only for a one-off script (a quick fix, a REPL-style DDL), not a versioned migration.
//!
//! On a managed-pg **cold start** the backend answers not-ready with a retryable `503` +
//! `Retry-After`; `exec` / `query` **wait** on it by default (bounded; `--wait-ready-secs` /
//! `--no-wait`) via the shared [`crate::managed_wait`] helper, rather than failing immediately.

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

/// Build the error for a non-success `sql exec` / `sql query` response. A **`503`** means the
/// managed backend is still provisioning *after* the bounded readiness wait was spent — a
/// transient state, so the message hints the cure (wait longer, or reach for the ordered migration
/// runner) instead of reading like a terminal failure. Every other status keeps the plain reason.
fn sql_op_error(verb: &str, db: &str, status: reqwest::StatusCode, text: &str) -> Error {
    if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
        Error::Server(format!(
            "sql {verb}: managed database `{db}` is still provisioning ({status}): {text}\n  \
             it may just need more time — retry, or wait longer with `--wait-ready-secs <N>` \
             (`--no-wait` to fail fast); for an ordered, ledger-tracked migration set use \
             `boatramp project migrate --dir migrations/ --db {db} apply`"
        ))
    } else {
        Error::Server(format!("sql {verb} failed: {status}: {text}"))
    }
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
    /// Run a single ad-hoc SQL **script** (multiple statements — `CREATE EXTENSION`, tables, RLS,
    /// chained DDL/DML) against a managed database, from `--file` or standard input. This is the
    /// one-off **escape hatch** — for an ordered, ledger-tracked schema-migration set use
    /// `boatramp project migrate --dir migrations/ --db <db> apply` (applies in filename order,
    /// stops on the first failure, and records each step in `schema_migrations` so a re-run is a
    /// no-op). A still-provisioning managed backend is waited for (see `--wait-ready-secs`).
    Exec {
        /// The database binding name (`default` = the project's default database).
        #[arg(long, default_value = boatramp_core::project::DEFAULT_DB_NAME)]
        db: String,
        /// Read the script from this file instead of standard input.
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        #[command(flatten)]
        wait: crate::managed_wait::WaitFlags,
    },
    /// Run one row-returning query against a managed database and print the result.
    Query {
        /// The SQL query (a single statement).
        sql: String,
        /// The database binding name (`default` = the project's default database).
        #[arg(long, default_value = boatramp_core::project::DEFAULT_DB_NAME)]
        db: String,
        #[command(flatten)]
        wait: crate::managed_wait::WaitFlags,
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

/// The result of a `boatramp sql` subcommand, rendered by [`crate::output`].
///
/// Query/ping/move/re-home results carry the structured server payload so a
/// `--output-format json` consumer reads rows and reports structurally (never a
/// pre-formatted table).
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum SqlOutput {
    /// `sql exec` — the migration script was applied (the `ok` ack is logged to stderr).
    Exec,
    /// `sql query` — the row-returning result (`{columns, rows}`). The human view is a table;
    /// `--output-format json` serializes `data` structurally.
    Query { data: serde_json::Value },
    /// `sql ping` — the per-replica reachability/health probe results.
    Ping { replicas: Vec<serde_json::Value> },
    /// `sql move` — the server's relocation report.
    Move {
        // The exact text the command historically printed (pretty JSON, or a non-JSON body
        // verbatim); `report` carries the structured value for JSON consumers.
        #[serde(skip)]
        human: String,
        report: serde_json::Value,
    },
    /// `sql rehome-default` — the offline libsql re-home report. Only the `sql` (libsql) feature's
    /// `rehome_default` constructs it; the `not(sql)` stub errors out instead.
    #[cfg(feature = "sql")]
    RehomeDefault { report: serde_json::Value },
}

impl crate::output::Rendered for SqlOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            // `exec` reports success via the `ok` line on the `tracing` sink (stderr); it
            // writes nothing to stdout, exactly as before.
            Self::Exec => Ok(()),
            Self::Query { data } => write_table(data, w),
            Self::Ping { replicas } => {
                if replicas.is_empty() {
                    return writeln!(
                        w,
                        "no replicas (the managed database has no compute replicas yet)"
                    );
                }
                writeln!(
                    w,
                    "{:<21}  {:<9}  {:<7}  PHASE",
                    "ENDPOINT", "REACHABLE", "HEALTHY"
                )?;
                for r in replicas {
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
                    writeln!(w, "{endpoint:<21}  {reachable:<9}  {healthy:<7}  {phase}")?;
                }
                Ok(())
            }
            Self::Move { human, .. } => writeln!(w, "{human}"),
            #[cfg(feature = "sql")]
            Self::RehomeDefault { report } => writeln!(
                w,
                "{}",
                serde_json::to_string_pretty(report).map_err(std::io::Error::other)?
            ),
        }
    }
}

/// Entry point for `boatramp sql`.
pub async fn run(args: SqlArgs, config: &ProjectConfig) -> Result<SqlOutput> {
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

    let out = match args.command {
        SqlCommand::Exec { db, file, wait } => {
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
            // Hold the body in memory so a readiness retry re-issues cleanly (stdin is read once).
            let url = format!("{server}/api/{seg}/{db}/exec");
            let body = serde_json::json!({ "sql": sql });
            let resp = crate::managed_wait::send_with_ready_wait(wait.policy(), || {
                http.post(url.as_str()).json(&body).send()
            })
            .await?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(sql_op_error("exec", &db, status, text.trim()));
            }
            // The script applied; the former stdout was empty and the ack rode stderr.
            tracing::info!("ok");
            SqlOutput::Exec
        }
        SqlCommand::Query { db, sql, wait } => {
            validate_db(&db)?;
            let url = format!("{server}/api/{seg}/{db}/query");
            let body = serde_json::json!({ "sql": sql });
            let resp = crate::managed_wait::send_with_ready_wait(wait.policy(), || {
                http.post(url.as_str()).json(&body).send()
            })
            .await?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(sql_op_error("query", &db, status, text.trim()));
            }
            let data: serde_json::Value = resp.json().await?;
            SqlOutput::Query { data }
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
            SqlOutput::Ping { replicas }
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
            // The server's JSON report ({status, from, to, integrity}); fall back to the
            // raw body verbatim if it is not JSON (preserving the former output exactly).
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(v) => {
                    let human = serde_json::to_string_pretty(&v)?;
                    SqlOutput::Move { human, report: v }
                }
                Err(_) => {
                    let human = body.trim().to_string();
                    SqlOutput::Move {
                        report: serde_json::Value::String(human.clone()),
                        human,
                    }
                }
            }
        }
        // Handled offline above (returned before the server target was resolved).
        SqlCommand::RehomeDefault { .. } => {
            unreachable!("handled offline before server resolution")
        }
    };
    Ok(out)
}

/// Run the offline, node-local default-scope libsql re-home (`boatramp sql rehome-default`, v0.31.0
/// Finding 8). Loads `--node-config`, refuses fail-closed for a REMOTE sqld binding (pointing at the
/// manual namespace-migration operator step), else builds the LOCAL libsql backend and copy-verifies
/// the site's bare `{dir}/{site}.db` to its two-segment `{dir}/default/{site}.db` via the inherent
/// [`rehome_default_site_db`](boatramp_storage::LibsqlSqlBackends::rehome_default_site_db).
#[cfg(feature = "sql")]
async fn rehome_default(site: &str, db: &str, node_config: &std::path::Path) -> Result<SqlOutput> {
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
    Ok(SqlOutput::RehomeDefault {
        report: serde_json::json!({
            "status": "rehomed",
            "project": report.project,
            "site": report.site,
            "from": report.from,
            "to": report.to,
            "integrity": report.integrity,
        }),
    })
}

/// `boatramp sql rehome-default` is unavailable in a build without the libsql backend (`sql` feature).
#[cfg(not(feature = "sql"))]
async fn rehome_default(
    _site: &str,
    _db: &str,
    _node_config: &std::path::Path,
) -> Result<SqlOutput> {
    Err(Error::Rehome(
        "`sql rehome-default` needs the libsql backend (rebuild with --features sql)".into(),
    ))
}

/// Render a `{columns, rows}` query response as a bordered text table.
fn write_table(out: &serde_json::Value, w: &mut dyn std::io::Write) -> std::io::Result<()> {
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
    writeln!(w, "{}", fmt_row(&headers))?;
    writeln!(
        w,
        "{}",
        widths
            .iter()
            .map(|width| "-".repeat(*width))
            .collect::<Vec<_>>()
            .join("-+-")
    )?;
    for row in &cells {
        writeln!(w, "{}", fmt_row(row))?;
    }
    writeln!(
        w,
        "({} row{})",
        cells.len(),
        if cells.len() == 1 { "" } else { "s" }
    )
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

    // A `503` carrying the not-ready hint is formatted so the operator sees the cure.
    #[test]
    fn not_ready_exec_error_hints_the_wait_and_migrate_cures() {
        let err = sql_op_error(
            "exec",
            "appdb",
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "managed database not ready: no healthy replica",
        );
        let msg = err.to_string();
        assert!(msg.contains("--wait-ready-secs"), "hints the wait: {msg}");
        assert!(
            msg.contains("project migrate --dir"),
            "steers to the ordered migration runner: {msg}"
        );
        // A non-503 keeps the plain reason (no cure clutter).
        let plain = sql_op_error(
            "exec",
            "appdb",
            reqwest::StatusCode::BAD_REQUEST,
            "syntax error",
        )
        .to_string();
        assert!(!plain.contains("--wait-ready-secs"), "plain error: {plain}");
    }

    /// Reproduce-first for `sql exec`: a managed backend that answers not-ready (`503` +
    /// `Retry-After`) twice, then succeeds — the Exec path must BLOCK on the wait-loop, then apply
    /// once ready (here after exactly 3 attempts). (MUTATION PROOF: drop the wait in
    /// `managed_wait::send_with_ready_wait` and this fails on the first 503.)
    #[tokio::test]
    async fn sql_exec_waits_through_pending_then_applies() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let hits = Arc::new(AtomicUsize::new(0));
        let hits_route = Arc::clone(&hits);
        let app = axum::Router::new().route(
            "/api/sql/default/exec",
            axum::routing::post(move || {
                let hits = Arc::clone(&hits_route);
                async move {
                    use axum::response::IntoResponse;
                    let n = hits.fetch_add(1, Ordering::SeqCst);
                    if n < 2 {
                        (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            [(axum::http::header::RETRY_AFTER, "0")],
                            "managed database not ready: no healthy replica\n",
                        )
                            .into_response()
                    } else {
                        axum::http::StatusCode::NO_CONTENT.into_response()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // A migration script in a temp file (so the Exec path doesn't read stdin).
        let script = std::env::temp_dir().join(format!("br-sqlexec-{}.sql", std::process::id()));
        std::fs::write(&script, "CREATE TABLE t (id int);").unwrap();

        let args = SqlArgs {
            server: Some(format!("http://127.0.0.1:{}", addr.port())),
            command: SqlCommand::Exec {
                db: boatramp_core::project::DEFAULT_DB_NAME.into(),
                file: Some(script.clone()),
                wait: crate::managed_wait::WaitFlags::waiting(10),
            },
        };
        let out = run(args, &ProjectConfig::default()).await;
        let _ = std::fs::remove_file(&script);
        assert!(matches!(out, Ok(SqlOutput::Exec)), "exec applied: {out:?}");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            3,
            "two not-ready attempts, then the applied one"
        );
    }

    /// A never-ready backend with `--no-wait` fails FAST (one attempt) and surfaces the not-ready
    /// hint — never a hang, never a silent terminal error.
    #[tokio::test]
    async fn sql_exec_no_wait_fails_fast_with_the_hint() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let hits = Arc::new(AtomicUsize::new(0));
        let hits_route = Arc::clone(&hits);
        let app = axum::Router::new().route(
            "/api/sql/default/exec",
            axum::routing::post(move || {
                let hits = Arc::clone(&hits_route);
                async move {
                    use axum::response::IntoResponse;
                    hits.fetch_add(1, Ordering::SeqCst);
                    (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        [(axum::http::header::RETRY_AFTER, "0")],
                        "managed database not ready: starting\n",
                    )
                        .into_response()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let script = std::env::temp_dir().join(format!("br-sqlexec-nw-{}.sql", std::process::id()));
        std::fs::write(&script, "SELECT 1;").unwrap();
        let args = SqlArgs {
            server: Some(format!("http://127.0.0.1:{}", addr.port())),
            command: SqlCommand::Exec {
                db: boatramp_core::project::DEFAULT_DB_NAME.into(),
                file: Some(script.clone()),
                wait: crate::managed_wait::WaitFlags::never(),
            },
        };
        let out = run(args, &ProjectConfig::default()).await;
        let _ = std::fs::remove_file(&script);
        match out {
            Err(Error::Server(msg)) => {
                assert!(msg.contains("--wait-ready-secs"), "carries the hint: {msg}");
            }
            other => panic!("expected a not-ready Server error, got {other:?}"),
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "--no-wait makes exactly one attempt"
        );
    }
}
