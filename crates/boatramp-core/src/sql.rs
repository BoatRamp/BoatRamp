//! A small, engine-agnostic SQL backend contract for the handler `sql` binding.
//!
//! The handler engine exposes a `sql` capability to guests, but *which* database
//! serves it is a deployment detail — the same seam as the blob ([`Storage`])
//! and KV ([`kv::KvStore`]) backends. [`SqlBackend`] is that seam, so the guest
//! interface and the server UX stay identical across single-node and cluster
//! deployments. The one implementation is **libsql** (SQLite-compatible): an
//! embedded file per site (single-node) or a sqld namespace per site (cluster,
//! read-replicable) — one engine, the split being config, not a backend choice.
//!
//! Each backend instance is **scoped to one site**; the engine/transport and the
//! per-site database mapping live behind the trait, so a handler can never
//! address another site's data ([`crate::deploy`]-style isolation).
//!
//! The contract is deliberately tiny — `begin` a transaction, `query`/`execute`
//! within it, then `commit`/`rollback` — and the trait keeps the engine
//! decoupled from libsql's specifics (and lets tests substitute a fake). The
//! handler engine wraps each invocation in one transaction (commit on success,
//! roll back on trap/error).
//!
//! [`Storage`]: crate::Storage
//! [`kv::KvStore`]: crate::kv::KvStore

use std::sync::Arc;

use async_trait::async_trait;

/// A single SQL value. `Boolean` is carried as a distinct class (so a guest can
/// express one and a strictly-typed engine could bind a native `BOOL`); libsql,
/// being SQLite-family, maps it to `0`/`1`.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    /// SQL `NULL`.
    Null,
    /// A boolean (a native `BOOL` where the engine has one, else `0`/`1`).
    Boolean(bool),
    /// A 64-bit signed integer.
    Integer(i64),
    /// A 64-bit float.
    Real(f64),
    /// UTF-8 text.
    Text(String),
    /// A byte string.
    Blob(Vec<u8>),
    /// A JSON document (its JSON text). Bound with the engine's JSON column type
    /// (`jsonb`/`json` on Postgres, a JSON string on MySQL, text on SQLite), so a
    /// guest can write a `jsonb` column with no `::jsonb` cast. Read back as
    /// [`Text`](Self::Text) (the engines stringify JSON on the way out).
    Json(String),
}

/// The rows a [`SqlTransaction::query`] returned: column names plus row-major
/// cells (each row's length equals `columns.len()`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SqlRows {
    /// Column names, in result order.
    pub columns: Vec<String>,
    /// Rows, each a vector of cells aligned to `columns`.
    pub rows: Vec<Vec<SqlValue>>,
}

/// Why a SQL operation failed.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SqlError {
    /// The statement could not be parsed or planned.
    #[error("sql syntax error: {0}")]
    Syntax(String),
    /// A constraint (unique, type, foreign key, ...) was violated.
    #[error("sql constraint error: {0}")]
    Constraint(String),
    /// Any other backend/transport error (I/O, connection, ...).
    #[error("sql error: {0}")]
    Other(String),
}

impl SqlError {
    /// Wrap any displayable error as [`SqlError::Other`].
    pub fn other<E: std::fmt::Display>(err: E) -> Self {
        Self::Other(err.to_string())
    }
}

/// The SQL dialect a backend speaks. The `orm` compiler is `?N`-portable for almost
/// everything (the backend rewrites the placeholders), and only consults this for the
/// handful of constructs whose *syntax* genuinely differs across engines — currently JSON
/// extraction (`json_extract(...)` on SQLite/MySQL vs `#>>` on Postgres).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Dialect {
    /// SQLite family (libsql). The default.
    #[default]
    Sqlite,
    Postgres,
    Mysql,
}

/// A per-site SQL backend (libsql — a local file or a remote sqld namespace).
///
/// One instance serves one site. The handler engine calls [`begin`] once per
/// invocation that uses SQL and drives the resulting [`SqlTransaction`] to a
/// commit (on a successful response) or rollback (on trap/error).
///
/// [`begin`]: SqlBackend::begin
#[async_trait]
pub trait SqlBackend: Send + Sync {
    /// The SQL dialect this backend speaks — used by the `orm` compiler for the few
    /// dialect-divergent constructs (e.g. JSON extraction). Defaults to SQLite-family
    /// (libsql); the Postgres/MySQL backends override it.
    fn dialect(&self) -> Dialect {
        Dialect::Sqlite
    }

    /// Open a new read-write transaction. Backends are free to draw the
    /// underlying connection from a pool, a fresh embedded connection, or a
    /// remote session. Writes always land on the primary.
    async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError>;

    /// Open a transaction for a **read-only** invocation, which a backend
    /// configured with a read replica may route to that replica (separate read
    /// vs write endpoint: reads → replicas, writes →
    /// primary). A replica may lag the primary, so such reads are
    /// **eventually consistent**; issuing a write on this transaction is a
    /// caller error (it hits the read endpoint, which a replica rejects).
    ///
    /// The default has no replica and simply opens a normal transaction, so
    /// single-node and replica-less deployments behave identically.
    async fn begin_read_only(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
        self.begin().await
    }

    /// Run a multi-statement SQL **script** as one unit (the simple-query protocol),
    /// for operator migrations: `CREATE EXTENSION` and long chains of DDL/DML that the
    /// parameterized per-statement path can't express. Only the external
    /// Postgres/MySQL backends implement it (the per-site libsql backend rejects it);
    /// it is an operator tool, not a guest capability.
    async fn run_script(&self, _sql: &str) -> Result<(), SqlError> {
        Err(SqlError::Other(
            "this database does not support running a raw SQL script".into(),
        ))
    }

    /// Run one row-returning statement directly, in its own short-lived read-only
    /// transaction — backs the operator `sql query`. The default composes the existing
    /// transaction methods, so every backend supports it.
    async fn run_query(&self, sql: &str) -> Result<SqlRows, SqlError> {
        let mut tx = self.begin_read_only().await?;
        let result = tx.query(sql, &[]).await;
        // Read-only: always roll back so nothing lingers and no write can slip through.
        let _ = tx.rollback().await;
        result
    }

    /// Whether this backend injects a **reserved** boatramp session context
    /// (`rls_session` — the `boatramp.project` / `boatramp.site` GUC on Postgres, or
    /// the `@boatramp_project` / `@boatramp_site` MySQL session var) that an app's
    /// row-level-security policy keys on. Default `false`.
    ///
    /// When `true`, the guest `sql` binding must **refuse** any guest statement that
    /// would set/reset those reserved keys (see [`reject_reserved_session_writes`]):
    /// otherwise a hostile guest could spoof its injected tenant and defeat the app's
    /// RLS. This is a security signal, not a routing one — see the `rls_session` doc for
    /// the trust model (the real isolation boundary is the per-tenant database + role).
    fn injects_session_context(&self) -> bool {
        false
    }
}

/// Reject a guest SQL statement that would set or reset a **boatramp-reserved**
/// session key — the `boatramp.*` GUC (Postgres) or an `@boatramp_*` user variable
/// (MySQL). Used by the guest `sql` binding when the backend
/// [`injects_session_context`](SqlBackend::injects_session_context): with `rls_session`
/// on, boatramp injects the request's tenant into those keys for the app's RLS, so a
/// guest that could overwrite them would spoof its tenant and defeat that RLS.
///
/// The match is deliberately **narrow** — only the reserved prefix is refused, so
/// ordinary app SQL (`SET statement_timeout = …`, `SET search_path = …`, a `SELECT`
/// mentioning "set" in an identifier or string) is untouched. Recognised hostile forms:
///
/// - `set_config('boatramp.<anything>', …)` — the Postgres GUC setter (in any casing,
///   with any surrounding whitespace), whether written as its own statement or inside a
///   `SELECT`.
/// - a statement whose **leading keyword** is `SET` / `RESET` / `DISCARD` (including
///   `SET SESSION` / `SET LOCAL`) targeting a `boatramp.` GUC or an `@boatramp_` var.
///
/// Returns [`SqlError::Other`] with a clear message on a match, else `Ok(())`.
pub fn reject_reserved_session_writes(sql: &str) -> Result<(), SqlError> {
    /// The reserved GUC namespace (Postgres) and MySQL user-var prefix, lowercased.
    const GUC_PREFIX: &str = "boatramp.";
    const MYSQL_VAR_PREFIX: &str = "@boatramp_";

    let refused = || {
        Err(SqlError::Other(
            "setting a boatramp-reserved session key (boatramp.* / @boatramp_*) is not \
             permitted from a handler: it is managed by rls_session and reserved for \
             per-request tenant isolation"
                .to_string(),
        ))
    };

    // Lowercase once for case-insensitive keyword/identifier matching. Reserved keys
    // are ASCII, so a byte-wise lowercase is exact for them.
    let lower = sql.to_ascii_lowercase();

    // 1. `set_config('boatramp.…', …)` anywhere (it is a function call, so it can hide
    //    inside a SELECT — including several in one statement). Check EVERY occurrence,
    //    tolerant of whitespace after `(` and around the opening quote — e.g.
    //    `set_config ( 'boatramp.project' , … )`.
    for (pos, _) in lower.match_indices("set_config") {
        let after = lower[pos + "set_config".len()..].trim_start();
        let Some(args) = after.strip_prefix('(') else {
            continue;
        };
        let arg0 = args.trim_start();
        // The first argument is the setting name as a quoted string literal.
        let Some(name) = arg0.strip_prefix('\'').or_else(|| arg0.strip_prefix('"')) else {
            continue;
        };
        if name.trim_start().starts_with(GUC_PREFIX) {
            return refused();
        }
    }

    // 2. A leading `SET` / `RESET` / `DISCARD` targeting the reserved keys. Tokenize the
    //    leading whitespace-separated words so `SET SESSION` / `SET LOCAL` are handled.
    let mut words = lower.split_whitespace();
    match words.next() {
        // DISCARD ALL / DISCARD … resets ALL session state incl. our GUCs, so a guest
        // must not run it while a session context is active.
        Some("discard") => return refused(),
        Some("reset") => {
            // `RESET boatramp.project` / `RESET ALL` (ALL clears our GUC too).
            if let Some(target) = words.next() {
                if target == "all" || target.starts_with(GUC_PREFIX) {
                    return refused();
                }
            }
        }
        Some("set") => {
            // Skip an optional SESSION / LOCAL qualifier, then inspect the target.
            let mut target = words.next();
            if matches!(target, Some("session") | Some("local")) {
                target = words.next();
            }
            if let Some(t) = target {
                // The target may be `name=value` or `name = value`; take the head up to
                // `=` so `set boatramp.project='x'` (no spaces) is caught too.
                let head = t.split('=').next().unwrap_or(t);
                if head.starts_with(GUC_PREFIX) || head.starts_with(MYSQL_VAR_PREFIX) {
                    return refused();
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// How a **preview** deployment's SQL database relates to the site's live one
/// (operator policy; see the per-site/server config). The default is the safe,
/// isolated choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PreviewSqlMode {
    /// A fresh, empty database isolated from live (optionally seeded by an init
    /// script). Can never read or clobber live data.
    #[default]
    Empty,
    /// A consistent **copy** of the live database at branch time — realistic
    /// data, but writes stay in the preview's copy.
    Branch,
    /// The site's **live** database, shared with production traffic. The preview
    /// reads and writes real data — use only when that's intended.
    Shared,
}

/// Resolves a site's named SQL databases to [`SqlBackend`]s — the seam the
/// server's handler runtime uses to obtain a per-site database on demand
/// (opening/caching it lazily). The concrete mapping (a libsql file per site,
/// or a sqld namespace per site) lives behind this, so the server stays
/// storage-agnostic.
#[async_trait]
pub trait SqlBackends: Send + Sync {
    /// Open (or reuse) the database called `name` for `site` within tenant
    /// `project` (the empty name is the site's default database). Per-tenant +
    /// per-site isolation is the implementation's responsibility — a handler can
    /// only ever reach its own project's site's data.
    ///
    /// `project` and `site` are **separately** validated by the implementation
    /// and composed internally via
    /// [`ProjectRef::qualified`](crate::project::ProjectRef::qualified) (the
    /// reserved `default` project keeps the byte-identical, pre-project identity
    /// for back-compat; any other project prefixes `"<project>/"`). Passing a
    /// single already-composed `"<project>/<site>"` string as `site` would be
    /// rejected — the two names are kept apart so each is validated on its own.
    async fn database(
        &self,
        project: &str,
        site: &str,
        name: &str,
    ) -> Result<Arc<dyn SqlBackend>, SqlError>;

    /// Open (or reuse) the database for a **preview** deployment `preview` of
    /// `site` within tenant `project`. The implementation applies its configured
    /// [`PreviewSqlMode`]. The default is [`PreviewSqlMode::Empty`] — an isolated
    /// database keyed by project+site+preview, so a preview can never touch live
    /// state. The default composition qualifies `site` by `project` first, then
    /// appends the trusted `_preview/{preview}` suffix (both from validated
    /// parts), and delegates to [`database`](Self::database) under the reserved
    /// `default` project so the already-qualified identity is not re-qualified.
    async fn preview_database(
        &self,
        project: &str,
        site: &str,
        name: &str,
        preview: &str,
    ) -> Result<Arc<dyn SqlBackend>, SqlError> {
        let qualified = crate::project::ProjectRef::new(project).qualified(site);
        self.database(
            crate::project::DEFAULT_PROJECT,
            &format!("{qualified}/_preview/{preview}"),
            name,
        )
        .await
    }
}

/// The operator-facing SQL capability for a **managed** database: run a migration
/// script or a single query against a compute-backed database boatramp runs, using
/// its sealed managed credential (resolved server-side — the credential never leaves
/// the node). Backs `POST /api/sql/{db}/{exec,query}` and the `boatramp sql` CLI.
/// Distinct from [`SqlBackends`] (the per-site guest binding): this is a
/// project-scoped **operator** tool, admin-gated at the API.
#[async_trait]
pub trait OperatorSql: Send + Sync {
    /// Run a multi-statement migration `script` against managed database `db` in
    /// `project` (the simple-query protocol — `CREATE EXTENSION` + chained DDL).
    async fn exec_script(&self, project: &str, db: &str, script: &str) -> Result<(), SqlError>;

    /// Run one row-returning `sql` statement against managed database `db`.
    async fn query(&self, project: &str, db: &str, sql: &str) -> Result<SqlRows, SqlError>;
}

/// One transaction's worth of work. Dropping it without [`commit`] must leave
/// the database unchanged (the engine rolls back).
///
/// [`commit`]: SqlTransaction::commit
#[async_trait]
pub trait SqlTransaction: Send {
    /// Run a row-returning statement (e.g. `SELECT`), binding `params` to the
    /// statement's positional placeholders.
    async fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<SqlRows, SqlError>;

    /// Run a non-row statement (`INSERT`/`UPDATE`/`DELETE`/DDL), binding
    /// `params`. Returns the number of affected rows (0 for DDL).
    async fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError>;

    /// Commit the transaction.
    async fn commit(self: Box<Self>) -> Result<(), SqlError>;

    /// Roll the transaction back.
    async fn rollback(self: Box<Self>) -> Result<(), SqlError>;
}

#[cfg(test)]
mod reserved_session_writes_tests {
    use super::reject_reserved_session_writes as check;

    fn rejected(sql: &str) -> bool {
        check(sql).is_err()
    }

    // ---- hostile statements that spoof the injected tenant MUST be rejected ----

    #[test]
    fn set_config_on_reserved_guc_is_rejected() {
        assert!(rejected(
            "SELECT set_config('boatramp.project','victim',false)"
        ));
        assert!(rejected("select set_config('boatramp.site', 'x', true)"));
        // Tolerant of whitespace around the call and the quote.
        assert!(rejected(
            "SELECT set_config ( 'boatramp.project' , 'v', false )"
        ));
        // Double-quoted first arg (unusual but a literal in some dialects).
        assert!(rejected(
            "SELECT set_config(\"boatramp.project\", 'v', false)"
        ));
        // A reserved set_config hiding AFTER a benign one in the same statement is
        // still caught (every occurrence is checked, not just the first).
        assert!(rejected(
            "SELECT set_config('search_path','app',false), \
             set_config('boatramp.project','v',false)"
        ));
    }

    #[test]
    fn set_reserved_guc_is_rejected() {
        assert!(rejected("SET boatramp.project = 'victim'"));
        assert!(rejected("set boatramp.project='victim'")); // no spaces
        assert!(rejected("SET SESSION boatramp.site = 'x'"));
        assert!(rejected("SET LOCAL boatramp.project TO 'x'"));
    }

    #[test]
    fn set_reserved_mysql_var_is_rejected() {
        assert!(rejected("SET @boatramp_project = 'victim'"));
        assert!(rejected("set @boatramp_site='x'"));
        assert!(rejected("SET @boatramp_project := 'x'")); // MySQL := assignment
        assert!(rejected("SET SESSION @boatramp_project = 'x'"));
    }

    #[test]
    fn reset_and_discard_of_reserved_state_is_rejected() {
        assert!(rejected("RESET boatramp.project"));
        assert!(rejected("RESET ALL")); // clears our GUC too
        assert!(rejected("DISCARD ALL"));
        assert!(rejected("discard all"));
    }

    // ---- legitimate app SQL MUST be allowed (narrow match) ----

    #[test]
    fn unrelated_set_statements_are_allowed() {
        assert!(!rejected("SET statement_timeout = 5000"));
        assert!(!rejected("SET search_path TO app, public"));
        assert!(!rejected("SET SESSION time_zone = '+00:00'"));
        assert!(!rejected("SET @my_var = 1")); // a non-reserved MySQL user var
        assert!(!rejected("RESET statement_timeout"));
    }

    #[test]
    fn a_select_mentioning_set_in_an_identifier_is_allowed() {
        // "set" appears only as an identifier / column word, not a SET statement.
        assert!(!rejected("SELECT settings FROM boatramp_projects"));
        assert!(!rejected(
            "SELECT * FROM offset_table WHERE reset_at > now()"
        ));
        // A normal SELECT that happens to filter on a column literally named similarly.
        assert!(!rejected("SELECT * FROM t WHERE name = 'boatramp.project'"));
    }

    #[test]
    fn set_config_on_a_non_reserved_guc_is_allowed() {
        assert!(!rejected("SELECT set_config('search_path','app',false)"));
        assert!(!rejected(
            "SELECT set_config('statement_timeout', '5000', true)"
        ));
    }
}
