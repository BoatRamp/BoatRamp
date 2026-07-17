//! [`SqlBackend`] backed by [libsql](https://github.com/tursodatabase/libsql):
//! the SQLite-compatible engine and the handler `sql` binding's **single**
//! backend. It runs either as an embedded **local file** (single-node) or
//! against a **remote/replica sqld primary** shared by every cluster node — one
//! engine spanning both, the split being config, not a backend choice.
//!
//! Each [`begin`](SqlBackend::begin) opens a connection off the shared
//! [`libsql::Database`] and starts a transaction with raw
//! `BEGIN`/`COMMIT`/`ROLLBACK` (so the connection is owned by the boxed txn,
//! not borrowed). Booleans map to `0`/`1` (SQLite has no native boolean).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::deploy::sha256_hex;
use boatramp_core::sql::{
    PreviewSqlMode, SqlBackend, SqlBackends, SqlError, SqlRows, SqlTransaction, SqlValue,
};
use libsql::{Builder, Connection, Database, Value as LibsqlValue};
use tokio::sync::Mutex;

/// How long a contended writer waits for the single-writer lock before giving
/// up (local mode). Keep it under the engine's per-invocation timeout so a
/// genuinely stuck lock surfaces as a SQL error rather than a request timeout.
const BUSY_TIMEOUT_MS: u32 = 5_000;

/// A libsql-backed SQL backend, scoped to a site. Open it on a local file
/// ([`open_local`](Self::open_local), single-node) or against a remote sqld
/// primary ([`connect_remote`](Self::connect_remote), cluster).
///
/// Concurrency (local): the database is opened in **WAL** mode, so any number of
/// readers run in parallel and never block the single writer (and vice versa);
/// only writes to the *same* database serialize. Each connection sets a
/// `busy_timeout` so a contended writer **waits** for the lock instead of failing
/// with `database is locked`. Transactions stay `DEFERRED` (a bare `BEGIN`) so
/// read-only invocations don't take the write lock and reads stay concurrent.
/// (Remote/sqld mode leaves locking + timeouts to the server, which serializes
/// writes per namespace.)
#[derive(Clone)]
pub struct LibsqlSql {
    db: Arc<Database>,
    /// Optional separate **read** endpoint (a sqld replica). When set,
    /// [`begin_read_only`](SqlBackend::begin_read_only) routes reads here while
    /// writes stay on `db` (the primary). `None` ⇒
    /// read-only transactions use the primary (single-node / replica-less).
    read_db: Option<Arc<Database>>,
    local: bool,
}

impl LibsqlSql {
    /// Open (creating if absent) a local database file at `path`, in WAL mode.
    pub async fn open_local(path: impl AsRef<Path>) -> Result<Self, SqlError> {
        let db = Builder::new_local(path)
            .build()
            .await
            .map_err(SqlError::other)?;
        // WAL persists in the database header, so setting it once on open is
        // enough; every later connection inherits it.
        let conn = db.connect().map_err(SqlError::other)?;
        run_pragma(&conn, "PRAGMA journal_mode=WAL").await?;
        Ok(Self {
            db: Arc::new(db),
            read_db: None,
            local: true,
        })
    }

    /// Connect to a remote sqld server at `url` (the shared cluster primary),
    /// authenticating with `token` (empty for an unauthenticated local server).
    pub async fn connect_remote(url: &str, token: &str) -> Result<Self, SqlError> {
        let db = Builder::new_remote(url.to_string(), token.to_string())
            .build()
            .await
            .map_err(SqlError::other)?;
        Ok(Self {
            db: Arc::new(db),
            read_db: None,
            local: false,
        })
    }

    /// Route this backend's read-only transactions to `replica` (its primary
    /// `db` still serves writes). Used to wire a sqld read replica behind a
    /// primary; reads on it are eventually consistent.
    pub fn with_read_replica(mut self, replica: Self) -> Self {
        self.read_db = Some(replica.db);
        self
    }

    /// Run a multi-statement script (e.g. a preview seed). Intended for
    /// **idempotent** scripts (`CREATE TABLE IF NOT EXISTS …`), since it may run
    /// again when the database is reopened.
    pub async fn execute_script(&self, sql: &str) -> Result<(), SqlError> {
        self.db
            .connect()
            .map_err(SqlError::other)?
            .execute_batch(sql)
            .await
            .map_err(SqlError::other)?;
        Ok(())
    }

    /// Copy this database to `path` as a transactionally consistent snapshot
    /// (SQLite `VACUUM INTO`) — safe to run online against a live database.
    async fn vacuum_into(&self, path: &Path) -> Result<(), SqlError> {
        // `VACUUM INTO` takes a string literal; escape any quotes in the path.
        let target = path.to_string_lossy().replace('\'', "''");
        self.db
            .connect()
            .map_err(SqlError::other)?
            .execute(&format!("VACUUM INTO '{target}'"), ())
            .await
            .map_err(SqlError::other)?;
        Ok(())
    }
}

impl LibsqlSql {
    /// Open a `DEFERRED` transaction on `db`. Under WAL a bare `BEGIN` keeps
    /// reads concurrent and only takes the write lock on the first write.
    async fn begin_on(&self, db: &Database) -> Result<Box<dyn SqlTransaction>, SqlError> {
        let conn = db.connect().map_err(SqlError::other)?;
        if self.local {
            // Per-connection: a contended writer waits for the lock rather than
            // erroring. (Remote leaves this to sqld.)
            run_pragma(&conn, &format!("PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")).await?;
        }
        conn.execute("BEGIN", ()).await.map_err(SqlError::other)?;
        Ok(Box::new(LibsqlTxn { conn }))
    }
}

#[async_trait]
impl SqlBackend for LibsqlSql {
    async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
        // Writes always land on the primary.
        self.begin_on(&self.db).await
    }

    async fn begin_read_only(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
        // Route reads to the replica when one is configured, else the primary.
        match &self.read_db {
            Some(replica) => self.begin_on(replica).await,
            None => self.begin_on(&self.db).await,
        }
    }
}

struct LibsqlTxn {
    conn: Connection,
}

#[async_trait]
impl SqlTransaction for LibsqlTxn {
    async fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<SqlRows, SqlError> {
        let mut rows = self
            .conn
            .query(sql, libsql::params_from_iter(to_libsql(params)))
            .await
            .map_err(SqlError::other)?;
        let columns = (0..rows.column_count())
            .map(|i| rows.column_name(i).unwrap_or_default().to_string())
            .collect();
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(SqlError::other)? {
            let mut cells = Vec::with_capacity(row.column_count() as usize);
            for i in 0..row.column_count() {
                cells.push(from_libsql(row.get_value(i).map_err(SqlError::other)?));
            }
            out.push(cells);
        }
        Ok(SqlRows { columns, rows: out })
    }

    async fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
        self.conn
            .execute(sql, libsql::params_from_iter(to_libsql(params)))
            .await
            .map_err(SqlError::other)
    }

    async fn commit(self: Box<Self>) -> Result<(), SqlError> {
        self.conn
            .execute("COMMIT", ())
            .await
            .map_err(SqlError::other)?;
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> Result<(), SqlError> {
        self.conn
            .execute("ROLLBACK", ())
            .await
            .map_err(SqlError::other)?;
        Ok(())
    }
}

/// Run a `PRAGMA` (or other settings statement). libsql's `execute` rejects
/// row-returning statements, and a value-setting `PRAGMA` returns the new value
/// as a row, so run it via `query` and drain.
async fn run_pragma(conn: &Connection, sql: &str) -> Result<(), SqlError> {
    let mut rows = conn.query(sql, ()).await.map_err(SqlError::other)?;
    while rows.next().await.map_err(SqlError::other)?.is_some() {}
    Ok(())
}

fn to_libsql(params: &[SqlValue]) -> Vec<LibsqlValue> {
    params
        .iter()
        .map(|value| match value {
            SqlValue::Null => LibsqlValue::Null,
            // SQLite has no boolean type — store as 0/1.
            SqlValue::Boolean(b) => LibsqlValue::Integer(*b as i64),
            SqlValue::Integer(i) => LibsqlValue::Integer(*i),
            SqlValue::Real(f) => LibsqlValue::Real(*f),
            SqlValue::Text(s) => LibsqlValue::Text(s.clone()),
            SqlValue::Blob(b) => LibsqlValue::Blob(b.clone()),
        })
        .collect()
}

fn from_libsql(value: LibsqlValue) -> SqlValue {
    match value {
        LibsqlValue::Null => SqlValue::Null,
        LibsqlValue::Integer(i) => SqlValue::Integer(i),
        LibsqlValue::Real(f) => SqlValue::Real(f),
        LibsqlValue::Text(s) => SqlValue::Text(s),
        LibsqlValue::Blob(b) => SqlValue::Blob(b),
    }
}

/// The per-site [`SqlBackends`] for the handler `sql` binding — the single SQL
/// backend. Each site gets a **real database boundary** (sqld/SQLite has no
/// cross-database SQL, so a handler's arbitrary guest SQL can never reach
/// another tenant), in one of two modes selected by config:
///
/// - [`local`](Self::local) — single-node: an embedded database **file per
///   site** under a directory (`{dir}/{site}.db`, `{dir}/{site}/{name}.db` for a
///   named one). No server.
/// - [`remote`](Self::remote) — cluster: each site is its own **namespace** on a
///   shared sqld primary (read-replicable), addressed as a subdomain of the data
///   URL (sqld Host-header routing) and created on first use via the admin API.
///
/// The guest UX (`sql.open(name)`) is identical across both — the single-node /
/// cluster difference is an environment detail behind this backend.
pub struct LibsqlSqlBackends {
    mode: Mode,
    preview_mode: PreviewSqlMode,
    preview_init: Option<Arc<str>>,
    cache: Mutex<HashMap<(String, String), Arc<dyn SqlBackend>>>,
}

enum Mode {
    /// Embedded file per site, rooted at `dir` (single-node).
    Local { dir: PathBuf },
    /// Namespace per site on a remote sqld primary (cluster).
    Remote {
        base_url: String,
        admin_url: String,
        token: String,
        admin_token: Option<String>,
        /// Optional read-replica data plane (a sqld replica). When set, each
        /// site's database routes read-only transactions to its namespace here
        /// while writes stay on `base_url`.
        replica_base_url: Option<String>,
        http: reqwest::Client,
    },
}

impl LibsqlSqlBackends {
    /// Single-node: per-site embedded database files rooted at `dir`.
    pub fn local(dir: impl Into<PathBuf>) -> Self {
        Self {
            mode: Mode::Local { dir: dir.into() },
            preview_mode: PreviewSqlMode::default(),
            preview_init: None,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Cluster: per-site namespaces on the sqld at `base_url` (data plane),
    /// created via `admin_url`. `token` authenticates data connections (empty
    /// for none); `admin_token` is the admin API bearer key, if set.
    pub fn remote(
        base_url: impl Into<String>,
        admin_url: impl Into<String>,
        token: impl Into<String>,
        admin_token: Option<String>,
    ) -> Self {
        Self {
            mode: Mode::Remote {
                base_url: base_url.into(),
                admin_url: admin_url.into(),
                token: token.into(),
                admin_token,
                replica_base_url: None,
                http: reqwest::Client::new(),
            },
            preview_mode: PreviewSqlMode::default(),
            preview_init: None,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Route read-only transactions to a sqld **read replica** at
    /// `replica_base_url` (writes still go to the primary). Each site's
    /// namespace is addressed on the replica the same way it is on the primary
    /// (Host-subdomain routing). A no-op in single-node (`local`) mode, where
    /// there is no separate read endpoint.
    pub fn with_read_replica(mut self, replica_base_url: impl Into<String>) -> Self {
        if let Mode::Remote {
            replica_base_url: slot,
            ..
        } = &mut self.mode
        {
            *slot = Some(replica_base_url.into());
        }
        self
    }

    /// Configure how preview deployments get their SQL database (default
    /// [`PreviewSqlMode::Empty`]). `init` is an **idempotent** SQL script
    /// (e.g. `CREATE TABLE IF NOT EXISTS …`) run when an `Empty` preview database
    /// is first opened in this process; it's ignored in `Branch`/`Shared` modes.
    pub fn with_preview_policy(mut self, mode: PreviewSqlMode, init: Option<String>) -> Self {
        self.preview_mode = mode;
        self.preview_init = init.map(Arc::from);
        self
    }

    /// The on-disk path for a site's named database (single-node). The default
    /// (empty) name lives directly under `dir`; named databases get a per-site
    /// subdirectory.
    ///
    /// `site` and `name` are assumed already validated by [`validate_db_name`]
    /// at the `SqlBackends` boundary (`database` / `preview_database`), so they
    /// are safe path components and can't escape `dir`. The one place `site`
    /// carries a `/` is the trusted `{site}/_preview/{preview}` scope from
    /// [`Self::preview_scope`], itself built only from validated parts.
    fn local_path(dir: &Path, site: &str, name: &str) -> PathBuf {
        if name.is_empty() {
            dir.join(format!("{site}.db"))
        } else {
            dir.join(site).join(format!("{name}.db"))
        }
    }

    /// The binding identity for a preview deployment's database.
    fn preview_scope(site: &str, preview: &str) -> String {
        format!("{site}/_preview/{preview}")
    }

    /// The sqld namespace for a site's named database (empty name = default).
    fn namespace(site: &str, name: &str) -> String {
        if name.is_empty() {
            format!("bramp-{}", dns_token(site))
        } else {
            format!("bramp-{}-{}", dns_token(site), dns_token(name))
        }
    }

    /// Open (without caching) the libsql database for `(site, name)` under the
    /// configured single-node/cluster mode.
    async fn open_one(&self, site: &str, name: &str) -> Result<LibsqlSql, SqlError> {
        match &self.mode {
            Mode::Local { dir } => {
                let path = Self::local_path(dir, site, name);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(SqlError::other)?;
                }
                LibsqlSql::open_local(path).await
            }
            Mode::Remote {
                base_url,
                admin_url,
                token,
                admin_token,
                replica_base_url,
                http,
            } => {
                let ns = Self::namespace(site, name);
                Self::ensure_namespace(http, admin_url, admin_token.as_deref(), &ns).await?;
                let data_url = subdomain_url(base_url, &ns)?;
                let primary = LibsqlSql::connect_remote(&data_url, token).await?;
                // Wire the read replica's matching namespace, if configured.
                match replica_base_url {
                    Some(replica_base) => {
                        let replica_url = subdomain_url(replica_base, &ns)?;
                        let replica = LibsqlSql::connect_remote(&replica_url, token).await?;
                        Ok(primary.with_read_replica(replica))
                    }
                    None => Ok(primary),
                }
            }
        }
    }

    /// Create the namespace (idempotently) via the admin API.
    async fn ensure_namespace(
        http: &reqwest::Client,
        admin_url: &str,
        admin_token: Option<&str>,
        ns: &str,
    ) -> Result<(), SqlError> {
        let url = format!(
            "{}/v1/namespaces/{ns}/create",
            admin_url.trim_end_matches('/')
        );
        let mut req = http
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body("{}");
        if let Some(token) = admin_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await.map_err(SqlError::other)?;
        if resp.status().is_success() {
            return Ok(());
        }
        // A namespace that already exists is fine — provisioning is idempotent.
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if body.contains("already exists") {
            return Ok(());
        }
        Err(SqlError::other(format!(
            "creating sqld namespace {ns} failed ({status}): {body}"
        )))
    }
}

#[async_trait]
impl SqlBackends for LibsqlSqlBackends {
    async fn database(&self, site: &str, name: &str) -> Result<Arc<dyn SqlBackend>, SqlError> {
        validate_db_name("site", site)?;
        validate_db_name("database", name)?;
        let key = (site.to_string(), name.to_string());
        let mut cache = self.cache.lock().await;
        if let Some(backend) = cache.get(&key) {
            return Ok(backend.clone());
        }
        let backend: Arc<dyn SqlBackend> = Arc::new(self.open_one(site, name).await?);
        cache.insert(key, backend.clone());
        Ok(backend)
    }

    async fn preview_database(
        &self,
        site: &str,
        name: &str,
        preview: &str,
    ) -> Result<Arc<dyn SqlBackend>, SqlError> {
        validate_db_name("site", site)?;
        validate_db_name("database", name)?;
        validate_db_name("preview", preview)?;
        match self.preview_mode {
            // The preview shares the site's live database (reads + writes real
            // data). No isolation — opt in only when intended.
            PreviewSqlMode::Shared => self.database(site, name).await,

            // A fresh isolated database, optionally seeded by the init script.
            PreviewSqlMode::Empty => {
                let scope = Self::preview_scope(site, preview);
                let key = (scope.clone(), name.to_string());
                let mut cache = self.cache.lock().await;
                if let Some(backend) = cache.get(&key) {
                    return Ok(backend.clone());
                }
                let db = self.open_one(&scope, name).await?;
                if let Some(init) = &self.preview_init {
                    db.execute_script(init).await?;
                }
                let backend: Arc<dyn SqlBackend> = Arc::new(db);
                cache.insert(key, backend.clone());
                Ok(backend)
            }

            // A consistent copy of the live database (SQLite `VACUUM INTO`).
            // Single-node only: a server-side namespace can't be cloned to the
            // client's filesystem.
            PreviewSqlMode::Branch => {
                let Mode::Local { dir } = &self.mode else {
                    return Err(SqlError::other(
                        "preview SQL mode `branch` is single-node only; use `empty` or `shared` \
                         with a remote sqld",
                    ));
                };
                let scope = Self::preview_scope(site, preview);
                let key = (scope.clone(), name.to_string());
                let mut cache = self.cache.lock().await;
                if let Some(backend) = cache.get(&key) {
                    return Ok(backend.clone());
                }
                let preview_path = Self::local_path(dir, &scope, name);
                if !preview_path.exists() {
                    if let Some(parent) = preview_path.parent() {
                        std::fs::create_dir_all(parent).map_err(SqlError::other)?;
                    }
                    // Snapshot the live db into the preview's file.
                    let live = self.open_one(site, name).await?;
                    live.vacuum_into(&preview_path).await?;
                }
                let backend: Arc<dyn SqlBackend> =
                    Arc::new(LibsqlSql::open_local(&preview_path).await?);
                cache.insert(key, backend.clone());
                Ok(backend)
            }
        }
    }
}

/// Reject a `site`/`database`/`preview` identifier that wouldn't be safe to use
/// verbatim as an on-disk path component in single-node (local-file) mode — i.e.
/// anything that could escape the data directory. We require a strict charset
/// (ASCII letters, digits, `.`, `_`, `-`) and additionally forbid a leading `.`,
/// which rules out `.`, `..` and hidden files; the charset alone already rejects
/// path separators (`/`, `\`), NUL and any other byte. The default database is
/// the empty name (mapping to `{dir}/{site}.db`, with no component of its own),
/// so empty is accepted — nothing empty can traverse.
///
/// Validation lives here, at the `SqlBackends` boundary, so it guards **both**
/// backends uniformly and rejects a hostile name early: the remote/sqld path
/// already sanitizes via [`dns_token`], and this stops a traversal name before
/// it ever reaches the local-file [`LibsqlSqlBackends::local_path`]. Because the
/// raw components are validated here, the `{site}/_preview/{preview}` scope that
/// `local_path` later receives is composed only from safe parts (the `/` and
/// `_preview` separators are ours), so `local_path` can never be handed `../…`.
///
/// We chose to **reject** (rather than hash-sanitize like `dns_token`) so an
/// already-valid on-disk layout is never silently rewritten. It's reported as
/// [`SqlError::Other`] — the crate's established variant for backend/config
/// errors (cf. the neighbouring `subdomain_url` "invalid libsql url" and the
/// branch-mode guard). `SqlError` is defined in `boatramp-core` and has no
/// dedicated `InvalidName` variant; this hardening is scoped to this file, and
/// `SqlError::other` constructs the typed variant from a message (it does not
/// stringify an existing typed error, and adds no untyped-error dependency).
fn validate_db_name(kind: &str, value: &str) -> Result<(), SqlError> {
    // The default (empty) database name has no path component of its own.
    if value.is_empty() {
        return Ok(());
    }
    let safe = !value.starts_with('.')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if safe {
        Ok(())
    } else {
        Err(SqlError::other(format!(
            "invalid {kind} name {value:?}: must contain only ASCII letters, digits, \
             '.', '_' or '-' and may not start with '.' (rejects path separators, \
             '..' and NUL)"
        )))
    }
}

/// A DNS-label-safe token from arbitrary input: `[a-z0-9]` only (so it's valid
/// in a hostname) plus an 8-char hash, so distinct inputs never collide after
/// sanitization.
fn dns_token(raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .filter_map(|c| {
            let c = c.to_ascii_lowercase();
            (c.is_ascii_lowercase() || c.is_ascii_digit()).then_some(c)
        })
        .take(12)
        .collect();
    let sanitized = if sanitized.is_empty() {
        "x".to_string()
    } else {
        sanitized
    };
    format!("{sanitized}-{}", &sha256_hex(raw.as_bytes())[..8])
}

/// Insert `label` as the leading subdomain of `base`'s host (sqld routes
/// namespaces by Host subdomain): `http://host:port/p` → `http://label.host:port/p`.
fn subdomain_url(base: &str, label: &str) -> Result<String, SqlError> {
    let (scheme, rest) = base
        .split_once("://")
        .ok_or_else(|| SqlError::other(format!("invalid libsql url (no scheme): {base}")))?;
    Ok(format!("{scheme}://{label}.{rest}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_are_dns_safe_and_distinct() {
        let ns = LibsqlSqlBackends::namespace("My Site!! 名前", "");
        // Valid DNS label characters only (sqld routes by subdomain).
        assert!(ns
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        assert!(ns.starts_with("bramp-"));
        // Default vs named differ; different sites differ.
        assert_ne!(
            LibsqlSqlBackends::namespace("alpha", ""),
            LibsqlSqlBackends::namespace("alpha", "logs")
        );
        assert_ne!(
            LibsqlSqlBackends::namespace("alpha", ""),
            LibsqlSqlBackends::namespace("beta", "")
        );
        // Inputs that sanitize identically still differ (hash suffix).
        assert_ne!(dns_token("a-b"), dns_token("ab"));
    }

    #[test]
    fn subdomain_url_prepends_namespace() {
        assert_eq!(
            subdomain_url("http://sqld.internal:8080", "bramp-x-1234").unwrap(),
            "http://bramp-x-1234.sqld.internal:8080"
        );
        assert_eq!(
            subdomain_url("https://host/path", "ns").unwrap(),
            "https://ns.host/path"
        );
        assert!(subdomain_url("no-scheme", "ns").is_err());
    }

    #[test]
    fn validate_db_name_accepts_safe_and_rejects_unsafe() {
        // Accepted: the default (empty) name and ordinary identifiers.
        for ok in ["", "blog", "my-db_1", "site.example", "A1_b-2"] {
            validate_db_name("database", ok)
                .unwrap_or_else(|e| panic!("{ok:?} should be accepted, got {e}"));
        }
        // Rejected: traversal, path separators, hidden/dot names, NUL and any
        // out-of-charset byte — each as `SqlError::Other`.
        for bad in [
            "..",
            ".",
            ".hidden",
            "/",
            "a/b",
            "..\\..",
            "a\\b",
            "../../etc/passwd",
            "a\0b",
            "naïve",
            "a b",
            "a:b",
        ] {
            assert!(
                matches!(validate_db_name("database", bad), Err(SqlError::Other(_))),
                "{bad:?} must be rejected as SqlError::Other"
            );
        }
    }

    /// The fix must not change the on-disk layout of already-valid names (it only
    /// rejects unsafe ones), so `local_path` still maps them exactly as before.
    #[test]
    fn local_path_layout_unchanged_for_valid_names() {
        let dir = Path::new("/data");
        // Default (empty) name → directly under `dir`; named → per-site subdir.
        assert_eq!(
            LibsqlSqlBackends::local_path(dir, "blog", ""),
            PathBuf::from("/data/blog.db")
        );
        assert_eq!(
            LibsqlSqlBackends::local_path(dir, "blog", "logs"),
            PathBuf::from("/data/blog/logs.db")
        );
    }

    /// End-to-end via the public `SqlBackends` API: an unsafe `site`, `name`, or
    /// preview id is rejected (no file is ever created outside `dir`), while a
    /// normal name opens fine and its path stays under `dir`.
    #[tokio::test]
    async fn database_rejects_traversal_names() {
        let dir = factory_dir("traversal");
        let backends = LibsqlSqlBackends::local(dir.clone());
        for bad in ["..", "../../etc", "a/b", "a\\b", ".hidden"] {
            assert!(
                matches!(backends.database(bad, "").await, Err(SqlError::Other(_))),
                "site {bad:?} should be rejected"
            );
            assert!(
                matches!(
                    backends.database("blog", bad).await,
                    Err(SqlError::Other(_))
                ),
                "name {bad:?} should be rejected"
            );
            assert!(
                matches!(
                    backends.preview_database("blog", "", bad).await,
                    Err(SqlError::Other(_))
                ),
                "preview {bad:?} should be rejected"
            );
        }
        // A normal site/name is accepted, and its file lands under `dir`.
        backends.database("my-site_1", "my-db_1").await.unwrap();
        let path = LibsqlSqlBackends::local_path(&dir, "my-site_1", "my-db_1");
        assert!(path.starts_with(&dir));
        assert!(!path.components().any(|c| c.as_os_str() == ".."));
    }

    async fn fresh_db(name: &str) -> LibsqlSql {
        let dir =
            std::env::temp_dir().join(format!("boatramp-libsql-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        LibsqlSql::open_local(dir.join("db.sqlite")).await.unwrap()
    }

    /// WAL: a reader holding an open transaction does **not** block a concurrent
    /// writer (under the old rollback-journal default this returned `database is
    /// locked`). Proves reads and writes to one database run concurrently.
    #[tokio::test]
    async fn wal_reader_does_not_block_writer() {
        let backend = fresh_db("walrw").await;
        {
            let mut tx = backend.begin().await.unwrap();
            tx.execute("CREATE TABLE t (v INTEGER)", &[]).await.unwrap();
            tx.execute("INSERT INTO t VALUES (1)", &[]).await.unwrap();
            tx.commit().await.unwrap();
        }
        // Reader opens a transaction and reads, then *holds it open*.
        let mut reader = backend.begin().await.unwrap();
        let seen = reader.query("SELECT count(*) FROM t", &[]).await.unwrap();
        assert_eq!(seen.rows[0][0], SqlValue::Integer(1));
        // Concurrent writer commits while the reader's transaction is still open.
        let mut writer = backend.begin().await.unwrap();
        writer
            .execute("INSERT INTO t VALUES (2)", &[])
            .await
            .expect("writer must not be blocked by an open reader under WAL");
        writer.commit().await.unwrap();
        reader.commit().await.unwrap();
    }

    /// Two writers to the same database **serialize** (the second waits on the
    /// busy-timeout for the first to commit) rather than erroring. Multi-thread
    /// so the holder's sleep doesn't stall the waiter.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_writers_serialize_without_error() {
        use std::sync::Arc;
        let backend = Arc::new(fresh_db("walww").await);
        {
            let mut tx = backend.begin().await.unwrap();
            tx.execute("CREATE TABLE t (v INTEGER)", &[]).await.unwrap();
            tx.commit().await.unwrap();
        }
        // Writer A grabs the lock and holds it ~100ms before committing.
        let a = {
            let backend = backend.clone();
            tokio::spawn(async move {
                let mut tx = backend.begin().await.unwrap();
                tx.execute("INSERT INTO t VALUES (1)", &[]).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                tx.commit().await.unwrap();
            })
        };
        // Let A acquire the write lock first.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        // Writer B's insert waits (busy_timeout) for A, then succeeds.
        let mut b = backend.begin().await.unwrap();
        b.execute("INSERT INTO t VALUES (2)", &[])
            .await
            .expect("second writer should wait for the lock, not error");
        b.commit().await.unwrap();
        a.await.unwrap();
        // Both writes landed.
        let mut tx = backend.begin().await.unwrap();
        let n = tx.query("SELECT count(*) FROM t", &[]).await.unwrap();
        assert_eq!(n.rows[0][0], SqlValue::Integer(2));
        tx.commit().await.unwrap();
    }

    /// Read-replica **routing seam**: `begin` goes to the primary, while
    /// `begin_read_only` goes to the configured read replica. Modeled with two
    /// local files standing in for primary/replica (the live sqld replica +
    /// replication lag is exercised separately behind an env gate); the
    /// distinct contents prove each transaction hit the intended endpoint.
    #[tokio::test]
    async fn read_only_routes_to_replica_writes_to_primary() {
        let primary = fresh_db("rr-primary").await;
        let replica = fresh_db("rr-replica").await;
        // Seed each endpoint with a distinguishable row.
        for (db, who) in [(&primary, "primary"), (&replica, "replica")] {
            let mut tx = db.begin().await.unwrap();
            tx.execute("CREATE TABLE t (v TEXT)", &[]).await.unwrap();
            tx.execute("INSERT INTO t VALUES (?1)", &[SqlValue::Text(who.into())])
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }

        let routed = primary.with_read_replica(replica);

        // A read-write transaction reads (and writes) the primary.
        let mut rw = routed.begin().await.unwrap();
        let seen = rw.query("SELECT v FROM t", &[]).await.unwrap();
        assert_eq!(seen.rows[0][0], SqlValue::Text("primary".into()));
        rw.commit().await.unwrap();

        // A read-only transaction is routed to the replica.
        let mut ro = routed.begin_read_only().await.unwrap();
        let seen = ro.query("SELECT v FROM t", &[]).await.unwrap();
        assert_eq!(seen.rows[0][0], SqlValue::Text("replica".into()));
        ro.commit().await.unwrap();
    }

    /// Without a replica configured, `begin_read_only` is just a normal
    /// transaction on the primary (single-node / replica-less parity).
    #[tokio::test]
    async fn read_only_falls_back_to_primary_without_replica() {
        let db = fresh_db("rr-none").await;
        let mut tx = db.begin().await.unwrap();
        tx.execute("CREATE TABLE t (v INTEGER)", &[]).await.unwrap();
        tx.execute("INSERT INTO t VALUES (7)", &[]).await.unwrap();
        tx.commit().await.unwrap();

        let mut ro = db.begin_read_only().await.unwrap();
        let seen = ro.query("SELECT v FROM t", &[]).await.unwrap();
        assert_eq!(seen.rows[0][0], SqlValue::Integer(7));
        ro.commit().await.unwrap();
    }

    /// Local-file mode runs anywhere (no service); the remote/sqld path is
    /// covered by the env-gated `tests/sql_libsql.rs`.
    #[tokio::test]
    async fn local_create_insert_select_commit_and_rollback() {
        let dir = std::env::temp_dir().join(format!("boatramp-libsql-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let backend = LibsqlSql::open_local(dir.join("db.sqlite")).await.unwrap();

        {
            let mut txn = backend.begin().await.unwrap();
            txn.execute("CREATE TABLE t (id INTEGER, name TEXT)", &[])
                .await
                .unwrap();
            let n = txn
                .execute(
                    "INSERT INTO t VALUES (?1, ?2), (?3, ?4)",
                    &[
                        SqlValue::Integer(1),
                        SqlValue::Text("a".into()),
                        SqlValue::Integer(2),
                        SqlValue::Text("b".into()),
                    ],
                )
                .await
                .unwrap();
            assert_eq!(n, 2);
            txn.commit().await.unwrap();
        }
        {
            let mut txn = backend.begin().await.unwrap();
            txn.execute("INSERT INTO t VALUES (3, 'c')", &[])
                .await
                .unwrap();
            txn.rollback().await.unwrap();
        }
        let mut txn = backend.begin().await.unwrap();
        let rows = txn
            .query("SELECT id, name FROM t ORDER BY id", &[])
            .await
            .unwrap();
        assert_eq!(rows.columns, vec!["id".to_string(), "name".to_string()]);
        assert_eq!(rows.rows.len(), 2); // the rolled-back row is gone
        assert_eq!(rows.rows[1][1], SqlValue::Text("b".into()));
        txn.commit().await.unwrap();
    }

    // ---- preview SQL modes (local, no server) ------------------------------

    fn factory_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("boatramp-prev-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    async fn put(db: &Arc<dyn SqlBackend>, sql: &str) {
        let mut tx = db.begin().await.unwrap();
        tx.execute(sql, &[]).await.unwrap();
        tx.commit().await.unwrap();
    }
    async fn one(db: &Arc<dyn SqlBackend>, sql: &str) -> Vec<SqlValue> {
        let mut tx = db.begin().await.unwrap();
        let rows = tx.query(sql, &[]).await.unwrap();
        tx.commit().await.unwrap();
        rows.rows.into_iter().flatten().collect()
    }

    #[tokio::test]
    async fn preview_empty_is_isolated_from_live() {
        let backends = LibsqlSqlBackends::local(factory_dir("empty"));
        let live = backends.database("blog", "").await.unwrap();
        put(&live, "CREATE TABLE t (v TEXT)").await;
        put(&live, "INSERT INTO t VALUES ('live')").await;
        // The preview is a fresh, separate database — the live table isn't there.
        let preview = backends.preview_database("blog", "", "pr1").await.unwrap();
        put(&preview, "CREATE TABLE t (v TEXT)").await;
        put(&preview, "INSERT INTO t VALUES ('preview')").await;
        assert_eq!(
            one(&preview, "SELECT v FROM t").await,
            vec![SqlValue::Text("preview".into())]
        );
        assert_eq!(
            one(&live, "SELECT v FROM t").await,
            vec![SqlValue::Text("live".into())]
        );
    }

    #[tokio::test]
    async fn preview_empty_runs_init_script() {
        let backends = LibsqlSqlBackends::local(factory_dir("init")).with_preview_policy(
            PreviewSqlMode::Empty,
            Some(
                "CREATE TABLE IF NOT EXISTS seed (v INTEGER); INSERT INTO seed VALUES (42);".into(),
            ),
        );
        let preview = backends.preview_database("blog", "", "pr1").await.unwrap();
        assert_eq!(
            one(&preview, "SELECT v FROM seed").await,
            vec![SqlValue::Integer(42)]
        );
    }

    #[tokio::test]
    async fn preview_branch_copies_live_then_diverges() {
        let backends = LibsqlSqlBackends::local(factory_dir("branch"))
            .with_preview_policy(PreviewSqlMode::Branch, None);
        let live = backends.database("blog", "").await.unwrap();
        put(&live, "CREATE TABLE t (v TEXT)").await;
        put(&live, "INSERT INTO t VALUES ('live-data')").await;
        // Branch sees the live data (copied), but writes stay in the copy.
        let preview = backends.preview_database("blog", "", "pr1").await.unwrap();
        assert_eq!(
            one(&preview, "SELECT v FROM t").await,
            vec![SqlValue::Text("live-data".into())]
        );
        put(&preview, "INSERT INTO t VALUES ('preview-only')").await;
        assert_eq!(
            one(&live, "SELECT count(*) FROM t").await,
            vec![SqlValue::Integer(1)]
        );
        assert_eq!(
            one(&preview, "SELECT count(*) FROM t").await,
            vec![SqlValue::Integer(2)]
        );
    }

    #[tokio::test]
    async fn preview_shared_uses_live_database() {
        let backends = LibsqlSqlBackends::local(factory_dir("shared"))
            .with_preview_policy(PreviewSqlMode::Shared, None);
        let live = backends.database("blog", "").await.unwrap();
        put(&live, "CREATE TABLE t (v TEXT)").await;
        put(&live, "INSERT INTO t VALUES ('x')").await;
        // Shared = the same database: the preview sees and writes live data.
        let preview = backends.preview_database("blog", "", "pr1").await.unwrap();
        put(&preview, "INSERT INTO t VALUES ('y')").await;
        assert_eq!(
            one(&live, "SELECT count(*) FROM t").await,
            vec![SqlValue::Integer(2)]
        );
    }
}
