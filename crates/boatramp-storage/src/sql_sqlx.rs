//! [`SqlBackend`] over an **external, operator-configured** Postgres or MySQL,
//! for the handler `sql` binding — the *bring-your-own-database* path.
//!
//! Unlike the libsql backend ([`sql_libsql`](crate::sql_libsql)), which gives
//! every site a **managed per-site database boundary**, an external database is
//! a resource the operator points boatramp at with a connection URL (a secret,
//! via an env var). A function/handler opens it by name through the unchanged
//! guest interface (`sql.open("analytics")`); which name maps to an external
//! database — versus a per-site libsql file/namespace — is server config
//! ([`CompositeSqlBackends`](crate::sql_sqlx::CompositeSqlBackends) selects).
//!
//! **Isolation is the operator's, not boatramp's.** An external database is a
//! single, *shared* endpoint: every site/function granted the `sql` binding and
//! the configured name reaches the same database with whatever privileges the
//! connection URL carries (it can run arbitrary SQL there). That is the same
//! deal every serverless platform offers for an external Postgres — the operator
//! chose the credentials — so this backend deliberately does **not** try to
//! recreate the per-tenant role/`REVOKE` machinery libsql avoids. Reach for it
//! for a single-tenant self-hosted deployment or a genuinely shared database;
//! keep multi-tenant *site data* on the managed libsql default.
//!
//! ## Transaction shape
//! Mirrors [`LibsqlSql`](crate::sql_libsql::LibsqlSql): a transaction **owns** a
//! pooled connection and drives raw `BEGIN [READ ONLY]` / `COMMIT` / `ROLLBACK`,
//! so read-only enforcement is the database's (a `read_only` backend, or the
//! `open-read-only` path, opens the transaction `READ ONLY` and the engine
//! rejects writes). One transaction per invocation; the engine commits on a
//! successful response and rolls back on trap/error.
//!
//! ## Value marshalling
//! The guest value vocabulary is small and engine-agnostic (null/bool/int/
//! float/text/blob). Rich column types are decoded into it by their type name:
//! integers → `integer`, float/double → `float`, `bytea`/`blob` → `blob`, and
//! `numeric`/`uuid`/timestamp/date/time/`json` are **stringified** into `text`
//! (ISO-8601 / canonical form). A column type outside that set is a clear error
//! naming the type and suggesting a `::text` cast — never a silent wrong value.
//!
//! ## Placeholders
//! The `sql` binding's contract is **numbered `?N` placeholders** (`?1`, `?2`, …)
//! on every engine — the SQLite/libsql form the WIT interface documents. This
//! backend rewrites them to the engine's native syntax before execution (Postgres
//! `$N`; MySQL positional `?`), via [`sql_placeholders`](crate::sql_placeholders),
//! which also **validates** the statement fail-closed (rejecting native `$N`, bare
//! `?`, `:name`/`@name`, out-of-range indices, and parameter miscounts) — writing
//! native `$N`/`?` in guest SQL is refused, not silently accepted.
//!
//! ## `NULL` parameter typing
//! A positional `NULL` bind carries no SQL type in the vocabulary. On Postgres it
//! is sent with an **unspecified type (OID 0)**, so the server infers the column
//! type at `Parse` — a `NULL` into any column works with no cast (see
//! `PgUntypedNull`). MySQL coerces a text null fine. Actual (non-null) values bind
//! with their natural type.
//!
//! ## `JSON` binding
//! A `SqlValue::Json` (JSON text) is bound so it reaches a JSON column with no
//! `::jsonb` cast in the query: on Postgres as `json` (OID 114, whose wire format
//! is the raw text — see `PgJson`), which lands in a `json` column directly and in
//! a `jsonb` column via the json→jsonb assignment cast; on MySQL as text (a valid
//! JSON string is accepted by a `JSON` column). SQLite/libsql store it as text.

use std::sync::Arc;
use std::time::Duration;

use boatramp_core::sql::SqlError;

/// Which external SQL engine a named database uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalSqlKind {
    /// PostgreSQL (also matches `postgresql` / `pg`). Needs the `sql-postgres`
    /// cargo feature.
    Postgres,
    /// MySQL / MariaDB. Needs the `sql-mysql` cargo feature.
    Mysql,
}

impl ExternalSqlKind {
    /// Parse a config `kind` string (case-insensitive). Returns `None` for an
    /// unrecognised engine so the caller can raise a config error naming it.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "postgres" | "postgresql" | "pg" => Some(Self::Postgres),
            "mysql" | "mariadb" => Some(Self::Mysql),
            _ => None,
        }
    }

    /// The cargo feature that must be compiled in to use this engine.
    pub fn feature(self) -> &'static str {
        match self {
            Self::Postgres => "sql-postgres",
            Self::Mysql => "sql-mysql",
        }
    }
}

/// How many pooled connections an external database opens by default.
const DEFAULT_MAX_CONNECTIONS: u32 = 8;
/// How long to wait for a free/established connection before erroring.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection options for one external database. The `url` (and optional
/// read-replica `read_url`) hold credentials and come from the environment, not
/// the config file — see the server wiring.
#[derive(Debug, Clone)]
pub struct ExternalSqlOptions {
    /// The connection URL (e.g. `postgres://user:pw@host/db`). A secret.
    pub url: String,
    /// Optional separate **read** endpoint (a replica). When set,
    /// `open-read-only` routes there; writes always use `url`.
    pub read_url: Option<String>,
    /// Maximum pooled connections.
    pub max_connections: u32,
    /// Open every transaction `READ ONLY` (the engine rejects writes). Use for a
    /// database the functions should only read.
    pub read_only: bool,
    /// Timeout acquiring/establishing a connection.
    pub connect_timeout: Duration,
}

impl ExternalSqlOptions {
    /// Options for `url` with the defaults (8 connections, 10s timeout,
    /// read-write, no replica).
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            read_url: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            read_only: false,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Route `open-read-only` transactions to `url` (a read replica).
    pub fn with_read_url(mut self, url: Option<String>) -> Self {
        self.read_url = url;
        self
    }

    /// Cap the connection pool (falls back to the default when `None`).
    pub fn with_max_connections(mut self, max: Option<u32>) -> Self {
        if let Some(max) = max.filter(|m| *m > 0) {
            self.max_connections = max;
        }
        self
    }

    /// Open every transaction `READ ONLY`.
    pub fn read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Override the connect/acquire timeout (falls back to the default when
    /// `None`).
    pub fn with_connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        if let Some(timeout) = timeout {
            self.connect_timeout = timeout;
        }
        self
    }
}

/// Connect an external [`SqlBackend`](boatramp_core::sql::SqlBackend) of `kind`.
///
/// The pool connects **lazily** (no I/O here), so a momentarily-unreachable
/// database doesn't block server start — the first `open` that uses it surfaces
/// the connection error as a SQL error. Returns an error if boatramp was built
/// without the cargo feature for `kind`.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub fn connect(
    kind: ExternalSqlKind,
    opts: &ExternalSqlOptions,
) -> Result<Arc<dyn boatramp_core::sql::SqlBackend>, SqlError> {
    match kind {
        #[cfg(feature = "sql-postgres")]
        ExternalSqlKind::Postgres => Ok(Arc::new(postgres_backend::PgSqlBackend::connect(opts)?)),
        #[cfg(not(feature = "sql-postgres"))]
        ExternalSqlKind::Postgres => Err(SqlError::Other(
            "external database kind `postgres` needs the `sql-postgres` cargo feature".into(),
        )),
        #[cfg(feature = "sql-mysql")]
        ExternalSqlKind::Mysql => Ok(Arc::new(mysql_backend::MySqlSqlBackend::connect(opts)?)),
        #[cfg(not(feature = "sql-mysql"))]
        ExternalSqlKind::Mysql => Err(SqlError::Other(
            "external database kind `mysql` needs the `sql-mysql` cargo feature".into(),
        )),
    }
}

/// Resolves a named binding to the caller's **own tenant's** SQL backend — the
/// per-tenant seam for the managed-database data plane.
///
/// Registered on a [`CompositeSqlBackends`] entry for a compute-backed managed
/// binding (every such binding is per-tenant; only a bring-your-own `url_env`
/// binding stays shared). Given the request's `(project, site)`, the implementation
/// (in `boatramp-node`) derives the tenant, resolves the per-tenant database +
/// credential, and returns a [`SqlBackend`](boatramp_core::sql::SqlBackend) that
/// connects **as that tenant's role to that tenant's database** — the isolation
/// perimeter. The composite caches the returned backend per `(binding, tenant)`.
///
/// Security: an implementation MUST derive names/credentials from `(project, site)`
/// alone (never from guest-controlled request state beyond those already-validated
/// identity parts), so tenant A's request can only ever resolve to tenant A's
/// credential.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
#[async_trait::async_trait]
pub trait PerTenantSqlResolver: Send + Sync {
    /// The [`SqlBackend`](boatramp_core::sql::SqlBackend) for the tenant identified by
    /// `(project, site)` (per the binding's `tenant`/`tenant_scope`). Returns a fresh
    /// or cached backend that connects as the tenant's role to the tenant's database.
    async fn resolve(
        &self,
        project: &str,
        site: &str,
    ) -> Result<Arc<dyn boatramp_core::sql::SqlBackend>, SqlError>;
}

/// A [`SqlBackends`](boatramp_core::sql::SqlBackends) that overlays
/// operator-configured **external** databases on a managed `default` (libsql).
///
/// A guest `open(name)` for a configured name gets that binding's backend; any
/// other name falls through to `default` — the per-site libsql file or namespace,
/// isolation intact. A binding is one of two shapes:
///
/// - **Shared external** ([`with_external`](Self::with_external)) — a bring-your-own
///   `url_env` database: a single *shared* endpoint reached by every project/site
///   that opens the name (isolation is the operator's; see the module docs).
/// - **Per-tenant** ([`with_per_tenant`](Self::with_per_tenant)) — a compute-backed
///   *managed* database: the name resolves, per request `(project, site)`, to the
///   caller's own tenant database via a [`PerTenantSqlResolver`]. The resolved
///   backend is cached per `(name, tenant-cache-key)` so a hot path doesn't
///   re-derive + reconnect each call.
///
/// A preview deployment is refused an external/per-tenant database unless it was
/// registered with `allow_preview`, mirroring the managed backend's safe-by-default
/// preview policy so a preview can't reach live data by accident.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub struct CompositeSqlBackends {
    default: Arc<dyn boatramp_core::sql::SqlBackends>,
    external: std::collections::HashMap<String, ExternalEntry>,
    per_tenant: std::collections::HashMap<String, PerTenantEntry>,
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
struct ExternalEntry {
    backend: Arc<dyn boatramp_core::sql::SqlBackend>,
    allow_preview: bool,
}

/// A per-tenant binding: its resolver plus a cache of already-resolved per-tenant
/// backends keyed by the resolver's tenant-cache key (`"<project>"` or
/// `"<project>/<site>"`). The cache guard is a plain `std::sync::Mutex` held only to
/// read/insert the `Arc` (never across the resolver's `.await`).
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
struct PerTenantEntry {
    resolver: Arc<dyn PerTenantSqlResolver>,
    allow_preview: bool,
    /// The tenant grain (`tenant_scope == Site`) — selects the cache key shape.
    site_scoped: bool,
    cache: std::sync::Mutex<
        std::collections::HashMap<String, Arc<dyn boatramp_core::sql::SqlBackend>>,
    >,
}

/// The `(project, site)`-derived key under which a per-tenant binding caches its
/// resolved backend. Mirrors the tenant grain: a project tenant caches by project;
/// a finer site tenant caches by `"<project>/<site>"`. Kept in this crate (not the
/// node) so the composite can key its cache without a node dependency; the node's
/// resolver derives the *same* tenant identity from the same inputs. `site_scoped`
/// selects the grain (the binding's `tenant_scope == Site`).
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
fn tenant_cache_key(project: &str, site: &str, site_scoped: bool) -> String {
    if site_scoped {
        format!("{project}/{site}")
    } else {
        project.to_string()
    }
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
impl CompositeSqlBackends {
    /// Wrap the managed `default` backend; register external databases with
    /// [`with_external`](Self::with_external) and per-tenant managed ones with
    /// [`with_per_tenant`](Self::with_per_tenant).
    pub fn new(default: Arc<dyn boatramp_core::sql::SqlBackends>) -> Self {
        Self {
            default,
            external: std::collections::HashMap::new(),
            per_tenant: std::collections::HashMap::new(),
        }
    }

    /// Register a named **shared external** backend (built via [`connect`]) — a
    /// bring-your-own `url_env` database, a single shared endpoint. `allow_preview`
    /// permits preview deployments to reach it; naming it `""` replaces the
    /// site's default managed database with the shared external one.
    pub fn with_external(
        mut self,
        name: impl Into<String>,
        backend: Arc<dyn boatramp_core::sql::SqlBackend>,
        allow_preview: bool,
    ) -> Self {
        self.external.insert(
            name.into(),
            ExternalEntry {
                backend,
                allow_preview,
            },
        );
        self
    }

    /// Register a named **per-tenant** managed binding: a `resolver` that maps the
    /// request's `(project, site)` to the caller's own tenant database, plus the
    /// tenant grain (`site_scoped` = the binding's `tenant_scope == Site`), used to
    /// key the resolved-backend cache. `allow_preview` permits preview deployments.
    pub fn with_per_tenant(
        mut self,
        name: impl Into<String>,
        resolver: Arc<dyn PerTenantSqlResolver>,
        site_scoped: bool,
        allow_preview: bool,
    ) -> Self {
        self.per_tenant.insert(
            name.into(),
            PerTenantEntry {
                resolver,
                allow_preview,
                site_scoped,
                cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            },
        );
        self
    }

    /// Whether any external or per-tenant database is registered (else the composite
    /// is a pure pass-through and the caller may use the `default` directly).
    pub fn has_external(&self) -> bool {
        !self.external.is_empty() || !self.per_tenant.is_empty()
    }

    /// Resolve a per-tenant binding for `(project, site)`, caching the result by the
    /// binding's tenant grain so a hot path re-uses the connection. The lock is held
    /// only for the map read/insert, never across the resolver's `.await`.
    async fn resolve_per_tenant(
        &self,
        entry: &PerTenantEntry,
        project: &str,
        site: &str,
    ) -> Result<Arc<dyn boatramp_core::sql::SqlBackend>, SqlError> {
        let key = tenant_cache_key(project, site, entry.site_scoped);
        if let Some(hit) = entry
            .cache
            .lock()
            .expect("per-tenant sql cache poisoned")
            .get(&key)
            .cloned()
        {
            return Ok(hit);
        }
        let backend = entry.resolver.resolve(project, site).await?;
        entry
            .cache
            .lock()
            .expect("per-tenant sql cache poisoned")
            .insert(key, backend.clone());
        Ok(backend)
    }
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
#[async_trait::async_trait]
impl boatramp_core::sql::SqlBackends for CompositeSqlBackends {
    async fn database(
        &self,
        project: &str,
        site: &str,
        name: &str,
    ) -> Result<Arc<dyn boatramp_core::sql::SqlBackend>, SqlError> {
        // A per-tenant managed binding resolves to the caller's OWN tenant database
        // (the isolation perimeter), keyed by (project, site) per its grain.
        if let Some(entry) = self.per_tenant.get(name) {
            return self.resolve_per_tenant(entry, project, site).await;
        }
        // A bring-your-own external database is a single *shared* endpoint by design
        // (see the type docs): every project/site opening the name reaches it.
        if let Some(entry) = self.external.get(name) {
            return Ok(entry.backend.clone());
        }
        // Fall-through: the managed `default` (per-site libsql), which qualifies the
        // site by `project` itself.
        self.default.database(project, site, name).await
    }

    async fn preview_database(
        &self,
        project: &str,
        site: &str,
        name: &str,
        preview: &str,
    ) -> Result<Arc<dyn boatramp_core::sql::SqlBackend>, SqlError> {
        if let Some(entry) = self.per_tenant.get(name) {
            if entry.allow_preview {
                // A preview shares its parent tenant's managed database (there is no
                // separate per-preview managed server); the parent's isolation still
                // holds. Gated by `allow_preview` exactly like the shared-external case.
                return self.resolve_per_tenant(entry, project, site).await;
            }
            return Err(SqlError::Other(format!(
                "managed database `{name}` is not available to preview deployments \
                 (set `allow_preview` on it to permit that)"
            )));
        }
        if let Some(entry) = self.external.get(name) {
            if entry.allow_preview {
                return Ok(entry.backend.clone());
            }
            return Err(SqlError::Other(format!(
                "external database `{name}` is not available to preview deployments \
                 (set `allow_preview` on it to permit that)"
            )));
        }
        self.default
            .preview_database(project, site, name, preview)
            .await
    }
}

// ---------------------------------------------------------------------------
// Shared sqlx helpers (compiled when at least one engine feature is on).
// ---------------------------------------------------------------------------

/// Classify a sqlx error into the guest-facing [`SqlError`] variants using the
/// portable SQLSTATE class (both Postgres and MySQL report one): `23xxx` =
/// integrity-constraint violation, `42xxx` = syntax / access-rule violation,
/// everything else (connection, I/O, decode, ...) is `Other`.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
fn map_err(err: sqlx::Error) -> SqlError {
    if let sqlx::Error::Database(db) = &err {
        if let Some(code) = db.code() {
            if code.starts_with("23") {
                return SqlError::Constraint(db.message().to_string());
            }
            if code.starts_with("42") {
                return SqlError::Syntax(db.message().to_string());
            }
        }
        return SqlError::Other(db.message().to_string());
    }
    SqlError::Other(err.to_string())
}

/// Bind the guest params onto a sqlx query in positional order. See the
/// module-level note on `NULL` parameter typing. `$null` is the value bound for a
/// `SqlValue::Null` — it differs per backend (Postgres wants an unspecified-type
/// null so the server infers the column type; MySQL coerces a text null fine).
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
macro_rules! bind_params {
    ($query:expr, $params:expr, $null:expr, $json:expr $(,)?) => {{
        let mut q = $query;
        for value in $params {
            q = match value {
                ::boatramp_core::sql::SqlValue::Null => q.bind($null),
                ::boatramp_core::sql::SqlValue::Boolean(b) => q.bind(*b),
                ::boatramp_core::sql::SqlValue::Integer(i) => q.bind(*i),
                ::boatramp_core::sql::SqlValue::Real(r) => q.bind(*r),
                ::boatramp_core::sql::SqlValue::Text(s) => q.bind(s.as_str()),
                ::boatramp_core::sql::SqlValue::Blob(b) => q.bind(b.as_slice()),
                // JSON differs per engine (`$json` wraps the text with the right
                // column type); see the module note on JSON binding.
                ::boatramp_core::sql::SqlValue::Json(s) => q.bind($json(s.as_str())),
            };
        }
        q
    }};
}

// ---------------------------------------------------------------------------
// PostgreSQL
// ---------------------------------------------------------------------------

#[cfg(feature = "sql-postgres")]
mod postgres_backend {
    use super::{map_err, ExternalSqlOptions};
    use crate::sql_placeholders::PlaceholderDialect;
    use async_trait::async_trait;
    use boatramp_core::sql::{SqlBackend, SqlError, SqlRows, SqlTransaction, SqlValue};
    use sqlx::pool::PoolConnection;
    use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions, PgRow};
    // `ConnectOptions` provides `log_statements` / `log_slow_statements` on the
    // per-connection options (silences credential-DDL logging; see `build_pool`).
    use sqlx::{Column, ConnectOptions, Executor, Postgres, Row, TypeInfo, ValueRef};

    /// A `NULL` bound with an **unspecified** Postgres type (OID 0), so the server
    /// infers the target column's type at `Parse`. Binding `None::<String>` instead
    /// forces `text` affinity, which a strict non-text column (`bigint`, `jsonb`, …)
    /// rejects with no cast — the latent-bug source this fixes. Non-null values are
    /// unaffected; they still bind with their natural type.
    struct PgUntypedNull;

    impl sqlx::Type<Postgres> for PgUntypedNull {
        fn type_info() -> sqlx::postgres::PgTypeInfo {
            sqlx::postgres::PgTypeInfo::with_oid(sqlx::postgres::types::Oid(0))
        }
    }

    impl<'q> sqlx::Encode<'q, Postgres> for PgUntypedNull {
        fn encode_by_ref(
            &self,
            _buf: &mut sqlx::postgres::PgArgumentBuffer,
        ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
            Ok(sqlx::encode::IsNull::Yes)
        }
    }

    /// A JSON document bound as Postgres `json` (OID 114) — whose binary wire
    /// format is the raw JSON text — so it lands in a `json` column directly and in
    /// a `jsonb` column via the built-in json→jsonb assignment cast, with no
    /// `::jsonb` in the query. Non-JSON values are unaffected.
    struct PgJson<'a>(&'a str);

    impl sqlx::Type<Postgres> for PgJson<'_> {
        fn type_info() -> sqlx::postgres::PgTypeInfo {
            sqlx::postgres::PgTypeInfo::with_oid(sqlx::postgres::types::Oid(114))
        }
    }

    impl<'q> sqlx::Encode<'q, Postgres> for PgJson<'q> {
        fn encode_by_ref(
            &self,
            buf: &mut sqlx::postgres::PgArgumentBuffer,
        ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
            buf.extend_from_slice(self.0.as_bytes());
            Ok(sqlx::encode::IsNull::No)
        }
    }

    /// An external PostgreSQL [`SqlBackend`] over a lazily-connecting pool.
    pub struct PgSqlBackend {
        pool: PgPool,
        /// Optional read-replica pool for `open-read-only`.
        read_pool: Option<PgPool>,
        read_only: bool,
    }

    impl PgSqlBackend {
        /// Build the (lazy) pools from `opts`. No connection is opened yet.
        pub fn connect(opts: &ExternalSqlOptions) -> Result<Self, SqlError> {
            let pool = build_pool(&opts.url, opts)?;
            let read_pool = match &opts.read_url {
                Some(url) => Some(build_pool(url, opts)?),
                None => None,
            };
            Ok(Self {
                pool,
                read_pool,
                read_only: opts.read_only,
            })
        }
    }

    fn build_pool(url: &str, opts: &ExternalSqlOptions) -> Result<PgPool, SqlError> {
        // sqlx logs every statement (on the `sqlx::query` target, INFO by default).
        // This same connection runs per-tenant provisioning DDL — `CREATE ROLE …
        // PASSWORD '…'` / `ALTER ROLE …` — so statement logging would leak the managed
        // credential into the logs (the password is in the statement text, not a bound
        // parameter). Silence it entirely — statements AND the slow-statement warning —
        // on the connect options every pooled connection is opened with.
        let connect_opts: PgConnectOptions = url
            .parse::<PgConnectOptions>()
            .map_err(map_err)?
            .log_statements(log::LevelFilter::Off)
            .log_slow_statements(log::LevelFilter::Off, std::time::Duration::default());
        Ok(PgPoolOptions::new()
            .max_connections(opts.max_connections)
            .acquire_timeout(opts.connect_timeout)
            .connect_lazy_with(connect_opts))
    }

    /// Acquire a pooled connection and open a transaction (read-only when asked).
    async fn begin_on(pool: &PgPool, read_only: bool) -> Result<Box<dyn SqlTransaction>, SqlError> {
        let mut conn = pool.acquire().await.map_err(map_err)?;
        let stmt = if read_only {
            "BEGIN READ ONLY"
        } else {
            "BEGIN"
        };
        // Transaction-control statements go through the text protocol: MySQL's
        // prepared-statement protocol rejects START TRANSACTION / COMMIT /
        // ROLLBACK ("not supported in the prepared statement protocol yet").
        (&mut *conn).execute(stmt).await.map_err(map_err)?;
        Ok(Box::new(PgTransaction { conn }))
    }

    #[async_trait]
    impl SqlBackend for PgSqlBackend {
        fn dialect(&self) -> boatramp_core::sql::Dialect {
            boatramp_core::sql::Dialect::Postgres
        }

        async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            begin_on(&self.pool, self.read_only).await
        }

        async fn begin_read_only(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            let pool = self.read_pool.as_ref().unwrap_or(&self.pool);
            begin_on(pool, true).await
        }

        async fn run_script(&self, sql: &str) -> Result<(), SqlError> {
            // Simple-query protocol on one pooled connection: runs the whole
            // multi-statement script (CREATE EXTENSION + chained DDL) that the
            // parameterized per-statement path can't express — the operator migration
            // path. An error in any statement aborts the batch and surfaces here.
            sqlx::raw_sql(sql)
                .execute(&self.pool)
                .await
                .map(|_| ())
                .map_err(map_err)
        }
    }

    /// One transaction, owning its pooled connection (raw `COMMIT`/`ROLLBACK`).
    struct PgTransaction {
        conn: PoolConnection<Postgres>,
    }

    #[async_trait]
    impl SqlTransaction for PgTransaction {
        async fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<SqlRows, SqlError> {
            // Rewrite the `?N` contract to Postgres `$N` (same numbering ⇒ natural
            // bind order) and reject any non-canonical placeholder / miscount.
            let stmt = crate::sql_placeholders::normalize(
                sql,
                PlaceholderDialect::Postgres,
                params.len(),
            )?;
            let bound = stmt.reorder(params);
            let q = bind_params!(
                sqlx::query(stmt.sql.as_ref()),
                bound.as_ref(),
                PgUntypedNull,
                PgJson,
            );
            let rows = q.fetch_all(&mut *self.conn).await.map_err(map_err)?;
            rows_to_sql(&rows)
        }

        async fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
            let stmt = crate::sql_placeholders::normalize(
                sql,
                PlaceholderDialect::Postgres,
                params.len(),
            )?;
            let bound = stmt.reorder(params);
            let q = bind_params!(
                sqlx::query(stmt.sql.as_ref()),
                bound.as_ref(),
                PgUntypedNull,
                PgJson,
            );
            let done = q.execute(&mut *self.conn).await.map_err(map_err)?;
            Ok(done.rows_affected())
        }

        async fn commit(mut self: Box<Self>) -> Result<(), SqlError> {
            (&mut *self.conn).execute("COMMIT").await.map_err(map_err)?;
            Ok(())
        }

        async fn rollback(mut self: Box<Self>) -> Result<(), SqlError> {
            (&mut *self.conn)
                .execute("ROLLBACK")
                .await
                .map_err(map_err)?;
            Ok(())
        }
    }

    fn rows_to_sql(rows: &[PgRow]) -> Result<SqlRows, SqlError> {
        let mut columns = Vec::new();
        if let Some(first) = rows.first() {
            columns.extend(first.columns().iter().map(|c| c.name().to_string()));
        }
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let mut cells = Vec::with_capacity(row.columns().len());
            for i in 0..row.columns().len() {
                cells.push(decode(row, i)?);
            }
            out.push(cells);
        }
        Ok(SqlRows { columns, rows: out })
    }

    /// The value class a Postgres column type name maps to.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum PgClass {
        Bool,
        I16,
        I32,
        I64,
        F32,
        F64,
        Numeric,
        Text,
        Bytea,
        Uuid,
        Timestamp,
        TimestampTz,
        Date,
        Time,
        Json,
        Unsupported,
    }

    /// Map a Postgres type name (sqlx reports the canonical upper-case name) to a
    /// value class. Pure — unit-tested.
    pub(super) fn pg_class(name: &str) -> PgClass {
        match name {
            "BOOL" => PgClass::Bool,
            "INT2" => PgClass::I16,
            "INT4" => PgClass::I32,
            "INT8" => PgClass::I64,
            "FLOAT4" => PgClass::F32,
            "FLOAT8" => PgClass::F64,
            "NUMERIC" => PgClass::Numeric,
            "TEXT" | "VARCHAR" | "BPCHAR" | "CHAR" | "NAME" | "CITEXT" | "UNKNOWN" => PgClass::Text,
            "BYTEA" => PgClass::Bytea,
            "UUID" => PgClass::Uuid,
            "TIMESTAMP" => PgClass::Timestamp,
            "TIMESTAMPTZ" => PgClass::TimestampTz,
            "DATE" => PgClass::Date,
            "TIME" => PgClass::Time,
            "JSON" | "JSONB" => PgClass::Json,
            _ => PgClass::Unsupported,
        }
    }

    fn decode(row: &PgRow, i: usize) -> Result<SqlValue, SqlError> {
        let name = row.column(i).type_info().name();
        if row.try_get_raw(i).map_err(map_err)?.is_null() {
            return Ok(SqlValue::Null);
        }
        let value = match pg_class(name) {
            PgClass::Bool => SqlValue::Boolean(get::<bool>(row, i)?),
            PgClass::I16 => SqlValue::Integer(get::<i16>(row, i)? as i64),
            PgClass::I32 => SqlValue::Integer(get::<i32>(row, i)? as i64),
            PgClass::I64 => SqlValue::Integer(get::<i64>(row, i)?),
            PgClass::F32 => SqlValue::Real(get::<f32>(row, i)? as f64),
            PgClass::F64 => SqlValue::Real(get::<f64>(row, i)?),
            PgClass::Numeric => SqlValue::Text(get::<sqlx::types::BigDecimal>(row, i)?.to_string()),
            PgClass::Text => SqlValue::Text(get::<String>(row, i)?),
            PgClass::Bytea => SqlValue::Blob(get::<Vec<u8>>(row, i)?),
            PgClass::Uuid => SqlValue::Text(get::<sqlx::types::Uuid>(row, i)?.to_string()),
            PgClass::Timestamp => {
                SqlValue::Text(get::<sqlx::types::chrono::NaiveDateTime>(row, i)?.to_string())
            }
            PgClass::TimestampTz => SqlValue::Text(
                get::<sqlx::types::chrono::DateTime<sqlx::types::chrono::Utc>>(row, i)?
                    .to_rfc3339(),
            ),
            PgClass::Date => {
                SqlValue::Text(get::<sqlx::types::chrono::NaiveDate>(row, i)?.to_string())
            }
            PgClass::Time => {
                SqlValue::Text(get::<sqlx::types::chrono::NaiveTime>(row, i)?.to_string())
            }
            PgClass::Json => SqlValue::Text(get::<sqlx::types::JsonValue>(row, i)?.to_string()),
            PgClass::Unsupported => {
                return Err(SqlError::Other(format!(
                    "unsupported postgres column type `{name}` (column {i}); \
                     cast it to text in your query, e.g. `SELECT col::text`"
                )))
            }
        };
        Ok(value)
    }

    fn get<'r, T>(row: &'r PgRow, i: usize) -> Result<T, SqlError>
    where
        T: sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
    {
        row.try_get::<T, _>(i).map_err(map_err)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The provisioning pool must build with statement logging disabled so
        /// credential DDL (`CREATE ROLE … PASSWORD '…'`) never reaches the logs. A
        /// lazy pool opens no connection, so this exercises the connect-options build
        /// path (URL parse + `log_statements(Off)`) that carries that setting; the
        /// pool constructing at all proves the logging config is accepted. Runs in a
        /// Tokio context because a lazy pool spawns its idle reaper on build.
        #[tokio::test]
        async fn build_pool_disables_statement_logging() {
            let opts = ExternalSqlOptions::new("postgres://app:s3cret@10.0.0.5:5432/analytics");
            let pool = build_pool(&opts.url, &opts).expect("lazy pool builds");
            // A lazy pool holds no live connections until first use.
            assert_eq!(pool.size(), 0);
        }

        /// A malformed URL still fails cleanly (parsed via `PgConnectOptions`, not
        /// silently ignored) — the credential-silencing path doesn't mask bad config.
        #[test]
        fn build_pool_rejects_a_malformed_url() {
            let opts = ExternalSqlOptions::new("not a url");
            assert!(build_pool(&opts.url, &opts).is_err());
        }
    }
}

// ---------------------------------------------------------------------------
// MySQL
// ---------------------------------------------------------------------------

#[cfg(feature = "sql-mysql")]
mod mysql_backend {
    use super::{map_err, ExternalSqlOptions};
    use crate::sql_placeholders::PlaceholderDialect;
    use async_trait::async_trait;
    use boatramp_core::sql::{SqlBackend, SqlError, SqlRows, SqlTransaction, SqlValue};
    use sqlx::mysql::{MySqlConnectOptions, MySqlPool, MySqlPoolOptions, MySqlRow};
    use sqlx::pool::PoolConnection;
    // `ConnectOptions` provides `log_statements` / `log_slow_statements` on the
    // per-connection options (silences credential-DDL logging; see `build_pool`).
    use sqlx::{Column, ConnectOptions, Executor, MySql, Row, TypeInfo, ValueRef};

    /// MySQL binds a JSON document as its text — a valid JSON string is accepted by
    /// a JSON column directly, no special type. A fn item (not a closure) so it is
    /// higher-ranked over the borrow's lifetime for `bind_params!`.
    fn json_as_text(s: &str) -> &str {
        s
    }

    /// An external MySQL/MariaDB [`SqlBackend`] over a lazily-connecting pool.
    pub struct MySqlSqlBackend {
        pool: MySqlPool,
        read_pool: Option<MySqlPool>,
        read_only: bool,
    }

    impl MySqlSqlBackend {
        /// Build the (lazy) pools from `opts`. No connection is opened yet.
        pub fn connect(opts: &ExternalSqlOptions) -> Result<Self, SqlError> {
            let pool = build_pool(&opts.url, opts)?;
            let read_pool = match &opts.read_url {
                Some(url) => Some(build_pool(url, opts)?),
                None => None,
            };
            Ok(Self {
                pool,
                read_pool,
                read_only: opts.read_only,
            })
        }
    }

    fn build_pool(url: &str, opts: &ExternalSqlOptions) -> Result<MySqlPool, SqlError> {
        // See the Postgres `build_pool`: this connection runs per-tenant provisioning
        // DDL (`CREATE USER … IDENTIFIED BY '…'`), so sqlx's default INFO statement
        // logging would leak the managed credential (the password is in the statement
        // text, not a bound parameter). Silence it — statements AND the slow-statement
        // warning — on the connect options every pooled connection is opened with.
        let connect_opts: MySqlConnectOptions = url
            .parse::<MySqlConnectOptions>()
            .map_err(map_err)?
            .log_statements(log::LevelFilter::Off)
            .log_slow_statements(log::LevelFilter::Off, std::time::Duration::default());
        Ok(MySqlPoolOptions::new()
            .max_connections(opts.max_connections)
            .acquire_timeout(opts.connect_timeout)
            .connect_lazy_with(connect_opts))
    }

    async fn begin_on(
        pool: &MySqlPool,
        read_only: bool,
    ) -> Result<Box<dyn SqlTransaction>, SqlError> {
        let mut conn = pool.acquire().await.map_err(map_err)?;
        let stmt = if read_only {
            "START TRANSACTION READ ONLY"
        } else {
            "START TRANSACTION"
        };
        // Transaction-control statements go through the text protocol: MySQL's
        // prepared-statement protocol rejects START TRANSACTION / COMMIT /
        // ROLLBACK ("not supported in the prepared statement protocol yet").
        (&mut *conn).execute(stmt).await.map_err(map_err)?;
        Ok(Box::new(MySqlTransaction { conn }))
    }

    #[async_trait]
    impl SqlBackend for MySqlSqlBackend {
        fn dialect(&self) -> boatramp_core::sql::Dialect {
            boatramp_core::sql::Dialect::Mysql
        }

        async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            begin_on(&self.pool, self.read_only).await
        }

        async fn begin_read_only(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            let pool = self.read_pool.as_ref().unwrap_or(&self.pool);
            begin_on(pool, true).await
        }

        async fn run_script(&self, sql: &str) -> Result<(), SqlError> {
            // Text protocol on one pooled connection: runs the whole multi-statement
            // migration script (chained DDL/DML) the parameterized path can't express.
            // An error in any statement aborts the batch and surfaces here.
            sqlx::raw_sql(sql)
                .execute(&self.pool)
                .await
                .map(|_| ())
                .map_err(map_err)
        }
    }

    struct MySqlTransaction {
        conn: PoolConnection<MySql>,
    }

    #[async_trait]
    impl SqlTransaction for MySqlTransaction {
        async fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<SqlRows, SqlError> {
            // Rewrite the `?N` contract to MySQL positional `?`, reordering the
            // bound parameters to the placeholders' appearance order.
            let stmt =
                crate::sql_placeholders::normalize(sql, PlaceholderDialect::MySql, params.len())?;
            let bound = stmt.reorder(params);
            let q = bind_params!(
                sqlx::query(stmt.sql.as_ref()),
                bound.as_ref(),
                Option::<String>::None,
                json_as_text,
            );
            let rows = q.fetch_all(&mut *self.conn).await.map_err(map_err)?;
            rows_to_sql(&rows)
        }

        async fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
            let stmt =
                crate::sql_placeholders::normalize(sql, PlaceholderDialect::MySql, params.len())?;
            let bound = stmt.reorder(params);
            let q = bind_params!(
                sqlx::query(stmt.sql.as_ref()),
                bound.as_ref(),
                Option::<String>::None,
                json_as_text,
            );
            let done = q.execute(&mut *self.conn).await.map_err(map_err)?;
            Ok(done.rows_affected())
        }

        async fn commit(mut self: Box<Self>) -> Result<(), SqlError> {
            (&mut *self.conn).execute("COMMIT").await.map_err(map_err)?;
            Ok(())
        }

        async fn rollback(mut self: Box<Self>) -> Result<(), SqlError> {
            (&mut *self.conn)
                .execute("ROLLBACK")
                .await
                .map_err(map_err)?;
            Ok(())
        }
    }

    fn rows_to_sql(rows: &[MySqlRow]) -> Result<SqlRows, SqlError> {
        let mut columns = Vec::new();
        if let Some(first) = rows.first() {
            columns.extend(first.columns().iter().map(|c| c.name().to_string()));
        }
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let mut cells = Vec::with_capacity(row.columns().len());
            for i in 0..row.columns().len() {
                cells.push(decode(row, i)?);
            }
            out.push(cells);
        }
        Ok(SqlRows { columns, rows: out })
    }

    /// The value class a MySQL column type name maps to.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum MyClass {
        Bool,
        I8,
        U8,
        I16,
        U16,
        I32,
        U32,
        I64,
        U64,
        F32,
        F64,
        Decimal,
        Text,
        Blob,
        DateTime,
        Timestamp,
        Date,
        Time,
        Json,
        Unsupported,
    }

    /// Map a MySQL type name (sqlx reports the upper-case name, unsigned kinds
    /// suffixed ` UNSIGNED`) to a value class. Pure — unit-tested. `TINYINT(1)`
    /// (the conventional bool) is reported as `TINYINT`, so it decodes to an
    /// integer `0`/`1`.
    pub(super) fn mysql_class(name: &str) -> MyClass {
        match name {
            "BOOLEAN" => MyClass::Bool,
            "TINYINT" => MyClass::I8,
            "TINYINT UNSIGNED" => MyClass::U8,
            "SMALLINT" => MyClass::I16,
            "SMALLINT UNSIGNED" => MyClass::U16,
            "INT" | "MEDIUMINT" => MyClass::I32,
            "INT UNSIGNED" | "MEDIUMINT UNSIGNED" => MyClass::U32,
            "BIGINT" => MyClass::I64,
            "BIGINT UNSIGNED" => MyClass::U64,
            "FLOAT" => MyClass::F32,
            "DOUBLE" => MyClass::F64,
            "DECIMAL" => MyClass::Decimal,
            "VARCHAR" | "CHAR" | "TEXT" | "TINYTEXT" | "MEDIUMTEXT" | "LONGTEXT" | "ENUM"
            | "SET" => MyClass::Text,
            "BLOB" | "TINYBLOB" | "MEDIUMBLOB" | "LONGBLOB" | "BINARY" | "VARBINARY" => {
                MyClass::Blob
            }
            "DATETIME" => MyClass::DateTime,
            "TIMESTAMP" => MyClass::Timestamp,
            "DATE" => MyClass::Date,
            "TIME" => MyClass::Time,
            "JSON" => MyClass::Json,
            _ => MyClass::Unsupported,
        }
    }

    fn decode(row: &MySqlRow, i: usize) -> Result<SqlValue, SqlError> {
        let name = row.column(i).type_info().name();
        if row.try_get_raw(i).map_err(map_err)?.is_null() {
            return Ok(SqlValue::Null);
        }
        let value = match mysql_class(name) {
            MyClass::Bool => SqlValue::Boolean(get::<bool>(row, i)?),
            MyClass::I8 => SqlValue::Integer(get::<i8>(row, i)? as i64),
            MyClass::U8 => SqlValue::Integer(get::<u8>(row, i)? as i64),
            MyClass::I16 => SqlValue::Integer(get::<i16>(row, i)? as i64),
            MyClass::U16 => SqlValue::Integer(get::<u16>(row, i)? as i64),
            MyClass::I32 => SqlValue::Integer(get::<i32>(row, i)? as i64),
            MyClass::U32 => SqlValue::Integer(get::<u32>(row, i)? as i64),
            MyClass::I64 => SqlValue::Integer(get::<i64>(row, i)?),
            MyClass::U64 => {
                let u = get::<u64>(row, i)?;
                match i64::try_from(u) {
                    Ok(i) => SqlValue::Integer(i),
                    // Values above i64::MAX can't fit the integer variant; keep
                    // full precision as text rather than wrapping.
                    Err(_) => SqlValue::Text(u.to_string()),
                }
            }
            MyClass::F32 => SqlValue::Real(get::<f32>(row, i)? as f64),
            MyClass::F64 => SqlValue::Real(get::<f64>(row, i)?),
            MyClass::Decimal => SqlValue::Text(get::<sqlx::types::BigDecimal>(row, i)?.to_string()),
            MyClass::Text => SqlValue::Text(get::<String>(row, i)?),
            MyClass::Blob => SqlValue::Blob(get::<Vec<u8>>(row, i)?),
            MyClass::DateTime => {
                SqlValue::Text(get::<sqlx::types::chrono::NaiveDateTime>(row, i)?.to_string())
            }
            MyClass::Timestamp => SqlValue::Text(
                get::<sqlx::types::chrono::DateTime<sqlx::types::chrono::Utc>>(row, i)?
                    .to_rfc3339(),
            ),
            MyClass::Date => {
                SqlValue::Text(get::<sqlx::types::chrono::NaiveDate>(row, i)?.to_string())
            }
            MyClass::Time => {
                SqlValue::Text(get::<sqlx::types::chrono::NaiveTime>(row, i)?.to_string())
            }
            MyClass::Json => SqlValue::Text(get::<sqlx::types::JsonValue>(row, i)?.to_string()),
            MyClass::Unsupported => {
                return Err(SqlError::Other(format!(
                    "unsupported mysql column type `{name}` (column {i}); \
                     cast it to char/text in your query, e.g. `CAST(col AS CHAR)`"
                )))
            }
        };
        Ok(value)
    }

    fn get<'r, T>(row: &'r MySqlRow, i: usize) -> Result<T, SqlError>
    where
        T: sqlx::Decode<'r, MySql> + sqlx::Type<MySql>,
    {
        row.try_get::<T, _>(i).map_err(map_err)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The provisioning pool must build with statement logging disabled so
        /// credential DDL (`CREATE USER … IDENTIFIED BY '…'`) never reaches the logs.
        /// The lazy pool constructing proves the connect-options path (URL parse +
        /// `log_statements(Off)`) is accepted. Runs in a Tokio context because a lazy
        /// pool spawns its idle reaper on build.
        #[tokio::test]
        async fn build_pool_disables_statement_logging() {
            let opts = ExternalSqlOptions::new("mysql://app:s3cret@10.0.0.5:3306/shop");
            let pool = build_pool(&opts.url, &opts).expect("lazy pool builds");
            assert_eq!(pool.size(), 0);
        }

        #[test]
        fn build_pool_rejects_a_malformed_url() {
            let opts = ExternalSqlOptions::new("not a url");
            assert!(build_pool(&opts.url, &opts).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_parses_common_aliases() {
        assert_eq!(
            ExternalSqlKind::parse("postgres"),
            Some(ExternalSqlKind::Postgres)
        );
        assert_eq!(
            ExternalSqlKind::parse("PostgreSQL"),
            Some(ExternalSqlKind::Postgres)
        );
        assert_eq!(
            ExternalSqlKind::parse("  pg "),
            Some(ExternalSqlKind::Postgres)
        );
        assert_eq!(
            ExternalSqlKind::parse("mysql"),
            Some(ExternalSqlKind::Mysql)
        );
        assert_eq!(
            ExternalSqlKind::parse("MariaDB"),
            Some(ExternalSqlKind::Mysql)
        );
        assert_eq!(ExternalSqlKind::parse("oracle"), None);
    }

    #[test]
    fn kind_reports_its_feature() {
        assert_eq!(ExternalSqlKind::Postgres.feature(), "sql-postgres");
        assert_eq!(ExternalSqlKind::Mysql.feature(), "sql-mysql");
    }

    #[test]
    fn options_builder_applies_and_falls_back() {
        let opts = ExternalSqlOptions::new("postgres://localhost/db")
            .with_max_connections(Some(20))
            .read_only(true)
            .with_read_url(Some("postgres://replica/db".into()))
            .with_connect_timeout(Some(Duration::from_secs(3)));
        assert_eq!(opts.max_connections, 20);
        assert!(opts.read_only);
        assert_eq!(opts.read_url.as_deref(), Some("postgres://replica/db"));
        assert_eq!(opts.connect_timeout, Duration::from_secs(3));

        // A zero/None max falls back to the default rather than a useless pool.
        let dflt = ExternalSqlOptions::new("x").with_max_connections(Some(0));
        assert_eq!(dflt.max_connections, DEFAULT_MAX_CONNECTIONS);
        let dflt = ExternalSqlOptions::new("x").with_max_connections(None);
        assert_eq!(dflt.max_connections, DEFAULT_MAX_CONNECTIONS);
    }

    #[cfg(feature = "sql-postgres")]
    #[test]
    fn postgres_type_classes() {
        use super::postgres_backend::{pg_class, PgClass};
        assert_eq!(pg_class("BOOL"), PgClass::Bool);
        assert_eq!(pg_class("INT4"), PgClass::I32);
        assert_eq!(pg_class("INT8"), PgClass::I64);
        assert_eq!(pg_class("FLOAT8"), PgClass::F64);
        assert_eq!(pg_class("NUMERIC"), PgClass::Numeric);
        assert_eq!(pg_class("TEXT"), PgClass::Text);
        assert_eq!(pg_class("VARCHAR"), PgClass::Text);
        assert_eq!(pg_class("BYTEA"), PgClass::Bytea);
        assert_eq!(pg_class("UUID"), PgClass::Uuid);
        assert_eq!(pg_class("TIMESTAMPTZ"), PgClass::TimestampTz);
        assert_eq!(pg_class("JSONB"), PgClass::Json);
        assert_eq!(pg_class("POINT"), PgClass::Unsupported);
    }

    #[cfg(feature = "sql-mysql")]
    #[test]
    fn mysql_type_classes() {
        use super::mysql_backend::{mysql_class, MyClass};
        assert_eq!(mysql_class("TINYINT"), MyClass::I8);
        assert_eq!(mysql_class("BIGINT UNSIGNED"), MyClass::U64);
        assert_eq!(mysql_class("INT"), MyClass::I32);
        assert_eq!(mysql_class("DOUBLE"), MyClass::F64);
        assert_eq!(mysql_class("DECIMAL"), MyClass::Decimal);
        assert_eq!(mysql_class("VARCHAR"), MyClass::Text);
        assert_eq!(mysql_class("LONGBLOB"), MyClass::Blob);
        assert_eq!(mysql_class("DATETIME"), MyClass::DateTime);
        assert_eq!(mysql_class("JSON"), MyClass::Json);
        assert_eq!(mysql_class("GEOMETRY"), MyClass::Unsupported);
    }

    // A tagged fake backend whose `begin` fails with its tag, so a routing test
    // can tell which backend the composite returned.
    struct TagBackend(&'static str);

    #[async_trait::async_trait]
    impl boatramp_core::sql::SqlBackend for TagBackend {
        async fn begin(
            &self,
        ) -> Result<Box<dyn boatramp_core::sql::SqlTransaction>, boatramp_core::sql::SqlError>
        {
            Err(boatramp_core::sql::SqlError::Other(self.0.to_string()))
        }
    }

    // A fake managed default that hands out a "DEFAULT"-tagged backend for every
    // (site, name) — its default `preview_database` delegates to `database`.
    struct DefaultBackends;

    #[async_trait::async_trait]
    impl boatramp_core::sql::SqlBackends for DefaultBackends {
        async fn database(
            &self,
            _project: &str,
            _site: &str,
            _name: &str,
        ) -> Result<std::sync::Arc<dyn boatramp_core::sql::SqlBackend>, boatramp_core::sql::SqlError>
        {
            Ok(std::sync::Arc::new(TagBackend("DEFAULT")))
        }
    }

    // Which backend did the composite return? Its `begin` fails with the tag
    // (the trait objects aren't `Debug`, so match rather than `unwrap_err`).
    async fn tag(
        result: Result<
            std::sync::Arc<dyn boatramp_core::sql::SqlBackend>,
            boatramp_core::sql::SqlError,
        >,
    ) -> String {
        match result.unwrap().begin().await {
            Ok(_) => panic!("expected the tagged backend's begin to fail"),
            Err(e) => e.to_string(),
        }
    }

    #[tokio::test]
    async fn composite_routes_by_name_and_guards_preview() {
        use boatramp_core::sql::{SqlBackends, SqlError};

        let composite = CompositeSqlBackends::new(std::sync::Arc::new(DefaultBackends))
            .with_external(
                "analytics",
                std::sync::Arc::new(TagBackend("EXTERNAL")),
                false,
            )
            .with_external(
                "shared",
                std::sync::Arc::new(TagBackend("EXTERNAL_PREVIEW")),
                true,
            );
        assert!(composite.has_external());

        // A configured name routes to its external backend; any other name falls
        // through to the managed default.
        assert_eq!(
            tag(composite.database("default", "s", "analytics").await).await,
            "sql error: EXTERNAL"
        );
        assert_eq!(
            tag(composite.database("default", "s", "other").await).await,
            "sql error: DEFAULT"
        );

        // A preview is refused an external database unless it opted in...
        let err = match composite
            .preview_database("default", "s", "analytics", "pr1")
            .await
        {
            Ok(_) => panic!("expected an external database to be refused in preview"),
            Err(e) => e,
        };
        assert!(matches!(err, SqlError::Other(m) if m.contains("not available to preview")));
        // ...allowed when `allow_preview` is set...
        assert_eq!(
            tag(composite
                .preview_database("default", "s", "shared", "pr1")
                .await)
            .await,
            "sql error: EXTERNAL_PREVIEW"
        );
        // ...and a non-external name keeps the managed backend's preview policy.
        assert_eq!(
            tag(composite
                .preview_database("default", "s", "other", "pr1")
                .await)
            .await,
            "sql error: DEFAULT"
        );
    }

    // ---- per-tenant seam: routing + caching ------------------------------

    /// A resolver that hands out a `TagBackend` tagged with the tenant it was asked
    /// for, and counts how many times it actually ran (to prove the composite caches).
    struct TenantTagResolver {
        calls: std::sync::Mutex<usize>,
    }
    #[async_trait::async_trait]
    impl PerTenantSqlResolver for TenantTagResolver {
        async fn resolve(
            &self,
            project: &str,
            site: &str,
        ) -> Result<Arc<dyn boatramp_core::sql::SqlBackend>, SqlError> {
            *self.calls.lock().unwrap() += 1;
            // Leak the per-tenant tag so `TagBackend`'s &'static str requirement is met
            // in-test (the composite treats each Arc opaquely; the tag proves identity).
            let tag: &'static str = Box::leak(format!("{project}/{site}").into_boxed_str());
            Ok(std::sync::Arc::new(TagBackend(tag)))
        }
    }

    #[tokio::test]
    async fn per_tenant_routes_by_tenant_and_caches_per_grain() {
        use boatramp_core::sql::SqlBackends;

        let resolver = std::sync::Arc::new(TenantTagResolver {
            calls: std::sync::Mutex::new(0),
        });
        // Site-scoped grain: the cache key is `<project>/<site>`.
        let composite = CompositeSqlBackends::new(std::sync::Arc::new(DefaultBackends))
            .with_per_tenant("data", resolver.clone(), /* site_scoped */ true, false);
        assert!(composite.has_external());

        // Two DIFFERENT tenants resolve to DIFFERENT backends (isolation).
        assert_eq!(
            tag(composite.database("acme", "blog", "data").await).await,
            "sql error: acme/blog"
        );
        assert_eq!(
            tag(composite.database("globex", "shop", "data").await).await,
            "sql error: globex/shop"
        );
        assert_eq!(*resolver.calls.lock().unwrap(), 2, "one resolve per tenant");

        // Re-opening the SAME tenant reuses the cached backend (no extra resolve).
        assert_eq!(
            tag(composite.database("acme", "blog", "data").await).await,
            "sql error: acme/blog"
        );
        assert_eq!(
            *resolver.calls.lock().unwrap(),
            2,
            "same tenant ⇒ cache hit, resolver not called again"
        );

        // A name with no per-tenant/external entry falls through to the managed default.
        assert_eq!(
            tag(composite.database("acme", "blog", "other").await).await,
            "sql error: DEFAULT"
        );
    }

    #[tokio::test]
    async fn per_tenant_project_grain_caches_across_sites() {
        use boatramp_core::sql::SqlBackends;

        let resolver = std::sync::Arc::new(TenantTagResolver {
            calls: std::sync::Mutex::new(0),
        });
        // Project-scoped grain: the cache key is the project alone, so two sites of one
        // project share one resolve.
        let composite = CompositeSqlBackends::new(std::sync::Arc::new(DefaultBackends))
            .with_per_tenant(
                "data",
                resolver.clone(),
                /* site_scoped */ false,
                false,
            );

        let _ = composite.database("acme", "blog", "data").await.unwrap();
        let _ = composite.database("acme", "shop", "data").await.unwrap();
        assert_eq!(
            *resolver.calls.lock().unwrap(),
            1,
            "project grain ⇒ two sites of one project share one cached resolve"
        );
    }

    #[tokio::test]
    async fn per_tenant_preview_is_gated() {
        use boatramp_core::sql::{SqlBackends, SqlError};

        let resolver = std::sync::Arc::new(TenantTagResolver {
            calls: std::sync::Mutex::new(0),
        });
        // allow_preview = false ⇒ a preview deployment is refused.
        let composite = CompositeSqlBackends::new(std::sync::Arc::new(DefaultBackends))
            .with_per_tenant("data", resolver, true, false);
        let err = match composite
            .preview_database("acme", "blog", "data", "pr1")
            .await
        {
            Ok(_) => panic!("expected a managed DB to be refused in preview"),
            Err(e) => e,
        };
        assert!(matches!(err, SqlError::Other(m) if m.contains("not available to preview")));
    }
}
