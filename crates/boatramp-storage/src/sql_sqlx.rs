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
//! ## `NULL` parameter typing
//! A positional `NULL` bind carries no SQL type in the vocabulary, so it is sent
//! with text affinity. Postgres is strict about parameter types, so a `NULL`
//! bound against a non-text column may need an explicit cast on the placeholder
//! (e.g. `$1::int`); MySQL coerces and is unaffected. Actual (non-null) values
//! bind with their natural type.

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

/// A [`SqlBackends`](boatramp_core::sql::SqlBackends) that overlays
/// operator-configured **external** databases on a managed `default` (libsql).
///
/// A guest `open(name)` for a configured name gets that shared external backend;
/// any other name falls through to `default` — the per-site libsql file or
/// namespace, isolation intact. External databases are **global and shared**
/// across every site/function that opens the name (see the module docs); a
/// preview deployment is refused an external database unless it was registered
/// with `allow_preview`, mirroring the managed backend's safe-by-default preview
/// policy so a preview can't reach the operator's live external database by
/// accident.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub struct CompositeSqlBackends {
    default: Arc<dyn boatramp_core::sql::SqlBackends>,
    external: std::collections::HashMap<String, ExternalEntry>,
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
struct ExternalEntry {
    backend: Arc<dyn boatramp_core::sql::SqlBackend>,
    allow_preview: bool,
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
impl CompositeSqlBackends {
    /// Wrap the managed `default` backend; register external databases with
    /// [`with_external`](Self::with_external).
    pub fn new(default: Arc<dyn boatramp_core::sql::SqlBackends>) -> Self {
        Self {
            default,
            external: std::collections::HashMap::new(),
        }
    }

    /// Register a named external backend (built via [`connect`]). `allow_preview`
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

    /// Whether any external database is registered (else the composite is a pure
    /// pass-through and the caller may use the `default` directly).
    pub fn has_external(&self) -> bool {
        !self.external.is_empty()
    }
}

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
#[async_trait::async_trait]
impl boatramp_core::sql::SqlBackends for CompositeSqlBackends {
    async fn database(
        &self,
        site: &str,
        name: &str,
    ) -> Result<Arc<dyn boatramp_core::sql::SqlBackend>, SqlError> {
        if let Some(entry) = self.external.get(name) {
            return Ok(entry.backend.clone());
        }
        self.default.database(site, name).await
    }

    async fn preview_database(
        &self,
        site: &str,
        name: &str,
        preview: &str,
    ) -> Result<Arc<dyn boatramp_core::sql::SqlBackend>, SqlError> {
        if let Some(entry) = self.external.get(name) {
            if entry.allow_preview {
                return Ok(entry.backend.clone());
            }
            return Err(SqlError::Other(format!(
                "external database `{name}` is not available to preview deployments \
                 (set `allow_preview` on it to permit that)"
            )));
        }
        self.default.preview_database(site, name, preview).await
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
/// module-level note on `NULL` parameter typing.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
macro_rules! bind_params {
    ($query:expr, $params:expr) => {{
        let mut q = $query;
        for value in $params {
            q = match value {
                ::boatramp_core::sql::SqlValue::Null => q.bind(Option::<String>::None),
                ::boatramp_core::sql::SqlValue::Boolean(b) => q.bind(*b),
                ::boatramp_core::sql::SqlValue::Integer(i) => q.bind(*i),
                ::boatramp_core::sql::SqlValue::Real(r) => q.bind(*r),
                ::boatramp_core::sql::SqlValue::Text(s) => q.bind(s.as_str()),
                ::boatramp_core::sql::SqlValue::Blob(b) => q.bind(b.as_slice()),
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
    use async_trait::async_trait;
    use boatramp_core::sql::{SqlBackend, SqlError, SqlRows, SqlTransaction, SqlValue};
    use sqlx::pool::PoolConnection;
    use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
    use sqlx::{Column, Postgres, Row, TypeInfo, ValueRef};

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
        PgPoolOptions::new()
            .max_connections(opts.max_connections)
            .acquire_timeout(opts.connect_timeout)
            .connect_lazy(url)
            .map_err(map_err)
    }

    /// Acquire a pooled connection and open a transaction (read-only when asked).
    async fn begin_on(pool: &PgPool, read_only: bool) -> Result<Box<dyn SqlTransaction>, SqlError> {
        let mut conn = pool.acquire().await.map_err(map_err)?;
        let stmt = if read_only {
            "BEGIN READ ONLY"
        } else {
            "BEGIN"
        };
        sqlx::query(stmt)
            .execute(&mut *conn)
            .await
            .map_err(map_err)?;
        Ok(Box::new(PgTransaction { conn }))
    }

    #[async_trait]
    impl SqlBackend for PgSqlBackend {
        async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            begin_on(&self.pool, self.read_only).await
        }

        async fn begin_read_only(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            let pool = self.read_pool.as_ref().unwrap_or(&self.pool);
            begin_on(pool, true).await
        }
    }

    /// One transaction, owning its pooled connection (raw `COMMIT`/`ROLLBACK`).
    struct PgTransaction {
        conn: PoolConnection<Postgres>,
    }

    #[async_trait]
    impl SqlTransaction for PgTransaction {
        async fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<SqlRows, SqlError> {
            let q = bind_params!(sqlx::query(sql), params);
            let rows = q.fetch_all(&mut *self.conn).await.map_err(map_err)?;
            rows_to_sql(&rows)
        }

        async fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
            let q = bind_params!(sqlx::query(sql), params);
            let done = q.execute(&mut *self.conn).await.map_err(map_err)?;
            Ok(done.rows_affected())
        }

        async fn commit(mut self: Box<Self>) -> Result<(), SqlError> {
            sqlx::query("COMMIT")
                .execute(&mut *self.conn)
                .await
                .map_err(map_err)?;
            Ok(())
        }

        async fn rollback(mut self: Box<Self>) -> Result<(), SqlError> {
            sqlx::query("ROLLBACK")
                .execute(&mut *self.conn)
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
}

// ---------------------------------------------------------------------------
// MySQL
// ---------------------------------------------------------------------------

#[cfg(feature = "sql-mysql")]
mod mysql_backend {
    use super::{map_err, ExternalSqlOptions};
    use async_trait::async_trait;
    use boatramp_core::sql::{SqlBackend, SqlError, SqlRows, SqlTransaction, SqlValue};
    use sqlx::mysql::{MySqlPool, MySqlPoolOptions, MySqlRow};
    use sqlx::pool::PoolConnection;
    use sqlx::{Column, MySql, Row, TypeInfo, ValueRef};

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
        MySqlPoolOptions::new()
            .max_connections(opts.max_connections)
            .acquire_timeout(opts.connect_timeout)
            .connect_lazy(url)
            .map_err(map_err)
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
        sqlx::query(stmt)
            .execute(&mut *conn)
            .await
            .map_err(map_err)?;
        Ok(Box::new(MySqlTransaction { conn }))
    }

    #[async_trait]
    impl SqlBackend for MySqlSqlBackend {
        async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            begin_on(&self.pool, self.read_only).await
        }

        async fn begin_read_only(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            let pool = self.read_pool.as_ref().unwrap_or(&self.pool);
            begin_on(pool, true).await
        }
    }

    struct MySqlTransaction {
        conn: PoolConnection<MySql>,
    }

    #[async_trait]
    impl SqlTransaction for MySqlTransaction {
        async fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<SqlRows, SqlError> {
            let q = bind_params!(sqlx::query(sql), params);
            let rows = q.fetch_all(&mut *self.conn).await.map_err(map_err)?;
            rows_to_sql(&rows)
        }

        async fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
            let q = bind_params!(sqlx::query(sql), params);
            let done = q.execute(&mut *self.conn).await.map_err(map_err)?;
            Ok(done.rows_affected())
        }

        async fn commit(mut self: Box<Self>) -> Result<(), SqlError> {
            sqlx::query("COMMIT")
                .execute(&mut *self.conn)
                .await
                .map_err(map_err)?;
            Ok(())
        }

        async fn rollback(mut self: Box<Self>) -> Result<(), SqlError> {
            sqlx::query("ROLLBACK")
                .execute(&mut *self.conn)
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
            tag(composite.database("s", "analytics").await).await,
            "sql error: EXTERNAL"
        );
        assert_eq!(
            tag(composite.database("s", "other").await).await,
            "sql error: DEFAULT"
        );

        // A preview is refused an external database unless it opted in...
        let err = match composite.preview_database("s", "analytics", "pr1").await {
            Ok(_) => panic!("expected an external database to be refused in preview"),
            Err(e) => e,
        };
        assert!(matches!(err, SqlError::Other(m) if m.contains("not available to preview")));
        // ...allowed when `allow_preview` is set...
        assert_eq!(
            tag(composite.preview_database("s", "shared", "pr1").await).await,
            "sql error: EXTERNAL_PREVIEW"
        );
        // ...and a non-external name keeps the managed backend's preview policy.
        assert_eq!(
            tag(composite.preview_database("s", "other", "pr1").await).await,
            "sql error: DEFAULT"
        );
    }
}
