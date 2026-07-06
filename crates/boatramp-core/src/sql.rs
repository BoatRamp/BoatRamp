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
#[derive(Debug, Clone)]
pub enum SqlError {
    /// The statement could not be parsed or planned.
    Syntax(String),
    /// A constraint (unique, type, foreign key, ...) was violated.
    Constraint(String),
    /// Any other backend/transport error (I/O, connection, ...).
    Other(String),
}

impl SqlError {
    /// Wrap any displayable error as [`SqlError::Other`].
    pub fn other<E: std::fmt::Display>(err: E) -> Self {
        SqlError::Other(err.to_string())
    }
}

impl std::fmt::Display for SqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SqlError::Syntax(m) => write!(f, "sql syntax error: {m}"),
            SqlError::Constraint(m) => write!(f, "sql constraint error: {m}"),
            SqlError::Other(m) => write!(f, "sql error: {m}"),
        }
    }
}

impl std::error::Error for SqlError {}

/// A per-site SQL backend (libsql — a local file or a remote sqld namespace).
///
/// One instance serves one site. The handler engine calls [`begin`] once per
/// invocation that uses SQL and drives the resulting [`SqlTransaction`] to a
/// commit (on a successful response) or rollback (on trap/error).
///
/// [`begin`]: SqlBackend::begin
#[async_trait]
pub trait SqlBackend: Send + Sync {
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
    /// Open (or reuse) the database called `name` for `site` (the empty name is
    /// the site's default database). Per-site isolation is the implementation's
    /// responsibility — a handler can only ever reach its own site's data.
    async fn database(&self, site: &str, name: &str) -> Result<Arc<dyn SqlBackend>, SqlError>;

    /// Open (or reuse) the database for a **preview** deployment `preview` of
    /// `site`. The implementation applies its configured [`PreviewSqlMode`].
    /// The default is [`PreviewSqlMode::Empty`] — an isolated database keyed by
    /// site+preview, so a preview can never touch live state.
    async fn preview_database(
        &self,
        site: &str,
        name: &str,
        preview: &str,
    ) -> Result<Arc<dyn SqlBackend>, SqlError> {
        self.database(&format!("{site}/_preview/{preview}"), name)
            .await
    }
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
