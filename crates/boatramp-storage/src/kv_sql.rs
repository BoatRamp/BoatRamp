//! [`SqlKv`] — a [`KvStore`](boatramp_core::kv::KvStore) over the existing SQL connection layer,
//! the SQL-backed control-plane metadata store alongside the object-store (SlateDB) family.
//!
//! Two backings share one dialect-parameterized shape — every statement is produced by
//! [`statements_for`], keyed on [`Dialect`], and the ops dispatch on an internal [`Backing`]:
//! - **SQLite / libsql-LOCAL** (build-order step 1, feature `sql`) — the embedded **single-writer**
//!   store: the lowest-risk standalone win that also deletes the SlateDB torn-manifest /
//!   `.compactions` durability class for a single box.
//! - **Postgres** (build-order step 2, feature `sql-postgres`) — the **multi-writer** store: N equal
//!   stateless nodes point at one shared primary; the engine serializes concurrent writers itself, so
//!   the value-predicate CAS below is cross-connection linearizable w.r.t. the primary and
//!   [`writer_model`](KvStore::writer_model) is [`MultiWriter`](WriterModel::MultiWriter).
//!
//! MySQL (`UPDATE … WHERE value=` / `INSERT IGNORE`) and shared-mode coordination (ChangePublisher,
//! the stale-authz fence, the non-Raft singleton election) are later workstreams; the dialect +
//! [`statements_for`] seam and the [`Backing`] split keep them ready to slot in without reshaping the
//! ops. `statements_for` has no arm for an un-built dialect, so one is never reachable.
//!
//! ## Schema (host-owned, created idempotently on open — Architect C9)
//! Two tables, created with the same idempotent `CREATE TABLE IF NOT EXISTS` host pattern the
//! migration substrate's `ensure_ledger` uses (NOT the guest `project migrate` tool):
//! - `kv(key BLOB/BYTEA PRIMARY KEY, value BLOB/BYTEA NOT NULL, version BIGINT NOT NULL)` — the store
//!   itself. Keys are the `&str` key's UTF-8 bytes stored as a byte string so comparison/ordering is
//!   bytewise (matching Rust `str` byte order — SQLite BLOB and Postgres BYTEA both order by raw
//!   bytes), and values are the raw bytes (an empty value is a zero-length byte string, distinct from
//!   an absent key). `version` bumps on every write.
//! - `kv_changes(seq INTEGER/BIGSERIAL PRIMARY KEY, key …, version BIGINT, ts …)` — the append-only
//!   change log. The single-writer SQLite path needs no cross-node propagation yet, but every write
//!   appends a row here (a put/CAS-win records the post-write version; a delete records a tombstone —
//!   `version = 0`, since live versions start at `1`) so the multi-writer ChangePublisher of a later
//!   workstream has the ledger it polls.
//!
//! ## CAS — value-predicate, single-statement, winner-by-rows-affected (MF-2 shape)
//! [`KvStore::compare_and_swap`](boatramp_core::kv::KvStore::compare_and_swap) is VALUE-based
//! (`expected: Option<&[u8]>`, whole-record bytes). The decision is ALWAYS one statement whose
//! rows-affected names the winner — never a follow-up `SELECT`:
//! - present-key: `UPDATE kv SET value=?2, version=version+1 WHERE key=?1 AND value=?3` → winner iff
//!   `rows_affected == 1`.
//! - absent-key (`expected = None`): `INSERT INTO kv (…) VALUES (…) ON CONFLICT(key) DO NOTHING` →
//!   winner iff `rows_affected == 1`.
//!
//! On Postgres under the default READ COMMITTED isolation this is linearizable w.r.t. the primary: a
//! second present-key writer blocks on the row lock, re-reads the committed row under EvalPlanQual,
//! re-applies the `value=` predicate, and matches 0 rows; a second absent-key writer sees the
//! committed row and `DO NOTHING` affects 0 rows. A single SQLite database serializes its writers, so
//! it is linearizable w.r.t. that one store. [`SqlKv::supports_cas`] is `true` for both — honestly,
//! because every CAS (and, in later workstreams, every authz/crown-jewel read) targets the primary,
//! never a lagging replica. The change-log append runs ONLY for the winner, in the same transaction.
//!
//! ## Synchronous-commit durability (Architect C6 / MF-5)
//! Every mutating op returns ONLY after its transaction has COMMITted durably:
//! - SQLite: opened in **WAL** mode with **`PRAGMA synchronous = FULL`**, so each `COMMIT` fsyncs the
//!   WAL before the call returns (the per-connection `synchronous` is re-asserted on every write
//!   connection).
//! - Postgres: a committed txn is durable iff `synchronous_commit = on`; a non-durable setting could
//!   drop a committed revoke on crash, so [`SqlKv::open_postgres`] reads `current_setting(
//!   'synchronous_commit')` at open and **FAILS LOUD** unless it is `on`.
//!
//! This is what makes the [`CheckpointKv`](boatramp_core::kv::CheckpointKv) wrapper already correct
//! over `SqlKv`: a durable `put`/CAS-win plus the trait's no-op `checkpoint()`.
//!
//! ## Secret custody (MF-6)
//! Sealing is PRE-PUT and backend-independent: a crown-jewel value is wrapped by the envelope
//! ([`KeyEnvelope`](boatramp_core::envelope::KeyEnvelope)) BEFORE it reaches `SqlKv`, so what lands
//! in `kv.value` is already ciphertext — stored as `BYTEA`/`BLOB`, no more exposed than in SlateDB.
//! The **envelope KEK is NEVER persisted into the shared KV/DB**: it is held separately (the
//! `[secrets]` envelope), so a reader of the SQL control-plane database sees only sealed bytes.
//! The `kv_changes` append log — and any NOTIFY payload derived from it — carries **key + version
//! ONLY, never value bytes** (there is no `value` column on `kv_changes`); the
//! `sqlkv_change_log_carries_no_secret_values` gate asserts this and goes RED under the
//! `leak_change_value` mutation. **Operator note for a shared SQL control-plane DB:** SQL
//! statement/parameter logging MUST be OFF (a bound sealed value would otherwise land in the DB log),
//! and the connection to the DB MUST use TLS (the sealed bytes + the plaintext control-plane
//! config/RBAC travel the wire) — see [`SqlKv::open_postgres`].

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use boatramp_core::kv::{KvError, KvStore, WriteOp, WriterModel};
use boatramp_core::sql::Dialect;

#[cfg(feature = "sql")]
use libsql::{Builder, Connection, Database, Value as LibsqlValue};
#[cfg(feature = "sql")]
use std::path::Path;

#[cfg(feature = "sql-postgres")]
use boatramp_core::sql::{SqlBackend, SqlTransaction, SqlValue};

/// How long a contended writer waits for the single-writer lock before erroring (local SQLite).
/// Keep it under the control-plane per-op timeout so a genuinely stuck lock surfaces as an error
/// rather than hanging; a racing CAS/write simply waits its turn here (the single-writer serialize).
#[cfg(feature = "sql")]
const BUSY_TIMEOUT_MS: u32 = 5_000;

/// The default Postgres pool size (MF-2: a shared-mode CAS wants ≥16 connections so a burst of
/// concurrent control-plane writers genuinely contends rather than queueing on the pool). The
/// operator overrides it via `[serve.kv.sql] pool_max`.
#[cfg(feature = "sql-postgres")]
const DEFAULT_PG_POOL_MAX: u32 = 16;

/// The fixed set of host-authored statements for one SQL dialect. Every field is `&'static` so the
/// whole set is `Copy` and resolved once at open ([`statements_for`]); the placeholders are the
/// canonical `?N` form — libsql speaks it natively, and the external Postgres path rewrites `?N` →
/// `$N` through the existing `sql_placeholders` normalizer inside the sqlx `SqlBackend`. All
/// statements are host-built with bound parameters only (never guest text), so no placeholder
/// validation is needed here.
#[derive(Debug, Clone, Copy)]
struct KvStatements {
    /// Idempotent `CREATE TABLE IF NOT EXISTS` DDL for `kv` + `kv_changes` (run in order on open).
    ddl: &'static [&'static str],
    /// `SELECT value FROM kv WHERE key = ?1`.
    get: &'static str,
    /// Upsert with a version bump (`?1` key, `?2` value).
    upsert: &'static str,
    /// Append the post-write `(key, version, ts)` to the change log (`?1` key, `?2` ts).
    append_change: &'static str,
    /// `DELETE FROM kv WHERE key = ?1`.
    delete: &'static str,
    /// Append a delete tombstone to the change log — `version = 0` (`?1` key, `?2` ts).
    delete_change: &'static str,
    /// Prefix scan bounded by `[prefix, prefix_successor)` (`?1` lower, `?2` upper).
    list_prefix_bounded: &'static str,
    /// Prefix scan with no upper bound — empty/all-`0xFF` prefix (`?1` lower).
    list_prefix_all: &'static str,
    /// Resumable range scan `(start, prefix_successor)`, capped (`?1` start, `?2` upper, `?3` limit).
    list_from_bounded: &'static str,
    /// Resumable range scan with no upper bound (`?1` start, `?2` limit).
    list_from_all: &'static str,
    /// VALUE-predicate present-key CAS, single statement (`?1` key, `?2` new, `?3` expected).
    cas_present: &'static str,
    /// Absent-key CAS — `INSERT … ON CONFLICT(key) DO NOTHING` (`?1` key, `?2` new).
    cas_absent: &'static str,
}

/// SQLite / libsql statement set. `ts` is an `INTEGER` (unix seconds); keys/values are `BLOB`.
#[cfg(feature = "sql")]
const SQLITE_STATEMENTS: KvStatements = KvStatements {
    ddl: &[
        "CREATE TABLE IF NOT EXISTS kv (\
         key BLOB PRIMARY KEY, \
         value BLOB NOT NULL, \
         version BIGINT NOT NULL\
         )",
        "CREATE TABLE IF NOT EXISTS kv_changes (\
         seq INTEGER PRIMARY KEY AUTOINCREMENT, \
         key BLOB NOT NULL, \
         version BIGINT NOT NULL, \
         ts INTEGER NOT NULL\
         )",
    ],
    get: "SELECT value FROM kv WHERE key = ?1",
    upsert: "INSERT INTO kv (key, value, version) VALUES (?1, ?2, 1) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, version = kv.version + 1",
    append_change: "INSERT INTO kv_changes (key, version, ts) \
                    SELECT key, version, ?2 FROM kv WHERE key = ?1",
    delete: "DELETE FROM kv WHERE key = ?1",
    delete_change: "INSERT INTO kv_changes (key, version, ts) VALUES (?1, 0, ?2)",
    list_prefix_bounded: "SELECT key FROM kv WHERE key >= ?1 AND key < ?2 ORDER BY key",
    list_prefix_all: "SELECT key FROM kv WHERE key >= ?1 ORDER BY key",
    list_from_bounded: "SELECT key FROM kv WHERE key > ?1 AND key < ?2 ORDER BY key LIMIT ?3",
    list_from_all: "SELECT key FROM kv WHERE key > ?1 ORDER BY key LIMIT ?2",
    cas_present: "UPDATE kv SET value = ?2, version = version + 1 WHERE key = ?1 AND value = ?3",
    cas_absent: "INSERT INTO kv (key, value, version) VALUES (?1, ?2, 1) \
                 ON CONFLICT(key) DO NOTHING",
};

/// Postgres statement set. Identical SQL text to SQLite (the `?N` → `$N` rewrite and value
/// marshalling happen in the sqlx `SqlBackend` layer, and `ON CONFLICT … DO UPDATE/NOTHING` +
/// `excluded` are shared between the two engines) — ONLY the DDL types differ: `BYTEA` keys/values,
/// `BIGSERIAL` for the change-log sequence, `BIGINT` for `ts`.
#[cfg(feature = "sql-postgres")]
const POSTGRES_STATEMENTS: KvStatements = KvStatements {
    ddl: &[
        "CREATE TABLE IF NOT EXISTS kv (\
         key BYTEA PRIMARY KEY, \
         value BYTEA NOT NULL, \
         version BIGINT NOT NULL\
         )",
        "CREATE TABLE IF NOT EXISTS kv_changes (\
         seq BIGSERIAL PRIMARY KEY, \
         key BYTEA NOT NULL, \
         version BIGINT NOT NULL, \
         ts BIGINT NOT NULL\
         )",
    ],
    get: "SELECT value FROM kv WHERE key = ?1",
    upsert: "INSERT INTO kv (key, value, version) VALUES (?1, ?2, 1) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, version = kv.version + 1",
    append_change: "INSERT INTO kv_changes (key, version, ts) \
                    SELECT key, version, ?2 FROM kv WHERE key = ?1",
    delete: "DELETE FROM kv WHERE key = ?1",
    delete_change: "INSERT INTO kv_changes (key, version, ts) VALUES (?1, 0, ?2)",
    list_prefix_bounded: "SELECT key FROM kv WHERE key >= ?1 AND key < ?2 ORDER BY key",
    list_prefix_all: "SELECT key FROM kv WHERE key >= ?1 ORDER BY key",
    list_from_bounded: "SELECT key FROM kv WHERE key > ?1 AND key < ?2 ORDER BY key LIMIT ?3",
    list_from_all: "SELECT key FROM kv WHERE key > ?1 ORDER BY key LIMIT ?2",
    cas_present: "UPDATE kv SET value = ?2, version = version + 1 WHERE key = ?1 AND value = ?3",
    cas_absent: "INSERT INTO kv (key, value, version) VALUES (?1, ?2, 1) \
                 ON CONFLICT(key) DO NOTHING",
};

/// Resolve the statement set for `dialect`. Each arm is gated on the engine feature that CONSTRUCTS
/// that dialect (SQLite → `sql`, Postgres → `sql-postgres`), so an un-built dialect has no statement
/// set and is unreachable — the only constructors ([`SqlKv::open_sqlite_local`] /
/// [`SqlKv::open_postgres`]) pin a dialect that is always compiled in their own build.
fn statements_for(dialect: Dialect) -> KvStatements {
    match dialect {
        #[cfg(feature = "sql")]
        Dialect::Sqlite => SQLITE_STATEMENTS,
        #[cfg(feature = "sql-postgres")]
        Dialect::Postgres => POSTGRES_STATEMENTS,
        other => unreachable!(
            "SqlKv has no statement set for {other:?} in this build (its engine feature is off); \
             the constructors only pin a dialect compiled in their own build"
        ),
    }
}

/// The engine backing a [`SqlKv`]. One variant per compiled engine; the trait ops match on it.
enum Backing {
    /// An embedded SQLite / libsql local database (single-writer). Each op opens a fresh connection
    /// off this shared `Database` handle.
    #[cfg(feature = "sql")]
    Sqlite(Arc<Database>),
    /// An external Postgres primary over the existing sqlx pool layer (multi-writer). Each op drives
    /// a transaction through the `SqlBackend`, which rewrites `?N` → `$N` and marshals values.
    #[cfg(feature = "sql-postgres")]
    Postgres(Arc<dyn SqlBackend>),
}

/// A SQL-backed [`KvStore`]. Backed by an embedded SQLite file ([`open_sqlite_local`](Self::open_sqlite_local),
/// single-writer) or an external Postgres primary ([`open_postgres`](Self::open_postgres),
/// multi-writer); the `dialect` + [`statements_for`] seam keeps the SQL generation ready for the
/// MySQL pool of a later workstream without reshaping the ops.
pub struct SqlKv {
    backing: Backing,
    dialect: Dialect,
    stmts: KvStatements,
}

#[cfg(feature = "sql")]
impl SqlKv {
    /// Open (creating if absent) a local SQLite database file at `path` as the control-plane KV,
    /// in **WAL** mode with **`synchronous = FULL`** (synchronous-commit, C6), and create the
    /// `kv` + `kv_changes` tables idempotently (host-owned DDL, C9). The parent directory is
    /// created if missing.
    pub async fn open_sqlite_local(path: impl AsRef<Path>) -> Result<Self, KvError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(KvError::from)?;
        }
        let db = Builder::new_local(path).build().await.map_err(kv_err)?;
        let conn = db.connect().map_err(kv_err)?;
        // WAL persists in the database header (set once); `synchronous = FULL` is per-connection —
        // re-asserted on every write connection below — so EVERY commit (incl. the DDL here) fsyncs.
        run_pragma(&conn, "PRAGMA journal_mode=WAL").await?;
        run_pragma(&conn, "PRAGMA synchronous=FULL").await?;
        let stmts = statements_for(Dialect::Sqlite);
        for ddl in stmts.ddl {
            conn.execute(ddl, ()).await.map_err(kv_err)?;
        }
        Ok(Self {
            backing: Backing::Sqlite(Arc::new(db)),
            dialect: Dialect::Sqlite,
            stmts,
        })
    }
}

#[cfg(feature = "sql-postgres")]
impl SqlKv {
    /// Open an external **Postgres primary** as the multi-writer control-plane KV, over the EXISTING
    /// sqlx pool layer ([`connect`](crate::sql_sqlx::connect) /
    /// [`ExternalSqlOptions`](crate::sql_sqlx::ExternalSqlOptions)). The pool is lazy (the first
    /// statement below forces the first connection); `pool_max` caps it (default
    /// [`DEFAULT_PG_POOL_MAX`] = 16 — MF-2 wants ≥16 so concurrent control-plane writers contend on
    /// the DB, not the pool). `url` is the connection URL resolved from its `url_env` by the caller —
    /// never a raw URL in config (UX-C2).
    ///
    /// Enforces the C6/MF-5 **durable-commit contract** at open: reads `synchronous_commit` and FAILS
    /// LOUD unless it is `on` (a non-durable setting could drop a committed revoke on crash). Then
    /// creates the `kv` + `kv_changes` tables idempotently (host-owned DDL, C9).
    ///
    /// **Custody (MF-6):** this database now sits inside the secret-custody boundary, but holds only
    /// SEALED ciphertext for secrets (sealing is pre-put) and plaintext control-plane config/RBAC —
    /// the envelope KEK is NEVER written here. The operator MUST (a) disable SQL statement/parameter
    /// logging on this database/role (a bound sealed value would otherwise be written to the DB log),
    /// and (b) require TLS on `url` (the sealed bytes + plaintext RBAC travel the wire). `kv_changes`
    /// carries key + version only — never value bytes — so a change feed / NOTIFY leaks no secret.
    pub async fn open_postgres(
        url: impl Into<String>,
        pool_max: Option<u32>,
    ) -> Result<Self, KvError> {
        use crate::sql_sqlx::{ExternalSqlKind, ExternalSqlOptions, connect};
        let max = pool_max.filter(|n| *n >= 1).unwrap_or(DEFAULT_PG_POOL_MAX);
        let opts = ExternalSqlOptions::new(url).with_max_connections(Some(max));
        let backend = connect(ExternalSqlKind::Postgres, &opts).map_err(sql_err)?;
        // C6 / MF-5: a committed txn must be durable before a put/CAS returns. This also forces the
        // first (lazy) connection, so a connect failure surfaces here.
        assert_synchronous_commit_on(backend.as_ref()).await?;
        let stmts = statements_for(Dialect::Postgres);
        for ddl in stmts.ddl {
            backend.run_script(ddl).await.map_err(sql_err)?;
        }
        Ok(Self {
            backing: Backing::Postgres(backend),
            dialect: Dialect::Postgres,
            stmts,
        })
    }
}

#[async_trait]
impl KvStore for SqlKv {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError> {
        match &self.backing {
            #[cfg(feature = "sql")]
            Backing::Sqlite(db) => sqlite_get(db, &self.stmts, key).await,
            #[cfg(feature = "sql-postgres")]
            Backing::Postgres(b) => pg_get(b.as_ref(), &self.stmts, key).await,
        }
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        match &self.backing {
            #[cfg(feature = "sql")]
            Backing::Sqlite(db) => sqlite_put(db, &self.stmts, key, value).await,
            #[cfg(feature = "sql-postgres")]
            Backing::Postgres(b) => {
                pg_write_batch(
                    b.as_ref(),
                    &self.stmts,
                    vec![WriteOp::Put(key.to_string(), value)],
                )
                .await
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        match &self.backing {
            #[cfg(feature = "sql")]
            Backing::Sqlite(db) => sqlite_delete(db, &self.stmts, key).await,
            #[cfg(feature = "sql-postgres")]
            Backing::Postgres(b) => {
                pg_write_batch(
                    b.as_ref(),
                    &self.stmts,
                    vec![WriteOp::Delete(key.to_string())],
                )
                .await
            }
        }
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, KvError> {
        match &self.backing {
            #[cfg(feature = "sql")]
            Backing::Sqlite(db) => sqlite_list_prefix(db, &self.stmts, prefix).await,
            #[cfg(feature = "sql-postgres")]
            Backing::Postgres(b) => pg_list_prefix(b.as_ref(), &self.stmts, prefix).await,
        }
    }

    async fn list_from(
        &self,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, KvError> {
        match &self.backing {
            #[cfg(feature = "sql")]
            Backing::Sqlite(db) => sqlite_list_from(db, &self.stmts, prefix, after, limit).await,
            #[cfg(feature = "sql-postgres")]
            Backing::Postgres(b) => {
                pg_list_from(b.as_ref(), &self.stmts, prefix, after, limit).await
            }
        }
    }

    fn atomic_write_batch(&self) -> bool {
        // The whole batch commits inside one transaction (SQLite `BEGIN IMMEDIATE … COMMIT`; Postgres
        // `BEGIN … COMMIT`), so a crash can never leave it partially applied — the ready-set fast
        // path (B2) is safe over it on either backend.
        true
    }

    async fn write_batch(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        match &self.backing {
            #[cfg(feature = "sql")]
            Backing::Sqlite(db) => sqlite_write_batch(db, &self.stmts, ops).await,
            #[cfg(feature = "sql-postgres")]
            Backing::Postgres(b) => pg_write_batch(b.as_ref(), &self.stmts, ops).await,
        }
    }

    fn supports_cas(&self) -> bool {
        // The single-statement value-predicate CAS below is linearizable w.r.t. the one store each
        // backing targets: a single SQLite database serializes its writers, and a Postgres PRIMARY
        // serializes them cross-connection via the row lock (READ COMMITTED EvalPlanQual). Every CAS
        // — and, in later workstreams, every authz/crown-jewel read — targets the primary, never a
        // lagging replica. So two racing swappers can never both win.
        true
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> Result<bool, KvError> {
        match &self.backing {
            #[cfg(feature = "sql")]
            Backing::Sqlite(db) => sqlite_cas(db, &self.stmts, key, expected, new).await,
            #[cfg(feature = "sql-postgres")]
            Backing::Postgres(b) => pg_cas(b.as_ref(), &self.stmts, key, expected, new).await,
        }
    }

    fn writer_model(&self) -> WriterModel {
        // The writer-model DECLARATION the node bootstrap derives coordination from: SQLite/libsql-
        // local is a single-writer store; the self-serializing Postgres (and the later MySQL) dialect
        // declares MultiWriter (the engine IS the coordinator — N stateless nodes, no Raft).
        match self.dialect {
            Dialect::Sqlite => WriterModel::SingleWriter,
            Dialect::Postgres | Dialect::Mysql => WriterModel::MultiWriter,
        }
    }
}

// ---------------------------------------------------------------------------
// Postgres (feature `sql-postgres`) — over the existing sqlx `SqlBackend` layer.
// ---------------------------------------------------------------------------

/// Read `synchronous_commit` on the primary and FAIL LOUD unless it is `on` (C6 / MF-5). A SELECT of
/// `current_setting(...)` (not a `SHOW`, so it binds through the prepared protocol cleanly) returns
/// the effective session value; the KV database/role default must be `on` so a committed revoke
/// survives a crash.
#[cfg(feature = "sql-postgres")]
async fn assert_synchronous_commit_on(backend: &dyn SqlBackend) -> Result<(), KvError> {
    let mut tx = backend.begin_read_only().await.map_err(sql_err)?;
    let rows = tx
        .query("SELECT current_setting('synchronous_commit')", &[])
        .await
        .map_err(sql_err)?;
    tx.commit().await.map_err(sql_err)?;
    let setting = rows
        .rows
        .into_iter()
        .next()
        .and_then(|r| r.into_iter().next())
        .and_then(|v| match v {
            SqlValue::Text(s) => Some(s),
            _ => None,
        })
        .unwrap_or_default();
    if !setting.eq_ignore_ascii_case("on") {
        return Err(KvError::backend(format!(
            "Postgres `synchronous_commit` is {setting:?}, not `on`: a committed control-plane write \
             (e.g. a token revoke) could be lost on crash. Set `synchronous_commit = on` on the KV \
             database/role before using Postgres as the boatramp control-plane KV."
        )));
    }
    Ok(())
}

#[cfg(feature = "sql-postgres")]
async fn pg_get(
    backend: &dyn SqlBackend,
    stmts: &KvStatements,
    key: &str,
) -> Result<Option<Vec<u8>>, KvError> {
    let mut tx = backend.begin_read_only().await.map_err(sql_err)?;
    let rows = tx
        .query(stmts.get, &[SqlValue::Blob(key.as_bytes().to_vec())])
        .await
        .map_err(sql_err)?;
    tx.commit().await.map_err(sql_err)?;
    match rows.rows.into_iter().next() {
        Some(row) => {
            let cell = row
                .into_iter()
                .next()
                .ok_or_else(|| KvError::backend("kv get row had no columns"))?;
            Ok(Some(pg_bytes(cell)?))
        }
        None => Ok(None),
    }
}

/// Apply one put inside an already-open transaction: upsert (version bump) + append the post-write
/// version to the change log.
#[cfg(feature = "sql-postgres")]
async fn pg_apply_put(
    tx: &mut dyn SqlTransaction,
    stmts: &KvStatements,
    key: &str,
    value: &[u8],
    ts: i64,
) -> Result<(), KvError> {
    let key_blob = SqlValue::Blob(key.as_bytes().to_vec());
    tx.execute(
        stmts.upsert,
        &[key_blob.clone(), SqlValue::Blob(value.to_vec())],
    )
    .await
    .map_err(sql_err)?;
    tx.execute(stmts.append_change, &[key_blob, SqlValue::Integer(ts)])
        .await
        .map_err(sql_err)?;
    // MF-6 custody — the change log carries KEY + VERSION ONLY, never value bytes. The leak seam
    // (test-only; never shipped) stamps the value into `kv_changes` so the no-values gate goes RED.
    if change_log_leaks_value() {
        tx.execute(
            stmts.delete_change,
            &[SqlValue::Blob(value.to_vec()), SqlValue::Integer(ts)],
        )
        .await
        .map_err(sql_err)?;
    }
    Ok(())
}

/// Apply one delete inside an already-open transaction: remove the row and, only if a row was
/// actually removed, append a `version = 0` tombstone (deleting a missing key is a no-op per the
/// trait contract, so it leaves the change log untouched).
#[cfg(feature = "sql-postgres")]
async fn pg_apply_delete(
    tx: &mut dyn SqlTransaction,
    stmts: &KvStatements,
    key: &str,
    ts: i64,
) -> Result<(), KvError> {
    let key_blob = SqlValue::Blob(key.as_bytes().to_vec());
    let affected = tx
        .execute(stmts.delete, std::slice::from_ref(&key_blob))
        .await
        .map_err(sql_err)?;
    if affected > 0 {
        tx.execute(stmts.delete_change, &[key_blob, SqlValue::Integer(ts)])
            .await
            .map_err(sql_err)?;
    }
    Ok(())
}

/// Apply all `ops` in ONE transaction (all-or-nothing — `atomic_write_batch` is `true`): on any error
/// roll back and surface it; otherwise commit. `put`/`delete` route here as single-op batches.
#[cfg(feature = "sql-postgres")]
async fn pg_write_batch(
    backend: &dyn SqlBackend,
    stmts: &KvStatements,
    ops: Vec<WriteOp>,
) -> Result<(), KvError> {
    let ts = now_ts();
    let mut tx = backend.begin().await.map_err(sql_err)?;
    for op in &ops {
        let res = match op {
            WriteOp::Put(key, value) => pg_apply_put(tx.as_mut(), stmts, key, value, ts).await,
            WriteOp::Delete(key) => pg_apply_delete(tx.as_mut(), stmts, key, ts).await,
        };
        if let Err(e) = res {
            let _ = tx.rollback().await;
            return Err(e);
        }
    }
    tx.commit().await.map_err(sql_err)
}

/// Whether the `#[cfg(test)]` CAS mutation seam is armed (MF-2 gate). Returns `false` in a non-test
/// build, so the mutation can never ship. Under `BOATRAMP_KVSQL_MUTATION=drop_cas_predicate` the CAS
/// below drops its value predicate (present-key UPDATE becomes unconditional; absent-key insert
/// becomes an unconditional upsert), making EVERY racer a winner — the gate's concurrency assertion
/// then MUST go RED (two+ winners), proving the predicate is load-bearing.
#[cfg(feature = "sql-postgres")]
fn cas_mutation_drops_predicate() -> bool {
    #[cfg(test)]
    {
        std::env::var("BOATRAMP_KVSQL_MUTATION").as_deref() == Ok("drop_cas_predicate")
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// Decide the CAS winner with ONE value-predicate statement (winner iff `rows_affected == 1`), then
/// append a change-log row ONLY for the winner — all inside `tx`. Never a follow-up `SELECT`.
#[cfg(feature = "sql-postgres")]
async fn pg_apply_cas(
    tx: &mut dyn SqlTransaction,
    stmts: &KvStatements,
    key: &str,
    expected: Option<&[u8]>,
    new: Vec<u8>,
    ts: i64,
) -> Result<bool, KvError> {
    let key_blob = SqlValue::Blob(key.as_bytes().to_vec());
    let new_blob = SqlValue::Blob(new);
    let mutate = cas_mutation_drops_predicate();
    let won = match expected {
        Some(expected) => {
            // present-key: winner iff the row's current value still equals `expected`.
            let (sql, params): (&str, Vec<SqlValue>) = if mutate {
                // MUTATION: drop `AND value=?3` → the UPDATE always matches the key, so every racer
                // reports rows_affected == 1 and "wins" (bind only ?1, ?2 so the normalizer accepts it).
                (
                    "UPDATE kv SET value = ?2, version = version + 1 WHERE key = ?1",
                    vec![key_blob.clone(), new_blob],
                )
            } else {
                (
                    stmts.cas_present,
                    vec![
                        key_blob.clone(),
                        new_blob,
                        SqlValue::Blob(expected.to_vec()),
                    ],
                )
            };
            tx.execute(sql, &params).await.map_err(sql_err)? == 1
        }
        None => {
            // absent-key: winner iff THIS statement inserted the row.
            let sql = if mutate {
                // MUTATION: turn `DO NOTHING` into an unconditional upsert → every racer affects a
                // row and "wins".
                "INSERT INTO kv (key, value, version) VALUES (?1, ?2, 1) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, version = kv.version + 1"
            } else {
                stmts.cas_absent
            };
            tx.execute(sql, &[key_blob.clone(), new_blob])
                .await
                .map_err(sql_err)?
                == 1
        }
    };
    if won {
        tx.execute(stmts.append_change, &[key_blob, SqlValue::Integer(ts)])
            .await
            .map_err(sql_err)?;
    }
    Ok(won)
}

#[cfg(feature = "sql-postgres")]
async fn pg_cas(
    backend: &dyn SqlBackend,
    stmts: &KvStatements,
    key: &str,
    expected: Option<&[u8]>,
    new: Vec<u8>,
) -> Result<bool, KvError> {
    let ts = now_ts();
    let mut tx = backend.begin().await.map_err(sql_err)?;
    let won = match pg_apply_cas(tx.as_mut(), stmts, key, expected, new, ts).await {
        Ok(won) => won,
        Err(e) => {
            let _ = tx.rollback().await;
            return Err(e);
        }
    };
    tx.commit().await.map_err(sql_err)?;
    Ok(won)
}

#[cfg(feature = "sql-postgres")]
async fn pg_list_prefix(
    backend: &dyn SqlBackend,
    stmts: &KvStatements,
    prefix: &str,
) -> Result<Vec<String>, KvError> {
    let lower = prefix.as_bytes().to_vec();
    let (sql, params) = match prefix_successor(&lower) {
        Some(upper) => (
            stmts.list_prefix_bounded,
            vec![SqlValue::Blob(lower), SqlValue::Blob(upper)],
        ),
        None => (stmts.list_prefix_all, vec![SqlValue::Blob(lower)]),
    };
    pg_collect_keys(backend, sql, &params).await
}

#[cfg(feature = "sql-postgres")]
async fn pg_list_from(
    backend: &dyn SqlBackend,
    stmts: &KvStatements,
    prefix: &str,
    after: &str,
    limit: usize,
) -> Result<Vec<String>, KvError> {
    let prefix_bytes = prefix.as_bytes().to_vec();
    let mut start = prefix_bytes.clone();
    start.extend_from_slice(after.as_bytes());
    let lim = SqlValue::Integer(limit as i64);
    let (sql, params) = match prefix_successor(&prefix_bytes) {
        Some(upper) => (
            stmts.list_from_bounded,
            vec![SqlValue::Blob(start), SqlValue::Blob(upper), lim],
        ),
        None => (stmts.list_from_all, vec![SqlValue::Blob(start), lim]),
    };
    pg_collect_keys(backend, sql, &params).await
}

/// Run a read-only `SELECT key …` and collect its first column (keys), decoded from BYTEA back to the
/// `String` keys.
#[cfg(feature = "sql-postgres")]
async fn pg_collect_keys(
    backend: &dyn SqlBackend,
    sql: &str,
    params: &[SqlValue],
) -> Result<Vec<String>, KvError> {
    let mut tx = backend.begin_read_only().await.map_err(sql_err)?;
    let rows = tx.query(sql, params).await.map_err(sql_err)?;
    tx.commit().await.map_err(sql_err)?;
    let mut out = Vec::with_capacity(rows.rows.len());
    for row in rows.rows {
        let cell = row
            .into_iter()
            .next()
            .ok_or_else(|| KvError::backend("kv list row had no columns"))?;
        let bytes = pg_bytes(cell)?;
        out.push(
            String::from_utf8(bytes)
                .map_err(|e| KvError::backend(format!("kv key is not valid UTF-8: {e}")))?,
        );
    }
    Ok(out)
}

/// Decode a `value`/`key` cell back to bytes. A BYTEA column decodes to [`SqlValue::Blob`] (empty
/// value ⇒ empty blob, distinct from an absent key); a `Text`/`Null` arm is defensive. Any other
/// value class is a schema bug → error.
#[cfg(feature = "sql-postgres")]
fn pg_bytes(value: SqlValue) -> Result<Vec<u8>, KvError> {
    match value {
        SqlValue::Blob(bytes) => Ok(bytes),
        SqlValue::Text(text) => Ok(text.into_bytes()),
        SqlValue::Null => Ok(Vec::new()),
        other => Err(KvError::backend(format!(
            "unexpected kv column type (want BYTEA): {other:?}"
        ))),
    }
}

/// Map a `boatramp_core::sql` error into the crate-facing [`KvError`].
#[cfg(feature = "sql-postgres")]
fn sql_err(err: boatramp_core::sql::SqlError) -> KvError {
    KvError::backend(err.to_string())
}

// ---------------------------------------------------------------------------
// SQLite / libsql (feature `sql`) — embedded single-writer.
// ---------------------------------------------------------------------------

/// A connection tuned for the control-plane KV: a contended writer WAITS for the single-writer lock
/// (`busy_timeout`) rather than erroring, and `synchronous = FULL` makes its commits fsync before
/// returning (C6). Each op opens a fresh connection off the shared `Database` (as the libsql
/// `SqlBackend` does), so concurrent ops each get their own transaction.
#[cfg(feature = "sql")]
async fn sqlite_connect(db: &Database) -> Result<Connection, KvError> {
    let conn = db.connect().map_err(kv_err)?;
    run_pragma(&conn, &format!("PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")).await?;
    run_pragma(&conn, "PRAGMA synchronous=FULL").await?;
    Ok(conn)
}

#[cfg(feature = "sql")]
async fn sqlite_get(
    db: &Database,
    stmts: &KvStatements,
    key: &str,
) -> Result<Option<Vec<u8>>, KvError> {
    let conn = sqlite_connect(db).await?;
    let mut rows = conn
        .query(stmts.get, libsql::params_from_iter([blob(key)]))
        .await
        .map_err(kv_err)?;
    match rows.next().await.map_err(kv_err)? {
        Some(row) => Ok(Some(value_bytes(row.get_value(0).map_err(kv_err)?)?)),
        None => Ok(None),
    }
}

#[cfg(feature = "sql")]
async fn sqlite_put(
    db: &Database,
    stmts: &KvStatements,
    key: &str,
    value: Vec<u8>,
) -> Result<(), KvError> {
    let conn = sqlite_connect(db).await?;
    begin(&conn).await?;
    let ts = now_ts();
    let res = async {
        conn.execute(
            stmts.upsert,
            libsql::params_from_iter([blob(key), LibsqlValue::Blob(value.clone())]),
        )
        .await
        .map_err(kv_err)?;
        conn.execute(
            stmts.append_change,
            libsql::params_from_iter([blob(key), LibsqlValue::Integer(ts)]),
        )
        .await
        .map_err(kv_err)?;
        // MF-6 custody — key + version ONLY in the change log; the leak seam (test-only) stamps the
        // value so the no-values gate goes RED.
        if change_log_leaks_value() {
            conn.execute(
                stmts.delete_change,
                libsql::params_from_iter([LibsqlValue::Blob(value), LibsqlValue::Integer(ts)]),
            )
            .await
            .map_err(kv_err)?;
        }
        Ok(())
    }
    .await;
    finish(&conn, res).await
}

#[cfg(feature = "sql")]
async fn sqlite_delete(db: &Database, stmts: &KvStatements, key: &str) -> Result<(), KvError> {
    let conn = sqlite_connect(db).await?;
    begin(&conn).await?;
    let ts = now_ts();
    let res = async {
        let affected = conn
            .execute(stmts.delete, libsql::params_from_iter([blob(key)]))
            .await
            .map_err(kv_err)?;
        // Only record a tombstone when a row was actually removed (deleting a missing key is a
        // no-op per the trait contract, so it leaves the change log untouched).
        if affected > 0 {
            conn.execute(
                stmts.delete_change,
                libsql::params_from_iter([blob(key), LibsqlValue::Integer(ts)]),
            )
            .await
            .map_err(kv_err)?;
        }
        Ok(())
    }
    .await;
    finish(&conn, res).await
}

#[cfg(feature = "sql")]
async fn sqlite_list_prefix(
    db: &Database,
    stmts: &KvStatements,
    prefix: &str,
) -> Result<Vec<String>, KvError> {
    let conn = sqlite_connect(db).await?;
    let lower = prefix.as_bytes().to_vec();
    let (sql, params) = match prefix_successor(&lower) {
        Some(upper) => (
            stmts.list_prefix_bounded,
            vec![LibsqlValue::Blob(lower), LibsqlValue::Blob(upper)],
        ),
        None => (stmts.list_prefix_all, vec![LibsqlValue::Blob(lower)]),
    };
    collect_keys(&conn, sql, params).await
}

#[cfg(feature = "sql")]
async fn sqlite_list_from(
    db: &Database,
    stmts: &KvStatements,
    prefix: &str,
    after: &str,
    limit: usize,
) -> Result<Vec<String>, KvError> {
    let conn = sqlite_connect(db).await?;
    let prefix_bytes = prefix.as_bytes().to_vec();
    let mut start = prefix_bytes.clone();
    start.extend_from_slice(after.as_bytes());
    let lim = LibsqlValue::Integer(limit as i64);
    let (sql, params) = match prefix_successor(&prefix_bytes) {
        Some(upper) => (
            stmts.list_from_bounded,
            vec![LibsqlValue::Blob(start), LibsqlValue::Blob(upper), lim],
        ),
        None => (stmts.list_from_all, vec![LibsqlValue::Blob(start), lim]),
    };
    collect_keys(&conn, sql, params).await
}

#[cfg(feature = "sql")]
async fn sqlite_write_batch(
    db: &Database,
    stmts: &KvStatements,
    ops: Vec<WriteOp>,
) -> Result<(), KvError> {
    let conn = sqlite_connect(db).await?;
    begin(&conn).await?;
    let ts = now_ts();
    let res = async {
        for op in &ops {
            match op {
                WriteOp::Put(key, value) => {
                    conn.execute(
                        stmts.upsert,
                        libsql::params_from_iter([blob(key), LibsqlValue::Blob(value.clone())]),
                    )
                    .await
                    .map_err(kv_err)?;
                    conn.execute(
                        stmts.append_change,
                        libsql::params_from_iter([blob(key), LibsqlValue::Integer(ts)]),
                    )
                    .await
                    .map_err(kv_err)?;
                }
                WriteOp::Delete(key) => {
                    let affected = conn
                        .execute(stmts.delete, libsql::params_from_iter([blob(key)]))
                        .await
                        .map_err(kv_err)?;
                    if affected > 0 {
                        conn.execute(
                            stmts.delete_change,
                            libsql::params_from_iter([blob(key), LibsqlValue::Integer(ts)]),
                        )
                        .await
                        .map_err(kv_err)?;
                    }
                }
            }
        }
        Ok(())
    }
    .await;
    finish(&conn, res).await
}

#[cfg(feature = "sql")]
async fn sqlite_cas(
    db: &Database,
    stmts: &KvStatements,
    key: &str,
    expected: Option<&[u8]>,
    new: Vec<u8>,
) -> Result<bool, KvError> {
    let conn = sqlite_connect(db).await?;
    begin(&conn).await?;
    let ts = now_ts();
    let res = async {
        // ONE statement decides the winner by rows-affected — never a read-then-write.
        let won = match expected {
            Some(expected) => {
                let affected = conn
                    .execute(
                        stmts.cas_present,
                        libsql::params_from_iter([
                            blob(key),
                            LibsqlValue::Blob(new),
                            LibsqlValue::Blob(expected.to_vec()),
                        ]),
                    )
                    .await
                    .map_err(kv_err)?;
                affected == 1
            }
            None => {
                let affected = conn
                    .execute(
                        stmts.cas_absent,
                        libsql::params_from_iter([blob(key), LibsqlValue::Blob(new)]),
                    )
                    .await
                    .map_err(kv_err)?;
                affected == 1
            }
        };
        // Only the winner mutated the store, so only the winner appends a change-log row.
        if won {
            conn.execute(
                stmts.append_change,
                libsql::params_from_iter([blob(key), LibsqlValue::Integer(ts)]),
            )
            .await
            .map_err(kv_err)?;
        }
        Ok(won)
    }
    .await;
    finish(&conn, res).await
}

/// Open a write transaction that takes the write lock at `BEGIN` (`IMMEDIATE`), so concurrent
/// writers queue on the `busy_timeout` and serialize cleanly — no deferred-transaction upgrade
/// deadlock.
#[cfg(feature = "sql")]
async fn begin(conn: &Connection) -> Result<(), KvError> {
    conn.execute("BEGIN IMMEDIATE", ())
        .await
        .map_err(kv_err)
        .map(|_| ())
}

/// Commit the transaction on success, or roll it back on error (a failed rollback is harmless —
/// dropping the connection rolls back too). Returns the inner result unchanged on success.
#[cfg(feature = "sql")]
async fn finish<T>(conn: &Connection, res: Result<T, KvError>) -> Result<T, KvError> {
    match res {
        Ok(value) => {
            conn.execute("COMMIT", ()).await.map_err(kv_err)?;
            Ok(value)
        }
        Err(e) => {
            let _ = conn.execute("ROLLBACK", ()).await;
            Err(e)
        }
    }
}

/// Run a `PRAGMA` (or other settings statement) and drain it: libsql's `execute` rejects
/// row-returning statements and a value-setting `PRAGMA` returns the new value as a row, so run it
/// via `query` and drain (mirrors the libsql `SqlBackend`).
#[cfg(feature = "sql")]
async fn run_pragma(conn: &Connection, sql: &str) -> Result<(), KvError> {
    let mut rows = conn.query(sql, ()).await.map_err(kv_err)?;
    while rows.next().await.map_err(kv_err)?.is_some() {}
    Ok(())
}

/// Run a one-row-one-column query and return that cell (for the pragma read-back in tests).
#[cfg(all(test, feature = "sql"))]
async fn query_one(conn: &Connection, sql: &str) -> Result<Option<LibsqlValue>, KvError> {
    let mut rows = conn.query(sql, ()).await.map_err(kv_err)?;
    match rows.next().await.map_err(kv_err)? {
        Some(row) => Ok(Some(row.get_value(0).map_err(kv_err)?)),
        None => Ok(None),
    }
}

/// Run `sql` and collect its first column (keys), decoded from BLOB back to the `String` keys.
#[cfg(feature = "sql")]
async fn collect_keys(
    conn: &Connection,
    sql: &str,
    params: Vec<LibsqlValue>,
) -> Result<Vec<String>, KvError> {
    let mut rows = conn
        .query(sql, libsql::params_from_iter(params))
        .await
        .map_err(kv_err)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.map_err(kv_err)? {
        let bytes = value_bytes(row.get_value(0).map_err(kv_err)?)?;
        out.push(
            String::from_utf8(bytes)
                .map_err(|e| KvError::backend(format!("kv key is not valid UTF-8: {e}")))?,
        );
    }
    Ok(out)
}

/// A KV key as the BLOB it is stored as — the `&str`'s UTF-8 bytes, so ordering/comparison is
/// bytewise (matching Rust `str` byte order) and never subject to SQLite text affinity.
#[cfg(feature = "sql")]
fn blob(key: &str) -> LibsqlValue {
    LibsqlValue::Blob(key.as_bytes().to_vec())
}

/// Decode a `value`/`key` column back to bytes. Stored as a BLOB (empty value ⇒ empty BLOB); a
/// defensive `Text` arm covers an engine that hands an empty BLOB back as empty text, and `Null`
/// (barred by `NOT NULL`) maps to empty for safety. A numeric cell is a schema bug → error.
#[cfg(feature = "sql")]
fn value_bytes(value: LibsqlValue) -> Result<Vec<u8>, KvError> {
    match value {
        LibsqlValue::Blob(bytes) => Ok(bytes),
        LibsqlValue::Text(text) => Ok(text.into_bytes()),
        LibsqlValue::Null => Ok(Vec::new()),
        other => Err(KvError::backend(format!(
            "unexpected kv column type (want BLOB): {other:?}"
        ))),
    }
}

/// Map any libsql / backend error into the crate-facing [`KvError`].
#[cfg(feature = "sql")]
fn kv_err<E: std::fmt::Display>(err: E) -> KvError {
    KvError::backend(err.to_string())
}

// ---------------------------------------------------------------------------
// Shared pure helpers.
// ---------------------------------------------------------------------------

/// The smallest byte string strictly greater than every string with `prefix` — the exclusive upper
/// bound of a prefix range scan. Increment the last byte below `0xFF`, dropping trailing `0xFF`s;
/// `None` when `prefix` is empty or all `0xFF` (no finite upper bound → scan to the end).
fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(&last) = end.last() {
        if last < 0xFF {
            *end.last_mut().expect("non-empty") = last + 1;
            return Some(end);
        }
        end.pop();
    }
    None
}

/// Whether the MF-6 change-log VALUE-LEAK mutation seam is armed — the write path then ALSO stamps
/// the (sealed) value bytes into `kv_changes`, so `sqlkv_change_log_carries_no_secret_values` finds
/// them and goes RED (proving the custody invariant — the change log carries KEY + VERSION ONLY,
/// never value bytes — is load-bearing, not incidental). ALWAYS `false` in a shipped build: the env
/// check compiles in ONLY under `cfg(test)`. Shares the one `BOATRAMP_KVSQL_MUTATION` env var.
fn change_log_leaks_value() -> bool {
    #[cfg(test)]
    {
        std::env::var("BOATRAMP_KVSQL_MUTATION").as_deref() == Ok("leak_change_value")
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// Unix-seconds timestamp for a change-log row (best-effort; a clock before the epoch records `0`).
fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "sql"))]
mod sqlite_tests {
    use super::*;

    impl SqlKv {
        /// The pragmas the WRITE path actually opens its connections with — `(journal_mode,
        /// synchronous)` — read back on a freshly-tuned connection. Proves the synchronous-commit
        /// contract (C6) at the seam the writes use: WAL + `synchronous = FULL` (`2`).
        async fn debug_pragmas(&self) -> Result<(String, i64), KvError> {
            let conn = self.sqlite_test_conn().await?;
            let journal = match query_one(&conn, "PRAGMA journal_mode").await? {
                Some(LibsqlValue::Text(s)) => s,
                other => format!("{other:?}"),
            };
            let synchronous = match query_one(&conn, "PRAGMA synchronous").await? {
                Some(LibsqlValue::Integer(n)) => n,
                _ => -1,
            };
            Ok((journal, synchronous))
        }

        /// A tuned SQLite connection off the backing (test-only; the change-log / pragma reads use it).
        async fn sqlite_test_conn(&self) -> Result<Connection, KvError> {
            match &self.backing {
                Backing::Sqlite(db) => sqlite_connect(db).await,
                #[cfg(feature = "sql-postgres")]
                Backing::Postgres(_) => {
                    Err(KvError::backend("sqlite_test_conn on a Postgres SqlKv"))
                }
            }
        }
    }

    fn temp_db(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(format!("{name}.db"));
        (dir, path)
    }

    /// GATE — `SqlKv` satisfies the shared `KvStore` conformance suite (the same assertions every
    /// backend runs), over a real SQLite store.
    #[tokio::test]
    async fn sqlkv_satisfies_the_conformance_suite() {
        let (_dir, path) = temp_db("conformance");
        let kv = SqlKv::open_sqlite_local(&path).await.unwrap();
        boatramp_core::kv::conformance::kv_conformance(&kv).await;
    }

    /// GATE — the value-CAS present + absent paths explicitly (beyond what the suite covers): an
    /// absent-key create, a losing present-key value mismatch, and a winning value match.
    #[tokio::test]
    async fn sqlkv_value_cas_present_and_absent() {
        let (_dir, path) = temp_db("value-cas");
        let kv = SqlKv::open_sqlite_local(&path).await.unwrap();

        // Absent-key CAS (`expected = None`): creates iff the key is missing.
        assert!(
            kv.compare_and_swap("k", None, b"v1".to_vec())
                .await
                .unwrap(),
            "absent-key CAS on a missing key wins"
        );
        assert!(
            !kv.compare_and_swap("k", None, b"v2".to_vec())
                .await
                .unwrap(),
            "absent-key CAS on a present key loses (no overwrite)"
        );
        assert_eq!(kv.get("k").await.unwrap(), Some(b"v1".to_vec()));

        // Present-key value predicate: only the exact prior bytes win.
        assert!(
            !kv.compare_and_swap("k", Some(b"WRONG"), b"v3".to_vec())
                .await
                .unwrap(),
            "present-key CAS with a non-matching value loses"
        );
        assert_eq!(kv.get("k").await.unwrap(), Some(b"v1".to_vec()));
        assert!(
            kv.compare_and_swap("k", Some(b"v1"), b"v4".to_vec())
                .await
                .unwrap(),
            "present-key CAS with the matching value wins"
        );
        assert_eq!(kv.get("k").await.unwrap(), Some(b"v4".to_vec()));
    }

    /// GATE — exactly one of many racing value-CAS swappers of the same key wins, over a real
    /// SQLite `SqlKv` (the single-writer serialize makes the single-statement CAS linearizable).
    /// Multi-thread so the 32 writers genuinely contend for the write lock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sqlkv_cas_race_has_exactly_one_winner() {
        let (_dir, path) = temp_db("cas-race");
        let kv: Arc<dyn KvStore> = Arc::new(SqlKv::open_sqlite_local(&path).await.unwrap());
        assert!(kv.supports_cas());
        kv.put("race/k", b"start".to_vec()).await.unwrap();
        let mut set = tokio::task::JoinSet::new();
        for i in 0..32u32 {
            let kv = kv.clone();
            set.spawn(async move {
                kv.compare_and_swap("race/k", Some(b"start"), i.to_le_bytes().to_vec())
                    .await
                    .unwrap()
            });
        }
        let mut wins = 0;
        while let Some(res) = set.join_next().await {
            if res.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(wins, 1, "exactly one racing CAS wins");
    }

    /// GATE — synchronous-commit durability (C6): a value written by a returned `put` is present
    /// after the store is dropped and REOPENED — i.e. the COMMIT was fsync'd before `put` acked
    /// (no async-buffered ack).
    #[tokio::test]
    async fn sqlkv_put_is_durable_after_reopen() {
        let (_dir, path) = temp_db("durable");
        {
            let kv = SqlKv::open_sqlite_local(&path).await.unwrap();
            kv.put("crown/secret", b"sealed".to_vec()).await.unwrap();
            // Drop the store with NO explicit flush/close — the `put` must already be durable.
        }
        let reopened = SqlKv::open_sqlite_local(&path).await.unwrap();
        assert_eq!(
            reopened.get("crown/secret").await.unwrap(),
            Some(b"sealed".to_vec())
        );
    }

    /// GATE — the store opens in WAL mode with `synchronous = FULL` (the pragmas the write path
    /// actually uses), the mechanism behind the synchronous-commit durability above.
    #[tokio::test]
    async fn sqlkv_open_uses_wal_and_full_synchronous() {
        let (_dir, path) = temp_db("pragmas");
        let kv = SqlKv::open_sqlite_local(&path).await.unwrap();
        let (journal, synchronous) = kv.debug_pragmas().await.unwrap();
        assert_eq!(journal.to_ascii_lowercase(), "wal", "WAL journal mode");
        assert_eq!(synchronous, 2, "synchronous = FULL (2)");
    }

    /// The SQLite single-writer store declares `SingleWriter` (the whole point of the
    /// writer-model declaration the node bootstrap derives coordination from).
    #[tokio::test]
    async fn sqlkv_declares_single_writer() {
        let (_dir, path) = temp_db("writer-model");
        let kv = SqlKv::open_sqlite_local(&path).await.unwrap();
        assert_eq!(kv.writer_model(), WriterModel::SingleWriter);
    }

    /// Change-log: every mutating op appends to `kv_changes` so the multi-writer ChangePublisher of
    /// a later workstream has a ledger — a put records the live version, a delete a `0` tombstone.
    #[tokio::test]
    async fn sqlkv_writes_append_to_the_change_log() {
        let (_dir, path) = temp_db("change-log");
        let kv = SqlKv::open_sqlite_local(&path).await.unwrap();
        kv.put("a", b"1".to_vec()).await.unwrap();
        kv.put("a", b"2".to_vec()).await.unwrap(); // version bump
        kv.delete("a").await.unwrap(); // tombstone (version 0)

        let conn = kv.sqlite_test_conn().await.unwrap();
        let mut rows = conn
            .query(
                "SELECT version FROM kv_changes WHERE key = ?1 ORDER BY seq",
                libsql::params_from_iter([blob("a")]),
            )
            .await
            .unwrap();
        let mut versions = Vec::new();
        while let Some(row) = rows.next().await.unwrap() {
            if let LibsqlValue::Integer(v) = row.get_value(0).unwrap() {
                versions.push(v);
            }
        }
        assert_eq!(
            versions,
            vec![1, 2, 0],
            "put v1, put v2, delete tombstone 0"
        );
    }

    /// MF-6 CUSTODY GATE — the change log carries the KEY + VERSION ONLY, NEVER the (sealed) value
    /// bytes. A secret write records its key and post-write version in `kv_changes`; no `kv_changes`
    /// cell may contain the value bytes (the sealed ciphertext lives only in `kv.value`). RED under
    /// `BOATRAMP_KVSQL_MUTATION=leak_change_value` (the write then stamps the value into the log).
    #[tokio::test]
    async fn sqlkv_change_log_carries_no_secret_values() {
        let (_dir, path) = temp_db("mf6-custody");
        let kv = SqlKv::open_sqlite_local(&path).await.unwrap();
        // A distinctive "sealed secret" value (incl. binary bytes) that must not appear in the log.
        let sealed = b"SEALED-CIPHERTEXT-\x00\x9f\x92\x96-secret".to_vec();
        kv.put("secret/default/api-key", sealed.clone())
            .await
            .unwrap();

        let conn = kv.sqlite_test_conn().await.unwrap();
        let mut rows = conn
            .query("SELECT key, version FROM kv_changes", ())
            .await
            .unwrap();
        let mut saw_key = false;
        while let Some(row) = rows.next().await.unwrap() {
            let key_bytes = value_bytes(row.get_value(0).unwrap()).unwrap();
            assert_ne!(
                key_bytes, sealed,
                "kv_changes must NEVER carry the (sealed) value bytes — key + version only (MF-6)"
            );
            if key_bytes == b"secret/default/api-key" {
                saw_key = true;
                if let LibsqlValue::Integer(v) = row.get_value(1).unwrap() {
                    assert_eq!(v, 1, "the change log records the key + post-write version");
                }
            }
        }
        assert!(
            saw_key,
            "the change log records the changed key (key + version)"
        );
        // The sealed value lives in `kv`, not in the change log / NOTIFY feed.
        assert_eq!(
            kv.get("secret/default/api-key").await.unwrap(),
            Some(sealed)
        );
    }
}

/// LIVE Postgres gates (build-order step 2 / MF-2). Env-gated on `BOATRAMP_TEST_PG_URL` — they skip
/// CLEANLY with an eprintln when it is unset (CI provides a `postgres:16-alpine` service with it).
/// These are UNIT tests (in the crate's own `cfg(test)` build) so the `#[cfg(test)]` CAS mutation
/// seam ([`cas_mutation_drops_predicate`]) is live: under `BOATRAMP_KVSQL_MUTATION=drop_cas_predicate`
/// the value predicate is dropped and [`sqlkv_pg_cas_race_has_exactly_one_winner`] MUST go RED. The
/// shared `kv`/`kv_changes` tables are reset per test and the tests run `#[serial]` so they don't
/// collide.
#[cfg(all(test, feature = "sql-postgres"))]
mod pg_tests {
    use super::*;
    use serial_test::serial;

    /// Open the PG `SqlKv` with a ≥16-conn pool and reset the shared tables — or `None` (skip) when
    /// `BOATRAMP_TEST_PG_URL` is unset.
    async fn fresh_pg() -> Option<SqlKv> {
        let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
            eprintln!("skip sqlkv pg gate: BOATRAMP_TEST_PG_URL unset");
            return None;
        };
        let kv = SqlKv::open_postgres(url, Some(16))
            .await
            .expect("open Postgres SqlKv");
        // Clean slate: the conformance suite asserts exact list contents, and the race gate counts
        // winners on a single key.
        match &kv.backing {
            Backing::Postgres(b) => b
                .run_script("DELETE FROM kv_changes; DELETE FROM kv")
                .await
                .expect("reset kv tables"),
            #[cfg(feature = "sql")]
            Backing::Sqlite(_) => unreachable!("fresh_pg opened Postgres"),
        }
        Some(kv)
    }

    /// GATE — the PG `SqlKv` satisfies the IDENTICAL shared `KvStore` conformance suite every backend
    /// runs (value CAS, empty/binary values, prefix/range scans, delete-of-missing).
    #[tokio::test]
    #[serial]
    async fn sqlkv_pg_conformance() {
        let Some(kv) = fresh_pg().await else {
            return;
        };
        boatramp_core::kv::conformance::kv_conformance(&kv).await;
        println!("SQLKV PG CONFORMANCE OK [postgres]");
    }

    /// MF-6 CUSTODY GATE (over a REAL Postgres) — `kv_changes` carries KEY + VERSION ONLY, never the
    /// (sealed) value bytes. RED under `BOATRAMP_KVSQL_MUTATION=leak_change_value`.
    #[tokio::test]
    #[serial]
    async fn sqlkv_pg_change_log_carries_no_secret_values() {
        let Some(kv) = fresh_pg().await else {
            return;
        };
        let sealed = b"SEALED-CIPHERTEXT-\x00\x9f\x92\x96-pg-secret".to_vec();
        kv.put("secret/default/pg-key", sealed.clone())
            .await
            .unwrap();
        let Backing::Postgres(b) = &kv.backing else {
            unreachable!("fresh_pg opened Postgres")
        };
        let mut tx = b.begin_read_only().await.unwrap();
        let rows = tx
            .query("SELECT key, version FROM kv_changes", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let mut saw_key = false;
        for row in rows.rows {
            let key_bytes = pg_bytes(row.into_iter().next().unwrap()).unwrap();
            assert_ne!(
                key_bytes, sealed,
                "kv_changes must NEVER carry the (sealed) value bytes — key + version only (MF-6)"
            );
            if key_bytes == b"secret/default/pg-key" {
                saw_key = true;
            }
        }
        assert!(saw_key, "the change log records the changed key");
        println!("SQLKV PG MF-6 CUSTODY OK [postgres]: kv_changes carries key + version only.");
    }

    /// GATE — the PG `SqlKv` declares `MultiWriter` and `supports_cas` (the self-coordinating
    /// multi-writer declaration the shared topology derives from).
    #[tokio::test]
    #[serial]
    async fn sqlkv_pg_declares_multi_writer() {
        let Some(kv) = fresh_pg().await else {
            return;
        };
        assert_eq!(kv.writer_model(), WriterModel::MultiWriter);
        assert!(kv.supports_cas());
    }

    /// THE MF-2 GATE (the NO-SHIP one) — over a REAL Postgres primary with a ≥16-conn pool, 32
    /// concurrent tasks on a multi-thread runtime race a value-predicate CAS and EXACTLY ONE wins,
    /// for BOTH a present-key race and an absent-key/insert race. The single-statement
    /// winner-by-rows-affected CAS is cross-connection linearizable w.r.t. the primary (READ
    /// COMMITTED row-lock + EvalPlanQual on present-key; `ON CONFLICT DO NOTHING` on absent-key).
    ///
    /// Mutation-verified: with `BOATRAMP_KVSQL_MUTATION=drop_cas_predicate` the value predicate is
    /// dropped (present-key UPDATE becomes unconditional; absent-key insert becomes an unconditional
    /// upsert), so EVERY racer wins and the `exactly one` assertion fails — proving the predicate is
    /// load-bearing, not decoration. (The CI mutation loop sets that env and asserts this gate RED.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn sqlkv_pg_cas_race_has_exactly_one_winner() {
        let Some(kv) = fresh_pg().await else {
            return;
        };
        let kv = Arc::new(kv);
        assert!(kv.supports_cas());

        // (1) present-key race: 32 racers swap the SAME prior value; exactly one matches.
        kv.put("race/k", b"start".to_vec()).await.unwrap();
        let mut set = tokio::task::JoinSet::new();
        for i in 0..32u32 {
            let kv = kv.clone();
            set.spawn(async move {
                kv.compare_and_swap("race/k", Some(b"start"), i.to_le_bytes().to_vec())
                    .await
                    .unwrap()
            });
        }
        let mut wins = 0;
        while let Some(res) = set.join_next().await {
            if res.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(
            wins, 1,
            "exactly one present-key CAS wins (over real Postgres)"
        );

        // (2) absent-key race: the key is absent; 32 racers insert-if-absent; exactly one inserts.
        let mut set = tokio::task::JoinSet::new();
        for i in 0..32u32 {
            let kv = kv.clone();
            set.spawn(async move {
                kv.compare_and_swap("race/insert", None, i.to_le_bytes().to_vec())
                    .await
                    .unwrap()
            });
        }
        let mut wins = 0;
        while let Some(res) = set.join_next().await {
            if res.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(
            wins, 1,
            "exactly one absent-key insert wins (over real Postgres)"
        );

        println!(
            "SQLKV PG CAS RACE OK [postgres]: 32-way present-key + absent-key value-CAS over a real \
             primary each had EXACTLY ONE winner (single-statement, winner-by-rows-affected)."
        );
    }

    // ---- MF-1 crown-jewel CAS conversion gates (over a REAL multi-writer Postgres) --------------
    //
    // The IDENTICAL gates run over `MemoryKv` in `boatramp-core`; here they run over the real
    // multi-writer `SqlKv` — the cross-node linearizable property the Security panel gated on. Each
    // is mutation-verified: built with `--features sql-postgres,crownjewel-cas-gate-mutation` and
    // `BOATRAMP_KVSQL_MUTATION=drop_crownjewel_cas`, the converted crown-jewel write reverts to the
    // blind pre-MF-1 path and the gate goes RED (the CI mutation loop asserts that). Env-gated on
    // `BOATRAMP_TEST_PG_URL`; skips CLEANLY when unset.
    use boatramp_core::crownjewel::gate::{
        GateEnvelope, assert_no_lost_update, distinct_policy, gate_project,
    };
    use boatramp_core::deploy::{policy_read_versioned, policy_set_if_match};
    use boatramp_core::error::DeployError;
    use boatramp_core::secret_store::{
        MAX_TENANT_SECRET_NAMES, SecretError, SecretStore, TenantSecretStore,
    };

    /// MF-1 GATE — N concurrent `SecretStore::set` on one key over a real Postgres have exactly one
    /// winner per read-prev, so the winning revisions are unique + monotonic and no rotation is lost
    /// (the loser gets `Conflict`, never a silent clobber). RED under the mutation (blind put →
    /// duplicate revisions).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn crownjewel_concurrent_secret_rotation_no_lost_update() {
        let Some(kv) = fresh_pg().await else {
            return;
        };
        let store = Arc::new(SecretStore::new(
            Arc::new(kv) as Arc<dyn KvStore>,
            Arc::new(GateEnvelope),
        ));
        let p = gate_project();
        let base = store.set(p, "k", b"seed").await.unwrap().revision;

        let mut set = tokio::task::JoinSet::new();
        for i in 0..32u32 {
            let store = store.clone();
            set.spawn(async move { store.set(p, "k", format!("v{i}").as_bytes()).await });
        }
        let mut wins = Vec::new();
        while let Some(res) = set.join_next().await {
            match res.unwrap() {
                Ok(meta) => wins.push(meta.revision),
                Err(SecretError::Conflict(_)) => {}
                Err(e) => panic!("unexpected secret error: {e}"),
            }
        }
        let final_rev = store
            .list(p)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.name == "k")
            .unwrap()
            .revision;
        assert_no_lost_update(base, wins, final_rev);
        println!(
            "SQLKV PG CROWNJEWEL ROTATION OK [postgres]: 32-way concurrent secret rotation over a \
             real primary — unique+monotonic revisions, no lost update."
        );
    }

    /// MF-1 GATE — a `delete` racing a rotation over a real Postgres never resurrects the deleted
    /// secret (a stale `set`'s value-CAS fails once the record is tombstoned). RED under the
    /// mutation (blind delete + blind put → a stale rotation lands after the delete).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn crownjewel_rotate_vs_delete_no_resurrection() {
        let Some(kv) = fresh_pg().await else {
            return;
        };
        let store = Arc::new(SecretStore::new(
            Arc::new(kv) as Arc<dyn KvStore>,
            Arc::new(GateEnvelope),
        ));
        let p = gate_project();
        let mut resurrections = 0usize;
        for round in 0..100u32 {
            let name = format!("k{round}");
            assert_eq!(store.set(p, &name, b"OLD").await.unwrap().revision, 1);

            let s1 = store.clone();
            let n1 = name.clone();
            let setter = tokio::spawn(async move { s1.set(p, &n1, b"NEW").await });
            let s2 = store.clone();
            let n2 = name.clone();
            let deleter = tokio::spawn(async move { s2.delete(p, &n2).await });
            let _ = setter.await.unwrap();
            let del_res = deleter.await.unwrap();

            // Resurrection = the delete committed, yet a STALE rotation (one that read OLD, hence
            // revision 2) is now live. Under value-CAS this is impossible; a fresh re-create is
            // revision 1. Under the blind mutation a stale put lands after the delete → revision 2.
            if matches!(del_res, Ok(true)) {
                let live_stale = store
                    .list(p)
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|m| m.name == name)
                    .is_some_and(|m| m.revision == 2);
                if live_stale {
                    resurrections += 1;
                }
            }
        }
        assert_eq!(
            resurrections, 0,
            "a committed delete must not be undone by a stale concurrent rotation (resurrection)"
        );
        println!(
            "SQLKV PG CROWNJEWEL RESURRECTION OK [postgres]: 100 rounds of rotate-vs-delete over a \
             real primary — no deleted secret resurrected."
        );
    }

    /// MF-1 GATE — N concurrent new-name `TenantSecretStore::set` at `count = max-1` over a real
    /// Postgres admit exactly ONE (the CAS'd per-tenant index), so the cap holds. RED under the
    /// mutation (list-then-write TOCTOU → all admitted, cap bypassed).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn crownjewel_tenant_name_cap_holds_under_concurrency() {
        let Some(kv) = fresh_pg().await else {
            return;
        };
        let store = Arc::new(TenantSecretStore::new(
            Arc::new(kv) as Arc<dyn KvStore>,
            Arc::new(GateEnvelope),
        ));
        let p = gate_project();
        let tenant = "firm-1";
        for i in 0..(MAX_TENANT_SECRET_NAMES - 1) {
            store.set(p, tenant, &format!("n{i}"), b"v").await.unwrap();
        }

        // 32 racers over a ≥16-conn pool: a first wave reads `count = max-1` concurrently, so the
        // old list-then-write TOCTOU (the mutation) admits the whole wave — RED. The CAS'd index
        // admits exactly one regardless of the racer count.
        let mut set = tokio::task::JoinSet::new();
        for i in 0..32u32 {
            let store = store.clone();
            set.spawn(async move { store.set(p, tenant, &format!("new-{i}"), b"v").await });
        }
        let (mut ok, mut rejected) = (0usize, 0usize);
        while let Some(res) = set.join_next().await {
            match res.unwrap() {
                Ok(_) => ok += 1,
                Err(SecretError::TooManyNames { .. }) | Err(SecretError::Conflict(_)) => {
                    rejected += 1;
                }
                Err(e) => panic!("unexpected secret error: {e}"),
            }
        }
        assert_eq!(
            ok, 1,
            "exactly one new name admitted at the cap boundary (got ok={ok}, rejected={rejected})"
        );
        let live = store.list(p, tenant).await.unwrap().len();
        assert_eq!(
            live, MAX_TENANT_SECRET_NAMES,
            "the per-tenant name cap must hold under concurrency (not be bypassed)"
        );
        println!(
            "SQLKV PG CROWNJEWEL TENANT CAP OK [postgres]: 32 concurrent new-name sets at \
             count=max-1 over a real primary — cap held at {MAX_TENANT_SECRET_NAMES}."
        );
    }

    /// MF-1 GATE — two concurrent policy edits (version/If-Match) over a real Postgres: exactly one
    /// wins, the other `Conflict`s (409), no lost write. RED under the mutation (blind whole-doc put
    /// drops the version guard → both win, one edit silently lost).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn crownjewel_concurrent_policy_edit_no_lost_write() {
        let Some(kv) = fresh_pg().await else {
            return;
        };
        let kv = Arc::new(kv) as Arc<dyn KvStore>;
        for round in 0..12u32 {
            let (_cur, ver) = policy_read_versioned(kv.as_ref()).await.unwrap();
            let k1 = kv.clone();
            let v1 = ver.clone();
            let a = distinct_policy(&format!("a{round}"));
            let ta = tokio::spawn(async move { policy_set_if_match(k1.as_ref(), &v1, &a).await });
            let k2 = kv.clone();
            let v2 = ver.clone();
            let b = distinct_policy(&format!("b{round}"));
            let tb = tokio::spawn(async move { policy_set_if_match(k2.as_ref(), &v2, &b).await });
            let ra = ta.await.unwrap();
            let rb = tb.await.unwrap();
            let oks = [&ra, &rb].iter().filter(|r| r.is_ok()).count();
            let conflicts = [&ra, &rb]
                .iter()
                .filter(|r| matches!(r, Err(DeployError::Conflict(_))))
                .count();
            assert_eq!(
                oks, 1,
                "round {round}: exactly one concurrent policy edit may win"
            );
            assert_eq!(
                conflicts, 1,
                "round {round}: the losing edit must Conflict (409) — no silent lost write"
            );
        }
        println!(
            "SQLKV PG CROWNJEWEL POLICY EDIT OK [postgres]: 12 rounds of concurrent If-Match edits \
             over a real primary — one wins, one 409s, no lost write."
        );
    }

    // ---- WS4 shared-mode gates (election + control-plane identity) over a REAL multi-writer PG ----
    //
    // The IDENTICAL properties are unit-tested over `MemoryKv` in `boatramp_core::shared_mode`; here
    // they run over the real multi-writer `SqlKv`, where the single-leader guarantee reduces to the
    // same cross-connection linearizable CAS the MF-2 gate proves. Each is mutation-verified: built
    // with `--features sql-postgres,shared-mode-gate-mutation` and
    // `BOATRAMP_KVSQL_MUTATION=disable_leader_lock` / `=skip_cp_id_stamp`, the lease / cp-id stamp is
    // driven off and the gate goes RED (the CI mutation loop asserts that). Env-gated on
    // `BOATRAMP_TEST_PG_URL`; skips CLEANLY when unset.
    use boatramp_core::shared_mode::{
        ControlPlaneIdentity, DEFAULT_MEMBER_WINDOW, LeaderLease, random_node_id,
    };
    use std::time::Duration;

    /// WS4 GATE (C1) — N leases over ONE real Postgres primary (≥16-conn pool) contend for leadership
    /// and EXACTLY ONE is leader at a time; when the holder's lease expires, a survivor takes over.
    /// The single-statement value-CAS makes the lease cross-connection linearizable. RED under
    /// `disable_leader_lock` (every lease declares itself leader → many leaders).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn shared_election_single_leader_under_concurrency() {
        let Some(kv) = fresh_pg().await else {
            return;
        };
        let store = Arc::new(kv) as Arc<dyn KvStore>;
        let ttl = Duration::from_secs(10);

        // 16 nodes all tick once concurrently over the shared primary → exactly one acquires.
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16u32 {
            let store = store.clone();
            set.spawn(async move {
                let lease = LeaderLease::new(store, random_node_id(), ttl);
                let won = lease.tick().await.unwrap();
                (won, lease.is_leader())
            });
        }
        let mut leaders = 0;
        while let Some(res) = set.join_next().await {
            let (won, is_leader) = res.unwrap();
            assert_eq!(won, is_leader, "tick result and is_leader fence agree");
            if won {
                leaders += 1;
            }
        }
        assert_eq!(
            leaders, 1,
            "exactly one node acquires the lease over a real primary"
        );

        // Bounded failover: force the lease expired (as if the holder died), a survivor takes over.
        boatramp_core::shared_mode::seed_expired_lease(&store, "dead-node")
            .await
            .unwrap();
        let survivor = LeaderLease::new(store.clone(), random_node_id(), ttl);
        assert!(
            survivor.tick().await.unwrap(),
            "a survivor takes over an expired lease within the bound"
        );
        assert!(survivor.is_leader());
        println!(
            "SQLKV PG SHARED ELECTION OK [postgres]: 16-way lease contention over a real primary had \
             EXACTLY ONE leader; a survivor took over an expired lease."
        );
    }

    /// WS4 GATE (UX-C1) — two opens against the SAME real Postgres share one cp-id and see TWO
    /// members (commingle detectable); a fresh (reset) database stamps a DIFFERENT cp-id
    /// (split-brain detectable). RED under `skip_cp_id_stamp` (no stamp → empty ids, undetectable).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn shared_control_plane_identity_detects_commingle_and_split_brain() {
        let Some(kv) = fresh_pg().await else {
            return;
        };
        let store = Arc::new(kv) as Arc<dyn KvStore>;

        // Commingle: two nodes open the SAME database → same cp-id, both members seen.
        let a = ControlPlaneIdentity::new(store.clone(), random_node_id(), DEFAULT_MEMBER_WINDOW);
        let b = ControlPlaneIdentity::new(store.clone(), random_node_id(), DEFAULT_MEMBER_WINDOW);
        let ra = a.join().await.unwrap();
        let rb = b.join().await.unwrap();
        assert!(
            !ra.control_plane_id.is_empty(),
            "the first open stamps a cp-id"
        );
        assert!(ra.created_new, "the first open created the control plane");
        assert!(!rb.created_new, "the second open JOINED it");
        assert_eq!(
            ra.control_plane_id, rb.control_plane_id,
            "both nodes on the same real db share the cp-id (commingle detectable)"
        );
        assert_eq!(rb.members_seen, 2, "both members seen on the shared db");

        // Split-brain: a fresh/empty database (reset) stamps a DIFFERENT cp-id.
        let first_id = ra.control_plane_id.clone();
        // Reset the tables to simulate a SEPARATE empty database.
        reset_tables(&store).await;
        let c = ControlPlaneIdentity::new(store.clone(), random_node_id(), DEFAULT_MEMBER_WINDOW);
        let rc = c.join().await.unwrap();
        assert!(rc.created_new, "the fresh db stamps its own cp-id");
        assert_ne!(
            first_id, rc.control_plane_id,
            "a separate database has a DIFFERENT cp-id (split-brain detectable)"
        );
        println!(
            "SQLKV PG CP IDENTITY OK [postgres]: same db ⇒ shared cp-id + 2 members (commingle); \
             separate db ⇒ distinct cp-id (split-brain)."
        );
    }

    /// Reset the `kv` + `kv_changes` tables (clearing the `_cp/*` rows too) over the PG store — used
    /// to simulate a second, empty database for the split-brain half.
    async fn reset_tables(store: &Arc<dyn KvStore>) {
        // `list_prefix("")` + delete each would also work; a direct script is faster + exact.
        for key in store.list_prefix("_cp/").await.unwrap() {
            store.delete(&key).await.unwrap();
        }
    }
}
