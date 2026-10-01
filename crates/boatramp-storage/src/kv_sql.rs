//! [`SqlKv`] — a [`KvStore`](boatramp_core::kv::KvStore) over the existing SQL connection layer,
//! the SQL-backed control-plane metadata store alongside the object-store (SlateDB) family.
//!
//! **This workstream (build-order step 1) wires the SQLite / libsql-LOCAL single-writer path only**
//! — the lowest-risk standalone win that also deletes the SlateDB torn-manifest / `.compactions`
//! durability class for a single box. Postgres and MySQL are later workstreams (step 2 / step 6):
//! the SQL here is **dialect-parameterized** (every statement is produced by
//! [`statements_for`], keyed on [`Dialect`]) and the writer-model declaration already branches on
//! the dialect, so adding the Postgres/MySQL pools slots in without reshaping this module — but
//! only the SQLite dialect is CONSTRUCTED and exercised today (`statements_for` panics for the
//! others, and the only constructor, [`SqlKv::open_sqlite_local`], pins [`Dialect::Sqlite`]).
//!
//! ## Schema (host-owned, created idempotently on open — Architect C9)
//! Two tables, created with the same `CREATE TABLE IF NOT EXISTS` host pattern the migration
//! substrate's `ensure_ledger` uses (NOT the guest `project migrate` tool):
//! - `kv(key BLOB PRIMARY KEY, value BLOB NOT NULL, version BIGINT NOT NULL)` — the store itself.
//!   Keys are the `&str` key's UTF-8 bytes stored as a BLOB so comparison/ordering is bytewise
//!   (matching Rust `str` byte order), and values are the raw bytes (an empty value is a
//!   zero-length BLOB, distinct from an absent key). `version` bumps on every write — the basis a
//!   later workstream's crown-jewel CAS and the change log build on.
//! - `kv_changes(seq INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB, version BIGINT, ts INTEGER)` —
//!   the append-only change log. The SQLite single-writer path does not need cross-node change
//!   propagation yet, but every write appends a row here (a put/CAS-win records the post-write
//!   version; a delete records a tombstone — `version = 0`, since live versions start at `1`) so
//!   the multi-writer ChangePublisher of a later workstream has the ledger it polls.
//!
//! ## CAS — value-predicate, single-statement, winner-by-rows-affected (MF-2 shape)
//! [`KvStore::compare_and_swap`](boatramp_core::kv::KvStore::compare_and_swap) is VALUE-based
//! (`expected: Option<&[u8]>`, whole-record bytes). The decision is ALWAYS one statement whose
//! rows-affected names the winner — never a follow-up `SELECT`:
//! - present-key: `UPDATE kv SET value=?, version=version+1 WHERE key=? AND value=?` → winner iff
//!   `rows_affected == 1`.
//! - absent-key (`expected = None`): `INSERT INTO kv (…) VALUES (…) ON CONFLICT(key) DO NOTHING` →
//!   winner iff `rows_affected == 1`.
//!
//! A single SQLite database serializes its writers, so this is a linearizable CAS w.r.t. that one
//! store — [`SqlKv::supports_cas`] is `true`, honestly, for the SQLite single-writer backend.
//!
//! ## Synchronous-commit durability (Architect C6)
//! Every mutating op returns ONLY after its transaction has COMMITted durably: the database is
//! opened in **WAL** mode with **`PRAGMA synchronous = FULL`**, so each `COMMIT` fsyncs the WAL
//! before the call returns — no async-buffered ack. (WAL is persisted in the file header; the
//! per-connection `synchronous` is re-asserted on every connection the write path opens.) This is
//! what makes the [`CheckpointKv`](boatramp_core::kv::CheckpointKv) wrapper already correct over
//! `SqlKv`: a durable `put` plus the trait's no-op `checkpoint()`.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use boatramp_core::kv::{KvError, KvStore, WriteOp, WriterModel};
use boatramp_core::sql::Dialect;
use libsql::{Builder, Connection, Database, Value as LibsqlValue};

/// How long a contended writer waits for the single-writer lock before erroring (local SQLite).
/// Keep it under the control-plane per-op timeout so a genuinely stuck lock surfaces as an error
/// rather than hanging; a racing CAS/write simply waits its turn here (the single-writer serialize).
const BUSY_TIMEOUT_MS: u32 = 5_000;

/// The fixed set of host-authored statements for one SQL dialect. Every field is `&'static` so the
/// whole set is `Copy` and resolved once at open ([`statements_for`]); the placeholders are the
/// canonical `?N` form (libsql speaks it natively — the external Postgres/MySQL path of a later
/// workstream rewrites `?N` via `sql_placeholders`). All statements are host-built with bound
/// parameters only (never guest text), so no placeholder validation is needed here.
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

/// SQLite / libsql statement set — the only dialect this workstream constructs.
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

/// Resolve the statement set for `dialect`. Only [`Dialect::Sqlite`] is wired in this workstream;
/// the Postgres/MySQL arms (BYTEA/BIGSERIAL types, `$N`/`?` placeholders, and the MySQL
/// `UPDATE … WHERE value=` / `INSERT IGNORE` CAS shapes) are built with their pools in build-order
/// steps 2 and 6. The only constructor pins [`Dialect::Sqlite`], so the other arms are never reached.
fn statements_for(dialect: Dialect) -> KvStatements {
    match dialect {
        Dialect::Sqlite => SQLITE_STATEMENTS,
        Dialect::Postgres | Dialect::Mysql => unreachable!(
            "the Postgres/MySQL SqlKv execution path is wired in a later workstream (step 2/6); \
             this workstream constructs only the SQLite dialect"
        ),
    }
}

/// A SQL-backed [`KvStore`]. This workstream backs it with an embedded **SQLite / libsql local
/// file** (single-writer); the `dialect` + [`statements_for`] seam keeps the SQL generation ready
/// for the Postgres/MySQL pools of a later workstream without reshaping the ops.
pub struct SqlKv {
    db: Arc<Database>,
    dialect: Dialect,
    stmts: KvStatements,
}

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
            db: Arc::new(db),
            dialect: Dialect::Sqlite,
            stmts,
        })
    }

    /// A connection tuned for the control-plane KV: a contended writer WAITS for the single-writer
    /// lock (`busy_timeout`) rather than erroring, and `synchronous = FULL` makes its commits fsync
    /// before returning (C6). Each op opens a fresh connection off the shared `Database` (as the
    /// libsql `SqlBackend` does), so concurrent ops each get their own transaction.
    async fn connect(&self) -> Result<Connection, KvError> {
        let conn = self.db.connect().map_err(kv_err)?;
        run_pragma(&conn, &format!("PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")).await?;
        run_pragma(&conn, "PRAGMA synchronous=FULL").await?;
        Ok(conn)
    }

    /// The pragmas the WRITE path actually opens its connections with — `(journal_mode,
    /// synchronous)` — read back on a freshly-tuned connection. Proves the synchronous-commit
    /// contract (C6) at the seam the writes use: WAL + `synchronous = FULL` (`2`).
    #[cfg(test)]
    pub(crate) async fn debug_pragmas(&self) -> Result<(String, i64), KvError> {
        let conn = self.connect().await?;
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
}

#[async_trait]
impl KvStore for SqlKv {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError> {
        let conn = self.connect().await?;
        let mut rows = conn
            .query(self.stmts.get, libsql::params_from_iter([blob(key)]))
            .await
            .map_err(kv_err)?;
        match rows.next().await.map_err(kv_err)? {
            Some(row) => Ok(Some(value_bytes(row.get_value(0).map_err(kv_err)?)?)),
            None => Ok(None),
        }
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        let conn = self.connect().await?;
        begin(&conn).await?;
        let ts = now_ts();
        let res = async {
            conn.execute(
                self.stmts.upsert,
                libsql::params_from_iter([blob(key), LibsqlValue::Blob(value)]),
            )
            .await
            .map_err(kv_err)?;
            conn.execute(
                self.stmts.append_change,
                libsql::params_from_iter([blob(key), LibsqlValue::Integer(ts)]),
            )
            .await
            .map_err(kv_err)?;
            Ok(())
        }
        .await;
        finish(&conn, res).await
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        let conn = self.connect().await?;
        begin(&conn).await?;
        let ts = now_ts();
        let res = async {
            let affected = conn
                .execute(self.stmts.delete, libsql::params_from_iter([blob(key)]))
                .await
                .map_err(kv_err)?;
            // Only record a tombstone when a row was actually removed (deleting a missing key is a
            // no-op per the trait contract, so it leaves the change log untouched).
            if affected > 0 {
                conn.execute(
                    self.stmts.delete_change,
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

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, KvError> {
        let conn = self.connect().await?;
        let lower = prefix.as_bytes().to_vec();
        let (sql, params) = match prefix_successor(&lower) {
            Some(upper) => (
                self.stmts.list_prefix_bounded,
                vec![LibsqlValue::Blob(lower), LibsqlValue::Blob(upper)],
            ),
            None => (self.stmts.list_prefix_all, vec![LibsqlValue::Blob(lower)]),
        };
        collect_keys(&conn, sql, params).await
    }

    async fn list_from(
        &self,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, KvError> {
        let conn = self.connect().await?;
        let prefix_bytes = prefix.as_bytes().to_vec();
        let mut start = prefix_bytes.clone();
        start.extend_from_slice(after.as_bytes());
        let lim = LibsqlValue::Integer(limit as i64);
        let (sql, params) = match prefix_successor(&prefix_bytes) {
            Some(upper) => (
                self.stmts.list_from_bounded,
                vec![LibsqlValue::Blob(start), LibsqlValue::Blob(upper), lim],
            ),
            None => (
                self.stmts.list_from_all,
                vec![LibsqlValue::Blob(start), lim],
            ),
        };
        collect_keys(&conn, sql, params).await
    }

    fn atomic_write_batch(&self) -> bool {
        // The whole batch commits inside one `BEGIN IMMEDIATE … COMMIT` (below), so a crash can
        // never leave it partially applied — the ready-set fast path (B2) is safe over it.
        true
    }

    async fn write_batch(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        let conn = self.connect().await?;
        begin(&conn).await?;
        let ts = now_ts();
        let res = async {
            for op in &ops {
                match op {
                    WriteOp::Put(key, value) => {
                        conn.execute(
                            self.stmts.upsert,
                            libsql::params_from_iter([blob(key), LibsqlValue::Blob(value.clone())]),
                        )
                        .await
                        .map_err(kv_err)?;
                        conn.execute(
                            self.stmts.append_change,
                            libsql::params_from_iter([blob(key), LibsqlValue::Integer(ts)]),
                        )
                        .await
                        .map_err(kv_err)?;
                    }
                    WriteOp::Delete(key) => {
                        let affected = conn
                            .execute(self.stmts.delete, libsql::params_from_iter([blob(key)]))
                            .await
                            .map_err(kv_err)?;
                        if affected > 0 {
                            conn.execute(
                                self.stmts.delete_change,
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

    fn supports_cas(&self) -> bool {
        // A single SQLite database serializes its writers, so the single-statement value-predicate
        // CAS below is linearizable w.r.t. this store: two racing swappers can never both win.
        true
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> Result<bool, KvError> {
        let conn = self.connect().await?;
        begin(&conn).await?;
        let ts = now_ts();
        let res = async {
            // ONE statement decides the winner by rows-affected — never a read-then-write.
            let won = match expected {
                Some(expected) => {
                    let affected = conn
                        .execute(
                            self.stmts.cas_present,
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
                            self.stmts.cas_absent,
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
                    self.stmts.append_change,
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

    fn writer_model(&self) -> WriterModel {
        // The writer-model DECLARATION (the whole point of the mechanism): SQLite/libsql-local is a
        // single-writer store; the self-serializing Postgres/MySQL dialects (a later workstream)
        // declare MultiWriter. Correct for every dialect even though only SQLite is built today.
        match self.dialect {
            Dialect::Sqlite => WriterModel::SingleWriter,
            Dialect::Postgres | Dialect::Mysql => WriterModel::MultiWriter,
        }
    }
}

/// Open a write transaction that takes the write lock at `BEGIN` (`IMMEDIATE`), so concurrent
/// writers queue on the `busy_timeout` and serialize cleanly — no deferred-transaction upgrade
/// deadlock.
async fn begin(conn: &Connection) -> Result<(), KvError> {
    conn.execute("BEGIN IMMEDIATE", ())
        .await
        .map_err(kv_err)
        .map(|_| ())
}

/// Commit the transaction on success, or roll it back on error (a failed rollback is harmless —
/// dropping the connection rolls back too). Returns the inner result unchanged on success.
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
async fn run_pragma(conn: &Connection, sql: &str) -> Result<(), KvError> {
    let mut rows = conn.query(sql, ()).await.map_err(kv_err)?;
    while rows.next().await.map_err(kv_err)?.is_some() {}
    Ok(())
}

/// Run a one-row-one-column query and return that cell (for the pragma read-back in tests).
#[cfg(test)]
async fn query_one(conn: &Connection, sql: &str) -> Result<Option<LibsqlValue>, KvError> {
    let mut rows = conn.query(sql, ()).await.map_err(kv_err)?;
    match rows.next().await.map_err(kv_err)? {
        Some(row) => Ok(Some(row.get_value(0).map_err(kv_err)?)),
        None => Ok(None),
    }
}

/// Run `sql` and collect its first column (keys), decoded from BLOB back to the `String` keys.
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
fn blob(key: &str) -> LibsqlValue {
    LibsqlValue::Blob(key.as_bytes().to_vec())
}

/// Decode a `value`/`key` column back to bytes. Stored as a BLOB (empty value ⇒ empty BLOB); a
/// defensive `Text` arm covers an engine that hands an empty BLOB back as empty text, and `Null`
/// (barred by `NOT NULL`) maps to empty for safety. A numeric cell is a schema bug → error.
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

/// Unix-seconds timestamp for a change-log row (best-effort; a clock before the epoch records `0`).
fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Map any libsql / backend error into the crate-facing [`KvError`].
fn kv_err<E: std::fmt::Display>(err: E) -> KvError {
    KvError::backend(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

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

        let conn = kv.connect().await.unwrap();
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
}
