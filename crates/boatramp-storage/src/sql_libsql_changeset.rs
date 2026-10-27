//! **The libsql/SQLite CHANGESET true-delta engine** (SQL true-delta program, Stage 4 — see
//! `PLAN-sql-true-delta.md`). The pg/mysql engines source a row-level delta from a server change
//! stream (logical WAL / binlog); libsql has no such stream, so this engine diffs two database
//! FILES with the SQLite **session** extension and replays the resulting **changeset** onto the
//! restored base inside the inc2 atomic shadow.
//!
//! ## Build capability
//! The session/changeset C API is compiled in by the `sql-delta-libsql` feature, which pulls
//! `libsql-ffi` with its `session` + `preupdate_hook` features. That is the SAME `libsql-ffi` the
//! `libsql` crate already links transitively (Cargo unifies the features onto ONE SQLite build), so
//! there is no second SQLite amalgamation and no duplicate-symbol collision — and the extension
//! comes from `libsql-ffi`'s PRE-GENERATED bindings, so no `libclang` runs at build time (musl-safe,
//! identical to the bindings the current build already uses).
//!
//! ## Offline, file-based — never the live serving connection
//! Both capture and replay open database FILES directly through the raw FFI (`sqlite3_open_v2`),
//! never the live `libsql::Connection` the handler `sql` binding serves. Capture runs on a
//! VACUUM-INTO snapshot of the live DB; replay runs on a fresh `*.shadow_*` copy of the base. So this
//! engine shares no state with live serving — it is a pure transform over files.
//!
//! ## Security model (replay confinement — the inc2 HIGH-1 class)
//! A changeset member crosses the SAME trust boundary as the streamed `.dump` and the pg/mysql
//! deltas: its bundle SHA is integrity, not authenticity, so a crafted member can carry arbitrary
//! row operations. Unlike a `.dump` (SQL text, so SQL-injection-shaped) a changeset is binary row
//! ops — the escape surface is *which tables it writes*. The replay confines it structurally:
//! - **Per-file isolation.** A changeset can only name tables in the ONE connected database; it has
//!   no `ATTACH`/cross-database reach. Each site's DB is a separate FILE, so a changeset applied
//!   during tenant A's restore CANNOT reach tenant B's file at all.
//! - **A base-table FILTER.** The apply's `xFilter` returns "apply" ONLY for tables present in the
//!   restored base's own schema; any other (foreign) table is SKIPPED (never written) AND flagged,
//!   turning the whole apply into a loud refusal.
//! - **Abort on ANY conflict.** The apply's `xConflict` returns `ABORT` for every conflict class, so
//!   a changeset whose base does not match (a mismatched/crafted base) rolls the whole apply back —
//!   never a forced/partial write.
//! - **Self-atomic.** The apply runs inside an explicit transaction that is COMMITTED only when the
//!   changeset applied cleanly AND touched no foreign table; otherwise it is ROLLED BACK, so the
//!   target file is left byte-for-byte unchanged on any refusal (and the restore caller additionally
//!   discards the shadow — live is never renamed-over).
//!
//! All of the above is proven, mutation-sensitively, by the in-process ≥2-tenant crafted-escape +
//! real-round-trip gate (`project_export_roundtrip.rs`).

use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::path::Path;

use boatramp_core::sql::SqlError;
use libsql_ffi::{
    SQLITE_CHANGESET_ABORT, SQLITE_OK, SQLITE_OPEN_READONLY, SQLITE_OPEN_READWRITE, SQLITE_ROW,
    sqlite3, sqlite3_changeset_iter, sqlite3_close_v2, sqlite3_errmsg, sqlite3_exec,
    sqlite3_finalize, sqlite3_free, sqlite3_open_v2, sqlite3_prepare_v2, sqlite3_step,
    sqlite3changeset_apply, sqlite3session_attach, sqlite3session_changeset, sqlite3session_create,
    sqlite3session_delete, sqlite3session_diff,
};

/// The outcome of a libsql changeset CAPTURE: either a true row-level changeset was produced, or the
/// engine must FALL BACK to a full dump (the all-families-consistent invariant, decision 3). Every
/// fallback carries a human reason (recorded in the export notes) and is NEVER an error — a delta
/// that cannot true-delta a DB still ships that DB as a full dump within the same bundle.
#[derive(Debug, Clone)]
pub enum ChangesetCapture {
    /// A true row-level changeset (base → current). May be EMPTY (no changes) — still a valid member.
    Changeset(Vec<u8>),
    /// The DB cannot be changeset-diffed against this base → full-dump fallback, with the reason.
    Fallback(String),
}

/// A RAII handle to a raw `sqlite3*` connection: closed on drop so every early-return path releases
/// the file (no leaked handle, no lingering `-wal`/`-shm`). Never crosses an `.await` (the engine is
/// synchronous, driven from `spawn_blocking`).
struct RawDb {
    db: *mut sqlite3,
}

impl RawDb {
    /// Open the database FILE at `path` with `flags` (no VFS). A path with an interior NUL, or any
    /// open failure, is a loud [`SqlError`].
    fn open(path: &Path, flags: c_int) -> Result<Self, SqlError> {
        let cpath = path_cstring(path)?;
        let mut db: *mut sqlite3 = std::ptr::null_mut();
        // SAFETY: `cpath` is a valid NUL-terminated C string that outlives the call; `db` is a valid
        // out-pointer. On any non-OK return SQLite still allocates a handle carrying the error, so we
        // keep it (via the RawDb) long enough to read `sqlite3_errmsg`, then Drop closes it.
        let rc = unsafe { sqlite3_open_v2(cpath.as_ptr(), &mut db, flags, std::ptr::null()) };
        let this = Self { db };
        if rc != SQLITE_OK {
            return Err(SqlError::other(format!(
                "libsql changeset: open {} failed (rc {rc}): {}",
                path.display(),
                this.errmsg()
            )));
        }
        Ok(this)
    }

    /// The connection's last error message (empty if none / the handle is null).
    fn errmsg(&self) -> String {
        if self.db.is_null() {
            return String::new();
        }
        // SAFETY: `self.db` is a live handle; `sqlite3_errmsg` returns a NUL-terminated string owned
        // by SQLite and valid until the next call on this connection — we copy it immediately.
        unsafe {
            let p = sqlite3_errmsg(self.db);
            if p.is_null() {
                String::new()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        }
    }

    /// Run a trusted, driver-generated statement (no bound data) via `sqlite3_exec`. The SQL is
    /// either a literal or built only from identifiers/paths we escape — never from changeset bytes.
    fn exec(&self, sql: &str) -> Result<(), SqlError> {
        let csql = CString::new(sql)
            .map_err(|_| SqlError::other("libsql changeset: SQL has a NUL byte"))?;
        let mut errmsg: *mut c_char = std::ptr::null_mut();
        // SAFETY: `csql` outlives the call; the callback is null (we discard rows); `errmsg` is a
        // valid out-pointer that, on error, receives a `sqlite3_malloc`'d string we free below.
        let rc = unsafe {
            sqlite3_exec(
                self.db,
                csql.as_ptr(),
                None,
                std::ptr::null_mut(),
                &mut errmsg,
            )
        };
        if rc != SQLITE_OK {
            let msg = if errmsg.is_null() {
                self.errmsg()
            } else {
                // SAFETY: `errmsg` is a NUL-terminated string SQLite allocated; copy then free it.
                let m = unsafe { CStr::from_ptr(errmsg).to_string_lossy().into_owned() };
                unsafe { sqlite3_free(errmsg.cast::<c_void>()) };
                m
            };
            return Err(SqlError::other(format!(
                "libsql changeset: exec failed (rc {rc}): {msg} [{}]",
                sql.chars().take(80).collect::<String>()
            )));
        }
        Ok(())
    }

    /// Run a single-column query and collect its TEXT values (used only for our own metadata reads:
    /// the schema fingerprint + the table list). Rows are read via prepare/step so no `sqlite3_exec`
    /// callback trampoline is needed. A NULL or non-text column yields an empty string.
    fn query_text_column(&self, sql: &str) -> Result<Vec<String>, SqlError> {
        let csql = CString::new(sql)
            .map_err(|_| SqlError::other("libsql changeset: query SQL has a NUL byte"))?;
        let mut stmt = std::ptr::null_mut();
        // SAFETY: `csql` outlives prepare; `stmt` is a valid out-pointer; `-1` lets SQLite scan to
        // the NUL; the tail out-pointer is null (single statement).
        let rc = unsafe {
            sqlite3_prepare_v2(self.db, csql.as_ptr(), -1, &mut stmt, std::ptr::null_mut())
        };
        if rc != SQLITE_OK {
            return Err(SqlError::other(format!(
                "libsql changeset: prepare failed (rc {rc}): {}",
                self.errmsg()
            )));
        }
        let mut out = Vec::new();
        loop {
            // SAFETY: `stmt` is a valid prepared statement; step advances it.
            let rc = unsafe { sqlite3_step(stmt) };
            if rc == SQLITE_ROW {
                // SAFETY: column 0 exists for these single-column queries; `sqlite3_column_text`
                // returns a NUL-terminated string valid until the next step/finalize — copy it now.
                let p = unsafe { libsql_ffi::sqlite3_column_text(stmt, 0) };
                let s = if p.is_null() {
                    String::new()
                } else {
                    unsafe {
                        CStr::from_ptr(p.cast::<c_char>())
                            .to_string_lossy()
                            .into_owned()
                    }
                };
                out.push(s);
            } else if rc == SQLITE_OK || rc == 101
            /* SQLITE_DONE */
            {
                break;
            } else {
                let msg = self.errmsg();
                // SAFETY: finalize the statement before returning (also done in the happy path below).
                unsafe { sqlite3_finalize(stmt) };
                return Err(SqlError::other(format!(
                    "libsql changeset: step failed (rc {rc}): {msg}"
                )));
            }
        }
        // SAFETY: `stmt` is finalized exactly once (the error path above returns before here).
        unsafe { sqlite3_finalize(stmt) };
        Ok(out)
    }

    /// The user-schema fingerprint: the sorted `type|name|sql` of every non-internal object in
    /// `schema` (`main` or an attached alias). Identical fingerprints ⇒ a changeset (row-only) can
    /// faithfully carry the delta; any difference ⇒ a DDL change the changeset cannot represent ⇒
    /// full-dump fallback.
    fn schema_fingerprint(&self, schema: &str) -> Result<String, SqlError> {
        // `schema` is one of our own literals ("main"/"base"); still, keep it identifier-safe.
        let q = format!(
            "SELECT type || '|' || name || '|' || COALESCE(sql,'') \
             FROM \"{}\".sqlite_master \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
            schema.replace('"', "\"\"")
        );
        Ok(self.query_text_column(&q)?.join("\n"))
    }

    /// The user TABLE names in `main` (excluding internal `sqlite_%`).
    fn table_names(&self) -> Result<Vec<String>, SqlError> {
        self.query_text_column(
            "SELECT name FROM main.sqlite_master \
             WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
    }

    /// Whether every user table in `main` has a PRIMARY KEY (and is a real, not VIRTUAL, table). The
    /// SQLite session API records changes ONLY for PK-bearing tables, so a PK-less (rowid-only) or
    /// virtual table cannot be faithfully diffed ⇒ the caller falls back to a full dump.
    fn every_table_has_pk(&self, tables: &[String]) -> Result<bool, SqlError> {
        for t in tables {
            let lit = t.replace('\'', "''");
            // A VIRTUAL table has no PK rows here either; this one query covers both.
            let rows = self.query_text_column(&format!(
                "SELECT count(*) FROM pragma_table_info('{lit}') WHERE \"pk\" > 0"
            ))?;
            let n: i64 = rows.first().and_then(|s| s.parse().ok()).unwrap_or(0);
            if n == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Drop for RawDb {
    fn drop(&mut self) {
        if !self.db.is_null() {
            // SAFETY: `self.db` was opened by `sqlite3_open_v2` and is closed exactly once (here).
            // `_v2` tolerates outstanding unfinalized statements by deferring the close; we finalize
            // everything we prepare, so this closes immediately.
            unsafe { sqlite3_close_v2(self.db) };
            self.db = std::ptr::null_mut();
        }
    }
}

/// Convert a path to a C string, rejecting an interior NUL (which would truncate the path).
fn path_cstring(path: &Path) -> Result<CString, SqlError> {
    let s = path
        .to_str()
        .ok_or_else(|| SqlError::other("libsql changeset: database path is not valid UTF-8"))?;
    CString::new(s).map_err(|_| SqlError::other("libsql changeset: database path has a NUL byte"))
}

/// **CAPTURE** the row-level delta between a `base` database snapshot and the `current` database, as
/// a SQLite changeset. Returns [`ChangesetCapture::Fallback`] (NOT an error) whenever a changeset
/// cannot faithfully carry the delta: the user schema changed since the base (DDL is not row data),
/// a table lacks a PRIMARY KEY (sessions cannot track it), or the session diff errors. Both files
/// are opened READ-ONLY; nothing is written.
///
/// Mechanism: open `current` as `main`, `ATTACH` `base` as `base`, create a session on `main`, and
/// for each table `sqlite3session_diff(session, "base", tbl)` records the changes that transform
/// `base.tbl` into `main.tbl`. The accumulated changeset therefore transforms the base INTO the
/// current state when applied — exactly what replay needs.
pub fn capture_changeset(base: &Path, current: &Path) -> Result<ChangesetCapture, SqlError> {
    let db = RawDb::open(current, SQLITE_OPEN_READONLY)?;
    // ATTACH the base snapshot read-only (URI mode=ro needs SQLITE_OPEN_URI; a plain ATTACH is fine
    // — we never issue a write against `base`, and the connection is READONLY anyway).
    let base_lit = base
        .to_str()
        .ok_or_else(|| SqlError::other("libsql changeset: base path is not valid UTF-8"))?
        .replace('\'', "''");
    db.exec(&format!("ATTACH DATABASE '{base_lit}' AS base"))?;

    // DDL skew ⇒ fallback (a changeset carries row ops only, never schema changes).
    if db.schema_fingerprint("main")? != db.schema_fingerprint("base")? {
        return Ok(ChangesetCapture::Fallback(
            "libsql schema changed since the base snapshot — full-dump fallback".into(),
        ));
    }
    let tables = db.table_names()?;
    if !db.every_table_has_pk(&tables)? {
        return Ok(ChangesetCapture::Fallback(
            "a libsql table has no PRIMARY KEY (sessions cannot diff it) — full-dump fallback"
                .into(),
        ));
    }

    // Create the session on `main` and diff each table base→current.
    let main_c = CString::new("main").expect("no NUL");
    let mut session = std::ptr::null_mut();
    // SAFETY: `db.db` is live; `main_c` outlives the call; `session` is a valid out-pointer.
    let rc = unsafe { sqlite3session_create(db.db, main_c.as_ptr(), &mut session) };
    if rc != SQLITE_OK || session.is_null() {
        return Err(SqlError::other(format!(
            "libsql changeset: session_create failed (rc {rc}): {}",
            db.errmsg()
        )));
    }
    // RAII the session so every early return frees it.
    struct Session(*mut libsql_ffi::sqlite3_session);
    impl Drop for Session {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: created by `sqlite3session_create`, deleted exactly once here.
                unsafe { sqlite3session_delete(self.0) };
            }
        }
    }
    let session = Session(session);
    let base_c = CString::new("base").expect("no NUL");

    for t in &tables {
        let tc = CString::new(t.as_str())
            .map_err(|_| SqlError::other("libsql changeset: table name has a NUL byte"))?;
        // SAFETY: session + strings are live for the call. attach restricts recording to this table.
        let rc = unsafe { sqlite3session_attach(session.0, tc.as_ptr()) };
        if rc != SQLITE_OK {
            return Err(SqlError::other(format!(
                "libsql changeset: session_attach({t:?}) failed (rc {rc}): {}",
                db.errmsg()
            )));
        }
        let mut errmsg: *mut c_char = std::ptr::null_mut();
        // SAFETY: session, base_c, tc live for the call; `errmsg` is a valid out-pointer that, on
        // error, receives a `sqlite3_malloc`'d string we copy + free.
        let rc =
            unsafe { sqlite3session_diff(session.0, base_c.as_ptr(), tc.as_ptr(), &mut errmsg) };
        if rc != SQLITE_OK {
            let msg = if errmsg.is_null() {
                db.errmsg()
            } else {
                let m = unsafe { CStr::from_ptr(errmsg).to_string_lossy().into_owned() };
                unsafe { sqlite3_free(errmsg.cast::<c_void>()) };
                m
            };
            // A diff error (e.g. a table shape sessions cannot handle) is a FALLBACK, not a hard
            // failure — the DB still ships as a full dump.
            return Ok(ChangesetCapture::Fallback(format!(
                "libsql session diff of table {t:?} failed (rc {rc}): {msg} — full-dump fallback"
            )));
        }
    }

    // Extract the accumulated changeset.
    let mut n: c_int = 0;
    let mut buf: *mut c_void = std::ptr::null_mut();
    // SAFETY: session live; `n`/`buf` are valid out-pointers; on OK `buf` is a `sqlite3_malloc`'d
    // block of `n` bytes we copy then free.
    let rc = unsafe { sqlite3session_changeset(session.0, &mut n, &mut buf) };
    if rc != SQLITE_OK {
        if !buf.is_null() {
            unsafe { sqlite3_free(buf) };
        }
        return Err(SqlError::other(format!(
            "libsql changeset: session_changeset failed (rc {rc}): {}",
            db.errmsg()
        )));
    }
    let bytes = if buf.is_null() || n <= 0 {
        Vec::new()
    } else {
        // SAFETY: `buf` points at `n` readable bytes SQLite allocated; copy them out before freeing.
        let slice = unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), n as usize) };
        slice.to_vec()
    };
    if !buf.is_null() {
        unsafe { sqlite3_free(buf) };
    }
    Ok(ChangesetCapture::Changeset(bytes))
}

/// The context passed to the apply callbacks: the set of tables the restored base legitimately owns,
/// and a flag set if the changeset referenced any table OUTSIDE that set (a crafted/foreign change).
struct ApplyCtx {
    allowed: BTreeSet<String>,
    saw_foreign: bool,
}

/// `xFilter`: apply changes ONLY to tables in the restored base's own schema. A foreign table is
/// SKIPPED (return 0 — never written) and flagged, turning the whole apply into a refusal below.
///
/// # Safety
/// `pCtx` is the `*mut ApplyCtx` we pass to `sqlite3changeset_apply`; `zTab` is a NUL-terminated
/// table name owned by SQLite for the duration of the call.
unsafe extern "C" fn apply_filter(pctx: *mut c_void, ztab: *const c_char) -> c_int {
    if pctx.is_null() || ztab.is_null() {
        return 0;
    }
    let ctx = unsafe { &mut *pctx.cast::<ApplyCtx>() };
    let name = unsafe { CStr::from_ptr(ztab) }.to_string_lossy();
    if ctx.allowed.contains(name.as_ref()) {
        1 // in the base schema → apply
    } else {
        ctx.saw_foreign = true;
        0 // foreign table → skip (never written); the post-apply check refuses the whole member
    }
}

/// `xConflict`: refuse EVERY conflict class by returning `ABORT`, so a changeset whose base does not
/// match (a mismatched or crafted base) rolls the apply back rather than forcing a guessed write.
///
/// # Safety
/// Signature dictated by `sqlite3changeset_apply`; the pointers are unused.
unsafe extern "C" fn apply_conflict(
    _pctx: *mut c_void,
    _econflict: c_int,
    _iter: *mut sqlite3_changeset_iter,
) -> c_int {
    SQLITE_CHANGESET_ABORT
}

/// **APPLY** a changeset onto the `target` database FILE, confined to the target's OWN tables. The
/// apply is self-atomic: it runs inside an explicit transaction COMMITTED only when the changeset
/// applied cleanly AND touched no table outside the target's schema; on any conflict (base mismatch)
/// or any foreign table it is ROLLED BACK and a loud [`SqlError`] is returned, leaving `target`
/// byte-for-byte unchanged. An EMPTY changeset is a no-op success.
pub fn apply_changeset_confined(target: &Path, changeset: &[u8]) -> Result<(), SqlError> {
    if changeset.is_empty() {
        return Ok(()); // no row changes to apply
    }
    // `sqlite3changeset_apply` takes the length as a C `int`; a changeset ≥ 2 GiB would truncate
    // (it would fail closed — a negative/short length reads as end-of-input → empty no-op, never
    // an over-read — but refuse explicitly for clarity rather than rely on that).
    if changeset.len() > c_int::MAX as usize {
        return Err(SqlError::other(format!(
            "libsql changeset: {} bytes exceeds the {}-byte apply limit",
            changeset.len(),
            c_int::MAX
        )));
    }
    let db = RawDb::open(target, SQLITE_OPEN_READWRITE)?;
    // Changeset apply is not guaranteed to visit rows in FK-dependency order; the source DB was
    // already FK-consistent and we `integrity_check` the shadow after, so disable FK enforcement for
    // the apply (matches the base `.dump` shadow restore, which also loads with FK off).
    db.exec("PRAGMA foreign_keys=OFF")?;

    let allowed: BTreeSet<String> = db.table_names()?.into_iter().collect();
    let mut ctx = ApplyCtx {
        allowed,
        saw_foreign: false,
    };

    db.exec("BEGIN")?;
    // SAFETY: `db.db` is live; `changeset` is a readable `len`-byte buffer (cast to `*mut c_void`,
    // but the apply only READS it); the callbacks have the required C ABI and run only for the
    // duration of this call with `&mut ctx` as their context (no aliasing — single-threaded here).
    let rc = unsafe {
        sqlite3changeset_apply(
            db.db,
            changeset.len() as c_int,
            changeset.as_ptr() as *mut c_void,
            Some(apply_filter),
            Some(apply_conflict),
            (&mut ctx as *mut ApplyCtx).cast::<c_void>(),
        )
    };
    let apply_err = (rc != SQLITE_OK).then(|| db.errmsg());

    if apply_err.is_some() || ctx.saw_foreign {
        // ROLLBACK leaves the target exactly as it was before this apply.
        let _ = db.exec("ROLLBACK");
        if ctx.saw_foreign {
            return Err(SqlError::other(
                "libsql changeset REFUSED: the member referenced a table outside the restored \
                 base's schema (a foreign/crafted change) — nothing applied",
            ));
        }
        return Err(SqlError::other(format!(
            "libsql changeset apply aborted (rc {rc}): {} — the base does not match the changeset's \
             expected base; refusing a partial/forced apply",
            apply_err.unwrap_or_default()
        )));
    }
    db.exec("COMMIT")?;
    Ok(())
}

/// Run `PRAGMA integrity_check` on the database FILE at `path`, erroring loudly unless it returns the
/// single `ok` row — the post-apply soundness check the restore runs before the atomic swap (the
/// libsql analogue of the `.dump` shadow's `integrity_check`).
pub fn verify_integrity(path: &Path) -> Result<(), SqlError> {
    let db = RawDb::open(path, SQLITE_OPEN_READONLY)?;
    let rows = db.query_text_column("PRAGMA integrity_check")?;
    match rows.first().map(String::as_str) {
        Some("ok") => Ok(()),
        other => Err(SqlError::other(format!(
            "libsql changeset: post-apply integrity_check failed: {}",
            other.unwrap_or("<no row>")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A tiny raw-FFI helper to create + seed a database FILE for the tests (open RW+CREATE, exec a
    /// script). Kept local to the tests so the production surface stays capture/apply only.
    fn make_db(path: &Path, script: &str) {
        let db = RawDb::open(path, SQLITE_OPEN_READWRITE | libsql_ffi::SQLITE_OPEN_CREATE)
            .expect("open create");
        db.exec(script).expect("seed script");
    }

    fn rows(path: &Path, sql: &str) -> Vec<String> {
        let db = RawDb::open(path, SQLITE_OPEN_READONLY).expect("open ro");
        db.query_text_column(sql).expect("query")
    }

    fn tmp() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().join("base.db");
        let cur = d.path().join("cur.db");
        let tgt = d.path().join("tgt.db");
        (d, base, cur, tgt)
    }

    /// Capture an insert/update/delete delta into a changeset, apply it onto a COPY of the base, and
    /// assert the result equals the current DB exactly — the engine's core round-trip.
    #[test]
    fn changeset_round_trip_insert_update_delete() {
        let (_d, base, cur, _t) = tmp();
        make_db(
            &base,
            "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT); \
             INSERT INTO t VALUES (1,'alpha'),(2,'beta'),(3,'gamma');",
        );
        // current = base + {insert 4, update 2→beta2, delete 3}
        make_db(
            &cur,
            "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT); \
             INSERT INTO t VALUES (1,'alpha'),(2,'beta2'),(4,'delta');",
        );
        let cs = match capture_changeset(&base, &cur).expect("capture") {
            ChangesetCapture::Changeset(c) => c,
            ChangesetCapture::Fallback(r) => panic!("unexpected fallback: {r}"),
        };
        assert!(
            !cs.is_empty(),
            "a real insert/update/delete delta is non-empty"
        );

        // Apply onto a fresh copy of the base.
        let shadow = _d.path().join("shadow.db");
        std::fs::copy(&base, &shadow).unwrap();
        apply_changeset_confined(&shadow, &cs).expect("apply");
        assert_eq!(
            rows(&shadow, "SELECT id || ':' || v FROM t ORDER BY id"),
            vec!["1:alpha", "2:beta2", "4:delta"],
            "base + changeset == current (insert 4, update 2, delete 3)"
        );
    }

    /// An unchanged DB produces an EMPTY changeset, and applying it is a no-op.
    #[test]
    fn changeset_empty_when_unchanged() {
        let (_d, base, cur, _t) = tmp();
        let schema =
            "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES (1,'x');";
        make_db(&base, schema);
        make_db(&cur, schema);
        match capture_changeset(&base, &cur).expect("capture") {
            ChangesetCapture::Changeset(c) => {
                assert!(c.is_empty(), "no changes → empty changeset");
                let shadow = _d.path().join("shadow.db");
                std::fs::copy(&base, &shadow).unwrap();
                apply_changeset_confined(&shadow, &c).expect("apply empty no-op");
                assert_eq!(rows(&shadow, "SELECT v FROM t"), vec!["x"]);
            }
            ChangesetCapture::Fallback(r) => panic!("unexpected fallback: {r}"),
        }
    }

    /// A DDL change since the base (a new column) ⇒ FALLBACK (a changeset carries no schema change).
    #[test]
    fn schema_change_falls_back() {
        let (_d, base, cur, _t) = tmp();
        make_db(&base, "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT);");
        make_db(
            &cur,
            "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT, extra INT);",
        );
        assert!(
            matches!(
                capture_changeset(&base, &cur).expect("capture"),
                ChangesetCapture::Fallback(_)
            ),
            "a schema change must fall back to a full dump"
        );
    }

    /// A table with NO primary key ⇒ FALLBACK (sessions cannot diff a rowid-only table).
    #[test]
    fn no_primary_key_falls_back() {
        let (_d, base, cur, _t) = tmp();
        make_db(&base, "CREATE TABLE t(v TEXT);");
        make_db(&cur, "CREATE TABLE t(v TEXT);");
        assert!(
            matches!(
                capture_changeset(&base, &cur).expect("capture"),
                ChangesetCapture::Fallback(_)
            ),
            "a PK-less table must fall back to a full dump"
        );
    }

    /// **Confinement (crafted-escape).** A changeset that writes a table OUTSIDE the target's schema
    /// is REFUSED, and — because the apply is self-atomic — the legit change bundled with it is
    /// rolled back too, so the target is byte-unchanged. Mutation-sensitive: without the filter's
    /// `saw_foreign` refusal (or the abort-on-conflict), the legit change would leak through.
    #[test]
    fn crafted_foreign_table_change_refused_atomically() {
        let (_d, base, _cur, _t) = tmp();
        // Target base: ONE table `t`.
        make_db(
            &base,
            "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES (1,'orig');",
        );
        // Craft a changeset (through the REAL engine) that touches BOTH `t` (legit-looking: update 1)
        // AND a foreign table `evil` the target does not have. Build it by diffing an evil-current
        // against an empty evil-base that both carry the two tables.
        let evil_base = _d.path().join("evil_base.db");
        let evil_cur = _d.path().join("evil_cur.db");
        make_db(
            &evil_base,
            "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES (1,'orig'); \
             CREATE TABLE evil(id INTEGER PRIMARY KEY, secret TEXT);",
        );
        make_db(
            &evil_cur,
            "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES (1,'HACKED'); \
             CREATE TABLE evil(id INTEGER PRIMARY KEY, secret TEXT); \
             INSERT INTO evil VALUES (1,'ESCAPED');",
        );
        let crafted = match capture_changeset(&evil_base, &evil_cur).expect("capture crafted") {
            ChangesetCapture::Changeset(c) => c,
            ChangesetCapture::Fallback(r) => panic!("crafted capture fell back: {r}"),
        };
        assert!(!crafted.is_empty());

        // Apply the crafted changeset onto the target (which has ONLY `t`, NOT `evil`).
        let shadow = _d.path().join("shadow.db");
        std::fs::copy(&base, &shadow).unwrap();
        let err = apply_changeset_confined(&shadow, &crafted)
            .expect_err("a foreign-table changeset MUST be refused");
        assert!(
            format!("{err}").contains("outside the restored base"),
            "the refusal names the foreign-table confinement; got: {err}"
        );
        // ATOMIC: the legit-looking `t` update is rolled back too — `t` still holds the ORIGINAL row.
        assert_eq!(
            rows(&shadow, "SELECT v FROM t WHERE id=1"),
            vec!["orig"],
            "the refused crafted apply left the target unchanged (no partial write)"
        );
        // And the foreign `evil` table was never created in the target.
        assert!(
            rows(&shadow, "SELECT name FROM sqlite_master WHERE name='evil'").is_empty(),
            "the crafted `evil` table must not exist in the target"
        );
    }

    /// A mismatched base (the changeset's expected base rows differ from the target's) conflicts →
    /// abort-on-conflict → refused, target unchanged.
    #[test]
    fn mismatched_base_conflict_refused() {
        let (_d, base, cur, _t) = tmp();
        make_db(
            &base,
            "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES (1,'alpha');",
        );
        make_db(
            &cur,
            "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES (1,'beta');",
        );
        let cs = match capture_changeset(&base, &cur).expect("capture") {
            ChangesetCapture::Changeset(c) => c,
            ChangesetCapture::Fallback(r) => panic!("fallback: {r}"),
        };
        // Apply onto a DIFFERENT base (row 1 is 'WRONG', not 'alpha') → UPDATE conflict → abort.
        let shadow = _d.path().join("shadow.db");
        make_db(
            &shadow,
            "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES (1,'WRONG');",
        );
        assert!(
            apply_changeset_confined(&shadow, &cs).is_err(),
            "a mismatched base must abort the apply (no forced write)"
        );
        assert_eq!(
            rows(&shadow, "SELECT v FROM t WHERE id=1"),
            vec!["WRONG"],
            "the aborted apply left the target unchanged"
        );
    }
}
