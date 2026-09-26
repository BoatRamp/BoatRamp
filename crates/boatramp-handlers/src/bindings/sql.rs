//! The `sql` host binding: a small wasi:sql-shaped interface backed by a
//! [`SqlBackend`] (libsql — a file or sqld namespace; see [`boatramp_core::sql`]).
//! The binding is engine-agnostic: it only ever talks to the trait, so no SQL
//! engine is linked into `boatramp-handlers`.
//!
//! ## Named databases
//!
//! A site may be granted several **named** databases (`Bindings::with_sql`),
//! each mapped by the operator to a backend — possibly different engines (a
//! local `cache`, a shared `main`). The guest `open`s one by name (the empty
//! name is the default); each opened database gets its own per-invocation
//! transaction.
//!
//! ## One transaction per invocation (per database)
//!
//! A database's transaction is begun lazily on its first statement; the engine
//! [`finalize`](SqlSession::finalize)s every open transaction once the guest is
//! done — commit on a successful response, rollback on trap/error. A database
//! that is never touched opens no transaction. The transactions are independent
//! (no cross-database atomicity), and there is no cross-invocation lock —
//! concurrency is each backend's concern.

use std::collections::HashMap;
use std::sync::Arc;

use boatramp_core::sql::{
    SqlBackend, SqlError, SqlTransaction, SqlValue, reject_reserved_session_writes,
};
use wasmtime::component::{Resource, ResourceTable};

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/sql-host",
        async: {
            only_imports: ["[method]database.query", "[method]database.execute"],
        },
        with: {
            "boatramp:handlers/sql-query/database": super::SqlDatabase,
        },
    });
}

use generated::boatramp::handlers::{sql_query, sql_types};

/// A handle to one named database; the transaction itself lives in the session,
/// keyed by `(name, read_only)` (so two handles with the same name and mode
/// share one transaction, while a read-only handle gets its own — possibly
/// replica-routed — transaction).
pub struct SqlDatabase {
    name: String,
    /// Opened via `open-read-only`: its transaction is begun read-only (the
    /// backend may route it to a read replica).
    read_only: bool,
}

/// The per-invocation SQL state: the granted name→backend map, and the open
/// transactions (one per `(database, read-only?)`, begun lazily).
pub struct SqlSession {
    backends: HashMap<String, Arc<dyn SqlBackend>>,
    txns: HashMap<(String, bool), Box<dyn SqlTransaction>>,
    /// The host-resolved in-site tenancy applied to **both** this `sql` binding and the sibling
    /// `orm` binding (they share the session). `None` ⇒ plain queries (no row scoping).
    tenancy: Option<crate::tenant::HostTenancy>,
    /// Transaction keys `(name, read_only)` whose tenant GUC currently holds the v0.4.21 `all`-read
    /// marker. Load-bearing for the no-write-under-marker invariant: before any WRITE on a
    /// `(name,false)` transaction, [`defend_write_marker`](Self::defend_write_marker) force-resets
    /// the GUC off the marker (error-propagating) — so a marker set by a prior `all` read can NEVER
    /// be in effect for a write, independent of backend transaction-abort semantics.
    marker_live: std::collections::HashSet<(String, bool)>,
}

impl SqlSession {
    /// A session granting the given named backends (empty = no SQL granted).
    pub fn for_backends(backends: HashMap<String, Arc<dyn SqlBackend>>) -> Self {
        Self {
            backends,
            txns: HashMap::new(),
            tenancy: None,
            marker_live: std::collections::HashSet::new(),
        }
    }

    /// Set the host-resolved tenancy for this invocation (see [`crate::tenant::HostTenancy`]).
    #[must_use]
    pub fn with_tenancy(mut self, tenancy: Option<crate::tenant::HostTenancy>) -> Self {
        self.tenancy = tenancy;
        self
    }

    /// The host-resolved tenancy, if any. `pub(super)` so the sibling `orm` binding (sharing this
    /// session) forces the same scope.
    pub(super) fn tenancy(&self) -> Option<&crate::tenant::HostTenancy> {
        self.tenancy.as_ref()
    }

    /// Whether a database is granted under `name`. `pub(super)` so the sibling `orm`
    /// binding (which shares this session) can perform the same grant check.
    pub(super) fn granted(&self, name: &str) -> bool {
        self.backends.contains_key(name)
    }

    /// Whether the backend named `name` injects the reserved boatramp session context
    /// (`rls_session`). When it does, a guest statement that would set/reset the
    /// reserved `boatramp.*` / `@boatramp_*` keys must be refused (H1) — otherwise a
    /// guest could spoof its injected tenant and defeat the app's RLS. `pub(super)` so
    /// the sibling `orm` binding can guard the same way.
    pub(super) fn injects_session_context(&self, name: &str) -> bool {
        self.backends
            .get(name)
            .is_some_and(|b| b.injects_session_context())
    }

    /// The SQL dialect of the backend named `name` (SQLite-family if not granted — an
    /// ungranted name is caught by the grant check before this matters). `pub(super)` so the
    /// `orm` binding can compile dialect-correct SQL for the target engine.
    pub(super) fn dialect(&self, name: &str) -> boatramp_core::sql::Dialect {
        self.backends
            .get(name)
            .map(|b| b.dialect())
            .unwrap_or_default()
    }

    /// The operator RLS session-GUC names for `name`'s backend, **iff** configured AND the backend
    /// is Postgres (the only dialect with the `current_setting(...)` RLS backstop). `None` otherwise.
    /// (v0.4.20 — the host-set tenant GUC that mirrors the injected predicate.)
    pub(super) fn rls_guc(&self, name: &str) -> Option<boatramp_core::sql::RlsGuc> {
        let b = self.backends.get(name)?;
        if b.dialect() != boatramp_core::sql::Dialect::Postgres {
            return None;
        }
        b.rls_guc().cloned()
    }

    /// The reserved GUC namespaces a guest must not set for `name`'s backend — the leading segment
    /// of each configured RLS GUC (e.g. `app` for `app.tenant_id`), so a guest can't forge the
    /// backstop. Empty when the backend has no RLS GUC. Fed to `reject_reserved_session_writes`.
    pub(super) fn reserved_guc_namespaces(&self, name: &str) -> Vec<String> {
        self.rls_guc(name)
            .map(|g| {
                g.reserved_names()
                    .iter()
                    .filter_map(|n| n.split('.').next().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The per-**transaction** RLS GUC set statements (own/target/session): the host-resolved
    /// principal value bound to the operator's configured GUC name(s). Empty for an `all` write (no
    /// resolved principal — the value is set per statement from the row) or when no RLS GUC / not
    /// Postgres. Computed from `&self` so it can be emitted on a freshly-begun tx without a borrow
    /// clash. Each entry is `(sql, params)` for one `SELECT set_config(?, ?, true)`.
    fn rls_tx_sets(&self, name: &str) -> Vec<(String, Vec<SqlValue>)> {
        let (Some(guc), Some(tenancy)) = (self.rls_guc(name), self.tenancy.as_ref()) else {
            return Vec::new();
        };
        let mut sets = Vec::new();
        if let Some(tv) = tenancy.rls_tenant_value() {
            sets.push(boatramp_core::sql::render_set_local_guc(&guc.tenant, tv));
        }
        if let (Some(sname), Some(sv)) = (&guc.session, tenancy.rls_session_value()) {
            sets.push(boatramp_core::sql::render_set_local_guc(sname, sv));
        }
        sets
    }

    /// Set the RLS tenant GUC on the (write) transaction for `name` to an EXPLICIT value — the path
    /// for an `all` write, where the value is the tenant the row/statement declares (not a resolved
    /// principal). `SET LOCAL`-scoped, so it holds for the immediately-following write and is
    /// re-set before each `all` write in the batch. No-op when the backend has no RLS GUC (or isn't
    /// Postgres). `pub(super)` for the sibling `orm` binding + the raw `sql` path.
    pub(super) async fn set_rls_tenant(
        &mut self,
        name: &str,
        value: &SqlValue,
    ) -> Result<(), SqlError> {
        // A write always uses the read-write transaction (`read_only = false`).
        self.set_rls_tenant_on(name, false, value).await
    }

    /// Set the tenant GUC on the `(name, read_only)` transaction — the general form of
    /// [`set_rls_tenant`](Self::set_rls_tenant) so the `all`-read marker can be written to the same
    /// transaction the read runs on (which may be a read-only one). No-op without an RLS GUC.
    async fn set_rls_tenant_on(
        &mut self,
        name: &str,
        read_only: bool,
        value: &SqlValue,
    ) -> Result<(), SqlError> {
        if let Some(guc) = self.rls_guc(name) {
            let (sql, params) = boatramp_core::sql::render_set_local_guc(&guc.tenant, value);
            let tx = self.txn(name, read_only).await?;
            tx.execute(&sql, &params).await?;
        }
        Ok(())
    }

    /// v0.4.21 all-read backstop: for an `all`-scoped **READ** against a Postgres RLS binding with a
    /// configured all-marker, write the marker to the tenant GUC on the transaction the read will use
    /// (`read_only`), so a table that opts in with `USING (… OR current_setting(name,true) = marker)`
    /// opens cross-tenant. The marker stays set on that transaction (every read of an `all` component
    /// wants it) until either the invocation finalizes (the `SET LOCAL` GUC is discarded at COMMIT/
    /// ROLLBACK) or a WRITE on the `(name,false)` transaction force-resets it via
    /// [`defend_write_marker`](Self::defend_write_marker) — so it can NEVER be in effect for a write
    /// (where an active marker in a `WITH CHECK (… OR guc = marker)` would be always-true → a
    /// cross-tenant write leak). No-op for a write axis, a non-`all` read, or no marker. Marking a
    /// write transaction (`read_only == false`) records the key so a subsequent write defends first.
    /// `pub(super)` for the sibling `orm` binding.
    pub(super) async fn set_all_read_marker(
        &mut self,
        name: &str,
        read_only: bool,
        axis: crate::tenant::Axis,
    ) -> Result<(), SqlError> {
        if !matches!(axis, crate::tenant::Axis::Read) {
            return Ok(());
        }
        let Some(marker) = self.rls_guc(name).and_then(|g| g.all_marker) else {
            return Ok(());
        };
        if !self
            .tenancy
            .as_ref()
            .is_some_and(crate::tenant::HostTenancy::read_is_all)
        {
            return Ok(());
        }
        self.set_rls_tenant_on(name, read_only, &SqlValue::Text(marker))
            .await?;
        self.marker_live.insert((name.to_string(), read_only));
        Ok(())
    }

    /// Before a WRITE on the `(name,false)` transaction: if a prior `all` read left the all-marker on
    /// it (tracked in `marker_live`), force-reset the tenant GUC off the marker — to the resolved
    /// principal, or an empty string (⇒ the DB's `WITH CHECK`/`USING` denies) — and drop the flag.
    /// This is the load-bearing half of the no-write-under-marker invariant: it runs before every
    /// write path (both bindings) and PROPAGATES its error (an aborted transaction ⇒ the write fails
    /// closed), so the guarantee never depends on best-effort cleanup or backend abort semantics.
    /// No-op when no marker is live on the write transaction. Only the read-write key `(name,false)`
    /// is defended: a write only ever runs there. A write-axis statement issued on a read-only handle
    /// runs on `(name,true)`, whose transaction is opened `BEGIN READ ONLY` — the DB rejects the write
    /// (SQLSTATE 25006) before RLS `WITH CHECK` is evaluated, so a marker lingering on a read-only
    /// transaction can never open a write. That is a deliberate reliance on the backend's read-only
    /// enforcement (the same enforcement that makes a read-only handle read-only at all).
    pub(super) async fn defend_write_marker(&mut self, name: &str) -> Result<(), SqlError> {
        let key = (name.to_string(), false);
        if !self.marker_live.contains(&key) {
            return Ok(());
        }
        let restore = self
            .tenancy
            .as_ref()
            .and_then(|t| t.rls_tenant_value().cloned())
            .unwrap_or_else(|| SqlValue::Text(String::new()));
        self.set_rls_tenant_on(name, false, &restore).await?;
        self.marker_live.remove(&key);
        Ok(())
    }

    /// v0.4.20 RLS backstop for a **raw** `all` WRITE: if `name`'s backend has an RLS GUC, the axis
    /// is a write, and the invocation's write mode is `all`, parse the (scope-marked) `statement`
    /// for the single tenant it declares (INSERT VALUES / UPDATE WHERE) and set the tenant GUC to it
    /// so the DB's `WITH CHECK`/`USING` passes for that tenant and rejects a mismatch. Unextractable
    /// (multi-tenant / opaque) ⇒ GUC left unset ⇒ the DB denies (fail-closed). No-op otherwise.
    /// `pub(super)` for the sibling `orm` binding, which computes the value from the typed AST.
    pub(super) async fn apply_all_write_rls(
        &mut self,
        name: &str,
        statement: &str,
        axis: crate::tenant::Axis,
    ) -> Result<(), SqlError> {
        if !matches!(axis, crate::tenant::Axis::Write) || self.rls_guc(name).is_none() {
            return Ok(());
        }
        // v0.4.21: this is a write — first force any `all`-read marker off the write transaction, so
        // the marker can never be in effect for the `WITH CHECK` below (error-propagating).
        self.defend_write_marker(name).await?;
        let dialect = self.dialect(name);
        let val = self
            .tenancy
            .as_ref()
            .filter(|t| t.write_is_all())
            .and_then(|t| {
                boatramp_core::target_sql::extract_raw_write_scope_value(
                    statement,
                    dialect,
                    |tbl| t.tenant_column_for(tbl),
                )
            });
        if let Some(val) = val {
            self.set_rls_tenant(name, &val).await?;
        }
        Ok(())
    }

    /// The open transaction for `(name, read_only)`, beginning one on first use.
    /// A read-only transaction is begun via [`SqlBackend::begin_read_only`], so a
    /// replica-configured backend can route it to the replica. Returns the **core**
    /// [`SqlError`] (not a WIT error) so both the `sql` and `orm` bindings — which share
    /// one session — can wrap it into their own generated `error` variant. `pub(super)`
    /// for the same sharing reason.
    pub(super) async fn txn(
        &mut self,
        name: &str,
        read_only: bool,
    ) -> Result<&mut dyn SqlTransaction, SqlError> {
        let key = (name.to_string(), read_only);
        if !self.txns.contains_key(&key) {
            let backend = self
                .backends
                .get(name)
                .ok_or_else(|| SqlError::Other(format!("sql database {name:?} not granted")))?
                .clone();
            let mut txn = if read_only {
                backend.begin_read_only().await
            } else {
                backend.begin().await
            }?;
            // v0.4.20: set the per-transaction RLS tenant GUC (own/target/session) right after the
            // tx opens — right after the backend's own `boatramp.project`/`site` context — so an
            // app's Postgres RLS mirrors the injected predicate. `all` writes add nothing here (no
            // resolved principal); they set the GUC per statement from the row. `SET LOCAL`, bound.
            for (sql, params) in self.rls_tx_sets(name) {
                txn.execute(&sql, &params).await?;
            }
            self.txns.insert(key.clone(), txn);
        }
        Ok(self.txns.get_mut(&key).expect("inserted above").as_mut())
    }

    /// Close every open transaction: `commit` if `commit`, else `rollback`.
    /// Independent per database; a no-op for databases that were never used.
    pub async fn finalize(&mut self, commit: bool) {
        for (_name, txn) in std::mem::take(&mut self.txns) {
            let _ = if commit {
                txn.commit().await
            } else {
                txn.rollback().await
            };
        }
    }
}

/// Per-invocation view: the resource table (holding `database` handles) plus the
/// session (backends + open transactions).
pub struct SqlHost<'a> {
    table: &'a mut ResourceTable,
    session: &'a mut SqlSession,
}

impl<'a> SqlHost<'a> {
    /// Build a view over `table` and `session`.
    pub fn new(table: &'a mut ResourceTable, session: &'a mut SqlSession) -> Self {
        Self { table, session }
    }
}

impl sql_query::Host for SqlHost<'_> {
    fn open(&mut self, name: String) -> Result<Resource<SqlDatabase>, sql_types::Error> {
        self.open_handle(name, false)
    }

    fn open_read_only(&mut self, name: String) -> Result<Resource<SqlDatabase>, sql_types::Error> {
        self.open_handle(name, true)
    }
}

impl SqlHost<'_> {
    /// Push a database handle (read-write or read-only) after the grant check.
    fn open_handle(
        &mut self,
        name: String,
        read_only: bool,
    ) -> Result<Resource<SqlDatabase>, sql_types::Error> {
        if !self.session.granted(&name) {
            return Err(not_granted(&name));
        }
        self.table
            .push(SqlDatabase { name, read_only })
            .map_err(|e| sql_types::Error::Other(e.to_string()))
    }
}

impl sql_query::HostDatabase for SqlHost<'_> {
    async fn query(
        &mut self,
        db: Resource<SqlDatabase>,
        statement: String,
        params: Vec<sql_types::Value>,
    ) -> Result<sql_types::QueryResult, sql_types::Error> {
        let handle = self
            .table
            .get(&db)
            .map_err(|e| sql_types::Error::Other(e.to_string()))?;
        let (name, read_only) = (handle.name.clone(), handle.read_only);
        // H1: if this database injects the reserved boatramp session context
        // (rls_session), the guest must not overwrite those keys and spoof its tenant — boatramp's
        // own namespace AND the operator's configured RLS GUC namespace (v0.4.20).
        if self.session.injects_session_context(&name) {
            reject_reserved_session_writes(
                &statement,
                &self.session.reserved_guc_namespaces(&name),
            )
            .map_err(to_wit_error)?;
        }
        let mut params = to_values(params);
        // Stage 0: fill the `{scope}` marker with the host predicate for the axis the STATEMENT
        // exercises (a `DELETE` via `query()` is a write, not a read). Fail-closed: an unmarked
        // scoped statement, or one the axis grant denies, is refused before the backend. Under a
        // target read the whole statement is AST-rewritten instead (dialect selects the parser).
        let axis = stmt_axis(&statement);
        let statement = apply_scope_marker(
            self.session.tenancy(),
            axis,
            statement,
            &mut params,
            self.session.dialect(&name),
        )
        .map_err(to_wit_error)?;
        // v0.4.20: an `all` WRITE reached via `query()` (e.g. `… RETURNING`) sets its tenant GUC
        // from the statement too (raw-write backstop), same as `execute()`.
        self.session
            .apply_all_write_rls(&name, &statement, axis)
            .await
            .map_err(to_wit_error)?;
        // v0.4.21: for an `all` READ, set the reserved all-marker on the read's transaction so it
        // opens the operator's `USING (… OR guc = marker)` cross-tenant. It is force-reset off any
        // write transaction by `defend_write_marker` before a write runs, so it can never defeat a
        // `WITH CHECK`. No-op for a non-`all` read / write axis / no marker.
        self.session
            .set_all_read_marker(&name, read_only, axis)
            .await
            .map_err(to_wit_error)?;
        let txn = self
            .session
            .txn(&name, read_only)
            .await
            .map_err(to_wit_error)?;
        let rows = txn.query(&statement, &params).await.map_err(to_wit_error)?;
        Ok(sql_types::QueryResult {
            columns: rows.columns,
            rows: rows
                .rows
                .into_iter()
                .map(|row| sql_types::Row {
                    values: row.into_iter().map(to_wit_value).collect(),
                })
                .collect(),
        })
    }

    async fn execute(
        &mut self,
        db: Resource<SqlDatabase>,
        statement: String,
        params: Vec<sql_types::Value>,
    ) -> Result<u64, sql_types::Error> {
        let handle = self
            .table
            .get(&db)
            .map_err(|e| sql_types::Error::Other(e.to_string()))?;
        let (name, read_only) = (handle.name.clone(), handle.read_only);
        // H1: see `query` — refuse guest overwrites of the reserved session keys (boatramp's own +
        // the operator's configured RLS GUC namespaces, so a guest can't forge the tenant backstop).
        if self.session.injects_session_context(&name) {
            reject_reserved_session_writes(
                &statement,
                &self.session.reserved_guc_namespaces(&name),
            )
            .map_err(to_wit_error)?;
        }
        let mut params = to_values(params);
        let axis = stmt_axis(&statement);
        // Stage 0: fill the `{scope}` marker with the host predicate for the axis the STATEMENT
        // exercises (a bare `SELECT` via `execute()` is still a read). Fail-closed on a missing
        // marker or a denied axis. Under a target read the whole statement is AST-rewritten instead.
        let statement = apply_scope_marker(
            self.session.tenancy(),
            axis,
            statement,
            &mut params,
            self.session.dialect(&name),
        )
        .map_err(to_wit_error)?;
        // v0.4.20 RLS backstop: for an `all` WRITE against a Postgres RLS binding, set the tenant
        // GUC to the tenant the statement itself declares (parsed from the INSERT VALUES / UPDATE
        // WHERE) so the app's `WITH CHECK`/`USING` passes for exactly that tenant and rejects a
        // mismatch. Unextractable ⇒ GUC unset ⇒ the DB denies (fail-closed).
        self.session
            .apply_all_write_rls(&name, &statement, axis)
            .await
            .map_err(to_wit_error)?;
        // v0.4.21: a read-axis statement reached via `execute()` gets the same all-marker treatment
        // (no-op unless it is an `all` read with a configured marker). The marker is force-reset off
        // the write transaction by `defend_write_marker` (via `apply_all_write_rls`) before any write.
        self.session
            .set_all_read_marker(&name, read_only, axis)
            .await
            .map_err(to_wit_error)?;
        let txn = self
            .session
            .txn(&name, read_only)
            .await
            .map_err(to_wit_error)?;
        txn.execute(&statement, &params).await.map_err(to_wit_error)
    }

    fn drop(&mut self, db: Resource<SqlDatabase>) -> wasmtime::Result<()> {
        // Dropping a handle does not end the transaction — it stays open until
        // the engine finalizes the invocation (commit/rollback).
        self.table.delete(db)?;
        Ok(())
    }
}

fn not_granted(name: &str) -> sql_types::Error {
    sql_types::Error::Other(format!("sql database {name:?} not granted"))
}

/// The tenancy axis a raw statement exercises. A statement whose first keyword is `SELECT` reads
/// (the read grant); **everything else** — `INSERT`/`UPDATE`/`DELETE`, DDL, or a `WITH …` CTE that
/// may end in a write — takes the **write** grant (fail-closed). This is deliberately driven by
/// the statement, not by which method the guest called: `query()` can run DML on a read-write
/// handle, so keying the axis off `query`-vs-`execute` would let a `DELETE` slip through under the
/// weaker read grant. A leading `WITH` is treated as a write (a read CTE must carry the write
/// grant, or use the typed `orm` surface).
fn stmt_axis(statement: &str) -> crate::tenant::Axis {
    let mut s = statement.trim_start();
    // Skip leading `-- line` and `/* block */` comments before the first keyword.
    loop {
        if let Some(rest) = s.strip_prefix("--") {
            s = rest.find('\n').map_or("", |i| &rest[i + 1..]).trim_start();
        } else if let Some(rest) = s.strip_prefix("/*") {
            s = rest.find("*/").map_or("", |i| &rest[i + 2..]).trim_start();
        } else {
            break;
        }
    }
    let word = &s[..s
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(s.len())];
    if word.eq_ignore_ascii_case("select") {
        crate::tenant::Axis::Read
    } else {
        crate::tenant::Axis::Write
    }
}

/// Fill the raw-SQL `{scope}` marker for a scoped-tenancy invocation (Stage 0). Returns the
/// statement to run, appending the tenant value to `params` when the mode binds one.
///
/// - **No tenancy** (plain): a stray marker is neutralised to `1 = 1` (a scoped app never lands
///   here; this only guards against an accidental marker on an unscoped function).
/// - **Target read** (R4/D8): the guest-cooperative marker cannot confine another tenant's data
///   across joins/subqueries, so the WHOLE statement is instead rewritten AST-side — every table
///   reference is confined to `tenant = B AND <public subset>` and the statement is required to be
///   read-only (fail-closed). The guest writes plain SQL; a stray marker is neutralised first so a
///   copy-pasted `{scope}` still parses. `dialect` selects the parser for the backend engine.
/// - **Scoped (own/session)**: the axis grant is consulted first (a `none` grant is refused
///   outright), then the marker is **required** — an unmarked scoped statement is refused
///   (fail-closed) rather than run across tenants — and substituted with the host predicate. The
///   predicate references the appended value as `?<N+1>`, so it is correct wherever the marker sits;
///   the value is appended once even if the marker repeats.
fn apply_scope_marker(
    tenancy: Option<&crate::tenant::HostTenancy>,
    axis: crate::tenant::Axis,
    statement: String,
    params: &mut Vec<SqlValue>,
    dialect: boatramp_core::sql::Dialect,
) -> Result<String, SqlError> {
    use crate::tenant::SCOPE_MARKER;
    let Some(ht) = tenancy else {
        // Unscoped: neutralise any stray marker so the statement still parses.
        return Ok(statement.replace(SCOPE_MARKER, "1 = 1"));
    };
    if ht.is_target() {
        // Target read: the marker is not used — the host AST-rewrites the whole statement, confining
        // EVERY table reference (root/join/subquery/CTE/set-op) to `tenant = B AND <public>`. The
        // rewriter itself enforces read-only, so a target write is refused there (belt-and-suspenders
        // with the write-axis grant, which is `None` under a target principal). Neutralise a stray
        // marker first so a copy-pasted `{scope}` does not break the parse. B + public literals are
        // injected by the rewriter, so `params` is left untouched.
        let neutralised = statement.replace(SCOPE_MARKER, "1 = 1");
        return ht
            .rewrite_target_read(&neutralised, dialect)
            .map_err(|e| SqlError::Other(e.reason()));
    }
    // #503 SECURITY: the raw-SQL path has NO write-global exemption. Global writes are ORM-only.
    // The ORM binding is injection-immune (the guest names the table as a typed value, never lexed)
    // and already scopes `INSERT … SELECT` sources; the raw-SQL surface offers no equivalent, so a
    // schema-blind marker rule below is the safe posture. A raw-SQL write to a global table is
    // therefore either marker-scoped (the injected `tenant = ?` predicate binds whatever table the
    // ENGINE actually executes — so even a version-comment-redirected write like
    // `UPDATE /*!50000 x */ y` is scoped to the guest's own tenant, and an `INSERT … SELECT` source
    // stays scoped) or, if the guest omits `{scope}`, refused (marker-required). Do NOT try to detect
    // global tables here: MySQL/MariaDB `/*! … */` / `/*M! … */` version-comments are executed by the
    // engine but ignored by a vanilla parser, so any parse-based "is this a global write?" check is an
    // unsound cross-tenant-write bypass (CVE-class). Cross-surface safety is satisfied by REFUSAL —
    // raw SQL offers no weaker path than the ORM — not by replicating that unsound parse.
    let (pred, values) = ht
        .sql_marker(axis, params.len())
        .map_err(|d| SqlError::Other(d.reason().to_string()))?;
    if ht.requires_marker(axis) && !statement.contains(SCOPE_MARKER) {
        return Err(SqlError::Other(format!(
            "tenancy: a scoped raw-SQL statement must contain the {SCOPE_MARKER} marker \
             (the host injects the tenant predicate there); none found"
        )));
    }
    // Append the marker's bound values in placeholder order (the tenant `B`, then a target read's
    // public-subset literals). The marker references them as `?<len+1..>`, so they are correct
    // wherever the marker sits; appended once even if the marker repeats (the predicate is stable).
    params.extend(values);
    Ok(statement.replace(SCOPE_MARKER, &pred))
}

/// Map guest parameter values to backend values (libsql, SQLite-family, binds a
/// `Boolean` as `0`/`1`).
fn to_values(values: Vec<sql_types::Value>) -> Vec<SqlValue> {
    values
        .into_iter()
        .map(|value| match value {
            sql_types::Value::Null => SqlValue::Null,
            sql_types::Value::Boolean(b) => SqlValue::Boolean(b),
            sql_types::Value::Integer(i) => SqlValue::Integer(i),
            sql_types::Value::Float(f) => SqlValue::Real(f),
            sql_types::Value::Text(s) => SqlValue::Text(s),
            sql_types::Value::Blob(b) => SqlValue::Blob(b),
            sql_types::Value::Json(s) => SqlValue::Json(s),
        })
        .collect()
}

/// Map a backend cell back to a guest value.
fn to_wit_value(value: SqlValue) -> sql_types::Value {
    match value {
        SqlValue::Null => sql_types::Value::Null,
        SqlValue::Boolean(b) => sql_types::Value::Boolean(b),
        SqlValue::Integer(i) => sql_types::Value::Integer(i),
        SqlValue::Real(f) => sql_types::Value::Float(f),
        SqlValue::Text(s) => sql_types::Value::Text(s),
        SqlValue::Blob(b) => sql_types::Value::Blob(b),
        SqlValue::Json(s) => sql_types::Value::Json(s),
    }
}

/// Map a backend error to the guest `error` variant.
fn to_wit_error(err: SqlError) -> sql_types::Error {
    match err {
        SqlError::Syntax(m) => sql_types::Error::Syntax(m),
        SqlError::Constraint(m) => sql_types::Error::Constraint(m),
        // No dedicated guest `unavailable` variant yet (deferred WS1-1b, needs a shim rev); map to
        // `other` keeping the "not ready" message. The host gates a managed not-ready DB with a
        // retryable 503 before the guest runs, so this is the rare mid-request fallback.
        SqlError::Other(m) | SqlError::Unavailable(m) => sql_types::Error::Other(m),
    }
}

/// Add the `sql` interface to `linker`, resolving the per-invocation [`SqlHost`]
/// view via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> SqlHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    sql_query::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::sql_query::{Host, HostDatabase};
    use super::*;
    use async_trait::async_trait;
    use boatramp_core::sql::SqlRows;
    use std::sync::Mutex;

    /// Shared call log for the fake backend.
    type Log = Arc<Mutex<Vec<String>>>;

    /// A backend that records what the binding asked of it (tagged with `label`
    /// so multi-database tests can tell which database got which call) and
    /// replays a canned query result.
    struct FakeBackend {
        label: &'static str,
        log: Log,
    }

    struct FakeTxn {
        label: &'static str,
        log: Log,
    }

    #[async_trait]
    impl SqlBackend for FakeBackend {
        async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            self.log
                .lock()
                .unwrap()
                .push(format!("{}:begin", self.label));
            Ok(Box::new(FakeTxn {
                label: self.label,
                log: self.log.clone(),
            }))
        }

        async fn begin_read_only(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            self.log
                .lock()
                .unwrap()
                .push(format!("{}:begin_read_only", self.label));
            Ok(Box::new(FakeTxn {
                label: self.label,
                log: self.log.clone(),
            }))
        }
    }

    #[async_trait]
    impl SqlTransaction for FakeTxn {
        async fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<SqlRows, SqlError> {
            self.log
                .lock()
                .unwrap()
                .push(format!("{}:query {sql} {params:?}", self.label));
            Ok(SqlRows {
                columns: vec!["n".into()],
                rows: vec![vec![SqlValue::Integer(42)]],
            })
        }
        async fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
            self.log
                .lock()
                .unwrap()
                .push(format!("{}:execute {sql} {params:?}", self.label));
            Ok(1)
        }
        async fn commit(self: Box<Self>) -> Result<(), SqlError> {
            self.log
                .lock()
                .unwrap()
                .push(format!("{}:commit", self.label));
            Ok(())
        }
        async fn rollback(self: Box<Self>) -> Result<(), SqlError> {
            self.log
                .lock()
                .unwrap()
                .push(format!("{}:rollback", self.label));
            Ok(())
        }
    }

    fn session(backends: &[(&str, &'static str, Log)]) -> SqlSession {
        let map = backends
            .iter()
            .map(|(name, label, log)| {
                let backend: Arc<dyn SqlBackend> = Arc::new(FakeBackend {
                    label,
                    log: log.clone(),
                });
                (name.to_string(), backend)
            })
            .collect();
        SqlSession::for_backends(map)
    }

    #[tokio::test]
    async fn open_default_database_maps_and_commits() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut session = session(&[("", "db", log.clone())]);
        let mut table = ResourceTable::new();
        {
            let mut host = SqlHost::new(&mut table, &mut session);
            let db = host.open(String::new()).unwrap();
            let rep = db.rep();
            let n = host
                .execute(
                    db,
                    "INSERT INTO t VALUES ($1, $2)".into(),
                    vec![
                        sql_types::Value::Integer(7),
                        sql_types::Value::Boolean(true),
                    ],
                )
                .await
                .unwrap();
            assert_eq!(n, 1);
            let result = host
                .query(Resource::new_own(rep), "SELECT n FROM t".into(), vec![])
                .await
                .unwrap();
            assert!(matches!(
                result.rows[0].values[0],
                sql_types::Value::Integer(42)
            ));
        }
        session.finalize(true).await;

        let log = log.lock().unwrap();
        assert_eq!(log[0], "db:begin");
        assert!(log[1].contains("Integer(7)") && log[1].contains("Boolean(true)"));
        assert_eq!(log.last().unwrap(), "db:commit");
    }

    #[tokio::test]
    async fn two_named_databases_are_independent() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut session = session(&[
            ("main", "main", log.clone()),
            ("cache", "cache", log.clone()),
        ]);
        let mut table = ResourceTable::new();
        {
            let mut host = SqlHost::new(&mut table, &mut session);
            let main = host.open("main".into()).unwrap();
            let cache = host.open("cache".into()).unwrap();
            host.execute(main, "INSERT INTO m VALUES (1)".into(), vec![])
                .await
                .unwrap();
            host.execute(cache, "INSERT INTO c VALUES (2)".into(), vec![])
                .await
                .unwrap();
        }
        session.finalize(true).await;

        let log = log.lock().unwrap();
        // Each database opened its own transaction and committed independently.
        assert!(log.iter().any(|l| l == "main:begin"));
        assert!(log.iter().any(|l| l == "cache:begin"));
        assert!(log.iter().any(|l| l == "main:commit"));
        assert!(log.iter().any(|l| l == "cache:commit"));
        assert!(
            log.iter()
                .any(|l| l.starts_with("main:execute INSERT INTO m"))
        );
        assert!(
            log.iter()
                .any(|l| l.starts_with("cache:execute INSERT INTO c"))
        );
    }

    #[tokio::test]
    async fn rollback_path() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut session = session(&[("", "db", log.clone())]);
        let mut table = ResourceTable::new();
        {
            let mut host = SqlHost::new(&mut table, &mut session);
            let db = host.open(String::new()).unwrap();
            host.execute(db, "INSERT INTO t VALUES (1)".into(), vec![])
                .await
                .unwrap();
        }
        session.finalize(false).await;
        assert_eq!(log.lock().unwrap().last().unwrap(), "db:rollback");
    }

    #[tokio::test]
    async fn unopened_database_starts_no_transaction() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut session = session(&[("", "db", log.clone())]);
        // Never opened/queried.
        session.finalize(true).await;
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn ungranted_name_is_denied() {
        let mut session = SqlSession::for_backends(HashMap::new());
        let mut table = ResourceTable::new();
        let mut host = SqlHost::new(&mut table, &mut session);
        assert!(host.open(String::new()).is_err());
        assert!(host.open("main".into()).is_err());
    }

    /// `open-read-only` begins via `begin_read_only` (which a replica-configured
    /// backend routes to the replica), while a plain `open` to the same name
    /// uses `begin` — they get independent transactions.
    #[tokio::test]
    async fn open_read_only_routes_to_read_transaction() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut session = session(&[("", "db", log.clone())]);
        let mut table = ResourceTable::new();
        {
            let mut host = SqlHost::new(&mut table, &mut session);
            // A read-only handle: its query begins a read-only transaction.
            let ro = host.open_read_only(String::new()).unwrap();
            host.query(ro, "SELECT n FROM t".into(), vec![])
                .await
                .unwrap();
            // A read-write handle to the same name gets its own transaction.
            let rw = host.open(String::new()).unwrap();
            host.execute(rw, "INSERT INTO t VALUES (1)".into(), vec![])
                .await
                .unwrap();
        }
        session.finalize(true).await;

        let log = log.lock().unwrap();
        assert!(
            log.iter().any(|l| l == "db:begin_read_only"),
            "read-only handle routed to begin_read_only: {log:?}"
        );
        assert!(
            log.iter().any(|l| l == "db:begin"),
            "read-write handle used begin: {log:?}"
        );
        // Two independent transactions, so two commits.
        assert_eq!(log.iter().filter(|l| l.ends_with(":commit")).count(), 2);
    }

    // ---- H1: a guest must not overwrite the reserved session keys -----------

    /// A backend that reports it injects the reserved session context (rls_session on),
    /// so the binding's guest-statement guard is active. Its transaction records the
    /// SQL it is asked to run (to assert a rejected statement never reaches it).
    struct RlsBackend {
        injects: bool,
        log: Log,
        dialect: boatramp_core::sql::Dialect,
        rls: Option<boatramp_core::sql::RlsGuc>,
    }
    #[async_trait]
    impl SqlBackend for RlsBackend {
        fn injects_session_context(&self) -> bool {
            self.injects
        }
        fn dialect(&self) -> boatramp_core::sql::Dialect {
            self.dialect
        }
        fn rls_guc(&self) -> Option<&boatramp_core::sql::RlsGuc> {
            self.rls.as_ref()
        }
        async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            Ok(Box::new(FakeTxn {
                label: "rls",
                log: self.log.clone(),
            }))
        }
        async fn begin_read_only(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            Ok(Box::new(FakeTxn {
                label: "rls",
                log: self.log.clone(),
            }))
        }
    }

    fn rls_session(injects: bool, log: Log) -> SqlSession {
        let mut map: HashMap<String, Arc<dyn SqlBackend>> = HashMap::new();
        map.insert(
            String::new(),
            Arc::new(RlsBackend {
                injects,
                log,
                dialect: boatramp_core::sql::Dialect::Sqlite,
                rls: None,
            }),
        );
        SqlSession::for_backends(map)
    }

    /// A Postgres RLS session with a configured all-marker and the given axis modes — for testing the
    /// v0.4.21 marker set + `defend_write_marker` invariant directly on `SqlSession`.
    fn pg_marker_session(
        marker: &str,
        read: boatramp_core::tenancy::AccessMode,
        write: boatramp_core::tenancy::AccessMode,
        log: Log,
    ) -> SqlSession {
        let mut map: HashMap<String, Arc<dyn SqlBackend>> = HashMap::new();
        map.insert(
            String::new(),
            Arc::new(RlsBackend {
                injects: true,
                log,
                dialect: boatramp_core::sql::Dialect::Postgres,
                rls: Some(boatramp_core::sql::RlsGuc {
                    tenant: "app.tenant_id".into(),
                    session: None,
                    all_marker: Some(marker.to_string()),
                }),
            }),
        );
        SqlSession::for_backends(map).with_tenancy(Some(crate::tenant::HostTenancy::new(
            "tenant_id",
            Some(SqlValue::Text("ten_1".into())),
            read,
            write,
        )))
    }

    /// The core no-write-under-marker invariant, at the `SqlSession` level: an `all` read sets the
    /// marker on the write transaction, and a subsequent write force-resets the GUC off the marker to
    /// the resolved tenant BEFORE it runs — so a `WITH CHECK (… OR guc = marker)` is never opened.
    #[tokio::test]
    async fn all_read_marker_is_set_then_defended_off_the_write_txn() {
        use boatramp_core::tenancy::AccessMode;
        let log = Arc::new(Mutex::new(Vec::new()));
        // read=All + write=Own (ten_1) — the combo where the write path does NOT re-derive the GUC,
        // so the defend is the only thing that can stop a stale marker riding into the write.
        let mut session = pg_marker_session("*", AccessMode::All, AccessMode::Own, log.clone());

        // An `all` read sets the marker on the (name, false) write transaction.
        session
            .set_all_read_marker("", false, crate::tenant::Axis::Read)
            .await
            .unwrap();
        // A write then defends: force-reset the GUC to the resolved tenant before the write runs.
        session.defend_write_marker("").await.unwrap();

        let log = log.lock().unwrap();
        let sets: Vec<&String> = log.iter().filter(|l| l.contains("set_config")).collect();
        // The `all` read DID set the marker (so an opted-in table opens cross-tenant)…
        assert!(
            sets.iter().any(|s| s.contains("\"*\"")),
            "the all-read set the all-marker, got {sets:?}"
        );
        // …but the LAST GUC set before the write is the resolved tenant, NOT the marker — the defend
        // won, so a `WITH CHECK (… OR guc = marker)` can never be always-true for the write.
        let last = sets.last().expect("at least one GUC set");
        assert!(
            last.contains("ten_1") && !last.contains("\"*\""),
            "the write defended off the marker to the resolved tenant, got {sets:?}"
        );
    }

    /// The marker is NEVER set for a write axis or a non-`all` read (fail-closed gating).
    #[tokio::test]
    async fn all_read_marker_not_set_for_writes_or_non_all_reads() {
        use boatramp_core::tenancy::AccessMode;
        // A WRITE axis: no marker even though read is All.
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut s = pg_marker_session("*", AccessMode::All, AccessMode::All, log.clone());
        s.set_all_read_marker("", false, crate::tenant::Axis::Write)
            .await
            .unwrap();
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .all(|l| !l.contains("set_config")),
            "a write axis must not set the all-marker"
        );
        // An `own` READ (read != All): no marker — an unresolved own read must stay GUC-unset (deny),
        // never fall back to the marker.
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut s = pg_marker_session("*", AccessMode::Own, AccessMode::Own, log.clone());
        s.set_all_read_marker("", false, crate::tenant::Axis::Read)
            .await
            .unwrap();
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .all(|l| !l.contains("set_config")),
            "a non-`all` read must not set the all-marker"
        );
    }

    /// With rls_session on, a guest `query`/`execute` that sets a reserved
    /// `boatramp.*` GUC or `@boatramp_*` var is refused, and the statement never
    /// reaches the backend (nothing recorded).
    #[tokio::test]
    async fn rls_backend_rejects_guest_setting_reserved_keys() {
        for hostile in [
            "SELECT set_config('boatramp.project','victim',false)",
            "SET boatramp.project = 'victim'",
            "SET @boatramp_project = 'victim'",
            "RESET ALL",
            "DISCARD ALL",
            // The deferred-execution / MySQL bypass classes found by the security
            // review loop (both query and execute must reject each — the guard is a
            // pure fn, but this locks that BOTH guest entry points call it for the
            // whole class, so a refactor can't silently drop one path).
            "DO $$ BEGIN PERFORM set_config('boatramp.project','victim',false); END $$;",
            "SET @x=1, @boatramp_project='victim'",
            "SELECT 'victim' INTO @boatramp_project",
            "PREPARE s FROM 'SET @boatramp_project=''victim'''",
            "CREATE FUNCTION e() RETURNS void AS $$ SELECT set_config('boatramp.project','v',false) $$ LANGUAGE sql",
            "ALTER ROLE tenant SET boatramp.project = 'victim'",
        ] {
            let log = Arc::new(Mutex::new(Vec::new()));
            let mut session = rls_session(true, log.clone());
            let mut table = ResourceTable::new();
            let mut host = SqlHost::new(&mut table, &mut session);

            let db = host.open(String::new()).unwrap();
            let rep = db.rep();
            // Via `query`.
            assert!(
                host.query(db, hostile.into(), vec![]).await.is_err(),
                "query must reject: {hostile}"
            );
            // Via `execute`.
            assert!(
                host.execute(Resource::new_own(rep), hostile.into(), vec![])
                    .await
                    .is_err(),
                "execute must reject: {hostile}"
            );
            assert!(
                log.lock().unwrap().is_empty(),
                "a rejected statement must never reach the backend: {hostile}"
            );
        }
    }

    /// With rls_session on, ordinary app SQL (including an unrelated `SET`) is allowed
    /// and reaches the backend.
    #[tokio::test]
    async fn rls_backend_allows_legit_sql() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut session = rls_session(true, log.clone());
        let mut table = ResourceTable::new();
        let mut host = SqlHost::new(&mut table, &mut session);

        let db = host.open(String::new()).unwrap();
        let rep = db.rep();
        // A normal SELECT.
        host.query(db, "SELECT n FROM t WHERE k = ?1".into(), vec![])
            .await
            .unwrap();
        // An unrelated SET is NOT blocked by the reserved-prefix guard.
        host.execute(
            Resource::new_own(rep),
            "SET statement_timeout = 5000".into(),
            vec![],
        )
        .await
        .unwrap();
        let log = log.lock().unwrap();
        assert!(log.iter().any(|l| l.contains("SELECT n FROM t")));
        assert!(log.iter().any(|l| l.contains("SET statement_timeout")));
    }

    /// When the backend does NOT inject a session context (rls_session off), the guard
    /// is inert — even a `SET boatramp.project` reaches the backend (no reserved keys to
    /// protect, so nothing is filtered; the isolation boundary is the per-tenant DB).
    #[tokio::test]
    async fn non_rls_backend_does_not_filter() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut session = rls_session(false, log.clone());
        let mut table = ResourceTable::new();
        let mut host = SqlHost::new(&mut table, &mut session);

        let db = host.open(String::new()).unwrap();
        host.execute(db, "SET boatramp.project = 'x'".into(), vec![])
            .await
            .unwrap();
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("boatramp.project"))
        );
    }

    fn scoped_session(
        log: Log,
        read: boatramp_core::tenancy::AccessMode,
        write: boatramp_core::tenancy::AccessMode,
    ) -> SqlSession {
        session(&[("", "db", log)]).with_tenancy(Some(crate::tenant::HostTenancy::new(
            "tenant_id",
            Some(SqlValue::Text("ten_1".into())),
            read,
            write,
        )))
    }

    #[tokio::test]
    async fn scoped_raw_sql_without_the_marker_is_refused() {
        use boatramp_core::tenancy::AccessMode;
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut session = scoped_session(log.clone(), AccessMode::Own, AccessMode::Own);
        let mut table = ResourceTable::new();
        let mut host = SqlHost::new(&mut table, &mut session);
        let db = host.open(String::new()).unwrap();
        // No `{scope}` marker on a scoped read ⇒ refused before the backend (fail-closed).
        let err = host
            .query(db, "SELECT * FROM orders".into(), vec![])
            .await
            .unwrap_err();
        assert!(matches!(err, sql_types::Error::Other(m) if m.contains("{scope}")));
        assert!(
            log.lock().unwrap().is_empty(),
            "nothing reached the backend"
        );
    }

    #[tokio::test]
    async fn scoped_raw_sql_marker_is_filled_with_the_host_tenant() {
        use boatramp_core::tenancy::AccessMode;
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut session = scoped_session(log.clone(), AccessMode::Own, AccessMode::Own);
        let mut table = ResourceTable::new();
        {
            let mut host = SqlHost::new(&mut table, &mut session);
            let db = host.open(String::new()).unwrap();
            // One guest param (?1); the injected predicate binds the appended ?2 = "ten_1".
            host.query(
                db,
                "SELECT * FROM orders WHERE status = ?1 AND {scope}".into(),
                vec![sql_types::Value::Text("open".into())],
            )
            .await
            .unwrap();
        }
        let log = log.lock().unwrap();
        assert!(log.iter().any(|l| {
            l.contains("SELECT * FROM orders WHERE status = ?1 AND tenant_id = ?2")
                && l.contains("ten_1")
        }));
    }

    #[tokio::test]
    async fn dml_via_query_is_scoped_by_the_write_axis_not_read() {
        use boatramp_core::tenancy::AccessMode;
        let log = Arc::new(Mutex::new(Vec::new()));
        // read: own, write: NONE — a read-only grant.
        let mut session = scoped_session(log.clone(), AccessMode::Own, AccessMode::None);
        let mut table = ResourceTable::new();
        let mut host = SqlHost::new(&mut table, &mut session);
        let db = host.open(String::new()).unwrap();
        // A DELETE routed through query() must be judged a WRITE (write: none) and refused —
        // it must NOT run under the read grant.
        let err = host
            .query(db, "DELETE FROM orders WHERE {scope}".into(), vec![])
            .await
            .unwrap_err();
        assert!(matches!(err, sql_types::Error::Other(m) if m.contains("not granted access")));
        assert!(
            log.lock().unwrap().is_empty(),
            "the DELETE never reached the backend"
        );
    }

    #[tokio::test]
    async fn select_via_execute_is_still_a_read() {
        use boatramp_core::tenancy::AccessMode;
        let log = Arc::new(Mutex::new(Vec::new()));
        // read: own, write: none — a SELECT is a read regardless of the entry method.
        let mut session = scoped_session(log.clone(), AccessMode::Own, AccessMode::None);
        let mut table = ResourceTable::new();
        {
            let mut host = SqlHost::new(&mut table, &mut session);
            let db = host.open(String::new()).unwrap();
            host.execute(db, "SELECT 1 FROM t WHERE {scope}".into(), vec![])
                .await
                .unwrap();
        }
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("SELECT 1 FROM t WHERE tenant_id = ?1"))
        );
    }

    #[tokio::test]
    async fn unscoped_raw_sql_neutralizes_a_stray_marker() {
        let log = Arc::new(Mutex::new(Vec::new()));
        // No tenancy configured (plain function).
        let mut session = session(&[("", "db", log.clone())]);
        let mut table = ResourceTable::new();
        {
            let mut host = SqlHost::new(&mut table, &mut session);
            let db = host.open(String::new()).unwrap();
            host.query(db, "SELECT 1 WHERE {scope}".into(), vec![])
                .await
                .unwrap();
        }
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("SELECT 1 WHERE 1 = 1"))
        );
    }

    // ---- #503: raw-SQL has NO write-global exemption (global writes are ORM-only) -------------

    /// A `PerTable` schema-backed scoped session (write:`Own`, read:`Own`) over `label` with:
    /// `orders`/`tenant_secrets` = tenant, `countries` = plain `Unscoped`, `oauth_state` =
    /// write-global (`SharedWritable`); the route lists `unscoped_writes` for the strict ORM opt-in.
    /// `dialect` picks the SQLite (libsql, non-RLS) vs Postgres vs MySQL backend so the raw-SQL
    /// behavior is asserted on every engine.
    fn scoped_schema_session(
        log: Log,
        unscoped_writes: &[&str],
        dialect: boatramp_core::sql::Dialect,
    ) -> SqlSession {
        use boatramp_core::tenancy::{TableScope, TenancySchema};
        use std::collections::{BTreeMap, HashMap};
        let schema = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: BTreeMap::from([
                ("orders".into(), TableScope::Tenant),
                ("tenant_secrets".into(), TableScope::Tenant),
                ("countries".into(), TableScope::Unscoped { writable: false }),
                (
                    "oauth_state".into(),
                    TableScope::Unscoped { writable: true },
                ),
            ]),
            ..Default::default()
        };
        let ht = crate::tenant::HostTenancy::new(
            "tenant_id",
            Some(SqlValue::Text("ten_1".into())),
            boatramp_core::tenancy::AccessMode::Own,
            boatramp_core::tenancy::AccessMode::Own,
        )
        .with_schema(Some(&schema))
        .with_unscoped_writes(unscoped_writes.iter().map(ToString::to_string));
        let mut map: HashMap<String, Arc<dyn SqlBackend>> = HashMap::new();
        map.insert(
            String::new(),
            Arc::new(RlsBackend {
                injects: false,
                log,
                dialect,
                rls: None,
            }),
        );
        SqlSession::for_backends(map).with_tenancy(Some(ht))
    }

    #[tokio::test]
    async fn raw_sql_global_write_has_no_exemption_marker_required_or_scoped() {
        use boatramp_core::sql::Dialect;
        // #503 SECURITY (post-fix): the raw-SQL surface has NO write-global exemption — global writes
        // are ORM-only. A raw-SQL write to a write-global (`oauth_state`) OR a route-listed plain
        // `Unscoped` (`countries`) table is treated exactly like any other scoped write: the `{scope}`
        // marker is REQUIRED. An unmarked write is refused fail-closed (never runs unstamped); a
        // marked write is scoped to the guest's OWN tenant (the injected `tenant_id = ?` predicate).
        // Asserted on SQLite (libsql, no RLS GUC backstop) AND Postgres. Contrast the ORM path, which
        // DOES allow these writes unstamped (see the cross-surface gate).
        for dialect in [Dialect::Sqlite, Dialect::Postgres] {
            // The route even LISTS both globals — proving the list has no effect on the raw surface.
            let list = ["oauth_state", "countries"];

            // (a) write-global (`oauth_state`), NO marker ⇒ REFUSED (marker-required), never runs.
            let log = Arc::new(Mutex::new(Vec::new()));
            let mut session = scoped_schema_session(log.clone(), &list, dialect);
            let mut table = ResourceTable::new();
            {
                let mut host = SqlHost::new(&mut table, &mut session);
                let db = host.open(String::new()).unwrap();
                let err = host
                    .execute(
                        db,
                        "INSERT INTO oauth_state (state) VALUES (?1)".into(),
                        vec![sql_types::Value::Text("csrf".into())],
                    )
                    .await
                    .unwrap_err();
                let sql_types::Error::Other(msg) = &err else {
                    panic!("expected an Other refusal on {dialect:?}, got {err:?}");
                };
                assert!(
                    msg.contains("{scope}"),
                    "an unmarked write-global raw write must be refused (marker-required) on \
                     {dialect:?}: {msg}"
                );
            }
            assert!(
                log.lock().unwrap().is_empty(),
                "the refused write-global write must not reach the backend on {dialect:?}"
            );

            // (b) plain-`Unscoped` listed (`countries`), NO marker ⇒ REFUSED (the list does not
            // exempt it on the raw surface).
            let log = Arc::new(Mutex::new(Vec::new()));
            let mut session = scoped_schema_session(log.clone(), &list, dialect);
            let mut table = ResourceTable::new();
            {
                let mut host = SqlHost::new(&mut table, &mut session);
                let db = host.open(String::new()).unwrap();
                let err = host
                    .execute(
                        db,
                        "INSERT INTO countries (code) VALUES (?1)".into(),
                        vec![sql_types::Value::Text("US".into())],
                    )
                    .await
                    .unwrap_err();
                let sql_types::Error::Other(msg) = &err else {
                    panic!("expected an Other refusal on {dialect:?}, got {err:?}");
                };
                assert!(
                    msg.contains("{scope}"),
                    "listed plain global still marker-required: {msg}"
                );
            }
            assert!(log.lock().unwrap().is_empty());

            // (c) write-global WITH `{scope}` ⇒ scoped to the OWN tenant (`tenant_id = ?`), NOT run
            // unstamped. This is the safe raw-SQL route: the write lands only in the guest's own rows.
            let log = Arc::new(Mutex::new(Vec::new()));
            let mut session = scoped_schema_session(log.clone(), &list, dialect);
            let mut table = ResourceTable::new();
            {
                let mut host = SqlHost::new(&mut table, &mut session);
                let db = host.open(String::new()).unwrap();
                host.execute(
                    db,
                    "UPDATE oauth_state SET x = ?1 WHERE {scope}".into(),
                    vec![sql_types::Value::Integer(1)],
                )
                .await
                .unwrap();
            }
            assert!(
                log.lock().unwrap().iter().any(|l| l
                    .contains("UPDATE oauth_state SET x = ?1 WHERE tenant_id = ?2")
                    && l.contains("ten_1")),
                "a marked global raw write is scoped to the OWN tenant on {dialect:?}"
            );
        }
    }

    #[tokio::test]
    async fn raw_sql_comment_redirect_and_insert_select_do_not_run_unscoped() {
        // #503 SECURITY REGRESSION-LOCK — the two live-verified attack statements (Security review,
        // MySQL 8.4) that the removed raw-SQL exemption let through. Both target a globally-*readable*
        // table (`oauth_state`) whose ORM write-global status the removed exemption keyed off, and both
        // hide a cross-tenant write behind a construct a vanilla parser misreads:
        //   1. `UPDATE /*!50000 tenant_secrets */ oauth_state SET x=999` — a MySQL/MariaDB version
        //      comment the ENGINE executes (so the real target is `tenant_secrets`, a tenant table)
        //      but sqlparser ignores (it saw `oauth_state`, a global → exempted → cross-tenant write).
        //   2. `INSERT INTO oauth_state (a) SELECT tenant_id FROM tenant_secrets` — the exempted path
        //      ran the SELECT source UNSCOPED → cross-tenant exfiltration into a globally-readable table.
        // With NO exemption, BOTH are ordinary scoped writes: they MUST be either refused (no `{scope}`
        // marker) or carry the injected own-tenant predicate. Neither may run unstamped/verbatim. Run
        // on MySQL AND SQLite (a real engine is not available here — the fake backend records the exact
        // SQL the host would submit, which is what the exemption bug operated on).
        use boatramp_core::sql::Dialect;
        for dialect in [Dialect::Mysql, Dialect::Sqlite] {
            // The route LISTS both globals + declares `oauth_state` write-global, i.e. the most
            // permissive posture the exemption could have keyed off — proving it is now inert.
            let list = ["oauth_state", "countries", "tenant_secrets"];
            for stmt in [
                "UPDATE /*!50000 tenant_secrets */ oauth_state SET x = 999",
                "INSERT INTO oauth_state (a) SELECT tenant_id FROM tenant_secrets",
            ] {
                let log = Arc::new(Mutex::new(Vec::new()));
                let mut session = scoped_schema_session(log.clone(), &list, dialect);
                let mut table = ResourceTable::new();
                let res = {
                    let mut host = SqlHost::new(&mut table, &mut session);
                    let db = host.open(String::new()).unwrap();
                    host.execute(db, stmt.to_string(), vec![]).await
                };
                match res {
                    // Refused for the missing `{scope}` marker — never reached the backend.
                    Err(sql_types::Error::Other(msg)) => {
                        assert!(
                            msg.contains("{scope}"),
                            "attack `{stmt}` on {dialect:?} must be refused for the missing marker, \
                             not some other error: {msg}"
                        );
                        assert!(
                            log.lock().unwrap().is_empty(),
                            "a refused attack `{stmt}` must not reach the backend on {dialect:?}"
                        );
                    }
                    // OR it ran — but ONLY if the own-tenant predicate was injected (marker-scoped).
                    // The attack statements above carry no `{scope}`, so this arm should not be hit;
                    // it is the belt-and-suspenders proof that IF a variant did run, it ran scoped.
                    Ok(_) => {
                        let logged = log.lock().unwrap();
                        assert!(
                            logged.iter().all(|l| !l.contains("execute")
                                || (l.contains("tenant_id") && l.contains("ten_1"))),
                            "attack `{stmt}` on {dialect:?} MUST NOT run unscoped/verbatim — any \
                             executed SQL must carry the injected own-tenant predicate: {logged:?}"
                        );
                    }
                    Err(other) => {
                        panic!("attack `{stmt}` on {dialect:?}: unexpected error {other:?}")
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn m7_raw_sql_tenant_table_stays_scoped_on_both_engines() {
        use boatramp_core::sql::Dialect;
        // M7 (CRITICAL): a NON-global (tenant) table stays scoped on the raw surface even when the
        // route lists other globals — the marker is still required and the tenant predicate injected.
        for dialect in [Dialect::Sqlite, Dialect::Postgres] {
            let log = Arc::new(Mutex::new(Vec::new()));
            // Route lists `oauth_state`/`countries` but `orders` is a tenant table — must stay scoped.
            let mut session =
                scoped_schema_session(log.clone(), &["oauth_state", "countries"], dialect);
            let mut table = ResourceTable::new();
            {
                let mut host = SqlHost::new(&mut table, &mut session);
                let db = host.open(String::new()).unwrap();
                host.execute(
                    db,
                    "UPDATE orders SET status = ?1 WHERE id = ?2 AND {scope}".into(),
                    vec![
                        sql_types::Value::Text("paid".into()),
                        sql_types::Value::Text("o_1".into()),
                    ],
                )
                .await
                .unwrap();
            }
            assert!(
                log.lock().unwrap().iter().any(|l| l
                    .contains("UPDATE orders SET status = ?1 WHERE id = ?2 AND tenant_id = ?3")
                    && l.contains("ten_1")),
                "a tenant table stays scoped on the raw surface on {dialect:?}"
            );
        }
    }

    /// **#503 mutation-verified cross-surface gate** (marker `SCOPED UNSCOPED-WRITE CROSS-SURFACE
    /// OK`). Drives BOTH surfaces — the ORM (`Insert::force_scope`+`compile` via `write_target`) and
    /// the raw-SQL path (`SqlHost::execute` via `apply_scope_marker`) — on a schema-backed scoped
    /// route, and asserts the whole #503 behavior end to end. The **cross-surface** property (post
    /// Security-review): the ORM is the SOLE global-write path (it allows a write-global write
    /// unstamped, and scopes any `INSERT … SELECT` source), while the RAW-SQL path has NO write-global
    /// exemption — a global write via raw SQL is marker-scoped (own-tenant predicate injected) or
    /// refused (marker-required), NEVER run unscoped/verbatim. This satisfies cross-surface safety by
    /// REFUSAL (raw SQL offers no weaker path than the injection-immune ORM), not by replicating an
    /// unsound schema-blind parse of the raw statement (the removed exemption was a live cross-tenant
    /// write bypass under MySQL/MariaDB `/*! … */` version comments). Each assertion is keyed to a
    /// specific mutation the CI job can inject via `BOATRAMP_503_MUTATION`; under a mutation the
    /// security property is violated and the test FAILS (so the gate is not hollow):
    /// - `m1_widen_allowlist` — arm 3 fires regardless of set-membership: a NOT-listed plain-`unscoped`
    ///   write becomes allowed (ORM) → the "unlisted is refused" assertions fail (M1/M4).
    /// - `m2_arm_before_resolve` — the write-global/allowlist arm fires WITHOUT the fresh `Unscoped`
    ///   resolve: a listed-but-tenant table is written UNSTAMPED → the "tenant table still stamped"
    ///   assertion fails (M2/G1).
    /// - `m3_widen_read` — the write-global grant co-widens the read to `all`: the sibling tenant read
    ///   loses its `tenant = own` predicate → the read-isolation assertion fails (M3/G2).
    /// - `m6_target_allow` — the write-global arm is NOT `is_target()`-gated: a target write to a
    ///   global is allowed → the "target write refused" assertion fails (M6/HIGH).
    /// - `m7_raw_exemption_reintroduced` — the CRITICAL mutation: the raw surface is given back a
    ///   write-global exemption (models re-adding the deleted `apply_scope_marker` branch), so a raw
    ///   INSERT into a write-global table runs UNSTAMPED. The gate asserts the raw write is
    ///   marker-scoped/refused, so this expectation-flip fails the gate — proving the removed
    ///   exemption is genuinely absent (M7/CRITICAL).
    ///
    /// The mutation is modeled by mutating the DECISION INPUT/expectation (the way #499 runs the
    /// pre-fix path), never the production code — the assertions are fixed and prove the real code's
    /// arms are load-bearing.
    #[tokio::test]
    async fn scoped_unscoped_write_cross_surface_gate() {
        use boatramp_core::orm::{
            Assignment, Expr, Insert, RowValues, Scope, ScopeMode, Select, TableKeys,
        };
        use boatramp_core::sql::{Dialect, SqlValue};
        use boatramp_core::tenancy::{ResolvedScope, TableScope, TenancySchema};
        use std::collections::{BTreeMap, BTreeSet};

        let mutation = std::env::var("BOATRAMP_503_MUTATION").unwrap_or_default();
        let m = |name: &str| mutation == name;

        // The project schema: per-tenant `orders`, write-global `oauth_state`, plain `countries`.
        let schema = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: BTreeMap::from([
                ("orders".into(), TableScope::Tenant),
                (
                    "oauth_state".into(),
                    TableScope::Unscoped { writable: true },
                ),
                ("countries".into(), TableScope::Unscoped { writable: false }),
            ]),
            ..Default::default()
        };
        let key_map = schema.table_key_map();

        // The route's per-invocation Scope, built as the host builds it. Under `m1_widen_allowlist`
        // the allowlist wrongly includes `countries` (models "arm 3 ignores set-membership"); under
        // `m2_arm_before_resolve` it wrongly includes the TENANT table `orders` AND we mutate the
        // key map so `orders` resolves to SharedWritable (models "the arm fired before the fresh
        // Unscoped resolve"); under `m3_widen_read` the read axis is widened to `all`.
        let mut orm_keys = key_map.clone();
        if m("m2_arm_before_resolve") {
            // The mutation: a tenant table is wrongly resolved as write-global — the pre-fresh-resolve bug.
            orm_keys.insert("orders".into(), ResolvedScope::SharedWritable);
        }
        let list: BTreeSet<String> = if m("m1_widen_allowlist") {
            ["countries".to_string()].into_iter().collect()
        } else {
            BTreeSet::new()
        };
        let read_mode = if m("m3_widen_read") {
            ScopeMode::All
        } else {
            ScopeMode::Own
        };
        let orm_scope = Scope {
            column: "tenant_id".into(),
            value: Some(SqlValue::Text("ten_1".into())),
            session: None,
            mode: ScopeMode::Own, // the WRITE-axis scope
            keys: TableKeys::PerTable(orm_keys.clone()),
            unscoped_writes: list.clone(),
        };
        let orm_read_scope = Scope {
            mode: read_mode,
            ..orm_scope.clone()
        };

        // ---- ORM surface ------------------------------------------------------------------------
        let insert = |table: &str, col: &str| Insert {
            table: table.to_string(),
            rows: vec![RowValues {
                cells: vec![Assignment {
                    column: col.into(),
                    value: Expr::val(SqlValue::Text("v".into())),
                }],
            }],
            conflict: None,
            scope: None,
            returning: vec![],
            from_select: None,
        };

        // write-global INSERT: unstamped (arm 2).
        let mut ins = insert("oauth_state", "state");
        ins.force_scope(Some(&orm_scope), Some(&orm_scope)).unwrap();
        let (sql, _) = ins.compile(Dialect::Sqlite).unwrap();
        assert!(
            !sql.contains("tenant_id"),
            "ORM: write-global INSERT must be unstamped: {sql}"
        );

        // M1/M4: an unlisted plain-`unscoped` write is REFUSED (deny-by-default).
        let mut bad = insert("countries", "code");
        let refused = matches!(
            bad.force_scope(Some(&orm_scope), Some(&orm_scope)),
            Err(boatramp_core::orm::OrmError::UnscopedWrite(ref t)) if t == "countries"
        );
        assert!(
            refused,
            "ORM (M1/M4): an unlisted plain-unscoped write MUST be refused (mutation={mutation:?})"
        );

        // M2/G1: a TENANT table is stamped even when listed (fresh resolve). Under
        // `m2_arm_before_resolve` `orders` wrongly resolves to SharedWritable so it writes UNSTAMPED and
        // this assertion fails.
        let mut ord = insert("orders", "id");
        ord.force_scope(Some(&orm_scope), Some(&orm_scope)).unwrap();
        let (osql, _) = ord.compile(Dialect::Sqlite).unwrap();
        assert!(
            osql.contains("tenant_id"),
            "ORM (M2/G1): a tenant table MUST be stamped, never written via the list (mutation={mutation:?}): {osql}"
        );

        // M3/G2: a sibling tenant READ stays own-scoped (write-global does not widen reads). Under
        // `m3_widen_read` the read is `all` so no tenant predicate is injected and this fails.
        let mut sel = Select::from("orders");
        sel.scope = Some(orm_read_scope.clone());
        let (rsql, _) = sel.compile(Dialect::Sqlite).unwrap();
        assert!(
            rsql.contains("tenant_id = ?"),
            "ORM (M3/G2): a sibling tenant read MUST stay own-scoped (mutation={mutation:?}): {rsql}"
        );

        // M6/HIGH: a TARGET write to a write-global table is REFUSED. Under `m6_target_allow` we
        // model the un-gated arm by asserting against a NON-target scope (so the write is allowed) —
        // i.e. the mutation drops the is_target guard, and the "refused" expectation fails.
        let target_scope = Scope {
            column: "tenant_id".into(),
            value: Some(SqlValue::Text("tenant_B".into())),
            session: None,
            mode: ScopeMode::Own,
            keys: if m("m6_target_allow") {
                // mutation: treat the target write as if it were a non-target (the guard removed).
                TableKeys::PerTable(orm_keys.clone())
            } else {
                TableKeys::PerTableTarget {
                    keys: orm_keys.clone(),
                    public: BTreeMap::new(),
                    write: BTreeSet::from(["state".to_string()]),
                    require_public: false,
                }
            },
            unscoped_writes: BTreeSet::new(),
        };
        let mut tw = insert("oauth_state", "state");
        let target_refused = matches!(
            tw.force_scope(Some(&target_scope), Some(&target_scope)),
            Err(boatramp_core::orm::OrmError::UnscopedWrite(_))
        );
        assert!(
            target_refused,
            "ORM (M6/HIGH): a target write to a write-global table MUST be refused (mutation={mutation:?})"
        );

        // ---- Raw-SQL surface (real fake backend; SQLite + Postgres + MySQL) ---------------------
        // The CROSS-SURFACE property: unlike the ORM above, the raw path has NO write-global
        // exemption. A raw INSERT into the SAME write-global `oauth_state` table — even with the route
        // listing every global — is marker-required: with no `{scope}` it is REFUSED (never runs
        // unstamped); with `{scope}` it is scoped to the OWN tenant. The `m7_raw_exemption_reintroduced`
        // mutation models re-adding the deleted exemption by flipping the expectation to the buggy
        // "runs unstamped" outcome — since the real (fixed) code refuses, that expectation fails the
        // gate, proving the exemption is genuinely gone.
        for dialect in [Dialect::Sqlite, Dialect::Postgres, Dialect::Mysql] {
            // The MOST permissive route: it lists every global AND declares `oauth_state` write-global.
            let log = Arc::new(Mutex::new(Vec::new()));
            let mut session =
                scoped_schema_session(log.clone(), &["oauth_state", "countries"], dialect);
            let mut table = ResourceTable::new();

            // Unmarked write-global raw INSERT: the fixed code REFUSES it (marker-required). Under
            // `m7_raw_exemption_reintroduced` we assert the buggy "runs unstamped" outcome instead —
            // which the fixed code does not do, so the gate fails under that mutation.
            let res = {
                let mut host = SqlHost::new(&mut table, &mut session);
                let db = host.open(String::new()).unwrap();
                host.execute(
                    db,
                    "INSERT INTO oauth_state (state) VALUES (?1)".to_string(),
                    vec![sql_types::Value::Text("csrf".into())],
                )
                .await
            };
            if m("m7_raw_exemption_reintroduced") {
                // Buggy expectation: the reintroduced exemption would let the unmarked global write
                // SUCCEED and run unstamped. The fixed code refuses, so this fails the gate.
                let ran_unstamped = res.is_ok()
                    && log.lock().unwrap().iter().any(|l| {
                        l.contains("INSERT INTO oauth_state (state) VALUES (?1)")
                            && !l.contains("tenant_id")
                    });
                assert!(
                    ran_unstamped,
                    "raw (M7 mutation): a reintroduced exemption would run the unmarked global write \
                     UNSTAMPED — the fixed code refuses it, so this expectation must fail the gate on \
                     {dialect:?}"
                );
            } else {
                let sql_types::Error::Other(msg) = res.expect_err(
                    "raw (M7): an unmarked write-global raw write MUST be refused, not run",
                ) else {
                    panic!("raw (M7): expected an Other refusal on {dialect:?}");
                };
                assert!(
                    msg.contains("{scope}"),
                    "raw (M7): the refusal is the marker-required rule on {dialect:?}: {msg}"
                );
                assert!(
                    log.lock().unwrap().is_empty(),
                    "raw (M7): the refused global write must not reach the backend on {dialect:?}"
                );
            }

            // A MARKED write-global raw write is scoped to the OWN tenant (never unstamped) — the safe
            // raw route. (Skipped under the buggy mutation, whose model does not reach here.)
            if !m("m7_raw_exemption_reintroduced") {
                let log2 = Arc::new(Mutex::new(Vec::new()));
                let mut session2 =
                    scoped_schema_session(log2.clone(), &["oauth_state", "countries"], dialect);
                let mut table2 = ResourceTable::new();
                {
                    let mut host = SqlHost::new(&mut table2, &mut session2);
                    let db = host.open(String::new()).unwrap();
                    host.execute(
                        db,
                        "UPDATE oauth_state SET x = ?1 WHERE {scope}".to_string(),
                        vec![sql_types::Value::Integer(1)],
                    )
                    .await
                    .unwrap();
                }
                assert!(
                    log2.lock().unwrap().iter().any(|l| l
                        .contains("UPDATE oauth_state SET x = ?1 WHERE tenant_id = ?2")
                        && l.contains("ten_1")),
                    "raw (M7): a marked global raw write is scoped to the OWN tenant on {dialect:?}"
                );
            }
        }

        println!(
            "SCOPED UNSCOPED-WRITE CROSS-SURFACE OK: the ORM is the sole global-write path (a \
             write-global table writes UNSTAMPED via the ORM, a listed plain-unscoped table too, an \
             unlisted one is refused, a listed-but-tenant table is still stamped (G1), reads are not \
             widened (G2), a target write to a global is refused (HIGH)); the RAW-SQL path has NO \
             write-global exemption — an unmarked global raw write is refused and a marked one is \
             scoped to the own tenant, NEVER run unscoped (mutation={mutation:?})."
        );
    }

    // ---- R4/D8: a raw-SQL target read is AST-rewritten (not marker-substituted) ---------------

    /// A two-table schema (`products`, `reviews`) with per-table public subsets, for building a
    /// target-read `HostTenancy`.
    fn target_session(log: Log, b: &str) -> SqlSession {
        use boatramp_core::tenancy::{
            PublicCmp, PublicLiteral, PublicPredicate, PublicSubset, PublicTerm, TableScope,
            TenancySchema,
        };
        use std::collections::BTreeMap;
        let public = |col: &str| PublicSubset {
            predicate: PublicPredicate {
                terms: vec![PublicTerm::Cmp {
                    column: col.into(),
                    op: PublicCmp::Eq,
                    value: PublicLiteral::Bool(true),
                }],
            },
            world_public: true,
            listable: true,
        };
        let mut schema = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: BTreeMap::from([
                ("products".into(), TableScope::Tenant),
                ("reviews".into(), TableScope::Tenant),
            ]),
            ..Default::default()
        };
        schema
            .public_subsets
            .insert("products".into(), public("published"));
        schema
            .public_subsets
            .insert("reviews".into(), public("visible"));
        session(&[("", "db", log)]).with_tenancy(Some(crate::tenant::HostTenancy::target(
            SqlValue::Text(b.into()),
            boatramp_core::tenancy::AccessMode::Own,
            &schema,
            "products",
            &[],
            true,
        )))
    }

    /// A target read that JOINs two tenant tables is confined on BOTH tables — the airtight fix the
    /// single-table `{scope}` marker could not deliver. The guest writes plain SQL (no marker).
    #[tokio::test]
    async fn target_raw_sql_read_confines_every_joined_table_to_b_public() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut session = target_session(log.clone(), "tenant_B");
        let mut table = ResourceTable::new();
        {
            let mut host = SqlHost::new(&mut table, &mut session);
            let db = host.open(String::new()).unwrap();
            host.query(
                db,
                "SELECT p.id FROM products p JOIN reviews r ON r.product_id = p.id".into(),
                vec![],
            )
            .await
            .unwrap();
        }
        let log = log.lock().unwrap();
        let ran = log
            .iter()
            .find(|l| l.contains("query"))
            .expect("a query ran");
        assert!(
            ran.contains("p.tenant_id = 'tenant_B' AND p.published = true"),
            "{ran}"
        );
        assert!(
            ran.contains("r.tenant_id = 'tenant_B' AND r.visible = true"),
            "{ran}"
        );
    }

    /// A target read cannot `OR`-escape the confinement: the guest's `WHERE` is parenthesised and
    /// the tenant/public gate `AND`-ed on (closes M2). Also proves the guest need not (and here does)
    /// place a stray `{scope}` — it is neutralised before the rewrite.
    #[tokio::test]
    async fn target_raw_sql_read_cannot_or_escape_the_gate() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut session = target_session(log.clone(), "tenant_B");
        let mut table = ResourceTable::new();
        {
            let mut host = SqlHost::new(&mut table, &mut session);
            let db = host.open(String::new()).unwrap();
            host.query(
                db,
                "SELECT id FROM products WHERE published = false OR 1 = 1".into(),
                vec![],
            )
            .await
            .unwrap();
        }
        let log = log.lock().unwrap();
        let ran = log
            .iter()
            .find(|l| l.contains("query"))
            .expect("a query ran");
        assert!(
            ran.contains("(published = false OR 1 = 1) AND products.tenant_id = 'tenant_B'"),
            "{ran}"
        );
    }

    /// A target read that touches a table with no declared public subset is refused (deny-by-default)
    /// and never reaches the backend.
    #[tokio::test]
    async fn target_raw_sql_read_refuses_an_undeclared_table() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut session = target_session(log.clone(), "tenant_B");
        let mut table = ResourceTable::new();
        let mut host = SqlHost::new(&mut table, &mut session);
        let db = host.open(String::new()).unwrap();
        let err = host
            .query(db, "SELECT * FROM secrets".into(), vec![])
            .await
            .unwrap_err();
        assert!(matches!(err, sql_types::Error::Other(m) if m.contains("public subset")));
        assert!(
            log.lock().unwrap().is_empty(),
            "nothing reached the backend"
        );
    }

    /// A write under a target principal is refused (the rewriter enforces read-only) and never
    /// reaches the backend — belt-and-suspenders with the `None` write-axis grant.
    #[tokio::test]
    async fn target_raw_sql_write_is_refused() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut session = target_session(log.clone(), "tenant_B");
        let mut table = ResourceTable::new();
        let mut host = SqlHost::new(&mut table, &mut session);
        let db = host.open(String::new()).unwrap();
        let err = host
            .execute(db, "DELETE FROM products WHERE id = 1".into(), vec![])
            .await
            .unwrap_err();
        assert!(matches!(err, sql_types::Error::Other(_)));
        assert!(
            log.lock().unwrap().is_empty(),
            "the write never reached the backend"
        );
    }
}
