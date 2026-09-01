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
    reject_reserved_session_writes, SqlBackend, SqlError, SqlTransaction, SqlValue,
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
}

impl SqlSession {
    /// A session granting the given named backends (empty = no SQL granted).
    pub fn for_backends(backends: HashMap<String, Arc<dyn SqlBackend>>) -> Self {
        Self {
            backends,
            txns: HashMap::new(),
        }
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
            let txn = if read_only {
                backend.begin_read_only().await
            } else {
                backend.begin().await
            }?;
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
        // (rls_session), the guest must not overwrite those keys and spoof its tenant.
        if self.session.injects_session_context(&name) {
            reject_reserved_session_writes(&statement).map_err(to_wit_error)?;
        }
        let params = to_values(params);
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
        // H1: see `query` — refuse guest overwrites of the reserved session keys.
        if self.session.injects_session_context(&name) {
            reject_reserved_session_writes(&statement).map_err(to_wit_error)?;
        }
        let params = to_values(params);
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
        SqlError::Other(m) => sql_types::Error::Other(m),
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
        assert!(log
            .iter()
            .any(|l| l.starts_with("main:execute INSERT INTO m")));
        assert!(log
            .iter()
            .any(|l| l.starts_with("cache:execute INSERT INTO c")));
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
    }
    #[async_trait]
    impl SqlBackend for RlsBackend {
        fn injects_session_context(&self) -> bool {
            self.injects
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
        map.insert(String::new(), Arc::new(RlsBackend { injects, log }));
        SqlSession::for_backends(map)
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
        assert!(log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("boatramp.project")));
    }
}
