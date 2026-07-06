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

use boatramp_core::sql::{SqlBackend, SqlError, SqlTransaction, SqlValue};
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

    /// Whether a database is granted under `name`.
    fn granted(&self, name: &str) -> bool {
        self.backends.contains_key(name)
    }

    /// The open transaction for `(name, read_only)`, beginning one on first use.
    /// A read-only transaction is begun via [`SqlBackend::begin_read_only`], so a
    /// replica-configured backend can route it to the replica.
    async fn txn(
        &mut self,
        name: &str,
        read_only: bool,
    ) -> Result<&mut dyn SqlTransaction, sql_types::Error> {
        let key = (name.to_string(), read_only);
        if !self.txns.contains_key(&key) {
            let backend = self
                .backends
                .get(name)
                .ok_or_else(|| not_granted(name))?
                .clone();
            let txn = if read_only {
                backend.begin_read_only().await
            } else {
                backend.begin().await
            }
            .map_err(to_wit_error)?;
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
        let params = to_values(params);
        let txn = self.session.txn(&name, read_only).await?;
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
        let params = to_values(params);
        let txn = self.session.txn(&name, read_only).await?;
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
}
