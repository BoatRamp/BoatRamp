//! The `orm` host binding: a typed query interface (`boatramp:handlers/orm`) that compiles
//! guest-supplied query ASTs to injection-safe `?N` SQL via [`boatramp_core::orm`] and runs
//! them through the **same** per-invocation [`SqlSession`] as the raw [`sql`](super::sql)
//! binding — so a handler may mix `orm` and `sql` on one database within one transaction.
//!
//! The compiler (in `boatramp-core`) does the SQL generation + safety; this module is only
//! the WIT⇄core translation plus the resource/transaction plumbing (mirroring `sql.rs`).

use boatramp_core::orm as core;
use boatramp_core::sql::SqlValue;
use wasmtime::component::{Resource, ResourceTable};

use super::sql::SqlSession;

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/orm-host",
        async: {
            only_imports: [
                "[method]database.select",
                "[method]database.insert",
                "[method]database.update",
            ],
        },
        with: {
            "boatramp:handlers/orm/database": super::OrmDatabase,
        },
    });
}

use generated::boatramp::handlers::orm as wit;
use generated::boatramp::handlers::sql_types;

/// A handle to one named database opened through the `orm` interface. The transaction lives
/// in the shared [`SqlSession`], keyed by name (read-write), so it is the same transaction a
/// `sql` handle to the same name uses.
pub struct OrmDatabase {
    name: String,
}

/// Per-invocation view: the resource table (holding `orm` `database` handles) plus the shared
/// SQL session (backends + open transactions), which it shares with the `sql` binding.
pub struct OrmHost<'a> {
    table: &'a mut ResourceTable,
    session: &'a mut SqlSession,
}

impl<'a> OrmHost<'a> {
    /// Build a view over `table` and the shared `session`.
    pub fn new(table: &'a mut ResourceTable, session: &'a mut SqlSession) -> Self {
        Self { table, session }
    }
}

impl wit::Host for OrmHost<'_> {
    fn open(&mut self, name: String) -> Result<Resource<OrmDatabase>, wit::Error> {
        if !self.session.granted(&name) {
            return Err(not_granted(&name));
        }
        self.table
            .push(OrmDatabase { name })
            .map_err(|e| wit::Error::Other(e.to_string()))
    }
}

impl wit::HostDatabase for OrmHost<'_> {
    async fn select(
        &mut self,
        db: Resource<OrmDatabase>,
        q: wit::Select,
    ) -> Result<wit::QueryResult, wit::Error> {
        let (sql, params) = to_core_select(q).compile().map_err(compile_err)?;
        let name = self.name_of(&db)?;
        let txn = self.session.txn(&name, false).await.map_err(backend_err)?;
        let rows = txn.query(&sql, &params).await.map_err(backend_err)?;
        Ok(wit::QueryResult {
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

    async fn insert(
        &mut self,
        db: Resource<OrmDatabase>,
        q: wit::Insert,
    ) -> Result<u64, wit::Error> {
        let (sql, params) = to_core_insert(q).compile().map_err(compile_err)?;
        let name = self.name_of(&db)?;
        let txn = self.session.txn(&name, false).await.map_err(backend_err)?;
        txn.execute(&sql, &params).await.map_err(backend_err)
    }

    async fn update(
        &mut self,
        db: Resource<OrmDatabase>,
        q: wit::Update,
    ) -> Result<u64, wit::Error> {
        let (sql, params) = to_core_update(q).compile().map_err(compile_err)?;
        let name = self.name_of(&db)?;
        let txn = self.session.txn(&name, false).await.map_err(backend_err)?;
        txn.execute(&sql, &params).await.map_err(backend_err)
    }

    fn drop(&mut self, db: Resource<OrmDatabase>) -> wasmtime::Result<()> {
        // Dropping a handle does not end the transaction — the engine finalizes the
        // invocation (commit/rollback). The transaction is shared with the `sql` binding.
        self.table.delete(db)?;
        Ok(())
    }
}

impl OrmHost<'_> {
    fn name_of(&self, db: &Resource<OrmDatabase>) -> Result<String, wit::Error> {
        self.table
            .get(db)
            .map(|h| h.name.clone())
            .map_err(|e| wit::Error::Other(e.to_string()))
    }
}

// ---- WIT → core translation ------------------------------------------------

fn to_sqlvalue(v: wit::Value) -> SqlValue {
    match v {
        wit::Value::Null => SqlValue::Null,
        wit::Value::Boolean(b) => SqlValue::Boolean(b),
        wit::Value::Integer(i) => SqlValue::Integer(i),
        wit::Value::Float(f) => SqlValue::Real(f),
        wit::Value::Text(s) => SqlValue::Text(s),
        wit::Value::Blob(b) => SqlValue::Blob(b),
    }
}

fn to_core_compare(c: wit::Compare) -> core::Compare {
    match c {
        wit::Compare::Eq(v) => core::Compare::Eq(to_sqlvalue(v)),
        wit::Compare::Ne(v) => core::Compare::Ne(to_sqlvalue(v)),
        wit::Compare::Lt(v) => core::Compare::Lt(to_sqlvalue(v)),
        wit::Compare::Le(v) => core::Compare::Le(to_sqlvalue(v)),
        wit::Compare::Gt(v) => core::Compare::Gt(to_sqlvalue(v)),
        wit::Compare::Ge(v) => core::Compare::Ge(to_sqlvalue(v)),
        wit::Compare::Like(p) => core::Compare::Like(p),
        wit::Compare::InList(vs) => {
            core::Compare::InList(vs.into_iter().map(to_sqlvalue).collect())
        }
        wit::Compare::IsNull => core::Compare::IsNull,
        wit::Compare::IsNotNull => core::Compare::IsNotNull,
    }
}

fn to_core_col_pred(p: wit::ColumnPredicate) -> core::ColumnPredicate {
    core::ColumnPredicate {
        column: p.column,
        test: to_core_compare(p.test),
    }
}

fn to_core_predicate(p: wit::Predicate) -> core::Predicate {
    match p {
        wit::Predicate::All(v) => {
            core::Predicate::All(v.into_iter().map(to_core_col_pred).collect())
        }
        wit::Predicate::Any(v) => {
            core::Predicate::Any(v.into_iter().map(to_core_col_pred).collect())
        }
    }
}

fn to_core_agg(a: wit::Agg) -> core::Agg {
    match a {
        wit::Agg::Count => core::Agg::Count,
        wit::Agg::Sum => core::Agg::Sum,
        wit::Agg::Avg => core::Agg::Avg,
        wit::Agg::Min => core::Agg::Min,
        wit::Agg::Max => core::Agg::Max,
    }
}

fn to_core_scope(s: wit::Scope) -> core::Scope {
    core::Scope {
        column: s.column,
        value: to_sqlvalue(s.value),
    }
}

fn to_core_assignment(a: wit::Assignment) -> core::Assignment {
    core::Assignment {
        column: a.column,
        value: to_sqlvalue(a.value),
    }
}

fn to_core_select(q: wit::Select) -> core::Select {
    core::Select {
        table: q.table,
        columns: q
            .columns
            .into_iter()
            .map(|p| match p {
                wit::Projection::Column(c) => core::Projection::Column(c),
                wit::Projection::Aggregate((a, c)) => {
                    core::Projection::Aggregate(to_core_agg(a), c)
                }
            })
            .collect(),
        joins: q
            .joins
            .into_iter()
            .map(|j| core::Join {
                kind: match j.kind {
                    wit::JoinKind::Inner => core::JoinKind::Inner,
                    wit::JoinKind::LeftJoin => core::JoinKind::Left,
                },
                table: j.table,
                left_column: j.left_column,
                right_column: j.right_column,
            })
            .collect(),
        filter: q.filter.map(to_core_predicate),
        scope: q.scope.map(to_core_scope),
        distinct: q.distinct,
        order: q
            .order
            .into_iter()
            .map(|o| core::OrderBy {
                column: o.column,
                dir: match o.dir {
                    wit::Direction::Asc => core::Direction::Asc,
                    wit::Direction::Desc => core::Direction::Desc,
                },
            })
            .collect(),
        limit: q.limit,
        offset: q.offset,
    }
}

fn to_core_insert(q: wit::Insert) -> core::Insert {
    core::Insert {
        table: q.table,
        rows: q
            .rows
            .into_iter()
            .map(|r| core::RowValues {
                cells: r.cells.into_iter().map(to_core_assignment).collect(),
            })
            .collect(),
        conflict: q.conflict.map(|c| core::OnConflict {
            conflict_columns: c.conflict_columns,
            update: c.update.into_iter().map(to_core_assignment).collect(),
        }),
        scope: q.scope.map(to_core_scope),
    }
}

fn to_core_update(q: wit::Update) -> core::Update {
    core::Update {
        table: q.table,
        set: q.set.into_iter().map(to_core_assignment).collect(),
        filter: to_core_predicate(q.filter),
        scope: q.scope.map(to_core_scope),
    }
}

// ---- core/backend → WIT ----------------------------------------------------

fn to_wit_value(value: SqlValue) -> wit::Value {
    match value {
        SqlValue::Null => wit::Value::Null,
        SqlValue::Boolean(b) => wit::Value::Boolean(b),
        SqlValue::Integer(i) => wit::Value::Integer(i),
        SqlValue::Real(f) => wit::Value::Float(f),
        SqlValue::Text(s) => wit::Value::Text(s),
        SqlValue::Blob(b) => wit::Value::Blob(b),
    }
}

fn not_granted(name: &str) -> wit::Error {
    wit::Error::Other(format!("sql database {name:?} not granted"))
}

/// A compiler error is a malformed query (bad identifier, unbounded update, …) → syntax.
fn compile_err(e: core::OrmError) -> wit::Error {
    wit::Error::Syntax(e.to_string())
}

fn backend_err(err: boatramp_core::sql::SqlError) -> wit::Error {
    use boatramp_core::sql::SqlError;
    match err {
        SqlError::Syntax(m) => wit::Error::Syntax(m),
        SqlError::Constraint(m) => wit::Error::Constraint(m),
        SqlError::Other(m) => wit::Error::Other(m),
    }
}

/// Add the `orm` interface to `linker`, resolving the per-invocation [`OrmHost`] via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> OrmHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    wit::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::wit::{Host, HostDatabase};
    use super::*;
    use async_trait::async_trait;
    use boatramp_core::sql::{SqlBackend, SqlError, SqlRows, SqlTransaction};
    use std::sync::{Arc, Mutex};

    type Log = Arc<Mutex<Vec<String>>>;
    struct FakeBackend {
        log: Log,
    }
    struct FakeTxn {
        log: Log,
    }

    #[async_trait]
    impl SqlBackend for FakeBackend {
        async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            self.log.lock().unwrap().push("begin".into());
            Ok(Box::new(FakeTxn {
                log: self.log.clone(),
            }))
        }
        async fn begin_read_only(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            self.begin().await
        }
    }

    #[async_trait]
    impl SqlTransaction for FakeTxn {
        async fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<SqlRows, SqlError> {
            self.log
                .lock()
                .unwrap()
                .push(format!("query|{sql}|{params:?}"));
            Ok(SqlRows {
                columns: vec!["id".into()],
                rows: vec![vec![SqlValue::Text("row1".into())]],
            })
        }
        async fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
            self.log
                .lock()
                .unwrap()
                .push(format!("execute|{sql}|{params:?}"));
            Ok(1)
        }
        async fn commit(self: Box<Self>) -> Result<(), SqlError> {
            self.log.lock().unwrap().push("commit".into());
            Ok(())
        }
        async fn rollback(self: Box<Self>) -> Result<(), SqlError> {
            Ok(())
        }
    }

    fn session(log: &Log) -> SqlSession {
        let backend: Arc<dyn SqlBackend> = Arc::new(FakeBackend { log: log.clone() });
        SqlSession::for_backends([(String::new(), backend)].into_iter().collect())
    }

    fn text(s: &str) -> wit::Value {
        wit::Value::Text(s.to_string())
    }

    #[tokio::test]
    async fn select_insert_update_compile_and_reach_the_backend() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut sess = session(&log);
        let mut table = ResourceTable::new();
        {
            let mut host = OrmHost::new(&mut table, &mut sess);
            let db = host.open(String::new()).unwrap();
            let rep = db.rep();

            let sel = wit::Select {
                table: "work_order".into(),
                columns: vec![wit::Projection::Column("id".into())],
                joins: vec![],
                filter: Some(wit::Predicate::All(vec![wit::ColumnPredicate {
                    column: "project_id".into(),
                    test: wit::Compare::Eq(text("prj_1")),
                }])),
                scope: Some(wit::Scope {
                    column: "tenant_id".into(),
                    value: text("ten_1"),
                }),
                distinct: false,
                order: vec![wit::OrderBy {
                    column: "created_at".into(),
                    dir: wit::Direction::Desc,
                }],
                limit: Some(10),
                offset: None,
            };
            let res = host.select(db, sel).await.unwrap();
            assert_eq!(res.columns, vec!["id".to_string()]);
            assert!(matches!(&res.rows[0].values[0], wit::Value::Text(s) if s == "row1"));

            let ins = wit::Insert {
                table: "work_area".into(),
                rows: vec![wit::RowValues {
                    cells: vec![wit::Assignment {
                        column: "id".into(),
                        value: text("wa_1"),
                    }],
                }],
                conflict: None,
                scope: Some(wit::Scope {
                    column: "tenant_id".into(),
                    value: text("ten_1"),
                }),
            };
            assert_eq!(host.insert(Resource::new_own(rep), ins).await.unwrap(), 1);

            let upd = wit::Update {
                table: "supplier_invoice".into(),
                set: vec![wit::Assignment {
                    column: "payment_gate".into(),
                    value: text("paid"),
                }],
                filter: wit::Predicate::All(vec![wit::ColumnPredicate {
                    column: "id".into(),
                    test: wit::Compare::Eq(text("inv_1")),
                }]),
                scope: None,
            };
            host.update(Resource::new_own(rep), upd).await.unwrap();
        }
        sess.finalize(true).await;

        let log = log.lock().unwrap();
        assert_eq!(log[0], "begin");
        assert!(log.iter().any(|l| l.starts_with(
            "query|SELECT id FROM work_order WHERE tenant_id = ?1 AND project_id = ?2 ORDER BY created_at DESC LIMIT 10|"
        )));
        assert!(log.iter().any(
            |l| l.starts_with("execute|INSERT INTO work_area (id, tenant_id) VALUES (?1, ?2)|")
        ));
        assert!(log.iter().any(|l| l
            .starts_with("execute|UPDATE supplier_invoice SET payment_gate = ?1 WHERE id = ?2|")));
        assert_eq!(log.last().unwrap(), "commit");
    }

    #[tokio::test]
    async fn unbounded_update_is_refused_before_the_backend() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut sess = session(&log);
        let mut table = ResourceTable::new();
        let mut host = OrmHost::new(&mut table, &mut sess);
        let db = host.open(String::new()).unwrap();
        let upd = wit::Update {
            table: "t".into(),
            set: vec![wit::Assignment {
                column: "x".into(),
                value: wit::Value::Integer(1),
            }],
            filter: wit::Predicate::All(vec![]),
            scope: None,
        };
        let err = host.update(db, upd).await.unwrap_err();
        assert!(matches!(err, wit::Error::Syntax(_)));
        // Refused at compile time — the backend was never opened.
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn open_unknown_database_is_not_granted() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut sess = session(&log); // only the default "" is granted
        let mut table = ResourceTable::new();
        let mut host = OrmHost::new(&mut table, &mut sess);
        assert!(host.open("nope".into()).is_err());
    }
}
