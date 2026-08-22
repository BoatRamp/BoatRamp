//! The `orm` host binding: a typed query interface (`boatramp:handlers/orm`) that compiles
//! guest-supplied query ASTs to injection-safe `?N` SQL via [`boatramp_core::orm`] and runs
//! them through the **same** per-invocation [`SqlSession`] as the raw [`sql`](super::sql)
//! binding — so a handler may mix `orm` and `sql` on one database within one transaction.
//!
//! The recursive expression/predicate trees cross the WIT boundary as **flat index arenas**
//! (`exprs` / `preds`), because WIT value types can't be recursive. This module rebuilds the
//! [`boatramp_core::orm`] tree from those arenas, **validating** every index (in range, and a
//! child always at a strictly-lower index → acyclic) so a malformed arena from the guest is
//! rejected rather than trusted. The compiler (in `boatramp-core`) then does the SQL
//! generation + safety; the SQL dialect comes from the resolved [`SqlBackend`].

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
        q: wit::SelectQuery,
    ) -> Result<wit::QueryResult, wit::Error> {
        let name = self.name_of(&db)?;
        let dialect = self.session.dialect(&name);
        let (sql, params) = to_core_select(&q)?.compile(dialect).map_err(compile_err)?;
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
        q: wit::InsertQuery,
    ) -> Result<u64, wit::Error> {
        let name = self.name_of(&db)?;
        let dialect = self.session.dialect(&name);
        let (sql, params) = to_core_insert(&q)?.compile(dialect).map_err(compile_err)?;
        let txn = self.session.txn(&name, false).await.map_err(backend_err)?;
        txn.execute(&sql, &params).await.map_err(backend_err)
    }

    async fn update(
        &mut self,
        db: Resource<OrmDatabase>,
        q: wit::UpdateQuery,
    ) -> Result<u64, wit::Error> {
        let name = self.name_of(&db)?;
        let dialect = self.session.dialect(&name);
        let (sql, params) = to_core_update(&q)?.compile(dialect).map_err(compile_err)?;
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

// ---- arena → core tree -----------------------------------------------------

fn bad_arena(msg: &'static str) -> wit::Error {
    wit::Error::Syntax(format!("malformed orm query arena: {msg}"))
}

/// Rebuild a core [`Expr`](core::Expr) from the `exprs` arena at `idx`. A child reference must
/// be strictly less than its parent's index, which makes the arena acyclic (and this recursion
/// terminating) and is rejected otherwise.
fn build_expr(exprs: &[wit::ExprNode], idx: u32) -> Result<core::Expr, wit::Error> {
    let i = idx as usize;
    let node = exprs.get(i).ok_or(bad_arena("expr index out of range"))?;
    let child = |c: u32| -> Result<core::Expr, wit::Error> {
        if c as usize >= i {
            return Err(bad_arena("expr child index must be < its parent"));
        }
        build_expr(exprs, c)
    };
    Ok(match node {
        wit::ExprNode::Column(s) => core::Expr::Column(s.clone()),
        wit::ExprNode::Literal(v) => core::Expr::Value(to_sqlvalue(v.clone())),
        wit::ExprNode::Star => core::Expr::Star,
        wit::ExprNode::Aggregate(a) => {
            core::Expr::Aggregate(to_core_agg(a.agg), Box::new(child(a.arg)?))
        }
        wit::ExprNode::Binary(b) => core::Expr::Binary(
            to_core_binop(b.op),
            Box::new(child(b.left)?),
            Box::new(child(b.right)?),
        ),
        wit::ExprNode::Call(c) => core::Expr::Func(
            to_core_func(c.which),
            c.args.iter().map(|&a| child(a)).collect::<Result<_, _>>()?,
        ),
        wit::ExprNode::JsonExtract(j) => {
            core::Expr::JsonExtract(Box::new(child(j.base)?), j.path.clone())
        }
    })
}

/// Rebuild a core [`Predicate`](core::Predicate) from the `preds` arena at `idx` (same
/// strictly-lower-child rule for the boolean children; scalar fields reference `exprs`).
fn build_pred(
    preds: &[wit::PredNode],
    exprs: &[wit::ExprNode],
    idx: u32,
) -> Result<core::Predicate, wit::Error> {
    let i = idx as usize;
    let node = preds.get(i).ok_or(bad_arena("pred index out of range"))?;
    let pchild = |c: u32| -> Result<core::Predicate, wit::Error> {
        if c as usize >= i {
            return Err(bad_arena("pred child index must be < its parent"));
        }
        build_pred(preds, exprs, c)
    };
    Ok(match node {
        wit::PredNode::Conj(cs) => {
            core::Predicate::And(cs.iter().map(|&c| pchild(c)).collect::<Result<_, _>>()?)
        }
        wit::PredNode::Disj(cs) => {
            core::Predicate::Or(cs.iter().map(|&c| pchild(c)).collect::<Result<_, _>>()?)
        }
        wit::PredNode::Negate(c) => core::Predicate::Not(Box::new(pchild(*c)?)),
        wit::PredNode::Compare(c) => core::Predicate::Cmp {
            left: build_expr(exprs, c.left)?,
            op: to_core_cmpop(c.op),
            right: build_expr(exprs, c.right)?,
        },
        wit::PredNode::Between(b) => core::Predicate::Between {
            expr: build_expr(exprs, b.expr)?,
            low: build_expr(exprs, b.low)?,
            high: build_expr(exprs, b.high)?,
            negated: b.negated,
        },
        wit::PredNode::Within(n) => core::Predicate::In {
            expr: build_expr(exprs, n.expr)?,
            values: n
                .values
                .iter()
                .map(|&v| build_expr(exprs, v))
                .collect::<Result<_, _>>()?,
            negated: n.negated,
        },
        wit::PredNode::Matches(l) => core::Predicate::Like {
            expr: build_expr(exprs, l.expr)?,
            pattern: l.pattern.clone(),
            insensitive: l.insensitive,
            negated: l.negated,
        },
        wit::PredNode::IsNull(n) => core::Predicate::Null {
            expr: build_expr(exprs, n.expr)?,
            negated: n.negated,
        },
    })
}

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

fn to_core_agg(a: wit::Agg) -> core::Agg {
    match a {
        wit::Agg::Count => core::Agg::Count,
        wit::Agg::Sum => core::Agg::Sum,
        wit::Agg::Avg => core::Agg::Avg,
        wit::Agg::Min => core::Agg::Min,
        wit::Agg::Max => core::Agg::Max,
    }
}

fn to_core_binop(o: wit::BinOp) -> core::BinOp {
    match o {
        wit::BinOp::Add => core::BinOp::Add,
        wit::BinOp::Sub => core::BinOp::Sub,
        wit::BinOp::Mul => core::BinOp::Mul,
        wit::BinOp::Div => core::BinOp::Div,
        wit::BinOp::Modulo => core::BinOp::Mod,
    }
}

fn to_core_func(f: wit::ScalarFunc) -> core::Func {
    match f {
        wit::ScalarFunc::LowerCase => core::Func::Lower,
        wit::ScalarFunc::UpperCase => core::Func::Upper,
        wit::ScalarFunc::Length => core::Func::Length,
        wit::ScalarFunc::Trim => core::Func::Trim,
        wit::ScalarFunc::Abs => core::Func::Abs,
        wit::ScalarFunc::Round => core::Func::Round,
        wit::ScalarFunc::Coalesce => core::Func::Coalesce,
        wit::ScalarFunc::Now => core::Func::Now,
    }
}

fn to_core_cmpop(o: wit::CmpOp) -> core::CmpOp {
    match o {
        wit::CmpOp::Eq => core::CmpOp::Eq,
        wit::CmpOp::Ne => core::CmpOp::Ne,
        wit::CmpOp::Lt => core::CmpOp::Lt,
        wit::CmpOp::Le => core::CmpOp::Le,
        wit::CmpOp::Gt => core::CmpOp::Gt,
        wit::CmpOp::Ge => core::CmpOp::Ge,
    }
}

fn to_core_joinkind(k: wit::JoinKind) -> core::JoinKind {
    match k {
        wit::JoinKind::Inner => core::JoinKind::Inner,
        wit::JoinKind::LeftJoin => core::JoinKind::Left,
    }
}

fn to_core_dir(d: wit::Direction) -> core::Direction {
    match d {
        wit::Direction::Asc => core::Direction::Asc,
        wit::Direction::Desc => core::Direction::Desc,
    }
}

fn to_core_scope(s: wit::Scope) -> core::Scope {
    core::Scope {
        column: s.column,
        value: to_sqlvalue(s.value),
    }
}

fn to_core_item(
    exprs: &[wit::ExprNode],
    it: &wit::SelectItem,
) -> Result<core::SelectItem, wit::Error> {
    Ok(core::SelectItem {
        expr: build_expr(exprs, it.expr)?,
        alias: it.alias.clone(),
    })
}

fn to_core_assignment(
    exprs: &[wit::ExprNode],
    a: &wit::Assignment,
) -> Result<core::Assignment, wit::Error> {
    Ok(core::Assignment {
        column: a.column.clone(),
        value: build_expr(exprs, a.value)?,
    })
}

fn to_core_select(q: &wit::SelectQuery) -> Result<core::Select, wit::Error> {
    let exprs = &q.exprs;
    let preds = &q.preds;
    Ok(core::Select {
        table: q.table.clone(),
        table_alias: q.table_alias.clone(),
        columns: q
            .columns
            .iter()
            .map(|it| to_core_item(exprs, it))
            .collect::<Result<_, _>>()?,
        joins: q
            .joins
            .iter()
            .map(|j| {
                Ok::<_, wit::Error>(core::Join {
                    kind: to_core_joinkind(j.kind),
                    table: j.table.clone(),
                    alias: j.alias.clone(),
                    on: build_pred(preds, exprs, j.on)?,
                })
            })
            .collect::<Result<_, _>>()?,
        filter: q.filter.map(|f| build_pred(preds, exprs, f)).transpose()?,
        scope: q.scope.clone().map(to_core_scope),
        group_by: q
            .group_by
            .iter()
            .map(|&g| build_expr(exprs, g))
            .collect::<Result<_, _>>()?,
        having: q.having.map(|h| build_pred(preds, exprs, h)).transpose()?,
        distinct: q.distinct,
        order: q
            .order
            .iter()
            .map(|o| {
                Ok::<_, wit::Error>(core::OrderBy {
                    expr: build_expr(exprs, o.expr)?,
                    dir: to_core_dir(o.dir),
                })
            })
            .collect::<Result<_, _>>()?,
        limit: q.limit,
        offset: q.offset,
    })
}

fn to_core_insert(q: &wit::InsertQuery) -> Result<core::Insert, wit::Error> {
    let exprs = &q.exprs;
    Ok(core::Insert {
        table: q.table.clone(),
        rows: q
            .rows
            .iter()
            .map(|r| {
                Ok::<_, wit::Error>(core::RowValues {
                    cells: r
                        .cells
                        .iter()
                        .map(|a| to_core_assignment(exprs, a))
                        .collect::<Result<_, _>>()?,
                })
            })
            .collect::<Result<_, _>>()?,
        conflict: q
            .conflict
            .as_ref()
            .map(|c| {
                Ok::<_, wit::Error>(core::OnConflict {
                    conflict_columns: c.conflict_columns.clone(),
                    update: c
                        .update
                        .iter()
                        .map(|a| to_core_assignment(exprs, a))
                        .collect::<Result<_, _>>()?,
                })
            })
            .transpose()?,
        scope: q.scope.clone().map(to_core_scope),
        returning: q
            .returning
            .iter()
            .map(|it| to_core_item(exprs, it))
            .collect::<Result<_, _>>()?,
    })
}

fn to_core_update(q: &wit::UpdateQuery) -> Result<core::Update, wit::Error> {
    let exprs = &q.exprs;
    let preds = &q.preds;
    Ok(core::Update {
        table: q.table.clone(),
        set: q
            .set
            .iter()
            .map(|a| to_core_assignment(exprs, a))
            .collect::<Result<_, _>>()?,
        filter: build_pred(preds, exprs, q.filter)?,
        scope: q.scope.clone().map(to_core_scope),
        returning: q
            .returning
            .iter()
            .map(|it| to_core_item(exprs, it))
            .collect::<Result<_, _>>()?,
    })
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
    fn col(name: &str) -> wit::ExprNode {
        wit::ExprNode::Column(name.to_string())
    }
    fn lit(v: wit::Value) -> wit::ExprNode {
        wit::ExprNode::Literal(v)
    }
    fn item(idx: u32) -> wit::SelectItem {
        wit::SelectItem {
            expr: idx,
            alias: None,
        }
    }
    fn cmp(left: u32, op: wit::CmpOp, right: u32) -> wit::PredNode {
        wit::PredNode::Compare(wit::CompareNode { left, op, right })
    }
    fn scope(column: &str, v: wit::Value) -> wit::Scope {
        wit::Scope {
            column: column.to_string(),
            value: v,
        }
    }

    fn empty_select(table: &str) -> wit::SelectQuery {
        wit::SelectQuery {
            exprs: vec![],
            preds: vec![],
            table: table.to_string(),
            table_alias: None,
            columns: vec![],
            joins: vec![],
            filter: None,
            scope: None,
            group_by: vec![],
            having: None,
            distinct: false,
            order: vec![],
            limit: None,
            offset: None,
        }
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

            // SELECT id FROM work_order WHERE tenant_id=? AND project_id=? ORDER BY created_at DESC LIMIT 10
            let sel = wit::SelectQuery {
                exprs: vec![
                    col("id"),          // 0
                    col("project_id"),  // 1
                    lit(text("prj_1")), // 2
                    col("created_at"),  // 3
                ],
                preds: vec![cmp(1, wit::CmpOp::Eq, 2)], // 0
                columns: vec![item(0)],
                filter: Some(0),
                scope: Some(scope("tenant_id", text("ten_1"))),
                order: vec![wit::OrderTerm {
                    expr: 3,
                    dir: wit::Direction::Desc,
                }],
                limit: Some(10),
                ..empty_select("work_order")
            };
            let res = host.select(db, sel).await.unwrap();
            assert_eq!(res.columns, vec!["id".to_string()]);
            assert!(matches!(&res.rows[0].values[0], wit::Value::Text(s) if s == "row1"));

            // INSERT INTO work_area (id, tenant_id) VALUES (?, ?)
            let ins = wit::InsertQuery {
                exprs: vec![lit(text("wa_1"))],
                table: "work_area".into(),
                rows: vec![wit::RowValues {
                    cells: vec![wit::Assignment {
                        column: "id".into(),
                        value: 0,
                    }],
                }],
                conflict: None,
                scope: Some(scope("tenant_id", text("ten_1"))),
                returning: vec![],
            };
            assert_eq!(host.insert(Resource::new_own(rep), ins).await.unwrap(), 1);

            // UPDATE supplier_invoice SET payment_gate=? WHERE id=?
            let upd = wit::UpdateQuery {
                exprs: vec![lit(text("paid")), col("id"), lit(text("inv_1"))],
                preds: vec![cmp(1, wit::CmpOp::Eq, 2)],
                table: "supplier_invoice".into(),
                set: vec![wit::Assignment {
                    column: "payment_gate".into(),
                    value: 0,
                }],
                filter: 0,
                scope: None,
                returning: vec![],
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
    async fn nested_predicate_and_aggregate_rebuild_from_the_arena() {
        // SELECT count(*) FROM t WHERE (a = ? OR b = ?) AND NOT c = ?
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut sess = session(&log);
        let mut table = ResourceTable::new();
        let mut host = OrmHost::new(&mut table, &mut sess);
        let db = host.open(String::new()).unwrap();

        let sel = wit::SelectQuery {
            exprs: vec![
                wit::ExprNode::Star,            // 0
                col("a"),                       // 1
                lit(wit::Value::Integer(1)),    // 2
                col("b"),                       // 3
                lit(wit::Value::Integer(2)),    // 4
                col("c"),                       // 5
                lit(wit::Value::Boolean(true)), // 6
            ],
            preds: vec![
                cmp(1, wit::CmpOp::Eq, 2),       // 0: a = ?
                cmp(3, wit::CmpOp::Eq, 4),       // 1: b = ?
                wit::PredNode::Disj(vec![0, 1]), // 2: (a=? OR b=?)
                cmp(5, wit::CmpOp::Eq, 6),       // 3: c = ?
                wit::PredNode::Negate(3),        // 4: NOT c=?
                wit::PredNode::Conj(vec![2, 4]), // 5: (..) AND NOT ..
            ],
            columns: vec![item(0)], // count(*) via aggregate below
            filter: Some(5),
            ..empty_select("t")
        };
        // Turn column 0 (Star) into count(*) by wrapping it — rebuild the select with an
        // aggregate select-item instead.
        let sel = wit::SelectQuery {
            exprs: {
                let mut e = sel.exprs;
                e.push(wit::ExprNode::Aggregate(wit::AggNode {
                    agg: wit::Agg::Count,
                    arg: 0,
                })); // 7: count(*)
                e
            },
            columns: vec![item(7)],
            ..sel
        };
        host.select(db, sel).await.unwrap();

        let log = log.lock().unwrap();
        assert!(
            log.iter().any(|l| l.starts_with(
                "query|SELECT count(*) FROM t WHERE (a = ?1 OR b = ?2) AND NOT c = ?3|"
            )),
            "got: {log:?}"
        );
    }

    #[tokio::test]
    async fn a_forward_arena_index_is_rejected() {
        // A pred whose child references itself/forward (>= its own index) must be refused.
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut sess = session(&log);
        let mut table = ResourceTable::new();
        let mut host = OrmHost::new(&mut table, &mut sess);
        let db = host.open(String::new()).unwrap();
        let sel = wit::SelectQuery {
            preds: vec![wit::PredNode::Negate(0)], // 0 references 0 → cycle
            filter: Some(0),
            ..empty_select("t")
        };
        let err = host.select(db, sel).await.unwrap_err();
        assert!(matches!(err, wit::Error::Syntax(_)));
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unbounded_update_is_refused_before_the_backend() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut sess = session(&log);
        let mut table = ResourceTable::new();
        let mut host = OrmHost::new(&mut table, &mut sess);
        let db = host.open(String::new()).unwrap();
        let upd = wit::UpdateQuery {
            exprs: vec![lit(wit::Value::Integer(1))],
            preds: vec![wit::PredNode::Conj(vec![])], // empty AND, no scope
            table: "t".into(),
            set: vec![wit::Assignment {
                column: "x".into(),
                value: 0,
            }],
            filter: 0,
            scope: None,
            returning: vec![],
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
