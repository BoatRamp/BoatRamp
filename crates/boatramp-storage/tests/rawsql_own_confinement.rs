//! **Live**, mutation-verified proof of the P0 raw-SQL own/session confinement fix — the
//! `RAWSQL OWN-CONFINEMENT AST OK` gate.
//!
//! The pre-existing hole: the raw-SQL `{scope}` marker for own/session was string-substituted into
//! guest SQL with NO AST check, so a guest `OR`-escaped it (`WHERE 1=1 OR {scope}` → cross-tenant
//! read+write). The fix force-injects the tenant confinement at the AST level for own/session READ
//! and WRITE (`boatramp_core::target_sql::rewrite_own_read`/`rewrite_own_write`), backend-independent,
//! exactly as the target-read path and the `orm` `force_scope`/`read_pred` already do — where the
//! guest can neither move nor `OR`-escape it.
//!
//! This battery drives the **real** rewrite against a **real** SQL engine (embedded libsql, and —
//! env-gated — Postgres + MySQL), holding two tenants' rows (`A`, victim `B`) plus a NULL baseline,
//! and asserts the 8 security invariants BEHAVIORALLY (victim rows unchanged / not disclosed), not
//! structurally. Each assertion is designed to FAIL under a **mutation** that reverts the AST
//! injection to the old escapable string marker: the `RAWSQL_CONFINE_MUTATION` env var swaps
//! `confine_read`/`confine_write` for the marker-substitution path, and a CI step loops the mutations
//! asserting the test then exits non-zero (so a regression that re-opens the hole fails the merge).
//!
//! Greppable gate marker: `RAWSQL OWN-CONFINEMENT AST OK` (mirrors the `… OK` live-gate convention).
#![cfg(any(feature = "sql", feature = "sql-postgres", feature = "sql-mysql"))]

use std::collections::BTreeMap;

use boatramp_core::orm::{
    Assignment, CmpOp, Expr, Predicate, Scope, ScopeMode, Select, SelectItem, TableKeys, Update,
};
use boatramp_core::sql::{Dialect, SqlBackend, SqlTransaction, SqlValue};
use boatramp_core::target_sql::{OwnKeys, OwnScope, rewrite_own_read, rewrite_own_write};
use boatramp_core::tenancy::ResolvedScope;

fn t(s: &str) -> SqlValue {
    SqlValue::Text(s.into())
}

/// The project schema's per-table tenant keys the confinement resolves against. `orders`/`order_lines` are
/// plain tenant tables (`tenant_id`); `catalog` is `Unscoped` (global reference).
fn keys() -> BTreeMap<String, ResolvedScope> {
    BTreeMap::from([
        (
            "orders".to_string(),
            ResolvedScope::Column("tenant_id".to_string()),
        ),
        (
            "order_lines".to_string(),
            ResolvedScope::Column("tenant_id".to_string()),
        ),
        ("catalog".to_string(), ResolvedScope::Unscoped),
    ])
}

/// The `orm` [`Scope`] equivalent of the own confinement, for the cross-surface parity invariant.
fn orm_scope(mode: ScopeMode, own: &str) -> Scope {
    Scope {
        column: "tenant_id".into(),
        value: Some(t(own)),
        session: None,
        mode,
        keys: TableKeys::PerTable(keys()),
    }
}

// ---- the mutation seam ------------------------------------------------------

/// Which mutation is active (from `RAWSQL_CONFINE_MUTATION`) — each reverts the AST injection to a
/// form the P0 fix replaced, so the gate MUST fail under it. `None` = the real fix.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mutation {
    /// No mutation — the real AST-injected confinement (the shipped fix). The gate PASSES.
    None,
    /// Revert to the OLD escapable string marker: substitute `{scope}` with the bare predicate
    /// `tenant_id = 'own'` (the pre-fix behavior). A guest `... OR {scope}` then OR-escapes it. The
    /// gate MUST fail (the victim leaks / is mutated).
    StringMarker,
    /// A weaker mutation: substitute `{scope}` but leave a bare `SELECT`/write with no marker
    /// UNconfined entirely (the "marker not required, so run plain" bug). The gate MUST fail.
    NoConfinement,
}

fn active_mutation() -> Mutation {
    match std::env::var("RAWSQL_CONFINE_MUTATION").as_deref() {
        Ok("string-marker") => Mutation::StringMarker,
        Ok("no-confinement") => Mutation::NoConfinement,
        _ => Mutation::None,
    }
}

/// Confine a READ. Under `Mutation::None` this is the real AST rewrite (the fix); under a mutation it
/// reverts to a form the fix replaced (so the gate detects the regression). The own value + mode are
/// the host-resolved principal (never guest input).
fn confine_read(sql: &str, own: &str, mode: ScopeMode) -> Result<String, String> {
    match active_mutation() {
        Mutation::None => rewrite_read(sql, own, mode),
        // OLD escapable marker: substitute `{scope}` → `tenant_id = 'own'`, leave the rest verbatim.
        Mutation::StringMarker => Ok(old_marker_substitute(sql, own)),
        // No confinement at all (the "marker optional so run plain" misread).
        Mutation::NoConfinement => Ok(sql.replace("{scope}", "1 = 1")),
    }
}

/// Confine a WRITE. Same mutation seam as [`confine_read`].
fn confine_write(sql: &str, own: &str, mode: ScopeMode) -> Result<String, String> {
    match active_mutation() {
        Mutation::None => rewrite_write(sql, own, mode),
        Mutation::StringMarker => Ok(old_marker_substitute(sql, own)),
        Mutation::NoConfinement => Ok(sql.replace("{scope}", "1 = 1")),
    }
}

/// The real fix: AST-rewrite a READ so every table reference is confined to the own partition. A
/// stray `{scope}` marker is neutralised to `1 = 1` first, exactly as the host binding's
/// `apply_scope_marker` does (the marker is now optional/inert — the confinement is host-injected).
fn rewrite_read(sql: &str, own: &str, mode: ScopeMode) -> Result<String, String> {
    let neutralised = sql.replace("{scope}", "1 = 1");
    let own_v = t(own);
    let k = keys();
    let scope = OwnScope {
        own: Some(&own_v),
        session: None,
        mode,
        keys: OwnKeys::PerTable(&k),
    };
    rewrite_own_read(&neutralised, &scope, dialect_of()).map_err(|e| e.reason())
}

/// The real fix: AST-rewrite a WRITE so it is structurally bounded to the own partition (stray
/// `{scope}` neutralised to `1 = 1` first, as `apply_scope_marker` does).
fn rewrite_write(sql: &str, own: &str, mode: ScopeMode) -> Result<String, String> {
    let neutralised = sql.replace("{scope}", "1 = 1");
    let own_v = t(own);
    let k = keys();
    let scope = OwnScope {
        own: Some(&own_v),
        session: None,
        mode,
        keys: OwnKeys::PerTable(&k),
    };
    rewrite_own_write(&neutralised, &scope, dialect_of()).map_err(|e| e.reason())
}

/// The OLD, escapable behavior a mutation reverts to: replace the `{scope}` marker with the bare
/// single-table predicate and leave the guest SQL otherwise verbatim (no parenthesisation, no
/// multi-table confinement) — exactly the hole the P0 fix closed.
fn old_marker_substitute(sql: &str, own: &str) -> String {
    sql.replace("{scope}", &format!("tenant_id = '{own}'"))
}

// The dialect the battery is compiled for (thread-local, set by `run_battery`) — so the mutation
// seam's `confine_read`/`confine_write` can parse under the same dialect the backend runs.
thread_local! {
    static DIALECT: std::cell::Cell<Dialect> = const { std::cell::Cell::new(Dialect::Sqlite) };
}
fn dialect_of() -> Dialect {
    DIALECT.with(std::cell::Cell::get)
}

// ---- run helpers ------------------------------------------------------------

/// Sorted single-column text rows of a query. Under the REAL fix a confined query always runs; under
/// a mutation the reverted (marker-substituted) SQL may be invalid (e.g. an unqualified `tenant_id`
/// is ambiguous across a JOIN) — that is itself a gate failure, so we surface it as a distinctive
/// non-matching row rather than panicking before `Checks::finish`, keeping the mutation's kill set
/// legible. The real fix never hits this arm (its SQL is always valid), so it can't mask a leak.
async fn rows(tx: &mut dyn SqlTransaction, sql: &str, params: &[SqlValue]) -> Vec<String> {
    let r = match tx.query(sql, params).await {
        Ok(r) => r,
        Err(e) => return vec![format!("__CONFINE_SQL_ERROR__: {e:?}")],
    };
    let mut out: Vec<String> = r
        .rows
        .into_iter()
        .flatten()
        .filter_map(|v| match v {
            SqlValue::Text(s) => Some(s),
            _ => None,
        })
        .collect();
    out.sort();
    out
}

/// (Re)seed the schema + rows: two tenants (A, B) + a NULL baseline, on `orders` and `order_lines`.
async fn seed(backend: &dyn SqlBackend) {
    let mut tx = backend.begin().await.unwrap();
    for ddl in [
        "DROP TABLE IF EXISTS orders",
        "DROP TABLE IF EXISTS order_lines",
        "DROP TABLE IF EXISTS catalog",
        "CREATE TABLE orders (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64), status VARCHAR(64))",
        "CREATE TABLE order_lines (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64), order_id VARCHAR(64), detail VARCHAR(64))",
        "CREATE TABLE catalog (sku VARCHAR(64) PRIMARY KEY, name VARCHAR(64))",
    ] {
        tx.execute(ddl, &[]).await.unwrap();
    }
    for (id, tenant, status) in [
        ("oA", Some("A"), "openA"),
        ("oB", Some("B"), "openB"),
        ("oN", None, "baseline"),
    ] {
        tx.execute(
            "INSERT INTO orders (id, tenant_id, status) VALUES (?1, ?2, ?3)",
            &[t(id), tenant.map_or(SqlValue::Null, t), t(status)],
        )
        .await
        .unwrap();
    }
    for (id, tenant, order_id, detail) in [
        ("lA", Some("A"), "oA", "lineA"),
        ("lB", Some("B"), "oB", "lineB"),
    ] {
        tx.execute(
            "INSERT INTO order_lines (id, tenant_id, order_id, detail) VALUES (?1, ?2, ?3, ?4)",
            &[
                t(id),
                tenant.map_or(SqlValue::Null, t),
                t(order_id),
                t(detail),
            ],
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
}

/// The status of order `id`, or `None` if the row is gone.
async fn order_status(backend: &dyn SqlBackend, id: &str) -> Option<String> {
    let mut tx = backend.begin().await.unwrap();
    let r = tx
        .query("SELECT status FROM orders WHERE id = ?1", &[t(id)])
        .await
        .unwrap();
    let out = r.rows.first().and_then(|row| match &row[0] {
        SqlValue::Text(s) => Some(s.clone()),
        _ => None,
    });
    tx.commit().await.unwrap();
    out
}

/// The tenant of order `id` (to prove a write can't re-tenant or land in the wrong tenant).
async fn order_tenant(backend: &dyn SqlBackend, id: &str) -> Option<String> {
    let mut tx = backend.begin().await.unwrap();
    let r = tx
        .query("SELECT tenant_id FROM orders WHERE id = ?1", &[t(id)])
        .await
        .unwrap();
    let out = r.rows.first().and_then(|row| match &row[0] {
        SqlValue::Text(s) => Some(s.clone()),
        _ => None,
    });
    tx.commit().await.unwrap();
    out
}

/// Accumulates per-invariant outcomes so the battery reports EVERY invariant a mutation kills (not
/// just the first). Under the real fix all pass; under a mutation, the ones the mutation re-opens
/// are recorded as failures and the battery panics at the end (non-zero exit for the CI loop).
struct Checks {
    engine: String,
    failures: Vec<String>,
}
impl Checks {
    fn new(engine: &str) -> Self {
        Self {
            engine: engine.to_string(),
            failures: Vec::new(),
        }
    }
    /// Record an equality check. `inv` is the invariant number; `what` describes the breach.
    fn eq<T: PartialEq + std::fmt::Debug>(&mut self, inv: u8, got: T, want: T, what: &str) {
        if got != want {
            self.failures.push(format!(
                "[{}] ({inv}) {what}: got {got:?}, want {want:?}",
                self.engine
            ));
        }
    }
    /// Record a "must be refused" check (fail-closed).
    fn refused<T: std::fmt::Debug>(&mut self, inv: u8, r: &Result<T, String>, what: &str) {
        if r.is_ok() {
            self.failures.push(format!(
                "[{}] ({inv}) {what}: expected a refusal, got {r:?}",
                self.engine
            ));
        }
    }
    /// Finish: pass (print the gate marker) or panic listing every violated invariant.
    fn finish(self) {
        assert!(
            self.failures.is_empty(),
            "[{}] RAWSQL OWN-CONFINEMENT gate FAILED — invariants breached:\n{}",
            self.engine,
            self.failures.join("\n")
        );
        println!("RAWSQL OWN-CONFINEMENT AST OK [{}]", self.engine);
    }
}

/// Run the full 8-invariant battery on `backend`/`dialect`, recording per-invariant outcomes so a
/// mutation's FULL kill set is reported. Passes (prints the marker) under the real fix; fails (panics
/// with the breached invariants) under a mutation — the CI loop asserts that non-zero exit.
async fn run_battery(backend: &dyn SqlBackend, dialect: Dialect, engine: &str) {
    DIALECT.with(|d| d.set(dialect));
    let mut c = Checks::new(engine);

    // (1) WRITE OR-escape neutralized: victim B's rows UNCHANGED.
    seed(backend).await;
    {
        let sql = confine_write(
            "UPDATE orders SET status = 'HACKED' WHERE 1 = 1 OR {scope}",
            "A",
            ScopeMode::Own,
        )
        .expect("confine");
        let mut tx = backend.begin().await.unwrap();
        tx.execute(&sql, &[]).await.unwrap();
        tx.commit().await.unwrap();
        c.eq(
            1,
            order_status(backend, "oB").await,
            Some("openB".to_string()),
            "write OR-escape must NOT touch victim B",
        );
        c.eq(
            1,
            order_status(backend, "oN").await,
            Some("baseline".to_string()),
            "write OR-escape must NOT touch the baseline",
        );
        // A's own row WAS updated (the write still works for the caller — confined, not broken).
        c.eq(
            1,
            order_status(backend, "oA").await,
            Some("HACKED".to_string()),
            "A's own row is updated (the write is not broken)",
        );
    }

    // (2) READ OR-escape neutralized: A sees ONLY A's rows.
    seed(backend).await;
    {
        let sql = confine_read(
            "SELECT status FROM orders WHERE {scope} OR 1 = 1",
            "A",
            ScopeMode::Own,
        )
        .expect("confine");
        let mut tx = backend.begin().await.unwrap();
        let got = rows(tx.as_mut(), &sql, &[]).await;
        tx.commit().await.unwrap();
        c.eq(
            2,
            got,
            vec!["openA".to_string()],
            "read OR-escape must return ONLY A's rows",
        );
    }

    // (3) Multi-table / JOIN / subquery confinement: no leak via a joined / subquery table.
    seed(backend).await;
    {
        let sql = confine_read(
            "SELECT o.status FROM orders o JOIN order_lines l ON l.order_id = o.id WHERE 1 = 1 OR {scope}",
            "A",
            ScopeMode::Own,
        )
        .expect("confine");
        let mut tx = backend.begin().await.unwrap();
        let got = rows(tx.as_mut(), &sql, &[]).await;
        tx.commit().await.unwrap();
        c.eq(
            3,
            got,
            vec!["openA".to_string()],
            "JOIN must confine BOTH tables",
        );
        let sql = confine_read(
            "SELECT status FROM orders WHERE id IN (SELECT order_id FROM order_lines WHERE 1=1 OR {scope})",
            "A",
            ScopeMode::Own,
        )
        .expect("confine");
        let mut tx = backend.begin().await.unwrap();
        let got = rows(tx.as_mut(), &sql, &[]).await;
        tx.commit().await.unwrap();
        c.eq(
            3,
            got,
            vec!["openA".to_string()],
            "subquery must confine the inner table",
        );
    }

    // (4) INSERT force-stamp overrides a guest-supplied victim tenant.
    seed(backend).await;
    {
        let sql = confine_write(
            "INSERT INTO orders (id, tenant_id, status) VALUES ('oNew', 'B', 'new')",
            "A",
            ScopeMode::Own,
        )
        .expect("confine");
        let mut tx = backend.begin().await.unwrap();
        tx.execute(&sql, &[]).await.unwrap();
        tx.commit().await.unwrap();
        c.eq(
            4,
            order_tenant(backend, "oNew").await,
            Some("A".to_string()),
            "INSERT must stamp the OWN tenant, overriding the guest's forged 'B'",
        );
    }

    // (5) UPDATE cannot re-tenant: A's row stays tenant A.
    seed(backend).await;
    {
        let sql = confine_write(
            "UPDATE orders SET tenant_id = 'B', status = 'moved' WHERE id = 'oA'",
            "A",
            ScopeMode::Own,
        )
        .expect("confine");
        let mut tx = backend.begin().await.unwrap();
        tx.execute(&sql, &[]).await.unwrap();
        tx.commit().await.unwrap();
        c.eq(
            5,
            order_tenant(backend, "oA").await,
            Some("A".to_string()),
            "UPDATE must NOT re-tenant A's row to B",
        );
    }

    // (6) OwnOrNull / NullOnly parity with the ORM (base-inclusive / baseline-only reads).
    seed(backend).await;
    {
        let sql = confine_read(
            "SELECT status FROM orders WHERE {scope}",
            "A",
            ScopeMode::OwnOrNull,
        )
        .expect("confine");
        let mut tx = backend.begin().await.unwrap();
        let got = rows(tx.as_mut(), &sql, &[]).await;
        tx.commit().await.unwrap();
        c.eq(
            6,
            got,
            vec!["baseline".to_string(), "openA".to_string()],
            "OwnOrNull = A + baseline, never B",
        );
        let sql = confine_read(
            "SELECT status FROM orders WHERE {scope}",
            "A",
            ScopeMode::NullOnly,
        )
        .expect("confine");
        let mut tx = backend.begin().await.unwrap();
        let got = rows(tx.as_mut(), &sql, &[]).await;
        tx.commit().await.unwrap();
        c.eq(
            6,
            got,
            vec!["baseline".to_string()],
            "NullOnly = baseline only",
        );
    }

    // (7) Cross-surface parity: the SAME confined read via raw `sql` and via the `orm` binding return
    // the identical row set (the load-bearing invariant — scoping one surface but not the other is a
    // bypass). Run an own read both ways and compare.
    seed(backend).await;
    {
        let raw_sql = confine_read(
            "SELECT status FROM orders WHERE {scope}",
            "A",
            ScopeMode::Own,
        )
        .expect("confine");
        let mut tx = backend.begin().await.unwrap();
        let raw = rows(tx.as_mut(), &raw_sql, &[]).await;
        tx.commit().await.unwrap();

        let mut sel = Select {
            columns: vec![SelectItem {
                expr: Expr::col("status"),
                alias: None,
            }],
            ..Select::from("orders")
        };
        sel.force_scope(&orm_scope(ScopeMode::Own, "A")).unwrap();
        let (orm_sql, orm_params) = sel.compile(dialect).unwrap();
        let mut tx = backend.begin().await.unwrap();
        let orm = rows(tx.as_mut(), &orm_sql, &orm_params).await;
        tx.commit().await.unwrap();

        c.eq(
            7,
            raw.clone(),
            orm,
            "raw `sql` and `orm` must confine a read identically",
        );
        c.eq(
            7,
            raw,
            vec!["openA".to_string()],
            "both surfaces return ONLY A's rows",
        );

        // Cross-surface WRITE parity: an ORM UPDATE with a re-tenant + OR-escape is equally confined.
        seed(backend).await;
        let mut upd = Update {
            table: "orders".into(),
            set: vec![
                Assignment {
                    column: "tenant_id".into(),
                    value: Expr::val(t("B")),
                },
                Assignment {
                    column: "status".into(),
                    value: Expr::val(t("ormedit")),
                },
            ],
            filter: Predicate::Or(vec![
                Predicate::Cmp {
                    left: Expr::col("id"),
                    op: CmpOp::Eq,
                    right: Expr::val(t("oB")),
                },
                Predicate::Cmp {
                    left: Expr::val(SqlValue::Integer(1)),
                    op: CmpOp::Eq,
                    right: Expr::val(SqlValue::Integer(1)),
                },
            ]),
            scope: None,
            returning: vec![],
        };
        upd.force_scope(&orm_scope(ScopeMode::Own, "A")).unwrap();
        let (sql, params) = upd.compile(dialect).unwrap();
        let mut tx = backend.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        tx.commit().await.unwrap();
        c.eq(
            7,
            order_status(backend, "oB").await,
            Some("openB".to_string()),
            "ORM UPDATE OR-escape must NOT touch B either",
        );
        c.eq(
            7,
            order_tenant(backend, "oB").await,
            Some("B".to_string()),
            "ORM UPDATE must NOT re-tenant B",
        );
    }

    // (8) Fail-closed: unparseable / no-principal / undeclared / Unscoped-write are REFUSED (never
    // run), and a DELETE OR-escape is confined. The refusals are a property of the real AST rewrite
    // (a mutation's marker-substitution does not error) — so they are asserted only under the real
    // fix; the DELETE OR-escape leak (below) is what a mutation re-opens on this invariant.
    if active_mutation() == Mutation::None {
        c.refused(
            8,
            &rewrite_read("NOT SQL ;;", "A", ScopeMode::Own),
            "unparseable must be refused",
        );
        c.refused(
            8,
            &rewrite_read("SELECT * FROM secrets", "A", ScopeMode::Own),
            "undeclared table must be refused",
        );
        {
            let k = keys();
            let scope = OwnScope {
                own: None,
                session: None,
                mode: ScopeMode::Own,
                keys: OwnKeys::PerTable(&k),
            };
            c.refused(
                8,
                &rewrite_own_write("UPDATE orders SET status='x' WHERE id=1", &scope, dialect)
                    .map_err(|e| e.reason()),
                "no-principal own write must be refused",
            );
        }
        c.refused(
            8,
            &rewrite_write("DELETE FROM catalog WHERE sku='x'", "A", ScopeMode::Own),
            "Unscoped write must be refused (global writes are ORM-only)",
        );
    }
    // A DELETE OR-escape is confined regardless of mutation state (a mutation re-opens it here too).
    seed(backend).await;
    {
        let sql = confine_write(
            "DELETE FROM orders WHERE 1=1 OR {scope}",
            "A",
            ScopeMode::Own,
        )
        .expect("confine");
        let mut tx = backend.begin().await.unwrap();
        tx.execute(&sql, &[]).await.unwrap();
        tx.commit().await.unwrap();
        c.eq(
            8,
            order_status(backend, "oB").await,
            Some("openB".to_string()),
            "DELETE OR-escape must NOT delete victim B",
        );
        c.eq(
            8,
            order_status(backend, "oA").await,
            None,
            "A's own row IS deleted (the delete is confined, not broken)",
        );
    }

    c.finish();
}

// ---- libsql / SQLite (unconditional, but `#[ignore]`d — see the ORM battery note) --------------

#[cfg(feature = "sql")]
#[tokio::test]
#[ignore = "run via the rawsql-own-confinement CI job on the host toolchain (static-musl libsql segfault)"]
async fn rawsql_own_confinement_libsql() {
    use boatramp_core::sql::SqlBackends;
    use boatramp_storage::LibsqlSqlBackends;
    let dir = std::env::temp_dir().join(format!("boatramp-rawsql-confine-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let backends = LibsqlSqlBackends::local(&dir);
    let db = backends.database("default", "shop", "").await.unwrap();
    run_battery(db.as_ref(), Dialect::Sqlite, "libsql").await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- Postgres + MySQL (env-gated, matching the sqlx-live batteries) -----------------------------

#[cfg(feature = "sql-postgres")]
#[tokio::test]
async fn rawsql_own_confinement_postgres() {
    use boatramp_storage::sql_sqlx::{ExternalSqlKind, ExternalSqlOptions, connect};
    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip rawsql_own_confinement_postgres: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let backend = connect(ExternalSqlKind::Postgres, &ExternalSqlOptions::new(url)).unwrap();
    run_battery(backend.as_ref(), Dialect::Postgres, "postgres").await;
}

#[cfg(feature = "sql-mysql")]
#[tokio::test]
async fn rawsql_own_confinement_mysql() {
    use boatramp_storage::sql_sqlx::{ExternalSqlKind, ExternalSqlOptions, connect};
    let Ok(url) = std::env::var("BOATRAMP_TEST_MYSQL_URL") else {
        eprintln!("skip rawsql_own_confinement_mysql: BOATRAMP_TEST_MYSQL_URL unset");
        return;
    };
    let backend = connect(ExternalSqlKind::Mysql, &ExternalSqlOptions::new(url)).unwrap();
    run_battery(backend.as_ref(), Dialect::Mysql, "mysql").await;
}
