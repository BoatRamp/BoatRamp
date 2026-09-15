//! **Live** proof that the Stage 0 in-site tenant scope isolates tenants on a real **Postgres**
//! and **MySQL** engine — the companion to `orm_tenant_isolation.rs` (which proves it on libsql /
//! SQLite). The ORM compiles the scope into portable `?N` SQL that the external-SQL backend
//! rewrites to each engine's native placeholder style (`$N` on Postgres, `?` on MySQL); a
//! per-dialect rendering bug in the scoped predicate (placeholder renumbering, column quoting, a
//! dialect-specific clause) could silently drop the tenant filter on one engine but not another,
//! so isolation must be proven on each engine the ORM targets, not just SQLite.
//!
//! **Env-gated**, matching `sql_sqlx_live.rs`: each engine's battery runs only when its
//! `BOATRAMP_TEST_{PG,MYSQL}_URL` is set (so `cargo test` is green without a database) and prints
//! an engine-tagged success marker. The `test-orm-tenancy-sqlx` CI job brings up `postgres:` +
//! `mysql:` service containers, sets the URLs, and greps the markers — so a silent skip OR a
//! cross-tenant regression on either engine fails the merge ([[ignore-gated-tests-not-evidence]]).
#![cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]

use boatramp_core::orm::{
    Assignment, CmpOp, Delete, Direction, Expr, Insert, Join, JoinKind, OrderBy, Predicate,
    RowValues, Scope, ScopeMode, Select, SelectItem, TableKeys, Update,
};
use boatramp_core::sql::{Dialect, SqlBackend, SqlValue};
use std::sync::Arc;

#[allow(unused_imports)]
use boatramp_storage::sql_sqlx::{connect, ExternalSqlKind, ExternalSqlOptions};

fn t(s: &str) -> SqlValue {
    SqlValue::Text(s.into())
}
fn scope(mode: ScopeMode, value: &str) -> Scope {
    Scope {
        column: "tenant_id".into(),
        value: Some(t(value)),
        session: None,
        mode,
        keys: TableKeys::Uniform,
    }
}
fn item(e: Expr) -> SelectItem {
    SelectItem {
        expr: e,
        alias: None,
    }
}

/// Run a compiled (sql, params) on the backend, returning the single-column text rows sorted.
async fn run_query(
    tx: &mut dyn boatramp_core::sql::SqlTransaction,
    sql: &str,
    params: &[SqlValue],
) -> Vec<String> {
    let rows = tx.query(sql, params).await.expect("query runs");
    let mut out: Vec<String> = rows
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

/// The full isolation battery — identical in intent to the libsql gate, parameterised over the
/// target `dialect` so it drives the host's real per-engine compilation. Portable DDL (`VARCHAR`,
/// no reserved names) so one body runs on both Postgres and MySQL.
async fn run_battery(backend: Arc<dyn SqlBackend>, dialect: Dialect, engine: &str) {
    // Fresh schema (idempotent across a reused service-container DB).
    {
        let mut tx = backend.begin().await.unwrap();
        for ddl in [
            "DROP TABLE IF EXISTS note_lines",
            "DROP TABLE IF EXISTS notes",
            "CREATE TABLE notes (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64), body VARCHAR(255))",
            "CREATE TABLE note_lines (id VARCHAR(64), tenant_id VARCHAR(64), note_id VARCHAR(64), detail VARCHAR(255))",
        ] {
            tx.execute(ddl, &[]).await.unwrap();
        }
        for (id, tenant, body) in [
            ("a1", Some("acme"), "acme-secret"),
            ("g1", Some("globex"), "globex-secret"),
            ("s1", None, "shared-baseline"),
        ] {
            tx.execute(
                "INSERT INTO notes (id, tenant_id, body) VALUES (?1, ?2, ?3)",
                &[t(id), tenant.map_or(SqlValue::Null, t), t(body)],
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
    }

    // A host-scoped SELECT of `body` for the given read mode, compiled for THIS engine's dialect.
    let select_bodies = |mode: ScopeMode, tenant: &str| {
        let mut s = Select {
            columns: vec![item(Expr::col("body"))],
            ..Select::from("notes")
        };
        s.force_scope(&scope(mode, tenant)).unwrap();
        s.compile(dialect).unwrap()
    };

    // 1) own (acme) sees ONLY acme — never globex, never the baseline.
    {
        let mut tx = backend.begin().await.unwrap();
        let (sql, params) = select_bodies(ScopeMode::Own, "acme");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["acme-secret".to_string()],
            "[{engine}] own = acme-only"
        );
        tx.commit().await.unwrap();
    }

    // 2) own+null (acme) sees acme + the shared baseline, but NOT globex.
    {
        let mut tx = backend.begin().await.unwrap();
        let (sql, params) = select_bodies(ScopeMode::OwnOrNull, "acme");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["acme-secret".to_string(), "shared-baseline".to_string()],
            "[{engine}] own+null = acme + baseline, no globex"
        );
        tx.commit().await.unwrap();
    }

    // 3) null-only sees ONLY the shared baseline.
    {
        let mut tx = backend.begin().await.unwrap();
        let (sql, params) = select_bodies(ScopeMode::NullOnly, "acme");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["shared-baseline".to_string()],
            "[{engine}] null = baseline only"
        );
        tx.commit().await.unwrap();
    }

    // 4) all (cross-tenant) sees everything — the deliberately-opened grant.
    {
        let mut tx = backend.begin().await.unwrap();
        let (sql, params) = select_bodies(ScopeMode::All, "acme");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(got.len(), 3, "[{engine}] all sees every row");
        tx.commit().await.unwrap();
    }

    // 5) A scoped INSERT stamps the tenant; a guest-forged tenant_id is overridden to own.
    {
        let mut ins = Insert {
            table: "notes".into(),
            rows: vec![RowValues {
                cells: vec![
                    Assignment {
                        column: "id".into(),
                        value: Expr::val(t("a2")),
                    },
                    Assignment {
                        column: "tenant_id".into(),
                        value: Expr::val(t("globex")), // forgery attempt
                    },
                    Assignment {
                        column: "body".into(),
                        value: Expr::val(t("acme-new")),
                    },
                ],
            }],
            conflict: None,
            scope: None,
            returning: vec![],
            from_select: None,
        };
        ins.force_scope(
            Some(&scope(ScopeMode::Own, "acme")),
            Some(&scope(ScopeMode::Own, "acme")),
        )
        .unwrap();
        let (sql, params) = ins.compile(dialect).unwrap();
        let mut tx = backend.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        let owner = tx
            .query("SELECT tenant_id FROM notes WHERE id = 'a2'", &[])
            .await
            .unwrap();
        assert_eq!(
            owner.rows[0][0],
            t("acme"),
            "[{engine}] insert stamped own, forgery ignored"
        );
        tx.commit().await.unwrap();
    }

    // 6) A scoped UPDATE only touches own rows AND can't reassign the tenant.
    {
        let mut upd = Update {
            table: "notes".into(),
            set: vec![
                Assignment {
                    column: "tenant_id".into(),
                    value: Expr::val(t("globex")), // reassignment attempt
                },
                Assignment {
                    column: "body".into(),
                    value: Expr::val(t("acme-edited")),
                },
            ],
            filter: Predicate::And(Vec::new()),
            scope: None,
            returning: vec![],
        };
        upd.force_scope(&scope(ScopeMode::Own, "acme")).unwrap();
        let (sql, params) = upd.compile(dialect).unwrap();
        let mut tx = backend.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        let g = tx
            .query("SELECT body FROM notes WHERE id = 'g1'", &[])
            .await
            .unwrap();
        assert_eq!(
            g.rows[0][0],
            t("globex-secret"),
            "[{engine}] globex row untouched by acme's update"
        );
        let owners = run_query(
            tx.as_mut(),
            "SELECT DISTINCT tenant_id FROM notes WHERE body LIKE 'acme%'",
            &[],
        )
        .await;
        assert_eq!(
            owners,
            vec!["acme".to_string()],
            "[{engine}] acme rows stay acme"
        );
        tx.commit().await.unwrap();
    }

    // 7) A scoped DELETE only removes own rows.
    {
        let mut del = Delete {
            table: "notes".into(),
            filter: Predicate::And(Vec::new()),
            scope: None,
            returning: vec![],
        };
        del.force_scope(&scope(ScopeMode::Own, "acme")).unwrap();
        let (sql, params) = del.compile(dialect).unwrap();
        let mut tx = backend.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        let survivors = run_query(tx.as_mut(), "SELECT id FROM notes", &[]).await;
        assert_eq!(
            survivors,
            vec!["g1".to_string(), "s1".to_string()],
            "[{engine}] acme's DELETE-all left globex + baseline"
        );
        tx.commit().await.unwrap();
    }

    // 8) A scoped SELECT with a guest JOIN scopes BOTH tables — a joined victim table can't leak.
    {
        let mut tx = backend.begin().await.unwrap();
        tx.execute(
            "INSERT INTO notes (id, tenant_id, body) VALUES ('g2','globex','g-body')",
            &[],
        )
        .await
        .unwrap();
        tx.execute(
            "INSERT INTO note_lines (id, tenant_id, note_id, detail) VALUES ('l_a','globex','g2','GLOBEX-LINE'),('l_b','globex','g2','GLOBEX-LINE2')",
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // acme, own: SELECT detail FROM notes o JOIN note_lines l ON l.note_id = o.id.
        let mut sel = Select {
            table: "notes".into(),
            table_alias: Some("o".into()),
            columns: vec![item(Expr::col("l.detail"))],
            joins: vec![Join {
                kind: JoinKind::Inner,
                table: "note_lines".into(),
                alias: Some("l".into()),
                on: Predicate::Cmp {
                    left: Expr::col("l.note_id"),
                    op: CmpOp::Eq,
                    right: Expr::col("o.id"),
                },
            }],
            ..Select::from("notes")
        };
        sel.force_scope(&scope(ScopeMode::Own, "acme")).unwrap();
        let (sql, params) = sel.compile(dialect).unwrap();
        let mut tx = backend.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert!(
            got.is_empty(),
            "[{engine}] a scoped join must not surface globex's lines, got {got:?}"
        );
        tx.commit().await.unwrap();
    }

    // 9) own_first(): on an own+null read, the tenant's override sorts ahead of the shared base
    //    (and falls back to the base when the tenant has no override) — the base-vs-override read,
    //    `ORDER BY is_own DESC LIMIT 1`, expressed without naming tenant_id.
    {
        let mut tx = backend.begin().await.unwrap();
        tx.execute(
            "INSERT INTO notes (id, tenant_id, body) VALUES \
             ('ovr_b', NULL, 'pref-base'), ('ovr_o', 'acme', 'pref-own'), ('base_only', NULL, 'only-base')",
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let own_first = |tenant: &str, like: &str| {
            let mut s = Select {
                columns: vec![item(Expr::col("body"))],
                filter: Some(Predicate::Like {
                    expr: Expr::col("body"),
                    pattern: like.to_string(),
                    insensitive: false,
                    negated: false,
                }),
                order: vec![OrderBy {
                    expr: Expr::IsOwn,
                    dir: Direction::Desc,
                }],
                limit: Some(1),
                ..Select::from("notes")
            };
            s.force_scope(&scope(ScopeMode::OwnOrNull, tenant)).unwrap();
            s.compile(dialect).unwrap()
        };

        let mut tx = backend.begin().await.unwrap();
        // acme HAS an override for the 'pref-%' key → own_first returns the override, not the base.
        let (sql, params) = own_first("acme", "pref-%");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["pref-own".to_string()],
            "[{engine}] own_first returns the tenant's override over the base"
        );
        // globex has NO override for the 'only-%' key → falls back to the shared base.
        let (sql, params) = own_first("globex", "only-%");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["only-base".to_string()],
            "[{engine}] own_first falls back to the shared base when there's no override"
        );
        tx.commit().await.unwrap();
    }

    println!(
        "ORM IN-SITE TENANT ISOLATION OK [{engine}]: own=acme-only, own+null=acme+baseline, \
         null=baseline, all=every-row; scoped insert stamps own (forgery ignored); scoped \
         update/delete touch own only and can't reassign tenant; a scoped JOIN can't reach \
         another tenant's table; own_first prefers the tenant's override over the base"
    );
}

/// The Stage 1 *per-table-key* battery — the multi-engine companion to the libsql
/// `orm_per_table_key_scope_isolates_on_a_real_engine` gate. A project schema keys each table
/// independently, so a per-dialect rendering bug (placeholder renumbering, column quoting) in the
/// per-ref scope predicate could drop or misplace one table's key on one engine but not another;
/// proving it on Postgres AND MySQL closes that gap. The [`Scope`] is built exactly as the host
/// builds it: `column = default_tenant_key`, `keys = PerTable(schema.table_key_map())`.
async fn run_pertable_battery(backend: Arc<dyn SqlBackend>, dialect: Dialect, engine: &str) {
    use boatramp_core::tenancy::{TableScope, TenancySchema};
    use std::collections::BTreeMap;

    // Fresh schema, idempotent across a reused service-container DB.
    {
        let mut tx = backend.begin().await.unwrap();
        for ddl in [
            "DROP TABLE IF EXISTS orders",
            "DROP TABLE IF EXISTS tenant",
            "DROP TABLE IF EXISTS countries",
            "DROP TABLE IF EXISTS member",
            "CREATE TABLE orders (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64), item VARCHAR(255))",
            "CREATE TABLE tenant (id VARCHAR(64) PRIMARY KEY, plan VARCHAR(64))",
            "CREATE TABLE countries (code VARCHAR(8) PRIMARY KEY, name VARCHAR(64))",
            // `member` keyed on `account_id` (NOT the default) with a shared `tenant_id='acme'` on
            // BOTH rows — the write-axis leak fixture (a tenant_id-keyed write would reach globex).
            "CREATE TABLE member (account_id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64), secret VARCHAR(255))",
        ] {
            tx.execute(ddl, &[]).await.unwrap();
        }
        tx.execute(
            "INSERT INTO orders (id, tenant_id, item) VALUES ('o_a','acme','acme-widget'),('o_g','globex','globex-gadget')",
            &[],
        )
        .await
        .unwrap();
        tx.execute(
            "INSERT INTO tenant (id, plan) VALUES ('acme','pro'),('globex','free')",
            &[],
        )
        .await
        .unwrap();
        tx.execute(
            "INSERT INTO countries (code, name) VALUES ('US','United States'),('FR','France')",
            &[],
        )
        .await
        .unwrap();
        tx.execute(
            "INSERT INTO member (account_id, tenant_id, secret) VALUES ('acme','acme','acme-secret'),('globex','acme','globex-secret')",
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let schema = TenancySchema {
        default_tenant_key: "tenant_id".into(),
        session_key: None,
        tables: BTreeMap::from([
            ("orders".into(), TableScope::Tenant),
            (
                "tenant".into(),
                TableScope::TenantKeyed { key: "id".into() },
            ),
            (
                "member".into(),
                TableScope::TenantKeyed {
                    key: "account_id".into(),
                },
            ),
            ("countries".into(), TableScope::Unscoped),
        ]),
        ..Default::default()
    };
    let keys = TableKeys::PerTable(schema.table_key_map());
    let scope_for = |tenant: &str| Scope {
        column: "tenant_id".into(),
        value: Some(t(tenant)),
        session: None,
        mode: ScopeMode::Own,
        keys: keys.clone(),
    };

    // 1) `orders` (Tenant) scoped on `tenant_id` → acme-only.
    {
        let mut s = Select {
            columns: vec![item(Expr::col("item"))],
            ..Select::from("orders")
        };
        s.force_scope(&scope_for("acme")).unwrap();
        let (sql, params) = s.compile(dialect).unwrap();
        let mut tx = backend.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["acme-widget".to_string()],
            "[{engine}] orders acme-only"
        );
        tx.commit().await.unwrap();
    }

    // 2) identity `tenant` (TenantKeyed on `id`) scoped on its own PK → acme's row only.
    {
        let mut s = Select {
            columns: vec![item(Expr::col("plan"))],
            ..Select::from("tenant")
        };
        s.force_scope(&scope_for("acme")).unwrap();
        let (sql, params) = s.compile(dialect).unwrap();
        let mut tx = backend.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["pro".to_string()],
            "[{engine}] identity row is own-only"
        );
        tx.commit().await.unwrap();
    }

    // 2b) CONTROL — a legacy Uniform `tenant_id` scope on the identity table names a column the
    //     table lacks; the REAL engine rejects it. The per-table key is load-bearing.
    {
        let mut bad = Select {
            columns: vec![item(Expr::col("plan"))],
            ..Select::from("tenant")
        };
        bad.force_scope(&scope(ScopeMode::Own, "acme")).unwrap(); // Uniform helper → tenant_id
        let (bad_sql, bad_params) = bad.compile(dialect).unwrap();
        let mut tx = backend.begin().await.unwrap();
        assert!(
            tx.query(&bad_sql, &bad_params).await.is_err(),
            "[{engine}] a uniform tenant_id scope must FAIL on the identity table: {bad_sql}"
        );
        // Roll the aborted transaction back before dropping it: on Postgres a failed statement puts
        // the transaction in the "aborted, commands ignored until end of transaction block" state, and
        // returning the pooled connection without an explicit ROLLBACK poisons the NEXT `begin()` on
        // it. (MySQL has no such sticky-abort, which is why only Postgres surfaced this.)
        tx.rollback().await.unwrap();
    }

    // 3) `countries` (Unscoped) → globally readable (every country).
    {
        let mut s = Select {
            columns: vec![item(Expr::col("name"))],
            ..Select::from("countries")
        };
        s.force_scope(&scope_for("acme")).unwrap();
        let (sql, params) = s.compile(dialect).unwrap();
        let mut tx = backend.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["France".to_string(), "United States".to_string()],
            "[{engine}] Unscoped reference table is global"
        );
        tx.commit().await.unwrap();
    }

    // 4) A JOIN scopes each ref on its own key → only acme's joined row.
    {
        let mut sel = Select {
            table: "orders".into(),
            table_alias: Some("o".into()),
            columns: vec![item(Expr::col("o.item"))],
            joins: vec![Join {
                kind: JoinKind::Inner,
                table: "tenant".into(),
                alias: Some("t".into()),
                on: Predicate::Cmp {
                    left: Expr::col("t.id"),
                    op: CmpOp::Eq,
                    right: Expr::col("o.tenant_id"),
                },
            }],
            ..Select::from("orders")
        };
        sel.force_scope(&scope_for("acme")).unwrap();
        let (sql, params) = sel.compile(dialect).unwrap();
        let mut tx = backend.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["acme-widget".to_string()],
            "[{engine}] join is acme-only"
        );
        tx.commit().await.unwrap();
    }

    // 5) DENY-BY-DEFAULT: an undeclared table is refused at compile — no SQL reaches the engine.
    {
        let mut undeclared = Select {
            columns: vec![item(Expr::col("v"))],
            ..Select::from("secrets_shadow")
        };
        undeclared.force_scope(&scope_for("acme")).unwrap();
        assert!(
            matches!(
                undeclared.compile(dialect),
                Err(boatramp_core::orm::OrmError::TenancyUndeclared(tbl)) if tbl == "secrets_shadow"
            ),
            "[{engine}] an undeclared table must be refused deny-by-default"
        );
    }

    // 6) WRITE target keyed on its DECLARED column: a guest DELETE of globex's row by a non-tenant
    //    predicate is scoped on `member.account_id` (not the shared tenant_id='acme'), so as acme it
    //    affects ZERO rows on the real engine — no cross-tenant write. Undeclared write refused.
    {
        let eq = |col: &str, v: &str| Predicate::Cmp {
            left: Expr::col(col),
            op: CmpOp::Eq,
            right: Expr::Value(t(v)),
        };
        let mut del = Delete {
            table: "member".into(),
            filter: eq("secret", "globex-secret"),
            scope: None,
            returning: vec![],
        };
        del.force_scope(&scope_for("acme")).unwrap();
        let (sql, params) = del.compile(dialect).unwrap();
        let mut tx = backend.begin().await.unwrap();
        let affected = tx.execute(&sql, &params).await.unwrap();
        assert_eq!(
            affected, 0,
            "[{engine}] a DELETE keyed on account_id must not reach globex's row"
        );
        tx.commit().await.unwrap();

        let mut undeclared_write = Delete {
            table: "secrets_shadow".into(),
            filter: eq("x", "y"),
            scope: None,
            returning: vec![],
        };
        undeclared_write.force_scope(&scope_for("acme")).unwrap();
        assert!(
            matches!(
                undeclared_write.compile(dialect),
                Err(boatramp_core::orm::OrmError::TenancyUndeclared(tbl)) if tbl == "secrets_shadow"
            ),
            "[{engine}] an undeclared write target must be refused deny-by-default"
        );

        // A write to an `Unscoped` (global reference) table is refused — reads are global, writes are
        // a cross-tenant blast (deny-by-default).
        let mut unscoped_write = Delete {
            table: "countries".into(),
            filter: eq("code", "US"),
            scope: None,
            returning: vec![],
        };
        unscoped_write.force_scope(&scope_for("acme")).unwrap();
        assert!(
            matches!(
                unscoped_write.compile(dialect),
                Err(boatramp_core::orm::OrmError::UnscopedWrite(tbl)) if tbl == "countries"
            ),
            "[{engine}] a guest write to an Unscoped reference table must be refused"
        );
    }

    println!(
        "ORM PER-TABLE-KEY TENANCY OK [{engine}]: Tenant table on default tenant_id; identity \
         TenantKeyed table on its own PK (uniform tenant_id scope rejected by the engine); \
         Unscoped reference table global for reads; per-ref join keys each on its own column; a \
         WRITE is bounded on the target's declared key (a cross-tenant DELETE affects 0 rows), \
         refuses an undeclared target, and refuses a write to an Unscoped table; an undeclared table \
         refused deny-by-default"
    );
}

/// The Stage 3 R3 **anonymous-first disjunct** (`TenantOrSession`) + `promote`, on real Postgres and
/// MySQL — the multi-engine companion to the SQLite `orm_tenant_or_session_disjunct_*` gate. The
/// disjunct's `Or([tenant=T, session=S])` and promote's `tenant_id IS NULL` guard lean on NULL /
/// three-valued-logic semantics that can differ per engine, so R3 is proven on each engine, not
/// SQLite alone (the repo's ignore-gated-tests-not-evidence rule).
async fn run_session_disjunct_battery(
    backend: Arc<dyn SqlBackend>,
    dialect: Dialect,
    engine: &str,
) {
    use boatramp_core::tenancy::{TableScope, TenancySchema};
    use std::collections::BTreeMap;

    {
        let mut tx = backend.begin().await.unwrap();
        for ddl in [
            "DROP TABLE IF EXISTS carts",
            "CREATE TABLE carts (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64), session_id VARCHAR(64), item VARCHAR(255))",
        ] {
            tx.execute(ddl, &[]).await.unwrap();
        }
        tx.execute(
            "INSERT INTO carts (id, tenant_id, session_id, item) VALUES \
             ('c_acme','acme',NULL,'acme-cart'),('c_glob','globex',NULL,'globex-cart'), \
             ('c_s1',NULL,'sess-1','anon-cart-1'),('c_s2',NULL,'sess-2','anon-cart-2')",
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let schema = TenancySchema {
        default_tenant_key: "tenant_id".into(),
        session_key: Some("session_id".into()),
        tables: BTreeMap::from([("carts".into(), TableScope::TenantOrSession)]),
        ..Default::default()
    };
    let keys = TableKeys::PerTable(schema.table_key_map());
    let sc = |tenant: Option<&str>, session: Option<&str>| Scope {
        column: "tenant_id".into(),
        value: tenant.map(t),
        session: session.map(t),
        mode: ScopeMode::Own,
        keys: keys.clone(),
    };
    let read_items = |scope: &Scope| {
        let mut s = Select {
            columns: vec![item(Expr::col("item"))],
            ..Select::from("carts")
        };
        s.force_scope(scope).unwrap();
        s.compile(dialect).unwrap()
    };

    // Anon reads only its own session; authed only its tenant; both = the Or.
    {
        let mut tx = backend.begin().await.unwrap();
        let (q, p) = read_items(&sc(None, Some("sess-1")));
        assert_eq!(
            run_query(tx.as_mut(), &q, &p).await,
            vec!["anon-cart-1".to_string()],
            "[{engine}] anon reads only its session cart"
        );
        let (q, p) = read_items(&sc(Some("acme"), None));
        assert_eq!(
            run_query(tx.as_mut(), &q, &p).await,
            vec!["acme-cart".to_string()],
            "[{engine}] authed reads only its tenant cart"
        );
        let (q, p) = read_items(&sc(Some("acme"), Some("sess-1")));
        assert_eq!(
            run_query(tx.as_mut(), &q, &p).await,
            vec!["acme-cart".to_string(), "anon-cart-1".to_string()],
            "[{engine}] both-fact reads the Or"
        );
        tx.commit().await.unwrap();
    }

    // No principal ⇒ refused; promote (D7) claims only sess-1's not-yet-owned rows, idempotent.
    {
        let mut refused = Select {
            columns: vec![item(Expr::col("item"))],
            ..Select::from("carts")
        };
        refused.force_scope(&sc(None, None)).unwrap();
        assert!(
            matches!(
                refused.compile(dialect),
                Err(boatramp_core::orm::OrmError::TenancyNoPrincipal)
            ),
            "[{engine}] a TenantOrSession read with no principal must be refused"
        );

        let promote = sc(Some("acme"), Some("sess-1"));
        let (psql, pparams) =
            boatramp_core::orm::compile_promote(&promote, "carts", dialect).unwrap();
        let mut tx = backend.begin().await.unwrap();
        assert_eq!(
            tx.execute(&psql, &pparams).await.unwrap(),
            1,
            "[{engine}] promote claims exactly sess-1's one not-yet-owned cart"
        );
        // sess-2 untouched; a second promote is a no-op.
        assert_eq!(
            tx.execute(&psql, &pparams).await.unwrap(),
            0,
            "[{engine}] re-promoting is a no-op (IS NULL guard)"
        );
        tx.commit().await.unwrap();
    }

    println!(
        "ORM TENANT-OR-SESSION DISJUNCT OK [{engine}]: anon reads/writes only its session; authed \
         only its tenant; both-fact reads the Or; no-principal refused; promote claims only this \
         session's not-yet-owned rows (IS NULL anti-widening, idempotent)"
    );
}

/// A tenant-scoped **upsert** (`INSERT … ON CONFLICT … DO UPDATE`) on real Postgres — the gate for
/// construens' P48 cutover bug. The host injects an own-partition guard into the `DO UPDATE`
/// (`WHERE <table>.<tenant_col> = $own`) so a guest upsert can't overwrite ANOTHER tenant's row via
/// a conflict on a NON-tenant unique key. That guard column must be **target-table-qualified**:
/// bare, it is ambiguous inside `DO UPDATE` on Postgres (the target table and the `excluded`
/// pseudo-relation both expose the column) and the whole upsert errors — which broke every
/// tenant-scoped upsert on PG. SQLite tolerates the bare form, so this can ONLY be proven on a real
/// Postgres engine. Postgres-only: a scoped upsert is refused at compile on MySQL (fail-closed,
/// unit-tested), so there is nothing to execute there.
#[cfg(feature = "sql-postgres")]
async fn run_upsert_guard_battery(backend: Arc<dyn SqlBackend>, engine: &str) {
    let dialect = Dialect::Postgres;
    // `module` is a shared (non-tenant) unique key: two tenants contend for the same key, so the
    // DO UPDATE guard is the ONLY thing keeping tenant A off tenant B's row.
    {
        let mut tx = backend.begin().await.unwrap();
        for ddl in [
            "DROP TABLE IF EXISTS module_config",
            "CREATE TABLE module_config (module VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64), enabled VARCHAR(8))",
        ] {
            tx.execute(ddl, &[]).await.unwrap();
        }
        // globex owns the shared key `mod_shared`; acme owns its own `mod_acme`.
        tx.execute(
            "INSERT INTO module_config (module, tenant_id, enabled) VALUES \
             ('mod_shared','globex','on'),('mod_acme','acme','on')",
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    // Build a scoped upsert as acme: INSERT (module, enabled) stamping tenant_id=acme, and on a
    // conflict flip `enabled` to the proposed value (`excluded.enabled`). The tenant stamp + the
    // DO UPDATE own-guard are host-injected by `force_scope`.
    let acme_upsert = |module: &str, enabled: &str| {
        let mut ins = Insert {
            table: "module_config".into(),
            rows: vec![RowValues {
                cells: vec![
                    Assignment {
                        column: "module".into(),
                        value: Expr::val(t(module)),
                    },
                    Assignment {
                        column: "enabled".into(),
                        value: Expr::val(t(enabled)),
                    },
                ],
            }],
            conflict: Some(boatramp_core::orm::OnConflict {
                conflict_columns: vec!["module".into()],
                update: vec![Assignment {
                    column: "enabled".into(),
                    value: Expr::col("excluded.enabled"),
                }],
            }),
            scope: None,
            returning: vec![],
            from_select: None,
        };
        ins.force_scope(
            Some(&scope(ScopeMode::Own, "acme")),
            Some(&scope(ScopeMode::Own, "acme")),
        )
        .unwrap();
        ins.compile(dialect).unwrap()
    };

    // 1) Cross-tenant protection: acme upserts the SHARED key globex owns. The statement must EXECUTE
    //    (before the fix it errored `column reference "tenant_id" is ambiguous`), and globex's row
    //    must be UNTOUCHED (the own-guard excludes it — no clobber, no insert).
    {
        let (sql, params) = acme_upsert("mod_shared", "off");
        let mut tx = backend.begin().await.unwrap();
        tx.execute(&sql, &params)
            .await
            .expect("scoped upsert must execute on Postgres (guard column must be qualified)");
        let row = tx
            .query(
                "SELECT tenant_id, enabled FROM module_config WHERE module = 'mod_shared'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            (row.rows[0][0].clone(), row.rows[0][1].clone()),
            (t("globex"), t("on")),
            "[{engine}] acme's upsert on the shared key must NOT clobber globex's row"
        );
        tx.commit().await.unwrap();
    }

    // 2) Own flip works: acme upserts its OWN key → the guard matches, the DO UPDATE flips `enabled`
    //    (construens' enableModule/disableModule on-conflict flip, confined to the caller's tenant).
    {
        let (sql, params) = acme_upsert("mod_acme", "off");
        let mut tx = backend.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        let row = tx
            .query(
                "SELECT enabled FROM module_config WHERE module = 'mod_acme' AND tenant_id = 'acme'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            row.rows[0][0],
            t("off"),
            "[{engine}] acme's upsert on its own key must flip enabled on conflict"
        );
        tx.commit().await.unwrap();
    }

    println!(
        "ORM UPSERT GUARD OK [{engine}]: a tenant-scoped ON CONFLICT DO UPDATE executes on Postgres \
         (the own-guard column is target-qualified, not ambiguous); acme's upsert on a shared \
         non-tenant key cannot clobber globex's row; acme's upsert on its own key flips on conflict"
    );
}

/// v0.4.12: a portable `SqlValue::Json` binds as Postgres **`jsonb`** (OID 3802), so it TYPE-UNIFIES
/// with a `jsonb` column — `COALESCE`, `=`/comparison, and `||` concat — not only on INSERT. The
/// pre-v0.4.12 `json` (OID 114) binding assignment-cast on write but errored
/// `COALESCE types jsonb and json cannot be matched` (and the analogous comparison/`||` mismatch),
/// so a jsonb column could be written but not defaulted/compared against a literal. Postgres-only:
/// MySQL's binary `JSON` and SQLite's text json1 are already the canonical document type.
#[cfg(feature = "sql-postgres")]
async fn run_json_jsonb_battery(backend: Arc<dyn SqlBackend>, engine: &str) {
    let j = |s: &str| SqlValue::Json(s.to_string());
    {
        let mut tx = backend.begin().await.unwrap();
        for ddl in [
            "DROP TABLE IF EXISTS bramp_jsonb_unify",
            "CREATE TABLE bramp_jsonb_unify (id TEXT PRIMARY KEY, doc JSONB)",
        ] {
            tx.execute(ddl, &[]).await.unwrap();
        }
        // A real doc (for comparison/concat) + a NULL doc (for the COALESCE fallback). The INSERT
        // itself proves a Json value binds into a jsonb column (jsonb→jsonb, direct).
        tx.execute(
            "INSERT INTO bramp_jsonb_unify (id, doc) VALUES (?1, ?2)",
            &[t("has"), j(r#"{"k":1}"#)],
        )
        .await
        .expect("a Json value must bind into a jsonb column (INSERT)");
        tx.execute(
            "INSERT INTO bramp_jsonb_unify (id, doc) VALUES (?1, NULL)",
            &[t("nil")],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    // (1) COALESCE(<jsonb col>, <jsonb literal>) — the reported gap. Must EXECUTE (pre-v0.4.12:
    //     "COALESCE types jsonb and json cannot be matched") and fall back to the literal.
    {
        let mut tx = backend.begin().await.unwrap();
        let rows = tx
            .query(
                "SELECT COALESCE(doc, ?1)->>'d' AS v FROM bramp_jsonb_unify WHERE id = 'nil'",
                &[j(r#"{"d":"fallback"}"#)],
            )
            .await
            .expect("COALESCE(jsonb, Json literal) must type-unify and execute on Postgres");
        assert!(
            matches!(&rows.rows[0][0], SqlValue::Text(s) if s == "fallback"),
            "[{engine}] COALESCE fell back to the jsonb literal: {:?}",
            rows.rows[0][0]
        );
        tx.commit().await.unwrap();
    }
    // (2) WHERE <jsonb col> = <jsonb literal> — comparison must unify and match.
    {
        let mut tx = backend.begin().await.unwrap();
        let rows = tx
            .query(
                "SELECT id FROM bramp_jsonb_unify WHERE doc = ?1",
                &[j(r#"{"k":1}"#)],
            )
            .await
            .expect("WHERE jsonb = Json literal must type-unify and execute on Postgres");
        assert!(
            rows.rows
                .iter()
                .any(|r| matches!(&r[0], SqlValue::Text(s) if s == "has")),
            "[{engine}] jsonb = jsonb literal matched the row"
        );
        tx.commit().await.unwrap();
    }
    // (3) <jsonb col> || <jsonb literal> — concat/merge must unify (jsonb || jsonb).
    {
        let mut tx = backend.begin().await.unwrap();
        let rows = tx
            .query(
                "SELECT (doc || ?1)->>'m' AS v FROM bramp_jsonb_unify WHERE id = 'has'",
                &[j(r#"{"m":"merged"}"#)],
            )
            .await
            .expect("jsonb || Json literal must type-unify and execute on Postgres");
        assert!(
            matches!(&rows.rows[0][0], SqlValue::Text(s) if s == "merged"),
            "[{engine}] jsonb || jsonb literal merged: {:?}",
            rows.rows[0][0]
        );
        tx.commit().await.unwrap();
    }
    println!(
        "ORM JSONB LITERAL OK [{engine}]: a portable SqlValue::Json binds as Postgres jsonb — \
         INSERT into a jsonb column, COALESCE(jsonb, literal), WHERE jsonb = literal, and \
         jsonb || literal all type-unify and execute (not only INSERT)"
    );
}

#[cfg(feature = "sql-postgres")]
#[tokio::test]
async fn postgres_orm_scope_isolates_on_a_real_engine() {
    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip postgres_orm_scope: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let backend = connect(ExternalSqlKind::Postgres, &ExternalSqlOptions::new(url)).unwrap();
    run_battery(backend.clone(), Dialect::Postgres, "postgres").await;
    run_pertable_battery(backend.clone(), Dialect::Postgres, "postgres").await;
    run_session_disjunct_battery(backend.clone(), Dialect::Postgres, "postgres").await;
    run_upsert_guard_battery(backend.clone(), "postgres").await;
    run_json_jsonb_battery(backend, "postgres").await;
}

#[cfg(feature = "sql-mysql")]
#[tokio::test]
async fn mysql_orm_scope_isolates_on_a_real_engine() {
    let Ok(url) = std::env::var("BOATRAMP_TEST_MYSQL_URL") else {
        eprintln!("skip mysql_orm_scope: BOATRAMP_TEST_MYSQL_URL unset");
        return;
    };
    let backend = connect(ExternalSqlKind::Mysql, &ExternalSqlOptions::new(url)).unwrap();
    run_battery(backend.clone(), Dialect::Mysql, "mysql").await;
    run_pertable_battery(backend.clone(), Dialect::Mysql, "mysql").await;
    run_session_disjunct_battery(backend, Dialect::Mysql, "mysql").await;
}
