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
        value: t(value),
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
    };
    let keys = TableKeys::PerTable(schema.table_key_map());
    let scope_for = |tenant: &str| Scope {
        column: "tenant_id".into(),
        value: t(tenant),
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

#[cfg(feature = "sql-postgres")]
#[tokio::test]
async fn postgres_orm_scope_isolates_on_a_real_engine() {
    let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip postgres_orm_scope: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let backend = connect(ExternalSqlKind::Postgres, &ExternalSqlOptions::new(url)).unwrap();
    run_battery(backend.clone(), Dialect::Postgres, "postgres").await;
    run_pertable_battery(backend, Dialect::Postgres, "postgres").await;
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
    run_pertable_battery(backend, Dialect::Mysql, "mysql").await;
}
