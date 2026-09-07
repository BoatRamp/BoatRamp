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
    Assignment, CmpOp, Delete, Expr, Insert, Join, JoinKind, Predicate, RowValues, Scope,
    ScopeMode, Select, SelectItem, Update,
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
        s.force_scope(&scope(mode, tenant));
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
        );
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
        upd.force_scope(&scope(ScopeMode::Own, "acme"));
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
        del.force_scope(&scope(ScopeMode::Own, "acme"));
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
        sel.force_scope(&scope(ScopeMode::Own, "acme"));
        let (sql, params) = sel.compile(dialect).unwrap();
        let mut tx = backend.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert!(
            got.is_empty(),
            "[{engine}] a scoped join must not surface globex's lines, got {got:?}"
        );
        tx.commit().await.unwrap();
    }

    println!(
        "ORM IN-SITE TENANT ISOLATION OK [{engine}]: own=acme-only, own+null=acme+baseline, \
         null=baseline, all=every-row; scoped insert stamps own (forgery ignored); scoped \
         update/delete touch own only and can't reassign tenant; a scoped JOIN can't reach \
         another tenant's table"
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
    run_battery(backend, Dialect::Postgres, "postgres").await;
}

#[cfg(feature = "sql-mysql")]
#[tokio::test]
async fn mysql_orm_scope_isolates_on_a_real_engine() {
    let Ok(url) = std::env::var("BOATRAMP_TEST_MYSQL_URL") else {
        eprintln!("skip mysql_orm_scope: BOATRAMP_TEST_MYSQL_URL unset");
        return;
    };
    let backend = connect(ExternalSqlKind::Mysql, &ExternalSqlOptions::new(url)).unwrap();
    run_battery(backend, Dialect::Mysql, "mysql").await;
}
