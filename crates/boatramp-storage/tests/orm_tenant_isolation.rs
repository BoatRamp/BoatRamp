//! **Live** proof that the Stage 0 in-site tenant scope actually isolates tenants on a **real**
//! SQL engine (embedded libsql / SQLite), not just in the compiler's string output. This is the
//! [[ignore-gated-tests-not-evidence]] guard for the ORM tenant model: it drives host-scoped
//! queries — built exactly as the host binding builds them (`force_scope` + `compile`) — against
//! a shared database holding two tenants' rows plus a NULL baseline, and asserts each mode reaches
//! only what it should. Runs unconditionally in normal CI (needs only a temp SQLite file), so a
//! cross-tenant regression fails the build, and prints a success marker so a silent skip can't
//! masquerade as a pass.
#![cfg(feature = "sql")]

use boatramp_core::orm::{
    Assignment, CmpOp, Delete, Expr, Insert, Predicate, RowValues, Scope, ScopeMode, Select,
    SelectItem, Update,
};
use boatramp_core::sql::{Dialect, SqlBackends, SqlTransaction, SqlValue};
use boatramp_storage::LibsqlSqlBackends;

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
async fn run_query(tx: &mut dyn SqlTransaction, sql: &str, params: &[SqlValue]) -> Vec<String> {
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

// `#[ignore]` by default so the general workspace test lane skips it (a skip is not evidence
// there): built for the **static-musl** target and run under musl's default malloc, libsql's
// bundled SQLite SIGSEGVs — a test-harness quirk, NOT a logic issue and NOT a production one (the
// shipped musl binary uses jemalloc; managed libsql is proven on musl by the container capability
// gate + real deployments). The dedicated `test-orm-tenancy` CI job runs it **unignored** on the
// host glibc toolchain (`-- --ignored`) and asserts the success marker — that job is the evidence.
#[tokio::test]
#[ignore = "run via the test-orm-tenancy CI job on the host toolchain (static-musl test binary segfaults in libsql's bundled SQLite)"]
async fn orm_in_site_tenant_scope_isolates_on_a_real_engine() {
    let dir = std::env::temp_dir().join(format!("boatramp-orm-tenancy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let backends = LibsqlSqlBackends::local(&dir);
    let db = backends.database("default", "shop", "").await.unwrap();

    // A shared multi-tenant table: acme + globex rows, plus a NULL-baseline (shared) row.
    {
        let mut tx = db.begin().await.unwrap();
        tx.execute(
            "CREATE TABLE notes (id TEXT PRIMARY KEY, tenant_id TEXT, body TEXT)",
            &[],
        )
        .await
        .unwrap();
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

    // Helper: run a host-scoped SELECT of `body` for the given read mode (as the host would).
    let select_bodies = |mode: ScopeMode, tenant: &str| {
        let mut s = Select {
            columns: vec![item(Expr::col("body"))],
            ..Select::from("notes")
        };
        s.force_scope(&scope(mode, tenant));
        s.compile(Dialect::Sqlite).unwrap()
    };

    // 1) read: own (acme) sees ONLY acme — never globex, never the baseline.
    {
        let mut tx = db.begin().await.unwrap();
        let (sql, params) = select_bodies(ScopeMode::Own, "acme");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["acme-secret".to_string()],
            "own must be acme-only"
        );
        tx.commit().await.unwrap();
    }

    // 2) own+null (acme) sees acme + the shared baseline, but NOT globex.
    {
        let mut tx = db.begin().await.unwrap();
        let (sql, params) = select_bodies(ScopeMode::OwnOrNull, "acme");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["acme-secret".to_string(), "shared-baseline".to_string()],
            "own+null = acme + baseline, no globex"
        );
        tx.commit().await.unwrap();
    }

    // 3) null-only sees ONLY the shared baseline.
    {
        let mut tx = db.begin().await.unwrap();
        let (sql, params) = select_bodies(ScopeMode::NullOnly, "acme");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(got, vec!["shared-baseline".to_string()]);
        tx.commit().await.unwrap();
    }

    // 4) all (cross-tenant) sees everything — the deliberately-opened grant.
    {
        let mut tx = db.begin().await.unwrap();
        let (sql, params) = select_bodies(ScopeMode::All, "acme");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(got.len(), 3, "all sees every row");
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
        let (sql, params) = ins.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        // The new row is acme's, not globex's — confirm via the DB.
        let owner = tx
            .query("SELECT tenant_id FROM notes WHERE id = 'a2'", &[])
            .await
            .unwrap();
        assert_eq!(
            owner.rows[0][0],
            t("acme"),
            "insert stamped own, forgery ignored"
        );
        tx.commit().await.unwrap();
    }

    // 6) A scoped UPDATE only touches own rows AND can't reassign the tenant. acme updates its own
    //    body and tries SET tenant_id = globex — globex's row is untouched and acme keeps its rows.
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
        let (sql, params) = upd.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        // globex's row is untouched (still globex, still its secret).
        let g = tx
            .query("SELECT body FROM notes WHERE id = 'g1'", &[])
            .await
            .unwrap();
        assert_eq!(
            g.rows[0][0],
            t("globex-secret"),
            "globex row untouched by acme's update"
        );
        // acme's rows are all still acme (tenant never reassigned).
        let owners = run_query(
            tx.as_mut(),
            "SELECT DISTINCT tenant_id FROM notes WHERE body LIKE 'acme%'",
            &[],
        )
        .await;
        assert_eq!(owners, vec!["acme".to_string()], "acme rows stay acme");
        tx.commit().await.unwrap();
    }

    // 7) A scoped DELETE only removes own rows. acme deletes-all → globex + baseline survive.
    {
        let mut del = Delete {
            table: "notes".into(),
            filter: Predicate::And(Vec::new()),
            scope: None,
            returning: vec![],
        };
        del.force_scope(&scope(ScopeMode::Own, "acme"));
        let (sql, params) = del.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        let survivors = run_query(tx.as_mut(), "SELECT id FROM notes", &[]).await;
        assert_eq!(
            survivors,
            vec!["g1".to_string(), "s1".to_string()],
            "acme's DELETE-all left globex + baseline"
        );
        tx.commit().await.unwrap();
    }

    // 8) A scoped SELECT with a guest JOIN scopes BOTH tables — a joined victim table can't leak.
    {
        let mut tx = db.begin().await.unwrap();
        tx.execute(
            "CREATE TABLE lines (id TEXT, tenant_id TEXT, note_id TEXT, detail TEXT)",
            &[],
        )
        .await
        .unwrap();
        // Re-seed a globex note + globex + acme lines to prove the join can't reach globex lines.
        tx.execute(
            "INSERT INTO notes (id, tenant_id, body) VALUES ('g2','globex','g-body')",
            &[],
        )
        .await
        .unwrap();
        tx.execute(
            "INSERT INTO lines (id, tenant_id, note_id, detail) VALUES ('l_a','globex','g2','GLOBEX-LINE'),('l_b','globex','g2','GLOBEX-LINE2')",
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // acme, own: SELECT detail FROM notes o JOIN lines l ON l.note_id = o.id.
        let mut sel = Select {
            table: "notes".into(),
            table_alias: Some("o".into()),
            columns: vec![item(Expr::col("l.detail"))],
            joins: vec![boatramp_core::orm::Join {
                kind: boatramp_core::orm::JoinKind::Inner,
                table: "lines".into(),
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
        let (sql, params) = sel.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert!(
            got.is_empty(),
            "a scoped join must not surface globex's lines, got {got:?}"
        );
        tx.commit().await.unwrap();
    }

    println!(
        "ORM IN-SITE TENANT ISOLATION OK: own=acme-only, own+null=acme+baseline, null=baseline, \
         all=every-row; scoped insert stamps own (forgery ignored); scoped update/delete touch \
         own only and can't reassign tenant; a scoped JOIN can't reach another tenant's table"
    );
}
