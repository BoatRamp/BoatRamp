//! Live gate (v0.4.20): the RLS **tenant session GUC** makes an app's Postgres row-level security a
//! faithful mirror of boatramp's injected predicate — a defense-in-depth backstop. Env-gated on
//! `BOATRAMP_TEST_PG_URL` (skips cleanly when unset). On a real Postgres, as a **non-superuser** role
//! against a `FORCE ROW LEVEL SECURITY` table whose policy keys on `current_setting('app.tenant_id',
//! true)`:
//!   * OWN case — the host sets the GUC to the resolved tenant (`render_set_local_guc`): a scoped
//!     read/write as tenant A sees/writes only A's rows, and a write declaring tenant B is REJECTED
//!     by `WITH CHECK`;
//!   * ALL provisioning — the host derives the GUC from the row the write declares (the typed
//!     `Insert::uniform_scope_value` and the raw `extract_raw_write_scope_value`): creating tenant B
//!     succeeds, and the same connection cannot touch A's rows.
//!
//! The itests can't catch this (they connect as the pg superuser, which BYPASSES RLS); this gate
//! connects as a deliberately non-superuser role so RLS is actually enforced.
#![cfg(feature = "sql-postgres")]

use boatramp_core::orm::{Assignment, Expr, Insert, RowValues};
use boatramp_core::sql::{render_set_local_guc, Dialect, SqlValue};
use boatramp_core::target_sql::extract_raw_write_scope_value;
use boatramp_storage::sql_sqlx::{connect, ExternalSqlKind, ExternalSqlOptions};

fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.to_string())
}

/// Set the RLS tenant GUC on `tx` to `tenant` via the SAME core renderer the handler binding uses.
async fn set_guc(tx: &mut dyn boatramp_core::sql::SqlTransaction, tenant: &str) {
    let (sql, params) = render_set_local_guc("app.tenant_id", &text(tenant));
    tx.execute(&sql, &params).await.expect("set_config runs");
}

#[tokio::test]
async fn rls_tenant_guc_mirrors_the_predicate_on_a_non_superuser_role() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip rls_tenant_guc: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    // A second URL as the NON-superuser app role (RLS is bypassed for a superuser).
    let app_url = su_url.replacen("boatramp:boatramp@", "brls_app:brls_pw@", 1);

    // --- setup as superuser: a FORCE-RLS table + policy keyed on the GUC + a non-superuser role ---
    let su = connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(su_url.clone()),
    )
    .unwrap();
    {
        let mut tx = su.begin().await.unwrap();
        for stmt in [
            "DROP TABLE IF EXISTS brls_note",
            "DROP ROLE IF EXISTS brls_app",
            "CREATE ROLE brls_app LOGIN PASSWORD 'brls_pw' NOSUPERUSER NOBYPASSRLS",
            "GRANT CONNECT ON DATABASE boatramp TO brls_app",
            "CREATE TABLE brls_note (tenant_id text NOT NULL, body text NOT NULL)",
            "ALTER TABLE brls_note ENABLE ROW LEVEL SECURITY",
            "ALTER TABLE brls_note FORCE ROW LEVEL SECURITY",
            "CREATE POLICY tenant_isolation ON brls_note \
               USING (tenant_id = current_setting('app.tenant_id', true)) \
               WITH CHECK (tenant_id = current_setting('app.tenant_id', true))",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON brls_note TO brls_app",
            // Seed one row per tenant (as superuser — bypasses RLS) so cross-tenant visibility is testable.
            "INSERT INTO brls_note (tenant_id, body) VALUES ('A','seed-a'), ('B','seed-b')",
        ] {
            tx.execute(stmt, &[])
                .await
                .unwrap_or_else(|e| panic!("setup `{stmt}`: {e}"));
        }
        tx.commit().await.unwrap();
    }

    let app = connect(ExternalSqlKind::Postgres, &ExternalSqlOptions::new(app_url)).unwrap();

    // (1) OWN case: GUC = resolved tenant A. Sees ONLY A; can write A; a B write is REJECTED.
    {
        let mut tx = app.begin().await.unwrap();
        set_guc(tx.as_mut(), "A").await;
        let rows = tx.query("SELECT body FROM brls_note", &[]).await.unwrap();
        let bodies: Vec<String> = rows
            .rows
            .into_iter()
            .flatten()
            .filter_map(|v| match v {
                SqlValue::Text(s) => Some(s),
                _ => None,
            })
            .collect();
        assert_eq!(
            bodies,
            vec!["seed-a".to_string()],
            "tenant A sees only A's rows (RLS USING)"
        );
        tx.execute(
            "INSERT INTO brls_note (tenant_id, body) VALUES ('A','a-own')",
            &[],
        )
        .await
        .expect("A may write its own row");
        let denied = tx
            .execute(
                "INSERT INTO brls_note (tenant_id, body) VALUES ('B','forge')",
                &[],
            )
            .await;
        assert!(denied.is_err(), "RLS WITH CHECK rejects A writing a B row");
        tx.rollback().await.unwrap();
    }

    // (2) ALL provisioning (typed): the host derives the GUC from the row the INSERT declares.
    {
        // The value the handler would extract from a typed `all` INSERT of a tenant-B row.
        let ins = Insert {
            table: "brls_note".into(),
            rows: vec![RowValues {
                cells: vec![
                    Assignment {
                        column: "tenant_id".into(),
                        value: Expr::Value(text("B")),
                    },
                    Assignment {
                        column: "body".into(),
                        value: Expr::Value(text("b-prov")),
                    },
                ],
            }],
            conflict: None,
            scope: None,
            returning: vec![],
            from_select: None,
        };
        let derived = ins.uniform_scope_value("tenant_id");
        assert_eq!(
            derived,
            Some(text("B")),
            "typed extractor reads the row's declared tenant"
        );

        let mut tx = app.begin().await.unwrap();
        set_guc(
            tx.as_mut(),
            derived
                .as_ref()
                .and_then(|v| match v {
                    SqlValue::Text(s) => Some(s.as_str()),
                    _ => None,
                })
                .unwrap(),
        )
        .await;
        tx.execute(
            "INSERT INTO brls_note (tenant_id, body) VALUES ('B','b-prov')",
            &[],
        )
        .await
        .expect("an `all` write provisioning tenant B succeeds under GUC=B");
        // ...and even under GUC=B it cannot touch A's rows (RLS still confines to B).
        let n = tx
            .execute("UPDATE brls_note SET body='x' WHERE tenant_id='A'", &[])
            .await
            .expect("update runs");
        assert_eq!(n, 0, "GUC=B cannot update A's rows (RLS USING)");
        tx.rollback().await.unwrap();
    }

    // (3) ALL provisioning (raw): the raw-write extractor reads the same declared tenant.
    {
        let derived = extract_raw_write_scope_value(
            "INSERT INTO brls_note (tenant_id, body) VALUES ('B','b-raw')",
            Dialect::Postgres,
            |t| (t == "brls_note").then(|| "tenant_id".to_string()),
        );
        assert_eq!(
            derived,
            Some(text("B")),
            "raw extractor reads the row's declared tenant"
        );

        let mut tx = app.begin().await.unwrap();
        set_guc(tx.as_mut(), "B").await;
        tx.execute(
            "INSERT INTO brls_note (tenant_id, body) VALUES ('B','b-raw')",
            &[],
        )
        .await
        .expect("raw `all` provisioning of tenant B succeeds under GUC=B");
        let denied = tx
            .execute(
                "INSERT INTO brls_note (tenant_id, body) VALUES ('A','forge')",
                &[],
            )
            .await;
        assert!(denied.is_err(), "GUC=B still rejects an A row (raw path)");
        tx.rollback().await.unwrap();
    }

    // cleanup
    {
        let mut tx = su.begin().await.unwrap();
        for stmt in [
            "DROP TABLE IF EXISTS brls_note",
            "REVOKE CONNECT ON DATABASE boatramp FROM brls_app",
            "DROP ROLE IF EXISTS brls_app",
        ] {
            let _ = tx.execute(stmt, &[]).await;
        }
        tx.commit().await.unwrap();
    }

    println!(
        "RLS TENANT GUC OK [postgres]: on a non-superuser FORCE-RLS role, the host-set tenant GUC \
         (render_set_local_guc) makes RLS mirror the injected predicate — own reads/writes see and \
         admit only the resolved tenant and reject a forged one; an `all` provisioning write derives \
         the GUC from the row the statement declares (typed + raw extractors) so creating tenant B \
         succeeds yet still cannot touch tenant A."
    );
}
