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

/// The `body` column of every row a `SELECT body FROM <table>` returns (RLS-filtered), sorted.
async fn bodies(tx: &mut dyn boatramp_core::sql::SqlTransaction, table: &str) -> Vec<String> {
    let rows = tx
        .query(&format!("SELECT body FROM {table} ORDER BY body"), &[])
        .await
        .unwrap();
    rows.rows
        .into_iter()
        .flatten()
        .filter_map(|v| match v {
            SqlValue::Text(s) => Some(s),
            _ => None,
        })
        .collect()
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
        // Best-effort teardown of any leftover state from a prior (possibly failed) run, so the gate
        // is re-runnable: drop the tables + REVOKE CONNECT before DROP ROLE (a lingering table grant
        // or the CONNECT grant would otherwise block DROP ROLE). Errors ignored — nothing may exist.
        let mut tx = su.begin().await.unwrap();
        for stmt in [
            "DROP TABLE IF EXISTS brls_note",
            "DROP TABLE IF EXISTS brls_open",
            "REVOKE CONNECT ON DATABASE boatramp FROM brls_app",
            "DROP ROLE IF EXISTS brls_app",
        ] {
            let _ = tx.execute(stmt, &[]).await;
        }
        tx.commit().await.unwrap();
    }
    {
        let mut tx = su.begin().await.unwrap();
        for stmt in [
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
            // v0.4.21: a second table that OPTS IN to `all` reads via the all-marker (`*`) — the
            // marker clause is on USING only (reads open cross-tenant); WITH CHECK stays strict (a
            // write is confined to the resolved tenant, never opened by the marker). `brls_note`
            // above has NO marker clause, so an `all` read must NOT open it.
            "CREATE TABLE brls_open (tenant_id text NOT NULL, body text NOT NULL)",
            "ALTER TABLE brls_open ENABLE ROW LEVEL SECURITY",
            "ALTER TABLE brls_open FORCE ROW LEVEL SECURITY",
            "CREATE POLICY tenant_or_all ON brls_open \
               USING (tenant_id = current_setting('app.tenant_id', true) \
                      OR current_setting('app.tenant_id', true) = '*') \
               WITH CHECK (tenant_id = current_setting('app.tenant_id', true))",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON brls_open TO brls_app",
            "INSERT INTO brls_open (tenant_id, body) VALUES ('A','open-a'), ('B','open-b')",
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

    // (4) ALL-READ MARKER (v0.4.21): the host writes a reserved marker (`*`) to the tenant GUC for
    // an `all` READ — via the SAME renderer the binding's `set_all_read_marker` uses — so a table
    // that opts in (`brls_open`) opens cross-tenant, while a strict table (`brls_note`) and every
    // write stay confined. Fail-closed: an unset GUC (a dropped resolution) opens nothing.
    {
        let mut tx = app.begin().await.unwrap();

        // (4a) own read (GUC = A): the marker clause does NOT over-open — only A's rows.
        set_guc(tx.as_mut(), "A").await;
        assert_eq!(
            bodies(tx.as_mut(), "brls_open").await,
            vec!["open-a".to_string()],
            "own read (GUC=A) sees only A even on a marker-opted table"
        );

        // (4b) all read (GUC = marker `*`): the opted-in table opens across tenants.
        set_guc(tx.as_mut(), "*").await;
        assert_eq!(
            bodies(tx.as_mut(), "brls_open").await,
            vec!["open-a".to_string(), "open-b".to_string()],
            "all read (GUC=marker) sees every tenant on the opted-in table"
        );

        // (4c) with the marker set, a table WITHOUT the marker clause stays strict → zero rows
        // (per-table opt-in: the marker never opens a table that didn't ask for it).
        assert_eq!(
            bodies(tx.as_mut(), "brls_note").await,
            Vec::<String>::new(),
            "marker does NOT open a non-opted-in table (brls_note has no OR-marker clause)"
        );

        // (4d) fail-closed: an UNSET GUC (simulating a dropped host resolution) opens nothing, even
        // on the marker-opted table — the backstop still denies.
        set_guc(tx.as_mut(), "").await;
        assert_eq!(
            bodies(tx.as_mut(), "brls_open").await,
            Vec::<String>::new(),
            "unset GUC (empty) opens nothing — fail-closed even on a marker table"
        );

        // (4e) even with GUC=marker, a WRITE is confined by WITH CHECK (which has NO marker clause):
        // an INSERT of a foreign tenant is rejected. (The host never sets the marker during a write;
        // this is the DB-side belt-and-suspenders that a strict WITH CHECK still holds.) This must be
        // LAST in the transaction — the rejection aborts it, so only `rollback` may follow.
        set_guc(tx.as_mut(), "*").await;
        let denied = tx
            .execute(
                "INSERT INTO brls_open (tenant_id, body) VALUES ('B','marker-forge')",
                &[],
            )
            .await;
        assert!(
            denied.is_err(),
            "GUC=marker must NOT open a write — WITH CHECK stays strict"
        );

        tx.rollback().await.unwrap();
    }

    // cleanup
    {
        let mut tx = su.begin().await.unwrap();
        for stmt in [
            "DROP TABLE IF EXISTS brls_note",
            "DROP TABLE IF EXISTS brls_open",
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
    println!(
        "RLS ALL-READ MARKER OK [postgres]: the reserved all-marker written to the tenant GUC on an \
         `all` READ opens ONLY a table that opts in (`USING … OR guc = marker`) across tenants — an \
         own read still sees only its tenant, a non-opted table and every write stay strict, and an \
         unset GUC opens nothing (fail-closed)."
    );
}
