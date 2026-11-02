//! **Live gate: ownership-safe per-replica DYNAMIC database credentials (PLAN phase 2).**
//!
//! This is the LOAD-BEARING proof for the whole phase-2 design — the ownership-orphaning
//! hazard can only be ruled out against a REAL Postgres, because it rides on Postgres
//! object-ownership semantics (`CREATE TABLE` ⇒ creator-owned; `DROP ROLE` refused while a
//! role owns objects). It stands up the REAL model the builders emit —
//! [`provision_ddl`] (stable owner role + owner-owned tenant DB), then
//! [`mint_dynamic_role_ddl`] / [`drop_dynamic_role_ddl`] — on a live engine and proves, at
//! the SQL/privilege level:
//!
//! 1. **Ownership transfer** — a per-replica dynamic role, minted as a member of the stable
//!    owner + `ALTER ROLE … SET role = '<owner>'`, creates a table (its serial sequence, an
//!    index) owned by the STABLE OWNER, not the dynamic role; the dynamic role owns NOTHING.
//!    1b. **NOINHERIT escape closure (MEDIUM-1)** — the same role, dropped to its RAW identity
//!    with `SET ROLE NONE`, CANNOT create an owner-orphan (no direct grant, no inherited one),
//!    while the operate-as-owner happy path keeps working.
//! 2. **Clean drop** — [`drop_dynamic_role_ddl`] (`REASSIGN OWNED … TO <owner>` → `DROP
//!    OWNED` → `DROP ROLE`) drops the dynamic role cleanly, and the drop clears its
//!    database-level `CONNECT` grant too.
//! 3. **Fresh role ⇒ identical access** — a second dynamic role minted after the first was
//!    dropped reads the first role's data, ALTERs/creates owner-owned objects (owner authority).
//! 4. **Robustness / escape safety net** — a dynamic role that escapes the GUC with `SET
//!    ROLE NONE` and creates an object as the RAW role still drops cleanly, because the
//!    `REASSIGN OWNED BY <dyn> TO <owner>` safety net moves the escaped object to the stable
//!    owner (no orphan, no data loss) before the drop.
//! 5. **Negative control** — a naive role that creates an object as ITSELF CANNOT be dropped:
//!    `DROP ROLE` is refused. This is the exact hazard the design removes.
//!
//! Requires `BOATRAMP_TEST_PG_URL` = a **superuser** Postgres URL (skips cleanly when unset).
//! Marked `#[ignore]` (run it explicitly — e.g. on lighthouse — or via the live-pg CI lane,
//! which greps the marker). Prints `DYNAMIC CRED OWNERSHIP OK [postgres]` on success.

#![cfg(feature = "sql-postgres")]

use std::sync::Arc;

use boatramp_core::sql::{SqlBackend, SqlValue};
use boatramp_storage::sql_sqlx::{ExternalSqlKind, ExternalSqlOptions, connect};
use boatramp_storage::tenant_provision::{
    drop_dynamic_role_ddl, mint_dynamic_role_ddl, provision_ddl,
};

const DB: &str = "dyn_appdb";
const ROLE: &str = "dyn_role";
const ROLE_PW: &str = "rolepw";
const OWNER: &str = "dyn_owner";
const OWNER_PW: &str = "0wnerpw";
const DYN1: &str = "dyn_appdb_d_web_0";
const DYN1_PW: &str = "d1pw";
const DYN2: &str = "dyn_appdb_d_web_0_b"; // the "relaunch" replica role (fresh)
const DYN2_PW: &str = "d2pw";
const DYN3: &str = "dyn_appdb_d_web_1"; // the escape-safety-net role
const DYN3_PW: &str = "d3pw";
const NAIVE: &str = "dyn_naive";
const NAIVE_PW: &str = "npw";

/// Rewrite a superuser URL to connect as `user`/`pw` to database `db` (the harness pattern).
fn as_role(su_url: &str, user: &str, pw: &str, db: &str) -> String {
    let (scheme, rest) = su_url.split_once("://").expect("url has scheme");
    let after_at = rest.split_once('@').map(|(_, r)| r).unwrap_or(rest);
    let (hostport, _tail) = after_at.split_once('/').unwrap_or((after_at, ""));
    format!("{scheme}://{user}:{pw}@{hostport}/{db}")
}

/// Run a one-cell probe and return it as a string (text/bool/int coerced).
async fn probe(be: &Arc<dyn SqlBackend>, sql: &str) -> String {
    let rows = be
        .run_query(sql)
        .await
        .unwrap_or_else(|e| panic!("probe `{sql}`: {e}"));
    match rows.rows.into_iter().flatten().next() {
        Some(SqlValue::Text(s)) => s,
        Some(SqlValue::Boolean(b)) => b.to_string(),
        Some(SqlValue::Integer(n)) => n.to_string(),
        other => panic!("probe `{sql}` returned unexpected cell {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs a live superuser Postgres via BOATRAMP_TEST_PG_URL (run on lighthouse / the live-pg CI lane)"]
async fn dynamic_cred_is_ownership_safe_on_a_real_postgres() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip dynamic_cred ownership: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let k = ExternalSqlKind::Postgres;
    let su = connect(k, &ExternalSqlOptions::new(su_url.clone())).unwrap();

    // Superuser connection to the tenant db — where REASSIGN/DROP OWNED + the ownership
    // assertions must run (they are database-local).
    let su_tenant_url = {
        let (scheme, rest) = su_url.split_once("://").unwrap();
        let (creds, after) = rest.split_once('@').unwrap();
        let (hostport, _) = after.split_once('/').unwrap_or((after, ""));
        format!("{scheme}://{creds}@{hostport}/{DB}")
    };

    // --- teardown any prior run (re-runnable) ---
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{DYN1}\""),
        format!("DROP ROLE IF EXISTS \"{DYN2}\""),
        format!("DROP ROLE IF EXISTS \"{DYN3}\""),
        format!("DROP ROLE IF EXISTS \"{NAIVE}\""),
        format!("DROP ROLE IF EXISTS \"{ROLE}\""),
        format!("DROP ROLE IF EXISTS \"{OWNER}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    // --- setup: the REAL provisioning (stable owner role owns the DB). ---
    for stmt in provision_ddl(k, DB, ROLE, ROLE_PW, OWNER, OWNER_PW) {
        su.run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("provision `{stmt}`: {e}"));
    }
    let su_tenant = connect(k, &ExternalSqlOptions::new(su_tenant_url.clone())).unwrap();

    let owned_by = |name: &str, owner: &str| {
        format!("SELECT (tableowner = '{owner}')::text FROM pg_tables WHERE tablename = '{name}'")
    };

    // =====================================================================
    // STEP 1: mint DYN1 and prove ownership transfer to the STABLE OWNER.
    // =====================================================================
    for stmt in mint_dynamic_role_ddl(k, DB, OWNER, DYN1, DYN1_PW) {
        su.run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("mint dyn1 `{stmt}`: {e}"));
    }
    let dyn1 = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, DYN1, DYN1_PW, DB)),
    )
    .unwrap();
    // It operates AS the owner: session_user = dyn1, current_user = owner.
    assert_eq!(
        probe(&dyn1, "SELECT session_user::text").await,
        DYN1,
        "session_user must be the dynamic role"
    );
    assert_eq!(
        probe(&dyn1, "SELECT current_user::text").await,
        OWNER,
        "current_user must be the stable owner (operate-as-owner)"
    );
    // It creates objects (table + serial sequence + index) as the app/ORM/migration would.
    for stmt in [
        "CREATE TABLE t1 (id serial PRIMARY KEY, v text)",
        "INSERT INTO t1 (v) VALUES ('from-dyn1')",
        "CREATE INDEX t1_v_idx ON t1 (v)",
    ] {
        dyn1.run_script(stmt)
            .await
            .unwrap_or_else(|e| panic!("dyn1 DDL/DML `{stmt}`: {e}"));
    }
    // Ownership assertions: everything owner-owned, dyn1 owns nothing.
    assert_eq!(
        probe(&su_tenant, &owned_by("t1", OWNER)).await,
        "true",
        "t1 must be owner-owned"
    );
    assert_eq!(
        probe(
            &su_tenant,
            &format!("SELECT (relowner::regrole::text = '{OWNER}')::text FROM pg_class WHERE relname = 't1_id_seq'")
        )
        .await,
        "true",
        "the serial sequence must be owner-owned"
    );
    assert_eq!(
        probe(
            &su_tenant,
            &format!("SELECT count(*)::int FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner WHERE r.rolname = '{DYN1}'")
        )
        .await,
        "0",
        "the dynamic role must own NOTHING"
    );

    // STEP 1b (Security MEDIUM-1): NOINHERIT structurally closes the `SET ROLE NONE` escape.
    // The happy path above (operate AS owner) is UNAFFECTED — owner authority flows through
    // the `SET role` GUC, not inheritance. But a dynamic role that drops back to its RAW
    // identity with `SET ROLE NONE` must NOT be able to create an owner-orphan object: it has
    // no direct CREATE grant on schema public, and NOINHERIT means it inherits none from the
    // owner. (Contrast STEP 4, which first GRANTs CREATE directly to materialize the hazard.)
    {
        let mut tx = dyn1.begin().await.unwrap();
        tx.execute("SET ROLE NONE", &[]).await.unwrap();
        let denied = tx
            .execute("CREATE TABLE noinherit_should_fail (id int)", &[])
            .await;
        assert!(
            denied.is_err(),
            "NOINHERIT must deny a raw (post-SET ROLE NONE) create with no direct grant — \
             the owner-orphan escape is closed structurally, not merely cleaned up after"
        );
        // The failed statement aborts the tx; roll back so nothing persists.
        let _ = tx.rollback().await;
    }
    // And the happy path still works right after: a fresh owner-authority create succeeds and
    // is owner-owned (NOINHERIT did not disturb operate-as-owner).
    dyn1.run_script("CREATE TABLE t1b (id int)")
        .await
        .expect("operate-as-owner create must still work under NOINHERIT");
    assert_eq!(
        probe(&su_tenant, &owned_by("t1b", OWNER)).await,
        "true",
        "operate-as-owner object stays owner-owned under NOINHERIT"
    );

    // =====================================================================
    // STEP 2: drop DYN1 cleanly (owns nothing) + its CONNECT grant is cleared.
    // =====================================================================
    for stmt in drop_dynamic_role_ddl(k, DYN1, OWNER) {
        su_tenant.run_script(&stmt).await.unwrap_or_else(|e| {
            panic!("drop dyn1 `{stmt}` must be CLEAN (dyn1 owns nothing): {e}")
        });
    }
    assert_eq!(
        probe(
            &su,
            &format!("SELECT (NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{DYN1}'))::text")
        )
        .await,
        "true",
        "dyn1 must be fully dropped"
    );
    assert_eq!(
        probe(
            &su,
            &format!("SELECT (coalesce(datacl::text,'') NOT LIKE '%{DYN1}%')::text FROM pg_database WHERE datname = '{DB}'")
        )
        .await,
        "true",
        "the dropped role's database-level CONNECT grant must be cleared"
    );

    // =====================================================================
    // STEP 3: a FRESH dynamic role has IDENTICAL access to the owner's objects.
    // =====================================================================
    for stmt in mint_dynamic_role_ddl(k, DB, OWNER, DYN2, DYN2_PW) {
        su.run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("mint dyn2 `{stmt}`: {e}"));
    }
    let dyn2 = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, DYN2, DYN2_PW, DB)),
    )
    .unwrap();
    for stmt in [
        "ALTER TABLE t1 ADD COLUMN w int", // owner-authority DDL on a pre-existing table
        "INSERT INTO t1 (v, w) VALUES ('from-dyn2', 7)",
        "CREATE TABLE t2 (id int)",
    ] {
        dyn2.run_script(stmt).await.unwrap_or_else(|e| {
            panic!("dyn2 identical-access `{stmt}` (must work — it IS the owner): {e}")
        });
    }
    assert_eq!(
        probe(&dyn2, "SELECT count(*)::int FROM t1").await,
        "2",
        "dyn2 must read dyn1-era data + its own row (identical access)"
    );
    assert_eq!(
        probe(&su_tenant, &owned_by("t2", OWNER)).await,
        "true",
        "t2 must be owner-owned too"
    );
    for stmt in drop_dynamic_role_ddl(k, DYN2, OWNER) {
        su_tenant
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("drop dyn2 `{stmt}`: {e}"));
    }

    // =====================================================================
    // STEP 4: escape safety net — SET ROLE NONE + create as the raw role (in ONE
    //         session), then the REASSIGN-OWNED safety net still makes the drop clean.
    // =====================================================================
    for stmt in mint_dynamic_role_ddl(k, DB, OWNER, DYN3, DYN3_PW) {
        su.run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("mint dyn3 `{stmt}`: {e}"));
    }
    su_tenant
        .run_script(&format!("GRANT CREATE ON SCHEMA public TO \"{DYN3}\""))
        .await
        .unwrap();
    let dyn3 = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, DYN3, DYN3_PW, DB)),
    )
    .unwrap();
    {
        // SET ROLE NONE + CREATE must share ONE connection → use a single transaction.
        let mut tx = dyn3.begin().await.unwrap();
        tx.execute("SET ROLE NONE", &[]).await.unwrap();
        tx.execute("CREATE TABLE escaped (id int)", &[])
            .await
            .expect("the raw role can create as itself after SET ROLE NONE (the hazard)");
        tx.commit().await.unwrap();
    }
    assert_eq!(
        probe(&su_tenant, &owned_by("escaped", DYN3)).await,
        "true",
        "escaped must initially be owned by the RAW dynamic role (the hazard materialized)"
    );
    // The safety net reassigns `escaped` to the owner, so the drop is clean.
    for stmt in drop_dynamic_role_ddl(k, DYN3, OWNER) {
        su_tenant.run_script(&stmt).await.unwrap_or_else(|e| {
            panic!("drop dyn3 `{stmt}` must be CLEAN via the REASSIGN safety net: {e}")
        });
    }
    assert_eq!(
        probe(&su_tenant, &owned_by("escaped", OWNER)).await,
        "true",
        "the escaped object must be reassigned to the owner (no orphan, no data loss)"
    );
    assert_eq!(
        probe(
            &su,
            &format!("SELECT (NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{DYN3}'))::text")
        )
        .await,
        "true",
        "dyn3 must be fully dropped despite the escape"
    );

    // =====================================================================
    // STEP 5: negative control — a naive role that owns an object CANNOT be dropped.
    // =====================================================================
    su.run_script(&format!(
        "CREATE ROLE \"{NAIVE}\" LOGIN NOSUPERUSER PASSWORD '{NAIVE_PW}'"
    ))
    .await
    .unwrap();
    su.run_script(&format!(
        "GRANT CONNECT ON DATABASE \"{DB}\" TO \"{NAIVE}\""
    ))
    .await
    .unwrap();
    su_tenant
        .run_script(&format!("GRANT CREATE ON SCHEMA public TO \"{NAIVE}\""))
        .await
        .unwrap();
    let naive = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, NAIVE, NAIVE_PW, DB)),
    )
    .unwrap();
    naive
        .run_script("CREATE TABLE orphan_tbl (id int)")
        .await
        .expect("naive role creates orphan_tbl as itself");
    assert!(
        su.run_script(&format!("DROP ROLE \"{NAIVE}\""))
            .await
            .is_err(),
        "a role that owns an object must NOT be droppable — the orphaning hazard the design removes"
    );
    // Clean up the control with the SAME safe sequence (reassign to owner, then drop).
    for stmt in drop_dynamic_role_ddl(k, NAIVE, OWNER) {
        let _ = su_tenant.run_script(&stmt).await;
    }

    // Teardown (best-effort).
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{ROLE}\""),
        format!("DROP ROLE IF EXISTS \"{OWNER}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    println!("DYNAMIC CRED OWNERSHIP OK [postgres]");
}
