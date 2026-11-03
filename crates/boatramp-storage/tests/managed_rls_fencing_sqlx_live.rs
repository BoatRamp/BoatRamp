//! **Live gate: container RLS fencing (v0.53.0).**
//!
//! The LOAD-BEARING proof that the opt-in RLS fencing feature actually enforces Postgres RLS
//! against the operate-as-owner managed credential — it can only be ruled in against a REAL
//! Postgres, because it rides on the engine's own owner-vs-FORCE row-security semantics:
//! PostgreSQL does NOT enforce a table's plain `ENABLE ROW LEVEL SECURITY` against the table's
//! OWNER, only `FORCE ROW LEVEL SECURITY` binds the owner — and a managed container connects as a
//! per-replica dynamic role that `SET role = <owner>`s (operate-as-owner, so one DSN auto-migrates).
//!
//! It stands up EXACTLY the model the builders emit, in the SAME placement the node-side
//! `provision_shared` / `mint_dynamic_role` use:
//!   1. [`provision_ddl`] (runtime + stable owner roles, owner-owned tenant DB, PUBLIC lockdown) on
//!      the MAINTENANCE connection — `rls_session = false` there, because the event trigger is a
//!      per-database object.
//!   2. [`force_rls_event_trigger_ddl`] on the TENANT-DB superuser connection — installs the
//!      FORCE-on-ENABLE event trigger (the `SECURITY DEFINER` function owned by the per-tenant
//!      owner).
//!   3. [`mint_dynamic_role_ddl`] WITH the fencing config on the MAINTENANCE connection — bakes the
//!      resolved tenant into the dynamic role as the role-default `app.tenant_id` GUC.
//!
//! Then, connected AS the dynamic role (operate-as-owner), it proves:
//!   - the event trigger FORCED a plain `ENABLE ROW LEVEL SECURITY` table (`relforcerowsecurity`);
//!   - the role-default GUC carries the minted tenant (`current_setting('app.tenant_id', true)`);
//!   - **the load-bearing assertion** — a `SELECT` returns ONLY the matching-tenant row, the
//!     other-tenant row is invisible (FORCE binds the owner the dynamic role acts as);
//!   - a no-RLS table is NOT broken by a blanket FORCE (the fencing is surgical).
//!
//! Requires `BOATRAMP_TEST_PG_URL` = a **superuser** Postgres URL (skips cleanly when unset).
//! Marked `#[ignore]` (run it explicitly — e.g. on lighthouse — or via the live-pg CI lane, which
//! greps the marker). Prints `MANAGED RLS FENCING OK [postgres]` on success.

#![cfg(feature = "sql-postgres")]

use std::sync::Arc;

use boatramp_core::sql::{SqlBackend, SqlValue};
use boatramp_storage::sql_sqlx::{ExternalSqlKind, ExternalSqlOptions, connect};
use boatramp_storage::tenant_provision::{
    RlsFencing, drop_dynamic_role_ddl, force_rls_event_trigger_ddl, mint_dynamic_role_ddl,
    provision_ddl,
};

const DB: &str = "rlsfence_appdb";
const ROLE: &str = "rlsfence_role";
const ROLE_PW: &str = "rolepw";
const OWNER: &str = "rlsfence_owner";
const OWNER_PW: &str = "0wnerpw";
const DYN: &str = "rlsfence_appdb_d_web_0";
const DYN_PW: &str = "d0pw";

const TENANT_GUC: &str = "app.tenant_id";
/// The tenant this replica's dynamic role is minted for — baked as the role-default GUC.
const TENANT: &str = "acme-tenant";
/// A DIFFERENT tenant's value — its row must be invisible to the (owner-acting) dynamic role.
const OTHER_TENANT: &str = "intruder-tenant";

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
async fn managed_rls_fencing_enforces_against_the_owner_on_a_real_postgres() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip managed_rls_fencing: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let k = ExternalSqlKind::Postgres;
    let su = connect(k, &ExternalSqlOptions::new(su_url.clone())).unwrap();

    // A superuser connection to the TENANT db — where the event trigger lives + where the
    // cross-tenant other-row is seeded (the superuser bypasses RLS entirely).
    let su_tenant_url = {
        let (scheme, rest) = su_url.split_once("://").unwrap();
        let (creds, after) = rest.split_once('@').unwrap();
        let (hostport, _) = after.split_once('/').unwrap_or((after, ""));
        format!("{scheme}://{creds}@{hostport}/{DB}")
    };

    // --- teardown any prior run (re-runnable). The event trigger + function live inside the DB,
    //     so they drop with it. ---
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{DYN}\""),
        format!("DROP ROLE IF EXISTS \"{ROLE}\""),
        format!("DROP ROLE IF EXISTS \"{OWNER}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    // =====================================================================
    // SETUP — exactly the node-side provision_shared placement:
    //   provision (maintenance) → event trigger (tenant DB) → mint w/ fencing (maintenance).
    // =====================================================================
    // (1) Provision on the MAINTENANCE connection. `rls_session = false` here: the event trigger
    //     is a per-database object and must be installed on the tenant-DB connection, below.
    for stmt in provision_ddl(k, DB, ROLE, ROLE_PW, OWNER, OWNER_PW, false) {
        su.run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("provision `{stmt}`: {e}"));
    }
    let su_tenant = connect(k, &ExternalSqlOptions::new(su_tenant_url.clone())).unwrap();

    // (2) Install the FORCE-on-ENABLE event trigger on the TENANT-DB superuser connection — the
    //     SAME builder + placement provision_shared uses.
    for stmt in force_rls_event_trigger_ddl(k, OWNER) {
        su_tenant
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("install event trigger `{stmt}`: {e}"));
    }

    // (3) Mint the per-replica dynamic role WITH the fencing config — bakes the resolved tenant
    //     into the role as the role-default `app.tenant_id` GUC.
    let fencing = RlsFencing {
        tenant_guc: TENANT_GUC.to_string(),
        tenant_value: TENANT.to_string(),
        session_guc: None,
        session_value: None,
        kind_guc: None,
        kind_value: None,
    };
    for stmt in mint_dynamic_role_ddl(k, DB, OWNER, DYN, DYN_PW, Some(&fencing)) {
        su.run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("mint `{stmt}`: {e}"));
    }

    // The container's runtime connection: the dynamic role, operate-as-owner, on the tenant DB.
    let dynrole = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, DYN, DYN_PW, DB)),
    )
    .unwrap();
    // Sanity: session_user = the dynamic role, current_user = the stable owner (operate-as-owner).
    assert_eq!(
        probe(&dynrole, "SELECT session_user::text").await,
        DYN,
        "session_user must be the dynamic role"
    );
    assert_eq!(
        probe(&dynrole, "SELECT current_user::text").await,
        OWNER,
        "current_user must be the stable owner (operate-as-owner)"
    );

    // =====================================================================
    // STEP 1: a plain `ENABLE ROW LEVEL SECURITY` table — as the app/ORM would write it.
    // =====================================================================
    for stmt in [
        "CREATE TABLE t (tenant text, v int)",
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY",
        &format!("CREATE POLICY p ON t USING (tenant = current_setting('{TENANT_GUC}', true))"),
    ] {
        dynrole
            .run_script(stmt)
            .await
            .unwrap_or_else(|e| panic!("app DDL `{stmt}`: {e}"));
    }

    // STEP 2: the event trigger FORCED it — plain ENABLE alone would NOT bind the owner.
    assert_eq!(
        probe(
            &su_tenant,
            "SELECT relforcerowsecurity::text FROM pg_class WHERE relname = 't'"
        )
        .await,
        "true",
        "the FORCE-on-ENABLE event trigger must have forced RLS on the RLS-enabled table"
    );

    // STEP 3: the role-default GUC carries the minted tenant (the backstop for a connection — the
    // ORM auto-migrate path — that never sets it per-request).
    assert_eq!(
        probe(
            &dynrole,
            &format!("SELECT current_setting('{TENANT_GUC}', true)")
        )
        .await,
        TENANT,
        "the dynamic role's baked role-default tenant GUC must carry the minted tenant"
    );

    // STEP 4 (LOAD-BEARING): with two tenants' rows present, a SELECT as the (owner-acting) dynamic
    // role returns ONLY the matching-tenant row — the other-tenant row is invisible because FORCE
    // binds the owner. The dynamic role inserts its OWN tenant's row (proving the operate-as-owner
    // write passes WITH CHECK under FORCE); the other-tenant row is seeded by the superuser (which
    // bypasses RLS), so it genuinely exists on disk.
    dynrole
        .run_script(&format!("INSERT INTO t (tenant, v) VALUES ('{TENANT}', 1)"))
        .await
        .expect("the operate-as-owner role must be able to write its OWN tenant's row under FORCE");
    su_tenant
        .run_script(&format!(
            "INSERT INTO t (tenant, v) VALUES ('{OTHER_TENANT}', 2)"
        ))
        .await
        .expect("superuser seeds the other-tenant row (bypasses RLS)");
    // Exactly one row is visible to the dynamic role...
    assert_eq!(
        probe(&dynrole, "SELECT count(*)::int FROM t").await,
        "1",
        "CROSS-TENANT LEAK: the owner-acting dynamic role must see ONLY its own tenant's row"
    );
    // ...and it is the matching-tenant row (never the intruder's).
    assert_eq!(
        probe(&dynrole, "SELECT tenant::text FROM t").await,
        TENANT,
        "the only visible row must be the minted tenant's — the other tenant's row is fenced out"
    );
    // The row IS physically present (non-vacuity: the superuser, bypassing RLS, sees both).
    assert_eq!(
        probe(&su_tenant, "SELECT count(*)::int FROM t").await,
        "2",
        "both rows must exist on disk — the fence is RLS visibility, not a failed insert"
    );

    // STEP 5 (positive / no-break control): a NO-RLS table (WordPress-style) is NOT broken by a
    // blanket FORCE — the event trigger is surgical (only touches a table that enabled RLS).
    dynrole
        .run_script("CREATE TABLE plain (v int)")
        .await
        .expect("creating a no-RLS table must succeed");
    assert_eq!(
        probe(
            &su_tenant,
            "SELECT relforcerowsecurity::text FROM pg_class WHERE relname = 'plain'"
        )
        .await,
        "false",
        "a no-RLS table must NOT be force-enabled (the fencing is surgical, not blanket)"
    );
    for stmt in [
        "INSERT INTO plain (v) VALUES (10), (20)",
        "SELECT count(*)::int FROM plain",
    ] {
        // Freely readable/writable — no RLS, no fence.
        let _ = dynrole
            .run_query(stmt)
            .await
            .unwrap_or_else(|e| panic!("no-RLS table must be freely usable `{stmt}`: {e}"));
    }
    assert_eq!(
        probe(&dynrole, "SELECT count(*)::int FROM plain").await,
        "2",
        "the no-RLS table must return all rows to the dynamic role"
    );

    // --- clean drop of the dynamic role (it owns nothing — operate-as-owner), connected to the
    //     tenant DB where REASSIGN/DROP OWNED run, so the gate stays re-runnable. ---
    for stmt in drop_dynamic_role_ddl(k, DYN, OWNER) {
        su_tenant
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("drop dyn `{stmt}`: {e}"));
    }
    // Teardown (best-effort).
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{ROLE}\""),
        format!("DROP ROLE IF EXISTS \"{OWNER}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    println!("MANAGED RLS FENCING OK [postgres]");
}
