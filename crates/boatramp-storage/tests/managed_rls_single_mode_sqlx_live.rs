//! **Live gate: the SINGLE-MODE `rls_session` opt-in (non-superuser app role) tenancy invariant.**
//!
//! The single-mode (dedicated-container) complement of [`managed_rls_nonowner_runtime_sqlx_live`].
//! A `tenant = single` managed Postgres is initialized with a **bootstrap superuser**
//! (`POSTGRES_USER`, `rolsuper`/`rolbypassrls`), which silently BYPASSES every table's row-level
//! security — so an app that runs `FORCE ROW LEVEL SECURITY` served on that superuser DSN has its
//! RLS un-enforced (a tenancy fail-open). The single-mode `rls_session` opt-in closes it: boatramp
//! provisions a STABLE **non-superuser app role** ([`rls_app_role_name`] via
//! [`ensure_login_role_ddl`] + [`grant_app_role_ddl`] + [`force_rls_event_trigger_ddl`]) that OWNS
//! NOTHING (the superuser owns the schema), and serves the runtime AS that role.
//!
//! On a real Postgres, with **≥ 2 app-level accounts** (A, B) sharing one `ENABLE ROW LEVEL
//! SECURITY` table keyed on an `app.account_id` GUC, this proves:
//!
//!   1. **INVARIANT (the fix):** served AS the provisioned non-superuser app role (pinned to account
//!      A), a `SELECT` returns ONLY account A's rows — ZERO account B bytes. Cross-account isolation
//!      is ENFORCED under the non-superuser role (a plain `ENABLE` binds a non-owner, no FORCE
//!      needed), and the runtime-role non-privilege probe ([`RUNTIME_ROLE_RLS_PRIVILEGED_PROBE_SQL`])
//!      reads `0` (unprivileged ⇒ the serving guard PERMITS it).
//!   2. **MUTATION / the fail-open the feature closes:** flip the runtime back to the bootstrap
//!      SUPERUSER (the pre-opt-in identity), pinned to the SAME account A — and the SAME `SELECT`
//!      against the SAME table returns BOTH accounts' rows: `rolsuper` bypasses RLS, so isolation
//!      BREAKS. The probe reads `1` (privileged ⇒ the serving guard REFUSES it fail-closed). This is
//!      exactly why single-mode RLS is sound ONLY when the serving role is the non-superuser app role;
//!      it proves the invariant is load-bearing, not vacuous.
//!   3. **The FORCE machinery ran:** the opt-in installs the FORCE-on-ENABLE event trigger (reusing
//!      the Shared machinery), so the table is `relforcerowsecurity` after `ENABLE` — defense-in-depth
//!      (the app role is a non-owner that `ENABLE` already binds; FORCE additionally binds any owner).
//!
//! Requires `BOATRAMP_TEST_PG_URL` = a **superuser** Postgres URL (skips cleanly when unset).
//! Marked `#[ignore]` (run it explicitly — e.g. on lighthouse — or via the live-pg CI lane, which
//! greps the marker). Prints `MANAGED RLS SINGLE-MODE OK [postgres]` on success.

#![cfg(feature = "sql-postgres")]

use std::sync::Arc;

use boatramp_core::sql::{SqlBackend, SqlValue};
use boatramp_storage::sql_sqlx::{ExternalSqlKind, ExternalSqlOptions, connect};
use boatramp_storage::tenant_provision::{
    RUNTIME_ROLE_RLS_PRIVILEGED_PROBE_SQL, ensure_login_role_ddl, force_rls_event_trigger_ddl,
    grant_app_role_ddl, rls_app_role_name, shared_default_db_connect_lockdown_ddl,
};

const DB: &str = "rlssingle_appdb";
const APP_PW: &str = "apppw";
const ACCT_GUC: &str = "app.account_id";
/// Account A — the account the serving session is pinned to (via a role-default GUC). It must see
/// ONLY its own rows under the non-superuser app role.
const ACCT_A: &str = "account-a";
/// Account B — a DIFFERENT app-level account. Invisible to A under the non-superuser role; LEAKED to
/// the bootstrap superuser (which bypasses RLS).
const ACCT_B: &str = "account-b";

/// Rewrite a superuser URL to connect as `user`/`pw` to database `db` (the harness pattern, shared
/// with [`managed_rls_nonowner_runtime_sqlx_live`]).
fn as_role(su_url: &str, user: &str, pw: &str, db: &str) -> String {
    let (scheme, rest) = su_url.split_once("://").expect("url has scheme");
    let after_at = rest.split_once('@').map(|(_, r)| r).unwrap_or(rest);
    let (hostport, _tail) = after_at.split_once('/').unwrap_or((after_at, ""));
    format!("{scheme}://{user}:{pw}@{hostport}/{db}")
}

/// Rewrite a superuser URL to connect to database `db` as the SUPERUSER (keeps its creds).
fn su_to_db(su_url: &str, db: &str) -> String {
    let (scheme, rest) = su_url.split_once("://").unwrap();
    let (creds, after) = rest.split_once('@').unwrap();
    let (hostport, _) = after.split_once('/').unwrap_or((after, ""));
    format!("{scheme}://{creds}@{hostport}/{db}")
}

/// The superuser's role NAME from the URL (`scheme://USER:pw@host/db`).
fn url_user(su_url: &str) -> String {
    let (_scheme, rest) = su_url.split_once("://").unwrap();
    let (creds, _after) = rest.split_once('@').unwrap();
    creds
        .split_once(':')
        .map(|(u, _)| u)
        .unwrap_or(creds)
        .to_string()
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
async fn single_mode_app_role_confines_accounts_while_the_superuser_leaks() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip managed_rls_single_mode: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let k = ExternalSqlKind::Postgres;
    let su = connect(k, &ExternalSqlOptions::new(su_url.clone())).unwrap();
    let superuser = url_user(&su_url);
    // The STABLE app role boatramp's single-mode provisioning derives from the database name — the
    // SAME name `rls_app_role_name` produces in `provision_rls_app_role`.
    let app_role = rls_app_role_name(DB);

    // --- teardown any prior run (re-runnable) ---
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{app_role}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    // Derivation invariant (unit-level, asserted next to the live proof): the provisioned app role is
    // STRUCTURALLY distinct from the bootstrap superuser — single-mode serving can never resolve the
    // superuser by name-collision.
    assert_ne!(
        app_role, superuser,
        "the single-mode app role must never collide with the bootstrap superuser name"
    );

    // =====================================================================
    // SETUP — the REAL single-mode provisioning: the superuser owns the DB + schema; the app role is
    // a STABLE non-superuser login that OWNS NOTHING (GRANT + DEFAULT PRIVILEGES only), exactly what
    // `provision_rls_app_role` runs on the tenant-DB superuser connection.
    // =====================================================================
    // (0) The superuser creates the database (so the SUPERUSER owns it + its schema — the single-mode
    //     container shape, where `POSTGRES_USER` owns everything initdb/migrations create).
    su.run_script(&format!("CREATE DATABASE \"{DB}\""))
        .await
        .unwrap_or_else(|e| panic!("create db: {e}"));
    let su_db = connect(k, &ExternalSqlOptions::new(su_to_db(&su_url, DB))).unwrap();

    // (1) Provision the app role: NOSUPERUSER/NOBYPASSRLS login + CONNECT, the app-role GRANTs +
    //     DEFAULT PRIVILEGES (owner = the schema-owning SUPERUSER), and the FORCE-on-ENABLE trigger
    //     (owned by the superuser). All on the tenant-DB superuser connection — byte-for-byte what
    //     `provision_rls_app_role` emits.
    let mut provision = ensure_login_role_ddl(k, &app_role, APP_PW, DB);
    provision.extend(grant_app_role_ddl(k, &app_role, &superuser));
    provision.extend(force_rls_event_trigger_ddl(k, &superuser));
    for stmt in provision {
        su_db
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("single-mode provision `{stmt}`: {e}"));
    }

    // The app role is genuinely NON-superuser / NON-BYPASSRLS (the whole point).
    assert_eq!(
        probe(
            &su_db,
            &format!(
                "SELECT (rolsuper OR rolbypassrls)::int FROM pg_roles WHERE rolname = '{app_role}'"
            )
        )
        .await,
        "0",
        "the provisioned app role must be NON-superuser and NON-BYPASSRLS"
    );

    // (2) As the SUPERUSER (the schema owner — the single-mode migrator identity), create a plain
    //     `ENABLE ROW LEVEL SECURITY` table with a per-ACCOUNT policy, and seed BOTH accounts' rows.
    //     DEFAULT PRIVILEGES (granted above, keyed on the superuser) make the new table readable by
    //     the app role.
    for stmt in [
        "CREATE TABLE t (account text, v int)".to_string(),
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY".to_string(),
        format!("CREATE POLICY p ON t USING (account = current_setting('{ACCT_GUC}', true))"),
        format!("INSERT INTO t (account, v) VALUES ('{ACCT_A}', 1)"),
        format!("INSERT INTO t (account, v) VALUES ('{ACCT_B}', 2)"),
    ] {
        su_db
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("superuser DDL/seed `{stmt}`: {e}"));
    }

    // The FORCE-on-ENABLE trigger fired on `ENABLE` → the table is now FORCE (defense-in-depth; the
    // Shared machinery ran). Both accounts' rows are physically present (the superuser, RLS-exempt,
    // sees both).
    assert_eq!(
        probe(
            &su_db,
            "SELECT relforcerowsecurity::text FROM pg_class WHERE relname = 't'"
        )
        .await,
        "true",
        "the single-mode opt-in's FORCE-on-ENABLE trigger must have upgraded the ENABLE table"
    );
    assert_eq!(
        probe(&su_db, "SELECT count(*)::int FROM t").await,
        "2",
        "both accounts' rows must exist on disk — the fence is RLS visibility, not a failed insert"
    );

    // (3) Pin the app role (and, for the mutation arm, prove the superuser) to account A via a
    //     role-default GUC, so the serving session carries `app.account_id = account-a` (mirrors how
    //     an app sets its own account per request). The leak in the mutation arm is then unambiguous:
    //     RLS EXEMPTION under the superuser, not a different GUC value.
    su.run_script(&format!(
        "ALTER ROLE \"{app_role}\" SET \"{ACCT_GUC}\" = '{ACCT_A}'"
    ))
    .await
    .unwrap();

    // =====================================================================
    // STEP 1 — INVARIANT: the NON-SUPERUSER app role is confined to account A (ZERO account-B bytes).
    // =====================================================================
    let app_conn = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, &app_role, APP_PW, DB)),
    )
    .unwrap();
    assert_eq!(
        probe(&app_conn, "SELECT current_user::text").await,
        app_role,
        "the single-mode runtime serves AS the provisioned non-superuser app role"
    );
    // The serving guard's probe PERMITS it: the resolved runtime role is unprivileged.
    assert_eq!(
        probe(&app_conn, RUNTIME_ROLE_RLS_PRIVILEGED_PROBE_SQL).await,
        "0",
        "the runtime-role non-privilege probe must read 0 (unprivileged ⇒ serving guard permits)"
    );
    assert_eq!(
        probe(&app_conn, "SELECT count(*)::int FROM t").await,
        "1",
        "CROSS-ACCOUNT LEAK: the non-superuser app role must see ONLY account A's row — the \
         single-mode tenancy guarantee the opt-in provides"
    );
    assert_eq!(
        probe(&app_conn, "SELECT account::text FROM t").await,
        ACCT_A,
        "the only row visible to the app role must be account A's"
    );

    // =====================================================================
    // STEP 2 — MUTATION (the fail-open the feature closes): flip the runtime to the bootstrap
    // SUPERUSER, pinned to the SAME account A, and it LEAKS BOTH accounts' rows — `rolsuper` bypasses
    // RLS (FORCE or not). This is exactly the pre-opt-in single-mode serving identity; the node's
    // serving guard REFUSES it fail-closed (the probe reads 1). It proves the non-superuser app role
    // is load-bearing: without it, single-mode RLS is silently un-enforced.
    // =====================================================================
    let su_serving = connect(k, &ExternalSqlOptions::new(su_to_db(&su_url, DB))).unwrap();
    su_serving
        .run_script(&format!("SET \"{ACCT_GUC}\" = '{ACCT_A}'"))
        .await
        .unwrap_or_else(|e| panic!("pin the superuser session to account A: {e}"));
    // The serving guard's probe REFUSES it: the resolved runtime role is privileged.
    assert_eq!(
        probe(&su_serving, RUNTIME_ROLE_RLS_PRIVILEGED_PROBE_SQL).await,
        "1",
        "the runtime-role non-privilege probe must read 1 for the superuser (privileged ⇒ serving \
         guard REFUSES fail-closed)"
    );
    assert_eq!(
        probe(&su_serving, "SELECT count(*)::int FROM t").await,
        "2",
        "MUTATION / EXPECTED-LEAK PROOF: served AS the bootstrap SUPERUSER, the SAME query sees BOTH \
         accounts' rows — rolsuper bypasses RLS, so single-mode isolation BREAKS without the \
         non-superuser app role (the fail-open the opt-in + guard close)"
    );

    // --- teardown (best-effort) ---
    drop(su_db);
    drop(su_serving);
    drop(app_conn);
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{app_role}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    println!("MANAGED RLS SINGLE-MODE OK [postgres]");
}

// ===========================================================================
// SHARED + DEFAULT cell (feat/shared-default-rls) — the reserved default tenant on a SHARED server.
// ===========================================================================

const SD_DB: &str = "rlsshareddefault_appdb";
/// The tenant GUC boatramp injects on the `rls_session` path (apps mirror it in their RLS so an app's
/// Postgres RLS tracks boatramp's host-resolved tenant). Here it models the **structural tenant
/// scoping** that must still bind the non-superuser app role in the Shared+default cell.
const SD_TENANT_GUC: &str = "app.tenant_id";
const SD_TENANT_A: &str = "tenant-a";
const SD_TENANT_B: &str = "tenant-b";

/// **Live gate: the SHARED + DEFAULT `rls_session` opt-in — the reserved default tenant on a shared
/// server.** Structurally the SAME superuser-owned cell as a `Single` install (the shared server's
/// OWN init database, superuser-owned, no per-tenant owner/runtime split), so it provisions + serves
/// the identical STABLE non-superuser app role via the identical DDL helpers. What is Shared-SPECIFIC
/// and proven here is the **coexistence of two session-var-keyed RLS layers on the non-superuser
/// role**: boatramp's injected **tenant** GUC (`app.tenant_id` — the structural tenant scoping the app
/// mirrors in RLS) AND the app's OWN **account** GUC (`app.account_id`). With ≥ 2 tenants × ≥ 2
/// accounts in one `ENABLE ROW LEVEL SECURITY` table keyed on BOTH, this proves on a real Postgres:
///
///   1. **INVARIANT (the fix + coexistence):** served AS the provisioned non-superuser app role
///      pinned to (tenant A, account A), a `SELECT` returns ONLY the (tenant A, account A) row — ZERO
///      foreign bytes across BOTH the tenant axis and the account axis. The structural tenant scoping
///      AND the app's own RLS both BIND the non-superuser role; the probe reads `0` (guard PERMITS).
///   2. **MUTATION / the fail-open this change closes:** flip the runtime to the shared server's
///      bootstrap SUPERUSER (the pre-opt-in Shared+default identity), pinned to the SAME GUCs — and the
///      SAME `SELECT` returns ALL rows: `rolsuper` bypasses RLS, so BOTH layers are silently
///      un-enforced. The probe reads `1` (guard REFUSES fail-closed). Proves the non-superuser role is
///      load-bearing for Shared+default too.
///
/// Requires `BOATRAMP_TEST_PG_URL` = a **superuser** Postgres URL (skips cleanly when unset).
/// `#[ignore]`-gated; prints `MANAGED RLS SHARED-DEFAULT OK [postgres]` on success.
#[tokio::test]
#[ignore = "needs a live superuser Postgres via BOATRAMP_TEST_PG_URL (run on lighthouse / the live-pg CI lane)"]
async fn shared_default_app_role_coexists_tenant_and_account_rls_while_the_superuser_leaks() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip managed_rls_shared_default: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let k = ExternalSqlKind::Postgres;
    let su = connect(k, &ExternalSqlOptions::new(su_url.clone())).unwrap();
    let superuser = url_user(&su_url);
    // The SAME role-name helper the node's Shared-arm provisioning uses (derived from the DB name).
    let app_role = rls_app_role_name(SD_DB);

    // --- teardown any prior run (re-runnable) ---
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{SD_DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{app_role}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }
    assert_ne!(
        app_role, superuser,
        "the Shared+default app role must never collide with the bootstrap superuser name"
    );

    // SETUP — the shared server's OWN default DB is superuser-owned (modeled by CREATE DATABASE as the
    // superuser), exactly like the Single install's DB. Provision the app role with the IDENTICAL
    // helpers the node runs (`provision_rls_app_role`): non-superuser login + GRANT/DEFAULT PRIVILEGES
    // (owner = the superuser) + the FORCE-on-ENABLE trigger.
    su.run_script(&format!("CREATE DATABASE \"{SD_DB}\""))
        .await
        .unwrap_or_else(|e| panic!("create db: {e}"));
    let su_db = connect(k, &ExternalSqlOptions::new(su_to_db(&su_url, SD_DB))).unwrap();
    let mut provision = ensure_login_role_ddl(k, &app_role, APP_PW, SD_DB);
    provision.extend(grant_app_role_ddl(k, &app_role, &superuser));
    provision.extend(force_rls_event_trigger_ddl(k, &superuser));
    for stmt in provision {
        su_db
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("shared-default provision `{stmt}`: {e}"));
    }
    assert_eq!(
        probe(
            &su_db,
            &format!(
                "SELECT (rolsuper OR rolbypassrls)::int FROM pg_roles WHERE rolname = '{app_role}'"
            )
        )
        .await,
        "0",
        "the provisioned Shared+default app role must be NON-superuser and NON-BYPASSRLS"
    );

    // As the SUPERUSER (schema owner / migrator), create an ENABLE-RLS table whose policy keys on BOTH
    // the injected TENANT GUC (structural scoping) AND the app's own ACCOUNT GUC, and seed a 2×2 grid
    // minus one so ≥ 2 tenants and ≥ 2 accounts are present.
    for stmt in [
        "CREATE TABLE t (tenant text, account text, v int)".to_string(),
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY".to_string(),
        format!(
            "CREATE POLICY p ON t USING (tenant = current_setting('{SD_TENANT_GUC}', true) \
             AND account = current_setting('{ACCT_GUC}', true))"
        ),
        format!("INSERT INTO t (tenant, account, v) VALUES ('{SD_TENANT_A}', '{ACCT_A}', 1)"),
        format!("INSERT INTO t (tenant, account, v) VALUES ('{SD_TENANT_A}', '{ACCT_B}', 2)"),
        format!("INSERT INTO t (tenant, account, v) VALUES ('{SD_TENANT_B}', '{ACCT_A}', 3)"),
    ] {
        su_db
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("superuser DDL/seed `{stmt}`: {e}"));
    }
    assert_eq!(
        probe(&su_db, "SELECT count(*)::int FROM t").await,
        "3",
        "all three rows must exist on disk — the fence is RLS visibility, not a failed insert"
    );

    // Pin the app role to (tenant A, account A) via role-default GUCs (mirrors how boatramp sets the
    // tenant GUC per request + how the app sets its own account GUC).
    for stmt in [
        format!("ALTER ROLE \"{app_role}\" SET \"{SD_TENANT_GUC}\" = '{SD_TENANT_A}'"),
        format!("ALTER ROLE \"{app_role}\" SET \"{ACCT_GUC}\" = '{ACCT_A}'"),
    ] {
        su.run_script(&stmt).await.unwrap();
    }

    // STEP 1 — INVARIANT + COEXISTENCE: the non-superuser app role sees ONLY (tenant A, account A).
    let app_conn = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, &app_role, APP_PW, SD_DB)),
    )
    .unwrap();
    assert_eq!(
        probe(&app_conn, "SELECT current_user::text").await,
        app_role,
        "the Shared+default runtime serves AS the provisioned non-superuser app role"
    );
    assert_eq!(
        probe(&app_conn, RUNTIME_ROLE_RLS_PRIVILEGED_PROBE_SQL).await,
        "0",
        "the runtime-role non-privilege probe must read 0 (unprivileged ⇒ serving guard permits)"
    );
    assert_eq!(
        probe(&app_conn, "SELECT count(*)::int FROM t").await,
        "1",
        "COEXISTENCE PROOF: the non-superuser app role is bound by BOTH the injected tenant GUC AND \
         the app's own account RLS — it sees ONLY the (tenant A, account A) row (zero foreign bytes \
         on either axis)"
    );
    assert_eq!(
        probe(&app_conn, "SELECT tenant || '/' || account FROM t").await,
        format!("{SD_TENANT_A}/{ACCT_A}"),
        "the only row visible to the app role must be (tenant A, account A)"
    );

    // STEP 2 — MUTATION: the bootstrap SUPERUSER (same GUCs) bypasses BOTH layers and sees ALL rows.
    let su_serving = connect(k, &ExternalSqlOptions::new(su_to_db(&su_url, SD_DB))).unwrap();
    for stmt in [
        format!("SET \"{SD_TENANT_GUC}\" = '{SD_TENANT_A}'"),
        format!("SET \"{ACCT_GUC}\" = '{ACCT_A}'"),
    ] {
        su_serving
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("pin the superuser session: {e}"));
    }
    assert_eq!(
        probe(&su_serving, RUNTIME_ROLE_RLS_PRIVILEGED_PROBE_SQL).await,
        "1",
        "the runtime-role non-privilege probe must read 1 for the superuser (privileged ⇒ REFUSE)"
    );
    assert_eq!(
        probe(&su_serving, "SELECT count(*)::int FROM t").await,
        "3",
        "MUTATION / EXPECTED-LEAK PROOF: served AS the bootstrap SUPERUSER, the SAME query sees ALL \
         rows — rolsuper bypasses RLS, so Shared+default isolation BREAKS without the non-superuser \
         app role (the fail-open this change closes)"
    );

    // --- teardown (best-effort) ---
    drop(su_db);
    drop(su_serving);
    drop(app_conn);
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{SD_DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{app_role}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    println!("MANAGED RLS SHARED-DEFAULT OK [postgres]");
}

// ===========================================================================
// SHARED + DEFAULT CONNECT lockdown (INFO-1) — the shared server's OWN init DB.
// ===========================================================================

const SDC_DB: &str = "rlssdconnect_appdb";
/// A STRAY cluster role modeling some OTHER tenant's per-tenant role. It is a member of `PUBLIC`
/// (every login is), but it is NEVER granted CONNECT on the default DB — so the lockdown must block
/// it. Non-superuser, so it is genuinely subject to the CONNECT privilege check.
const SDC_STRAY_ROLE: &str = "rlssdconnect_stray";
const SDC_STRAY_PW: &str = "straypw";

/// Connect as `url` and run a trivial `SELECT 1`, returning whether the connection + query
/// SUCCEEDED. A role denied `CONNECT` on the target database fails here (sqlx surfaces the privilege
/// error when the pooled connection is first acquired for the query), which is exactly the signal
/// the lockdown assertions need.
async fn can_connect(url: &str) -> bool {
    let k = ExternalSqlKind::Postgres;
    match connect(k, &ExternalSqlOptions::new(url.to_string())) {
        Ok(be) => be.run_query("SELECT 1").await.is_ok(),
        Err(_) => false,
    }
}

/// **Live gate: the INFO-1 CONNECT lockdown on the shared server's OWN default database.** The
/// shared server's init DB is created by the image's `initdb`, which leaves Postgres's default
/// everyone-in-`PUBLIC`-can-connect grant in place — so a stray per-tenant cluster role (a member of
/// `PUBLIC`) can `CONNECT` to it, unlike every NON-default Shared database (which `provision_shared`
/// already `REVOKE CONNECT … FROM PUBLIC`-locks). [`shared_default_db_connect_lockdown_ddl`] closes
/// that gap. On a real Postgres this proves, with a BEFORE/AFTER mutation:
///
///   1. **MUTATION / the gap (baseline):** a plain `CREATE DATABASE` (modeling `initdb`) leaves
///      `PUBLIC` able to connect, so the stray non-superuser role CAN connect to the default DB.
///   2. **INVARIANT (the fix):** after the lockdown DDL runs, the SAME stray role CANNOT connect
///      (`REVOKE CONNECT … FROM PUBLIC` with no grant to it), while BOTH legitimate principals still
///      connect and serve: the bootstrap SUPERUSER, and the STABLE non-superuser rls app role (its
///      explicit grant survives the PUBLIC revoke).
///   3. **IDEMPOTENT:** a second lockdown pass (the reconcile re-run) re-asserts the same state —
///      legitimate roles still connect, the stray stays blocked.
///
/// Requires `BOATRAMP_TEST_PG_URL` = a **superuser** Postgres URL (skips cleanly when unset).
/// `#[ignore]`-gated; prints `MANAGED RLS SHARED-DEFAULT CONNECT-LOCKDOWN OK [postgres]` on success.
#[tokio::test]
#[ignore = "needs a live superuser Postgres via BOATRAMP_TEST_PG_URL (run on lighthouse / the live-pg CI lane)"]
async fn shared_default_connect_lockdown_blocks_stray_roles_keeps_legitimate() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip managed_rls_shared_default_connect: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let k = ExternalSqlKind::Postgres;
    let su = connect(k, &ExternalSqlOptions::new(su_url.clone())).unwrap();
    let superuser = url_user(&su_url);
    let app_role = rls_app_role_name(SDC_DB);

    // --- teardown any prior run (re-runnable) ---
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{SDC_DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{app_role}\""),
        format!("DROP ROLE IF EXISTS \"{SDC_STRAY_ROLE}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    // SETUP — model the shared server's OWN init DB: a plain `CREATE DATABASE` as the superuser,
    // which (like `initdb`) leaves PUBLIC able to connect. Create the rls app role (with its own
    // CONNECT grant, exactly as `ensure_login_role_ddl` does on the opt-in path) and a STRAY
    // non-superuser role that is NEVER granted CONNECT here.
    su.run_script(&format!("CREATE DATABASE \"{SDC_DB}\""))
        .await
        .unwrap_or_else(|e| panic!("create db: {e}"));
    let su_db = connect(k, &ExternalSqlOptions::new(su_to_db(&su_url, SDC_DB))).unwrap();
    for stmt in ensure_login_role_ddl(k, &app_role, APP_PW, SDC_DB) {
        su_db
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("provision app role `{stmt}`: {e}"));
    }
    su.run_script(&format!(
        "CREATE ROLE \"{SDC_STRAY_ROLE}\" LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{SDC_STRAY_PW}'"
    ))
    .await
    .unwrap_or_else(|e| panic!("create stray role: {e}"));

    let stray_url = as_role(&su_url, SDC_STRAY_ROLE, SDC_STRAY_PW, SDC_DB);
    let app_url = as_role(&su_url, &app_role, APP_PW, SDC_DB);
    let su_db_url = su_to_db(&su_url, SDC_DB);

    // STEP 1 — MUTATION / the gap: before the lockdown, PUBLIC's default connect grant lets the
    // stray role reach the default DB.
    assert!(
        can_connect(&stray_url).await,
        "BASELINE/MUTATION: before the lockdown a stray PUBLIC member CAN connect to the shared \
         server's default DB (the INFO-1 gap left by initdb) — if this is already false the test is \
         not exercising the gap"
    );

    // STEP 2 — THE FIX: run the real lockdown DDL (opted-in cell ⇒ the app role is admitted too).
    let lockdown = shared_default_db_connect_lockdown_ddl(k, SDC_DB, &superuser, true);
    assert!(
        !lockdown.is_empty(),
        "the Postgres lockdown DDL must be non-empty"
    );
    for stmt in &lockdown {
        su_db
            .run_script(stmt)
            .await
            .unwrap_or_else(|e| panic!("lockdown `{stmt}`: {e}"));
    }

    // STEP 3 — INVARIANT: the stray role is now BLOCKED, both legitimate principals still connect.
    assert!(
        !can_connect(&stray_url).await,
        "INVARIANT: after REVOKE CONNECT … FROM PUBLIC the stray role must NOT be able to connect \
         to the shared server's default DB"
    );
    assert!(
        can_connect(&su_db_url).await,
        "the bootstrap superuser must still connect to its own default DB after the lockdown"
    );
    assert!(
        can_connect(&app_url).await,
        "the STABLE non-superuser rls app role must still connect after the lockdown (its explicit \
         CONNECT grant survives the PUBLIC revoke)"
    );

    // STEP 4 — IDEMPOTENT: a second reconcile pass re-asserts the same state.
    for stmt in &lockdown {
        su_db
            .run_script(stmt)
            .await
            .unwrap_or_else(|e| panic!("idempotent re-run `{stmt}`: {e}"));
    }
    assert!(
        !can_connect(&stray_url).await,
        "IDEMPOTENT: the stray role stays blocked after a second lockdown pass"
    );
    assert!(
        can_connect(&su_db_url).await && can_connect(&app_url).await,
        "IDEMPOTENT: both legitimate principals still connect after a second lockdown pass"
    );

    // --- teardown (best-effort) ---
    drop(su_db);
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{SDC_DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{app_role}\""),
        format!("DROP ROLE IF EXISTS \"{SDC_STRAY_ROLE}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    println!("MANAGED RLS SHARED-DEFAULT CONNECT-LOCKDOWN OK [postgres]");
}
