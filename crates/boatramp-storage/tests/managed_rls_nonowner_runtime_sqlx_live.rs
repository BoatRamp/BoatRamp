//! **Live gate: the `rls_session` NON-OWNER-runtime tenancy invariant (fix/rls-tenancy-contract).**
//!
//! The complement of [`managed_rls_fencing_sqlx_live`]. That gate proves the OPERATE-AS-OWNER
//! managed-compute path needs `FORCE ROW LEVEL SECURITY` for RLS to bind (because PostgreSQL does
//! NOT enforce a plain `ENABLE ROW LEVEL SECURITY` table against its OWNER). THIS gate proves the
//! OTHER half of boatramp's two-posture `rls_session` contract — the one the WASI/FaaS **handler**
//! serving path ([`NodeTenantSqlResolver::build_backend`]) actually runs on, and the posture a
//! tenant like `construens` deploys:
//!
//!   * the handler serving path connects as the per-tenant **runtime `_role`** — a NON-OWNER
//!     ([`tenant_role_name`], kept non-superuser + non-owner precisely so RLS is enforced against
//!     it), distinct from the stable **owner `_owner`** ([`tenant_owner_role_name`]);
//!   * against a plain `ENABLE ROW LEVEL SECURITY` table (NO `FORCE`, NO force-trigger), a
//!     non-owner IS bound by RLS — so the serving path is confined to its own tenant with ZERO
//!     `FORCE` needed. `FORCE` is a defense-in-depth backstop for the owner posture, not the
//!     primary guarantee on the handler path.
//!
//! It stands up the REAL three-identity [`provision_ddl`] + [`grant_app_role_ddl`] model (runtime
//! `_role`, stable `_owner`, owner-owned tenant DB, PUBLIC lockdown) — `rls_session = false`, i.e.
//! NO force-trigger, exactly the `construens` shape — then, with TWO tenants' rows present in one
//! shared table, proves on a real Postgres:
//!
//!   1. **INVARIANT (the handler-path guarantee):** as the NON-OWNER runtime role, a `SELECT`
//!      returns ONLY its own tenant's row — the other tenant's row is invisible. ZERO foreign
//!      bytes under plain `ENABLE`, no `FORCE`.
//!   2. **FAILURE MODE / the crux leak (the owner posture must NOT serve):** as the OWNER role
//!      (the operate-as-owner identity the managed-compute dynamic role acts as), the SAME
//!      `SELECT` against the SAME `ENABLE`-not-`FORCE` table returns BOTH rows — a cross-tenant
//!      leak. This is exactly why `rls_session` is sound ONLY when the serving role is a non-owner
//!      (handler path) OR `FORCE` is in effect (owner path); it proves the invariant is load-
//!      bearing rather than vacuous.
//!   3. **`FORCE` closes the owner leak:** after `ALTER TABLE … FORCE ROW LEVEL SECURITY`, the
//!      owner-role `SELECT` returns ONLY its tenant's row — matching the fencing gate, and proving
//!      the failure in (2) is precisely the owner/`FORCE` semantics, not a seeding/visibility bug.
//!
//! This file ALSO carries the **`serve_as` serving-posture gate** ("Option C", v0.59.4):
//! [`serve_as_posture_drives_force_install_and_confines_each_posture`] proves the declared posture
//! drives the FORCE install and the serving role — `non-owner` (default) serves the non-owner role
//! confined by `ENABLE` with NO trigger; `owner` installs the FORCE trigger and serves the owner
//! role confined by `FORCE`; and the MUTATION arm exhibits the cross-tenant leak (owner-serving with
//! FORCE absent) that the node guard refuses fail-closed. It prints `MANAGED RLS SERVE-AS POSTURE OK
//! [postgres]`.
//!
//! Requires `BOATRAMP_TEST_PG_URL` = a **superuser** Postgres URL (skips cleanly when unset).
//! Marked `#[ignore]` (run it explicitly — e.g. on lighthouse — or via the live-pg CI lane, which
//! greps the marker). Prints `MANAGED RLS NON-OWNER RUNTIME OK [postgres]` on success.

#![cfg(feature = "sql-postgres")]

use std::sync::Arc;

use boatramp_core::sql::{SqlBackend, SqlValue};
use boatramp_storage::sql_sqlx::{ExternalSqlKind, ExternalSqlOptions, connect};
use boatramp_storage::tenant_provision::{
    RLS_ENABLE_NOT_FORCE_COUNT_SQL, force_rls_event_trigger_ddl, force_rls_sweep_ddl,
    grant_app_role_ddl, provision_ddl, tenant_owner_role_name, tenant_role_name,
};

const DB: &str = "rlsnonowner_appdb";
const ROLE: &str = "rlsnonowner_role";
const ROLE_PW: &str = "rolepw";
const OWNER: &str = "rlsnonowner_owner";
const OWNER_PW: &str = "0wnerpw";

const TENANT_GUC: &str = "app.tenant_id";
/// The tenant BOTH the runtime role and the owner role are pinned to (role-default GUC). The
/// runtime (non-owner) must see ONLY this tenant's row; the owner (ENABLE-not-FORCE) must see both.
const TENANT: &str = "acme-tenant";
/// A DIFFERENT tenant's row — invisible to the non-owner runtime, but leaked to the owner until FORCE.
const OTHER_TENANT: &str = "intruder-tenant";

/// Rewrite a superuser URL to connect as `user`/`pw` to database `db` (the harness pattern, shared
/// with [`managed_rls_fencing_sqlx_live`]).
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
async fn nonowner_runtime_is_confined_by_plain_enable_while_the_owner_posture_leaks() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip managed_rls_nonowner_runtime: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let k = ExternalSqlKind::Postgres;
    let su = connect(k, &ExternalSqlOptions::new(su_url.clone())).unwrap();

    // A superuser connection to the TENANT db — where the schema + the cross-tenant other-row are
    // seeded for the non-vacuity check (the superuser bypasses RLS entirely).
    let su_tenant_url = {
        let (scheme, rest) = su_url.split_once("://").unwrap();
        let (creds, after) = rest.split_once('@').unwrap();
        let (hostport, _) = after.split_once('/').unwrap_or((after, ""));
        format!("{scheme}://{creds}@{hostport}/{DB}")
    };

    // --- teardown any prior run (re-runnable) ---
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{ROLE}\""),
        format!("DROP ROLE IF EXISTS \"{OWNER}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    // Derivation invariant (unit-level, but asserted here next to the live proof): the serving
    // runtime role is STRUCTURALLY distinct from the owner — the handler path can never connect as
    // the owner by name-collision. `base`/`ident` are arbitrary; the point is `_role != _owner`.
    assert_ne!(
        tenant_role_name("pg", "acme-abc123"),
        tenant_owner_role_name("pg", "acme-abc123"),
        "the runtime (_role) and owner (_owner) derivations must never collide — the handler \
         serving path connects as the NON-OWNER runtime role"
    );

    // =====================================================================
    // SETUP — the REAL provision_ddl three-identity model, NO force-trigger (rls_session=false):
    // the `construens` shape (non-owner runtime + ENABLE-not-FORCE + an inert/absent force-trigger).
    // =====================================================================
    // (1) Provision on the MAINTENANCE connection: runtime `_role` (non-owner), stable `_owner`,
    //     owner-owned DB, REVOKE CONNECT FROM PUBLIC. `rls_session = false` ⇒ NO force event trigger.
    for stmt in provision_ddl(k, DB, ROLE, ROLE_PW, OWNER, OWNER_PW, false) {
        su.run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("provision `{stmt}`: {e}"));
    }
    let su_tenant = connect(k, &ExternalSqlOptions::new(su_tenant_url.clone())).unwrap();

    // (2) Grant the NON-OWNER runtime role the everyday app DML — INCLUDING default privileges for
    //     objects the OWNER creates later (so the table the owner makes below is readable by the
    //     runtime role). Runs as the superuser on the tenant DB, BEFORE the owner creates the table.
    for stmt in grant_app_role_ddl(k, ROLE, OWNER) {
        su_tenant
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("grant app role `{stmt}`: {e}"));
    }

    // (3) Pin BOTH the runtime role and the owner role to the SAME tenant via a role-default GUC —
    //     so every session carries `app.tenant_id = acme-tenant` without a per-request SET (mirrors
    //     how the handler injects it / the dynamic role bakes it). The owner is pinned to the SAME
    //     tenant so the leak in step 2 is unambiguous: it is RLS EXEMPTION, not a different GUC.
    for stmt in [
        format!("ALTER ROLE \"{ROLE}\" SET \"{TENANT_GUC}\" = '{TENANT}'"),
        format!("ALTER ROLE \"{OWNER}\" SET \"{TENANT_GUC}\" = '{TENANT}'"),
    ] {
        su.run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("pin role-default GUC `{stmt}`: {e}"));
    }

    // (4) As the OWNER (construens's migrator identity), create a plain `ENABLE ROW LEVEL SECURITY`
    //     table (NO FORCE) with a per-tenant policy, and seed its OWN tenant's row. The owner relies
    //     on NO-FORCE to seed freely — exactly construens's "migrator runs AS the owner and relies
    //     on NO-FORCE to seed data" model.
    let owner_conn = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, OWNER, OWNER_PW, DB)),
    )
    .unwrap();
    for stmt in [
        "CREATE TABLE t (tenant text, v int)",
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY",
        &format!("CREATE POLICY p ON t USING (tenant = current_setting('{TENANT_GUC}', true))"),
        &format!("INSERT INTO t (tenant, v) VALUES ('{TENANT}', 1)"),
    ] {
        owner_conn
            .run_script(stmt)
            .await
            .unwrap_or_else(|e| panic!("owner DDL/seed `{stmt}`: {e}"));
    }
    // The OTHER tenant's row, seeded by the superuser (bypasses RLS) so it genuinely exists on disk.
    su_tenant
        .run_script(&format!(
            "INSERT INTO t (tenant, v) VALUES ('{OTHER_TENANT}', 2)"
        ))
        .await
        .expect("superuser seeds the other-tenant row (bypasses RLS)");

    // Sanity: the table is ENABLE but NOT FORCE (the construens shape — no force-trigger upgraded it).
    assert_eq!(
        probe(
            &su_tenant,
            "SELECT relrowsecurity::text FROM pg_class WHERE relname = 't'"
        )
        .await,
        "true",
        "RLS must be ENABLED on t"
    );
    assert_eq!(
        probe(
            &su_tenant,
            "SELECT relforcerowsecurity::text FROM pg_class WHERE relname = 't'"
        )
        .await,
        "false",
        "t must be ENABLE-but-NOT-FORCE (no force-trigger ran — the construens shape)"
    );
    // Non-vacuity: both rows physically present (the superuser, RLS-exempt, sees both).
    assert_eq!(
        probe(&su_tenant, "SELECT count(*)::int FROM t").await,
        "2",
        "both tenants' rows must exist on disk — the fence is RLS visibility, not a failed insert"
    );

    // =====================================================================
    // STEP 1 — INVARIANT: the NON-OWNER runtime role is confined by plain ENABLE (ZERO foreign bytes).
    // =====================================================================
    let runtime = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, ROLE, ROLE_PW, DB)),
    )
    .unwrap();
    // It really is the non-owner runtime role (session_user == current_user == ROLE; NOT operate-as-owner).
    assert_eq!(
        probe(&runtime, "SELECT current_user::text").await,
        ROLE,
        "the handler serving path connects AS the non-owner runtime role"
    );
    assert_eq!(
        probe(
            &runtime,
            &format!("SELECT current_setting('{TENANT_GUC}', true)")
        )
        .await,
        TENANT,
        "the runtime role's baked role-default tenant GUC must carry its tenant"
    );
    assert_eq!(
        probe(&runtime, "SELECT count(*)::int FROM t").await,
        "1",
        "CROSS-TENANT LEAK: the NON-OWNER runtime role must see ONLY its own tenant's row under \
         plain ENABLE (no FORCE needed) — this is the handler-path tenancy guarantee"
    );
    assert_eq!(
        probe(&runtime, "SELECT tenant::text FROM t").await,
        TENANT,
        "the only row visible to the non-owner runtime must be its own tenant's"
    );

    // =====================================================================
    // STEP 2 — FAILURE MODE (the crux): the OWNER posture against ENABLE-not-FORCE LEAKS both rows.
    // This is why the owner-posture managed-compute path REQUIRES FORCE, and why a tenant whose
    // runtime operates-as-owner must NOT drop FORCE. On the handler (non-owner) path above, it cannot
    // happen; here we PROVE the invariant is load-bearing by exhibiting the leak when it is violated.
    // =====================================================================
    assert_eq!(
        probe(&owner_conn, "SELECT current_user::text").await,
        OWNER,
        "the owner connection acts as the table OWNER"
    );
    assert_eq!(
        probe(&owner_conn, "SELECT count(*)::int FROM t").await,
        "2",
        "EXPECTED-LEAK PROOF: the OWNER sees BOTH tenants' rows under ENABLE-not-FORCE — plain \
         ENABLE does NOT bind the owner, so an owner-posture serving role would leak cross-tenant"
    );

    // =====================================================================
    // STEP 3 — FORCE closes the owner leak (confirming step 2 is the owner/FORCE semantics).
    // =====================================================================
    owner_conn
        .run_script("ALTER TABLE t FORCE ROW LEVEL SECURITY")
        .await
        .expect("the table owner may FORCE RLS on its own table");
    // A fresh owner connection (the role-default GUC still pins it to TENANT) now sees ONLY its row.
    let owner_forced = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, OWNER, OWNER_PW, DB)),
    )
    .unwrap();
    assert_eq!(
        probe(&owner_forced, "SELECT count(*)::int FROM t").await,
        "1",
        "after FORCE, the OWNER too is bound by RLS — it sees ONLY its own tenant's row"
    );
    assert_eq!(
        probe(&owner_forced, "SELECT tenant::text FROM t").await,
        TENANT,
        "post-FORCE, the only owner-visible row is its own tenant's"
    );
    // The non-owner runtime is UNAFFECTED by the FORCE toggle — still confined (ENABLE already bound it).
    assert_eq!(
        probe(&runtime, "SELECT count(*)::int FROM t").await,
        "1",
        "the non-owner runtime stays confined regardless of FORCE — ENABLE already bound it"
    );

    // --- teardown (best-effort) ---
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{ROLE}\""),
        format!("DROP ROLE IF EXISTS \"{OWNER}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    println!("MANAGED RLS NON-OWNER RUNTIME OK [postgres]");
}

// ===========================================================================
// serve_as POSTURE gate ("Option C", v0.59.4) — the posture DRIVES the FORCE install + the
// serving role, and the owner-serving ⟺ FORCE invariant holds on a real Postgres.
// ===========================================================================

/// Reproduce the node's `provision_shared` for ONE posture, faithfully: the real three-identity
/// `provision_ddl` (NO force-append — the node passes `false` to it) on the maintenance connection,
/// `grant_app_role_ddl` on the tenant DB, and — IFF the posture installs FORCE (`serve_as: owner`,
/// i.e. `install_force = rls_session && owner`) — `force_rls_event_trigger_ddl` on the tenant DB
/// (the event trigger is a per-database object, so it MUST land there). This is byte-for-byte what
/// `NodeTenantSqlResolver`'s provisioning does for the posture; the test then proves the serving
/// confinement the posture produces.
/// The per-posture provisioning inputs for [`provision_posture`], grouped into one struct so the
/// helper stays within clippy's argument budget (the node resolves these from a single binding +
/// posture; the test spells them out).
struct PosturePlan<'a> {
    db: &'a str,
    role: &'a str,
    role_pw: &'a str,
    owner: &'a str,
    owner_pw: &'a str,
    /// Exactly `install_force_rls(rls_session, serve_as, kind)` in the node — `true` only for the
    /// `serve_as: owner` posture (installs the FORCE-on-ENABLE event trigger); a `non-owner` posture
    /// installs NOTHING.
    install_force: bool,
}

async fn provision_posture(
    su: &std::sync::Arc<dyn SqlBackend>,
    su_tenant: &std::sync::Arc<dyn SqlBackend>,
    plan: PosturePlan<'_>,
) {
    let k = ExternalSqlKind::Postgres;
    for stmt in provision_ddl(
        k,
        plan.db,
        plan.role,
        plan.role_pw,
        plan.owner,
        plan.owner_pw,
        false,
    ) {
        su.run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("provision `{stmt}`: {e}"));
    }
    for stmt in grant_app_role_ddl(k, plan.role, plan.owner) {
        su_tenant
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("grant app role `{stmt}`: {e}"));
    }
    // The posture's FORCE install — exactly `install_force_rls(rls_session, serve_as, kind)` in the
    // node (true only for `serve_as: owner`). A `non-owner` posture installs NOTHING here.
    if plan.install_force {
        for stmt in force_rls_event_trigger_ddl(k, plan.owner) {
            su_tenant
                .run_script(&stmt)
                .await
                .unwrap_or_else(|e| panic!("force trigger `{stmt}`: {e}"));
        }
    }
}

const NO_DB: &str = "rlsserveas_nonowner_db";
const NO_ROLE: &str = "rlsserveas_nonowner_role";
const NO_OWNER: &str = "rlsserveas_nonowner_owner";
const OW_DB: &str = "rlsserveas_owner_db";
const OW_ROLE: &str = "rlsserveas_owner_role";
const OW_OWNER: &str = "rlsserveas_owner_owner";
const PW: &str = "p0sturepw";

/// Rewrite a superuser URL to connect to database `db` as the SUPERUSER (keeps the su creds).
fn su_to_db(su_url: &str, db: &str) -> String {
    let (scheme, rest) = su_url.split_once("://").unwrap();
    let (creds, after) = rest.split_once('@').unwrap();
    let (hostport, _) = after.split_once('/').unwrap_or((after, ""));
    format!("{scheme}://{creds}@{hostport}/{db}")
}

/// **Live gate: the `serve_as` serving posture ("Option C").** Proves on a real Postgres, with TWO
/// tenants' rows in ONE shared table (the `rls_session` keyspace), that the DECLARED posture drives
/// the FORCE install and the serving role, and that the owner-serving ⟺ FORCE invariant holds:
///
///   * **(a) `serve_as: non-owner`** (the default) — provisioning installs NO force trigger; serving
///     AS the per-tenant NON-OWNER runtime role is confined by plain `ENABLE` (sees ONLY its own
///     tenant's row — ZERO foreign bytes). The table is `ENABLE`-but-NOT-`FORCE`.
///   * **(b) `serve_as: owner`** — provisioning installs the FORCE-on-ENABLE trigger, which upgrades
///     the owner's `ENABLE` table to `FORCE` on `ALTER TABLE … ENABLE`; serving AS the OWNER role is
///     then confined by `FORCE` (ZERO foreign bytes). This is the owner the Phase-2 operate-as-owner
///     dynamic role also acts as.
///   * **(c) FORCE is load-bearing** — drop the trigger + `ALTER TABLE … NO FORCE` on the
///     owner-posture DB, and the OWNER serving role LEAKS BOTH tenants' rows: owner-serving is sound
///     only while FORCE is live. (The node posture guard keeps the owner identity off the serving
///     path except under `serve_as: owner`.)
///   * **(d) the Security FINDING 1 leak window + its fix — a POSTURE FLIP onto a POPULATED DB.** The
///     FORCE-on-ENABLE trigger is non-retroactive, so flipping a DB with PRE-EXISTING `ENABLE`-only
///     tables to `serve_as: owner` (or a cross-posture clone/sync) would leave them un-`FORCE`d and
///     the owner serving role LEAKS. Proven here: the pre-existing table leaks under the owner
///     identity; installing the trigger ALONE does NOT fix it (non-retroactive); the owner-posture
///     provision's retroactive [`force_rls_sweep_ddl`] FORCEs it + the [`RLS_ENABLE_NOT_FORCE_COUNT_SQL`]
///     assert reads ZERO → the owner then sees ONLY its own tenant's row (zero foreign bytes), so
///     owner-serving ⟺ FORCE is ACTUALLY LIVE, not merely posture-declared.
///
/// Requires `BOATRAMP_TEST_PG_URL` = a superuser Postgres URL (skips cleanly when unset). Prints
/// `MANAGED RLS SERVE-AS POSTURE OK [postgres]` on success.
#[tokio::test]
#[ignore = "needs a live superuser Postgres via BOATRAMP_TEST_PG_URL (run on lighthouse / the live-pg CI lane)"]
async fn serve_as_posture_drives_force_install_and_confines_each_posture() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip serve_as_posture: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let k = ExternalSqlKind::Postgres;
    let su = connect(k, &ExternalSqlOptions::new(su_url.clone())).unwrap();

    // --- teardown any prior run (re-runnable) ---
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{NO_DB}\" WITH (FORCE)"),
        format!("DROP DATABASE IF EXISTS \"{OW_DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{NO_ROLE}\""),
        format!("DROP ROLE IF EXISTS \"{NO_OWNER}\""),
        format!("DROP ROLE IF EXISTS \"{OW_ROLE}\""),
        format!("DROP ROLE IF EXISTS \"{OW_OWNER}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    // =====================================================================
    // ARM (a) — serve_as: non-owner (DEFAULT). install_force = false ⇒ NO trigger.
    // =====================================================================
    let su_no = connect(k, &ExternalSqlOptions::new(su_to_db(&su_url, NO_DB))).unwrap();
    provision_posture(
        &su,
        &su_no,
        PosturePlan {
            db: NO_DB,
            role: NO_ROLE,
            role_pw: PW,
            owner: NO_OWNER,
            owner_pw: PW,
            install_force: false,
        },
    )
    .await;
    // Pin BOTH identities to the SAME tenant via a role-default GUC (the leak, if any, is RLS
    // exemption — not a different GUC).
    for stmt in [
        format!("ALTER ROLE \"{NO_ROLE}\" SET \"{TENANT_GUC}\" = '{TENANT}'"),
        format!("ALTER ROLE \"{NO_OWNER}\" SET \"{TENANT_GUC}\" = '{TENANT}'"),
    ] {
        su.run_script(&stmt).await.unwrap();
    }
    // The owner (migrator) creates a plain ENABLE table + seeds its own tenant's row.
    let no_owner_conn = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, NO_OWNER, PW, NO_DB)),
    )
    .unwrap();
    for stmt in [
        "CREATE TABLE t (tenant text, v int)",
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY",
        &format!("CREATE POLICY p ON t USING (tenant = current_setting('{TENANT_GUC}', true))"),
        &format!("INSERT INTO t (tenant, v) VALUES ('{TENANT}', 1)"),
    ] {
        no_owner_conn
            .run_script(stmt)
            .await
            .unwrap_or_else(|e| panic!("non-owner arm owner DDL/seed `{stmt}`: {e}"));
    }
    su_no
        .run_script(&format!(
            "INSERT INTO t (tenant, v) VALUES ('{OTHER_TENANT}', 2)"
        ))
        .await
        .expect("superuser seeds the other-tenant row");
    // The posture installed NO force trigger, and the table is ENABLE-but-NOT-FORCE.
    assert_eq!(
        probe(
            &su_no,
            "SELECT count(*)::int FROM pg_event_trigger WHERE evtname = 'boatramp_force_rls_trg'"
        )
        .await,
        "0",
        "serve_as: non-owner must install NO FORCE event trigger"
    );
    assert_eq!(
        probe(
            &su_no,
            "SELECT relforcerowsecurity::text FROM pg_class WHERE relname = 't'"
        )
        .await,
        "false",
        "non-owner posture: the table stays ENABLE-but-NOT-FORCE"
    );
    assert_eq!(
        probe(&su_no, "SELECT count(*)::int FROM t").await,
        "2",
        "both rows on disk"
    );
    // Serving AS the NON-OWNER runtime role: confined by plain ENABLE — ZERO foreign bytes.
    let no_runtime = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, NO_ROLE, PW, NO_DB)),
    )
    .unwrap();
    assert_eq!(
        probe(&no_runtime, "SELECT current_user::text").await,
        NO_ROLE
    );
    assert_eq!(
        probe(&no_runtime, "SELECT count(*)::int FROM t").await,
        "1",
        "serve_as: non-owner serving role sees ONLY its own tenant's row (ZERO foreign bytes, no FORCE)"
    );
    assert_eq!(
        probe(&no_runtime, "SELECT tenant::text FROM t").await,
        TENANT
    );

    // =====================================================================
    // ARM (b) — serve_as: owner. install_force = true ⇒ trigger installed; owner serving FORCE-bound.
    // =====================================================================
    let su_ow = connect(k, &ExternalSqlOptions::new(su_to_db(&su_url, OW_DB))).unwrap();
    provision_posture(
        &su,
        &su_ow,
        PosturePlan {
            db: OW_DB,
            role: OW_ROLE,
            role_pw: PW,
            owner: OW_OWNER,
            owner_pw: PW,
            install_force: true,
        },
    )
    .await;
    su.run_script(&format!(
        "ALTER ROLE \"{OW_OWNER}\" SET \"{TENANT_GUC}\" = '{TENANT}'"
    ))
    .await
    .unwrap();
    // The trigger IS installed.
    assert_eq!(
        probe(
            &su_ow,
            "SELECT count(*)::int FROM pg_event_trigger WHERE evtname = 'boatramp_force_rls_trg'"
        )
        .await,
        "1",
        "serve_as: owner must install the FORCE-on-ENABLE event trigger"
    );
    // The owner creates a plain ENABLE table; the trigger upgrades it to FORCE on ENABLE.
    let ow_owner_conn = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, OW_OWNER, PW, OW_DB)),
    )
    .unwrap();
    for stmt in [
        "CREATE TABLE t (tenant text, v int)",
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY",
        &format!("CREATE POLICY p ON t USING (tenant = current_setting('{TENANT_GUC}', true))"),
        &format!("INSERT INTO t (tenant, v) VALUES ('{TENANT}', 1)"),
    ] {
        ow_owner_conn
            .run_script(stmt)
            .await
            .unwrap_or_else(|e| panic!("owner arm owner DDL/seed `{stmt}`: {e}"));
    }
    su_ow
        .run_script(&format!(
            "INSERT INTO t (tenant, v) VALUES ('{OTHER_TENANT}', 2)"
        ))
        .await
        .expect("superuser seeds the other-tenant row");
    assert_eq!(
        probe(
            &su_ow,
            "SELECT relforcerowsecurity::text FROM pg_class WHERE relname = 't'"
        )
        .await,
        "true",
        "serve_as: owner — the FORCE trigger upgraded the ENABLE table to FORCE"
    );
    assert_eq!(
        probe(&su_ow, "SELECT count(*)::int FROM t").await,
        "2",
        "both rows on disk"
    );
    // Serving AS the OWNER role: confined by FORCE — ZERO foreign bytes.
    let ow_serving = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, OW_OWNER, PW, OW_DB)),
    )
    .unwrap();
    assert_eq!(
        probe(&ow_serving, "SELECT current_user::text").await,
        OW_OWNER
    );
    assert_eq!(
        probe(&ow_serving, "SELECT count(*)::int FROM t").await,
        "1",
        "serve_as: owner serving role (FORCE-bound) sees ONLY its own tenant's row (ZERO foreign bytes)"
    );
    assert_eq!(
        probe(&ow_serving, "SELECT tenant::text FROM t").await,
        TENANT
    );

    // =====================================================================
    // ARM (c) — FORCE is load-bearing: with FORCE absent the owner serving role LEAKS. Drop the
    // trigger + un-FORCE the table; the OWNER serving role then sees BOTH rows. This proves the
    // owner posture is sound ONLY while FORCE is live — the reason the `serve_as: owner` provision
    // installs the trigger AND (arm d) FORCE-sweeps + asserts, and the reason the node's posture
    // guard keeps the owner identity off the serving path except under `serve_as: owner`. It does
    // NOT by itself show the guard catches a FORCE-absent-under-owner state — arm (d) does that.
    // =====================================================================
    for stmt in [
        "DROP EVENT TRIGGER IF EXISTS boatramp_force_rls_trg",
        "ALTER TABLE t NO FORCE ROW LEVEL SECURITY",
    ] {
        su_ow
            .run_script(stmt)
            .await
            .unwrap_or_else(|e| panic!("mutation `{stmt}`: {e}"));
    }
    let ow_leak = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, OW_OWNER, PW, OW_DB)),
    )
    .unwrap();
    assert_eq!(
        probe(&ow_leak, "SELECT count(*)::int FROM t").await,
        "2",
        "LOAD-BEARING PROOF: with FORCE absent the OWNER serving role LEAKS BOTH tenants' rows — \
         owner-serving is sound only while FORCE is live"
    );

    // =====================================================================
    // ARM (d) — the Security FINDING 1 leak window + its fix: a POSTURE FLIP onto a POPULATED DB.
    // NO_DB already holds a PRE-EXISTING ENABLE-only table `t` (2 tenants' rows), created under the
    // non-owner posture in arm (a). Now flip it to `serve_as: owner` and reproduce the review's leak:
    //   1. Before anything, the NO_OWNER role (the owner serving identity after the flip) LEAKS both
    //      rows — `t` is ENABLE-not-FORCE, and ENABLE does not bind the owner.
    //   2. Installing the FORCE trigger ALONE does NOT fix it — the trigger is non-retroactive, so
    //      the pre-existing `t` stays ENABLE-not-FORCE and the owner STILL leaks. (The gap.)
    //   3. The owner-posture provision's retroactive `force_rls_sweep_ddl` FORCEs `t`, and the
    //      `RLS_ENABLE_NOT_FORCE_COUNT_SQL` assert backstop reads ZERO — now the owner sees ONLY its
    //      own tenant's row (zero foreign bytes). owner-serving ⟺ FORCE is ACTUALLY LIVE.
    // =====================================================================
    su.run_script(&format!(
        "ALTER ROLE \"{NO_OWNER}\" SET \"{TENANT_GUC}\" = '{TENANT}'"
    ))
    .await
    .unwrap();
    // (1) the reachable leak the posture guard alone would permit.
    let no_owner_serving = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, NO_OWNER, PW, NO_DB)),
    )
    .unwrap();
    assert_eq!(
        probe(&no_owner_serving, "SELECT count(*)::int FROM t").await,
        "2",
        "FLIP LEAK WINDOW: a pre-existing ENABLE-only table served as owner leaks BOTH tenants' rows"
    );
    // (2) the trigger ALONE is non-retroactive — the pre-existing table is untouched, still leaks.
    for stmt in force_rls_event_trigger_ddl(k, NO_OWNER) {
        su_no
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("flip trigger install `{stmt}`: {e}"));
    }
    assert_eq!(
        probe(
            &su_no,
            "SELECT relforcerowsecurity::text FROM pg_class WHERE relname = 't'"
        )
        .await,
        "false",
        "the event trigger is NON-RETROACTIVE — a pre-existing ENABLE table stays un-FORCED"
    );
    let no_owner_still = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, NO_OWNER, PW, NO_DB)),
    )
    .unwrap();
    assert_eq!(
        probe(&no_owner_still, "SELECT count(*)::int FROM t").await,
        "2",
        "trigger-only is NOT enough: the pre-existing table still leaks under the owner identity"
    );
    // (3) the owner-posture provision's RETROACTIVE sweep + the fail-closed assert — the fix.
    for stmt in force_rls_sweep_ddl(k) {
        su_no
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("force sweep `{stmt}`: {e}"));
    }
    assert_eq!(
        probe(&su_no, RLS_ENABLE_NOT_FORCE_COUNT_SQL).await,
        "0",
        "after the sweep the fail-closed assert reads ZERO ENABLE-not-FORCE tables (provision would \
         otherwise REFUSE)"
    );
    assert_eq!(
        probe(
            &su_no,
            "SELECT relforcerowsecurity::text FROM pg_class WHERE relname = 't'"
        )
        .await,
        "true",
        "the retroactive sweep FORCEd the pre-existing table"
    );
    let no_owner_fixed = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, NO_OWNER, PW, NO_DB)),
    )
    .unwrap();
    assert_eq!(
        probe(&no_owner_fixed, "SELECT count(*)::int FROM t").await,
        "1",
        "FIX: after the owner-posture retroactive FORCE-sweep, the owner sees ONLY its own tenant's \
         row (ZERO foreign bytes) — owner-serving ⟺ FORCE is actually live even after a posture flip"
    );
    assert_eq!(
        probe(&no_owner_fixed, "SELECT tenant::text FROM t").await,
        TENANT
    );

    // --- teardown (best-effort) ---
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{NO_DB}\" WITH (FORCE)"),
        format!("DROP DATABASE IF EXISTS \"{OW_DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{NO_ROLE}\""),
        format!("DROP ROLE IF EXISTS \"{NO_OWNER}\""),
        format!("DROP ROLE IF EXISTS \"{OW_ROLE}\""),
        format!("DROP ROLE IF EXISTS \"{OW_OWNER}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    println!("MANAGED RLS SERVE-AS POSTURE OK [postgres]");
}
