//! **Live gate: `rls_session` ENGAGES on the SERVE path (v0.72.1).**
//!
//! v0.72.0 made `rls_session` ADOPTABLE on an already-provisioned managed Postgres (the reconcile
//! self-heal: [`advance_readiness`]'s `Provisioned` branch re-runs `provision_managed` to create the
//! missing non-superuser app role in place — the sibling `rls_adopt_existing_db_live` gate locks
//! that). But a lighthouse repro found the app role being created was not enough to actually SERVE
//! under it:
//!
//!   * **Live apply did not ENGAGE without a restart (b1):** the reconcile created the app role, but
//!     the running node kept serving on its WARM, cached bootstrap-SUPERUSER backend (built when the
//!     cell was rls-off). The serving-backend cache was never invalidated on the config flip, so RLS
//!     stayed silently OFF until the pods cycled. Fix: on the adoption success path, invalidate the
//!     cached serving backend (`invalidate_serving_backend` → a `sql_binding_epochs` bump), so the
//!     next request REBUILDS it as the restricted app role — engaging RLS live, no restart.
//!   * **A cold-boot ordering window (A):** the serve listener binds ~82ms before the detached
//!     reconcile's first tick, so a cold boot of an rls-on cell whose app role is not yet present
//!     could route to an absent role. Fix: PROVISION-THEN-SERVE — the serve path ensures the app
//!     role exists (provisioning it in place, as the superuser, if absent) BEFORE binding the
//!     serving identity to it, fail-closed.
//!
//! This gate proves BOTH on a REAL Postgres, end to end, through the REAL serving resolvers:
//!
//!   1. **Provision-then-serve (A)** — [`NodeTenantSqlResolver::resolve`] over an already-provisioned
//!      (rls-OFF) cell whose app role is ABSENT, with the binding re-resolved rls-ON (the cold-boot
//!      shape). `resolve` must create the app role in place and return a backend that serves AS the
//!      non-superuser app role: `current_user` is the app role (NOT the superuser), the first query
//!      SUCCEEDS (zero fail-closed), RLS binds (ZERO foreign rows), and the non-privilege probe reads
//!      `0`. The base superuser credential is UNCHANGED.
//!   2. **Live-apply engage via cache invalidation (b1)** — through [`NodeDeclaredDbResolver`] (the
//!      real `apply`/declared serve path, which re-reads the declaration from the store per
//!      cache-miss and keys its cache by the `sql_binding_epochs` generation). Serve rls-OFF
//!      (`current_user` = the superuser) → cache warm. Flip the declaration rls-ON (the live
//!      `apply`) → a cache HIT STILL serves the superuser (the stale warm cache — the pre-fix shape,
//!      and the mutation witness: without the invalidation this is where it stays). Run the adoption
//!      (`needs_reprovision` → `provision_managed` → `invalidate_serving_backend`, exactly what
//!      `advance_readiness` does) → the next resolve is a cache MISS that REBUILDS as the app role:
//!      `pg_stat_activity` shows the serving session switched to the app role, the request keeps
//!      serving (no 500), RLS binds. NO restart.
//!
//! **never-serve-as-superuser-while-rls-on (d)** holds throughout: every rls-ON serving session
//! asserts `current_user` is the provisioned non-superuser app role, and the non-privilege probe
//! reads `0`. The one point where a WARM pre-flip superuser backend is still served (step 2's cache
//! hit) is rls-ON only in the freshly-applied CONFIG, not in the backend that was legitimately built
//! while the cell was rls-off; it is exactly the staleness the invalidation closes.
//!
//! Requires `BOATRAMP_TEST_PG_URL` = a **superuser** Postgres URL (CREATE DATABASE / CREATE ROLE /
//! CREATE EVENT TRIGGER). Skips cleanly (passes) when unset — never fails on a bare dev box.
//! `#[ignore]`-gated (run explicitly — e.g. on lighthouse against `pgvector/pgvector:pg16`, or via
//! the live-pg CI lane, which greps the markers). Prints `RLS ENGAGE LIVE OK [provision-then-serve]`
//! and `RLS ENGAGE LIVE OK [live-apply]` on success.
//!
//! [`advance_readiness`]: boatramp_core::compute
//! [`NodeTenantSqlResolver::resolve`]: boatramp_node::tenant_sql
//! [`NodeDeclaredDbResolver`]: boatramp_node::declared_sql

#![cfg(feature = "sql-postgres")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::compute::{
    ApplyDatabase, ApplyDatabaseKind, ApplyDatabaseScope, ApplyDatabaseSize, ApplyDatabaseTenant,
    Endpoint, InstanceHandle, ManagedDbEnvResolver, ObservedInstance, Readiness, ReplicaPhase,
    Scheme,
};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
use boatramp_core::sql::{SqlBackend, SqlValue};
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use boatramp_node::config::{
    ExternalDatabaseConfig, ManagedDbPrivilege, TenantIsolation, TenantScope,
};
use boatramp_node::declared_sql::NodeDeclaredDbResolver;
use boatramp_node::managed_db_declare::derived_workload;
use boatramp_node::managed_sql::{ManagedDbEnv, ManagedSqlCredentials};
use boatramp_node::tenant_sql::NodeTenantSqlResolver;
use boatramp_storage::sql_sqlx::{
    DeclaredDbResolver, ExternalSqlKind, ExternalSqlOptions, PerTenantSqlResolver, connect,
};
use boatramp_storage::tenant_provision::{
    RUNTIME_ROLE_RLS_PRIVILEGED_PROBE_SQL, rls_app_role_name,
};
use bytes::Bytes;
use futures::StreamExt;

const ACCT_GUC: &str = "app.account_id";
const ACCT_A: &str = "engage-account-a";
const ACCT_B: &str = "engage-account-b";

/// A no-op `Storage` (the gate drives the PG wire directly; the endpoint comes from a published
/// replica-state row, not blob storage).
struct NoopBlob;
#[async_trait]
impl Storage for NoopBlob {
    async fn get(&self, _key: &str) -> Result<GetObject, StorageError> {
        let body: ByteStream = futures::stream::once(async { Ok(Bytes::new()) }).boxed();
        Ok(GetObject {
            meta: ObjectMeta {
                key: String::new(),
                size: Some(0),
                content_type: None,
                etag: None,
            },
            body,
        })
    }
    async fn get_range(&self, _: &str, _: u64, _: Option<u64>) -> Result<GetObject, StorageError> {
        Err(StorageError::unsupported("range"))
    }
    async fn put(&self, _: &str, _: ByteStream, _: PutMeta) -> Result<ObjectMeta, StorageError> {
        Err(StorageError::unsupported("put"))
    }
    async fn head(&self, _: &str) -> Result<ObjectMeta, StorageError> {
        Err(StorageError::NotFound(String::new()))
    }
    async fn delete(&self, _: &str) -> Result<(), StorageError> {
        Ok(())
    }
    async fn list(&self, _: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        Ok(Vec::new())
    }
}

/// The reversible test "envelope" (NOT encryption) — the same double the sibling live gates use,
/// exercising the exact `ManagedSqlCredentials` seal/unseal path.
struct RevEnvelope;
#[async_trait]
impl KeyEnvelope for RevEnvelope {
    async fn wrap(&self, p: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        Ok(p.iter().rev().copied().collect())
    }
    async fn unwrap(&self, w: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        Ok(w.iter().rev().copied().collect())
    }
}

/// `(user, password, host, port)` parsed from `scheme://USER:PW@HOST:PORT/db`.
fn url_parts(su_url: &str) -> (String, String, String, u16) {
    let (_scheme, rest) = su_url.split_once("://").unwrap();
    let (creds, after) = rest.split_once('@').unwrap();
    let (user, pw) = creds.split_once(':').unwrap_or((creds, ""));
    let (hostport, _) = after.split_once('/').unwrap_or((after, ""));
    let (host, port) = hostport.split_once(':').unwrap_or((hostport, "5432"));
    (
        user.to_string(),
        pw.to_string(),
        host.to_string(),
        port.parse().unwrap_or(5432),
    )
}

/// Rewrite a superuser URL to connect to database `db`, keeping its creds.
fn su_to_db(su_url: &str, db: &str) -> String {
    let (scheme, rest) = su_url.split_once("://").unwrap();
    let (creds, after) = rest.split_once('@').unwrap();
    let (hostport, _) = after.split_once('/').unwrap_or((after, ""));
    format!("{scheme}://{creds}@{hostport}/{db}")
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

/// Publish a Running + healthy + Provisioned replica for `(project, workload)` pointing at the live
/// PG, so the resolvers' endpoint resolver resolves a target to connect to.
async fn publish_replica(
    deploy: &DeployStore,
    project: ProjectRef<'_>,
    workload: &str,
    ep: &Endpoint,
) {
    let observed = ObservedInstance {
        handle: InstanceHandle::new(
            project.as_str().to_string(),
            workload.to_string(),
            0,
            "live".into(),
        ),
        node: 0,
        backend: "live".to_string(),
        endpoint: ep.clone(),
        region: None,
        healthy: true,
        started_at: None,
        phase: ReplicaPhase::Running,
        readiness: Readiness::Provisioned,
        data_dir: None,
        snapshot: None,
        active_spec: None,
    };
    deploy
        .set_replica_state(project, &observed)
        .await
        .expect("publish replica state");
}

/// Seed a 2-account `ENABLE ROW LEVEL SECURITY` table (as the schema-owning superuser) on the live
/// database reachable at `su_db_url`.
async fn seed_two_account_rls_table(k: ExternalSqlKind, su_db_url: &str) {
    let su_db = connect(k, &ExternalSqlOptions::new(su_db_url.to_string())).unwrap();
    for stmt in [
        "DROP TABLE IF EXISTS t".to_string(),
        "CREATE TABLE t (account text, v int)".to_string(),
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY".to_string(),
        "DROP POLICY IF EXISTS p ON t".to_string(),
        format!("CREATE POLICY p ON t USING (account = current_setting('{ACCT_GUC}', true))"),
        format!("INSERT INTO t (account, v) VALUES ('{ACCT_A}', 1)"),
        format!("INSERT INTO t (account, v) VALUES ('{ACCT_B}', 2)"),
    ] {
        su_db
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("seed `{stmt}`: {e}"));
    }
    assert_eq!(
        probe(&su_db, "SELECT count(*)::int FROM t").await,
        "2",
        "both accounts' rows must be seeded"
    );
}

/// Assert a SERVING backend serves AS the non-superuser app role with RLS BOUND (pinned to account A
/// it sees ONLY account A's one row — ZERO foreign bytes) and the runtime-role non-privilege probe
/// reads `0` — the never-serve-as-superuser-while-rls-on invariant, live.
async fn assert_serves_as_bound_app_role(serving: &Arc<dyn SqlBackend>, app_role: &str) {
    assert_eq!(
        probe(serving, "SELECT current_user::text").await,
        app_role,
        "rls-on serving MUST be the provisioned non-superuser app role, NEVER the superuser"
    );
    assert_eq!(
        probe(serving, RUNTIME_ROLE_RLS_PRIVILEGED_PROBE_SQL).await,
        "0",
        "the runtime serving role must be NON-superuser / NON-BYPASSRLS (probe reads 0)"
    );
    assert_eq!(
        probe(serving, "SELECT count(*)::int FROM t").await,
        "1",
        "RLS must bind: pinned to account A the app role sees ONLY account A's row (zero foreign)"
    );
    assert_eq!(
        probe(
            serving,
            &format!("SELECT v::int FROM t WHERE account = '{ACCT_A}'")
        )
        .await,
        "1",
        "the one visible row is account A's"
    );
}

// =====================================================================================
// (A) PROVISION-THEN-SERVE — the serve path ensures the app role exists before binding to it.
// =====================================================================================
#[tokio::test]
#[ignore = "needs a live superuser Postgres via BOATRAMP_TEST_PG_URL (run on lighthouse / the live-pg CI lane)"]
async fn rls_cold_boot_serve_path_provisions_the_app_role_then_serves() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip rls_engage (provision-then-serve): BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let k = ExternalSqlKind::Postgres;
    let (su_user, su_pw, host, port) = url_parts(&su_url);
    const COMPUTE: &str = "pg_engage_pts";
    const DB: &str = "rlsengage_pts_appdb";
    let app_role = rls_app_role_name(DB);
    assert_ne!(
        app_role, su_user,
        "the app role must never collide with the bootstrap superuser name"
    );

    // Clean slate (idempotent reruns).
    let su = connect(k, &ExternalSqlOptions::new(su_url.clone())).unwrap();
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{app_role}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn Storage> = Arc::new(NoopBlob);
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);

    // Pre-seal the bootstrap superuser credential under `(default, COMPUTE)` — the REAL PG password,
    // the "already-provisioned" base credential the fix must never rotate.
    {
        let sealed = envelope.wrap(su_pw.as_bytes()).await.unwrap();
        kv.put(
            &format!("managed-sql-cred/{DEFAULT_PROJECT}/{COMPUTE}"),
            sealed,
        )
        .await
        .unwrap();
    }
    let endpoint = Endpoint::new(Scheme::Http, host.clone(), port);
    publish_replica(&deploy, ProjectRef::DEFAULT, COMPUTE, &endpoint).await;

    // The managed-DB binding. `rls_session` toggles the adoption.
    let binding = |rls: bool| ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DB.into()),
        user: Some(su_user.clone()),
        tenant: TenantIsolation::Single,
        tenant_scope: TenantScope::Project,
        rls_session: rls,
        connect_timeout_secs: Some(10),
        ..Default::default()
    };

    // Provision WITHOUT rls_session (the already-provisioned shape): the DB exists, superuser-owned,
    // NO app role. Seed a 2-account RLS table as the superuser.
    let env_off = ManagedDbEnv::from_config(
        &BTreeMap::from([("db".to_string(), binding(false))]),
        ManagedSqlCredentials::new(kv.clone(), envelope.clone()),
        ManagedDbPrivilege::default(),
        deploy.clone(),
        BTreeSet::new(),
    );
    env_off
        .provision_managed(DEFAULT_PROJECT, COMPUTE, &endpoint)
        .await
        .expect("provision the managed DB rls-off");
    let su_db = connect(k, &ExternalSqlOptions::new(su_to_db(&su_url, DB))).unwrap();
    assert_eq!(
        probe(
            &su_db,
            &format!("SELECT count(*)::int FROM pg_roles WHERE rolname = '{app_role}'")
        )
        .await,
        "0",
        "the app role must be ABSENT before serving (the cold-boot shape the serve path heals)"
    );
    seed_two_account_rls_table(k, &su_to_db(&su_url, DB)).await;

    // THE SERVE PATH, rls-ON, with the role ABSENT (serve binds before the reconcile provisions it):
    // `resolve` must PROVISION-THEN-SERVE — create the app role in place, then return a backend that
    // serves AS it. The first query SUCCEEDS (zero fail-closed).
    let resolver =
        NodeTenantSqlResolver::new(deploy.clone(), kv.clone(), envelope.clone(), &binding(true))
            .expect("a compute-backed managed binding builds a per-tenant resolver");
    let serving = resolver
        .resolve(DEFAULT_PROJECT, "")
        .await
        .expect("provision-then-serve must NOT fail closed: the serve path creates the app role");
    // The first query already SUCCEEDS as the non-superuser app role (zero fail-closed).
    assert_eq!(
        probe(&serving, "SELECT current_user::text").await,
        app_role,
        "provision-then-serve: the serve path binds the (just-provisioned) non-superuser app role"
    );

    // Pin the (now-created) app role to account A, mirroring how an app sets its own account, then
    // re-resolve so a fresh session picks up the role-default GUC and the RLS binding is observable.
    su_db
        .run_script(&format!(
            "ALTER ROLE \"{app_role}\" SET \"{ACCT_GUC}\" = '{ACCT_A}'"
        ))
        .await
        .expect("pin the app role to account A");
    let serving = resolver.resolve(DEFAULT_PROJECT, "").await.expect("serve");
    assert_serves_as_bound_app_role(&serving, &app_role).await;

    // The app role now exists, NON-superuser / NON-BYPASSRLS.
    assert_eq!(
        probe(
            &su_db,
            &format!(
                "SELECT (count(*) FILTER (WHERE NOT rolsuper AND NOT rolbypassrls))::int \
                 FROM pg_roles WHERE rolname = '{app_role}'"
            )
        )
        .await,
        "1",
        "the serve path must create the app role as a NON-superuser / NON-BYPASSRLS login"
    );
    // The base superuser credential is UNCHANGED (provision-then-serve never rotates it).
    assert_eq!(
        ManagedSqlCredentials::new(kv.clone(), envelope.clone())
            .password(DEFAULT_PROJECT, COMPUTE)
            .await
            .unwrap(),
        su_pw,
        "the base superuser credential must be byte-identical after provision-then-serve"
    );

    // Cleanup.
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{app_role}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }
    println!("RLS ENGAGE LIVE OK [provision-then-serve]");
}

// =====================================================================================
// (b1) LIVE-APPLY ENGAGE — flip rls_session on via the declared store; the serving cache
// invalidation on the adoption success rebuilds the serving backend as the app role, no restart.
// =====================================================================================
#[tokio::test]
#[ignore = "needs a live superuser Postgres via BOATRAMP_TEST_PG_URL (run on lighthouse / the live-pg CI lane)"]
async fn rls_live_apply_engages_via_serving_cache_invalidation() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip rls_engage (live-apply): BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let k = ExternalSqlKind::Postgres;
    let (_real_su, _real_pw, host, port) = url_parts(&su_url);
    // The declared/apply path lowers `user = database = <name>` (boatramp owns the init superuser
    // name, exactly as the stock image's `POSTGRES_USER` does). So the cell's bootstrap superuser is
    // a role NAMED after the declared DB; we create it on the live cluster with the sealed password,
    // mirroring the turnkey `initdb`. `DB_NAME` is the declared binding name.
    const DB_NAME: &str = "rlsengage_apply";
    let app_role = rls_app_role_name(DB_NAME);
    let workload = derived_workload(DEFAULT_PROJECT, DB_NAME);

    let su = connect(k, &ExternalSqlOptions::new(su_url.clone())).unwrap();
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{DB_NAME}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{app_role}\""),
        format!("DROP ROLE IF EXISTS \"{DB_NAME}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn Storage> = Arc::new(NoopBlob);
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());

    // Mint + seal the cell's bootstrap-superuser password under the key the declared path reads
    // `(default, <derived workload>)`, then CREATE that superuser ROLE on the live cluster with the
    // SAME password — so the provisioning/serve connections (which connect as `<DB_NAME>`)
    // authenticate, exactly as a turnkey-initdb'd container would.
    let su2 = creds
        .password(DEFAULT_PROJECT, &workload)
        .await
        .expect("mint the cell superuser credential");
    su.run_script(&format!(
        "CREATE ROLE \"{DB_NAME}\" SUPERUSER LOGIN PASSWORD '{su2}'"
    ))
    .await
    .expect("create the cell's bootstrap superuser role");

    let endpoint = Endpoint::new(Scheme::Http, host.clone(), port);
    publish_replica(&deploy, ProjectRef::DEFAULT, &workload, &endpoint).await;

    // The declared database (an `apply` record), rls OFF initially.
    let declare = |rls: bool| {
        ApplyDatabase::new(DB_NAME.to_string(), ApplyDatabaseKind::Postgres)
            .with_tenant(ApplyDatabaseTenant::Single)
            .with_tenant_scope(ApplyDatabaseScope::Project)
            .with_size(ApplyDatabaseSize::Small)
            .with_connect_timeout_secs(Some(10))
            .with_rls_session(rls)
    };
    deploy
        .set_project_database(ProjectRef::DEFAULT, &declare(false))
        .await
        .expect("store the rls-off declaration");

    // A `ManagedDbEnv` built with EMPTY node-static config: it resolves the applied cell from the
    // deploy store (`resolve_applied`) live on every call — so the SAME env observes the rls flip,
    // exactly as the production reconcile does (the real turnkey shape).
    let env = ManagedDbEnv::from_config(
        &BTreeMap::new(),
        ManagedSqlCredentials::new(kv.clone(), envelope.clone()),
        ManagedDbPrivilege::default(),
        deploy.clone(),
        BTreeSet::new(),
    );

    // Provision the cell rls-OFF through the real reconcile entry point, then seed a 2-account RLS
    // table (connect as the cell superuser `<DB_NAME>` to its own DB).
    env.provision_managed(DEFAULT_PROJECT, &workload, &endpoint)
        .await
        .expect("provision the declared DB rls-off");
    let cell_su_url = {
        let (scheme, rest) = su_url.split_once("://").unwrap();
        let (_creds, after) = rest.split_once('@').unwrap();
        let (hostport, _) = after.split_once('/').unwrap_or((after, ""));
        format!("{scheme}://{DB_NAME}:{su2}@{hostport}/{DB_NAME}")
    };
    seed_two_account_rls_table(k, &cell_su_url).await;

    // The REAL serve path for an applied DB: the declared-DB resolver, whose epoch-stamped cache
    // persists across the live config flip.
    let declared = NodeDeclaredDbResolver::new(
        deploy.clone(),
        kv.clone(),
        envelope.clone(),
        &BTreeMap::new(),
    );

    // Serve rls-OFF: the serving session is the superuser `<DB_NAME>` (correct — rls is off). Warm.
    let off = declared
        .resolve(DEFAULT_PROJECT, "", DB_NAME)
        .await
        .expect("declared resolve")
        .expect("the declared DB resolves");
    assert_eq!(
        probe(&off, "SELECT current_user::text").await,
        DB_NAME,
        "rls-off serving is the cell's bootstrap superuser (correct while rls is off)"
    );

    // THE LIVE `apply`: flip the declaration rls-ON. The config now says rls-on.
    deploy
        .set_project_database(ProjectRef::DEFAULT, &declare(true))
        .await
        .expect("flip the declaration rls-on (the live apply)");

    // PRE-FIX / MUTATION WITNESS: a cache HIT still serves the WARM superuser backend (built when
    // the cell was rls-off). Without the serving-cache invalidation this is where it STAYS — rls
    // silently off until the pods cycle.
    let still_warm = declared
        .resolve(DEFAULT_PROJECT, "", DB_NAME)
        .await
        .expect("declared resolve")
        .expect("resolves");
    assert_eq!(
        probe(&still_warm, "SELECT current_user::text").await,
        DB_NAME,
        "the WARM cache still serves the superuser after the flip — the staleness the fix closes"
    );

    // THE ADOPTION (what `advance_readiness`'s Provisioned branch now does): detect + reprovision +
    // INVALIDATE the serving cache.
    assert!(
        env.needs_reprovision(DEFAULT_PROJECT, &workload, &endpoint)
            .await,
        "needs_reprovision must be TRUE after the rls-on flip (the app role is absent)"
    );
    env.provision_managed(DEFAULT_PROJECT, &workload, &endpoint)
        .await
        .expect("adoption reprovision creates the app role in place");
    env.invalidate_serving_backend(DEFAULT_PROJECT, &workload)
        .await;

    // Pin the (now-existing) app role to account A.
    su.run_script(&format!(
        "ALTER ROLE \"{app_role}\" SET \"{ACCT_GUC}\" = '{ACCT_A}'"
    ))
    .await
    .expect("pin the app role to account A");

    // ENGAGE, NO RESTART: the SAME declared resolver now rebuilds (cache miss, epoch bumped),
    // re-reads the rls-on declaration, and serves AS the app role. The request keeps serving.
    let engaged = declared
        .resolve(DEFAULT_PROJECT, "", DB_NAME)
        .await
        .expect("declared resolve")
        .expect("resolves");
    assert_serves_as_bound_app_role(&engaged, &app_role).await;

    // `pg_stat_activity` corroboration: an app-role serving session is live, and the probe session
    // is NOT the superuser (serving switched off the superuser identity).
    assert_eq!(
        probe(
            &engaged,
            &format!(
                "SELECT count(*)::int FROM pg_stat_activity \
                 WHERE usename = '{app_role}' AND datname = '{DB_NAME}'"
            )
        )
        .await
        .parse::<i64>()
        .map(|n| n >= 1)
        .unwrap_or(false)
        .to_string(),
        "true",
        "pg_stat_activity must show a live serving session AS the non-superuser app role"
    );

    // Cleanup.
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{DB_NAME}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{app_role}\""),
        format!("DROP ROLE IF EXISTS \"{DB_NAME}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }
    println!("RLS ENGAGE LIVE OK [live-apply]");
}
