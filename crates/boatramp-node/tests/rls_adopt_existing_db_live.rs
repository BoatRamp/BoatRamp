//! **Live gate: `rls_session` ADOPTION on an ALREADY-PROVISIONED managed Postgres (v0.71.1).**
//!
//! The regression this file reproduces and locks is a production incident: adopting
//! `rls_session` on a managed Postgres that was **already provisioned** (under an earlier
//! version, WITHOUT `rls_session`) failed closed, because the non-superuser **app role** the
//! runtime must be served as was never created. Flipping `rls_session` on with a re-`apply`
//! does NOT change the container launch spec, so the DB replica is never relaunched and never
//! re-enters `Starting`; the one-shot post-ready provisioning pass that creates the app role
//! therefore never re-runs. The serving path (which now resolves the runtime to that app role)
//! then routes to an ABSENT role and fails closed indefinitely. A k8s pod rollout does NOT
//! reset boatramp's observed `Provisioned`, so the DB stays stuck until an operator intervenes.
//!
//! The fresh-DB flow the existing `managed_rls_single_mode_sqlx_live` gate exercises
//! (Starting → provision → Provisioned) never hits this gap, which is exactly why the bug
//! shipped. This gate models **adoption on an existing DB** end-to-end through the REAL node
//! adoption path — [`ManagedDbEnv::needs_reprovision`] (the v0.71.1 detection) +
//! [`ManagedDbEnv::provision_managed`] (the idempotent create-in-place), the two calls
//! [`advance_readiness`] makes in its fixed `Provisioned` branch — against a REAL Postgres.
//!
//! Phases:
//!   1. **v0.66.1 shape** — provision a managed `tenant = single` Postgres WITHOUT
//!      `rls_session`, through the real `provision_managed`. The DB is created and served as
//!      the bootstrap superuser; NO app role exists. As the superuser, seed a `ENABLE ROW
//!      LEVEL SECURITY` table keyed on `app.account_id` with **two accounts' rows**.
//!   2. **The pre-fix FAILURE SHAPE** — with the binding re-resolved as `rls_session = true`
//!      (the adoption), the serving identity is now the app role, but it does not exist:
//!      connecting as it FAILS (fails closed). `needs_reprovision` reports `true`. (Reverting
//!      the fix — `needs_reprovision` → `false` — makes this assertion fail: the mutation proof.)
//!   3. **Adoption (the fix)** — re-run the idempotent `provision_managed`. It creates the app
//!      role IN PLACE on the EXISTING database (connecting as the bootstrap superuser, SAME
//!      volume): no `CREATE DATABASE` re-init, no volume destroy/recreate, no base-credential
//!      rotation. `needs_reprovision` now reports `false`.
//!   4. **Post-adoption invariants** — the app role exists and is NON-superuser/NON-BYPASSRLS;
//!      the seeded rows + BOTH accounts SURVIVE (the same volume/data); serving switches to the
//!      non-superuser app role (its distinct sealed credential), pinned to account A it sees
//!      ONLY account A's row (ZERO foreign bytes) and the runtime-role non-privilege probe reads
//!      `0`; the base SUPERUSER credential is UNCHANGED.
//!
//! Requires `BOATRAMP_TEST_PG_URL` = a **superuser** Postgres URL (CREATE DATABASE / CREATE ROLE
//! / CREATE EVENT TRIGGER). Skips cleanly (passes) when unset — never fails on a bare dev box.
//! `#[ignore]`-gated (run explicitly — e.g. on lighthouse against `pgvector/pgvector:pg16`, or
//! via the live-pg CI lane, which greps the marker). Prints `RLS ADOPT EXISTING DB OK [postgres]`
//! on success.
//!
//! [`ManagedDbEnv::needs_reprovision`]: boatramp_node::managed_sql
//! [`ManagedDbEnv::provision_managed`]: boatramp_node::managed_sql
//! [`advance_readiness`]: boatramp_core::compute

#![cfg(feature = "sql-postgres")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::compute::{
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
use boatramp_node::managed_sql::{ManagedDbEnv, ManagedSqlCredentials};
use boatramp_storage::sql_sqlx::{ExternalSqlKind, ExternalSqlOptions, connect};
use boatramp_storage::tenant_provision::{
    RUNTIME_ROLE_RLS_PRIVILEGED_PROBE_SQL, rls_app_role_name,
};
use bytes::Bytes;
use futures::StreamExt;

/// The managed Postgres' compute-workload name (the binding's `compute`) — the DEFAULT single
/// install, so `(project, workload) = (default, pg)` keys the sealed superuser credential and
/// the replica state the endpoint resolver reads.
const COMPUTE: &str = "pg";
/// The managed database this `(default, pg)` cell hosts (a dedicated, superuser-owned DB).
const DB: &str = "rlsadopt_appdb";
/// The account GUC the seeded table's RLS policy keys on (the app's OWN per-request account).
const ACCT_GUC: &str = "app.account_id";
/// Account A — the account the app-role serving session is pinned to; it must see ONLY its row.
const ACCT_A: &str = "account-a";
/// Account B — a DIFFERENT account; invisible to A under the non-superuser app role.
const ACCT_B: &str = "account-b";

/// A no-op `Storage` (the `DeployStore` wants one; this gate drives the PG wire directly and the
/// endpoint comes from a published replica-state row, not from blob storage).
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

/// The reversible test "envelope" (NOT encryption) the `managed_sql` unit tests use — proves the
/// sealed credential round-trips; production uses a real KMS/local envelope with the same contract.
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

/// Rewrite a superuser URL to connect as `user`/`pw` to database `db` (shared with the sibling
/// `managed_rls_single_mode_sqlx_live` gate).
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

/// The managed-DB binding under test. `rls_session` is the adoption toggle: phase 1 provisions
/// with it OFF (the v0.66.1 shape), phase 3 re-resolves it ON (the adoption).
fn binding(user: &str, rls_session: bool) -> ExternalDatabaseConfig {
    ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DB.into()),
        user: Some(user.into()),
        tenant: TenantIsolation::Single,
        tenant_scope: TenantScope::Project,
        rls_session,
        connect_timeout_secs: Some(10),
        ..Default::default()
    }
}

/// Build a `ManagedDbEnv` over the shared control-plane state for `binding`.
fn env_for(
    binding: &ExternalDatabaseConfig,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    deploy: &DeployStore,
) -> ManagedDbEnv {
    let mut dbs = BTreeMap::new();
    dbs.insert("db".to_string(), binding.clone());
    ManagedDbEnv::from_config(
        &dbs,
        ManagedSqlCredentials::new(kv.clone(), envelope.clone()),
        ManagedDbPrivilege::default(),
        deploy.clone(),
        BTreeSet::new(),
    )
}

#[tokio::test]
#[ignore = "needs a live superuser Postgres via BOATRAMP_TEST_PG_URL (run on lighthouse / the live-pg CI lane)"]
async fn rls_session_adopted_on_an_already_provisioned_db_reconciles_the_app_role() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip rls_adopt_existing_db: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let k = ExternalSqlKind::Postgres;
    let (su_user, su_pw, host, port) = url_parts(&su_url);
    let app_role = rls_app_role_name(DB);

    // The STABLE app role must never collide with the bootstrap superuser (so "served as the app
    // role" can never silently mean "served as the superuser" by name).
    assert_ne!(
        app_role, su_user,
        "the adopted app role must never collide with the bootstrap superuser name"
    );

    // Direct superuser handle (connects to the URL's own DB) for teardown + CREATE DATABASE.
    let su = connect(k, &ExternalSqlOptions::new(su_url.clone())).unwrap();
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{app_role}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    // --- Control-plane state (KV + Storage → DeployStore) + the sealed-credential store.
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn Storage> = Arc::new(NoopBlob);
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);

    // Pre-SEAL the bootstrap superuser credential under the SAME key the server-init env +
    // readiness + provisioning paths read — `(default, pg)` — with the REAL password of the
    // existing Postgres, so `provision_managed`'s superuser connection authenticates (mirroring a
    // DB already initialized with this sealed password). This is the "already-provisioned" base
    // credential the fix must NEVER rotate.
    {
        let sealed = envelope.wrap(su_pw.as_bytes()).await.unwrap();
        kv.put(
            &format!("managed-sql-cred/{DEFAULT_PROJECT}/{COMPUTE}"),
            sealed,
        )
        .await
        .unwrap();
    }
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());
    assert_eq!(
        creds.password(DEFAULT_PROJECT, COMPUTE).await.unwrap(),
        su_pw,
        "pre-seal: the sealed superuser credential must round-trip to the real PG password"
    );

    // Publish a Running + healthy + Provisioned replica for `(default, pg)` pointing at the live
    // PG, so the resolver's ungated `DeployEndpointResolver` resolves the endpoint to connect to.
    let endpoint = Endpoint::new(Scheme::Http, host.clone(), port);
    let observed = ObservedInstance {
        handle: InstanceHandle::new(
            DEFAULT_PROJECT.to_string(),
            COMPUTE.to_string(),
            0,
            "live".into(),
        ),
        node: 0,
        backend: "live".to_string(),
        endpoint: endpoint.clone(),
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
        .set_replica_state(ProjectRef::DEFAULT, &observed)
        .await
        .expect("publish replica state");

    // =====================================================================================
    // PHASE 1 — the v0.66.1 shape: provision WITHOUT rls_session, through the REAL adoption path.
    // =====================================================================================
    let env_off = env_for(&binding(&su_user, false), &kv, &envelope, &deploy);
    env_off
        .provision_managed(DEFAULT_PROJECT, COMPUTE, &endpoint)
        .await
        .expect("phase 1: provision the managed DB without rls_session");

    // The DB now exists and is superuser-owned; NO app role was created (rls off).
    let su_db = connect(k, &ExternalSqlOptions::new(su_to_db(&su_url, DB))).unwrap();
    assert_eq!(
        probe(
            &su_db,
            &format!("SELECT count(*)::int FROM pg_roles WHERE rolname = '{app_role}'")
        )
        .await,
        "0",
        "phase 1 (rls OFF) must NOT create the app role — that is the pre-adoption shape"
    );

    // As the superuser (schema owner), seed a plain ENABLE-RLS table keyed on the account GUC with
    // BOTH accounts' rows. (The app role is pinned to account A via a role-default GUC in phase 4,
    // once it exists — mirroring how an app sets its own account per request / session.)
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
            .unwrap_or_else(|e| panic!("phase 1 seed `{stmt}`: {e}"));
    }
    assert_eq!(
        probe(&su_db, "SELECT count(*)::int FROM t").await,
        "2",
        "both accounts' rows must be seeded on the existing DB"
    );

    // =====================================================================================
    // PHASE 2 — the adoption toggle + the PRE-FIX FAILURE SHAPE. Re-resolve the binding with
    // rls_session = true: the serving identity is now the app role, but it does not exist yet.
    // =====================================================================================
    let env_on = env_for(&binding(&su_user, true), &kv, &envelope, &deploy);

    // The app role's own sealed credential (distinct key) — `password` get-or-mints it even before
    // the role exists, exactly as the serving path would, so the connection attempt is realistic.
    let app_pw = creds
        .password(DEFAULT_PROJECT, &format!("{COMPUTE}/rlsapp"))
        .await
        .expect("app-role sealed credential");

    // THE FAILURE SHAPE: the serving path routes to the (absent) app role and FAILS CLOSED.
    {
        let serving = connect(
            k,
            &ExternalSqlOptions::new(as_role(&su_url, &app_role, &app_pw, DB)),
        )
        .expect("build a serving backend");
        assert!(
            serving.run_query("SELECT 1").await.is_err(),
            "PRE-FIX FAILURE SHAPE: before adoption the app role does not exist, so serving as it \
             must FAIL CLOSED — this is the incident the reconcile adoption pass closes"
        );
    }

    // THE DETECTION (the fix): an already-Provisioned replica needs its provisioning re-run.
    // MUTATION PROOF: revert the fix (`needs_reprovision` → the default `false`) and this fails.
    assert!(
        env_on
            .needs_reprovision(DEFAULT_PROJECT, COMPUTE, &endpoint)
            .await,
        "needs_reprovision must be TRUE: rls_session was adopted on an already-provisioned cell \
         whose non-superuser app role was never created"
    );

    // =====================================================================================
    // PHASE 3 — ADOPTION: re-run the idempotent provisioning IN PLACE (what advance_readiness now
    // does for a Provisioned replica with a pending reprovision). SAME DB, SAME volume, SAME cred.
    // =====================================================================================
    env_on
        .provision_managed(DEFAULT_PROJECT, COMPUTE, &endpoint)
        .await
        .expect("phase 3: re-run provisioning to adopt rls_session on the existing DB");

    // The detection is now satisfied (idempotent — nothing more to do).
    assert!(
        !env_on
            .needs_reprovision(DEFAULT_PROJECT, COMPUTE, &endpoint)
            .await,
        "after adoption the app role exists, so needs_reprovision must be FALSE (idempotent)"
    );

    // =====================================================================================
    // PHASE 4 — POST-ADOPTION INVARIANTS.
    // =====================================================================================
    // (a) The app role now exists and is genuinely NON-superuser / NON-BYPASSRLS.
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
        "adoption must create the app role as a NON-superuser / NON-BYPASSRLS login"
    );

    // (b) DATA SURVIVED: the same volume/data is intact — both seeded accounts' rows persist, and
    //     the table was not re-created (the fix must never destroy/recreate the volume).
    assert_eq!(
        probe(&su_db, "SELECT count(*)::int FROM t").await,
        "2",
        "DATA-SAFETY: the seeded rows on the SAME volume must survive adoption (no re-init)"
    );

    // (c) BASE CREDENTIAL UNTOUCHED: the superuser still authenticates with the ORIGINAL password,
    //     and the sealed value is unchanged — adoption never rotates the base credential.
    assert_eq!(
        creds.password(DEFAULT_PROJECT, COMPUTE).await.unwrap(),
        su_pw,
        "DATA-SAFETY: the base superuser credential must be byte-identical after adoption"
    );
    let su_recheck = connect(k, &ExternalSqlOptions::new(su_to_db(&su_url, DB))).unwrap();
    assert_eq!(
        probe(&su_recheck, "SELECT 1::int").await,
        "1",
        "the bootstrap superuser must still connect with its unchanged credential"
    );

    // (d) SERVING SWITCHES to the non-superuser app role (its DISTINCT sealed credential), and the
    //     2-account RLS isolation now HOLDS: pinned to account A it sees ONLY account A's row.
    //     Pin the (now-existing) app role to account A via a role-default GUC (mirrors how an app
    //     sets its own account per request), so the leak axis is unambiguous RLS visibility.
    su_db
        .run_script(&format!(
            "ALTER ROLE \"{app_role}\" SET \"{ACCT_GUC}\" = '{ACCT_A}'"
        ))
        .await
        .expect("pin the app role to account A");
    let serving = connect(
        k,
        &ExternalSqlOptions::new(as_role(&su_url, &app_role, &app_pw, DB)),
    )
    .expect("serving backend as the adopted app role");
    assert_eq!(
        probe(&serving, "SELECT current_user::text").await,
        app_role,
        "after adoption the runtime serves AS the provisioned non-superuser app role"
    );
    assert_eq!(
        probe(&serving, RUNTIME_ROLE_RLS_PRIVILEGED_PROBE_SQL).await,
        "0",
        "the runtime-role non-privilege probe must read 0 (unprivileged ⇒ the serving guard PERMITS)"
    );
    assert_eq!(
        probe(&serving, "SELECT count(*)::int FROM t").await,
        "1",
        "ISOLATION: served as the non-superuser app role (pinned to account A), the SELECT must \
         return ONLY account A's row — ZERO foreign (account B) bytes"
    );
    assert_eq!(
        probe(&serving, "SELECT account::text FROM t").await,
        ACCT_A,
        "the only row visible to the app role must be account A's"
    );

    // --- teardown (best-effort) ---
    drop(su_db);
    drop(su_recheck);
    drop(serving);
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"),
        format!("DROP ROLE IF EXISTS \"{app_role}\""),
    ] {
        let _ = su.run_script(&stmt).await;
    }

    println!("RLS ADOPT EXISTING DB OK [postgres]");
}
