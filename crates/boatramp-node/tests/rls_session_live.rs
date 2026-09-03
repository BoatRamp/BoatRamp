//! **The load-bearing `rls_session` guard gate** for the per-tenant managed-database
//! feature (PLAN-per-tenant-db) — Linux + root + a bridge, **ignored by default**. It
//! is the live proof that the `rls_session` guest-SQL guard actually holds end-to-end
//! against a real Postgres, complementing [`tenant_isolation_live`] (which proves the
//! per-tenant DB/role boundary).
//!
//! The `rls_session` feature injects the request's tenant into a reserved Postgres GUC
//! (`boatramp.project` / `boatramp.site`) so an app's hand-written row-level security
//! can key on it. A hostile guest must not be able to overwrite that injected value and
//! spoof its tenant. The guard
//! ([`boatramp_core::sql::reject_reserved_session_writes`]) is exhaustively
//! **unit**-tested, and the guest entry points that call it
//! (`boatramp_handlers::bindings::sql` `SqlHost::query`/`SqlHost::execute`, at
//! `crates/boatramp-handlers/src/bindings/sql.rs:195,229`) are **unit**-tested to both
//! call it for the whole hostile class — but unit tests prove nothing *against a live
//! database*. A prior round shipped a guard that unit-tested green yet was live
//! -bypassable on MySQL, so an end-to-end live assertion is the point.
//!
//! Against a really-provisioned per-tenant managed Postgres with `rls_session = true`,
//! this gate asserts, **live, within one begun transaction on the real
//! session-context-injecting backend the data plane hands a request**:
//!
//! 1. **Injection is real + wired**: after the backend begins a transaction for tenant
//!    `acme`, `SELECT current_setting('boatramp.project')` returns `acme`. This proves
//!    the resolved backend's [`injects_session_context()`] is actually `true` and the
//!    value is injected live (not merely that the config flag is set).
//! 2. **A guest spoof is refused AND the value is unchanged**: each hostile form (the
//!    `set_config` / `SET` / dollar-quoted `DO` classes) is driven through the exact
//!    guest entry-point sequence — the guard gated on the same
//!    [`injects_session_context()`] signal the `SqlHost` gates on — and every one is
//!    refused (`Err`), and the statement never reaches the transaction. Then the
//!    reserved GUC is re-read and asserted to STILL equal `acme` — `victim` never took
//!    effect. A control transaction proves the spoof WOULD change the GUC if run
//!    unguarded, so the value-unchanged assertion is meaningful (it's the guard doing
//!    the protecting, not an inert statement).
//! 3. Prints a clear success marker on pass so the CI step can grep for it.
//!
//! ## Faithfulness to the real guest entry points
//!
//! `SqlHost` / `SqlSession` live behind a **private** `mod bindings` in
//! `boatramp-handlers` (only `Bindings` is re-exported), so they cannot be driven
//! directly from this crate's test harness. This gate therefore uses the documented
//! fallback: it obtains the **real** session-context-injecting [`SqlBackend`] the data
//! plane builds for the tenant (via [`NodeTenantSqlResolver::resolve`], the exact
//! production path), and drives each spoof through a helper that reproduces the guest
//! entry point's sequence **byte-for-byte** — `if backend.injects_session_context() {
//! reject_reserved_session_writes(stmt)?; }` then run on the transaction — i.e. exactly
//! what `SqlHost::query` (`sql.rs:195`) and `SqlHost::execute` (`sql.rs:229`) do. That
//! BOTH entry points call the guard for the whole hostile class is separately locked by
//! the `rls_backend_rejects_guest_setting_reserved_keys` unit test in `boatramp-handlers`
//! (which drives the real `SqlHost::query` *and* `SqlHost::execute`); this gate adds the
//! live half those unit tests cannot: the guard holds against a real database and the
//! injected value is provably unchanged after a refused spoof.
//!
//! Prereqs on the host (same as [`tenant_isolation_live`]): a bridge with the gateway
//! IP, e.g.
//! ```sh
//! sudo ip link add br-boatramp type bridge 2>/dev/null || true
//! sudo ip addr add 10.0.0.1/24 dev br-boatramp 2>/dev/null || true
//! sudo ip link set br-boatramp up
//! ```
//! Run (as root, since the backend does veth/cgroup/unshare):
//! ```sh
//! sudo -E BOATRAMP_BIN=target/debug/boatramp \
//!   cargo test -p boatramp-node --features sql-postgres \
//!   --test rls_session_live -- --ignored --test-threads=1 --nocapture
//! ```
//! Skips (passes) when `BOATRAMP_BIN` is absent — never fails on a dev box. The single
//! test thread matters: the shared bridge (`br-boatramp`) can host only one launch at a
//! time.
//!
//! [`tenant_isolation_live`]: crate
//! [`injects_session_context()`]: boatramp_core::sql::SqlBackend::injects_session_context
//! [`NodeTenantSqlResolver::resolve`]: boatramp_node::tenant_sql

#![cfg(target_os = "linux")]
// The whole feature (and thus every symbol below) exists only under a sql engine.
#![cfg(feature = "sql-postgres")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use boatramp_container::ContainerBackend;
use boatramp_core::compute::{
    managed_db_spec, Artifact, ComputeBackend, ComputeWorkload, LaunchRequest, ManagedDbEngine,
    ObservedInstance, PlacementConstraints, PrivilegeDirective, ReplicaPhase,
};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::project::{ProjectRef, DEFAULT_PROJECT};
use boatramp_core::sql::{
    reject_reserved_session_writes, SqlBackend, SqlError, SqlTransaction, SqlValue,
};
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
use boatramp_node::managed_sql::ManagedSqlCredentials;
use boatramp_node::tenant_sql::NodeTenantSqlResolver;
use boatramp_storage::sql_sqlx::PerTenantSqlResolver;
use bytes::Bytes;
use futures::StreamExt;

/// The shared Postgres server's compute-workload name (the binding's `compute`).
const COMPUTE: &str = "pg";
/// The binding's configured database name (the per-tenant base; `appdb_<ident>`).
const DATABASE: &str = "appdb";
/// The binding's configured **superuser** on the shared server (the server-init user +
/// the account that runs provisioning DDL). Never handed to a tenant's data plane.
const SUPERUSER: &str = "postgres";
/// The tenant this gate injects + guards. Its `boatramp.project` must read back as this
/// and stay this across every refused spoof.
const TENANT_PROJECT: &str = "acme";

/// A `Storage` that serves one on-disk blob for every key (unused on the Image path —
/// the pgvector pull is over HTTP — but `ContainerBackend::new` still wants a store).
struct FileBlob(Vec<u8>);

#[async_trait]
impl Storage for FileBlob {
    async fn get(&self, _key: &str) -> Result<GetObject, StorageError> {
        let bytes = Bytes::from(self.0.clone());
        let size = self.0.len() as u64;
        let body: ByteStream = futures::stream::once(async move { Ok(bytes) }).boxed();
        Ok(GetObject {
            meta: ObjectMeta {
                key: String::new(),
                size: Some(size),
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

/// A reversible test "envelope" (NOT encryption) — the same test double the
/// `managed_sql` / `tenant_sql` unit tests use. Proves the sealed credential
/// round-trips; production uses a real KMS/local envelope with an identical contract.
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

/// The `Shared` / `Project`-grain binding under test, with **`rls_session = true`** so
/// the resolved backend injects `boatramp.project` / `boatramp.site` at every
/// transaction start and reports `injects_session_context() == true`.
fn rls_project_binding() -> ExternalDatabaseConfig {
    ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DATABASE.into()),
        user: Some(SUPERUSER.into()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        // THE feature under test: inject the request's tenant into the reserved GUC.
        rls_session: true,
        // A short connect timeout so a misconfigured connection fails fast.
        connect_timeout_secs: Some(10),
        ..Default::default()
    }
}

/// Poll `psql -tAc "select 1"` over TCP against `conn` until it answers `1`. ~30 s
/// budget for a first-boot `initdb`. Kept identical to the isolation gate's wait so the
/// two share the same first-boot behavior.
fn wait_for_pg(conn: &str) -> (bool, String) {
    let mut last = String::new();
    for _ in 0..60 {
        if let Ok(out) = std::process::Command::new("psql")
            .args([conn, "-tAc", "select 1"])
            .output()
        {
            last = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if out.status.success() && last.trim() == "1" {
                return (true, last);
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    (false, last)
}

/// LIVE `rls_session` guard proof on a real shared Postgres. See the module header.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Linux + root + a bridge + psql (privileged live seam); pulls pgvector"]
async fn rls_session_guard_holds_live_postgres() {
    let Some(bin) = std::env::var_os("BOATRAMP_BIN") else {
        eprintln!(
            "rls_session_live: set BOATRAMP_BIN (and have `psql` on PATH, root, and a \
             br-boatramp bridge) to run"
        );
        return;
    };
    let bridge = std::env::var("CONTAINER_BRIDGE").unwrap_or_else(|_| "br-boatramp".into());
    let subnet = std::env::var("CONTAINER_SUBNET").unwrap_or_else(|_| "10.0.0.0/24".into());

    // --- Control-plane state (KV + Storage → DeployStore) + the sealed-credential store.
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn Storage> = Arc::new(FileBlob(Vec::new()));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());

    // The superuser credential is sealed under the SAME key the server-init env injector
    // + the Shared provisioning path read: `(DEFAULT_PROJECT, COMPUTE)`. Materialise it
    // now and initialize the container with EXACTLY this password (mirroring how the
    // reconcile injects `POSTGRES_*` from the sealed credential), so provisioning as the
    // superuser later authenticates.
    let superuser_pw = creds
        .password(DEFAULT_PROJECT, COMPUTE)
        .await
        .expect("seal superuser credential");

    // --- Launch ONE shared Postgres via the native container backend, exactly as the
    // isolation gate does: the SHARED `managed_db_spec` synthesizer + the rootless
    // privilege directive + the managed server-init env from the sealed credential.
    let data_dir =
        std::env::temp_dir().join(format!("boatramp-rls-session-{}", std::process::id()));
    let backend = ContainerBackend::new(
        Arc::new(FileBlob(Vec::new())),
        data_dir.clone(),
        bridge,
        &subnet,
        PathBuf::from(bin),
    )
    .expect("backend");

    let mut spec = managed_db_spec(
        ManagedDbEngine::Postgres,
        Some("pgvector/pgvector:pg16"),
        512,
    );
    PrivilegeDirective::Rootless { uid: 999, gid: 999 }.apply(&mut spec);
    // The server-init credential env from the sealed superuser password.
    spec.env
        .insert("POSTGRES_USER".to_string(), SUPERUSER.to_string());
    spec.env
        .insert("POSTGRES_PASSWORD".to_string(), superuser_pw.clone());
    spec.env
        .insert("POSTGRES_DB".to_string(), DATABASE.to_string());

    let artifact = backend
        .materialize(&spec)
        .await
        .expect("materialize (pull) pgvector image");
    assert!(matches!(artifact, Artifact::Rootfs { .. }));

    // Register the workload's desired state + persist a healthy Running replica so
    // `DeployEndpointResolver` (and thus the resolver's `ComputeResolvedSqlBackend`)
    // resolves `pg` to host:port.
    let spec_id = deploy
        .put_compute_spec(&spec)
        .await
        .expect("store compute spec");
    deploy
        .set_compute_workload(
            ProjectRef::DEFAULT,
            &ComputeWorkload {
                version: 1,
                name: COMPUTE.to_string(),
                active: spec_id,
                replicas: 1,
                placement: PlacementConstraints::default(),
            },
        )
        .await
        .expect("register compute workload");

    let req = LaunchRequest {
        project: "default".into(),
        workload: COMPUTE.to_string(),
        replica: 0,
        spec,
        artifact,
    };
    let inst = backend
        .launch(&req)
        .await
        .expect("launch pgvector container");
    let handle = inst.handle.clone();
    let host = inst.endpoint.host.clone();
    let port = inst.endpoint.port;
    eprintln!("== shared pgvector launched == endpoint={host}:{port}");

    // Publish the replica state the endpoint resolver reads.
    let observed = ObservedInstance {
        handle: inst.handle.clone(),
        node: 0,
        backend: backend.id().to_string(),
        endpoint: inst.endpoint.clone(),
        region: None,
        healthy: true,
        started_at: None,
        phase: ReplicaPhase::Running,
        snapshot: None,
    };
    deploy
        .set_replica_state(ProjectRef::DEFAULT, &observed)
        .await
        .expect("publish replica state");

    // Run the assertions inside a closure so the container + temp dir are torn down on
    // BOTH the success and the failure path (a leaked rootless container would hold the
    // single test bridge). The outcome is unwrapped AFTER cleanup, so a failed assertion
    // still stops before the success marker (the gate greps for the marker, not for
    // `test result: ok`).
    let outcome = run_assertions(&deploy, &kv, &envelope, &superuser_pw, &host, port).await;

    let _ = backend.stop(&handle).await;
    let _ = std::fs::remove_dir_all(&data_dir);

    outcome.expect("rls_session guard assertions");

    // The single success marker the capability gate greps for. Printed ONLY after every
    // assertion held (a silent skip returns before this line; a failed assertion returns
    // an Err above and `expect` panics before here).
    println!(
        "RLS SESSION GUARD OK (postgres): guest spoof refused, boatramp.project stayed {TENANT_PROJECT}"
    );

    // TODO(follow-up): MySQL live variant. It is where the guard was previously
    // live-bypassable (the `@boatramp_*` comma-assign / `SELECT … INTO` family), so it
    // is high value. It is deferred here only because the shared harness
    // (`tenant_isolation_live` + this gate) stands up Postgres alone: a MySQL variant
    // needs a `mysql:8.0` container via `managed_db_spec(ManagedDbEngine::Mysql, …)` +
    // its `MYSQL_*` server-init env, a longer/heavier first-boot init wait than
    // Postgres, and reads via `@boatramp_project` instead of
    // `current_setting('boatramp.project')`. The guard itself and both `SqlHost` entry
    // points are engine-agnostic and unit-tested for the MySQL forms; the resolver's
    // MySQL backend also scrubs the connection-lifetime `@boatramp_*` var on pooled
    // reuse. Building it: add a `mysql` variant of `run_assertions` (spoofs =
    // `SET @x=1, @boatramp_project='victim'` and `SELECT 'victim' INTO @boatramp_project`;
    // read = `SELECT @boatramp_project`) and wire a second capability.yml step with
    // `--features sql-mysql`.
}

/// The spoof forms the guard must refuse on Postgres, each of which — if it ran — would
/// overwrite the injected `boatramp.project` and let the guest spoof its tenant. Covers
/// the three classes from the security-review loop: `set_config`, leading `SET`, and the
/// dollar-quoted `DO` block (the proven Round-1 High).
const PG_SPOOFS: &[&str] = &[
    "SELECT set_config('boatramp.project','victim',false)",
    "SET boatramp.project='victim'",
    "DO $$ BEGIN PERFORM set_config('boatramp.project','victim',false); END $$;",
];

/// A statement that, run UNGUARDED on the injecting transaction, actually changes
/// `boatramp.project` — used by the control check to prove the spoofs are not inert (so
/// the "value unchanged after a refused spoof" assertion is meaningful). `is_local =>
/// true` keeps it transaction-scoped like the injection itself.
const PG_UNGUARDED_OVERWRITE: &str = "SELECT set_config('boatramp.project','victim',true)";

/// Reproduce the guest `sql` entry point's sequence **exactly** as
/// `SqlHost::query`/`SqlHost::execute` do (`sql.rs:195` / `:229`): when the backend
/// injects the reserved session context, run the guard first and refuse on a match; only
/// then touch the transaction. Returns `Ok(())` if the statement was allowed and ran,
/// `Err` if the guard refused it (so the caller can assert the refusal + that nothing
/// reached the DB).
async fn guest_entry_point_execute(
    backend: &Arc<dyn SqlBackend>,
    tx: &mut Box<dyn SqlTransaction>,
    statement: &str,
) -> Result<(), SqlError> {
    // === The exact guard gate the real SqlHost applies (H1). ===
    if backend.injects_session_context() {
        reject_reserved_session_writes(statement)?;
    }
    tx.execute(statement, &[]).await.map(|_| ())
}

/// Read the live value of the reserved `boatramp.project` GUC on `tx` (the same
/// injecting transaction), as text.
async fn read_boatramp_project(tx: &mut Box<dyn SqlTransaction>) -> Result<String, SqlError> {
    let rows = tx
        .query("SELECT current_setting('boatramp.project')", &[])
        .await?;
    match rows.rows.first().and_then(|r| r.first()) {
        Some(SqlValue::Text(s)) => Ok(s.clone()),
        other => Err(SqlError::other(format!(
            "current_setting('boatramp.project') was not text: {other:?}"
        ))),
    }
}

/// The live `rls_session` guard assertions, factored out so the caller can tear the
/// container down on either outcome. Returns `Err(reason)` on the first failed invariant
/// (fail closed), `Ok(())` when every assertion held.
async fn run_assertions(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    superuser_pw: &str,
    host: &str,
    port: u16,
) -> Result<(), String> {
    // --- Wait for the server to be up as the superuser (first-boot initdb + our creds).
    let super_conn = format!("postgresql://{SUPERUSER}:{superuser_pw}@{host}:{port}/{DATABASE}");
    let (up, last) = wait_for_pg(&super_conn);
    if !up {
        return Err(format!(
            "shared Postgres should answer `select 1` as the superuser (last: {last:?})"
        ));
    }

    // --- Obtain the REAL session-context-injecting backend the data plane hands a
    // request, through the SHIPPED resolver path. `resolve` lazily provisions the tenant
    // (idempotent) and builds the `ComputeResolvedSqlBackend` with the request's tenant
    // injected — the exact production seam. No hand-rolled backend.
    let binding = rls_project_binding();
    let resolver =
        NodeTenantSqlResolver::new(deploy.clone(), kv.clone(), envelope.clone(), &binding)
            .ok_or_else(|| {
                "resolver should build for a compute-backed managed binding".to_string()
            })?;
    let backend: Arc<dyn SqlBackend> = resolver
        .resolve(TENANT_PROJECT, "-")
        .await
        .map_err(|e| format!("resolve tenant {TENANT_PROJECT}: {e}"))?;

    // The whole point of the guard is gated on this signal — assert it is actually on,
    // so a resolver regression that dropped the injection can't make the gate vacuous.
    if !backend.injects_session_context() {
        return Err(
            "the resolved rls_session backend must report injects_session_context() == true \
             (else the guest guard would be inert and this gate vacuous)"
                .to_string(),
        );
    }

    // === Assertion 1 (INJECTION IS REAL + WIRED): begin a transaction for `acme` on the
    // real backend; the injected GUC must read back as `acme`. This proves the value is
    // injected LIVE (not merely that the flag is set). ===
    let mut tx = backend
        .begin()
        .await
        .map_err(|e| format!("begin injecting transaction: {e}"))?;
    let injected = read_boatramp_project(&mut tx)
        .await
        .map_err(|e| format!("read injected boatramp.project: {e}"))?;
    if injected != TENANT_PROJECT {
        return Err(format!(
            "injection not wired: boatramp.project read back {injected:?}, expected {TENANT_PROJECT:?}"
        ));
    }
    eprintln!("injection: boatramp.project == {injected:?}  OK");

    // === Assertion 2 (GUEST SPOOF REFUSED + VALUE UNCHANGED): each hostile form is
    // driven through the exact guest entry-point sequence and must be REFUSED, and after
    // every refusal the reserved GUC must STILL equal `acme`. ===
    for spoof in PG_SPOOFS {
        let refused = guest_entry_point_execute(&backend, &mut tx, spoof).await;
        // (a) the guard refused it at the entry point.
        if refused.is_ok() {
            return Err(format!(
                "GUARD BYPASS: guest spoof was ALLOWED through the entry point: {spoof:?}"
            ));
        }
        // (b) the reserved value is unchanged — `victim` never took effect.
        let after = read_boatramp_project(&mut tx)
            .await
            .map_err(|e| format!("re-read boatramp.project after refused spoof {spoof:?}: {e}"))?;
        if after != TENANT_PROJECT {
            return Err(format!(
                "RLS SPOOF LANDED: after refused spoof {spoof:?}, boatramp.project = {after:?} \
                 (expected it to stay {TENANT_PROJECT:?})"
            ));
        }
        eprintln!("spoof refused + value unchanged: {spoof:?}  OK");
    }

    // === Control (the value-unchanged assertion is meaningful): a spoof run UNGUARDED
    // on a fresh injecting transaction DOES change the GUC — so the assertions above are
    // the guard doing the protecting, not inert statements. This never runs through the
    // guest entry point (it deliberately bypasses it to demonstrate the danger). ===
    {
        let mut ctl = backend
            .begin()
            .await
            .map_err(|e| format!("begin control transaction: {e}"))?;
        let base = read_boatramp_project(&mut ctl)
            .await
            .map_err(|e| format!("control read (pre): {e}"))?;
        if base != TENANT_PROJECT {
            return Err(format!(
                "control precondition: expected {TENANT_PROJECT:?}, got {base:?}"
            ));
        }
        // Bypass the guard on purpose: run the overwrite straight on the transaction.
        ctl.execute(PG_UNGUARDED_OVERWRITE, &[])
            .await
            .map_err(|e| format!("control unguarded overwrite: {e}"))?;
        let after = read_boatramp_project(&mut ctl)
            .await
            .map_err(|e| format!("control read (post): {e}"))?;
        if after != "victim" {
            return Err(format!(
                "control invalid: an UNGUARDED set_config should change boatramp.project to \
                 \"victim\", got {after:?} — the spoofs would be inert, making the \
                 value-unchanged assertion meaningless"
            ));
        }
        let _ = ctl.rollback().await;
        eprintln!("control: an UNGUARDED overwrite DOES change boatramp.project to \"victim\"  OK");
    }

    let _ = tx.rollback().await;
    Ok(())
}
