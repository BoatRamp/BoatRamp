//! **The MySQL `rls_session` guard gate** — the two-engine-parity counterpart to the
//! Postgres gate in [`rls_session_live`] (`rls_session_guard_holds_live_postgres`). Needs
//! Linux, root, and a bridge; **ignored by default**. It is the live proof that the
//! `rls_session` guest-SQL guard actually holds end-to-end against a real **MySQL**.
//!
//! MySQL is where this matters most: the guard was previously *live-bypassable* on MySQL
//! (the `@boatramp_*` comma-assign — `SET @x=1, @boatramp_project='victim'` — and the
//! `SELECT … INTO @boatramp_project` forms, neither of which the leading-token check
//! sees). The guard ([`boatramp_core::sql::reject_reserved_session_writes`]) now refuses
//! the whole `@boatramp_*` family position-independently, and this gate is the durable
//! live proof of that on a stock `mysql:8.0`.
//!
//! The `rls_session` feature injects the request's tenant into a reserved MySQL session
//! variable (`@boatramp_project` / `@boatramp_site`) so an app's hand-written row-level
//! security can key on it. A hostile guest must not be able to overwrite that injected
//! value and spoof its tenant. Against a really-provisioned per-tenant managed MySQL with
//! `rls_session = true`, this gate asserts, **live, within one begun transaction on the
//! real session-context-injecting backend the data plane hands a request**:
//!
//! 1. **Injection is real + wired**: after the backend begins a transaction for tenant
//!    `acme`, `SELECT @boatramp_project` returns `acme`. This proves the resolved
//!    backend's [`injects_session_context()`] is actually `true` and the value is injected
//!    live (not merely that the config flag is set).
//! 2. **A guest spoof is refused AND the value is unchanged**: each hostile MySQL form
//!    (the comma-assign and the `SELECT … INTO @var` classes) is driven through the exact
//!    guest entry-point sequence — the guard gated on the same
//!    [`injects_session_context()`] signal the `SqlHost` gates on — and every one is
//!    refused (`Err`), and the statement never reaches the transaction. Then the reserved
//!    var is re-read and asserted to STILL equal `acme` — `victim` never took effect.
//! 3. A **control** transaction proves the spoof WOULD change the var if run unguarded, so
//!    the value-unchanged assertion is meaningful (it's the guard doing the protecting,
//!    not an inert statement). MySQL user vars are connection-scoped, so the control runs
//!    on its OWN fresh injecting transaction and is rolled back — the injecting backend
//!    wraps every transaction in a session-scoped tx that scrubs `@boatramp_*` to `NULL`
//!    on rollback, so the pooled connection returns clean.
//! 4. Prints a clear success marker on pass so the CI step can grep for it.
//!
//! ## Faithfulness to the real guest entry points
//!
//! Identical to the Postgres gate: `SqlHost` / `SqlSession` live behind a **private**
//! `mod bindings` in `boatramp-handlers`, so this gate obtains the **real**
//! session-context-injecting [`SqlBackend`] the data plane builds for the tenant (via
//! [`NodeTenantSqlResolver::resolve`], the exact production path) and drives each spoof
//! through a helper that reproduces the guest entry point's sequence **byte-for-byte** —
//! `if backend.injects_session_context() { reject_reserved_session_writes(stmt)?; }` then
//! run on the transaction — i.e. exactly what `SqlHost::query`/`SqlHost::execute` do. That
//! BOTH entry points call the guard for the whole hostile class is separately locked by
//! the `rls_backend_rejects_guest_setting_reserved_keys` unit test in `boatramp-handlers`;
//! this gate adds the live half those unit tests cannot: the guard holds against a real
//! MySQL and the injected value is provably unchanged after a refused spoof.
//!
//! Prereqs on the host (same as the Postgres gates): a bridge with the gateway IP, e.g.
//! ```sh
//! sudo ip link add br-boatramp type bridge 2>/dev/null || true
//! sudo ip addr add 10.0.0.1/24 dev br-boatramp 2>/dev/null || true
//! sudo ip link set br-boatramp up
//! ```
//! Run (as root, since the backend does veth/cgroup/unshare):
//! ```sh
//! sudo -E BOATRAMP_BIN=target/debug/boatramp \
//!   cargo test -p boatramp-node --features sql-mysql \
//!   --test rls_session_mysql_live -- --ignored --test-threads=1 --nocapture
//! ```
//! Unlike the Postgres gates, **no host DB client is required**: readiness and every read
//! go through boatramp's own MySQL [`SqlBackend`] (sqlx), not a `mysql` CLI. MySQL's
//! first-boot init is slower than Postgres's `initdb`, so the readiness wait is generous
//! (~120 s). Skips (passes) when `BOATRAMP_BIN` is absent — never fails on a dev box. The
//! single test thread matters: the shared bridge (`br-boatramp`) can host only one launch
//! at a time.
//!
//! [`rls_session_live`]: crate
//! [`injects_session_context()`]: boatramp_core::sql::SqlBackend::injects_session_context
//! [`NodeTenantSqlResolver::resolve`]: boatramp_node::tenant_sql

#![cfg(target_os = "linux")]
// The whole feature (and thus every symbol below) exists only under the MySQL sql engine.
#![cfg(feature = "sql-mysql")]

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

/// The shared MySQL server's compute-workload name (the binding's `compute`).
const COMPUTE: &str = "my";
/// The binding's configured database name (the per-tenant base; `appdb_<ident>`).
const DATABASE: &str = "appdb";
/// The binding's configured **superuser** on the shared server. For MySQL this is `root`
/// (the account `MYSQL_ROOT_PASSWORD` initializes), which runs the provisioning DDL and
/// is never handed to a tenant's data plane.
const SUPERUSER: &str = "root";
/// The tenant this gate injects + guards. Its `@boatramp_project` must read back as this
/// and stay this across every refused spoof.
const TENANT_PROJECT: &str = "acme";

/// A `Storage` that serves one on-disk blob for every key (unused on the Image path —
/// the mysql pull is over HTTP — but `ContainerBackend::new` still wants a store).
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
/// the resolved backend injects `@boatramp_project` / `@boatramp_site` at every
/// transaction start and reports `injects_session_context() == true`.
fn rls_project_binding() -> ExternalDatabaseConfig {
    ExternalDatabaseConfig {
        kind: "mysql".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DATABASE.into()),
        user: Some(SUPERUSER.into()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        // THE feature under test: inject the request's tenant into the reserved var.
        rls_session: true,
        // A short connect timeout so a misconfigured connection fails fast.
        connect_timeout_secs: Some(10),
        ..Default::default()
    }
}

/// LIVE `rls_session` guard proof on a real shared MySQL. See the module header.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Linux + root + a bridge (privileged live seam); pulls mysql:8.0"]
async fn rls_session_guard_holds_live_mysql() {
    let Some(bin) = std::env::var_os("BOATRAMP_BIN") else {
        eprintln!("rls_session_mysql_live: set BOATRAMP_BIN (root + a br-boatramp bridge) to run");
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

    // The superuser (root) credential is sealed under the SAME key the server-init env
    // injector + the Shared provisioning path read: `(DEFAULT_PROJECT, COMPUTE)`.
    // Materialise it now and initialize the container with EXACTLY this password
    // (mirroring how the reconcile injects `MYSQL_ROOT_PASSWORD` from the sealed
    // credential), so provisioning as root later authenticates.
    let superuser_pw = creds
        .password(DEFAULT_PROJECT, COMPUTE)
        .await
        .expect("seal superuser credential");

    // --- Launch ONE shared MySQL via the native container backend, exactly as the
    // Postgres gates do: the SHARED `managed_db_spec` synthesizer + the rootless privilege
    // directive + the managed server-init env from the sealed credential. The container
    // backend supplies the sticky `/run` tmpfs (`mode=1777`) MySQL needs to create its
    // socket dir under `/run` during init.
    let data_dir =
        std::env::temp_dir().join(format!("boatramp-rls-session-my-{}", std::process::id()));
    let backend = ContainerBackend::new(
        Arc::new(FileBlob(Vec::new())),
        data_dir.clone(),
        bridge,
        &subnet,
        PathBuf::from(bin),
    )
    .expect("backend");

    let mut spec = managed_db_spec(ManagedDbEngine::Mysql, Some("mysql:8.0"), 512);
    PrivilegeDirective::Rootless { uid: 999, gid: 999 }.apply(&mut spec);
    // The server-init credential env from the sealed root password. MySQL refuses
    // `MYSQL_USER=root`, so only the root password + default database are set here; the
    // per-tenant login role is created by the provisioning DDL (run as root), exactly as
    // the Shared path does in production.
    spec.env
        .insert("MYSQL_ROOT_PASSWORD".to_string(), superuser_pw.clone());
    spec.env
        .insert("MYSQL_DATABASE".to_string(), DATABASE.to_string());

    let artifact = backend
        .materialize(&spec)
        .await
        .expect("materialize (pull) mysql image");
    assert!(matches!(artifact, Artifact::Rootfs { .. }));

    // Register the workload's desired state + persist a healthy Running replica so
    // `DeployEndpointResolver` (and thus the resolver's `ComputeResolvedSqlBackend`)
    // resolves `my` to host:port.
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
    let inst = backend.launch(&req).await.expect("launch mysql container");
    let handle = inst.handle.clone();
    let host = inst.endpoint.host.clone();
    let port = inst.endpoint.port;
    eprintln!("== shared mysql launched == endpoint={host}:{port}");

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
    let outcome = run_assertions(&deploy, &kv, &envelope).await;

    let _ = backend.stop(&handle).await;
    let _ = std::fs::remove_dir_all(&data_dir);

    outcome.expect("rls_session guard assertions");

    // The single success marker the capability gate greps for. Printed ONLY after every
    // assertion held (a silent skip returns before this line; a failed assertion returns
    // an Err above and `expect` panics before here).
    println!(
        "RLS SESSION GUARD OK (mysql): guest spoof refused, @boatramp_project stayed {TENANT_PROJECT}"
    );
}

/// The spoof forms the guard must refuse on MySQL, each of which — if it ran — would
/// overwrite the injected `@boatramp_project` and let the guest spoof its tenant. These
/// are the two forms that were previously live-bypassable (they evade the leading-`SET`
/// target check): the comma-assign and the `SELECT … INTO @var` (no `SET` at all).
const MYSQL_SPOOFS: &[&str] = &[
    "SET @x=1, @boatramp_project='victim'",
    "SELECT 'victim' INTO @boatramp_project",
];

/// A statement that, run UNGUARDED on the injecting transaction, actually changes
/// `@boatramp_project` — used by the control check to prove the spoofs are not inert (so
/// the "value unchanged after a refused spoof" assertion is meaningful).
const MYSQL_UNGUARDED_OVERWRITE: &str = "SET @boatramp_project='victim'";

/// Reproduce the guest `sql` entry point's sequence **exactly** as
/// `SqlHost::query`/`SqlHost::execute` do: when the backend injects the reserved session
/// context, run the guard first and refuse on a match; only then touch the transaction.
/// Returns `Ok(())` if the statement was allowed and ran, `Err` if the guard refused it
/// (so the caller can assert the refusal + that nothing reached the DB).
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

/// Read the live value of the reserved `@boatramp_project` MySQL user var on `tx` (the
/// same injecting transaction), as text. `@boatramp_project` is unset ⇒ `NULL`; the
/// injected value is a string. The read is `CAST(… AS CHAR)` so MySQL reports the user
/// var as `VARCHAR` (→ `SqlValue::Text`) regardless of the var's internal collation kind
/// — a stray `Blob` (bytes) is decoded to text too, so the assertion never wrongly fails
/// on a decode-class quirk.
async fn read_boatramp_project(tx: &mut Box<dyn SqlTransaction>) -> Result<String, SqlError> {
    let rows = tx
        .query("SELECT CAST(@boatramp_project AS CHAR)", &[])
        .await?;
    match rows.rows.first().and_then(|r| r.first()) {
        Some(SqlValue::Text(s)) => Ok(s.clone()),
        Some(SqlValue::Blob(b)) => Ok(String::from_utf8_lossy(b).into_owned()),
        Some(SqlValue::Null) => Ok(String::new()),
        other => Err(SqlError::other(format!(
            "@boatramp_project was not text/blob/null: {other:?}"
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
) -> Result<(), String> {
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

    // --- Wait for the server: MySQL's first boot (init + user/db creation + a restart)
    // is markedly slower than Postgres's `initdb`, so budget ~120 s. Readiness goes
    // through boatramp's OWN MySQL backend (no host `mysql` CLI): `resolve` provisions +
    // connects as the tenant role, then `begin` opens a transaction, which is exactly the
    // path a request takes. Retry until it succeeds or the budget elapses.
    let backend = wait_for_resolved_backend(&resolver).await?;

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
    // real backend; the injected var must read back as `acme`. This proves the value is
    // injected LIVE (not merely that the flag is set). ===
    let mut tx = backend
        .begin()
        .await
        .map_err(|e| format!("begin injecting transaction: {e}"))?;
    let injected = read_boatramp_project(&mut tx)
        .await
        .map_err(|e| format!("read injected @boatramp_project: {e}"))?;
    if injected != TENANT_PROJECT {
        return Err(format!(
            "injection not wired: @boatramp_project read back {injected:?}, expected {TENANT_PROJECT:?}"
        ));
    }
    eprintln!("injection: @boatramp_project == {injected:?}  OK");

    // === Assertion 2 (GUEST SPOOF REFUSED + VALUE UNCHANGED): each hostile form is
    // driven through the exact guest entry-point sequence and must be REFUSED, and after
    // every refusal the reserved var must STILL equal `acme`. ===
    for spoof in MYSQL_SPOOFS {
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
            .map_err(|e| format!("re-read @boatramp_project after refused spoof {spoof:?}: {e}"))?;
        if after != TENANT_PROJECT {
            return Err(format!(
                "RLS SPOOF LANDED: after refused spoof {spoof:?}, @boatramp_project = {after:?} \
                 (expected it to stay {TENANT_PROJECT:?})"
            ));
        }
        eprintln!("spoof refused + value unchanged: {spoof:?}  OK");
    }
    let _ = tx.rollback().await;

    // === Control (the value-unchanged assertion is meaningful): a spoof run UNGUARDED
    // on a FRESH injecting transaction DOES change the var — so the assertions above are
    // the guard doing the protecting, not inert statements. MySQL user vars are
    // connection-scoped, so this runs on its own transaction; the injecting backend wraps
    // every transaction so `@boatramp_*` is scrubbed to `NULL` on rollback, returning the
    // pooled connection clean. This never runs through the guest entry point (it
    // deliberately bypasses it to demonstrate the danger). ===
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
        ctl.execute(MYSQL_UNGUARDED_OVERWRITE, &[])
            .await
            .map_err(|e| format!("control unguarded overwrite: {e}"))?;
        let after = read_boatramp_project(&mut ctl)
            .await
            .map_err(|e| format!("control read (post): {e}"))?;
        if after != "victim" {
            return Err(format!(
                "control invalid: an UNGUARDED `SET @boatramp_project` should change it to \
                 \"victim\", got {after:?} — the spoofs would be inert, making the \
                 value-unchanged assertion meaningless"
            ));
        }
        // Rollback scrubs `@boatramp_*` to NULL on the pooled connection (the injecting
        // backend's session-scoped tx), so no `victim` lingers for a later reuse.
        let _ = ctl.rollback().await;
        eprintln!(
            "control: an UNGUARDED overwrite DOES change @boatramp_project to \"victim\"  OK"
        );
    }

    Ok(())
}

/// Resolve the injecting backend and prove it can begin a transaction, retrying while
/// MySQL finishes its (slow) first boot. `resolve` provisions the tenant + connects as
/// its role; `begin` opens a transaction — the exact request path, so a success proves
/// the server is fully up AND the tenant is provisioned. ~120 s budget.
async fn wait_for_resolved_backend(
    resolver: &NodeTenantSqlResolver,
) -> Result<Arc<dyn SqlBackend>, String> {
    let mut last = String::new();
    for _ in 0..120 {
        match resolver.resolve(TENANT_PROJECT, "-").await {
            Ok(backend) => match backend.begin().await {
                // A transaction begun (which also applies the session context) proves the
                // server is serving and the tenant role can connect.
                Ok(tx) => {
                    let _ = tx.rollback().await;
                    return Ok(backend);
                }
                Err(e) => last = format!("begin: {e}"),
            },
            Err(e) => last = format!("resolve: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(format!(
        "shared MySQL never became ready for tenant {TENANT_PROJECT} within the budget \
         (last: {last:?})"
    ))
}
