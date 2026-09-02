//! **The load-bearing Single-mode volume-isolation gate** for the per-tenant managed
//! database feature (PLAN-per-tenant-db) — Linux + root + a bridge, **ignored by
//! default**. It is the live proof of the v0.3.11 fix: a **non-default** `Single`-mode
//! per-tenant managed Postgres comes up on its **own isolated data volume** and the app
//! **authenticates** with its freshly-minted per-tenant credential.
//!
//! ## The bug this guards (v0.3.11)
//!
//! Before v0.3.11, `managed_db_spec` gave every managed DB the fixed volume name
//! `"data"`, and the container backend backs a volume at
//! `<data_dir>/compute/volumes/<name>` keyed by NAME alone — so every managed workload on
//! a node mounted the SAME PGDATA. A non-default per-tenant `Single` container reused
//! another tenant's (or a prior default / v0.3.9) data dir, Postgres skipped `initdb`, and
//! the app failed auth ("password authentication failed for user …") against its own
//! freshly-minted credential. The fix
//! ([`managed_volume_name`](boatramp_node::tenant_sql), in `tenant_sql.rs`): a non-default
//! `Single` workload's volume is keyed to its own **workload**
//! (`<data_dir>/compute/volumes/<workload>`), while the reserved **default** install keeps
//! the historical `"data"` so an existing deployment is not re-initdb'd on upgrade.
//!
//! There was NO Single-mode live gate — which is why it shipped broken — so this gate is
//! that missing proof. It complements [`tenant_isolation_live`] (the Shared DB/role
//! boundary) and [`rls_session_live`] (the RLS spoof guard).
//!
//! ## What this gate asserts (live, on a real Postgres)
//!
//! Provision a **non-default** `Single` tenant (`acme`, `tenant = Single`,
//! `tenant_scope = project`) through the SHIPPED path
//! ([`provision_tenant`](boatramp_node::tenant_sql)) — which registers the tenant's
//! dedicated compute workload with the per-tenant volume name **and** mints the per-tenant
//! credential — then stand up its dedicated container via the native
//! [`ContainerBackend`] (mirroring [`tenant_isolation_live`] / [`rls_session_live`]) and:
//!
//! 1. **Isolated volume:** the launched container's data volume is
//!    `<data_dir>/compute/volumes/<workload>` (the per-tenant workload name), NOT
//!    `<data_dir>/compute/volumes/data`. Asserted on the registered spec's volume name AND
//!    the on-disk backing dir the backend created.
//! 2. **Fresh initdb + matching credential (the core):** connect through the SHIPPED
//!    resolved backend for the tenant ([`NodeTenantSqlResolver::resolve`] →
//!    `ComputeResolvedSqlBackend`) and run `SELECT current_user` — it must SUCCEED, proving
//!    the container `initdb`'d the app role with the per-tenant credential on its fresh
//!    volume and the app authenticates. (Before the fix this failed auth.)
//! 3. **No collision between two Single tenants:** a SECOND non-default `Single` tenant
//!    (`globex`) lands on a DISTINCT volume dir and ALSO authenticates independently — the
//!    isolation the fixed key provides (the real failure mode was two tenants sharing one
//!    volume).
//! 4. Print a single success marker only after every assertion held.
//!
//! No host `psql` is needed — every connection goes through boatramp's own Postgres backend
//! (sqlx), exactly as [`rls_session_live`] does.
//!
//! Prereqs on the host (same as the sibling live gates): a bridge with the gateway IP, e.g.
//! ```sh
//! sudo ip link add br-boatramp type bridge 2>/dev/null || true
//! sudo ip addr add 10.0.0.1/24 dev br-boatramp 2>/dev/null || true
//! sudo ip link set br-boatramp up
//! ```
//! Run (as root, since the backend does veth/cgroup/unshare):
//! ```sh
//! sudo -E BOATRAMP_BIN=target/debug/boatramp \
//!   cargo test -p boatramp-node --features sql-postgres \
//!   --test single_volume_live -- --ignored --test-threads=1 --nocapture
//! ```
//! Skips (passes) when `BOATRAMP_BIN` is absent — never fails on a dev box. The single test
//! thread matters: the two per-tenant launches share the one `br-boatramp` bridge and must
//! not contend.
//!
//! [`tenant_isolation_live`]: https://docs.rs/boatramp-node
//! [`rls_session_live`]: https://docs.rs/boatramp-node
//! [`ContainerBackend`]: boatramp_container::ContainerBackend
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
    Artifact, ComputeBackend, LaunchRequest, ObservedInstance, PrivilegeDirective, ReplicaPhase,
};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::project::ProjectRef;
use boatramp_core::sql::{SqlBackend, SqlValue};
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
use boatramp_node::managed_sql::ManagedSqlCredentials;
use boatramp_node::tenant_sql::{provision_tenant, NodeTenantSqlResolver};
use boatramp_storage::sql_sqlx::PerTenantSqlResolver;
use bytes::Bytes;
use futures::StreamExt;

/// The binding's configured compute-workload base. A `Single` tenant's dedicated
/// workload is `<COMPUTE>-<ident>` (e.g. `pg-acme`), so its volume name is that same
/// derived, unique workload — the v0.3.11 fix.
const COMPUTE: &str = "pg";
/// The binding's configured database name — the plain DB inside each per-tenant Single
/// container (the container is the isolation, not the db name).
const DATABASE: &str = "appdb";
/// The binding's configured app user. For `Single` this is the account the container is
/// initialized with AND the account the resolver connects as (no per-database role).
const APP_USER: &str = "app";
/// The two non-default `Single` tenants under test. Distinct projects ⇒ distinct
/// workloads ⇒ distinct volume dirs (the collision this gate rules out).
const TENANTS: &[&str] = &["acme", "globex"];
/// The literal shared volume name the pre-v0.3.11 bug used for EVERY managed DB — the
/// exact name a non-default Single volume must NOT be (else two tenants share PGDATA).
const SHARED_VOLUME_BUG_NAME: &str = "data";

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
/// `managed_sql` / `tenant_sql` unit tests and the sibling live gates use. Proves the
/// sealed credential round-trips; production uses a real KMS/local envelope with an
/// identical contract, so this exercises the exact `ManagedSqlCredentials` path.
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

/// The `Single` / `Project`-grain binding under test: one **dedicated** per-tenant
/// Postgres container per project tenant (isolation by process/volume), with the plain
/// `appdb` database + `app` user inside each.
fn single_project_binding() -> ExternalDatabaseConfig {
    ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DATABASE.into()),
        user: Some(APP_USER.into()),
        tenant: TenantIsolation::Single,
        tenant_scope: TenantScope::Project,
        // A short connect timeout so a misconfigured connection fails fast.
        connect_timeout_secs: Some(10),
        ..Default::default()
    }
}

/// LIVE Single-mode volume-isolation + authenticate proof on a real Postgres. See the
/// module header. Stands up TWO per-tenant containers (`acme`, `globex`) to prove the
/// no-collision half — the real failure mode was two tenants sharing one volume.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Linux + root + a bridge (privileged live seam); pulls pgvector, boots 2 containers"]
async fn single_mode_isolates_volumes_and_each_authenticates() {
    let Some(bin) = std::env::var_os("BOATRAMP_BIN") else {
        eprintln!(
            "single_volume_live: set BOATRAMP_BIN (root + a br-boatramp bridge) to run; \
             skipping (never fails on a dev box)"
        );
        return;
    };
    let bin = PathBuf::from(bin);
    let bridge = std::env::var("CONTAINER_BRIDGE").unwrap_or_else(|_| "br-boatramp".into());
    let subnet = std::env::var("CONTAINER_SUBNET").unwrap_or_else(|_| "10.0.0.0/24".into());

    // --- Control-plane state (KV + Storage → DeployStore) + the sealed-credential store.
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn Storage> = Arc::new(FileBlob(Vec::new()));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());

    // One backend + one temp data_dir shared by both tenants — so the two per-tenant
    // volumes land under the SAME `<data_dir>/compute/volumes/`, which is exactly where a
    // shared `"data"` name WOULD have collided. Distinct volume dirs here therefore prove
    // the fix, not merely two separate data_dirs.
    let data_dir = std::env::temp_dir().join(format!("boatramp-single-vol-{}", std::process::id()));
    let backend = Arc::new(
        ContainerBackend::new(
            Arc::new(FileBlob(Vec::new())),
            data_dir.clone(),
            bridge,
            &subnet,
            bin,
        )
        .expect("backend"),
    );

    // Run the assertions inside a closure so BOTH launched containers + the temp dir are
    // torn down on either outcome (a leaked rootless container would hold the single test
    // bridge). The outcome is unwrapped AFTER cleanup, so a failed assertion still stops
    // before the success marker (the gate greps for the marker, not for `test result: ok`).
    let outcome = run_assertions(&deploy, &kv, &envelope, &creds, &backend, &data_dir).await;

    // Tear down every launched container (best-effort), then the temp dir.
    for handle in &outcome.handles {
        let _ = backend.stop(handle).await;
    }
    let _ = std::fs::remove_dir_all(&data_dir);

    outcome
        .result
        .expect("single-mode volume isolation assertions");

    // The single success marker the capability gate greps for. Printed ONLY after every
    // assertion held (a silent skip returns before this line; a failed assertion returns an
    // Err inside `outcome` and `expect` panics before here).
    println!("SINGLE VOLUME ISOLATION OK: acme + globex on distinct volumes, each authenticates");
}

/// The assertion outcome plus every launched container handle, so the caller can tear the
/// containers down on either the success or the failure path.
struct Outcome {
    result: Result<(), String>,
    handles: Vec<boatramp_core::compute::InstanceHandle>,
}

/// Provision + launch + assert one tenant, accumulating the launched handle so the caller
/// can always clean it up. Returns `Err(reason)` on the first failed invariant (fail
/// closed); records the launched container's `data_dir`-relative volume dir for the
/// cross-tenant distinctness check.
async fn run_assertions(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    creds: &ManagedSqlCredentials,
    backend: &Arc<ContainerBackend>,
    data_dir: &std::path::Path,
) -> Outcome {
    let mut handles = Vec::new();
    let mut volume_dirs: Vec<(String, PathBuf)> = Vec::new();
    let binding = single_project_binding();

    for tenant in TENANTS {
        match provision_and_launch_tenant(
            deploy, kv, envelope, creds, backend, data_dir, &binding, tenant,
        )
        .await
        {
            Ok((handle, vol_dir)) => {
                handles.push(handle);
                volume_dirs.push((tenant.to_string(), vol_dir));
            }
            Err(e) => {
                return Outcome {
                    result: Err(format!("tenant {tenant}: {e}")),
                    handles,
                };
            }
        }
    }

    // === Assertion 3 (NO COLLISION): the two non-default Single tenants landed on DISTINCT
    // volume dirs. The real failure mode was two tenants sharing one `"data"` volume; each
    // authenticating (proved per-tenant above) plus distinct dirs here is the isolation the
    // fixed key provides. ===
    let result = (|| {
        let [(a_name, a_dir), (b_name, b_dir)] = volume_dirs.as_slice() else {
            return Err(format!(
                "expected {} tenants, got {}",
                TENANTS.len(),
                volume_dirs.len()
            ));
        };
        if a_dir == b_dir {
            return Err(format!(
                "CROSS-TENANT VOLUME COLLISION: {a_name} and {b_name} share the volume dir {a_dir:?}"
            ));
        }
        eprintln!("distinct volumes: {a_name} -> {a_dir:?}  !=  {b_name} -> {b_dir:?}  OK");
        Ok(())
    })();

    Outcome { result, handles }
}

/// Provision (shipped path) + launch + assert one non-default `Single` tenant. Returns the
/// launched container handle (for teardown) and its host-side volume dir (for the
/// cross-tenant distinctness check). Fails closed on the first broken invariant.
#[allow(clippy::too_many_arguments)]
async fn provision_and_launch_tenant(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    creds: &ManagedSqlCredentials,
    backend: &Arc<ContainerBackend>,
    data_dir: &std::path::Path,
    binding: &ExternalDatabaseConfig,
    tenant: &str,
) -> Result<(boatramp_core::compute::InstanceHandle, PathBuf), String> {
    // --- Provision through the SHIPPED path: registers the tenant's dedicated compute
    // workload (with the per-tenant volume name — the fix) AND mints + seals the per-tenant
    // credential under `(tenant, workload)`. `site` is unused under Project scope; pass a
    // stable placeholder. Idempotent + fails closed.
    provision_tenant(deploy, kv, envelope, binding, tenant, "-")
        .await
        .map_err(|e| format!("provision: {e}"))?;

    // --- Read back the registered workload + its content-addressed spec, so every
    // assertion is against what `provision_tenant` ACTUALLY registered (not a hand-rolled
    // copy). The Single workload lives under the tenant's OWN project.
    let proj = ProjectRef::new(tenant);
    let workload = deploy
        .get_compute_workload(proj, &single_workload_name(tenant))
        .await
        .map_err(|e| format!("read workload: {e}"))?
        .ok_or_else(|| "provision did not register the per-tenant Single workload".to_string())?;
    let mut spec = deploy
        .get_compute_spec(&workload.active)
        .await
        .map_err(|e| format!("read spec: {e}"))?
        .ok_or_else(|| "workload's active spec is missing".to_string())?;

    // === Assertion 1 (ISOLATED VOLUME): the registered spec's data volume is keyed to the
    // per-tenant workload, NOT the shared `"data"` the pre-v0.3.11 bug used. ===
    let vol = spec
        .volumes
        .first()
        .ok_or_else(|| "managed Single spec must carry a data volume".to_string())?;
    if vol.name != workload.name {
        return Err(format!(
            "volume name {:?} is not keyed to the per-tenant workload {:?} (the v0.3.11 fix)",
            vol.name, workload.name
        ));
    }
    if vol.name == SHARED_VOLUME_BUG_NAME {
        return Err(format!(
            "volume name is the shared {SHARED_VOLUME_BUG_NAME:?} — the pre-v0.3.11 bug where \
             every tenant mounts the SAME PGDATA"
        ));
    }
    // The host-side backing dir the backend keys by name: `<data_dir>/compute/volumes/<name>`.
    let vol_dir = data_dir.join("compute").join("volumes").join(&vol.name);
    eprintln!(
        "[{tenant}] workload={:?} volume-name={:?} -> {vol_dir:?}  (not {SHARED_VOLUME_BUG_NAME:?})  OK",
        workload.name, vol.name
    );

    // --- Launch the tenant's dedicated container from ITS spec. Mirror the reconcile's
    // launch: the shared `managed_db_spec` synthesizer already shaped `spec` (via
    // provision), so apply the rootless privilege directive + inject the server-init env
    // (`POSTGRES_*`) from the per-tenant sealed credential exactly as
    // `managed_db_server_env(Postgres, DATABASE, APP_USER, tenant_pw)` does — so the
    // container `initdb`s the APP user with EXACTLY the credential the resolver will present.
    let tenant_pw = creds
        .password(tenant, &workload.name)
        .await
        .map_err(|e| format!("resolve per-tenant credential: {e}"))?;
    PrivilegeDirective::Rootless { uid: 999, gid: 999 }.apply(&mut spec);
    spec.env
        .insert("POSTGRES_USER".to_string(), APP_USER.to_string());
    spec.env
        .insert("POSTGRES_PASSWORD".to_string(), tenant_pw.clone());
    spec.env
        .insert("POSTGRES_DB".to_string(), DATABASE.to_string());

    let artifact = backend
        .materialize(&spec)
        .await
        .map_err(|e| format!("materialize (pull) image: {e}"))?;
    if !matches!(artifact, Artifact::Rootfs { .. }) {
        return Err("expected a rootfs artifact from the image pull".to_string());
    }

    // Persist the spec the backend just staged, so `DeployEndpointResolver` (project =
    // the tenant, workload = `pg-<ident>`) later resolves the endpoint the resolver connects
    // to. (The workload already points at this spec hash from `provision_tenant`.)
    let _ = deploy
        .put_compute_spec(&spec)
        .await
        .map_err(|e| format!("store staged spec: {e}"))?;

    let req = LaunchRequest {
        workload: workload.name.clone(),
        replica: 0,
        spec,
        artifact,
    };
    let inst = backend
        .launch(&req)
        .await
        .map_err(|e| format!("launch container: {e}"))?;
    let handle = inst.handle.clone();
    let host = inst.endpoint.host.clone();
    let port = inst.endpoint.port;
    eprintln!("[{tenant}] == dedicated pgvector launched == endpoint={host}:{port}");

    // The backend created the per-tenant volume dir at stage time; assert it exists on disk
    // (the v0.3.11 fix's on-disk half — a real, per-tenant PGDATA dir).
    if !vol_dir.is_dir() {
        return Err(format!(
            "the per-tenant volume backing dir {vol_dir:?} was not created on disk"
        ));
    }

    // Publish a healthy, Running replica pointing at the launched container's endpoint,
    // under the TENANT's project (Single per-tenant workloads live under the request's
    // project), so `DeployEndpointResolver` resolves `pg-<ident>` → host:port — the same
    // `ObservedInstance` the reconcile's `launch_one` builds.
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
        .set_replica_state(ProjectRef::new(tenant), &observed)
        .await
        .map_err(|e| format!("publish replica state: {e}"))?;

    // === Assertion 2 (FRESH INITDB + MATCHING CREDENTIAL — the core): connect through the
    // SHIPPED resolved backend for this tenant and run `SELECT current_user`. It must
    // SUCCEED — proving the container `initdb`'d the app role with the per-tenant credential
    // on its FRESH volume and the app authenticates. Before the v0.3.11 fix a non-default
    // Single container reused another workload's `"data"` dir, skipped initdb, and this
    // failed with "password authentication failed for user". ===
    let backend_for_tenant = resolve_tenant_backend(deploy, kv, envelope, binding, tenant)
        .await
        .map_err(|e| format!("resolve shipped backend: {e}"))?;

    // Poll: a first-boot `initdb` takes a while; the resolver connect fails fast until the
    // server is up + accepting the app credential. ~60 s budget.
    let current_user = wait_for_authenticated_query(&backend_for_tenant).await?;
    if current_user != APP_USER {
        return Err(format!(
            "authenticated, but current_user was {current_user:?}, expected {APP_USER:?}"
        ));
    }
    eprintln!(
        "[{tenant}] resolved-backend SELECT current_user = {current_user:?}  (authenticated)  OK"
    );

    Ok((handle, vol_dir))
}

/// The dedicated per-tenant `Single` workload name for `tenant` — `<COMPUTE>-<ident>`, the
/// derivation `provision_tenant` uses (and the volume name the fix keys the data dir to).
fn single_workload_name(tenant: &str) -> String {
    format!(
        "{COMPUTE}-{}",
        boatramp_storage::tenant_provision::sanitize_ident(tenant)
    )
}

/// Build the REAL data-plane backend the shipped resolver hands a request for `tenant`,
/// through [`NodeTenantSqlResolver`]. Uses `build_backend`-equivalent behavior: `resolve`
/// lazily re-provisions (idempotent) then connects as the app user with the per-tenant
/// credential to the per-tenant server — the exact production seam, no hand-rolled backend.
async fn resolve_tenant_backend(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    binding: &ExternalDatabaseConfig,
    tenant: &str,
) -> Result<Arc<dyn SqlBackend>, String> {
    let resolver =
        NodeTenantSqlResolver::new(deploy.clone(), kv.clone(), envelope.clone(), binding)
            .ok_or_else(|| {
                "resolver should build for a compute-backed managed binding".to_string()
            })?;
    resolver
        .resolve(tenant, "-")
        .await
        .map_err(|e| format!("resolve: {e}"))
}

/// Poll `SELECT current_user` through the resolved backend until it answers (first-boot
/// `initdb` + our credential). ~60 s budget — matches the sibling gates' first-boot wait.
/// Returns the authenticated `current_user` text, or an `Err` describing the last failure
/// (so a genuine auth failure — the pre-fix symptom — is surfaced, not masked as a timeout).
async fn wait_for_authenticated_query(backend: &Arc<dyn SqlBackend>) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..120 {
        match backend.run_query("SELECT current_user").await {
            Ok(rows) => match rows.rows.first().and_then(|r| r.first()) {
                Some(SqlValue::Text(s)) => return Ok(s.clone()),
                other => {
                    last = format!("current_user was not text: {other:?}");
                }
            },
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!(
        "the resolved per-tenant backend never authenticated + answered `SELECT current_user` \
         within the budget (last: {last:?}) — the pre-v0.3.11 symptom was \"password \
         authentication failed\" because the Single container reused another workload's volume \
         and skipped initdb"
    ))
}
