//! **The docker-backend analog of [`single_reconcile_live`]'s Assertion 5** — the live
//! proof, on a REAL Docker daemon, that the managed-DB re-provision papercut fix reclaims
//! a dropped `Single` tenant's data volume on the **remote-Docker** `ComputeBackend` too,
//! so a same-name re-provision `initdb`s afresh against its NEW credential instead of
//! silently re-attaching the dropped DB's stale, OLD-credential volume.
//!
//! ## Why a docker-specific gate (the owner's "green on BOTH a native-container AND a
//! docker node" requirement)
//!
//! The native-container gate [`single_reconcile_live`] proves the WHOLE lifecycle
//! (provision → launch → resolve+authenticate → drop → reclaim → re-provision →
//! authenticate) — but it is native-container-only *by construction*: its Assertion 5
//! asserts the **SCOPED** on-disk PGDATA dir (`<data_dir>/compute/volumes/@<scope>/…`,
//! reclaimed by `remove_scoped_volume`) is gone. The remote-Docker backend uses a
//! completely different, **FLAT** volume layout — a daemon-managed named volume
//! `boatramp-<workload>` (`DockerVolumeMode::Named`, the production default) reclaimed by
//! `remove_volume`, NOT the scoped `@`-dir. Those two reclaim surfaces are independent
//! code paths (the drop's `SingleDrop` arm calls BOTH; each backend no-ops on the layout
//! it does not own), and the papercut bug was *first observed on docker*: a `db drop
//! database` left the named volume behind, so re-provisioning a managed Postgres of the
//! same name re-attached a cluster `initdb`-ed with the OLD credential and every
//! connection failed `password authentication failed … data volume was initialized with a
//! different credential`.
//!
//! `remove_volume` / `list_volumes` were ADDED to the docker backend by that fix (it had
//! neither — `compute volume rm` + `GET /api/compute/volumes` previously no-op'd against
//! docker), so the docker reclaim is genuinely NEW runtime behavior that no live gate
//! exercised end-to-end. This test closes that gap: it drives the SHIPPED
//! [`deprovision_tenant`] drop with a **docker** backend registry and proves the named
//! volume is reclaimed and a same-name re-provision authenticates with a FRESH credential.
//!
//! ## What this gate asserts (live, on a real Docker daemon)
//!
//! For a **non-default** `exampleorg` project, `Single`/`Project`-scope binding, backed by
//! the remote-Docker `ComputeBackend` (default `Published` endpoint + `Named` volume):
//!
//! 1. **One workload, no split:** exactly ONE managed workload `pg-<ident>` under
//!    `exampleorg`, NONE (`pg`) under `default`.
//! 2. **Reachable + authenticates:** through the SHIPPED [`NodeTenantSqlResolver::resolve`]
//!    backend, `SELECT current_user` returns the tenant user — the lazily-provisioned
//!    docker container became reachable (on its published host-loopback port) and the
//!    credential it was `initdb`'d with authenticates.
//! 3. **Drop reclaims the Named volume + a re-provision initializes fresh (the papercut,
//!    docker layout):** the dropped DB's docker named volume `boatramp-<workload>` EXISTS
//!    before the drop (via `list_volumes`); drive the SHIPPED drop
//!    ([`deprovision_tenant`] with a docker backend registry) — it stops + removes the
//!    container, then reclaims the FLAT named volume via `remove_volume` — so
//!    `list_volumes` no longer reports it and the workload desired-state is gone; then
//!    re-provision the same tenant (mints a NEW credential), relaunch (fresh `initdb` on
//!    a now-empty named volume), and prove the SHIPPED resolver authenticates with the NEW
//!    credential live (no stale-volume "password authentication failed" re-provision
//!    failure).
//! 4. Print the success markers only after every assertion held.
//!
//! Every connection goes through boatramp's own Postgres backend (sqlx) exactly as
//! [`single_reconcile_live`] does — no host `psql`. The docker `Published` endpoint binds
//! the container's `5432` on `127.0.0.1:<ephemeral>` (host-loopback), so `serve`-on-the-
//! host (this test process) reaches it directly on Linux.
//!
//! Env-gated (needs a reachable Docker daemon): skips (passes) when `BOATRAMP_TEST_DOCKER`
//! is unset — never fails on a dev box. Run (NO root needed; docker is the isolation):
//! ```sh
//! BOATRAMP_TEST_DOCKER=1 cargo test -p boatramp-node --features sql-postgres \
//!   --test single_reconcile_docker_live -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! [`single_reconcile_live`]: single_reconcile_live
//! [`NodeTenantSqlResolver::resolve`]: boatramp_node::tenant_sql

#![cfg(all(target_os = "linux", feature = "sql-postgres"))]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use boatramp_core::compute::{
    Artifact, BackendRegistry, ComputeBackend, InstanceHandle, LaunchRequest, ObservedInstance,
    PrivilegeDirective, ReplicaPhase,
};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::project::ProjectRef;
use boatramp_core::sql::{SqlBackend, SqlValue};
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use boatramp_docker::DockerBackend;
use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
use boatramp_node::managed_sql::ManagedSqlCredentials;
use boatramp_node::tenant_sql::{NodeTenantSqlResolver, deprovision_tenant, provision_tenant};
use boatramp_storage::sql_sqlx::PerTenantSqlResolver;
use bytes::Bytes;
use futures::StreamExt;

const COMPUTE: &str = "pg";
const DATABASE: &str = "appdb";
const APP_USER: &str = "app";
const TENANT: &str = "exampleorg";
const SITE: &str = "app";

/// A `Storage` serving one in-memory blob for every key (the docker pull is over the
/// daemon, not the blob store, but `ContainerBackend::new`-style constructors want one;
/// the docker backend here needs none, so this is only wired into `DeployStore`).
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

/// The same reversible test "envelope" (NOT encryption) the sibling live gates use.
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

/// The `Single` / `Project`-grain binding under test — identical to the native gate's, so
/// the SAME shipped provision/resolve/drop code runs; only the compute backend differs.
fn single_project_binding() -> ExternalDatabaseConfig {
    ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DATABASE.into()),
        user: Some(APP_USER.into()),
        tenant: TenantIsolation::Single,
        tenant_scope: TenantScope::Project,
        connect_timeout_secs: Some(10),
        startup_grace_secs: Some(120),
        ..Default::default()
    }
}

fn tenant_workload_name() -> String {
    format!(
        "{COMPUTE}-{}",
        boatramp_storage::tenant_provision::sanitize_ident(TENANT)
    )
}

async fn seed_project_with_site(deploy: &DeployStore, kv: &Arc<dyn KvStore>) {
    deploy
        .put_project(&boatramp_core::project::Project {
            version: 1,
            name: TENANT.to_string(),
            created_at: 0,
            meta: Default::default(),
            config: Default::default(),
            secrets_ref: None,
        })
        .await
        .expect("seed the project pointer");
    let key = format!("project/{TENANT}/current/{SITE}");
    kv.put(&key, b"deadbeef".to_vec())
        .await
        .expect("seed a current site deployment pointer");
}

/// LIVE docker-backend managed-DB re-provision papercut proof. See the module header.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a reachable Docker daemon (privileged live seam); pulls pgvector, launches a container. Set BOATRAMP_TEST_DOCKER=1 and run with --ignored"]
async fn docker_single_tenant_drop_reclaims_volume_and_reprovision_authenticates() {
    if std::env::var_os("BOATRAMP_TEST_DOCKER").is_none() {
        eprintln!(
            "single_reconcile_docker_live: set BOATRAMP_TEST_DOCKER=1 (needs a reachable Docker \
             daemon) to run; skipping (never fails on a dev box)"
        );
        return;
    }

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn Storage> = Arc::new(FileBlob(Vec::new()));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());

    // The remote-Docker backend with production defaults: `Published` endpoint (the
    // container port on `127.0.0.1:<ephemeral>`, host-reachable) + `Named` volume mode
    // (the daemon volume `boatramp-<workload>` the drop reclaims via `remove_volume`).
    let backend: Arc<dyn ComputeBackend> =
        Arc::new(DockerBackend::connect().expect("connect to the docker daemon"));

    // Run the body inside a closure so the launched container(s) + the named volume are
    // always torn down (a leaked `boatramp-<workload>` named volume on a shared daemon is
    // exactly the orphan this fix avoids). The outcome is unwrapped AFTER cleanup, so a
    // failed assertion still stops before the success marker (the gate greps the marker).
    let outcome = run_assertions(&deploy, &kv, &envelope, &creds, &backend).await;

    let workload = tenant_workload_name();
    for handle in &outcome.handles {
        let _ = backend.stop(handle).await;
    }
    // Reclaim the named volume on either outcome (idempotent; `Ok(false)` if already gone).
    let _ = backend.remove_volume(&workload).await;

    outcome
        .result
        .expect("docker-backend managed-DB re-provision papercut assertions");

    println!(
        "DOCKER SINGLE RECONCILE OK: one tenant workload on the docker backend, reachable, \
         resolver authenticates with the initdb'd credential"
    );
    println!(
        "DOCKER SINGLE REPROVISION OK: the drop reclaimed the FLAT docker named volume; a \
         same-name re-provision initialized fresh and authenticates with its NEW credential \
         (no stale-volume failure)"
    );
}

struct Outcome {
    result: Result<(), String>,
    handles: Vec<InstanceHandle>,
}

async fn run_assertions(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    creds: &ManagedSqlCredentials,
    backend: &Arc<dyn ComputeBackend>,
) -> Outcome {
    let mut handles = Vec::new();
    let result = drive(deploy, kv, envelope, creds, backend, &mut handles).await;
    Outcome { result, handles }
}

async fn drive(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    creds: &ManagedSqlCredentials,
    backend: &Arc<dyn ComputeBackend>,
    handles: &mut Vec<InstanceHandle>,
) -> Result<(), String> {
    let binding = single_project_binding();
    let workload_name = tenant_workload_name();
    let proj = ProjectRef::new(TENANT);

    seed_project_with_site(deploy, kv).await;
    provision_tenant(deploy, kv, envelope, &binding, TENANT, "")
        .await
        .map_err(|e| format!("provision_tenant: {e}"))?;

    // === Assertion 1: exactly ONE managed workload for the tenant, NONE under default. ===
    let tenant_workloads = deploy
        .list_compute_workloads(proj)
        .await
        .map_err(|e| format!("list tenant workloads: {e}"))?;
    if tenant_workloads.len() != 1 || tenant_workloads[0].name != workload_name {
        return Err(format!(
            "expected exactly ONE workload {workload_name:?} under {TENANT:?}, found {:?}",
            tenant_workloads.iter().map(|w| &w.name).collect::<Vec<_>>()
        ));
    }
    let default_workloads = deploy
        .list_compute_workloads(ProjectRef::DEFAULT)
        .await
        .map_err(|e| format!("list default workloads: {e}"))?;
    if default_workloads.iter().any(|w| w.name == COMPUTE) {
        return Err("a tenant-blind bare `pg` workload exists under `default`".to_string());
    }
    eprintln!("assertion 1: one workload {workload_name:?} under {TENANT:?}  OK");

    // --- Launch the tenant's dedicated docker container from the registered spec, with
    // the per-tenant sealed credential injected as the server-init env (so the container
    // `initdb`s the APP user with EXACTLY the credential the resolver will present).
    let handle = launch_from_registered_spec(deploy, creds, backend, &workload_name).await?;
    handles.push(handle);

    // === Assertion 2: the SHIPPED resolver authenticates (reachable on the published
    // host-loopback port, credential the container was initdb'd with). ===
    let resolved = resolve_tenant_backend(deploy, kv, envelope, &binding).await?;
    let user_before = wait_for_authenticated_query(&resolved).await?;
    if user_before != APP_USER {
        return Err(format!(
            "authenticated, but current_user was {user_before:?}, expected {APP_USER:?}"
        ));
    }
    let old_pw = creds
        .password(TENANT, &workload_name)
        .await
        .map_err(|e| format!("read the pre-drop credential: {e}"))?;
    eprintln!("assertion 2: resolver SELECT current_user = {user_before:?} (reachable)  OK");

    // === Assertion 3 (THE PAPERCUT, docker FLAT layout): the dropped DB's docker named
    // volume must be reclaimed by `remove_volume` so a same-name re-provision `initdb`s
    // afresh. ===
    // Pre-check: the backend reports the named volume `boatramp-<workload>` (listed under
    // its boatramp name — the `boatramp-` prefix stripped), proving it was staged.
    if !backend_lists_volume(backend, &workload_name).await? {
        return Err(format!(
            "pre-drop: the docker backend should list the tenant's named volume \
             {workload_name:?} (it was staged at launch)"
        ));
    }

    // Drive the SHIPPED drop with a registry holding THIS docker backend, so the FLAT
    // `remove_volume` reclaim actually fires. grace=0 ⇒ immediate SingleDrop. The drop
    // stops + removes the container and reclaims the named volume; pop its handle.
    let dropped = handles
        .pop()
        .expect("a launched handle present before the drop");
    let mut reg: BackendRegistry = std::collections::BTreeMap::new();
    reg.insert(backend.id().to_string(), backend.clone());
    deprovision_tenant(deploy, kv, envelope, Some(&reg), &binding, TENANT, "", 0)
        .await
        .map_err(|e| format!("drop (deprovision_tenant): {e}"))?;
    let _ = &dropped; // its container was stopped + removed by the drop above

    // The named volume must be GONE — the stale-credential cluster can no longer be
    // re-attached (a docker backend without `remove_volume`, the pre-fix state, would
    // leave this listed).
    if backend_lists_volume(backend, &workload_name).await? {
        return Err(format!(
            "PAPERCUT: the drop left the docker named volume {workload_name:?} behind — a \
             same-name re-provision would re-attach the stale, old-credential cluster (the \
             docker backend's `remove_volume` reclaim did not fire)"
        ));
    }
    if deploy
        .get_compute_workload(proj, &workload_name)
        .await
        .map_err(|e| format!("re-check workload after drop: {e}"))?
        .is_some()
    {
        return Err("the drop did not remove the tenant's workload desired-state".to_string());
    }
    eprintln!("assertion 3a: drop reclaimed the FLAT docker named volume {workload_name:?}  OK");

    // Re-provision the SAME tenant: a FRESH credential (the drop deleted the old sealed one).
    provision_tenant(deploy, kv, envelope, &binding, TENANT, "")
        .await
        .map_err(|e| format!("re-provision after drop: {e}"))?;
    let new_pw = creds
        .password(TENANT, &workload_name)
        .await
        .map_err(|e| format!("read the re-provisioned credential: {e}"))?;
    if new_pw == old_pw {
        return Err("re-provision did not mint a NEW credential".to_string());
    }

    // Relaunch — the named volume was reclaimed, so the daemon stages a FRESH empty one and
    // the container `initdb`s against the NEW credential.
    let handle3 = launch_from_registered_spec(deploy, creds, backend, &workload_name).await?;
    handles.push(handle3);

    // The SHIPPED resolver must authenticate LIVE with the NEW credential.
    let resolved3 = resolve_tenant_backend(deploy, kv, envelope, &binding).await?;
    let user_reprov = wait_for_authenticated_query(&resolved3).await?;
    if user_reprov != APP_USER {
        return Err(format!(
            "after drop + re-provision, current_user was {user_reprov:?}, expected {APP_USER:?} \
             — a surviving stale named volume would fail auth here"
        ));
    }
    eprintln!(
        "assertion 3b: after drop + re-provision, SELECT current_user = {user_reprov:?} with a \
         FRESH credential (initdb took, no stale-volume auth failure)  OK"
    );

    Ok(())
}

/// Whether the docker backend's `list_volumes` reports a volume by its boatramp `name`
/// (the `boatramp-` daemon prefix stripped). `Unsupported` is a hard error here — this
/// gate requires the backend to own + list its FLAT volumes.
async fn backend_lists_volume(
    backend: &Arc<dyn ComputeBackend>,
    name: &str,
) -> Result<bool, String> {
    let vols = backend
        .list_volumes()
        .await
        .map_err(|e| format!("list_volumes: {e}"))?;
    Ok(vols.iter().any(|v| v.name == name))
}

/// Read back the registered workload's active spec, inject the per-tenant sealed
/// credential as the server-init env, launch the docker container, and publish a healthy
/// Running replica (pointing at the launched container's published endpoint) so
/// `DeployEndpointResolver` resolves `pg-<ident>` → host:port.
async fn launch_from_registered_spec(
    deploy: &DeployStore,
    creds: &ManagedSqlCredentials,
    backend: &Arc<dyn ComputeBackend>,
    workload_name: &str,
) -> Result<InstanceHandle, String> {
    let proj = ProjectRef::new(TENANT);
    let workload = deploy
        .get_compute_workload(proj, workload_name)
        .await
        .map_err(|e| format!("read workload: {e}"))?
        .ok_or_else(|| "the per-tenant Single workload is not registered".to_string())?;
    let mut spec = deploy
        .get_compute_spec(&workload.active)
        .await
        .map_err(|e| format!("read spec: {e}"))?
        .ok_or_else(|| "the workload's active spec is missing".to_string())?;

    let tenant_pw = creds
        .password(TENANT, workload_name)
        .await
        .map_err(|e| format!("resolve per-tenant credential: {e}"))?;
    // Apply the SAME rootless privilege directive production's reconcile applies to a
    // managed DB via `managed_db_privilege` (see `launch_one`): run the container as the
    // stock postgres image's uid 999. The docker backend's hardened posture drops
    // CAP_CHOWN/CAP_FOWNER, so the postgres entrypoint's root-path `chown`/`chmod` of
    // PGDATA fails (`Operation not permitted`, a crash loop) — but a fresh `Named` volume
    // inherits the image mount point's ownership (uid 999), and the entrypoint's non-root
    // path skips the chown and `initdb`s directly as 999. This is the production launch
    // path for a docker-backed managed DB, not a test-only workaround.
    PrivilegeDirective::Rootless { uid: 999, gid: 999 }.apply(&mut spec);
    spec.env
        .insert("POSTGRES_USER".to_string(), APP_USER.to_string());
    spec.env.insert("POSTGRES_PASSWORD".to_string(), tenant_pw);
    spec.env
        .insert("POSTGRES_DB".to_string(), DATABASE.to_string());

    let artifact = backend
        .materialize(TENANT, &workload.name, &spec, None)
        .await
        .map_err(|e| format!("materialize (pull) image: {e}"))?;
    if !matches!(artifact, Artifact::Image { .. }) {
        return Err("expected an image artifact from the docker pull".to_string());
    }
    deploy
        .put_compute_spec(&spec)
        .await
        .map_err(|e| format!("store staged spec: {e}"))?;

    let req = LaunchRequest {
        project: TENANT.into(),
        workload: workload.name.clone(),
        replica: 0,
        spec,
        artifact,
        redaction: Default::default(),
        priority_class: None,
    };
    let inst = backend
        .launch(&req)
        .await
        .map_err(|e| format!("launch container: {e}"))?;
    let handle = inst.handle.clone();
    eprintln!(
        "[{TENANT}] launched {workload_name} @ {}:{} (docker named volume boatramp-{workload_name})",
        inst.endpoint.host, inst.endpoint.port
    );

    let observed = ObservedInstance {
        handle: inst.handle.clone(),
        node: 0,
        backend: backend.id().to_string(),
        endpoint: inst.endpoint.clone(),
        region: None,
        healthy: true,
        started_at: None,
        phase: ReplicaPhase::Running,
        readiness: boatramp_core::compute::Readiness::Provisioned,
        data_dir: None,
        snapshot: None,
        active_spec: None,
    };
    deploy
        .set_replica_state(proj, &observed)
        .await
        .map_err(|e| format!("publish replica state: {e}"))?;
    Ok(handle)
}

/// Build the REAL data-plane backend the shipped resolver hands a request for `TENANT`,
/// through [`NodeTenantSqlResolver`] — the exact production seam.
async fn resolve_tenant_backend(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    binding: &ExternalDatabaseConfig,
) -> Result<Arc<dyn SqlBackend>, String> {
    let resolver =
        NodeTenantSqlResolver::new(deploy.clone(), kv.clone(), envelope.clone(), binding)
            .ok_or_else(|| {
                "resolver should build for a compute-backed managed binding".to_string()
            })?;
    resolver
        .resolve(TENANT, "-")
        .await
        .map_err(|e| format!("resolve: {e}"))
}

/// Poll `SELECT current_user` through a resolved backend until it answers. ~90 s budget (a
/// first-boot `initdb` + pull). Returns the authenticated `current_user`, or an `Err` with
/// the last failure (so a genuine auth failure — the pre-fix symptom — surfaces).
async fn wait_for_authenticated_query(backend: &Arc<dyn SqlBackend>) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..180 {
        match backend.run_query("SELECT current_user").await {
            Ok(rows) => match rows.rows.first().and_then(|r| r.first()) {
                Some(SqlValue::Text(s)) => return Ok(s.clone()),
                other => last = format!("current_user was not text: {other:?}"),
            },
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!(
        "the resolved per-tenant backend never authenticated + answered `SELECT current_user` \
         within the budget (last: {last:?})"
    ))
}
