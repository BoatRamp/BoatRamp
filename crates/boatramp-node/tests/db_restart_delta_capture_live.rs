//! **Live proof of the PLAN-sql-true-delta Stage 1b restart primitive** — Linux + root +
//! a bridge, **ignored by default**. Proves, on a REAL co-located Postgres container,
//! that:
//!
//! 1. Toggling `delta_capture` under the default `restart_policy: manual` STAGES the
//!    change — `restart_pending` flips `true`, but the LIVE container is left
//!    untouched (still running, still the OLD launch argv — `wal_level=replica`).
//! 2. An explicit `boatramp db restart` (here, `ManagedDbDeclare::restart` directly)
//!    adopts the staged change: the workload's active spec rolls to the new one (now
//!    carrying `wal_level=logical`), and the REAL relaunched server actually reports
//!    `wal_level = logical` — not just the stored spec. `restart_pending` clears.
//! 3. Flipping `delta_capture` back off under `restart_policy: auto` applies it
//!    IMMEDIATELY on `declare` itself (no explicit restart call needed): the running
//!    replica's state is dropped right there, and the next relaunch reports
//!    `wal_level = replica` again.
//!
//! This complements the in-engine unit tests in `managed_db_declare.rs` (which prove
//! the staging/pending bookkeeping against `NullStorage` + `MemoryKv`, no real
//! container) with the one thing those can't: that the primitive's remint actually
//! changes what the REAL Postgres server is running with.
//!
//! Prereqs + run command: identical to the sibling live gates (`single_reconcile_live`,
//! `single_volume_live`, `tenant_isolation_live`) — a `br-boatramp` bridge, root, and
//! `BOATRAMP_BIN` pointing at a built `boatramp` binary:
//! ```sh
//! sudo ip link add br-boatramp type bridge 2>/dev/null || true
//! sudo ip addr add 10.0.0.1/24 dev br-boatramp 2>/dev/null || true
//! sudo ip link set br-boatramp up
//! sudo -E BOATRAMP_BIN=target/debug/boatramp \
//!   cargo test -p boatramp-node --features sql-postgres \
//!   --test db_restart_delta_capture_live -- --ignored --test-threads=1 --nocapture
//! ```
//! Skips (passes) when `BOATRAMP_BIN` is absent — never fails on a dev box.
//!
//! Like the sibling live gates, the full reconcile *loop* is not spun up — this drives
//! the same primitives the loop/`ManagedDbDeclare::restart` use directly: the container
//! backend `materialize`/`launch`/`stop`, `NodeManagedDbDeclare::{declare,restart,
//! restart_pending}` (the ACTUAL code under test), and the `set_replica_state`/
//! `delete_replica_state` bookkeeping `launch_one`/`restart` perform. A manual relaunch
//! after `restart` stands in for the reconcile loop noticing the dropped replica state
//! and relaunching against the now-active spec — exactly as production does.

#![cfg(all(target_os = "linux", feature = "sql-postgres"))]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use boatramp_container::ContainerBackend;
use boatramp_core::compute::{
    ApplyDatabase, ApplyDatabaseKind, ApplyDatabaseScope, ApplyDatabaseSize, ApplyDatabaseTenant,
    Artifact, BackendRegistry, ComputeBackend, DbRestartPolicy, InstanceHandle, LaunchRequest,
    ObservedInstance, PrivilegeDirective, ReplicaPhase,
};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::project::ProjectRef;
use boatramp_core::sql::{ManagedDbDeclare, OperatorSql, SqlValue};
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use boatramp_node::managed_db_declare::{DeclareQuota, NodeManagedDbDeclare, lower};
use boatramp_node::managed_sql::{ManagedSqlCredentials, NodeOperatorSql};
use bytes::Bytes;
use futures::StreamExt;

/// Non-default project, so this gets a per-tenant-qualified derived workload (the
/// production shape) rather than the reserved default's plain names.
const PROJECT: &str = "s1btest";
/// The declared binding's name — the `{name}` segment of `boatramp db restart --db
/// <name>` / `POST /api/databases/{name}/restart`.
const DB_NAME: &str = "main";

/// A `Storage` that serves one on-disk blob for every key (unused on the Image path —
/// the pgvector pull is over HTTP — but `ContainerBackend::new` still wants a store).
/// Verbatim from the sibling live gates.
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

/// A reversible test "envelope" (NOT encryption) — the same test double the sibling
/// live gates use. Production uses a real KMS/local envelope with an identical
/// contract.
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

/// The declared `ApplyDatabase` under test: a dedicated (`Single`/`Project`) managed
/// Postgres binding, `delta_capture`/`restart_policy` set per the scenario step.
fn app_binding(delta_capture: bool, restart_policy: DbRestartPolicy) -> ApplyDatabase {
    ApplyDatabase {
        name: DB_NAME.to_string(),
        kind: ApplyDatabaseKind::Postgres,
        version: Some(16),
        extensions: vec![],
        size: ApplyDatabaseSize::Small,
        tenant: ApplyDatabaseTenant::Single,
        tenant_scope: ApplyDatabaseScope::Project,
        read_only: false,
        rls_session: false,
        tenant_guc: None,
        session_guc: None,
        tenant_all_marker: None,
        pool_max: None,
        // A short connect timeout so a misconfigured connection fails fast; a generous
        // startup grace for a first-boot `initdb`.
        connect_timeout_secs: Some(10),
        startup_grace_secs: Some(120),
        readiness_gate: Default::default(),
        delta_capture,
        restart_policy,
    }
}

/// The dedicated per-tenant `Single` workload name for `PROJECT` — the SAME derivation
/// `provision_single`/the restart primitive use for a DECLARED (`ApplyDatabase`/
/// `NodeManagedDbDeclare`) binding: `<derived_workload(project, name)>-<ident>`. Unlike
/// a node-STATIC binding (the sibling live gates' `single_project_binding`, which names
/// its own fixed `compute`), a declared binding's base `compute` is itself DERIVED
/// (`bramp-db-<hash>` — see `derived_workload`'s doc comment), so this must mirror that,
/// not a literal fixed name.
fn tenant_workload_name() -> String {
    let compute = boatramp_node::managed_db_declare::derived_workload(PROJECT, DB_NAME);
    format!(
        "{compute}-{}",
        boatramp_storage::tenant_provision::sanitize_ident(PROJECT)
    )
}

/// LIVE proof of the restart primitive. See the module header. Boots ONE dedicated
/// container, stages + adopts a `delta_capture` config change under `manual`, then
/// applies one under `auto` — checking the REAL server's `wal_level` at each step.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Linux + root + a bridge (privileged live seam); pulls pgvector, boots a container, relaunches it twice"]
async fn delta_capture_restart_primitive_live() {
    let Some(bin) = std::env::var_os("BOATRAMP_BIN") else {
        eprintln!(
            "db_restart_delta_capture_live: set BOATRAMP_BIN (root + a br-boatramp bridge) to \
             run; skipping (never fails on a dev box)"
        );
        return;
    };
    let bin = PathBuf::from(bin);
    let bridge = std::env::var("CONTAINER_BRIDGE").unwrap_or_else(|_| "br-boatramp".into());
    let subnet = std::env::var("CONTAINER_SUBNET").unwrap_or_else(|_| "10.0.0.0/24".into());

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn Storage> = Arc::new(FileBlob(Vec::new()));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);

    let data_dir =
        std::env::temp_dir().join(format!("boatramp-s1b-restart-{}", std::process::id()));
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
    let mut backends: BackendRegistry = BTreeMap::new();
    backends.insert(
        boatramp_core::compute::ComputeBackend::id(backend.as_ref()).to_string(),
        backend.clone() as Arc<dyn ComputeBackend>,
    );
    let cap = NodeManagedDbDeclare::new(
        BTreeMap::new(),
        deploy.clone(),
        kv.clone(),
        envelope.clone(),
        DeclareQuota::default(),
        backends,
    );

    // Run the assertions inside a closure so the launched container(s) + the temp dir
    // are torn down on either outcome.
    let outcome = run_assertions(&cap, &deploy, &kv, &envelope, &backend, &data_dir).await;

    for handle in &outcome.handles {
        let _ = backend.stop(handle).await;
    }
    let _ = std::fs::remove_dir_all(&data_dir);

    outcome
        .result
        .expect("db restart / delta_capture live assertions");

    // The single success marker the capability gate greps for.
    println!(
        "DB RESTART DELTA CAPTURE OK: manual stages pending (server untouched), explicit \
         restart adopts + the RELAUNCHED server reports wal_level=logical, auto applies \
         immediately on declare"
    );
}

struct Outcome {
    result: Result<(), String>,
    handles: Vec<InstanceHandle>,
}

async fn run_assertions(
    cap: &NodeManagedDbDeclare,
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    backend: &Arc<ContainerBackend>,
    data_dir: &std::path::Path,
) -> Outcome {
    let mut handles = Vec::new();
    let result = drive(cap, deploy, kv, envelope, backend, data_dir, &mut handles).await;
    Outcome { result, handles }
}

/// The scenario body (steps map to the module header's numbered proofs). Any launched
/// handle is pushed into `handles` immediately after a successful `launch`, so the
/// caller always tears it down even if a later assertion fails.
async fn drive(
    cap: &NodeManagedDbDeclare,
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    backend: &Arc<ContainerBackend>,
    data_dir: &std::path::Path,
    handles: &mut Vec<InstanceHandle>,
) -> Result<(), String> {
    let workload_name = tenant_workload_name();
    let operator = |db: &ApplyDatabase| {
        let cfg = lower(PROJECT, db);
        NodeOperatorSql::new(
            BTreeMap::from([(DB_NAME.to_string(), cfg)]),
            kv.clone(),
            Some(envelope.clone()),
            deploy.clone(),
        )
    };

    // --- Step 0: first-time declare (delta_capture OFF, the default `manual` policy).
    // `declare`'s eager `provision` registers the workload + mints the credential
    // (KV only — no container yet); launch it for real.
    cap.declare(
        PROJECT,
        DB_NAME,
        &app_binding(false, DbRestartPolicy::Manual),
    )
    .await
    .map_err(|e| format!("initial declare: {e}"))?;
    let h0 = launch_and_publish(deploy, envelope, kv, backend, data_dir, &workload_name)
        .await
        .map_err(|e| format!("initial launch: {e}"))?;
    handles.push(h0);

    let op_off = operator(&app_binding(false, DbRestartPolicy::Manual));
    let level0 = wait_for_sql(&op_off, "SHOW wal_level").await?;
    if !level0.eq_ignore_ascii_case("replica") {
        return Err(format!(
            "expected the freshly launched (delta_capture=false) server to report \
             wal_level=replica, got {level0:?}"
        ));
    }
    eprintln!("step 0: fresh launch reports wal_level={level0:?} (delta_capture off)  OK");

    // === Step 1 (MANUAL STAGES, SERVER UNTOUCHED): flip delta_capture under the
    // default `manual` policy. Persisted, but the LIVE container must be left running
    // unchanged — `restart_pending` flips true, `wal_level` on the REAL server stays
    // `replica`. ===
    let flipped = app_binding(true, DbRestartPolicy::Manual);
    cap.declare(PROJECT, DB_NAME, &flipped)
        .await
        .map_err(|e| format!("declare delta_capture=true (manual): {e}"))?;
    if !cap
        .restart_pending(PROJECT, DB_NAME)
        .await
        .map_err(|e| format!("restart_pending: {e}"))?
    {
        return Err("GATE: manual policy must STAGE the change as pending".to_string());
    }
    let op_on = operator(&flipped);
    let level1 = wait_for_sql(&op_on, "SHOW wal_level").await?;
    if !level1.eq_ignore_ascii_case("replica") {
        return Err(format!(
            "GATE: a MANUAL-staged config change must NOT touch the live server — expected it \
             to still report wal_level=replica, got {level1:?} (the server was relaunched \
             without an explicit restart)"
        ));
    }
    eprintln!(
        "step 1: manual-staged delta_capture=true is pending, live server UNTOUCHED \
         (wal_level={level1:?})  OK"
    );

    // === Step 2 (EXPLICIT RESTART ADOPTS IT): stop the old replica + roll the active
    // spec (`ManagedDbDeclare::restart`), then relaunch (standing in for the reconcile
    // loop noticing the dropped replica state) — the RELAUNCHED server must report
    // wal_level=logical, and `restart_pending` must clear. ===
    let restart_outcome = cap
        .restart(PROJECT, DB_NAME)
        .await
        .map_err(|e| format!("restart: {e}"))?;
    if !restart_outcome.config_applied {
        return Err(
            "GATE: restart must report config_applied=true (it adopted the staged \
                     delta_capture flip)"
                .to_string(),
        );
    }
    // A brief settle so the stop (cgroup kill + veth teardown) completes before the
    // relaunch reuses the single test bridge.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let h1 = launch_and_publish(deploy, envelope, kv, backend, data_dir, &workload_name)
        .await
        .map_err(|e| format!("relaunch after restart: {e}"))?;
    handles.push(h1);

    let level2 = wait_for_sql(&op_on, "SHOW wal_level").await?;
    if !level2.eq_ignore_ascii_case("logical") {
        return Err(format!(
            "GATE: after `restart` adopted a `delta_capture=true` flip + a relaunch, the \
             server must report wal_level=logical, got {level2:?}"
        ));
    }
    if cap
        .restart_pending(PROJECT, DB_NAME)
        .await
        .map_err(|e| format!("restart_pending after restart: {e}"))?
    {
        return Err("GATE: restart_pending must clear once `restart` adopted the change".into());
    }
    eprintln!(
        "step 2: explicit restart adopted the staged change — RELAUNCHED server reports \
         wal_level={level2:?}, restart_pending cleared  OK"
    );

    // === Step 3 (AUTO APPLIES IMMEDIATELY ON DECLARE): flip delta_capture back OFF
    // under `restart_policy: auto`. `declare` itself must stop the current replica (no
    // explicit `restart` call) — a relaunch then reports wal_level=replica again, and
    // `restart_pending` never observes it as pending. ===
    let off_auto = app_binding(false, DbRestartPolicy::Auto);
    cap.declare(PROJECT, DB_NAME, &off_auto)
        .await
        .map_err(|e| format!("declare delta_capture=false (auto): {e}"))?;
    if cap
        .restart_pending(PROJECT, DB_NAME)
        .await
        .map_err(|e| format!("restart_pending after auto declare: {e}"))?
    {
        return Err(
            "GATE: restart_policy=auto must apply a pending change ON declare, leaving nothing \
             pending"
                .into(),
        );
    }
    let prior = handles.pop().expect("the restarted replica is present");
    // `declare`'s auto hook already stopped it and dropped its replica state; `stop` is
    // idempotent, so calling it again here is a harmless, defensive no-op cleanup.
    let _ = backend.stop(&prior).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let h2 = launch_and_publish(deploy, envelope, kv, backend, data_dir, &workload_name)
        .await
        .map_err(|e| format!("relaunch after auto apply: {e}"))?;
    handles.push(h2);

    let op_off2 = operator(&off_auto);
    let level3 = wait_for_sql(&op_off2, "SHOW wal_level").await?;
    if !level3.eq_ignore_ascii_case("replica") {
        return Err(format!(
            "GATE: after an AUTO-applied delta_capture=false flip + a relaunch, the server must \
             report wal_level=replica again, got {level3:?}"
        ));
    }
    eprintln!(
        "step 3: auto-applied delta_capture=false on declare (no explicit restart) — \
         RELAUNCHED server reports wal_level={level3:?}  OK"
    );

    Ok(())
}

/// Poll an operator-SQL query until it answers. ~60s budget (a relaunched server may
/// still be warming). Returns the first row's first column as text, or an `Err`
/// describing the last failure.
async fn wait_for_sql(operator: &NodeOperatorSql, sql: &str) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..120 {
        match operator.query(PROJECT, DB_NAME, sql).await {
            Ok(rows) => match rows.rows.first().and_then(|r| r.first()) {
                Some(SqlValue::Text(s)) => return Ok(s.clone()),
                other => last = format!("unexpected row shape for {sql:?}: {other:?}"),
            },
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!(
        "the operator path never answered {sql:?} within the budget (last: {last:?})"
    ))
}

/// Read back the registered workload's active spec, launch its dedicated container
/// (the reconcile's launch), publish a healthy Running replica so `restart` (and the
/// operator path) can find + reach it, and return the launched handle. Mirrors
/// `single_reconcile_live.rs`'s `launch_from_registered_spec`.
async fn launch_and_publish(
    deploy: &DeployStore,
    envelope: &Arc<dyn KeyEnvelope>,
    kv: &Arc<dyn KvStore>,
    backend: &Arc<ContainerBackend>,
    data_dir: &std::path::Path,
    workload_name: &str,
) -> Result<InstanceHandle, String> {
    let proj = ProjectRef::new(PROJECT);
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());
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

    // The per-tenant credential — keyed under the workload's OWN `(project, workload)`,
    // the production server-init key — so both a fresh `initdb` and a relaunch present
    // the SAME credential.
    let tenant_pw = creds
        .password(PROJECT, workload_name)
        .await
        .map_err(|e| format!("resolve per-tenant credential: {e}"))?;
    // `lower()` sets BOTH `database` and `user` to the declared binding's own `name`
    // (`DB_NAME`) for a declared binding — mirror that exactly, so the container
    // `initdb`s the SAME role/database the operator-SQL seam connects as.
    PrivilegeDirective::Rootless { uid: 999, gid: 999 }.apply(&mut spec);
    spec.env
        .insert("POSTGRES_USER".to_string(), DB_NAME.to_string());
    spec.env.insert("POSTGRES_PASSWORD".to_string(), tenant_pw);
    spec.env
        .insert("POSTGRES_DB".to_string(), DB_NAME.to_string());

    let artifact = backend
        .materialize("default", &workload.name, &spec)
        .await
        .map_err(|e| format!("materialize (pull) image: {e}"))?;
    if !matches!(artifact, Artifact::Rootfs { .. }) {
        return Err("expected a rootfs artifact from the image pull".to_string());
    }
    // Persist the staged spec (the rootless privilege directive + launch env) so the
    // next read-back/relaunch sees the same materialized shape.
    deploy
        .put_compute_spec(&spec)
        .await
        .map_err(|e| format!("store staged spec: {e}"))?;

    // The per-workload volume dir, so the caller can confirm the SAME on-disk data
    // persists across a stop + relaunch (the restart primitive reattaches it, never
    // recreates it).
    let vol_name = spec
        .volumes
        .first()
        .map(|v| v.name.clone())
        .ok_or_else(|| "managed Single spec must carry a data volume".to_string())?;
    let scope = boatramp_core::compute::compute_volume_scope("default", &workload.name);
    let vol_dir = data_dir
        .join("compute")
        .join("volumes")
        .join(format!("@{scope}"))
        .join(&vol_name);

    let req = LaunchRequest {
        project: "default".into(),
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
    eprintln!(
        "[{PROJECT}] launched {workload_name} @ {}:{}",
        inst.endpoint.host, inst.endpoint.port
    );
    if !vol_dir.is_dir() {
        return Err(format!(
            "the per-tenant volume backing dir {vol_dir:?} was not created on disk"
        ));
    }

    // Publish a healthy, Running replica — the SAME `ObservedInstance` `launch_one`
    // builds — under the REAL project, so `restart` (and the operator resolver) can
    // find + reach it.
    let observed = ObservedInstance {
        handle: inst.handle.clone(),
        node: 0,
        backend: ComputeBackend::id(backend.as_ref()).to_string(),
        endpoint: inst.endpoint.clone(),
        region: None,
        healthy: true,
        started_at: None,
        phase: ReplicaPhase::Running,
        readiness: boatramp_core::compute::Readiness::Provisioned,
        data_dir: None,
        snapshot: None,
    };
    deploy
        .set_replica_state(proj, &observed)
        .await
        .map_err(|e| format!("publish replica state: {e}"))?;
    Ok(handle)
}
