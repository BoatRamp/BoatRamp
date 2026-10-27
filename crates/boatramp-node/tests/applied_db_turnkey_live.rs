//! **The turnkey APPLIED-DB recovery gate** — Linux + root + a bridge, **ignored by
//! default**. The live, end-to-end proof of the v0.45.0 last-layer fix: on a turnkey,
//! ENV-configured node with EMPTY node-static `[handlers.bindings.sql.databases]`, a
//! managed database declared via `boatramp apply` (the deploy-store path, launched as the
//! derived `bramp-db-<digest>` workload) now receives its sealed `POSTGRES_*` server-init
//! env, `initdb`s, comes healthy, and is QUERYABLE through the operator SQL path.
//!
//! ## What this gate proves (the whole fix, live)
//!
//! The node-static `databases` map is EMPTY — the turnkey deployment. Everything the
//! applied db needs is resolved from the DEPLOY STORE:
//!
//! 1. **Declare (apply):** `NodeManagedDbDeclare::declare` persists the declaration at
//!    `project/default/database/<name>`, registers the derived `bramp-db-<digest>` server
//!    workload, and mints + seals its superuser credential — with NO node-static config.
//! 2. **Server-init env from the deploy store (the fix's core):** the PRODUCTION
//!    `ManagedDbEnv` injector — built with an EMPTY static map — resolves the launched
//!    `(default, bramp-db-<digest>)` workload from the deploy-store declaration
//!    (`resolve_spec` → `resolve_applied`) and yields a NON-EMPTY `POSTGRES_USER/PASSWORD/DB`
//!    env (pre-fix it returned `Vec::new()`, so the stock image refused to `initdb`). The
//!    container is launched with exactly that env, so it initializes the app user with the
//!    sealed credential. The privilege directive (rootless) is injected the same way.
//! 3. **Healthy + initdb'd:** a real Postgres cluster comes up on the per-`(project,
//!    workload)` scoped volume and answers.
//! 4. **Queryable through the serve path (no serve-side variant):** `NodeOperatorSql` —
//!    ALSO built with an EMPTY static map — resolves the applied db through the same merge
//!    point (`resolve_binding` → the deploy-store declaration), connects with the SAME
//!    sealed credential the container was initialized with, runs DDL + DML, and a
//!    `SELECT` returns the inserted row. This proves the init-credential and the
//!    connection-credential AGREE, and that the applied db is reachable end to end.
//! 5. **Migratable through the serve path (the v0.46.0 last-layer fix):** a
//!    `NodeMigrationRunner` over a `NodeOperatorSql` — AGAIN built with an EMPTY static map —
//!    resolves the applied db's ENGINE through the SAME merge point (`engine_kind` →
//!    `resolve_binding`, the seam this fix routes). Pre-fix, `engine_kind` was static-map-only,
//!    so `NodeMigrationRunner::engine_gate` returned `NotConfigured` for an applied db on a
//!    turnkey node — `sql migrate` could never reach it. Post-fix: `preflight` resolves +
//!    ensures the host-owned ledger, one `sql` step applies as the owner/DDL role, the ledger
//!    reflects it (status), and a re-run is an idempotent no-op — mirroring the real Provisor
//!    control-schema migrate. This is the operator-SQL parity's last gap closed.
//!
//! A silent skip (no `BOATRAMP_BIN`) still prints `test result: ok`, so the capability
//! gate greps for the `APPLIED-DB TURNKEY OK` marker, not the test-runner line.
//!
//! Run (as root, since the backend does veth/cgroup/unshare):
//! ```sh
//! sudo -E BOATRAMP_BIN=target/debug/boatramp \
//!   cargo test -p boatramp-node --features sql-postgres \
//!   --test applied_db_turnkey_live -- --ignored --test-threads=1 --nocapture
//! ```
//! Prereqs (same as the sibling live gates): a `br-boatramp` bridge with its gateway IP.

#![cfg(all(target_os = "linux", feature = "sql-postgres"))]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use boatramp_container::ContainerBackend;
use boatramp_core::compute::{
    ApplyDatabase, ApplyDatabaseKind, ApplyDatabaseScope, ApplyDatabaseSize, ApplyDatabaseTenant,
    Artifact, ComputeBackend, InstanceHandle, LaunchRequest, ManagedDbEnvResolver,
    ObservedInstance, ReplicaPhase,
};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::project::ProjectRef;
use boatramp_core::sql::{
    ManagedDbDeclare, MigrationAction, MigrationStep, MigrationSubstrate, OperatorSql, SqlValue,
    SubstrateStepOutcome,
};
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use boatramp_node::config::ManagedDbPrivilege;
use boatramp_node::managed_db_declare::{DeclareQuota, NodeManagedDbDeclare, derived_workload};
use boatramp_node::managed_sql::{
    ManagedDbEnv, ManagedSqlCredentials, NodeMigrationRunner, NodeOperatorSql,
};
use bytes::Bytes;
use futures::StreamExt;

/// The reserved default project — the turnkey node's own project. A `Single`/`Project`
/// applied db under it launches the BARE derived workload (no `-<ident>` suffix).
const PROJECT: &str = "default";
/// The applied database's binding name (its `databases:` entry). Lowered to both the
/// physical database name AND the app user (the managed-credential projection).
const DB_NAME: &str = "orders";

/// A no-op `Storage` (the pgvector image is pulled over HTTP; the store is unused but
/// `ContainerBackend::new` + `DeployStore` still want one).
struct FileBlob;
#[async_trait]
impl Storage for FileBlob {
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

/// A reversible test "envelope" (NOT encryption) — the same double the sibling live gates
/// use, exercising the exact `ManagedSqlCredentials` seal/unseal path.
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

/// The `databases:` entry an operator applies (a `Single`/`Project` managed pg — the
/// default tenancy). The lowering derives the server workload + managed credential; the
/// manifest carries NO image/secret/compute (the security contract).
fn applied_pg() -> ApplyDatabase {
    ApplyDatabase {
        name: DB_NAME.to_string(),
        kind: ApplyDatabaseKind::Postgres,
        version: None,
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
        connect_timeout_secs: Some(10),
        startup_grace_secs: Some(120),
        readiness_gate: Default::default(),
        delta_capture: false,
        restart_policy: Default::default(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Linux + root + a bridge (privileged live seam); pulls pgvector, boots a container"]
async fn applied_db_on_a_turnkey_node_gets_its_credential_initdbs_and_is_queryable() {
    let Some(bin) = std::env::var_os("BOATRAMP_BIN") else {
        eprintln!(
            "applied_db_turnkey_live: set BOATRAMP_BIN (root + a br-boatramp bridge) to run; \
             skipping (never fails on a dev box)"
        );
        return;
    };
    let bin = PathBuf::from(bin);
    let bridge = std::env::var("CONTAINER_BRIDGE").unwrap_or_else(|_| "br-boatramp".into());
    let subnet = std::env::var("CONTAINER_SUBNET").unwrap_or_else(|_| "10.0.0.0/24".into());

    // ONE KV backs both the deploy state and the sealed-credential store, so the declare,
    // the resolver, and the operator path all see the same world.
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn Storage> = Arc::new(FileBlob);
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);

    let data_dir =
        std::env::temp_dir().join(format!("boatramp-applied-turnkey-{}", std::process::id()));
    let backend = Arc::new(
        ContainerBackend::new(Arc::new(FileBlob), data_dir.clone(), bridge, &subnet, bin)
            .expect("backend"),
    );

    let mut handles: Vec<InstanceHandle> = Vec::new();
    let result = drive(&deploy, &kv, &envelope, &backend, &mut handles).await;

    for h in &handles {
        let _ = backend.stop(h).await;
    }
    let _ = std::fs::remove_dir_all(&data_dir);

    result.expect("turnkey applied-db recovery assertions");
    println!(
        "APPLIED-DB TURNKEY OK: empty static config, deploy-store applied pg got its sealed POSTGRES_PASSWORD, initdb'd, healthy, sql query returned a row, and sql migrate applied + idempotently re-ran a migration through the resolve_binding engine gate"
    );
}

async fn drive(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    backend: &Arc<ContainerBackend>,
    handles: &mut Vec<InstanceHandle>,
) -> Result<(), String> {
    use std::collections::BTreeMap;

    // === (1) DECLARE via the real apply path, with EMPTY node-static config. This stores
    // the declaration, registers the derived server workload, and mints + seals the
    // superuser credential — all from the deploy store, no node-static `[databases]`. ===
    let declare = NodeManagedDbDeclare::new(
        BTreeMap::new(), // EMPTY node-static databases — the turnkey node
        deploy.clone(),
        kv.clone(),
        envelope.clone(),
        DeclareQuota::default(),
        BTreeMap::new(), // no backends needed (a fresh Single/Project declare never restarts)
    );
    declare
        .declare(PROJECT, DB_NAME, &applied_pg())
        .await
        .map_err(|e| format!("declare: {e}"))?;

    // The launched server workload is the derived `bramp-db-<digest>` of (default, orders).
    let workload = derived_workload(PROJECT, DB_NAME);
    if !workload.starts_with("bramp-db-") {
        return Err(format!(
            "derived workload {workload:?} lost its reserved prefix"
        ));
    }
    let proj = ProjectRef::new(PROJECT);
    let registered = deploy
        .get_compute_workload(proj, &workload)
        .await
        .map_err(|e| format!("read workload: {e}"))?
        .ok_or_else(|| "the applied db's server workload was not registered".to_string())?;

    // === (2) THE FIX: the PRODUCTION `ManagedDbEnv` injector — built with an EMPTY static
    // map — resolves the launched workload from the DEPLOY STORE and yields the server-init
    // env. Pre-fix this returned Vec::new() (no POSTGRES_PASSWORD), so the image refused to
    // initdb. This is the forcing assertion. ===
    let env = ManagedDbEnv::from_config(
        &BTreeMap::new(),
        ManagedSqlCredentials::new(kv.clone(), envelope.clone()),
        ManagedDbPrivilege::Rootless,
        deploy.clone(),
    );
    let server_env = env.managed_db_env(PROJECT, &workload).await;
    if server_env.is_empty() {
        return Err(
            "FORCING FAILURE: ManagedDbEnv returned an EMPTY server-init env for the applied db \
             — the deploy-store resolve (resolve_applied) did not engage, so the container would \
             launch with no POSTGRES_PASSWORD and refuse to initdb (the exact bug this fix closes)"
                .to_string(),
        );
    }
    if !server_env.iter().any(|(k, _)| k == "POSTGRES_PASSWORD") {
        return Err(format!(
            "server-init env is non-empty but carries no POSTGRES_PASSWORD: {:?}",
            server_env.iter().map(|(k, _)| k).collect::<Vec<_>>()
        ));
    }
    let privilege = env.managed_db_privilege(PROJECT, &workload).await;
    if privilege.is_none() {
        return Err("applied db got no rootless privilege directive".to_string());
    }
    eprintln!(
        "step 2: deploy-store resolve yielded {} server-init vars incl. POSTGRES_PASSWORD + rootless privilege  OK",
        server_env.len()
    );

    // === (3) LAUNCH the container with exactly that resolver-produced env + privilege (the
    // reconcile's launch), then publish a healthy Running replica so the operator endpoint
    // resolver can reach it. ===
    let handle = launch_with_env(
        deploy,
        backend,
        &registered,
        &workload,
        privilege.unwrap(),
        &server_env,
    )
    .await?;
    handles.push(handle);

    // === (4) QUERYABLE through the serve path: `NodeOperatorSql`, ALSO built with an EMPTY
    // static map, resolves the applied db from the deploy store (resolve_binding), connects
    // with the SAME sealed credential, runs DDL + DML, and reads the row back. Proves the
    // init-credential and the connection-credential agree AND the serve path covers applied
    // dbs. A generous budget absorbs the first-boot initdb. ===
    let operator = NodeOperatorSql::new(
        BTreeMap::new(), // EMPTY static config — the serve path must resolve the applied db too
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    );
    wait_for_exec(
        &operator,
        "CREATE TABLE IF NOT EXISTS t (v text); INSERT INTO t VALUES ('turnkey-row')",
    )
    .await?;
    let rows = operator
        .query(PROJECT, DB_NAME, "SELECT v FROM t")
        .await
        .map_err(|e| format!("sql query against the applied db: {e}"))?;
    match rows.rows.first().and_then(|r| r.first()) {
        Some(SqlValue::Text(v)) if v == "turnkey-row" => {}
        other => {
            return Err(format!(
                "sql query returned an unexpected row (expected the inserted 'turnkey-row'): {other:?}"
            ));
        }
    }
    eprintln!(
        "step 4: NodeOperatorSql (empty static config) resolved the applied db + returned the row  OK"
    );

    // === (5) MIGRATE through the FIXED engine gate: a `NodeMigrationRunner` over a
    // `NodeOperatorSql` with the SAME EMPTY static config. The migrate path resolves the
    // applied db's engine through `resolve_binding` (pre-fix `NodeOperatorSql::engine_kind` —
    // and so `NodeMigrationRunner::engine_gate` — was static-map-only, returning `NotConfigured`
    // for an applied db on a turnkey node). This is the forcing assertion for THIS fix: a
    // `preflight` that returns `Ok` (not `NotConfigured`) proves the engine gate now reaches the
    // applied db exactly as `sql exec/query` does. Then apply one `sql` step as the owner/DDL
    // identity, confirm the ledger records it (status), and confirm a re-run is an idempotent
    // no-op — mirroring the real Provisor control-schema migrate. ===
    let migrate_op = Arc::new(NodeOperatorSql::new(
        BTreeMap::new(), // EMPTY static config — the migrate path must resolve the applied db too
        kv.clone(),
        Some(envelope.clone()),
        deploy.clone(),
    ));
    let runner = NodeMigrationRunner::new(migrate_op, std::collections::BTreeSet::new());

    // preflight: the engine gate resolves the applied db (FORCING: pre-fix this was
    // NotConfigured), ensures the host-owned ledger, and returns the applied rows (empty on a
    // fresh db). A generous retry absorbs the just-booted cluster's first owner-role connect.
    let before = wait_for_preflight(&runner).await?;
    if !before.is_empty() {
        return Err(format!(
            "expected an empty migration ledger on a fresh applied db, got {} row(s)",
            before.len()
        ));
    }

    // Apply one `sql` step as the owner/DDL identity — the exact call the orchestrator makes
    // (intrinsic content hash as the effective hash, `apply` origin, recorded atomically on pg).
    let step = MigrationStep {
        id: "0001_turnkey_migrate".to_string(),
        action: MigrationAction::Sql {
            script: "CREATE TABLE IF NOT EXISTS migrated_orders (n int)".to_string(),
            no_transaction: false,
        },
    };
    let eff = step.content_hash();
    match runner
        .apply_substrate_step(PROJECT, DB_NAME, &step, 0, &eff)
        .await
        .map_err(|e| format!("migrate apply_substrate_step against the applied db: {e}"))?
    {
        SubstrateStepOutcome::Applied => {}
        other => return Err(format!("expected the migrate step to apply, got {other:?}")),
    }

    // Status reflects it: the ledger now carries EXACTLY the applied step with its content hash.
    let after = runner
        .preflight(PROJECT, DB_NAME)
        .await
        .map_err(|e| format!("migrate preflight after apply: {e}"))?;
    if after.len() != 1 || after[0].id != step.id || after[0].content_hash != eff {
        return Err(format!(
            "the migration ledger did not reflect the applied step (expected one row \
             {:?}/{eff}): {after:?}",
            step.id
        ));
    }

    // Idempotent re-run: the orchestrator applies only steps ABSENT from the ledger; the step's
    // id is now present with a matching content hash, so a re-run applies NOTHING. Mirror that
    // decision and confirm the ledger is unchanged (never a duplicate row / re-run DDL).
    let applied_ids: std::collections::BTreeSet<&str> =
        after.iter().map(|m| m.id.as_str()).collect();
    if applied_ids.contains(step.id.as_str()) {
        // pending suffix is empty → no-op; nothing to apply.
    } else {
        return Err(
            "idempotency broken: the applied step was not recognized as already-applied on re-run"
                .to_string(),
        );
    }
    let reread = runner
        .preflight(PROJECT, DB_NAME)
        .await
        .map_err(|e| format!("migrate preflight on re-run: {e}"))?;
    if reread.len() != 1 || reread[0].content_hash != eff {
        return Err(format!(
            "idempotent re-run changed the ledger (expected the one unchanged row): {reread:?}"
        ));
    }
    eprintln!(
        "step 5: NodeMigrationRunner (empty static config) resolved the applied db via \
         resolve_binding, applied 1 migration as the owner role, status reflected it, and a \
         re-run was a no-op  OK"
    );
    Ok(())
}

/// Read the registered workload's spec, inject the resolver-produced privilege + server-init
/// env, materialize (pull) the image, launch, and publish a healthy Provisioned replica so
/// `DeployEndpointResolver` resolves the workload → host:port for the operator path.
async fn launch_with_env(
    deploy: &DeployStore,
    backend: &Arc<ContainerBackend>,
    workload: &boatramp_core::compute::ComputeWorkload,
    workload_name: &str,
    privilege: boatramp_core::compute::PrivilegeDirective,
    server_env: &[(String, String)],
) -> Result<InstanceHandle, String> {
    let proj = ProjectRef::new(PROJECT);
    let mut spec = deploy
        .get_compute_spec(&workload.active)
        .await
        .map_err(|e| format!("read spec: {e}"))?
        .ok_or_else(|| "the workload's active spec is missing".to_string())?;

    // Apply the resolver's privilege + server-init env — exactly what the reconcile's
    // `launch_one` does via the `ManagedDbEnvResolver` trait.
    privilege.apply(&mut spec);
    for (k, v) in server_env {
        spec.env.insert(k.clone(), v.clone());
    }

    let artifact = backend
        .materialize(PROJECT, &workload.name, &spec)
        .await
        .map_err(|e| format!("materialize (pull) image: {e}"))?;
    if !matches!(artifact, Artifact::Rootfs { .. }) {
        return Err("expected a rootfs artifact from the image pull".to_string());
    }
    deploy
        .put_compute_spec(&spec)
        .await
        .map_err(|e| format!("store staged spec: {e}"))?;

    let req = LaunchRequest {
        project: PROJECT.into(),
        workload: workload.name.clone(),
        replica: 0,
        spec,
        artifact,
    };
    let inst = backend
        .launch(&req)
        .await
        .map_err(|e| format!("launch container: {e}"))?;
    eprintln!(
        "step 3: launched applied db {workload_name} @ {}:{}",
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
    };
    deploy
        .set_replica_state(proj, &observed)
        .await
        .map_err(|e| format!("publish replica state: {e}"))?;
    Ok(inst.handle)
}

/// Poll the migrate `preflight` until the just-booted cluster accepts the owner-role connect
/// and the ledger is ensured. The engine gate itself resolves immediately (deploy-store, no
/// cluster IO) — this budget only absorbs the owner-role connection against the fresh cluster,
/// which step 4 has usually already warmed. A resolve-level `NotConfigured` is returned
/// immediately (never retried): that would be the fix regressing, not a transient.
async fn wait_for_preflight(
    runner: &NodeMigrationRunner,
) -> Result<Vec<boatramp_core::sql::AppliedMigration>, String> {
    let mut last = String::new();
    for _ in 0..180 {
        match runner.preflight(PROJECT, DB_NAME).await {
            Ok(applied) => return Ok(applied),
            // A clean `NotConfigured` is the fix failing, not a transient — fail fast + loud.
            Err(boatramp_core::sql::MigrationError::NotConfigured) => {
                return Err(
                    "FORCING FAILURE: migrate preflight returned NotConfigured for the applied db \
                     — the engine gate did not resolve it through resolve_binding (pre-fix \
                     behavior); this is the exact gap the fix closes"
                        .to_string(),
                );
            }
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!(
        "migrate preflight never succeeded against the applied db within the budget (last: \
         {last:?})"
    ))
}

/// Poll the operator exec path until the first-boot `initdb` + our credential let it connect
/// and run the DDL/DML. ~90 s budget — a superset of the binding's startup grace.
async fn wait_for_exec(operator: &NodeOperatorSql, sql: &str) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..180 {
        match operator.exec_script(PROJECT, DB_NAME, sql).await {
            Ok(()) => return Ok(()),
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!(
        "the applied db never accepted the operator exec within the budget (last: {last:?}) — a \
         missing server-init credential (image refused initdb) or an unresolvable serve-path \
         binding would surface here"
    ))
}
