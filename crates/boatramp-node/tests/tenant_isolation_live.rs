//! **The load-bearing cross-tenant-isolation gate** for the per-tenant managed
//! database feature (PLAN-per-tenant-db) — Linux + root + a bridge, **ignored by
//! default**. It is the live proof that the module's #1 invariant actually holds on
//! a real Postgres:
//!
//! > **Tenant A's database credential must never be able to reach tenant B's
//! > database.**
//!
//! The pure name-derivation + DDL is unit-tested in `boatramp-storage`, and the
//! resolver's credential-key isolation is unit-tested in `boatramp-node`; but neither
//! proves that Postgres actually *denies the connection*. That is what this test does:
//! it stands up ONE shared Postgres via the native container backend (exactly the
//! co-located managed-DB workload the container capability gate exercises), wires the
//! control-plane state so the endpoint resolves, provisions two tenants (`acme` and
//! `globex`) through `boatramp_node::tenant_sql::provision_tenant`, and then asserts,
//! live:
//!
//! - `acme`'s role → `acme`'s database: connect + a trivial query **succeeds**.
//! - `acme`'s role → **`globex`'s** database: the connection is **REFUSED** by
//!   Postgres (the `REVOKE CONNECT … FROM PUBLIC` + per-role `GRANT CONNECT`). This is
//!   the core assertion — cross-tenant access must FAIL closed.
//!
//! It lives in `boatramp-node` (not `boatramp-container`) because it needs
//! `boatramp-node`'s `tenant_sql` + `managed_sql` alongside the container backend
//! (`boatramp-node` depends on `boatramp-container`).
//!
//! Prereqs on the host (see `boatramp-container`'s `container_live` module header): a
//! bridge with the gateway IP, e.g.
//! ```sh
//! sudo ip link add br-boatramp type bridge 2>/dev/null || true
//! sudo ip addr add 10.0.0.1/24 dev br-boatramp 2>/dev/null || true
//! sudo ip link set br-boatramp up
//! ```
//! Run (as root, since the backend does veth/cgroup/unshare; needs `psql` on PATH):
//! ```sh
//! sudo -E BOATRAMP_BIN=target/debug/boatramp \
//!   cargo test -p boatramp-node --features sql-postgres \
//!   --test tenant_isolation_live -- --ignored --test-threads=1 --nocapture
//! ```
//! The single test thread matters: the shared bridge (`br-boatramp`) can host only
//! one launch at a time. Skips (passes) when `BOATRAMP_BIN` is absent — never fails on
//! a dev box.

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
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
use boatramp_node::managed_sql::ManagedSqlCredentials;
use boatramp_node::tenant_sql::{provision_tenant, tenant_key, TenantNames};
use boatramp_storage::tenant_provision::{sanitize_ident, tenant_db_name, tenant_role_name};
use bytes::Bytes;
use futures::StreamExt;

/// The shared Postgres server's compute-workload name (the binding's `compute`). One
/// server; two tenants get two databases + two login roles inside it.
const COMPUTE: &str = "pg";
/// The binding's configured database name (the per-tenant base; `appdb_<ident>`).
const DATABASE: &str = "appdb";
/// The binding's configured **superuser** on the shared server (the server-init user +
/// the account that runs provisioning DDL). Never handed to a tenant's data plane.
const SUPERUSER: &str = "postgres";

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
/// `managed_sql` / `tenant_sql` unit tests use. It proves the sealed credential
/// round-trips; the node uses a real KMS/local envelope in production, but the sealing
/// contract is identical, so this exercises the exact `ManagedSqlCredentials` path.
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

/// The `Shared` / `Project`-grain binding under test: one shared `pg` server, a
/// per-tenant database (`appdb_<ident>`) + login role per project tenant.
fn shared_project_binding() -> ExternalDatabaseConfig {
    ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DATABASE.into()),
        user: Some(SUPERUSER.into()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        // A short connect timeout so the negative test's refused connection fails fast.
        connect_timeout_secs: Some(10),
        ..Default::default()
    }
}

/// Poll `psql -tAc "select 1"` over TCP against `conn`, returning `true` once it
/// answers `1`. ~30 s budget for a first-boot `initdb`.
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

/// Run `psql -tAc <sql>` against `conn`, returning `(ok, combined_output)`.
fn psql(conn: &str, sql: &str) -> (bool, String) {
    match std::process::Command::new("psql")
        .args([conn, "-tAc", sql])
        .output()
    {
        Ok(out) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            (out.status.success(), combined)
        }
        Err(e) => (false, e.to_string()),
    }
}

/// LIVE cross-tenant isolation on a real shared Postgres. See the module header.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Linux + root + a bridge + psql (privileged live seam); pulls pgvector"]
async fn tenant_isolation_shared_postgres_denies_cross_tenant() {
    let Some(bin) = std::env::var_os("BOATRAMP_BIN") else {
        eprintln!(
            "tenant_isolation_live: set BOATRAMP_BIN (and have `psql` on PATH, root, and \
             a br-boatramp bridge) to run"
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
    // now, and initialize the container with EXACTLY this password (mirroring how the
    // reconcile injects `POSTGRES_*` from the sealed credential — `managed_db_server_env`
    // / `ManagedDbEnv`). So provisioning-as-superuser later authenticates.
    let superuser_pw = creds
        .password(DEFAULT_PROJECT, COMPUTE)
        .await
        .expect("seal superuser credential");

    // --- Launch ONE shared Postgres via the native container backend. Built through the
    // SHARED `managed_db_spec` synthesizer (never a divergent hand-rolled copy) + the
    // rootless privilege directive + the managed server-init env from the sealed
    // credential — exactly what the node's reconcile does at launch.
    let data_dir = std::env::temp_dir().join(format!("boatramp-tenant-iso-{}", std::process::id()));
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
    // The server-init credential env (`POSTGRES_*`) from the sealed superuser password —
    // exactly `managed_db_server_env(Postgres, DATABASE, SUPERUSER, superuser_pw)`.
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

    // Register the workload's desired state + persist a healthy Running replica pointing
    // at the launched container's endpoint, so `DeployEndpointResolver` (and thus the
    // provisioning + resolver `ComputeResolvedSqlBackend`s) resolve `pg` to host:port.
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

    // Publish the replica state the endpoint resolver reads: a healthy, Running replica
    // pointing at the launched container's endpoint, so `DeployEndpointResolver` resolves
    // `pg` → host:port (the same `ObservedInstance` the reconcile's `launch_one` builds).
    let observed = ObservedInstance {
        handle: inst.handle.clone(),
        node: 0,
        backend: backend.id().to_string(),
        endpoint: inst.endpoint.clone(),
        region: None,
        healthy: true,
        phase: ReplicaPhase::Running,
        snapshot: None,
    };
    deploy
        .set_replica_state(ProjectRef::DEFAULT, &observed)
        .await
        .expect("publish replica state");

    // Run the actual assertions inside a closure that returns a Result, so the container +
    // temp dir are torn down (async, no nested-runtime panic) on BOTH the success and the
    // failure path — a leaked rootless container would hold the single test bridge. The
    // outcome is unwrapped AFTER cleanup, so a failed assertion still stops before the
    // success marker (the gate greps for the marker, not for `test result: ok`).
    let outcome = run_assertions(&deploy, &kv, &envelope, &creds, &superuser_pw, &host, port).await;

    let _ = backend.stop(&handle).await;
    let _ = std::fs::remove_dir_all(&data_dir);

    outcome.expect("tenant isolation assertions");

    // The single success marker the capability gate greps for. Printed ONLY after every
    // assertion held (a silent skip returns before this line; a failed assertion returns an
    // Err above and `expect` panics before here).
    println!("TENANT ISOLATION OK: acme reaches acme, acme denied globex");
}

/// The isolation assertions, factored out so the caller can tear the container down on
/// either outcome. Returns `Err(reason)` on the first failed invariant (fail closed),
/// `Ok(())` when every assertion held.
#[allow(clippy::too_many_arguments)]
async fn run_assertions(
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    envelope: &Arc<dyn KeyEnvelope>,
    creds: &ManagedSqlCredentials,
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

    // --- Provision two tenants through the SHIPPED provisioning path. `site` is unused
    // under Project scope; pass a stable placeholder. Idempotent + fails closed.
    let binding = shared_project_binding();
    provision_tenant(deploy, kv, envelope, &binding, "acme", "-")
        .await
        .map_err(|e| format!("provision tenant acme: {e}"))?;
    provision_tenant(deploy, kv, envelope, &binding, "globex", "-")
        .await
        .map_err(|e| format!("provision tenant globex: {e}"))?;

    // --- Derive each tenant's live names + fetch its per-tenant login credential the
    // SAME way the resolver does, so we connect with the exact role/db/password the
    // data plane would hand a request. (No divergent hand-rolled names.)
    let acme = tenant_names_for(&binding, "acme");
    let globex = tenant_names_for(&binding, "globex");
    let acme_pw = tenant_password(creds, COMPUTE, "acme").await;
    // (globex's own password is not needed — the negative test uses ACME's role.)

    // Distinct tenants must have distinct db + role (belt-and-suspenders vs the unit
    // tests; a collision here would make the live assertions meaningless).
    if acme.database == globex.database || acme.role == globex.role {
        return Err(format!(
            "cross-tenant name collision: acme=({},{}) globex=({},{})",
            acme.database, acme.role, globex.database, globex.role
        ));
    }

    // === Assertion 1 (POSITIVE): acme's role reaches acme's database + can query. ===
    let acme_to_acme = format!(
        "postgresql://{}:{}@{}:{}/{}",
        acme.role, acme_pw, host, port, acme.database
    );
    let (ok, out) = psql(&acme_to_acme, "select 1");
    if !ok || out.trim() != "1" {
        return Err(format!(
            "acme's role must reach acme's database and query (got ok={ok}, out={out:?})"
        ));
    }
    eprintln!("positive: acme role -> acme db  OK");

    // === Assertion 2 (NEGATIVE, the core invariant): acme's role -> GLOBEX's db is
    // REFUSED. We connect with ACME's role + ACME's password to GLOBEX's database name
    // explicitly (a direct URL — the resolver never hands this pairing out, so we build
    // it by hand). Postgres denies CONNECT (REVOKE CONNECT FROM PUBLIC + per-role grant),
    // so `psql` must FAIL and the error must be a permission/connect denial. ===
    let acme_to_globex = format!(
        "postgresql://{}:{}@{}:{}/{}",
        acme.role, acme_pw, host, port, globex.database
    );
    let (cross_ok, cross_out) = psql(&acme_to_globex, "select 1");
    if cross_ok {
        return Err(format!(
            "CROSS-TENANT BREACH: acme's role connected to globex's database! (out={cross_out:?})"
        ));
    }
    // Fail closed for the RIGHT reason: a permission denial on the database, not a
    // transient network error. Postgres reports `permission denied for database "<db>"`
    // (SQLSTATE 42501) for a role lacking CONNECT.
    let lc = cross_out.to_ascii_lowercase();
    if !(lc.contains("permission denied") || lc.contains("not permitted") || lc.contains("42501")) {
        return Err(format!(
            "acme->globex must be refused with a permission denial (Postgres denies CONNECT), \
             got: {cross_out:?}"
        ));
    }
    eprintln!(
        "negative: acme role -> globex db  DENIED ({})",
        cross_out.trim()
    );

    // === Assertion 3 (OPTIONAL): the superuser reaches BOTH tenants' databases, proving
    // provisioning actually created them (so the negative result above is a real denial,
    // not a missing database). ===
    for (who, db) in [("acme", &acme.database), ("globex", &globex.database)] {
        let super_to_db = format!("postgresql://{SUPERUSER}:{superuser_pw}@{host}:{port}/{db}");
        let (ok, out) = psql(&super_to_db, "select 1");
        if !ok || out.trim() != "1" {
            return Err(format!(
                "superuser must reach {who}'s provisioned database {db:?} (got ok={ok}, out={out:?})"
            ));
        }
    }
    eprintln!("superuser reaches both provisioned databases  OK");
    Ok(())
}

/// Derive a tenant's live `TenantNames` for `binding` the same way `tenant_sql` does
/// (its internal `tenant_names` is private, so reproduce it from the public
/// `tenant_key` + the `boatramp-storage` derivation used inside it — for this test's
/// `Shared`/`Project` binding).
fn tenant_names_for(binding: &ExternalDatabaseConfig, project: &str) -> TenantNames {
    let compute = binding.compute.as_deref().unwrap();
    let database = binding.database.as_deref().unwrap();
    let (raw, is_default) = tenant_key(binding.tenant_scope, project, "-");
    assert!(!is_default, "test tenants must be derived, not the default");
    let ident = sanitize_ident(&raw);
    TenantNames {
        database: tenant_db_name(database, &ident),
        role: tenant_role_name(compute, &ident),
        workload: compute.to_string(),
    }
}

/// Fetch a `Shared`-mode tenant's per-tenant login password under the SAME credential
/// key the resolver + provisioner use: `password(<project>, "<compute>/<ident>")`.
async fn tenant_password(creds: &ManagedSqlCredentials, compute: &str, project: &str) -> String {
    let ident = sanitize_ident(project);
    creds
        .password(project, &format!("{compute}/{ident}"))
        .await
        .expect("resolve per-tenant credential")
}
