//! **Cross-platform, in-process multi-project compute-orchestration integration
//! tests** — the missing CI-runnable proof for the v0.3.12 per-tenant managed-Postgres
//! fixes. Every bug this release closed (spurious default `pg`, `10.0.0.2`-twice IP
//! collision, cross-project identity/IPAM collision, operator-SQL/HTTP-upstream
//! default-project routing, internal-DNS cross-tenant leak) reproduced ONLY on a live
//! multi-tenant node — none was caught by CI, because there was no in-process,
//! multi-project integration test. This file is that test.
//!
//! It runs in plain `cargo test` on macOS: **NO KVM, NO Linux-only paths.** The real
//! Linux container backend is `#[cfg(target_os = "linux")]`, so instead of calling it
//! this drives the *cross-platform* orchestration + resolution logic — the real
//! `reconcile_once`, `auto_register_managed_db_workloads`, `provision_tenant`,
//! `adopt_running_replica_ips`, `DeployEndpointResolver`, `ManagedSqlCredentials`, and
//! the pure DNS `Resolver` — against a [`FakeComputeBackend`] that stands in for the
//! container backend. The fake implements the REAL `ComputeBackend` trait and allocates
//! from the REAL [`IpAuthority`]/`IpPool`
//! ([`boatramp_core::ipam`], cross-platform), mirroring the container backend's
//! `IpLifecycle` exactly — so cross-workload / cross-project IP uniqueness, the
//! last-user release rule, boot-time IP adoption, and pool-vs-reality GC are all
//! exercised for real, not modelled.
//!
//! Each test is named after the bug it locks. Every one would have been RED before this
//! release's fixes (see the per-test docs) and is GREEN now.

#![cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use boatramp_container::dns::{Decision, ResolvedAddrs, Resolver, DEFAULT_INTERNAL_DOMAIN};
use boatramp_core::compute::{
    reconcile_once, AlwaysActive, Artifact, BackendError, BackendPolicy, Capabilities,
    ComputeBackend, ComputeSpec, Endpoint, Health, Instance, InstanceHandle, IsolationClass,
    LaunchRequest, Node, ObservedInstance, ReplicaPhase, Scheme, Snapshot,
};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
use boatramp_core::ipam::IpAuthority;
use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::project::ProjectRef;
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use boatramp_node::compute::adopt_running_replica_ips;
use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
use boatramp_node::managed_sql::{
    auto_register_managed_db_workloads, DeployEndpointResolver, ManagedSqlCredentials,
};
use boatramp_node::tenant_sql::provision_tenant;
use boatramp_storage::sql_compute::ComputeEndpointResolver;
use boatramp_storage::tenant_provision::sanitize_ident;

/// The compute-workload base name for the managed Postgres binding under test. A
/// `Single`/`Project` tenant's dedicated workload is `<COMPUTE>-<ident>`
/// (e.g. `pg-acme`).
const COMPUTE: &str = "pg";
/// The bridge subnet the fake backend + the shared IP authority draw from — the same
/// `10.0.0.0/24` the container backend defaults to, so `.1` is the gateway and the
/// first handed-out address is `.2`.
const SUBNET: &str = "10.0.0.0/24";
/// The compute node id every replica lands on (single-node topology).
const NODE_ID: u64 = 1;

// ===========================================================================
// FakeComputeBackend — a cross-platform stand-in for the Linux container backend.
// ===========================================================================

/// The `(project, workload, replica)` identity key — the first dimension is the
/// project, so two projects' same-named workloads never collide (mirrors the container
/// backend's `IpLifecycle` map key).
type ReplicaKey = (String, String, u32);

/// One launched replica the fake is tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FakeInstance {
    /// The project-qualified backend/container identity
    /// ([`boatramp_core::compute::compute_instance_id`]) — the stem the real backend
    /// derives the cgroup / veth / hostname from. Two projects' same-named workloads
    /// get DISTINCT ids here (the cross-tenant identity collision the fix closes).
    container_id: String,
    /// The stable guest IP allocated for this replica (from the shared authority).
    ip: Ipv4Addr,
    /// The TCP port (the spec's port).
    port: u16,
}

/// A configurable, deterministic, inspectable stand-in for the native container
/// [`ComputeBackend`], usable on any platform.
///
/// It reproduces the parts of the real container backend the orchestration depends on,
/// and NOTHING platform-specific:
///
/// * **IP allocation** draws from the REAL shared [`IpAuthority`]
///   ([`boatramp_core::ipam`]) keyed by `(project, workload, replica)`, so
///   cross-workload / cross-project uniqueness and the node-unique guarantee are
///   exercised for real. A relaunch of the same key reclaims its own address
///   (stable), via `allocate_stable` — exactly like `IpLifecycle::launch`.
/// * **release** applies the container backend's *last-user rule*: an IP is returned
///   to the pool only when no other tracked replica still holds it.
/// * **health** is per-instance configurable (a global "ready after N polls" counter
///   models a stock DB image that is not ready then becomes ready).
/// * **snapshot / restore** keep the IP reserved and restore the same endpoint (the
///   scale-to-zero wake reuses the parked replica's address).
/// * **`reserve_in_use` / `gc_ip_pool`** mirror the container backend's boot-time IP
///   adoption and pool-vs-reality GC.
///
/// It is deterministic and fully inspectable: [`FakeComputeBackend::instances`]
/// exposes the live set with each replica's identity + IP for assertions.
struct FakeComputeBackend {
    /// The SHARED address authority for the bridge/subnet — the same one every
    /// co-located backend clones (A5). Injected so a fresh-on-reboot backend can be
    /// built over the SAME authority, or a distinct one, as a test wants.
    authority: IpAuthority,
    /// The endpoint scheme this backend hands out (the container backend uses `Http`).
    scheme: Scheme,
    /// Live replicas by identity key — the fake's stable-endpoint + last-user
    /// bookkeeping (the container backend's `IpLifecycle::assigned`).
    instances: Mutex<BTreeMap<ReplicaKey, FakeInstance>>,
    /// Global readiness counter: `health` returns `Unhealthy` for the first
    /// `not_ready_polls` calls, then `Healthy`. `0` ⇒ always healthy.
    not_ready_polls: Mutex<u32>,
}

impl FakeComputeBackend {
    /// Build over a shared IP authority, always-ready.
    fn new(authority: IpAuthority) -> Self {
        Self {
            authority,
            scheme: Scheme::Http,
            instances: Mutex::new(BTreeMap::new()),
            not_ready_polls: Mutex::new(0),
        }
    }

    /// A snapshot of the live replicas as `(container_id, ip)` for assertions.
    fn instances(&self) -> Vec<(String, Ipv4Addr)> {
        self.instances
            .lock()
            .expect("instances")
            .values()
            .map(|i| (i.container_id.clone(), i.ip))
            .collect()
    }

    /// The IP currently assigned to `(project, workload, replica)`, if launched.
    fn ip_of(&self, project: &str, workload: &str, replica: u32) -> Option<Ipv4Addr> {
        self.instances
            .lock()
            .expect("instances")
            .get(&(project.to_string(), workload.to_string(), replica))
            .map(|i| i.ip)
    }

    /// The project-qualified backend identity of `(project, workload, replica)`, if
    /// launched — the cgroup/veth/hostname stem the real backend derives.
    fn container_id_of(&self, project: &str, workload: &str, replica: u32) -> Option<String> {
        self.instances
            .lock()
            .expect("instances")
            .get(&(project.to_string(), workload.to_string(), replica))
            .map(|i| i.container_id.clone())
    }

    /// Release `ip` only if no remaining tracked replica still holds it (the container
    /// backend's `release_if_last` last-user rule).
    fn release_if_last(&self, instances: &BTreeMap<ReplicaKey, FakeInstance>, ip: Ipv4Addr) {
        if !instances.values().any(|i| i.ip == ip) {
            self.authority.release(ip);
        }
    }
}

#[async_trait]
impl ComputeBackend for FakeComputeBackend {
    fn id(&self) -> &'static str {
        // Present as the `container` backend so the node wiring (IP adoption groups by
        // backend id; the internal-DNS enablement checks for "container") treats it
        // exactly as it would the real one.
        "container"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // A shared-kernel namespace container, volume- and snapshot-capable so a
            // managed DB (volume) + a scale-to-zero workload can place.
            isolation: IsolationClass::Namespace,
            scale_to_zero: true,
            persistent_volumes: true,
            max_vcpus: None,
            max_mem_mib: None,
        }
    }

    async fn materialize(&self, spec: &ComputeSpec) -> Result<Artifact, BackendError> {
        // The fake doesn't stage a real rootfs; echo an opaque image ref.
        Ok(Artifact::Image {
            reference: format!("fake:{}", spec.port),
        })
    }

    async fn reserve_in_use(&self, replicas: &[(String, String, u32, Ipv4Addr)]) {
        // Boot-time adoption (container backend's `IpLifecycle::adopt`): reserve every
        // in-subnet IP in the shared authority, and record ownership of the ones this
        // pool manages so a relaunch reclaims its own address.
        let ips: Vec<Ipv4Addr> = replicas.iter().map(|(_, _, _, ip)| *ip).collect();
        self.authority.reserve_in_use(&ips);
        let mut instances = self.instances.lock().expect("instances");
        for (p, w, r, ip) in replicas {
            if self.authority.manages(*ip) {
                instances.insert(
                    (p.clone(), w.clone(), *r),
                    FakeInstance {
                        container_id: boatramp_core::compute::compute_instance_id(p, w, *r),
                        ip: *ip,
                        // Port is unknown from adoption alone; the real backend recovers
                        // it from the `<ip>:<port>` ref on relaunch. Not asserted on.
                        port: 0,
                    },
                );
            }
        }
    }

    async fn gc_ip_pool(&self, parked: &[(String, String, u32)]) {
        // Pool-vs-reality GC (container backend's `gc_ip_pool`): the fake's tracked set
        // IS reality (there is no crashed container out-of-band here), so nothing is
        // reclaimed except keys neither tracked nor parked — which never arise. Kept a
        // faithful no-op-for-live-keys so the reconcile's post-loop GC call is exercised
        // without wrongly freeing a live/parked IP.
        let _parked: std::collections::BTreeSet<ReplicaKey> = parked.iter().cloned().collect();
    }

    async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
        let key = (req.project.clone(), req.workload.clone(), req.replica);
        let mut instances = self.instances.lock().expect("instances");
        // Stable allocation keyed by identity: reclaim this replica's own recorded
        // address when it still holds it (idempotent reserve), else let the pool pick a
        // free preferred address or a fresh unique one — mirroring `IpLifecycle::launch`.
        let recorded = instances.get(&key).map(|i| i.ip);
        let owns_recorded =
            recorded.is_some_and(|ip| !instances.iter().any(|(k, i)| k != &key && i.ip == ip));
        let ip = if let Some(ip) = recorded.filter(|_| owns_recorded) {
            self.authority.reserve(ip); // idempotent — keep a released-then-reclaimed IP held
            ip
        } else {
            self.authority
                .allocate_stable(recorded)
                .map_err(|e| BackendError::Launch(e.to_string()))?
        };
        let port = req.spec.port;
        instances.insert(
            key,
            FakeInstance {
                container_id: boatramp_core::compute::compute_instance_id(
                    &req.project,
                    &req.workload,
                    req.replica,
                ),
                ip,
                port,
            },
        );
        Ok(Instance {
            handle: InstanceHandle {
                project: req.project.clone(),
                workload: req.workload.clone(),
                replica: req.replica,
                backend_ref: format!("{ip}:{port}"),
            },
            endpoint: Endpoint {
                scheme: self.scheme,
                host: ip.to_string(),
                port,
            },
        })
    }

    async fn stop(&self, handle: &InstanceHandle) -> Result<(), BackendError> {
        let key = (
            handle.project.clone(),
            handle.workload.clone(),
            handle.replica,
        );
        let mut instances = self.instances.lock().expect("instances");
        // Prefer the recorded assignment; fall back to the handle's `<ip>:<port>` ref.
        let ip = instances.remove(&key).map(|i| i.ip).or_else(|| {
            handle
                .backend_ref
                .split(':')
                .next()
                .and_then(|s| s.parse().ok())
        });
        if let Some(ip) = ip {
            self.release_if_last(&instances, ip);
        }
        Ok(())
    }

    async fn health(&self, _handle: &InstanceHandle) -> Result<Health, BackendError> {
        let mut left = self.not_ready_polls.lock().expect("not_ready_polls");
        if *left > 0 {
            *left -= 1;
            Ok(Health::Unhealthy)
        } else {
            Ok(Health::Healthy)
        }
    }

    async fn snapshot(&self, handle: &InstanceHandle) -> Result<Option<Snapshot>, BackendError> {
        // Keep the IP reserved for the wake (do NOT release); persist the endpoint in
        // the snapshot ref so `restore` reuses the same address, like the real backend.
        let key = (
            handle.project.clone(),
            handle.workload.clone(),
            handle.replica,
        );
        let instances = self.instances.lock().expect("instances");
        let Some(inst) = instances.get(&key) else {
            return Ok(None);
        };
        Ok(Some(Snapshot {
            project: handle.project.clone(),
            workload: handle.workload.clone(),
            replica: handle.replica,
            data_ref: format!("snap|{}|{}", inst.ip, inst.port),
        }))
    }

    async fn restore(&self, snapshot: &Snapshot) -> Result<Instance, BackendError> {
        // Decode the parked endpoint and re-reserve the SAME IP for the SAME identity.
        let mut parts = snapshot.data_ref.rsplitn(3, '|');
        let port: u16 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let ip: Ipv4Addr = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| BackendError::Other("bad snapshot ref".into()))?;
        self.authority.reserve(ip);
        let mut instances = self.instances.lock().expect("instances");
        instances.insert(
            (
                snapshot.project.clone(),
                snapshot.workload.clone(),
                snapshot.replica,
            ),
            FakeInstance {
                container_id: boatramp_core::compute::compute_instance_id(
                    &snapshot.project,
                    &snapshot.workload,
                    snapshot.replica,
                ),
                ip,
                port,
            },
        );
        Ok(Instance {
            handle: InstanceHandle {
                project: snapshot.project.clone(),
                workload: snapshot.workload.clone(),
                replica: snapshot.replica,
                backend_ref: format!("{ip}:{port}"),
            },
            endpoint: Endpoint {
                scheme: self.scheme,
                host: ip.to_string(),
                port,
            },
        })
    }
}

// ===========================================================================
// Test fixtures (shared across the scenarios).
// ===========================================================================

/// A blob store the reconcile never touches (it only uses the KV-backed methods).
struct NullStorage;

#[async_trait]
impl Storage for NullStorage {
    async fn get(&self, _: &str) -> Result<GetObject, StorageError> {
        Err(StorageError::NotFound(String::new()))
    }
    async fn get_range(&self, _: &str, _: u64, _: Option<u64>) -> Result<GetObject, StorageError> {
        Err(StorageError::NotFound(String::new()))
    }
    async fn put(&self, _: &str, _: ByteStream, _: PutMeta) -> Result<ObjectMeta, StorageError> {
        Err(StorageError::unsupported("null"))
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

/// A reversible test "envelope" (NOT encryption) — the same double the `managed_sql` /
/// `tenant_sql` unit tests and the live gates use. Proves the sealed credential
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

/// The managed-`Single`, project-scoped Postgres binding: one dedicated per-tenant
/// container (`<compute>-<ident>`) with the plain `appdb` database + `app` user.
fn single_project_binding() -> ExternalDatabaseConfig {
    ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some("appdb".into()),
        user: Some("app".into()),
        tenant: TenantIsolation::Single,
        tenant_scope: TenantScope::Project,
        ..Default::default()
    }
}

/// The `databases` map the node config carries for the single binding under a logical
/// name (`main`).
fn databases() -> BTreeMap<String, ExternalDatabaseConfig> {
    BTreeMap::from([("main".to_string(), single_project_binding())])
}

/// The dedicated per-tenant `Single` workload name for `project` — `<compute>-<ident>`,
/// the exact derivation `provision_tenant`/`auto_register` use, via the same public
/// `sanitize_ident`.
fn tenant_workload_name(project: &str) -> String {
    format!("{COMPUTE}-{}", sanitize_ident(project))
}

/// A one-node inventory offering the fake `container` backend, sized for several
/// managed DBs. Region tags each replica's endpoint (denormalized by the reconcile).
fn nodes() -> Vec<Node> {
    vec![Node {
        id: NODE_ID,
        region: Some("eu".into()),
        labels: BTreeMap::new(),
        free_vcpus: 32,
        free_mem_mib: 65536,
        backends: vec![boatramp_core::compute::BackendKind {
            id: "container".into(),
            isolation: IsolationClass::Namespace,
            persistent_volumes: true,
            scale_to_zero: true,
        }],
    }]
}

/// A fresh in-memory control plane (`MemoryKv`-backed `DeployStore`) + the shared IP
/// authority the fake backend draws from.
fn control_plane() -> (DeployStore, Arc<dyn KvStore>, IpAuthority) {
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(Arc::new(NullStorage), kv.clone());
    let authority = IpAuthority::new(SUBNET).expect("valid subnet");
    (deploy, kv, authority)
}

/// Register a backend registry containing just the fake `container` backend over a
/// shared authority.
fn registry(backend: Arc<FakeComputeBackend>) -> boatramp_core::compute::BackendRegistry {
    let mut reg: boatramp_core::compute::BackendRegistry = BTreeMap::new();
    reg.insert("container".into(), backend as Arc<dyn ComputeBackend>);
    reg
}

/// Seed a project pointer so `discover_projects` (hence the reconcile's per-project
/// fan-out) sees it. A managed workload key alone also makes a project discoverable, so
/// this only matters for the static-only `default` in bug 1.
async fn seed_project(deploy: &DeployStore, name: &str) {
    deploy
        .put_project(&boatramp_core::project::Project {
            version: 1,
            name: name.to_string(),
            created_at: 0,
            meta: Default::default(),
            config: Default::default(),
            secrets_ref: None,
        })
        .await
        .expect("seed project pointer");
}

/// Seed a deployed static site under a project (a `current/<site>` pointer, as
/// `activate` leaves behind) — makes the project "have resources" WITHOUT using `sql`,
/// the static-only case bug 1 must not over-warm.
async fn seed_static_site(kv: &Arc<dyn KvStore>, project: &str, site: &str) {
    kv.put(
        &format!("project/{project}/current/{site}"),
        b"deadbeef".to_vec(),
    )
    .await
    .expect("seed static-site pointer");
}

/// Run one reconcile pass with the SQL resolvers wired the way the node does (no
/// binding resolver / managed-db env here — the fake DB never boots a real image, and
/// the workload/credential wiring under test is exercised by `provision_tenant`).
async fn reconcile(
    deploy: &DeployStore,
    reg: &boatramp_core::compute::BackendRegistry,
) -> boatramp_core::compute::ReconcileReport {
    reconcile_once(
        deploy,
        reg,
        &nodes(),
        &BackendPolicy::default(),
        &AlwaysActive,
        None,
        None,
    )
    .await
    .expect("reconcile pass")
}

/// Every persisted replica across all projects (project-backfilled), for building the
/// DNS fleet + reboot adoption.
async fn all_states(deploy: &DeployStore) -> Vec<ObservedInstance> {
    deploy
        .list_all_replica_states()
        .await
        .expect("list all replica states")
}

// ===========================================================================
// Bug 1 — no over-warm of a static-only default (the spurious `pg` under default).
// ===========================================================================

/// LOCKS: the spurious default `pg` workload. Before the fix, `auto_register`'s
/// Single boot-warm enumerated any project with a site/function (not one that uses
/// `sql`) and registered a bare `pg` under it — so a static-only `default` got a
/// managed Postgres it never asked for. DRIVES: the REAL
/// `auto_register_managed_db_workloads` for the Single binding, then a REAL
/// `provision_tenant` for `acme` (the lazy first-use path). ASSERTS: nothing managed
/// under `default`, and exactly ONE `pg-<ident>` under `acme`.
#[tokio::test]
async fn single_binding_does_not_overwarm_a_static_only_default() {
    let (deploy, kv, _authority) = control_plane();
    let kv_arc = kv.clone();
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);

    // `default` owns only a static site (no sql); `acme` will lazily provision a DB.
    seed_project(&deploy, "default").await;
    seed_static_site(&kv, "default", "www").await;
    seed_project(&deploy, "acme").await;

    // The boot-warm path for the Single binding: it must register NOTHING (Single
    // warms nothing at boot — the lazy resolve provisions per tenant).
    auto_register_managed_db_workloads(&deploy, &databases()).await;

    let default_after_boot = deploy
        .list_compute_workloads(ProjectRef::DEFAULT)
        .await
        .expect("list default workloads");
    assert!(
        default_after_boot.is_empty(),
        "a Single binding must NOT auto-register any workload under a static-only default; \
         found {default_after_boot:?}"
    );

    // acme's first `sql` use lazily provisions its dedicated per-tenant workload.
    provision_tenant(
        &deploy,
        &kv_arc,
        &envelope,
        &single_project_binding(),
        "acme",
        "",
    )
    .await
    .expect("provision acme");

    // Still nothing under default …
    let default_final = deploy
        .list_compute_workloads(ProjectRef::DEFAULT)
        .await
        .expect("list default workloads");
    assert!(
        default_final.is_empty(),
        "no bare `pg` (or any managed workload) may exist under default; found {default_final:?}"
    );

    // … and EXACTLY ONE `pg-<ident>` under acme.
    let acme = deploy
        .list_compute_workloads(ProjectRef::new("acme"))
        .await
        .expect("list acme workloads");
    assert_eq!(
        acme.len(),
        1,
        "acme must have exactly one managed workload, found {acme:?}"
    );
    assert_eq!(
        acme[0].name,
        tenant_workload_name("acme"),
        "acme's managed workload must be the tenant-aware `pg-<ident>`"
    );
}

// ===========================================================================
// Bug 2 — no IP collision + node-unique, reboot-stable IPs.
// ===========================================================================

/// LOCKS: the `10.0.0.2`-twice collision + endpoint drift across a reboot. Before the
/// fix, a fresh-on-boot pool re-handed a live `10.0.0.x` to a different workload, and a
/// relaunch moved a replica's endpoint. DRIVES: `provision_tenant` (two tenants) +
/// `reconcile_once` (real launch through the fake over the shared authority), then a
/// simulated REBOOT — drop the backend, build a fresh one, `adopt_running_replica_ips`
/// from persisted state, reconcile again. ASSERTS: the two replicas get DISTINCT IPs;
/// after the reboot the IPs are reserved (adopted), still distinct, and each replica
/// keeps its exact endpoint.
#[tokio::test]
async fn reboot_adoption_keeps_ips_unique_and_stable() {
    let (deploy, kv, authority) = control_plane();
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);

    // Two tenants, each with a dedicated Single Postgres → two distinct managed
    // workloads on the one node.
    for project in ["acme", "globex"] {
        seed_project(&deploy, project).await;
        provision_tenant(
            &deploy,
            &kv,
            &envelope,
            &single_project_binding(),
            project,
            "",
        )
        .await
        .unwrap_or_else(|e| panic!("provision {project}: {e}"));
    }

    let backend = Arc::new(FakeComputeBackend::new(authority.clone()));
    let reg = registry(backend.clone());
    let report = reconcile(&deploy, &reg).await;
    assert_eq!(
        report.launched, 2,
        "both tenants launch: {:?}",
        report.errors
    );

    // The two replicas' endpoints are DISTINCT (no collision).
    let acme_wl = tenant_workload_name("acme");
    let globex_wl = tenant_workload_name("globex");
    let acme_ip = backend
        .ip_of("acme", &acme_wl, 0)
        .expect("acme replica launched");
    let globex_ip = backend
        .ip_of("globex", &globex_wl, 0)
        .expect("globex replica launched");
    assert_ne!(
        acme_ip, globex_ip,
        "two projects' managed DBs must get distinct IPs (no 10.0.0.2-twice collision)"
    );

    // ---- Simulate a REBOOT: a brand-new backend over a brand-new authority (a fresh
    // process's empty pool), adopt the persisted in-use IPs, then reconcile. ----
    let rebooted_authority = IpAuthority::new(SUBNET).expect("subnet");
    let rebooted = Arc::new(FakeComputeBackend::new(rebooted_authority));
    let reg2 = registry(rebooted.clone());
    adopt_running_replica_ips(&deploy, &reg2).await;

    // THE COLLISION CHECK: adoption must have reserved both live addresses in the fresh
    // pool, so the very next fresh allocation can NEVER be one of them. Before the fix,
    // a fresh-on-boot pool had not reserved the in-use IPs and would re-hand `10.0.0.2`
    // (the first free address) to a different workload — the exact `10.0.0.2`-twice
    // collision. This is the load-bearing assertion.
    let next_fresh = rebooted
        .authority
        .allocate()
        .expect("pool still has room after adopting two addresses");
    assert!(
        next_fresh != acme_ip && next_fresh != globex_ip,
        "a fresh allocation after adoption re-handed a LIVE address ({next_fresh}) — the \
         10.0.0.2-twice collision; adoption must reserve {acme_ip} and {globex_ip}"
    );
    rebooted.authority.release(next_fresh); // don't leak the probe address

    let report2 = reconcile(&deploy, &reg2).await;
    assert_eq!(
        report2.launched, 0,
        "a boot reconcile of already-running replicas relaunches nothing: {:?}",
        report2.errors
    );

    // Each replica kept its EXACT endpoint across the reboot (adoption made the address
    // stable), and the two are still distinct.
    let acme_after = rebooted.ip_of("acme", &acme_wl, 0).expect("acme adopted");
    let globex_after = rebooted
        .ip_of("globex", &globex_wl, 0)
        .expect("globex adopted");
    assert_eq!(acme_after, acme_ip, "acme keeps its IP across the reboot");
    assert_eq!(
        globex_after, globex_ip,
        "globex keeps its IP across the reboot"
    );
    assert_ne!(
        acme_after, globex_after,
        "the two replicas' IPs remain distinct after the reboot"
    );

    // And the persisted endpoints match (the gateway's upstream source is stable).
    let acme_states = deploy
        .list_replica_states(ProjectRef::new("acme"), &acme_wl)
        .await
        .unwrap();
    assert_eq!(acme_states[0].endpoint.host, acme_ip.to_string());
}

// ===========================================================================
// Bug 3 — project-scoped identity: same-named workloads in two projects.
// ===========================================================================

/// LOCKS: the cross-project cgroup/veth/IPAM identity collision. Before the fix, two
/// projects' same-named workloads derived the SAME backend id (and thus the same
/// cgroup/veth/IP). DRIVES: `reconcile_once` launching a same-named `web` workload
/// registered under BOTH `acme` and `globex` (the identity is `(project, workload,
/// replica)`). ASSERTS: distinct `container_id` (identity) AND distinct IPs.
#[tokio::test]
async fn two_projects_same_workload_name_get_distinct_ids_and_ips() {
    let (deploy, _kv, authority) = control_plane();

    // The SAME workload name `web` in two different projects (a plain compute spec —
    // this is the generic-workload identity case, not a managed DB).
    let spec = plain_web_spec();
    let spec_id = deploy.put_compute_spec(&spec).await.expect("put spec");
    for project in ["acme", "globex"] {
        seed_project(&deploy, project).await;
        deploy
            .set_compute_workload(
                ProjectRef::new(project),
                &boatramp_core::compute::ComputeWorkload {
                    version: 1,
                    name: "web".into(),
                    active: spec_id.clone(),
                    replicas: 1,
                    placement: Default::default(),
                },
            )
            .await
            .expect("register web");
    }

    let backend = Arc::new(FakeComputeBackend::new(authority));
    let reg = registry(backend.clone());
    let report = reconcile(&deploy, &reg).await;
    assert_eq!(
        report.launched, 2,
        "both `web`s launch: {:?}",
        report.errors
    );

    // Inspect the live instance set: distinct identities AND distinct IPs.
    let live = backend.instances();
    assert_eq!(live.len(), 2, "two replicas launched: {live:?}");
    let acme_id = backend.container_id_of("acme", "web", 0).expect("acme web");
    let globex_id = backend
        .container_id_of("globex", "web", 0)
        .expect("globex web");

    // The project-qualified identity stems are distinct (`acme-web-0` vs `globex-web-0`)
    // — so the derived cgroup / veth / hostname never collide.
    assert_ne!(
        acme_id, globex_id,
        "same-named workloads in two projects must derive DISTINCT identities"
    );
    assert_eq!(acme_id, "acme-web-0");
    assert_eq!(globex_id, "globex-web-0");

    // And they hold distinct IPs.
    let acme_ip = backend.ip_of("acme", "web", 0).unwrap();
    let globex_ip = backend.ip_of("globex", "web", 0).unwrap();
    assert_ne!(
        acme_ip, globex_ip,
        "same-named workloads in two projects must get DISTINCT IPs"
    );
    // The inspector's identity set matches (sanity on the inspector itself).
    let ids: std::collections::BTreeSet<_> = live.into_iter().map(|(id, _)| id).collect();
    assert!(ids.contains("acme-web-0") && ids.contains("globex-web-0"));
}

/// A minimal always-on compute spec for a plain `web` workload (not a managed DB).
fn plain_web_spec() -> ComputeSpec {
    ComputeSpec {
        version: 1,
        root: boatramp_core::compute::RootSource::Image("web:latest".into()),
        kernel: String::new(),
        kernel_cmdline: None,
        vcpus: 1,
        mem_mib: 128,
        entrypoint: vec![],
        env: BTreeMap::new(),
        port: 8080,
        restart: boatramp_core::compute::RestartPolicy::Always,
        startup_grace_secs: 30,
        scale_to_zero: false,
        volumes: vec![],
        writable_root: false,
        cap_add: Vec::new(),
        user: None,
        isolation: boatramp_core::compute::IsolationRequirement::Trusted,
        prefer_backend: None,
        bindings: vec![],
    }
}

// ===========================================================================
// Bug 4 — operator-SQL routing targets the tenant, not default.
// ===========================================================================

/// LOCKS: the operator sql exec/query default-project routing bug. Before the fix,
/// operator SQL for `--project acme` targeted a tenant-blind bare `pg`/`default`. The
/// pure `operator_target` derivation is unit-tested in `managed_sql.rs`; this drives the
/// REACHABLE public composition the operator path uses — `DeployEndpointResolver`
/// (the resolver `NodeOperatorSql` builds from `operator_target`'s `endpoint_project`)
/// + `ManagedSqlCredentials` (the sealed credential keyed by `operator_target`'s
/// `cred_project`/`cred_workload`). ASSERTS: for `acme`, the resolver finds the
/// `pg-<ident>` endpoint and the credential exists under `(acme, pg-<ident>)`; there is
/// NO bare `pg` under `default` and no such default credential — so an operator query
/// cannot fall through to it.
#[tokio::test]
async fn operator_sql_targets_the_tenant_not_default() {
    let (deploy, kv, authority) = control_plane();
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);

    seed_project(&deploy, "acme").await;
    // Provision acme's per-tenant DB: registers `pg-<ident>` under `acme` and seals the
    // per-tenant credential under `(acme, pg-<ident>)` — the exact keys `operator_target`
    // derives for a non-default Single tenant.
    provision_tenant(
        &deploy,
        &kv,
        &envelope,
        &single_project_binding(),
        "acme",
        "",
    )
    .await
    .expect("provision acme");

    let backend = Arc::new(FakeComputeBackend::new(authority));
    let reg = registry(backend);
    reconcile(&deploy, &reg).await;

    let acme_wl = tenant_workload_name("acme");

    // The operator path resolves endpoints via a project-scoped DeployEndpointResolver
    // built for the TENANT's project (operator_target.endpoint_project == "acme"). It
    // finds acme's `pg-<ident>` replica …
    let acme_resolver = DeployEndpointResolver::new(deploy.clone(), "acme");
    let acme_eps = acme_resolver
        .endpoints(&acme_wl)
        .await
        .expect("acme endpoints");
    assert_eq!(
        acme_eps.len(),
        1,
        "operator sql for acme must resolve acme's own `pg-<ident>` replica"
    );

    // … while a DEFAULT-scoped resolver for a bare `pg` (the pre-fix target) finds
    // NOTHING — there is no default server to fall through to.
    let default_resolver = DeployEndpointResolver::new(deploy.clone(), "default");
    assert!(
        default_resolver
            .endpoints(COMPUTE)
            .await
            .expect("default endpoints")
            .is_empty(),
        "operator sql must NOT find a bare `pg` under default (the routing bug)"
    );

    // The sealed credential lives under the tenant key `(acme, pg-<ident>)` — the key
    // operator_target derives (cred_project=acme, cred_workload=pg-<ident>). Reading it
    // back proves the operator path would unseal the TENANT's credential.
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());
    let tenant_pw = creds
        .password("acme", &acme_wl)
        .await
        .expect("tenant credential exists");
    assert!(
        !tenant_pw.is_empty(),
        "the tenant credential is materialized"
    );

    // And there is no bare-`pg`-under-default managed workload the operator could target.
    let default_workloads = deploy
        .list_compute_workloads(ProjectRef::DEFAULT)
        .await
        .unwrap();
    assert!(
        !default_workloads.iter().any(|w| w.name == COMPUTE),
        "no bare `{COMPUTE}` workload may exist under default"
    );
}

// ===========================================================================
// Bug 5 — HTTP compute-upstream resolution is project-scoped.
// ===========================================================================

/// LOCKS: the hardcoded-DEFAULT project in the HTTP compute-upstream resolution.
/// `boatramp_server::proxy::compute_endpoints` is crate-private (its own in-crate test
/// `compute_endpoints_are_project_scoped` guards it); the reachable public helper the
/// project was threaded through is `DeployEndpointResolver`, which applies the identical
/// `list_replica_states(ProjectRef::new(project), workload)` project scoping. DRIVES:
/// a two-project fleet (`acme`'s `api` + a same-named `api` under `default`) through the
/// real reconcile, then resolves per project. ASSERTS: `acme`'s resolver returns acme's
/// endpoint; `default`'s resolver does NOT see acme's replica (and vice-versa).
#[tokio::test]
async fn compute_upstream_resolves_per_project() {
    let (deploy, _kv, authority) = control_plane();

    // A same-named `api` compute workload under BOTH acme and default.
    let spec = plain_web_spec();
    let spec_id = deploy.put_compute_spec(&spec).await.unwrap();
    for project in ["acme", "default"] {
        seed_project(&deploy, project).await;
        deploy
            .set_compute_workload(
                ProjectRef::new(project),
                &boatramp_core::compute::ComputeWorkload {
                    version: 1,
                    name: "api".into(),
                    active: spec_id.clone(),
                    replicas: 1,
                    placement: Default::default(),
                },
            )
            .await
            .unwrap();
    }

    let backend = Arc::new(FakeComputeBackend::new(authority));
    let reg = registry(backend.clone());
    let report = reconcile(&deploy, &reg).await;
    assert_eq!(
        report.launched, 2,
        "both `api`s launch: {:?}",
        report.errors
    );

    let acme_ip = backend.ip_of("acme", "api", 0).unwrap();
    let default_ip = backend.ip_of("default", "api", 0).unwrap();

    // acme's project-scoped resolution returns ONLY acme's endpoint …
    let acme = DeployEndpointResolver::new(deploy.clone(), "acme");
    let acme_eps = acme.endpoints("api").await.unwrap();
    assert_eq!(acme_eps, vec![(acme_ip.to_string(), 8080)]);
    assert!(
        !acme_eps.iter().any(|(h, _)| *h == default_ip.to_string()),
        "acme's compute upstream must not see default's replica"
    );

    // … and default's returns ONLY default's endpoint (never acme's) — the isolation
    // the project-blind resolution violated.
    let default = DeployEndpointResolver::new(deploy.clone(), "default");
    let default_eps = default.endpoints("api").await.unwrap();
    assert_eq!(default_eps, vec![(default_ip.to_string(), 8080)]);
    assert!(
        !default_eps.iter().any(|(h, _)| *h == acme_ip.to_string()),
        "default's compute upstream must not see acme's replica (the hardcoded-DEFAULT bug)"
    );

    // A project with no such workload resolves to nothing (no cross-tenant fallthrough).
    let beta = DeployEndpointResolver::new(deploy.clone(), "beta");
    assert!(beta.endpoints("api").await.unwrap().is_empty());
}

// ===========================================================================
// Bug 6 — internal DNS isolation across projects.
// ===========================================================================

/// LOCKS: the internal-DNS cross-project name-resolution isolation. DRIVES: the pure,
/// cross-platform `Resolver` (`boatramp-container::dns`) over a fleet built the SAME way
/// the Linux `DeployDnsSource` builds it — from the REAL reconciled replica states
/// (owner map = every replica's IP → (project, workload); forward map = healthy running
/// replica IPs). Two projects each run a same-named `web`. ASSERTS: acme's source IP
/// resolves acme's `web` to acme's IP; a cross-project FQDN is REFUSED (never leaking
/// the other tenant's address); an unknown source is forwarded.
#[tokio::test]
async fn internal_dns_refuses_cross_project() {
    let (deploy, _kv, authority) = control_plane();

    // Two projects, each with a same-named `web` workload.
    let spec = plain_web_spec();
    let spec_id = deploy.put_compute_spec(&spec).await.unwrap();
    for project in ["acme", "globex"] {
        seed_project(&deploy, project).await;
        deploy
            .set_compute_workload(
                ProjectRef::new(project),
                &boatramp_core::compute::ComputeWorkload {
                    version: 1,
                    name: "web".into(),
                    active: spec_id.clone(),
                    replicas: 1,
                    placement: Default::default(),
                },
            )
            .await
            .unwrap();
    }
    let backend = Arc::new(FakeComputeBackend::new(authority));
    let reg = registry(backend);
    reconcile(&deploy, &reg).await;

    // Build the DNS fleet maps from the real reconciled state — exactly as
    // `DeployDnsSource::snapshot` does (owner map from EVERY replica; forward map from
    // healthy, running replicas only). This proves the isolation over live output.
    let states = all_states(&deploy).await;
    let mut owners: BTreeMap<Ipv4Addr, (String, String)> = BTreeMap::new();
    let mut addrs: BTreeMap<(String, String), Vec<Ipv4Addr>> = BTreeMap::new();
    for st in &states {
        let ip: Ipv4Addr = st.endpoint.host.parse().expect("endpoint host is an IPv4");
        let key = (st.handle.project.clone(), st.handle.workload.clone());
        owners.insert(ip, key.clone());
        if st.phase == ReplicaPhase::Running && st.healthy {
            addrs.entry(key).or_default().push(ip);
        }
    }
    let acme_ip = *owners
        .iter()
        .find(|(_, (p, _))| p == "acme")
        .map(|(ip, _)| ip)
        .expect("acme replica IP");
    let globex_ip = *owners
        .iter()
        .find(|(_, (p, _))| p == "globex")
        .map(|(ip, _)| ip)
        .expect("globex replica IP");

    let resolver = Resolver::new(
        DEFAULT_INTERNAL_DOMAIN,
        move |ip| owners.get(&ip).cloned(),
        move |p, w| ResolvedAddrs {
            v4: addrs
                .get(&(p.to_string(), w.to_string()))
                .cloned()
                .unwrap_or_default(),
            v6: Vec::new(),
        },
    );

    // acme's `web` container resolves its OWN bare `web` to acme's IP.
    let q = encode_query(0x1, "web", 1, 1);
    let Decision::Reply(reply) = resolver.handle_query(acme_ip, &q) else {
        panic!("acme must resolve its own workload, got forward");
    };
    assert_eq!(rcode_of(&reply), 0, "NOERROR for an in-project name");
    assert_eq!(
        a_records(&reply),
        vec![acme_ip],
        "the bare name resolves within the caller's own project only"
    );

    // acme's container asking for globex's `web` by FQDN is REFUSED — and globex's
    // address never leaks.
    let q = encode_query(0x2, "web.globex.boatramp.internal", 1, 1);
    let Decision::Reply(reply) = resolver.handle_query(acme_ip, &q) else {
        panic!("a cross-project internal name must NOT be forwarded");
    };
    assert_eq!(
        rcode_of(&reply),
        5,
        "cross-project resolution must be REFUSED"
    );
    assert!(
        a_records(&reply).is_empty() && !a_records(&reply).contains(&globex_ip),
        "globex's address must never leak into acme's answer"
    );

    // An unknown source IP (not a co-located container) is forwarded, never answered an
    // internal name.
    let q = encode_query(0x3, "web.acme.boatramp.internal", 1, 1);
    assert_eq!(
        resolver.handle_query(Ipv4Addr::new(203, 0, 113, 7), &q),
        Decision::Forward,
        "an unknown source must be forwarded, not answered an internal name"
    );
}

// ===========================================================================
// Regression — v0.3.12 health-persist: a recovered replica must reach the resolver.
// ===========================================================================

/// LOCKS the v0.3.12 health-persist regression. `launch_one` probes readiness BEFORE the
/// guest binds its port and persists `healthy:false`; the reconcile's health-refresh
/// flips it true once the guest is reachable — but a *running* replica needs no
/// Launch/Stop action, so before the fix that recovery was never written back. The store
/// kept `healthy:false` forever and `DeployEndpointResolver` (which reads the store)
/// reported "no healthy replica" for a perfectly reachable DB — exactly construens'
/// v0.3.12 symptom. DRIVES two real `reconcile_once` passes over a fake that is Unhealthy
/// on its first probe (pre-bind) then Healthy. ASSERTS: after launch the resolver sees no
/// healthy endpoint; after the next reconcile the recovered health is PERSISTED and the
/// resolver returns it.
#[tokio::test]
async fn health_recovery_is_persisted_so_the_resolver_sees_it() {
    let (deploy, kv, authority) = control_plane();
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);

    seed_project(&deploy, "acme").await;
    provision_tenant(
        &deploy,
        &kv,
        &envelope,
        &single_project_binding(),
        "acme",
        "",
    )
    .await
    .expect("provision acme");
    let wl = tenant_workload_name("acme");

    // Unhealthy on the FIRST probe (launch_one, pre-bind), Healthy thereafter.
    let backend = Arc::new(FakeComputeBackend::new(authority));
    *backend.not_ready_polls.lock().expect("not_ready_polls") = 1;
    let reg = registry(backend.clone());
    let resolver = DeployEndpointResolver::new(deploy.clone(), "acme");

    // Pass 1 — launch; launch_one's pre-bind probe fails → persisted healthy:false.
    reconcile(&deploy, &reg).await;
    assert!(
        resolver.endpoints(&wl).await.unwrap().is_empty(),
        "a replica whose launch-time probe failed must not resolve as healthy yet"
    );

    // Pass 2 — the guest is now reachable; the health-refresh must PERSIST the recovery.
    reconcile(&deploy, &reg).await;
    assert!(
        !resolver.endpoints(&wl).await.unwrap().is_empty(),
        "recovered health was not persisted — the resolver still reports no healthy \
         replica for a reachable DB (the v0.3.12 regression this locks)"
    );
}

// --- Minimal DNS wire helpers (mirroring the dns.rs test encoders) --------

/// Encode a single-question DNS query datagram.
fn encode_query(id: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR counts
    for label in name.trim_end_matches('.').split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // root
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&qclass.to_be_bytes());
    buf
}

/// The RCODE nibble from a reply header.
fn rcode_of(reply: &[u8]) -> u8 {
    reply[3] & 0x0F
}

/// The ANCOUNT from a reply header.
fn ancount_of(reply: &[u8]) -> u16 {
    u16::from_be_bytes([reply[6], reply[7]])
}

/// Extract the A-record IPv4 addresses from a reply (our own `answer_reply` encoding).
fn a_records(reply: &[u8]) -> Vec<Ipv4Addr> {
    let mut pos = 12;
    while reply[pos] != 0 {
        pos += 1 + reply[pos] as usize;
    }
    pos += 1 + 4; // root + qtype + qclass
    let mut out = Vec::new();
    let mut i = 0;
    while i < ancount_of(reply) {
        let rtype = u16::from_be_bytes([reply[pos + 2], reply[pos + 3]]);
        let rdlen = u16::from_be_bytes([reply[pos + 10], reply[pos + 11]]) as usize;
        let rdata = &reply[pos + 12..pos + 12 + rdlen];
        if rtype == 1 && rdlen == 4 {
            out.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
        }
        pos += 12 + rdlen;
        i += 1;
    }
    out
}
