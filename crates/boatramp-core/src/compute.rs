//! Compute: the wasm-clean workload model (re-exported from
//! [`boatramp_types::compute`]) plus the native control-plane layer — the
//! pluggable [`ComputeBackend`] trait, the backend-aware scheduler, the
//! selection/isolation policy, and the pure reconcile planner.
//!
//! Everything here is backend-agnostic and cross-platform. The concrete backends
//! (VMM = `boatramp-firecracker`, native container, remote docker, cloudflare)
//! implement [`ComputeBackend`]; a leader-gated loop drives [`reconcile_plan`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use boatramp_types::compute::*;

use crate::deploy::DeployStore;

// ---------------------------------------------------------------------------
// Backend trait + value types
// ---------------------------------------------------------------------------

/// The isolation a backend **provides** (distinct from the workload's
/// [`IsolationRequirement`], which is what it *needs*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationClass {
    /// A microVM with its own guest kernel under KVM (strongest).
    VmKvm,
    /// OS-level namespaces + cgroups, sharing the host kernel.
    Namespace,
    /// A container on a (possibly remote) container runtime.
    Container,
    /// A managed platform (e.g. Cloudflare Containers).
    Platform,
}

impl IsolationClass {
    /// Whether this class is strong enough for untrusted multi-tenant code
    /// (a microVM or a managed platform — never a shared-kernel container).
    pub fn is_strong(self) -> bool {
        matches!(self, IsolationClass::VmKvm | IsolationClass::Platform)
    }

    /// Whether this class satisfies a workload's isolation requirement.
    pub fn satisfies(self, req: IsolationRequirement) -> bool {
        match req {
            IsolationRequirement::Trusted => true,
            IsolationRequirement::Untrusted => self.is_strong(),
        }
    }
}

/// What a backend can do in the current environment (for scheduling + policy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// The isolation class this backend provides.
    pub isolation: IsolationClass,
    /// Whether it supports snapshot/restore (scale-to-zero).
    pub scale_to_zero: bool,
    /// Whether it supports persistent volumes.
    pub persistent_volumes: bool,
    /// Max vCPUs per replica, if bounded.
    pub max_vcpus: Option<u32>,
    /// Max memory (MiB) per replica, if bounded.
    pub max_mem_mib: Option<u32>,
}

/// A backend-specific, materialized artifact for a spec (what the backend boots).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Artifact {
    /// A microVM: an `ext4` rootfs + a guest kernel, as host paths.
    VmImages {
        /// Host path to the `ext4` rootfs.
        rootfs_path: String,
        /// Host path to the guest `vmlinux`.
        kernel_path: String,
    },
    /// An unpacked rootfs directory (native container).
    Rootfs {
        /// Host path to the rootfs tree.
        dir: String,
    },
    /// An OCI image reference a runtime/platform pulls (docker / cloudflare).
    Image {
        /// The image reference (`registry/repo:tag` or a digest).
        reference: String,
    },
}

/// The request to launch one replica.
#[derive(Debug, Clone)]
pub struct LaunchRequest {
    /// Workload name (for naming / teardown / logging).
    pub workload: String,
    /// Replica ordinal within the workload (`0..replicas`).
    pub replica: u32,
    /// The immutable spec to run.
    pub spec: ComputeSpec,
    /// The materialized artifact for `spec`.
    pub artifact: Artifact,
}

/// An opaque handle to a launched replica (for `stop`/`health`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceHandle {
    /// Workload name.
    pub workload: String,
    /// Replica ordinal.
    pub replica: u32,
    /// Backend-specific reference (pid / container id / CF instance id / …).
    pub backend_ref: String,
}

/// URL scheme for a replica endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    /// Plain HTTP.
    Http,
    /// HTTPS.
    Https,
}

/// Where the gateway routes to reach a replica.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Scheme to reach the replica with.
    pub scheme: Scheme,
    /// Host or IP.
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl Endpoint {
    /// The endpoint as a base URL (`scheme://host:port`).
    pub fn url(&self) -> String {
        let scheme = match self.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        format!("{scheme}://{}:{}", self.host, self.port)
    }
}

/// A launched replica: its handle + the endpoint the gateway routes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// Handle for later `stop`/`health`.
    pub handle: InstanceHandle,
    /// The endpoint to route ingress to.
    pub endpoint: Endpoint,
}

/// Liveness/readiness of a running replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Up and serving.
    Healthy,
    /// Running but not serving (or exited).
    Unhealthy,
    /// Indeterminate (e.g. transient probe failure).
    Unknown,
}

/// An opaque snapshot for scale-to-zero (persisted inside [`ObservedInstance`]
/// while a replica is parked in the [`Zero`](ReplicaPhase::Zero) phase).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Workload the snapshot belongs to.
    pub workload: String,
    /// Replica ordinal.
    pub replica: u32,
    /// Backend-specific reference to the stored snapshot.
    pub data_ref: String,
}

/// Why a backend operation failed.
#[derive(Debug)]
pub enum BackendError {
    /// The backend doesn't support the requested operation.
    Unsupported,
    /// Staging the artifact failed.
    Materialize(String),
    /// Launching the replica failed.
    Launch(String),
    /// Stopping the replica failed.
    Stop(String),
    /// Any other failure.
    Other(String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::Unsupported => write!(f, "operation not supported by this backend"),
            BackendError::Materialize(d) => write!(f, "materialize: {d}"),
            BackendError::Launch(d) => write!(f, "launch: {d}"),
            BackendError::Stop(d) => write!(f, "stop: {d}"),
            BackendError::Other(d) => write!(f, "{d}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// A pluggable compute execution backend (VMM / container / cloudflare / docker).
///
/// The control plane only ever sees [`Instance`]/[`Endpoint`]; whether the
/// backend runs the workload directly (VMM, container) or delegates to a
/// platform/daemon (cloudflare, docker) is internal.
#[async_trait]
pub trait ComputeBackend: Send + Sync {
    /// Stable backend id (`"vmm"` / `"container"` / `"cloudflare"` / `"docker"`).
    fn id(&self) -> &'static str;

    /// What this backend can do here (used by the scheduler + policy gate).
    fn capabilities(&self) -> Capabilities;

    /// Stage `spec`'s artifact into whatever this backend boots from.
    /// Idempotent + content-addressed (cache/dedup by spec id).
    async fn materialize(&self, spec: &ComputeSpec) -> Result<Artifact, BackendError>;

    /// Launch one replica; returns its handle + routable endpoint.
    async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError>;

    /// Stop + clean up a replica (idempotent; safe on a half-launched instance).
    async fn stop(&self, handle: &InstanceHandle) -> Result<(), BackendError>;

    /// Liveness/readiness of a running replica.
    async fn health(&self, handle: &InstanceHandle) -> Result<Health, BackendError>;

    /// Snapshot a replica for scale-to-zero (backends that support it).
    async fn snapshot(&self, _handle: &InstanceHandle) -> Result<Option<Snapshot>, BackendError> {
        Ok(None)
    }

    /// Restore a snapshotted replica.
    async fn restore(&self, _snapshot: &Snapshot) -> Result<Instance, BackendError> {
        Err(BackendError::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// Backend selection policy
// ---------------------------------------------------------------------------

/// Per-site/tenant backend policy: which backends a workload may use. Default
/// permits any backend; `force` pins one (overrides allow/forbid).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackendPolicy {
    /// If set, only these backend ids are permitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    /// Backend ids that are never permitted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub forbid: Vec<String>,
    /// If set, the only permitted backend (e.g. force `vmm` for a tenant).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force: Option<String>,
    /// Require a **strong** isolation class (VM/platform) for every placement,
    /// making shared-kernel backends (native namespace / Docker) ineligible even
    /// for a workload that only declares `Trusted`. Set by the
    /// operator security posture (`!allow_shared_kernel_compute`); default `false`
    /// preserves the prior behavior. Closes the "misclassified workload lands on
    /// a weak backend" gap.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_strong_isolation: bool,
}

impl BackendPolicy {
    /// Whether backend `id` is permitted by this policy.
    pub fn permits(&self, id: &str) -> bool {
        if let Some(force) = &self.force {
            return id == force;
        }
        if self.forbid.iter().any(|x| x == id) {
            return false;
        }
        match &self.allow {
            Some(allow) => allow.iter().any(|x| x == id),
            None => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Scheduler (backend-aware placement)
// ---------------------------------------------------------------------------

/// A backend a node offers, with the isolation class it provides there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendKind {
    /// Backend id (`"vmm"`, …).
    pub id: String,
    /// Isolation class this backend provides on this node.
    pub isolation: IsolationClass,
}

/// A node's advertised capacity, attributes, and the backends it offers
/// (from cluster membership). The scheduler receives a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Cluster node id.
    pub id: u64,
    /// Region, for placement constraints.
    pub region: Option<String>,
    /// Advertised labels, for placement constraints.
    pub labels: BTreeMap<String, String>,
    /// Free vCPUs.
    pub free_vcpus: u32,
    /// Free memory in MiB.
    pub free_mem_mib: u32,
    /// Backends this node can run a replica on.
    pub backends: Vec<BackendKind>,
}

impl Node {
    /// The backend to use for `spec` on this node, honoring the spec's preferred
    /// backend, the isolation requirement, and the policy. `None` ⇒ no eligible
    /// backend here.
    fn pick_backend(&self, spec: &ComputeSpec, policy: &BackendPolicy) -> Option<String> {
        let eligible = |b: &BackendKind| {
            policy.permits(&b.id)
                && b.isolation.satisfies(spec.isolation)
                // Strict posture: only strong isolation, regardless of the spec's
                // (possibly misclassified) requirement.
                && (!policy.require_strong_isolation || b.isolation.is_strong())
        };
        if let Some(pref) = &spec.prefer_backend {
            if let Some(b) = self.backends.iter().find(|b| &b.id == pref && eligible(b)) {
                return Some(b.id.clone());
            }
        }
        self.backends
            .iter()
            .find(|b| eligible(b))
            .map(|b| b.id.clone())
    }
}

/// One placed replica: the node + the backend chosen for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// Chosen node id.
    pub node: u64,
    /// Chosen backend id.
    pub backend: String,
}

/// Place `count` replicas of `spec` (subject to `placement` + `policy`) across
/// `nodes`. Eligibility = satisfies the placement constraints, currently fits
/// the spec's CPU/mem, **and** offers a policy-allowed backend whose isolation
/// satisfies the spec. Worst-fit (most-free node first) spreads load; capacity is
/// decremented per placement. Returns fewer than `count` when capacity/eligible
/// backends run out (the caller surfaces "insufficient capacity").
pub fn place_replicas(
    count: u32,
    placement: &PlacementConstraints,
    spec: &ComputeSpec,
    nodes: &[Node],
    policy: &BackendPolicy,
) -> Vec<Placement> {
    let need_cpu = spec.vcpus.max(1);
    let need_mem = spec.mem_mib.max(1);

    // Working copy: (id, free_cpu, free_mem, the node) for placement-eligible nodes.
    let mut free: Vec<(u64, u32, u32, &Node)> = nodes
        .iter()
        .filter(|n| placement.allows(n.region.as_deref(), &n.labels))
        .map(|n| (n.id, n.free_vcpus, n.free_mem_mib, n))
        .collect();

    let mut placements = Vec::new();
    for _ in 0..count {
        // Worst-fit among nodes that fit AND have an eligible backend.
        let pick = free
            .iter_mut()
            .filter(|(_, c, m, n)| {
                *c >= need_cpu && *m >= need_mem && n.pick_backend(spec, policy).is_some()
            })
            .max_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
        match pick {
            Some(slot) => {
                let backend = slot
                    .3
                    .pick_backend(spec, policy)
                    .expect("filtered to nodes with an eligible backend");
                placements.push(Placement {
                    node: slot.0,
                    backend,
                });
                slot.1 -= need_cpu;
                slot.2 -= need_mem;
            }
            None => break, // no node can fit another eligible replica
        }
    }
    placements
}

// ---------------------------------------------------------------------------
// Reconcile planner (pure)
// ---------------------------------------------------------------------------

/// The lifecycle phase of an observed replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ReplicaPhase {
    /// Launched + serving (the normal phase; also the back-compat default).
    #[default]
    Running,
    /// **Scaled to zero**: snapshotted + stopped to free node resources;
    /// resumable from its [`ObservedInstance::snapshot`] on the next activity.
    Zero,
}

/// An observed replica (the persisted control-plane state at
/// `compute_state/<workload>/<replica>`; also the gateway's upstream source).
/// Usually [`Running`](ReplicaPhase::Running); a scale-to-zero replica persists
/// in the [`Zero`](ReplicaPhase::Zero) phase carrying its snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedInstance {
    /// The replica's handle.
    pub handle: InstanceHandle,
    /// The node it runs on (for `Zero`, the node holding its snapshot — restore
    /// is same-node until live migration lands).
    pub node: u64,
    /// The backend that runs it.
    pub backend: String,
    /// The endpoint the gateway routes to (the last-known endpoint while `Zero`).
    pub endpoint: Endpoint,
    /// The region of the node this replica runs on, denormalized from
    /// [`Node::region`] at launch so the gateway's nearest-replica LB (FA-8) can
    /// tag the replica's endpoint without a node lookup. `#[serde(default)]` keeps
    /// older records (no field) deserializing — schema stays v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Whether the last health check passed (always `false` while `Zero`).
    pub healthy: bool,
    /// Lifecycle phase. `#[serde(default)]` keeps older records (no field)
    /// deserializing as [`Running`](ReplicaPhase::Running) — schema stays v1.
    #[serde(default)]
    pub phase: ReplicaPhase,
    /// The snapshot to restore from — `Some` iff `phase == Zero`.
    #[serde(default)]
    pub snapshot: Option<Snapshot>,
}

/// KV key prefix for observed replica state.
pub const REPLICA_STATE_PREFIX: &str = "compute_state/";

/// The observed-state key for a workload's replica.
pub fn replica_state_key(workload: &str, replica: u32) -> String {
    format!("{REPLICA_STATE_PREFIX}{workload}/{replica}")
}

/// The key prefix listing a workload's replica states.
pub fn replica_state_prefix(workload: &str) -> String {
    format!("{REPLICA_STATE_PREFIX}{workload}/")
}

/// A reconcile action the driver executes against a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Launch a new replica at `(node, backend)`.
    Launch {
        /// Workload name.
        workload: String,
        /// Replica ordinal to launch.
        replica: u32,
        /// Chosen node.
        node: u64,
        /// Chosen backend.
        backend: String,
    },
    /// Stop a replica.
    Stop {
        /// The replica to stop.
        handle: InstanceHandle,
    },
    /// **Sleep** a running replica for scale-to-zero: snapshot it, stop
    /// it, and persist it in the [`Zero`](ReplicaPhase::Zero) phase.
    Snapshot {
        /// The running replica to snapshot + stop.
        handle: InstanceHandle,
    },
    /// **Wake** a zeroed replica: restore it from its snapshot.
    Restore {
        /// The snapshot to restore.
        snapshot: Snapshot,
        /// The node to restore onto (same node that holds the snapshot).
        node: u64,
        /// The backend that owns the snapshot.
        backend: String,
    },
}

/// A workload's recent traffic, the input that drives scale-to-zero decisions.
/// Sourced from the gateway; the reconcile loop treats it as opaque.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WorkloadActivity {
    /// Recent traffic (or unknown) — keep running, and **wake** if zeroed. The
    /// default, so the loop never sleeps a workload absent a real idle signal.
    #[default]
    Active,
    /// Idle past the scale-to-zero threshold — eligible to **sleep**.
    Idle,
}

/// Compute the actions to converge `workload` (running `spec`) from `observed`
/// to its desired replica count, honoring placement, the isolation requirement,
/// and the backend `policy`. Pure: no IO, fully unit-tested.
///
/// Rules: replicas are addressed by ordinal `0..replicas`. A *healthy* in-range
/// replica is kept. An out-of-range replica (scaled down) is **stopped**. An
/// *unhealthy* in-range replica is **stopped** and its ordinal relaunched —
/// unless the restart policy is `Never`, in which case it is left as a terminal
/// (completed) instance and not relaunched. Free ordinals are placed onto
/// eligible nodes; if capacity runs out, fewer launches are emitted.
pub fn reconcile_plan(
    workload: &ComputeWorkload,
    spec: &ComputeSpec,
    nodes: &[Node],
    policy: &BackendPolicy,
    observed: &[ObservedInstance],
    activity: WorkloadActivity,
    caps: &BTreeMap<String, Capabilities>,
) -> Vec<Action> {
    let desired = workload.replicas;
    let mut actions = Vec::new();

    // Scale-to-zero is in effect only when the workload opts in *and* the
    // replica's backend advertises the capability.
    let sleeps =
        |backend: &str| spec.scale_to_zero && caps.get(backend).is_some_and(|c| c.scale_to_zero);

    // Classify this workload's observed replicas by ordinal.
    let mut healthy: BTreeSet<u32> = BTreeSet::new();
    let mut terminal: BTreeSet<u32> = BTreeSet::new(); // Never + exited → done, don't relaunch
    let mut zeroed: BTreeSet<u32> = BTreeSet::new(); // scaled-to-zero → wake on activity, never relaunch
    for inst in observed
        .iter()
        .filter(|i| i.handle.workload == workload.name)
    {
        let ord = inst.handle.replica;
        if ord >= desired {
            // Out of range (also discards a Zero replica's snapshot — Stop is
            // idempotent and the driver forgets the state).
            actions.push(Action::Stop {
                handle: inst.handle.clone(),
            });
        } else if inst.phase == ReplicaPhase::Zero {
            zeroed.insert(ord);
            // Wake on activity; otherwise stay parked.
            if matches!(activity, WorkloadActivity::Active) {
                if let Some(snapshot) = inst.snapshot.clone() {
                    actions.push(Action::Restore {
                        snapshot,
                        node: inst.node,
                        backend: inst.backend.clone(),
                    });
                }
            }
        } else if inst.healthy {
            healthy.insert(ord);
            // Sleep on sustained idle (opt-in + capable backend).
            if matches!(activity, WorkloadActivity::Idle) && sleeps(&inst.backend) {
                actions.push(Action::Snapshot {
                    handle: inst.handle.clone(),
                });
            }
        } else if matches!(spec.restart, RestartPolicy::Never) {
            terminal.insert(ord); // run-to-completion: leave it, don't replace
        } else {
            actions.push(Action::Stop {
                handle: inst.handle.clone(),
            });
            // ordinal becomes free below → relaunched
        }
    }

    // Ordinals in range that need a (re)launch — excluding intentionally parked
    // (Zero) replicas, which wake via Restore rather than a fresh Launch.
    let need: Vec<u32> = (0..desired)
        .filter(|ord| !healthy.contains(ord) && !terminal.contains(ord) && !zeroed.contains(ord))
        .collect();
    if need.is_empty() {
        return actions;
    }

    // Place the needed count; zip ordinals with placements (a capacity shortfall
    // simply leaves the tail unplaced — the caller logs it).
    let placements = place_replicas(need.len() as u32, &workload.placement, spec, nodes, policy);
    for (ord, place) in need.iter().zip(placements) {
        actions.push(Action::Launch {
            workload: workload.name.clone(),
            replica: *ord,
            node: place.node,
            backend: place.backend,
        });
    }
    actions
}

// ---------------------------------------------------------------------------
// Reconcile driver (async — drives the backends to converge desired state)
// ---------------------------------------------------------------------------

/// The execution backends available to the reconcile loop, keyed by
/// [`ComputeBackend::id`].
pub type BackendRegistry = BTreeMap<String, Arc<dyn ComputeBackend>>;

/// Where the reconcile loop reads each workload's recent traffic to drive
/// scale-to-zero (sleep idle replicas / wake them on demand). The real source is
/// the gateway's per-workload activity, aggregated across the cluster;
/// [`AlwaysActive`] is the production-safe default until that lands — it never
/// sleeps a workload, so scale-to-zero stays inert.
#[async_trait]
pub trait ActivitySource: Send + Sync {
    /// The workload's current activity (queried once per reconcile pass).
    async fn activity(&self, workload: &str) -> WorkloadActivity;
}

/// The default [`ActivitySource`]: every workload is [`Active`](WorkloadActivity::Active),
/// so nothing is ever scaled to zero.
pub struct AlwaysActive;

#[async_trait]
impl ActivitySource for AlwaysActive {
    async fn activity(&self, _workload: &str) -> WorkloadActivity {
        WorkloadActivity::Active
    }
}

/// What one reconcile pass did (for logging + tests).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Replicas launched this pass.
    pub launched: usize,
    /// Replicas stopped this pass.
    pub stopped: usize,
    /// Replicas slept (snapshotted + stopped → Zero) this pass.
    pub slept: usize,
    /// Replicas woken (restored from a snapshot) this pass.
    pub woke: usize,
    /// Per-action failures (the pass continues past them; retried next tick).
    pub errors: Vec<String>,
}

/// One reconcile pass: for every workload, refresh replica health, compute the
/// plan ([`reconcile_plan`]), and execute it against the chosen backends —
/// launching/stopping replicas and persisting their observed state (which the
/// gateway reads as the upstream pool). Per-action failures are collected (not
/// fatal) so one bad workload can't stall the rest; a top-level KV failure
/// aborts the pass. The caller leader-gates this (cron-style).
///
/// For now the chosen backend is invoked locally (the leader also runs it).
/// Cross-node dispatch via messaging is a later refinement.
pub async fn reconcile_once(
    deploy: &DeployStore,
    backends: &BackendRegistry,
    nodes: &[Node],
    policy: &BackendPolicy,
    activity: &dyn ActivitySource,
) -> Result<ReconcileReport, crate::error::DeployError> {
    let mut report = ReconcileReport::default();
    // Per-backend capabilities (the planner gates scale-to-zero on them).
    let caps: BTreeMap<String, Capabilities> = backends
        .iter()
        .map(|(id, b)| (id.clone(), b.capabilities()))
        .collect();
    for workload in deploy.list_compute_workloads().await? {
        let Some(spec) = deploy.get_compute_spec(&workload.active).await? else {
            report
                .errors
                .push(format!("{}: active spec missing", workload.name));
            continue;
        };

        // Observed replica state + a health refresh (skipping parked Zero
        // replicas — they're intentionally down).
        let mut observed = deploy.list_replica_states(&workload.name).await?;
        for state in &mut observed {
            if state.phase == ReplicaPhase::Zero {
                continue;
            }
            if let Some(backend) = backends.get(&state.backend) {
                if let Ok(health) = backend.health(&state.handle).await {
                    state.healthy = matches!(health, Health::Healthy);
                }
            }
        }

        let workload_activity = activity.activity(&workload.name).await;
        for action in reconcile_plan(
            &workload,
            &spec,
            nodes,
            policy,
            &observed,
            workload_activity,
            &caps,
        ) {
            match action {
                Action::Launch {
                    workload: wl,
                    replica,
                    node,
                    backend,
                } => {
                    let Some(b) = backends.get(&backend) else {
                        report
                            .errors
                            .push(format!("{wl}/{replica}: no backend {backend:?}"));
                        continue;
                    };
                    let node_region = region_of_node(nodes, node);
                    match launch_one(b.as_ref(), &wl, replica, node, node_region, &spec).await {
                        Ok(state) => match deploy.set_replica_state(&state).await {
                            Ok(()) => report.launched += 1,
                            Err(e) => report.errors.push(format!("{wl}/{replica}: persist: {e}")),
                        },
                        Err(e) => report.errors.push(format!("{wl}/{replica}: launch: {e}")),
                    }
                }
                Action::Stop { handle } => {
                    if let Some(b) = observed
                        .iter()
                        .find(|o| o.handle == handle)
                        .and_then(|o| backends.get(&o.backend))
                    {
                        if let Err(e) = b.stop(&handle).await {
                            report
                                .errors
                                .push(format!("{}/{}: stop: {e}", handle.workload, handle.replica));
                        }
                    }
                    match deploy
                        .delete_replica_state(&handle.workload, handle.replica)
                        .await
                    {
                        Ok(()) => report.stopped += 1,
                        Err(e) => report.errors.push(format!(
                            "{}/{}: forget: {e}",
                            handle.workload, handle.replica
                        )),
                    }
                }
                Action::Snapshot { handle } => {
                    let Some(obs) = observed.iter().find(|o| o.handle == handle).cloned() else {
                        continue; // vanished between plan + execute
                    };
                    let Some(b) = backends.get(&obs.backend) else {
                        report.errors.push(format!(
                            "{}/{}: no backend {:?}",
                            handle.workload, handle.replica, obs.backend
                        ));
                        continue;
                    };
                    match b.snapshot(&handle).await {
                        // Park it: persist the Zero phase carrying the snapshot
                        // (the backend's `snapshot` already stopped the replica).
                        Ok(Some(snapshot)) => {
                            let parked = ObservedInstance {
                                healthy: false,
                                phase: ReplicaPhase::Zero,
                                snapshot: Some(snapshot),
                                ..obs
                            };
                            match deploy.set_replica_state(&parked).await {
                                Ok(()) => report.slept += 1,
                                Err(e) => report.errors.push(format!(
                                    "{}/{}: persist zero: {e}",
                                    handle.workload, handle.replica
                                )),
                            }
                        }
                        // Backend declined (e.g. not running) — leave it as is.
                        Ok(None) => {}
                        Err(e) => report.errors.push(format!(
                            "{}/{}: snapshot: {e}",
                            handle.workload, handle.replica
                        )),
                    }
                }
                Action::Restore {
                    snapshot,
                    node,
                    backend,
                } => {
                    let Some(b) = backends.get(&backend) else {
                        report.errors.push(format!(
                            "{}/{}: no backend {backend:?}",
                            snapshot.workload, snapshot.replica
                        ));
                        continue;
                    };
                    match b.restore(&snapshot).await {
                        Ok(instance) => {
                            let state = ObservedInstance {
                                handle: instance.handle,
                                node,
                                backend: backend.clone(),
                                endpoint: instance.endpoint,
                                region: region_of_node(nodes, node),
                                healthy: true,
                                phase: ReplicaPhase::Running,
                                snapshot: None,
                            };
                            match deploy.set_replica_state(&state).await {
                                Ok(()) => report.woke += 1,
                                Err(e) => report.errors.push(format!(
                                    "{}/{}: persist running: {e}",
                                    snapshot.workload, snapshot.replica
                                )),
                            }
                        }
                        Err(e) => report.errors.push(format!(
                            "{}/{}: restore: {e}",
                            snapshot.workload, snapshot.replica
                        )),
                    }
                }
            }
        }
    }
    Ok(report)
}

/// The region of node `id` in `nodes`, for tagging a replica's endpoint (FA-8).
fn region_of_node(nodes: &[Node], id: u64) -> Option<String> {
    nodes
        .iter()
        .find(|n| n.id == id)
        .and_then(|n| n.region.clone())
}

/// Materialize + launch one replica, returning its observed state.
async fn launch_one(
    backend: &dyn ComputeBackend,
    workload: &str,
    replica: u32,
    node: u64,
    node_region: Option<String>,
    spec: &ComputeSpec,
) -> Result<ObservedInstance, BackendError> {
    let artifact = backend.materialize(spec).await?;
    let instance = backend
        .launch(&LaunchRequest {
            workload: workload.to_string(),
            replica,
            spec: spec.clone(),
            artifact,
        })
        .await?;
    Ok(ObservedInstance {
        handle: instance.handle,
        node,
        backend: backend.id().to_string(),
        endpoint: instance.endpoint,
        region: node_region,
        healthy: true,
        phase: ReplicaPhase::Running,
        snapshot: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(vcpus: u32, mem_mib: u32) -> ComputeSpec {
        ComputeSpec {
            version: 1,
            rootfs: "r".repeat(64),
            kernel: "k".repeat(64),
            kernel_cmdline: None,
            vcpus,
            mem_mib,
            entrypoint: vec![],
            env: BTreeMap::new(),
            port: 80,
            restart: RestartPolicy::Always,
            scale_to_zero: false,
            volumes: vec![],
            isolation: IsolationRequirement::Trusted,
            prefer_backend: None,
        }
    }

    fn workload(replicas: u32, placement: PlacementConstraints) -> ComputeWorkload {
        ComputeWorkload {
            version: 1,
            name: "w".into(),
            active: "h".into(),
            replicas,
            placement,
        }
    }

    fn node(
        id: u64,
        region: &str,
        cpus: u32,
        mem: u32,
        backends: &[(&str, IsolationClass)],
    ) -> Node {
        Node {
            id,
            region: Some(region.into()),
            labels: BTreeMap::new(),
            free_vcpus: cpus,
            free_mem_mib: mem,
            backends: backends
                .iter()
                .map(|(id, iso)| BackendKind {
                    id: (*id).to_string(),
                    isolation: *iso,
                })
                .collect(),
        }
    }

    fn vmm(id: u64, region: &str, cpus: u32, mem: u32) -> Node {
        node(id, region, cpus, mem, &[("vmm", IsolationClass::VmKvm)])
    }

    fn container(id: u64, region: &str, cpus: u32, mem: u32) -> Node {
        node(
            id,
            region,
            cpus,
            mem,
            &[("container", IsolationClass::Namespace)],
        )
    }

    #[test]
    fn isolation_class_strength_and_satisfaction() {
        assert!(IsolationClass::VmKvm.is_strong());
        assert!(IsolationClass::Platform.is_strong());
        assert!(!IsolationClass::Namespace.is_strong());
        assert!(!IsolationClass::Container.is_strong());
        // Untrusted needs strong; trusted accepts any.
        assert!(IsolationClass::Namespace.satisfies(IsolationRequirement::Trusted));
        assert!(!IsolationClass::Namespace.satisfies(IsolationRequirement::Untrusted));
        assert!(IsolationClass::VmKvm.satisfies(IsolationRequirement::Untrusted));
    }

    #[test]
    fn endpoint_url() {
        assert_eq!(
            Endpoint {
                scheme: Scheme::Http,
                host: "10.0.0.5".into(),
                port: 8080
            }
            .url(),
            "http://10.0.0.5:8080"
        );
    }

    #[test]
    fn policy_permits_force_forbid_allow() {
        assert!(BackendPolicy::default().permits("vmm"));
        let forbid = BackendPolicy {
            forbid: vec!["container".into()],
            ..Default::default()
        };
        assert!(forbid.permits("vmm"));
        assert!(!forbid.permits("container"));
        let allow = BackendPolicy {
            allow: Some(vec!["vmm".into()]),
            ..Default::default()
        };
        assert!(allow.permits("vmm"));
        assert!(!allow.permits("docker"));
        let force = BackendPolicy {
            force: Some("vmm".into()),
            forbid: vec!["vmm".into()],
            ..Default::default()
        };
        assert!(force.permits("vmm"), "force overrides forbid");
        assert!(!force.permits("container"));
    }

    #[test]
    fn worst_fit_spreads_and_picks_a_backend() {
        let nodes = vec![vmm(1, "eu", 4, 4096), vmm(2, "eu", 4, 4096)];
        let placed = place_replicas(
            2,
            &PlacementConstraints::default(),
            &spec(1, 256),
            &nodes,
            &BackendPolicy::default(),
        );
        assert_eq!(placed.len(), 2);
        assert_ne!(placed[0].node, placed[1].node, "worst-fit → one each");
        assert!(placed.iter().all(|p| p.backend == "vmm"));
    }

    #[test]
    fn capacity_shortfall_returns_fewer() {
        let nodes = vec![vmm(1, "eu", 4, 8192)];
        let placed = place_replicas(
            5,
            &PlacementConstraints::default(),
            &spec(2, 256),
            &nodes,
            &BackendPolicy::default(),
        );
        assert_eq!(placed.len(), 2, "only two 2-vCPU replicas fit");
    }

    #[test]
    fn untrusted_skips_shared_kernel_nodes() {
        // A container-only node can't satisfy an untrusted workload.
        let nodes = vec![container(1, "eu", 8, 8192)];
        let mut s = spec(1, 128);
        s.isolation = IsolationRequirement::Untrusted;
        assert!(place_replicas(
            2,
            &PlacementConstraints::default(),
            &s,
            &nodes,
            &BackendPolicy::default()
        )
        .is_empty());
        // A vmm node satisfies it.
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let placed = place_replicas(
            2,
            &PlacementConstraints::default(),
            &s,
            &nodes,
            &BackendPolicy::default(),
        );
        assert_eq!(placed.len(), 2);
        assert!(placed.iter().all(|p| p.backend == "vmm"));
    }

    #[test]
    fn strict_posture_skips_shared_kernel_even_for_trusted_workload() {
        // A Trusted (possibly misclassified) workload normally lands
        // on a shared-kernel container node...
        let nodes = vec![container(1, "eu", 8, 8192)];
        let s = spec(1, 128); // default isolation = Trusted
        assert_eq!(
            place_replicas(
                2,
                &PlacementConstraints::default(),
                &s,
                &nodes,
                &BackendPolicy::default()
            )
            .len(),
            2,
            "a trusted workload uses the shared-kernel node by default"
        );
        // ...but the strict posture makes shared-kernel ineligible regardless.
        let strict = BackendPolicy {
            require_strong_isolation: true,
            ..Default::default()
        };
        assert!(
            place_replicas(2, &PlacementConstraints::default(), &s, &nodes, &strict).is_empty(),
            "strict posture refuses shared-kernel even for a trusted workload"
        );
        // A vmm (strong) node still satisfies it under the strict posture.
        let vnodes = vec![vmm(1, "eu", 8, 8192)];
        assert_eq!(
            place_replicas(2, &PlacementConstraints::default(), &s, &vnodes, &strict).len(),
            2
        );
    }

    #[test]
    fn prefer_backend_is_honored_when_eligible() {
        let n = node(
            1,
            "eu",
            8,
            8192,
            &[
                ("vmm", IsolationClass::VmKvm),
                ("container", IsolationClass::Namespace),
            ],
        );
        let mut s = spec(1, 128);
        s.prefer_backend = Some("container".into());
        let placed = place_replicas(
            1,
            &PlacementConstraints::default(),
            &s,
            &[n],
            &BackendPolicy::default(),
        );
        assert_eq!(placed[0].backend, "container");
    }

    #[test]
    fn policy_force_overrides_preference() {
        let n = node(
            1,
            "eu",
            8,
            8192,
            &[
                ("vmm", IsolationClass::VmKvm),
                ("container", IsolationClass::Namespace),
            ],
        );
        let mut s = spec(1, 128);
        s.prefer_backend = Some("container".into());
        let policy = BackendPolicy {
            force: Some("vmm".into()),
            ..Default::default()
        };
        let placed = place_replicas(1, &PlacementConstraints::default(), &s, &[n], &policy);
        assert_eq!(
            placed[0].backend, "vmm",
            "policy force beats the spec preference"
        );
    }

    fn observed(workload: &str, replica: u32, node: u64, healthy: bool) -> ObservedInstance {
        ObservedInstance {
            handle: InstanceHandle {
                workload: workload.into(),
                replica,
                backend_ref: format!("ref-{replica}"),
            },
            node,
            backend: "vmm".into(),
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: "10.0.0.2".into(),
                port: 80,
            },
            region: None,
            healthy,
            phase: ReplicaPhase::Running,
            snapshot: None,
        }
    }

    /// A scaled-to-zero observed replica (phase `Zero` + a snapshot to wake from).
    fn zeroed(workload: &str, replica: u32, node: u64) -> ObservedInstance {
        let mut o = observed(workload, replica, node, false);
        o.phase = ReplicaPhase::Zero;
        o.snapshot = Some(Snapshot {
            workload: workload.into(),
            replica,
            data_ref: format!("snap-{replica}"),
        });
        o
    }

    /// Wrapper for the baseline tests: `Active` activity + no scale-to-zero
    /// capable backends, so the sleep/wake paths stay inert (behavior unchanged).
    fn plan(
        wl: &ComputeWorkload,
        spec: &ComputeSpec,
        nodes: &[Node],
        policy: &BackendPolicy,
        observed: &[ObservedInstance],
    ) -> Vec<Action> {
        reconcile_plan(
            wl,
            spec,
            nodes,
            policy,
            observed,
            WorkloadActivity::Active,
            &BTreeMap::new(),
        )
    }

    /// A capability map advertising scale-to-zero for the `vmm` backend (the id
    /// the `observed`/`zeroed` helpers use).
    fn s2z_caps() -> BTreeMap<String, Capabilities> {
        let mut m = BTreeMap::new();
        m.insert(
            "vmm".to_string(),
            Capabilities {
                isolation: IsolationClass::VmKvm,
                scale_to_zero: true,
                persistent_volumes: false,
                max_vcpus: None,
                max_mem_mib: None,
            },
        );
        m
    }

    /// A spec that opts into scale-to-zero.
    fn s2z_spec() -> ComputeSpec {
        let mut s = spec(1, 256);
        s.scale_to_zero = true;
        s
    }

    #[test]
    fn idle_running_replica_is_snapshotted_when_scale_to_zero() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let obs = vec![observed("w", 0, 1, true)];
        let actions = reconcile_plan(
            &workload(1, Default::default()),
            &s2z_spec(),
            &nodes,
            &BackendPolicy::default(),
            &obs,
            WorkloadActivity::Idle,
            &s2z_caps(),
        );
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], Action::Snapshot { handle } if handle.replica == 0));
    }

    #[test]
    fn idle_replica_not_snapshotted_without_opt_in_or_capability() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let obs = vec![observed("w", 0, 1, true)];
        // Opted in, but the backend isn't capable → no snapshot.
        let no_cap = reconcile_plan(
            &workload(1, Default::default()),
            &s2z_spec(),
            &nodes,
            &BackendPolicy::default(),
            &obs,
            WorkloadActivity::Idle,
            &BTreeMap::new(),
        );
        assert!(no_cap.is_empty(), "no capable backend: {no_cap:?}");
        // Capable backend, but the spec didn't opt in → no snapshot.
        let no_opt = reconcile_plan(
            &workload(1, Default::default()),
            &spec(1, 256),
            &nodes,
            &BackendPolicy::default(),
            &obs,
            WorkloadActivity::Idle,
            &s2z_caps(),
        );
        assert!(no_opt.is_empty(), "not opted in: {no_opt:?}");
    }

    #[test]
    fn zeroed_replica_wakes_on_activity() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let obs = vec![zeroed("w", 0, 1)];
        let actions = reconcile_plan(
            &workload(1, Default::default()),
            &s2z_spec(),
            &nodes,
            &BackendPolicy::default(),
            &obs,
            WorkloadActivity::Active,
            &s2z_caps(),
        );
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(&actions[0], Action::Restore { snapshot, node, .. } if snapshot.replica == 0 && *node == 1)
        );
    }

    #[test]
    fn zeroed_replica_stays_parked_when_idle_and_is_not_relaunched() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let obs = vec![zeroed("w", 0, 1)];
        let actions = reconcile_plan(
            &workload(1, Default::default()),
            &s2z_spec(),
            &nodes,
            &BackendPolicy::default(),
            &obs,
            WorkloadActivity::Idle,
            &s2z_caps(),
        );
        // Idle → no restore, and crucially no Launch (the parked ordinal is not
        // treated as a missing replica).
        assert!(
            actions.is_empty(),
            "parked replica left untouched: {actions:?}"
        );
    }

    #[test]
    fn out_of_range_zeroed_replica_is_stopped_not_restored() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let obs = vec![zeroed("w", 1, 1)]; // ordinal 1, desired 1 → out of range
        let actions = reconcile_plan(
            &workload(1, Default::default()),
            &s2z_spec(),
            &nodes,
            &BackendPolicy::default(),
            &obs,
            WorkloadActivity::Active,
            &s2z_caps(),
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Stop { handle } if handle.replica == 1)));
        assert!(
            !actions.iter().any(|a| matches!(a, Action::Restore { .. })),
            "out-of-range parked replica is stopped, not restored"
        );
    }

    #[test]
    fn reconcile_scales_up_from_nothing() {
        let nodes = vec![vmm(1, "eu", 8, 8192), vmm(2, "eu", 8, 8192)];
        let actions = plan(
            &workload(2, Default::default()),
            &spec(1, 256),
            &nodes,
            &BackendPolicy::default(),
            &[],
        );
        let launches: Vec<u32> = actions
            .iter()
            .filter_map(|a| match a {
                Action::Launch { replica, .. } => Some(*replica),
                _ => None,
            })
            .collect();
        assert_eq!(launches, vec![0, 1], "both ordinals launched");
        assert!(!actions.iter().any(|a| matches!(a, Action::Stop { .. })));
    }

    #[test]
    fn reconcile_is_noop_when_at_desired() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let obs = vec![observed("w", 0, 1, true), observed("w", 1, 1, true)];
        let actions = plan(
            &workload(2, Default::default()),
            &spec(1, 256),
            &nodes,
            &BackendPolicy::default(),
            &obs,
        );
        assert!(actions.is_empty(), "already converged");
    }

    #[test]
    fn reconcile_scales_down_stops_out_of_range() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let obs = vec![
            observed("w", 0, 1, true),
            observed("w", 1, 1, true),
            observed("w", 2, 1, true),
        ];
        let actions = plan(
            &workload(2, Default::default()),
            &spec(1, 256),
            &nodes,
            &BackendPolicy::default(),
            &obs,
        );
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], Action::Stop { handle } if handle.replica == 2));
    }

    #[test]
    fn reconcile_replaces_unhealthy_when_restart_always() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let obs = vec![observed("w", 0, 1, true), observed("w", 1, 1, false)];
        let actions = plan(
            &workload(2, Default::default()),
            &spec(1, 256),
            &nodes,
            &BackendPolicy::default(),
            &obs,
        );
        // ordinal 1 is stopped AND relaunched.
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Stop { handle } if handle.replica == 1)));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Launch { replica: 1, .. })));
    }

    #[test]
    fn reconcile_leaves_terminal_replicas_for_restart_never() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let mut s = spec(1, 256);
        s.restart = RestartPolicy::Never;
        let obs = vec![observed("w", 0, 1, true), observed("w", 1, 1, false)];
        let actions = plan(
            &workload(2, Default::default()),
            &s,
            &nodes,
            &BackendPolicy::default(),
            &obs,
        );
        // The exited (unhealthy) Never replica is left alone — no stop, no relaunch.
        assert!(
            actions.is_empty(),
            "run-to-completion replica is terminal: {actions:?}"
        );
    }

    #[test]
    fn reconcile_only_touches_its_own_workload() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let obs = vec![observed("other", 0, 1, true), observed("other", 5, 1, true)];
        let actions = plan(
            &workload(1, Default::default()),
            &spec(1, 256),
            &nodes,
            &BackendPolicy::default(),
            &obs,
        );
        // Launches ordinal 0 for "w"; ignores "other"'s replicas entirely.
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(&actions[0], Action::Launch { workload, replica: 0, .. } if workload == "w")
        );
    }

    // A trivial in-memory backend, exercising the trait end-to-end.
    struct FakeBackend;

    #[async_trait]
    impl ComputeBackend for FakeBackend {
        fn id(&self) -> &'static str {
            "fake"
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                isolation: IsolationClass::Namespace,
                scale_to_zero: false,
                persistent_volumes: false,
                max_vcpus: None,
                max_mem_mib: None,
            }
        }
        async fn materialize(&self, _spec: &ComputeSpec) -> Result<Artifact, BackendError> {
            Ok(Artifact::Image {
                reference: "img:latest".into(),
            })
        }
        async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
            Ok(Instance {
                handle: InstanceHandle {
                    workload: req.workload.clone(),
                    replica: req.replica,
                    backend_ref: format!("fake-{}", req.replica),
                },
                endpoint: Endpoint {
                    scheme: Scheme::Http,
                    host: "127.0.0.1".into(),
                    port: 8080,
                },
            })
        }
        async fn stop(&self, _handle: &InstanceHandle) -> Result<(), BackendError> {
            Ok(())
        }
        async fn health(&self, _handle: &InstanceHandle) -> Result<Health, BackendError> {
            Ok(Health::Healthy)
        }
    }

    #[tokio::test]
    async fn fake_backend_round_trips_through_the_trait() {
        let backend: Box<dyn ComputeBackend> = Box::new(FakeBackend);
        assert_eq!(backend.id(), "fake");
        let s = spec(1, 128);
        let artifact = backend.materialize(&s).await.unwrap();
        let inst = backend
            .launch(&LaunchRequest {
                workload: "w".into(),
                replica: 0,
                spec: s,
                artifact,
            })
            .await
            .unwrap();
        assert_eq!(inst.endpoint.url(), "http://127.0.0.1:8080");
        assert_eq!(backend.health(&inst.handle).await.unwrap(), Health::Healthy);
        backend.stop(&inst.handle).await.unwrap();
        // Default snapshot/restore: unsupported.
        assert!(backend.snapshot(&inst.handle).await.unwrap().is_none());
    }

    /// A do-nothing blob backend so the driver test can build a `DeployStore`
    /// (the reconcile loop only touches the KV-backed methods).
    struct NullStorage;

    #[async_trait]
    impl crate::Storage for NullStorage {
        async fn get(&self, _: &str) -> Result<crate::GetObject, crate::StorageError> {
            Err(crate::StorageError::NotFound(String::new()))
        }
        async fn get_range(
            &self,
            _: &str,
            _: u64,
            _: Option<u64>,
        ) -> Result<crate::GetObject, crate::StorageError> {
            Err(crate::StorageError::NotFound(String::new()))
        }
        async fn put(
            &self,
            _: &str,
            _: crate::ByteStream,
            _: crate::PutMeta,
        ) -> Result<crate::ObjectMeta, crate::StorageError> {
            Err(crate::StorageError::unsupported("null"))
        }
        async fn head(&self, _: &str) -> Result<crate::ObjectMeta, crate::StorageError> {
            Err(crate::StorageError::NotFound(String::new()))
        }
        async fn delete(&self, _: &str) -> Result<(), crate::StorageError> {
            Ok(())
        }
        async fn list(&self, _: &str) -> Result<Vec<crate::ObjectMeta>, crate::StorageError> {
            Ok(Vec::new())
        }
    }

    fn fake_node() -> Node {
        Node {
            id: 1,
            region: Some("eu".into()),
            labels: BTreeMap::new(),
            free_vcpus: 8,
            free_mem_mib: 8192,
            backends: vec![BackendKind {
                id: "fake".into(),
                isolation: IsolationClass::Namespace,
            }],
        }
    }

    /// A scale-to-zero-capable backend: `snapshot` always parks (returns a
    /// snapshot), `restore` brings it back. Reuses id `"fake"` (the node's
    /// backend) so placement still works.
    struct S2zBackend;

    #[async_trait]
    impl ComputeBackend for S2zBackend {
        fn id(&self) -> &'static str {
            "fake"
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                isolation: IsolationClass::Namespace,
                scale_to_zero: true,
                persistent_volumes: false,
                max_vcpus: None,
                max_mem_mib: None,
            }
        }
        async fn materialize(&self, _spec: &ComputeSpec) -> Result<Artifact, BackendError> {
            Ok(Artifact::Image {
                reference: "img:latest".into(),
            })
        }
        async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
            Ok(Instance {
                handle: InstanceHandle {
                    workload: req.workload.clone(),
                    replica: req.replica,
                    backend_ref: format!("fake-{}", req.replica),
                },
                endpoint: Endpoint {
                    scheme: Scheme::Http,
                    host: "127.0.0.1".into(),
                    port: 8080,
                },
            })
        }
        async fn stop(&self, _handle: &InstanceHandle) -> Result<(), BackendError> {
            Ok(())
        }
        async fn health(&self, _handle: &InstanceHandle) -> Result<Health, BackendError> {
            Ok(Health::Healthy)
        }
        async fn snapshot(
            &self,
            handle: &InstanceHandle,
        ) -> Result<Option<Snapshot>, BackendError> {
            Ok(Some(Snapshot {
                workload: handle.workload.clone(),
                replica: handle.replica,
                data_ref: format!("snap-{}", handle.replica),
            }))
        }
        async fn restore(&self, snapshot: &Snapshot) -> Result<Instance, BackendError> {
            Ok(Instance {
                handle: InstanceHandle {
                    workload: snapshot.workload.clone(),
                    replica: snapshot.replica,
                    backend_ref: format!("restored-{}", snapshot.replica),
                },
                endpoint: Endpoint {
                    scheme: Scheme::Http,
                    host: "127.0.0.1".into(),
                    port: 8080,
                },
            })
        }
    }

    /// An [`ActivitySource`] that reports the same activity for every workload.
    struct FixedActivity(WorkloadActivity);

    #[async_trait]
    impl ActivitySource for FixedActivity {
        async fn activity(&self, _workload: &str) -> WorkloadActivity {
            self.0
        }
    }

    #[tokio::test]
    async fn reconcile_sleeps_idle_replica_then_wakes_it_on_activity() {
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(crate::kv::MemoryKv::new()));
        let mut s = spec(1, 128);
        s.scale_to_zero = true;
        let hash = deploy.put_compute_spec(&s).await.unwrap();
        deploy
            .set_compute_workload(&ComputeWorkload {
                version: 1,
                name: "w".into(),
                active: hash,
                replicas: 1,
                placement: Default::default(),
            })
            .await
            .unwrap();
        let mut backends: BackendRegistry = BTreeMap::new();
        backends.insert("fake".into(), Arc::new(S2zBackend));
        let nodes = vec![fake_node()];
        let policy = BackendPolicy::default();

        // Active → launch the replica.
        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &FixedActivity(WorkloadActivity::Active),
        )
        .await
        .unwrap();
        assert_eq!(r.launched, 1, "{:?}", r.errors);

        // Idle → sleep it: snapshot + park in Zero.
        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &FixedActivity(WorkloadActivity::Idle),
        )
        .await
        .unwrap();
        assert_eq!(r.slept, 1, "{:?}", r.errors);
        let parked = deploy.list_replica_states("w").await.unwrap();
        assert_eq!(parked.len(), 1);
        assert_eq!(parked[0].phase, ReplicaPhase::Zero);
        assert!(parked[0].snapshot.is_some(), "carries its snapshot");
        assert!(!parked[0].healthy);

        // Idle again → stays parked (no churn).
        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &FixedActivity(WorkloadActivity::Idle),
        )
        .await
        .unwrap();
        assert_eq!((r.slept, r.woke, r.launched), (0, 0, 0), "{:?}", r.errors);

        // Active → wake it: restore → Running.
        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &FixedActivity(WorkloadActivity::Active),
        )
        .await
        .unwrap();
        assert_eq!(r.woke, 1, "{:?}", r.errors);
        let woken = deploy.list_replica_states("w").await.unwrap();
        assert_eq!(woken.len(), 1);
        assert_eq!(woken[0].phase, ReplicaPhase::Running);
        assert!(woken[0].snapshot.is_none());
        assert!(woken[0].healthy);
    }

    #[tokio::test]
    async fn reconcile_once_launches_converges_then_stops() {
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(crate::kv::MemoryKv::new()));
        let s = spec(1, 128);
        let hash = deploy.put_compute_spec(&s).await.unwrap();
        deploy
            .set_compute_workload(&ComputeWorkload {
                version: 1,
                name: "w".into(),
                active: hash.clone(),
                replicas: 2,
                placement: Default::default(),
            })
            .await
            .unwrap();
        let nodes = vec![fake_node()];
        let mut backends: BackendRegistry = BTreeMap::new();
        backends.insert("fake".into(), Arc::new(FakeBackend));
        let policy = BackendPolicy::default();

        // Pass 1: launches both replicas + persists their state.
        let r = reconcile_once(&deploy, &backends, &nodes, &policy, &AlwaysActive)
            .await
            .unwrap();
        assert_eq!((r.launched, r.stopped), (2, 0), "{:?}", r.errors);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        let states = deploy.list_replica_states("w").await.unwrap();
        assert_eq!(states.len(), 2);
        // FA-8: each launched replica inherits its node's region tag.
        assert!(
            states.iter().all(|s| s.region.as_deref() == Some("eu")),
            "replicas carry their node's region"
        );

        // Pass 2: already converged (FakeBackend reports Healthy) → no-op.
        let r2 = reconcile_once(&deploy, &backends, &nodes, &policy, &AlwaysActive)
            .await
            .unwrap();
        assert_eq!((r2.launched, r2.stopped), (0, 0));

        // Scale to zero → both stopped + state cleared.
        deploy
            .set_compute_workload(&ComputeWorkload {
                version: 1,
                name: "w".into(),
                active: hash,
                replicas: 0,
                placement: Default::default(),
            })
            .await
            .unwrap();
        let r3 = reconcile_once(&deploy, &backends, &nodes, &policy, &AlwaysActive)
            .await
            .unwrap();
        assert_eq!(r3.stopped, 2);
        assert!(deploy.list_replica_states("w").await.unwrap().is_empty());
    }
}
