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
use crate::project::ProjectRef;

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
        matches!(self, Self::VmKvm | Self::Platform)
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

impl Scheme {
    /// The lowercase URL-scheme token (matches the serde `rename_all`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
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
        format!("{}://{}:{}", self.scheme, self.host, self.port)
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
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// The backend doesn't support the requested operation.
    #[error("operation not supported by this backend")]
    Unsupported,
    /// Staging the artifact failed.
    #[error("materialize: {0}")]
    Materialize(String),
    /// Launching the replica failed.
    #[error("launch: {0}")]
    Launch(String),
    /// Stopping the replica failed.
    #[error("stop: {0}")]
    Stop(String),
    /// Any other failure.
    #[error("{0}")]
    Other(String),
}

/// A pluggable compute execution backend (VMM / container / cloudflare / docker).
///
/// The control plane only ever sees [`Instance`]/[`Endpoint`]; whether the
/// backend runs the workload directly (VMM, container) or delegates to a
/// platform/daemon (cloudflare, docker) is internal.
/// The buffered result of running a one-shot command inside a running workload
/// replica (`ComputeBackend::exec`). Non-streaming: stdout/stderr are captured to
/// completion. `exit_code` is the command's status (128+signal if it was killed).
#[derive(Debug, Clone)]
pub struct ExecOutput {
    /// The command's exit status (128 + signal number if terminated by a signal).
    pub exit_code: i32,
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
}

/// Why an operator [`ComputeExec::exec`] failed (distinct from a backend launch
/// error — this layer adds "no replica to target" and "backend can't exec").
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// No running replica of the workload to exec inside.
    #[error("workload {0:?} has no running replica to exec in")]
    NoReplica(String),
    /// The workload's backend doesn't support exec (VM / edge backends).
    #[error("the {0} backend does not support exec")]
    Unsupported(String),
    /// Any other failure (backend error, resolution failure, …).
    #[error("exec failed: {0}")]
    Other(String),
}

/// The operator-facing "run a command inside a running workload" capability
/// (docker-exec style), backing `POST /api/compute/{name}/exec` and `boatramp
/// compute exec`. The node implementation resolves a workload's running replica,
/// selects its backend, and calls [`ComputeBackend::exec`]; only the shared-kernel
/// backends (native `container`, remote `docker`) support it. Gated by the
/// `allow_compute_exec` security posture at the API.
#[async_trait]
pub trait ComputeExec: Send + Sync {
    /// Run `argv` (feeding `stdin` when present) inside a running replica of
    /// `workload` in `project`, returning its buffered output.
    async fn exec(
        &self,
        project: &str,
        workload: &str,
        argv: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<ExecOutput, ExecError>;
}

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

    /// Run a one-shot command **inside** a running replica (docker-exec style) and
    /// return its buffered output — for operator ops (migrations, `pg_dump`, debug).
    /// `stdin` is fed to the command's standard input when present. Only the
    /// shared-kernel backends that can re-enter a running container implement it
    /// (native `container` via `setns`, remote `docker` via the exec API); the
    /// VM/edge backends return [`BackendError::Unsupported`]. The caller gates this
    /// behind the `allow_compute_exec` security posture.
    async fn exec(
        &self,
        _handle: &InstanceHandle,
        _argv: &[String],
        _stdin: Option<&[u8]>,
    ) -> Result<ExecOutput, BackendError> {
        Err(BackendError::Unsupported)
    }

    /// List this backend's persistent volumes (the host-side backing for a
    /// spec's [`VolumeRef`]s). Only the backends that own an on-node volume
    /// directory implement it (the native `container` backend, under
    /// `<data_dir>/compute/volumes/<name>`); the rest return the empty default,
    /// so a listing across a mixed fleet simply omits them. Backs the operator
    /// `GET /api/compute/volumes` volume-reclamation surface.
    async fn list_volumes(&self) -> Result<Vec<VolumeInfo>, BackendError> {
        Ok(Vec::new())
    }

    /// Remove the backing for persistent volume `name`, returning whether it
    /// existed. Only the backends that own an on-node volume directory implement
    /// it (native `container`); the rest return [`BackendError::Unsupported`].
    /// The caller (the node volume capability) refuses to remove a volume still
    /// referenced by a registered workload's spec unless forced — see
    /// [`ComputeVolumes`]. Backs `DELETE /api/compute/volumes/{name}`.
    async fn remove_volume(&self, _name: &str) -> Result<bool, BackendError> {
        Err(BackendError::Unsupported)
    }
}

/// A persistent volume as seen by an operator listing (`GET /api/compute/volumes`
/// / `boatramp compute volume ls`): the volume `name` (which backs the on-node
/// directory `<data_dir>/compute/volumes/<name>`) and its total on-disk size in
/// bytes. Whether the volume is still referenced by a registered workload's spec
/// (in use vs orphaned) is decided one layer up, by [`ComputeVolumes`], not by the
/// backend, which only sees the on-disk directories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeInfo {
    /// The volume name (the single path component under `.../compute/volumes/`).
    pub name: String,
    /// The volume's total on-disk size in bytes (summed recursively).
    pub size_bytes: u64,
}

/// Why a [`ComputeVolumes`] operation failed. Distinct from a raw
/// [`BackendError`]: this layer adds the "still in use" refusal (a volume a
/// registered workload's spec still mounts) and "no volume-capable backend".
#[derive(Debug, thiserror::Error)]
pub enum VolumeError {
    /// The volume is still referenced by a registered workload's active spec, so
    /// removing it could corrupt a running/relaunching replica. `compute rm` the
    /// workload first, or force the removal.
    #[error("volume {0:?} is in use by a registered workload")]
    InUse(String),
    /// No backend on this node backs persistent volumes (so nothing to list/remove).
    #[error("no volume-capable backend on this node")]
    Unsupported,
    /// Any other failure (backend error, store read failure, …).
    #[error("volume operation failed: {0}")]
    Other(String),
}

/// The operator-facing persistent-volume reclamation capability, backing
/// `GET /api/compute/volumes` + `DELETE /api/compute/volumes/{name}` and the
/// `boatramp compute volume` subcommand. The node implementation lists the
/// volume-capable backends' on-node volumes, flags which are still referenced by
/// a registered workload's spec (in use vs orphaned), and refuses to remove an
/// in-use volume unless forced. Admin-scoped at the API (the deny-safe
/// `/api/compute/*` default).
#[async_trait]
pub trait ComputeVolumes: Send + Sync {
    /// List every persistent volume on this node, each flagged with whether a
    /// registered workload's active spec still references it (`in_use`).
    async fn list(&self) -> Result<Vec<VolumeStatus>, VolumeError>;

    /// Remove the backing for volume `name`. Refuses with [`VolumeError::InUse`]
    /// when a registered workload's spec still references it, unless `force`.
    /// Returns whether the volume existed (`false` ⇒ `404` at the API).
    async fn remove(&self, name: &str, force: bool) -> Result<bool, VolumeError>;
}

/// A persistent volume plus whether a registered workload's spec still references
/// it — the `GET /api/compute/volumes` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeStatus {
    /// The underlying volume (name + on-disk size).
    #[serde(flatten)]
    pub info: VolumeInfo,
    /// Whether a registered workload's active spec still mounts this volume (a
    /// running/relaunching replica depends on it). Removal of an in-use volume is
    /// refused unless forced.
    pub in_use: bool,
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

    /// The placement policy implied by a security posture's shared-kernel stance.
    /// When shared-kernel compute is disallowed (a strict posture), only
    /// **strong-isolation** (VM/platform) backends are eligible — so a workload
    /// that only declares `Trusted` still cannot land on a native-namespace /
    /// Docker backend. `allow_shared_kernel = true` yields the default permissive
    /// policy. The single source of truth for the mapping the serve + cluster
    /// paths apply (previously inlined + duplicated in the binary).
    pub fn from_shared_kernel_allowed(allow_shared_kernel: bool) -> Self {
        Self {
            require_strong_isolation: !allow_shared_kernel,
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Scheduler (backend-aware placement)
// ---------------------------------------------------------------------------

/// A backend a node offers, with the capabilities the scheduler gates placement
/// on: the isolation class it provides, plus whether it can back persistent
/// volumes and scale a workload to zero. Populated from the backend's
/// [`Capabilities`] at node advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendKind {
    /// Backend id (`"vmm"`, …).
    pub id: String,
    /// Isolation class this backend provides on this node.
    pub isolation: IsolationClass,
    /// Whether this backend can attach the spec's persistent volumes. A spec with
    /// `volumes` placed on a `false` backend would run storage-less (silent data
    /// loss), so the scheduler treats it as ineligible.
    pub persistent_volumes: bool,
    /// Whether this backend can scale a workload to zero. A `scale_to_zero` spec on
    /// a `false` backend would run always-on (a silently missed cost optimization),
    /// so the scheduler treats it as ineligible rather than surprise the operator.
    pub scale_to_zero: bool,
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
                // A volume spec needs a volume-capable backend — else it would run
                // storage-less (silent data loss). No capable backend ⇒ no placement.
                && (spec.volumes.is_empty() || b.persistent_volumes)
                // A scale-to-zero spec needs a scale-to-zero-capable backend — else it
                // silently runs always-on. Fail loud (no placement) instead.
                && (!spec.scale_to_zero || b.scale_to_zero)
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
    /// Wall-clock unix seconds the replica was launched, set by `launch_one`. The
    /// reconcile loop uses it to give a freshly launched replica a startup grace (see
    /// [`ComputeSpec::startup_grace_secs`]) before treating a `Running`-but-unhealthy
    /// replica as a broken launch to stop + relaunch — so a slow-initializing image is
    /// not killed mid-init. `None` (older records, or a restored replica) is treated as
    /// past-grace, preserving the prior immediate-relaunch behavior. `#[serde(default)]`
    /// keeps older records deserializing — schema stays v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<u64>,
    /// Lifecycle phase. `#[serde(default)]` keeps older records (no field)
    /// deserializing as [`Running`](ReplicaPhase::Running) — schema stays v1.
    #[serde(default)]
    pub phase: ReplicaPhase,
    /// The snapshot to restore from — `Some` iff `phase == Zero`.
    #[serde(default)]
    pub snapshot: Option<Snapshot>,
}

/// The observed-state key for a workload's replica, **project-scoped** (0.2.0):
/// `project/<proj>/compute_state/<workload>/<replica>`.
pub fn replica_state_key(project: &str, workload: &str, replica: u32) -> String {
    format!("project/{project}/compute_state/{workload}/{replica}")
}

/// The key prefix listing one workload's replica states within a project.
pub fn replica_state_prefix(project: &str, workload: &str) -> String {
    format!("project/{project}/compute_state/{workload}/")
}

/// The key prefix listing **every** replica state in a project (all workloads).
pub fn replica_states_project_prefix(project: &str) -> String {
    format!("project/{project}/compute_state/")
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
/// unless (a) the restart policy is `Never`, in which case it is left as a terminal
/// (completed) instance and not relaunched, or (b) it is still within its **startup
/// grace**: a `Running`-but-unhealthy replica whose `started_at` is within
/// [`ComputeSpec::startup_grace_secs`] of `now` is treated as **starting** — left
/// alone (no Stop, no duplicate Launch), so a slow-initializing image (a stock
/// database's first `initdb`) is not killed mid-init into a crash loop. A replica with
/// `started_at == None` (older records / restored) is treated as past-grace, preserving
/// the prior immediate stop + relaunch. Free ordinals are placed onto eligible nodes;
/// if capacity runs out, fewer launches are emitted.
///
/// `now` is the current wall-clock unix seconds, compared against each replica's
/// `started_at` for the startup-grace check.
#[allow(clippy::too_many_arguments)]
pub fn reconcile_plan(
    workload: &ComputeWorkload,
    spec: &ComputeSpec,
    nodes: &[Node],
    policy: &BackendPolicy,
    observed: &[ObservedInstance],
    activity: WorkloadActivity,
    caps: &BTreeMap<String, Capabilities>,
    now: u64,
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
    let mut starting: BTreeSet<u32> = BTreeSet::new(); // launched, still within its startup grace → leave alone
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
        } else if inst
            .started_at
            .is_some_and(|t| now.saturating_sub(t) < spec.startup_grace_secs as u64)
        {
            // Launched but still within its startup grace: it's *starting*, not broken.
            // Leave it alone — don't Stop it (that would kill a slow first `initdb`
            // mid-init) and don't relaunch its ordinal (excluded from `need` below).
            // A missing `started_at` (older record / restored) falls through to the
            // stop + relaunch arm, preserving the prior behavior.
            starting.insert(ord);
        } else {
            actions.push(Action::Stop {
                handle: inst.handle.clone(),
            });
            // ordinal becomes free below → relaunched
        }
    }

    // Ordinals in range that need a (re)launch — excluding intentionally parked
    // (Zero) replicas, which wake via Restore rather than a fresh Launch, and
    // *starting* replicas, which are converging within their startup grace.
    let need: Vec<u32> = (0..desired)
        .filter(|ord| {
            !healthy.contains(ord)
                && !terminal.contains(ord)
                && !zeroed.contains(ord)
                && !starting.contains(ord)
        })
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

/// Resolves a workload's declared [`ComputeBinding`]s (PLAN-compute-bindings) to
/// env vars injected into the guest at launch, registering any backing shim state.
/// The concrete impl (the sql-shim resolver) lives server-side, where the
/// `SqlBackends` provider + the shim listener are; the reconcile only calls this
/// trait. All methods are keyed by `(project, workload, replica)` and **idempotent**,
/// so the reconcile can call `resolve` for every running replica each tick to keep
/// the shim registry populated across a restart.
#[async_trait]
pub trait ComputeBindingResolver: Send + Sync {
    /// Resolve `bindings` to `(env_key, env_value)` pairs to inject into the guest,
    /// registering the shim state for `(project, workload, replica)`.
    async fn resolve(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
    ) -> Vec<(String, String)>;

    /// Release the shim state for a torn-down replica.
    async fn release(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
    );
}

/// Injects **server-initialization env** (`POSTGRES_*` / `MYSQL_*`) into a compute
/// workload that a handler `sql` binding manages (PLAN-managed-compute-sql, Phase
/// 2). The reverse of [`ComputeBindingResolver`]: that wires a *guest* to reach
/// boatramp's shims; this wires boatramp's managed **credential** into a *database
/// server* the guest then connects to. Given `(project, workload)` it returns the
/// env the DB image reads on first boot to create boatramp's user/password/database
/// — empty when `workload` is not a managed database. **Idempotent**: the credential
/// is generated once + sealed, then stable, so it is safe to call on every launch
/// (the DB, initialized with it, keeps accepting the same password across restarts).
/// The concrete impl lives in `boatramp-node`, where the handler sql config + the
/// sealed-credential store are; the reconcile only calls this trait.
#[async_trait]
pub trait ManagedDbEnvResolver: Send + Sync {
    /// Server-init env for `workload` if it is a managed database, else empty.
    async fn managed_db_env(&self, project: &str, workload: &str) -> Vec<(String, String)>;

    /// The privilege strategy that lets `workload`'s stock DB image initialize on a
    /// shared-kernel backend, or `None` if `workload` is not a managed database.
    /// Sync + defaulted so a non-DB resolver needs no change. The reconcile applies it
    /// to the **launch** spec only (never the stored one), and only when the operator
    /// has not already set `user`/`cap_add`.
    fn managed_db_privilege(&self, _project: &str, _workload: &str) -> Option<PrivilegeDirective> {
        None
    }
}

/// How a managed database is made able to initialize its stock image on a shared-kernel
/// backend despite the dropped-`ALL` default. Applied to the launch spec by the
/// reconcile (see [`ManagedDbEnvResolver::managed_db_privilege`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivilegeDirective {
    /// Run rootless as `uid:gid` (the image's DB user) against its pre-owned volume —
    /// needs no capabilities and works under any posture. The preferred default.
    Rootless { uid: u32, gid: u32 },
    /// Grant these capabilities back (short names, no `CAP_` prefix). Single-tenant
    /// only — the backend's posture gate drops them under the multi-tenant guard.
    Caps(Vec<String>),
}

impl PrivilegeDirective {
    /// Apply this directive to a **launch** `spec`, without overriding a value the
    /// operator set explicitly (an operator `user`/`cap_add` always wins).
    pub fn apply(&self, spec: &mut ComputeSpec) {
        match self {
            Self::Rootless { uid, gid } if spec.user.is_none() => {
                spec.user = Some(format!("{uid}:{gid}"));
            }
            Self::Caps(caps) if spec.cap_add.is_empty() => {
                spec.cap_add = caps.clone();
            }
            _ => {}
        }
    }
}

/// The engine of a managed co-located database, selecting the stock OCI image, TCP
/// port, in-guest data directory, and entrypoint that [`managed_db_spec`]
/// synthesizes for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedDbEngine {
    /// PostgreSQL — the pgvector image by default (a superset of the official
    /// image, so `create extension vector` works out of the box).
    Postgres,
    /// MySQL — the official image.
    Mysql,
}

impl ManagedDbEngine {
    /// The default stock OCI image for this engine.
    pub fn default_image(self) -> &'static str {
        match self {
            Self::Postgres => "pgvector/pgvector:pg16",
            Self::Mysql => "mysql:8.0",
        }
    }

    /// The TCP port the server listens on.
    pub fn port(self) -> u16 {
        match self {
            Self::Postgres => 5432,
            Self::Mysql => 3306,
        }
    }

    /// The in-guest data directory that must be backed by a persistent volume.
    pub fn data_dir(self) -> &'static str {
        match self {
            Self::Postgres => "/var/lib/postgresql/data",
            Self::Mysql => "/var/lib/mysql",
        }
    }
}

/// Synthesize the immutable [`ComputeSpec`] for a managed co-located database from a
/// stock engine image, so the auto-registration path (node assembly) and the
/// capability gate build the **identical** workload — the gate proves exactly what
/// ships (the managed-DB spec never diverges from the tested one).
///
/// The spec carries only non-secret, image-shaping fields: the OCI image, the TCP
/// port, an **explicit entrypoint** (the shared-kernel backends apply the image's
/// filesystem, not its OCI config, so the argv plus `listen_addresses`/`bind-address`
/// must be supplied so the server answers on the container's bridge IP), the
/// non-secret `PATH`/data-dir env, and one persistent volume at the data directory.
/// The server-init credential env (`POSTGRES_*`/`MYSQL_*`) is injected at **launch**
/// from the sealed credential — never stored in this content-addressed spec. `user`
/// and `cap_add` are left unset so the reconcile's [`PrivilegeDirective`] (rootless
/// by default) sets them per posture, keeping the rootless default intact.
pub fn managed_db_spec(
    engine: ManagedDbEngine,
    image: Option<&str>,
    volume_size_mib: u32,
) -> ComputeSpec {
    // A stock database's *first* boot runs `initdb` before it opens its port, so the
    // reconcile loop must not mistake a still-initializing container for a broken
    // launch and kill it into a crash loop. These per-engine graces bound that window
    // (Postgres `initdb` ~10–30s; MySQL's first-boot bootstrap is markedly slower,
    // 60s+). Generic compute keeps the smaller `default_startup_grace_secs()` (30).
    const POSTGRES_STARTUP_GRACE_SECS: u32 = 60;
    const MYSQL_STARTUP_GRACE_SECS: u32 = 120;

    let startup_grace_secs = match engine {
        ManagedDbEngine::Postgres => POSTGRES_STARTUP_GRACE_SECS,
        ManagedDbEngine::Mysql => MYSQL_STARTUP_GRACE_SECS,
    };
    let data_dir = engine.data_dir();
    let (entrypoint, env) = match engine {
        ManagedDbEngine::Postgres => (
            vec![
                "/usr/local/bin/docker-entrypoint.sh".to_string(),
                "postgres".to_string(),
                "-c".to_string(),
                "listen_addresses=*".to_string(),
            ],
            BTreeMap::from([
                (
                    "PATH".to_string(),
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\
                     /usr/lib/postgresql/16/bin"
                        .to_string(),
                ),
                ("PGDATA".to_string(), data_dir.to_string()),
            ]),
        ),
        ManagedDbEngine::Mysql => (
            vec![
                "/usr/local/bin/docker-entrypoint.sh".to_string(),
                "mysqld".to_string(),
                "--bind-address=*".to_string(),
            ],
            BTreeMap::from([(
                "PATH".to_string(),
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            )]),
        ),
    };
    ComputeSpec {
        version: 1,
        root: RootSource::Image(image.unwrap_or_else(|| engine.default_image()).to_string()),
        kernel: String::new(),
        kernel_cmdline: None,
        vcpus: 1,
        mem_mib: 512,
        entrypoint,
        env,
        port: engine.port(),
        restart: RestartPolicy::Always,
        startup_grace_secs,
        scale_to_zero: false,
        volumes: vec![VolumeRef {
            mount: data_dir.to_string(),
            name: "data".to_string(),
            size_mib: volume_size_mib,
        }],
        writable_root: false,
        cap_add: Vec::new(),
        user: None,
        isolation: IsolationRequirement::Trusted,
        prefer_backend: None,
        bindings: vec![],
    }
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
    resolver: Option<&dyn ComputeBindingResolver>,
    managed_db: Option<&dyn ManagedDbEnvResolver>,
) -> Result<ReconcileReport, crate::error::DeployError> {
    let mut report = ReconcileReport::default();
    // Per-backend capabilities (the planner gates scale-to-zero on them).
    let caps: BTreeMap<String, Capabilities> = backends
        .iter()
        .map(|(id, b)| (id.clone(), b.capabilities()))
        .collect();
    // Fan out over every project's workloads (compute is project-scoped in 0.2.0).
    // The owning project threads through every replica-state read/write below.
    for (project_name, workload) in deploy.list_compute_workloads_all().await? {
        let project = ProjectRef::new(&project_name);
        let Some(spec) = deploy.get_compute_spec(&workload.active).await? else {
            report
                .errors
                .push(format!("{}: active spec missing", workload.name));
            continue;
        };

        // Observed replica state + a health refresh (skipping parked Zero
        // replicas — they're intentionally down).
        let mut observed = deploy.list_replica_states(project, &workload.name).await?;
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

        // Keep the shim registry populated for every running replica (idempotent),
        // so a workload's bindings keep working across a server restart while the
        // guest is still up.
        if let Some(resolver) = resolver {
            if !spec.bindings.is_empty() {
                for state in &observed {
                    if state.phase == ReplicaPhase::Running {
                        resolver
                            .resolve(
                                &project_name,
                                &workload.name,
                                state.handle.replica,
                                &spec.bindings,
                            )
                            .await;
                    }
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
            crate::time::now_unix(),
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
                    // Resolve declared bindings → env injected into the guest (registers
                    // the shim token for this replica).
                    let mut launch_env = match resolver {
                        Some(r) if !spec.bindings.is_empty() => {
                            r.resolve(&project_name, &wl, replica, &spec.bindings).await
                        }
                        _ => Vec::new(),
                    };
                    // If this workload is a managed database, inject its server-init
                    // env (POSTGRES_*/MYSQL_*) from the sealed managed credential, so it
                    // initializes on first boot with the user/password the handler will
                    // connect as. Empty for a non-managed workload (idempotent).
                    if let Some(m) = managed_db {
                        launch_env.extend(m.managed_db_env(&project_name, &wl).await);
                    }
                    // A managed DB also gets a privilege strategy (rootless user or a
                    // cap allowlist) so its stock image can init on a shared-kernel
                    // backend; applied to the launch spec only, and only where the
                    // operator has not set `user`/`cap_add` already.
                    let privilege =
                        managed_db.and_then(|m| m.managed_db_privilege(&project_name, &wl));
                    match launch_one(
                        b.as_ref(),
                        &wl,
                        replica,
                        node,
                        node_region,
                        &spec,
                        &launch_env,
                        privilege.as_ref(),
                    )
                    .await
                    {
                        Ok(state) => match deploy.set_replica_state(project, &state).await {
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
                        .delete_replica_state(project, &handle.workload, handle.replica)
                        .await
                    {
                        Ok(()) => report.stopped += 1,
                        Err(e) => report.errors.push(format!(
                            "{}/{}: forget: {e}",
                            handle.workload, handle.replica
                        )),
                    }
                    // Revoke this replica's shim tokens.
                    if let Some(resolver) = resolver {
                        if !spec.bindings.is_empty() {
                            resolver
                                .release(
                                    &project_name,
                                    &handle.workload,
                                    handle.replica,
                                    &spec.bindings,
                                )
                                .await;
                        }
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
                            match deploy.set_replica_state(project, &parked).await {
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
                                started_at: Some(crate::time::now_unix()),
                                phase: ReplicaPhase::Running,
                                snapshot: None,
                            };
                            match deploy.set_replica_state(project, &state).await {
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
#[allow(clippy::too_many_arguments)]
async fn launch_one(
    backend: &dyn ComputeBackend,
    workload: &str,
    replica: u32,
    node: u64,
    node_region: Option<String>,
    spec: &ComputeSpec,
    extra_env: &[(String, String)],
    privilege: Option<&PrivilegeDirective>,
) -> Result<ObservedInstance, BackendError> {
    // The launch wall-clock time, so the next reconcile tick can grant this replica a
    // startup grace before treating it as a broken launch (see `reconcile_plan`).
    let started_at = crate::time::now_unix();
    let artifact = backend.materialize(spec).await?;
    // Fold the resolved binding env into the launched spec. The workload's own env
    // wins on a collision, so a hand-set value is never clobbered by a binding.
    let mut spec = spec.clone();
    for (k, v) in extra_env {
        spec.env.entry(k.clone()).or_insert_with(|| v.clone());
    }
    // A managed-DB privilege strategy (rootless user / cap allowlist) — launch spec
    // only; never overrides an operator-set `user`/`cap_add`.
    if let Some(p) = privilege {
        p.apply(&mut spec);
    }
    let instance = backend
        .launch(&LaunchRequest {
            workload: workload.to_string(),
            replica,
            spec: spec.clone(),
            artifact,
        })
        .await?;
    // Probe readiness right after launch instead of asserting `healthy: true`
    // unconditionally. A stock DB image (Postgres/MySQL) takes a moment to `initdb`
    // and open its port, and a *first* launch can also fail outright (e.g. a broken
    // gateway, a stale volume) yet still return a handle — so a blind `true` recorded
    // a broken replica as healthy, and nothing ever retried it: only an unrelated
    // process restart (whose health refresh finally observed it down → Stop → relaunch)
    // "fixed" it. Recording the *actual* readiness here means the very next reconcile
    // tick's health refresh + plan self-heals a broken first launch, no restart needed.
    //
    // The probe is bounded by the backend's own `health` timeout (a couple of seconds),
    // so it never stalls the reconcile; `Unknown`/`Unhealthy`/`Err` all record
    // `healthy: false` (the readiness is re-confirmed on the next tick regardless). The
    // phase stays `Running` — the replica IS launched — so the next tick treats a
    // still-unhealthy replica as a launched-but-unready one (Stop + relaunch) rather
    // than a missing one (spurious extra launch).
    let healthy = matches!(backend.health(&instance.handle).await, Ok(Health::Healthy));
    Ok(ObservedInstance {
        handle: instance.handle,
        node,
        backend: backend.id().to_string(),
        endpoint: instance.endpoint,
        region: node_region,
        healthy,
        started_at: Some(started_at),
        phase: ReplicaPhase::Running,
        snapshot: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_db_spec_is_launchable_and_privilege_deferred() {
        // Postgres: default image, port, one volume at the data dir, explicit
        // entrypoint (the shared-kernel backends don't apply OCI config), and
        // `user`/`cap_add` LEFT UNSET so the privilege directive owns them.
        let pg = managed_db_spec(ManagedDbEngine::Postgres, None, 2048);
        assert_eq!(pg.root, RootSource::Image("pgvector/pgvector:pg16".into()));
        assert_eq!(pg.port, 5432);
        assert!(pg.user.is_none(), "rootless directive sets user at launch");
        assert!(pg.cap_add.is_empty());
        assert!(matches!(pg.restart, RestartPolicy::Always));
        assert!(!pg.scale_to_zero, "a database must not snapshot when idle");
        assert_eq!(pg.volumes.len(), 1);
        assert_eq!(pg.volumes[0].mount, "/var/lib/postgresql/data");
        assert_eq!(pg.volumes[0].size_mib, 2048);
        assert!(pg.entrypoint.iter().any(|a| a == "listen_addresses=*"));
        assert_eq!(
            pg.env.get("PGDATA").map(String::as_str),
            Some("/var/lib/postgresql/data")
        );
        // No secret env in the content-addressed spec — the credential is injected at launch.
        assert!(!pg.env.contains_key("POSTGRES_PASSWORD"));

        // The rootless directive then makes it launchable as the image's DB user.
        let mut launched = pg.clone();
        PrivilegeDirective::Rootless { uid: 999, gid: 999 }.apply(&mut launched);
        assert_eq!(launched.user.as_deref(), Some("999:999"));

        // An explicit image override is honored; MySQL uses its own port/data dir.
        let my = managed_db_spec(ManagedDbEngine::Mysql, Some("mysql:8.4"), 512);
        assert_eq!(my.root, RootSource::Image("mysql:8.4".into()));
        assert_eq!(my.port, 3306);
        assert_eq!(my.volumes[0].mount, "/var/lib/mysql");

        // Per-engine startup graces (slow first `initdb`): Postgres 60, MySQL 120 —
        // both above the generic 30 a plain compute spec carries.
        assert_eq!(pg.startup_grace_secs, 60);
        assert_eq!(my.startup_grace_secs, 120);
        assert_eq!(default_startup_grace_secs(), 30);
        assert_eq!(spec(1, 64).startup_grace_secs, 30);
    }

    #[test]
    fn privilege_directive_applies_without_overriding_operator_values() {
        // Rootless sets `user` when unset.
        let mut s = spec(1, 64);
        PrivilegeDirective::Rootless { uid: 999, gid: 999 }.apply(&mut s);
        assert_eq!(s.user.as_deref(), Some("999:999"));
        assert!(s.cap_add.is_empty());

        // An operator-set `user` is never overridden.
        let mut s = spec(1, 64);
        s.user = Some("1000".into());
        PrivilegeDirective::Rootless { uid: 999, gid: 999 }.apply(&mut s);
        assert_eq!(s.user.as_deref(), Some("1000"));

        // Caps fills `cap_add` when empty…
        let mut s = spec(1, 64);
        PrivilegeDirective::Caps(vec!["CHOWN".into(), "SETUID".into()]).apply(&mut s);
        assert_eq!(s.cap_add, vec!["CHOWN".to_string(), "SETUID".to_string()]);

        // …but not over an operator-set allowlist.
        let mut s = spec(1, 64);
        s.cap_add = vec!["NET_BIND_SERVICE".into()];
        PrivilegeDirective::Caps(vec!["CHOWN".into()]).apply(&mut s);
        assert_eq!(s.cap_add, vec!["NET_BIND_SERVICE".to_string()]);
    }

    fn spec(vcpus: u32, mem_mib: u32) -> ComputeSpec {
        ComputeSpec {
            version: 1,
            root: RootSource::Rootfs("r".repeat(64)),
            kernel: "k".repeat(64),
            kernel_cmdline: None,
            vcpus,
            mem_mib,
            entrypoint: vec![],
            env: BTreeMap::new(),
            port: 80,
            restart: RestartPolicy::Always,
            startup_grace_secs: 30,
            scale_to_zero: false,
            volumes: vec![],
            writable_root: false,
            cap_add: Vec::new(),
            user: None,
            isolation: IsolationRequirement::Trusted,
            prefer_backend: None,
            bindings: vec![],
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
                    // Fully-capable fixture: the volume / scale-to-zero gates only
                    // *refuse* on absent capability, so a capable fixture leaves every
                    // existing placement test unaffected; negative cases build their
                    // own incapable `BackendKind`.
                    persistent_volumes: true,
                    scale_to_zero: true,
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
    fn policy_from_shared_kernel_allowed_maps_posture_to_strong_isolation() {
        // Strict posture (shared-kernel disallowed) ⇒ require strong isolation.
        assert!(BackendPolicy::from_shared_kernel_allowed(false).require_strong_isolation);
        // Permissive posture ⇒ the default (no strong-isolation requirement).
        let permissive = BackendPolicy::from_shared_kernel_allowed(true);
        assert!(!permissive.require_strong_isolation);
        assert_eq!(permissive, BackendPolicy::default());
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

    /// A node offering one backend with the given capabilities — for the negative
    /// gate cases (the shared fixtures are deliberately fully-capable).
    fn node_with_caps(id: &str, iso: IsolationClass, volumes: bool, s2z: bool) -> Node {
        Node {
            id: 1,
            region: Some("eu".into()),
            labels: BTreeMap::new(),
            free_vcpus: 8,
            free_mem_mib: 8192,
            backends: vec![BackendKind {
                id: id.into(),
                isolation: iso,
                persistent_volumes: volumes,
                scale_to_zero: s2z,
            }],
        }
    }

    #[test]
    fn volume_spec_needs_a_volume_capable_backend() {
        let mut s = spec(1, 128);
        s.volumes = vec![VolumeRef {
            mount: "/data".into(),
            name: "db".into(),
            size_mib: 64,
        }];
        // A backend that can't back volumes ⇒ no placement (fail loud, not
        // silently storage-less).
        let no_vol = vec![node_with_caps(
            "container",
            IsolationClass::Namespace,
            false,
            false,
        )];
        assert!(
            place_replicas(
                1,
                &PlacementConstraints::default(),
                &s,
                &no_vol,
                &BackendPolicy::default()
            )
            .is_empty(),
            "a volume spec must not place on a volume-incapable backend"
        );
        // A volume-capable backend places it.
        let vol_ok = vec![node_with_caps("vmm", IsolationClass::VmKvm, true, false)];
        assert_eq!(
            place_replicas(
                1,
                &PlacementConstraints::default(),
                &s,
                &vol_ok,
                &BackendPolicy::default()
            )
            .len(),
            1
        );
    }

    #[test]
    fn scale_to_zero_spec_needs_a_capable_backend() {
        let mut s = spec(1, 128);
        s.scale_to_zero = true;
        // A backend that can't scale to zero ⇒ no placement, rather than silently
        // running always-on.
        let no_s2z = vec![node_with_caps(
            "docker",
            IsolationClass::Container,
            false,
            false,
        )];
        assert!(
            place_replicas(
                1,
                &PlacementConstraints::default(),
                &s,
                &no_s2z,
                &BackendPolicy::default()
            )
            .is_empty(),
            "a scale-to-zero spec must not place on a scale-to-zero-incapable backend"
        );
        // A scale-to-zero-capable backend places it.
        let s2z_ok = vec![node_with_caps(
            "container",
            IsolationClass::Namespace,
            false,
            true,
        )];
        assert_eq!(
            place_replicas(
                1,
                &PlacementConstraints::default(),
                &s,
                &s2z_ok,
                &BackendPolicy::default()
            )
            .len(),
            1
        );
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
            // No launch time: treated as past-grace (the baseline behavior these
            // helpers exercise); the startup-grace tests set `started_at` explicitly.
            started_at: None,
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
        // A `now` far past any `started_at` (the baseline helpers set `started_at:
        // None` anyway, which is unconditionally past-grace) so the startup-grace path
        // stays inert here — the grace tests drive `reconcile_plan` directly.
        reconcile_plan(
            wl,
            spec,
            nodes,
            policy,
            observed,
            WorkloadActivity::Active,
            &BTreeMap::new(),
            u64::MAX,
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
            u64::MAX,
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
            u64::MAX,
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
            u64::MAX,
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
            u64::MAX,
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
            u64::MAX,
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
            u64::MAX,
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

    /// An `observed` replica with an explicit `started_at`, for the startup-grace path.
    fn observed_started(
        workload: &str,
        replica: u32,
        node: u64,
        healthy: bool,
        started_at: Option<u64>,
    ) -> ObservedInstance {
        ObservedInstance {
            started_at,
            ..observed(workload, replica, node, healthy)
        }
    }

    #[test]
    fn reconcile_leaves_a_starting_replica_within_its_startup_grace() {
        // A Running-but-unhealthy replica launched 10s ago, grace 60s → still starting.
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let now = 1_000_000u64;
        let mut s = spec(1, 256);
        s.startup_grace_secs = 60;
        let obs = vec![observed_started("w", 0, 1, false, Some(now - 10))];
        let actions = reconcile_plan(
            &workload(1, Default::default()),
            &s,
            &nodes,
            &BackendPolicy::default(),
            &obs,
            WorkloadActivity::Active,
            &BTreeMap::new(),
            now,
        );
        // Mid-init: neither stopped nor relaunched (it counts toward `desired`).
        assert!(
            actions.is_empty(),
            "a replica within its startup grace is left alone: {actions:?}"
        );
    }

    #[test]
    fn reconcile_relaunches_a_replica_past_its_startup_grace() {
        // Same replica, launched 120s ago, grace 60s → past grace → broken → self-heal.
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let now = 1_000_000u64;
        let mut s = spec(1, 256);
        s.startup_grace_secs = 60;
        let obs = vec![observed_started("w", 0, 1, false, Some(now - 120))];
        let actions = reconcile_plan(
            &workload(1, Default::default()),
            &s,
            &nodes,
            &BackendPolicy::default(),
            &obs,
            WorkloadActivity::Active,
            &BTreeMap::new(),
            now,
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Stop { handle } if handle.replica == 0)),
            "past-grace unhealthy replica is stopped: {actions:?}"
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Launch { replica: 0, .. })),
            "and its ordinal relaunched: {actions:?}"
        );
    }

    #[test]
    fn reconcile_treats_started_at_none_as_past_grace() {
        // `started_at: None` (older record / restored) → immediate stop + relaunch,
        // exactly the prior behavior — even with a large grace and `now`.
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let mut s = spec(1, 256);
        s.startup_grace_secs = 3600;
        let obs = vec![observed_started("w", 0, 1, false, None)];
        let actions = reconcile_plan(
            &workload(1, Default::default()),
            &s,
            &nodes,
            &BackendPolicy::default(),
            &obs,
            WorkloadActivity::Active,
            &BTreeMap::new(),
            1_000_000,
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Stop { handle } if handle.replica == 0)),
            "None started_at preserves the prior immediate relaunch: {actions:?}"
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Launch { replica: 0, .. })));
    }

    #[test]
    fn a_starting_replica_counts_toward_desired_and_is_not_duplicated() {
        // desired=1 with one starting replica → NO new Launch (it's not a missing slot).
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let now = 1_000_000u64;
        let mut s = spec(1, 256);
        s.startup_grace_secs = 60;
        let obs = vec![observed_started("w", 0, 1, false, Some(now - 5))];
        let actions = reconcile_plan(
            &workload(1, Default::default()),
            &s,
            &nodes,
            &BackendPolicy::default(),
            &obs,
            WorkloadActivity::Active,
            &BTreeMap::new(),
            now,
        );
        assert!(
            !actions.iter().any(|a| matches!(a, Action::Launch { .. })),
            "a starting replica fills its ordinal — no duplicate Launch: {actions:?}"
        );
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

    /// A backend whose replicas launch but are **not yet ready** — `health` returns
    /// `Unhealthy` (a stock DB image mid-`initdb`, or a broken first launch). Used to
    /// prove `launch_one` records the real readiness rather than a blind `true`.
    struct NotReadyBackend;

    #[async_trait]
    impl ComputeBackend for NotReadyBackend {
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
            Ok(Health::Unhealthy)
        }
    }

    /// Fix 3: `launch_one` probes readiness post-launch. A backend that launches but is
    /// not yet ready must be recorded `healthy: false` (phase still `Running`), so the
    /// next reconcile tick's health refresh + plan self-heals it (Stop + relaunch) with
    /// no process restart — where the old unconditional `healthy: true` hid it forever.
    #[tokio::test]
    async fn launch_one_records_probed_readiness_not_a_blind_true() {
        let s = spec(1, 128);
        // Not-ready backend → healthy:false, but the replica IS launched (phase Running).
        let unready = launch_one(&NotReadyBackend, "pg", 0, 1, None, &s, &[], None)
            .await
            .unwrap();
        assert!(
            !unready.healthy,
            "a launched-but-unready replica is recorded unhealthy so the next tick relaunches it"
        );
        assert_eq!(unready.phase, ReplicaPhase::Running);

        // A ready backend still records healthy:true (the happy path is unchanged).
        let ready = launch_one(&FakeBackend, "pg", 0, 1, None, &s, &[], None)
            .await
            .unwrap();
        assert!(ready.healthy);

        // And the plan then Stops+relaunches the unhealthy one (RestartPolicy::Always),
        // proving the self-heal — the whole point of recording real readiness.
        let mut always = s.clone();
        always.restart = RestartPolicy::Always;
        let wl = ComputeWorkload {
            version: 1,
            name: "pg".into(),
            active: "spec".into(),
            replicas: 1,
            placement: PlacementConstraints::default(),
        };
        let caps: BTreeMap<String, Capabilities> =
            [("fake".to_string(), FakeBackend.capabilities())]
                .into_iter()
                .collect();
        // Advance `now` past the startup grace so the self-heal fires — this test is
        // about a *genuinely broken* launch (still unhealthy after its grace), not a
        // mid-init replica (which the startup-grace test covers).
        let past_grace = unready.started_at.unwrap() + always.startup_grace_secs as u64 + 1;
        let actions = reconcile_plan(
            &wl,
            &always,
            &[fake_node()],
            &BackendPolicy::default(),
            &[unready],
            WorkloadActivity::Active,
            &caps,
            past_grace,
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Stop { handle } if handle.replica == 0)),
            "the unhealthy first launch is stopped: {actions:?}"
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Launch { replica: 0, .. })),
            "and its ordinal relaunched: {actions:?}"
        );
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
                // Fully-capable so the scale-to-zero reconcile tests (which reuse this
                // fixture) still place; negative gate tests build their own node.
                persistent_volumes: true,
                scale_to_zero: true,
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
            .set_compute_workload(
                crate::project::ProjectRef::DEFAULT,
                &ComputeWorkload {
                    version: 1,
                    name: "w".into(),
                    active: hash,
                    replicas: 1,
                    placement: Default::default(),
                },
            )
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
            None,
            None,
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
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.slept, 1, "{:?}", r.errors);
        let parked = deploy
            .list_replica_states(crate::project::ProjectRef::DEFAULT, "w")
            .await
            .unwrap();
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
            None,
            None,
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
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.woke, 1, "{:?}", r.errors);
        let woken = deploy
            .list_replica_states(crate::project::ProjectRef::DEFAULT, "w")
            .await
            .unwrap();
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
            .set_compute_workload(
                crate::project::ProjectRef::DEFAULT,
                &ComputeWorkload {
                    version: 1,
                    name: "w".into(),
                    active: hash.clone(),
                    replicas: 2,
                    placement: Default::default(),
                },
            )
            .await
            .unwrap();
        let nodes = vec![fake_node()];
        let mut backends: BackendRegistry = BTreeMap::new();
        backends.insert("fake".into(), Arc::new(FakeBackend));
        let policy = BackendPolicy::default();

        // Pass 1: launches both replicas + persists their state.
        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &AlwaysActive,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!((r.launched, r.stopped), (2, 0), "{:?}", r.errors);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        let states = deploy
            .list_replica_states(crate::project::ProjectRef::DEFAULT, "w")
            .await
            .unwrap();
        assert_eq!(states.len(), 2);
        // FA-8: each launched replica inherits its node's region tag.
        assert!(
            states.iter().all(|s| s.region.as_deref() == Some("eu")),
            "replicas carry their node's region"
        );

        // Pass 2: already converged (FakeBackend reports Healthy) → no-op.
        let r2 = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &AlwaysActive,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!((r2.launched, r2.stopped), (0, 0));

        // Scale to zero → both stopped + state cleared.
        deploy
            .set_compute_workload(
                crate::project::ProjectRef::DEFAULT,
                &ComputeWorkload {
                    version: 1,
                    name: "w".into(),
                    active: hash,
                    replicas: 0,
                    placement: Default::default(),
                },
            )
            .await
            .unwrap();
        let r3 = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &AlwaysActive,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(r3.stopped, 2);
        assert!(deploy
            .list_replica_states(crate::project::ProjectRef::DEFAULT, "w")
            .await
            .unwrap()
            .is_empty());
    }
}
