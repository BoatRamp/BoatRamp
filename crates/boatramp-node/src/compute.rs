//! Compute-backend assembly (moved from the binary — node-library N2).
//!
//! Builds this node's compute [`BackendRegistry`](boatramp_core::compute::BackendRegistry)
//! and scheduler [`Node`](boatramp_core::compute::Node) inventory from the optional
//! `[compute]` config, capability-detecting Docker, native-container, and
//! embedded-VMM backends. Lives here (not in the backend-agnostic
//! `boatramp-server`) because it depends on the concrete backend crates; the
//! binary and future `assemble()` call [`build_compute`].

use std::sync::Arc;

/// The posture-scaled kernel-trust gate wired into the compute backends: it runs
/// [`boatramp_core::kernel_trust::verify_kernel`] on the staged kernel right
/// before boot. The always-on check is the content hash; under the strict
/// (multi-tenant) posture it additionally requires the pinned hash to be on the
/// static allow-list and to carry a signature — sourced from the **live fleet
/// default kernel** — verifying against a static signing key. No daemon, or a hash
/// that isn't the current signed default, has no signature source and so **fails
/// closed** under strict: the kernel does not boot.
#[cfg(target_os = "linux")]
struct PostureKernelVerifier {
    strict: bool,
    signing_keys: Vec<String>,
    allowed_hashes: Vec<String>,
    daemon: Option<Arc<boatramp_server::DaemonRuntime>>,
}

// `KernelVerifier` requires `Debug`, but `DaemonRuntime` isn't `Debug` (it holds a
// lock + a `Notify`); summarise instead of recursing into it.
#[cfg(target_os = "linux")]
impl std::fmt::Debug for PostureKernelVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostureKernelVerifier")
            .field("strict", &self.strict)
            .field("signing_keys", &self.signing_keys.len())
            .field("allowed_hashes", &self.allowed_hashes.len())
            .field("has_daemon", &self.daemon.is_some())
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl boatramp_firecracker::KernelVerifier for PostureKernelVerifier {
    // Fully-qualified: this module aliases `Result<T>` to its own error type.
    fn verify(&self, bytes: &[u8], expected_hash: &str) -> std::result::Result<(), String> {
        // The only signature we trust for this hash is the one on the current
        // fleet default kernel (the operator-vetted kernel); any other hash has no
        // signature source and fails the strict bar.
        let sig = self
            .daemon
            .as_ref()
            .and_then(|d| d.effective().default_kernel.clone())
            .filter(|dk| dk.sha256 == expected_hash)
            .and_then(|dk| dk.sig);
        let kref = boatramp_core::daemon_config::KernelRef {
            source: expected_hash.to_string(),
            sha256: expected_hash.to_string(),
            sig,
        };
        boatramp_core::kernel_trust::verify_kernel(
            bytes,
            &kref,
            self.strict,
            &self.signing_keys,
            &self.allowed_hashes,
        )
        .map_err(|e| e.to_string())
    }
}

/// The macOS-VMM twin of [`PostureKernelVerifier`], implementing
/// [`boatramp_vz::KernelVerifier`] with the identical posture-scaled trust logic
/// so the Virtualization.framework backend enforces the same verify-before-boot
/// bar as the KVM backend (the kernel is ring-0 code on either substrate).
#[cfg(target_os = "macos")]
struct VzPostureKernelVerifier {
    strict: bool,
    signing_keys: Vec<String>,
    allowed_hashes: Vec<String>,
    daemon: Option<Arc<boatramp_server::DaemonRuntime>>,
}

#[cfg(target_os = "macos")]
impl std::fmt::Debug for VzPostureKernelVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VzPostureKernelVerifier")
            .field("strict", &self.strict)
            .field("signing_keys", &self.signing_keys.len())
            .field("allowed_hashes", &self.allowed_hashes.len())
            .field("has_daemon", &self.daemon.is_some())
            .finish()
    }
}

#[cfg(target_os = "macos")]
impl boatramp_vz::KernelVerifier for VzPostureKernelVerifier {
    fn verify(&self, bytes: &[u8], expected_hash: &str) -> std::result::Result<(), String> {
        let sig = self
            .daemon
            .as_ref()
            .and_then(|d| d.effective().default_kernel.clone())
            .filter(|dk| dk.sha256 == expected_hash)
            .and_then(|dk| dk.sig);
        let kref = boatramp_core::daemon_config::KernelRef {
            source: expected_hash.to_string(),
            sha256: expected_hash.to_string(),
            sig,
        };
        boatramp_core::kernel_trust::verify_kernel(
            bytes,
            &kref,
            self.strict,
            &self.signing_keys,
            &self.allowed_hashes,
        )
        .map_err(|e| e.to_string())
    }
}

/// Whether this host can run the macOS VMM backend: **Apple silicon** (arm64) on
/// **macOS 15+** (the Virtualization.framework Linux-container floor). Detected via
/// `sysctl` — `hw.optional.arm64 == 1` and `kern.osproductversion >= 15`. macOS 26
/// is recommended (macOS 15 lacks container-to-container networking over vmnet),
/// but single-node serve works on 15, so 15 is the floor; the operator's macOS
/// version determines multi-replica cross-VM reachability, not the user surface.
#[cfg(target_os = "macos")]
fn macos_supports_vz() -> bool {
    // Apple silicon: the Virtualization.framework Linux path is arm64-only.
    if cfg!(not(target_arch = "aarch64")) {
        return false;
    }
    let major = sysctl_string("kern.osproductversion")
        .and_then(|v| v.split('.').next().and_then(|m| m.parse::<u32>().ok()));
    matches!(major, Some(m) if m >= 15)
}

/// Read a string `sysctl` by name (e.g. `kern.osproductversion`). `None` on any
/// failure — the caller treats an unreadable sysctl as "unsupported" (fail-closed).
#[cfg(target_os = "macos")]
fn sysctl_string(name: &str) -> Option<String> {
    let out = std::process::Command::new("sysctl")
        .args(["-n", name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Build this node's compute [`BackendRegistry`] + scheduler [`Node`] inventory
/// from the optional `[compute]` config. Backends
/// are **capability-detected**: a reachable Docker daemon ⇒ `docker`; Linux ⇒ the
/// native `container` backend; Linux + `/dev/kvm` ⇒ the in-process
/// `vmm-embedded` microVM backend (strongest isolation). Absent config ⇒ an empty
/// registry + a node advertising nothing, so the reconcile loop stays a no-op.
pub async fn build_compute(
    cfg: Option<&crate::config::ComputeConfig>,
    storage: std::sync::Arc<dyn boatramp_core::Storage>,
    data_dir: &std::path::Path,
    node_id: u64,
    strict: bool,
    daemon: Option<Arc<boatramp_server::DaemonRuntime>>,
    // The binary the re-exec'd container/microVM workers run as; `None` ⇒ this
    // process's own executable (`current_exe`). An embedding harness points it at a
    // built `boatramp` binary so the workers find the `__sandbox`/`__vmm-run`/
    // `__vz-run` subcommands. See [`crate::node::NodeInput::worker_exe`].
    worker_exe: Option<&std::path::Path>,
) -> (
    boatramp_core::compute::BackendRegistry,
    boatramp_core::compute::Node,
) {
    use boatramp_core::compute::{BackendKind, BackendRegistry, Node};
    let mut backends: BackendRegistry = std::collections::BTreeMap::new();
    let empty_node = |id| Node {
        id,
        region: None,
        labels: std::collections::BTreeMap::new(),
        free_vcpus: 0,
        free_mem_mib: 0,
        backends: Vec::new(),
    };
    let Some(cfg) = cfg else {
        return (backends, empty_node(node_id));
    };

    // Remote docker: register only if a daemon actually answers.
    match boatramp_docker::DockerBackend::connect() {
        Ok(docker) => {
            // `writable_root` and `cap_add` are honored only under the single-tenant
            // posture (`!strict`); the multi-tenant guard keeps the hardened read-only
            // root and every capability dropped.
            let docker = docker
                .with_endpoint(cfg.docker_endpoint)
                .with_volume_mode(cfg.docker_volume_mode)
                .with_data_dir(data_dir)
                .with_writable_root_allowed(!strict)
                .with_cap_add_allowed(!strict);
            if docker.reachable().await {
                backends.insert("docker".to_string(), std::sync::Arc::new(docker));
            } else {
                tracing::debug!("no reachable docker daemon; skipping docker backend");
            }
        }
        Err(e) => tracing::debug!(%e, "docker backend unavailable"),
    }

    // Ensure the shared compute bridge exists before the backends that enslave a
    // veth/tap to it. boatramp creates it itself over netlink (needs `CAP_NET_ADMIN`)
    // rather than requiring the operator to pre-create it — so a stock image on a fresh
    // host is turnkey. If it can't be created, the container + embedded-VMM backends are
    // skipped rather than advertised and then failing at launch on the missing bridge.
    #[cfg(target_os = "linux")]
    let bridge_ready = match boatramp_core::ipam::IpPool::new(&cfg.subnet) {
        Ok(pool) => {
            match boatramp_container::ensure_bridge(&cfg.bridge, pool.gateway(), pool.prefix_len())
                .await
            {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(%e, bridge = %cfg.bridge, "could not create the compute bridge (need CAP_NET_ADMIN); container + embedded-VMM backends disabled");
                    false
                }
            }
        }
        Err(e) => {
            tracing::warn!(%e, subnet = %cfg.subnet, "bad compute subnet; container + embedded-VMM backends disabled");
            false
        }
    };

    // Native container backend (Linux only).
    #[cfg(target_os = "linux")]
    if bridge_ready {
        match worker_exe.map_or_else(std::env::current_exe, |p| Ok(p.to_path_buf())) {
            Ok(self_exe) => match boatramp_container::ContainerBackend::new(
                storage.clone(),
                data_dir.to_path_buf(),
                cfg.bridge.clone(),
                &cfg.subnet,
                self_exe,
            ) {
                Ok(c) => {
                    // Single-tenant posture (`!strict`) may honor `cap_add`; multi-tenant
                    // keeps every capability dropped.
                    let c = c.with_cap_add_allowed(!strict);
                    backends.insert("container".to_string(), std::sync::Arc::new(c));
                }
                Err(e) => tracing::warn!(%e, "container backend unavailable"),
            },
            Err(e) => tracing::warn!(%e, "current_exe for container backend"),
        }
    }
    // Embedded VMM backend (Linux + x86_64 + `/dev/kvm`): in-process microVMs, no
    // external `firecracker` binary — the strongest isolation when KVM is available.
    // Like the container backend it enslaves each tap to `cfg.bridge` (ensured above,
    // hence the `bridge_ready` gate). The embedded VMM is KVM-x86-specific, so this is
    // x86_64-only; boatramp
    // still serves on linux/aarch64 (with the container backend, no embedded VMM).
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if bridge_ready && std::path::Path::new("/dev/kvm").exists() {
        match (
            worker_exe.map_or_else(std::env::current_exe, |p| Ok(p.to_path_buf())),
            boatramp_core::ipam::IpPool::new(&cfg.subnet),
        ) {
            (Ok(self_exe), Ok(pool)) => {
                let gateway = pool.gateway().to_string();
                // Verify-before-boot gate for every kernel this backend stages.
                let verifier: Arc<dyn boatramp_firecracker::KernelVerifier> =
                    Arc::new(PostureKernelVerifier {
                        strict,
                        signing_keys: cfg.kernel_signing_pubkeys.clone(),
                        allowed_hashes: cfg.kernel_allowed_hashes.clone(),
                        daemon: daemon.clone(),
                    });
                match boatramp_firecracker::EmbeddedVmmBackend::new(
                    storage.clone(),
                    self_exe, // re-exec'd as `__vmm-run` per VM (jailed subprocess)
                    data_dir.to_path_buf(),
                    cfg.bridge.clone(),
                    gateway,
                    &cfg.subnet,
                    verifier,
                ) {
                    Ok(vmm) => {
                        backends.insert("vmm-embedded".to_string(), std::sync::Arc::new(vmm));
                    }
                    Err(e) => tracing::warn!(%e, "embedded VMM backend unavailable"),
                }
            }
            (Err(e), _) => tracing::warn!(%e, "current_exe for VMM backend"),
            (_, Err(e)) => tracing::warn!(%e, "bad compute subnet for VMM backend"),
        }
    } else {
        tracing::debug!("no /dev/kvm; skipping embedded VMM backend");
    }

    // macOS-native VMM backend (Apple silicon + macOS): each replica is a Linux
    // microVM under Virtualization.framework, run by a re-exec'd `__vz-run`
    // worker. Strong isolation (VmKvm), matching the KVM backend's user surface.
    // Capability-detected + log-skipped on Intel / older macOS, exactly like the
    // `/dev/kvm` check gates the Linux VMM.
    #[cfg(target_os = "macos")]
    if macos_supports_vz() {
        match (
            worker_exe.map_or_else(std::env::current_exe, |p| Ok(p.to_path_buf())),
            boatramp_core::ipam::IpPool::new(&cfg.subnet),
        ) {
            (Ok(self_exe), Ok(_pool)) => {
                let verifier: Arc<dyn boatramp_vz::KernelVerifier> =
                    Arc::new(VzPostureKernelVerifier {
                        strict,
                        signing_keys: cfg.kernel_signing_pubkeys.clone(),
                        allowed_hashes: cfg.kernel_allowed_hashes.clone(),
                        daemon: daemon.clone(),
                    });
                match boatramp_vz::VzBackend::new(
                    storage.clone(),
                    self_exe, // re-exec'd as `__vz-run` per VM
                    data_dir.to_path_buf(),
                    &cfg.subnet, // the vmnet range (e.g. 192.168.64.0/24); `.1` = gateway
                    verifier,
                ) {
                    // `writable_root` honored only under the single-tenant posture.
                    Ok(vz) => {
                        let vz = vz.with_writable_root_allowed(!strict);
                        backends.insert("vmm-vz".to_string(), std::sync::Arc::new(vz));
                    }
                    Err(e) => tracing::warn!(%e, "macOS VMM backend unavailable"),
                }
            }
            (Err(e), _) => tracing::warn!(%e, "current_exe for macOS VMM backend"),
            (_, Err(e)) => tracing::warn!(%e, "bad compute subnet for macOS VMM backend"),
        }
    } else {
        tracing::debug!("not Apple silicon + macOS 15+; skipping macOS VMM backend");
    }

    let _ = (&storage, data_dir); // used only on Linux/macOS (container / VMM backends)
                                  // The kernel-trust verifier is wired for the embedded VMM (x86_64 Linux) and
                                  // the macOS VMM; silence `strict`/`daemon` on the platforms that wire neither
                                  // (linux/aarch64, and any non-Linux non-macOS host).
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64"), target_os = "macos")))]
    let _ = (strict, &daemon);

    let free_vcpus = if cfg.vcpus > 0 {
        cfg.vcpus
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1)
    };
    let free_mem_mib = if cfg.mem_mib > 0 { cfg.mem_mib } else { 1024 };
    let advertised: Vec<BackendKind> = backends
        .iter()
        .map(|(id, b)| {
            let caps = b.capabilities();
            BackendKind {
                id: id.clone(),
                isolation: caps.isolation,
                persistent_volumes: caps.persistent_volumes,
                scale_to_zero: caps.scale_to_zero,
            }
        })
        .collect();
    tracing::info!(backends = ?advertised, free_vcpus, free_mem_mib, "compute node inventory");
    let node = Node {
        id: node_id,
        region: cfg.region.clone(),
        labels: std::collections::BTreeMap::new(),
        free_vcpus,
        free_mem_mib,
        backends: advertised,
    };
    (backends, node)
}

/// The node's [`ComputeExec`](boatramp_core::compute::ComputeExec): resolve a
/// workload's running replica from the control-plane state, pick its backend, and
/// run the command inside it. Backs `POST /api/compute/{name}/exec`; the API gates
/// it behind the `allow_compute_exec` posture. Only the shared-kernel backends
/// (native `container`, remote `docker`) actually implement
/// [`ComputeBackend::exec`](boatramp_core::compute::ComputeBackend::exec); the rest
/// surface as [`ExecError::Unsupported`](boatramp_core::compute::ExecError).
pub struct NodeComputeExec {
    backends: boatramp_core::compute::BackendRegistry,
    deploy: boatramp_core::deploy::DeployStore,
}

impl NodeComputeExec {
    /// Build over this node's compute backends + the control-plane store. The
    /// registry is a cheap `BTreeMap` of `Arc` backends (clone it before the
    /// reconcile loop consumes the original).
    pub fn new(
        backends: boatramp_core::compute::BackendRegistry,
        deploy: boatramp_core::deploy::DeployStore,
    ) -> Self {
        Self { backends, deploy }
    }
}

#[async_trait::async_trait]
impl boatramp_core::compute::ComputeExec for NodeComputeExec {
    async fn exec(
        &self,
        project: &str,
        workload: &str,
        argv: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<boatramp_core::compute::ExecOutput, boatramp_core::compute::ExecError> {
        use boatramp_core::compute::{BackendError, ExecError, ReplicaPhase};
        use boatramp_core::project::ProjectRef;
        let states = self
            .deploy
            .list_replica_states(ProjectRef::new(project), workload)
            .await
            .map_err(|e| ExecError::Other(e.to_string()))?;
        // A running replica — prefer a healthy one, else any running (a just-launched
        // DB may not be health-marked yet but can still accept an exec).
        let target = states
            .iter()
            .find(|s| s.phase == ReplicaPhase::Running && s.healthy)
            .or_else(|| states.iter().find(|s| s.phase == ReplicaPhase::Running))
            .ok_or_else(|| ExecError::NoReplica(workload.to_string()))?;
        let backend = self
            .backends
            .get(&target.backend)
            .ok_or_else(|| ExecError::Unsupported(target.backend.clone()))?;
        match backend.exec(&target.handle, argv, stdin).await {
            Ok(out) => Ok(out),
            Err(BackendError::Unsupported) => Err(ExecError::Unsupported(target.backend.clone())),
            Err(e) => Err(ExecError::Other(e.to_string())),
        }
    }
}

/// The node's [`ComputeVolumes`](boatramp_core::compute::ComputeVolumes): list +
/// reclaim persistent volumes. Backs `GET /api/compute/volumes` +
/// `DELETE /api/compute/volumes/{name}` (admin-scoped). Lists every
/// volume-capable backend's on-node volumes, flags which are still referenced by a
/// registered workload's active spec (in use vs orphaned), and refuses to remove
/// an in-use volume unless forced — so `compute rm <workload>` (which unregisters
/// it, then the reconcile loop stops the replica) is the safe precondition for
/// reclaiming its volume.
pub struct NodeComputeVolumes {
    backends: boatramp_core::compute::BackendRegistry,
    deploy: boatramp_core::deploy::DeployStore,
}

impl NodeComputeVolumes {
    /// Build over this node's compute backends + the control-plane store.
    pub fn new(
        backends: boatramp_core::compute::BackendRegistry,
        deploy: boatramp_core::deploy::DeployStore,
    ) -> Self {
        Self { backends, deploy }
    }

    /// The set of volume names still referenced by **any** registered workload's
    /// active spec, across every project (the `_all` fan-out). A name in this set
    /// is "in use": a running or relaunching replica mounts it, so removing its
    /// backing would corrupt live data. Resolves each workload's content-addressed
    /// spec to read its `volumes[].name`; a workload whose spec can't be resolved
    /// is skipped (it can't be actively mounting a volume the backend still backs).
    async fn referenced_volume_names(
        &self,
    ) -> Result<std::collections::BTreeSet<String>, boatramp_core::compute::VolumeError> {
        use boatramp_core::compute::VolumeError;
        let mut names = std::collections::BTreeSet::new();
        let workloads = self
            .deploy
            .list_compute_workloads_all()
            .await
            .map_err(|e| VolumeError::Other(e.to_string()))?;
        for (_project, workload) in workloads {
            let spec = self
                .deploy
                .get_compute_spec(&workload.active)
                .await
                .map_err(|e| VolumeError::Other(e.to_string()))?;
            if let Some(spec) = spec {
                for vol in spec.volumes {
                    names.insert(vol.name);
                }
            }
        }
        Ok(names)
    }
}

#[async_trait::async_trait]
impl boatramp_core::compute::ComputeVolumes for NodeComputeVolumes {
    async fn list(
        &self,
    ) -> Result<Vec<boatramp_core::compute::VolumeStatus>, boatramp_core::compute::VolumeError>
    {
        use boatramp_core::compute::{VolumeError, VolumeStatus};
        let referenced = self.referenced_volume_names().await?;
        // Union the volumes every backend reports (dedup by name — a name is unique
        // per node's volumes dir). A backend that doesn't back volumes returns the
        // empty default, so this naturally reduces to the volume-capable backend(s).
        let mut by_name: std::collections::BTreeMap<String, u64> =
            std::collections::BTreeMap::new();
        for backend in self.backends.values() {
            let vols = backend
                .list_volumes()
                .await
                .map_err(|e| VolumeError::Other(e.to_string()))?;
            for v in vols {
                // Keep the largest reported size if two backends somehow name-collide.
                let slot = by_name.entry(v.name).or_insert(0);
                *slot = (*slot).max(v.size_bytes);
            }
        }
        Ok(by_name
            .into_iter()
            .map(|(name, size_bytes)| VolumeStatus {
                in_use: referenced.contains(&name),
                info: boatramp_core::compute::VolumeInfo { name, size_bytes },
            })
            .collect())
    }

    async fn remove(
        &self,
        name: &str,
        force: bool,
    ) -> Result<bool, boatramp_core::compute::VolumeError> {
        use boatramp_core::compute::{BackendError, VolumeError};
        // Safety guard: refuse to pull a volume out from under a registered
        // workload unless the operator forces it. `compute rm <workload>` first is
        // the safe flow; `--force` is the disposable-data override.
        if !force && self.referenced_volume_names().await?.contains(name) {
            return Err(VolumeError::InUse(name.to_string()));
        }
        // Remove from whichever backend owns it. `true` from any backend ⇒ existed.
        // Every backend reports `Unsupported` ⇒ no volume-capable backend here.
        let mut existed = false;
        let mut any_supported = false;
        for backend in self.backends.values() {
            match backend.remove_volume(name).await {
                Ok(removed) => {
                    any_supported = true;
                    existed |= removed;
                }
                Err(BackendError::Unsupported) => {}
                Err(e) => return Err(VolumeError::Other(e.to_string())),
            }
        }
        if !any_supported {
            return Err(VolumeError::Unsupported);
        }
        Ok(existed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use boatramp_core::compute::{
        Artifact, BackendError, Capabilities, ComputeBackend, ComputeSpec, ComputeVolumes,
        ComputeWorkload, Health, Instance, InstanceHandle, IsolationClass, IsolationRequirement,
        LaunchRequest, RestartPolicy, RootSource, VolumeError, VolumeInfo, VolumeRef,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::project::ProjectRef;
    use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    /// A `Storage` the `DeployStore` never actually reads on the volume paths (the
    /// spec/workload records live in the KV) — every method is a stub.
    struct NullStorage;
    #[async_trait]
    impl Storage for NullStorage {
        async fn get(&self, _: &str) -> Result<GetObject, StorageError> {
            Err(StorageError::NotFound(String::new()))
        }
        async fn get_range(
            &self,
            _: &str,
            _: u64,
            _: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            Err(StorageError::unsupported("range"))
        }
        async fn put(
            &self,
            _: &str,
            _: ByteStream,
            _: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
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

    /// A fake volume-capable backend over an in-memory set of `(name, size)`
    /// volumes — enough to drive `NodeComputeVolumes` without a real container node.
    struct FakeVolumeBackend {
        vols: Mutex<BTreeMap<String, u64>>,
    }
    impl FakeVolumeBackend {
        fn with(names: &[(&str, u64)]) -> Self {
            Self {
                vols: Mutex::new(names.iter().map(|(n, s)| (n.to_string(), *s)).collect()),
            }
        }
    }
    #[async_trait]
    impl ComputeBackend for FakeVolumeBackend {
        fn id(&self) -> &'static str {
            "container"
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                isolation: IsolationClass::Namespace,
                scale_to_zero: false,
                persistent_volumes: true,
                max_vcpus: None,
                max_mem_mib: None,
            }
        }
        async fn materialize(&self, _: &ComputeSpec) -> Result<Artifact, BackendError> {
            Err(BackendError::Unsupported)
        }
        async fn launch(&self, _: &LaunchRequest) -> Result<Instance, BackendError> {
            Err(BackendError::Unsupported)
        }
        async fn stop(&self, _: &InstanceHandle) -> Result<(), BackendError> {
            Ok(())
        }
        async fn health(&self, _: &InstanceHandle) -> Result<Health, BackendError> {
            Ok(Health::Unknown)
        }
        async fn list_volumes(&self) -> Result<Vec<VolumeInfo>, BackendError> {
            Ok(self
                .vols
                .lock()
                .unwrap()
                .iter()
                .map(|(name, size)| VolumeInfo {
                    name: name.clone(),
                    size_bytes: *size,
                })
                .collect())
        }
        async fn remove_volume(&self, name: &str) -> Result<bool, BackendError> {
            Ok(self.vols.lock().unwrap().remove(name).is_some())
        }
    }

    fn spec_with_volume(vol: Option<&str>) -> ComputeSpec {
        ComputeSpec {
            version: 1,
            root: RootSource::Image("img".into()),
            kernel: String::new(),
            kernel_cmdline: None,
            vcpus: 1,
            mem_mib: 64,
            entrypoint: vec![],
            env: BTreeMap::new(),
            port: 8080,
            restart: RestartPolicy::Always,
            startup_grace_secs: 30,
            scale_to_zero: false,
            volumes: vol
                .map(|n| {
                    vec![VolumeRef {
                        mount: "/data".into(),
                        name: n.into(),
                        size_mib: 128,
                    }]
                })
                .unwrap_or_default(),
            writable_root: false,
            cap_add: vec![],
            user: None,
            isolation: IsolationRequirement::Trusted,
            prefer_backend: None,
            bindings: vec![],
        }
    }

    /// Build a store with one workload named `wl` whose spec references volume
    /// `referenced` (or none), plus a `NodeComputeVolumes` over a fake backend that
    /// backs `backend_vols`.
    async fn setup(referenced: Option<&str>, backend_vols: &[(&str, u64)]) -> NodeComputeVolumes {
        let store = DeployStore::new(
            Arc::new(NullStorage),
            Arc::new(boatramp_core::kv::MemoryKv::new()),
        );
        let spec = spec_with_volume(referenced);
        let hash = store.put_compute_spec(&spec).await.expect("put spec");
        let workload = ComputeWorkload {
            version: 1,
            name: "wl".into(),
            active: hash,
            replicas: 1,
            placement: Default::default(),
        };
        store
            .set_compute_workload(ProjectRef::DEFAULT, &workload)
            .await
            .expect("set workload");
        let mut backends: boatramp_core::compute::BackendRegistry = BTreeMap::new();
        backends.insert(
            "container".into(),
            Arc::new(FakeVolumeBackend::with(backend_vols)) as Arc<dyn ComputeBackend>,
        );
        NodeComputeVolumes::new(backends, store)
    }

    #[tokio::test]
    async fn list_flags_referenced_volume_in_use_and_orphan_free() {
        // "data" is referenced by the workload spec; "old" is an orphan.
        let vols = setup(Some("data"), &[("data", 100), ("old", 50)]).await;
        let listed = vols.list().await.expect("list");
        assert_eq!(listed.len(), 2);
        let data = listed.iter().find(|v| v.info.name == "data").unwrap();
        let old = listed.iter().find(|v| v.info.name == "old").unwrap();
        assert!(data.in_use, "spec-referenced volume is in use");
        assert_eq!(data.info.size_bytes, 100);
        assert!(!old.in_use, "unreferenced volume is orphaned");
        assert_eq!(old.info.size_bytes, 50);
    }

    #[tokio::test]
    async fn remove_refuses_in_use_without_force_and_allows_with_force() {
        let vols = setup(Some("data"), &[("data", 100)]).await;
        // Without force: refused (in use by the registered workload).
        assert!(matches!(
            vols.remove("data", false).await,
            Err(VolumeError::InUse(n)) if n == "data"
        ));
        // The volume is still there (refusal didn't remove it).
        assert!(vols
            .list()
            .await
            .unwrap()
            .iter()
            .any(|v| v.info.name == "data"));
        // With force: removed.
        assert!(vols.remove("data", true).await.expect("forced remove"));
        assert!(vols.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn remove_orphan_succeeds_and_absent_reports_false() {
        // No workload references "old"; it removes without force.
        let vols = setup(None, &[("old", 50)]).await;
        assert!(vols.remove("old", false).await.expect("remove orphan"));
        // Removing an absent volume reports "did not exist".
        assert!(!vols.remove("gone", false).await.expect("remove absent"));
    }
}
