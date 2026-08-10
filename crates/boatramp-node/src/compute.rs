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

    // Native container backend (Linux only).
    #[cfg(target_os = "linux")]
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
    // Embedded VMM backend (Linux + x86_64 + `/dev/kvm`): in-process microVMs, no
    // external `firecracker` binary — the strongest isolation when KVM is available.
    // Like the container backend it enslaves each tap to `cfg.bridge` (assumed set
    // up). The embedded VMM is KVM-x86-specific, so this is x86_64-only; boatramp
    // still serves on linux/aarch64 (with the container backend, no embedded VMM).
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if std::path::Path::new("/dev/kvm").exists() {
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
