//! The macOS-native VMM [`ComputeBackend`]: run each replica as a Linux microVM
//! under Virtualization.framework via a re-exec'd `boatramp __vz-run` worker.
//!
//! Structurally the twin of the KVM `EmbeddedVmmBackend`: it stages the rootfs +
//! kernel blobs from `Storage`, hands out guest IPs from an [`IpPool`], spawns a
//! per-VM worker process, and reports a routable `Endpoint{host: guest_ip, port}`
//! on the vmnet NAT. It runs the same verify-before-boot [`KernelVerifier`] gate,
//! advertises the same strong `IsolationClass::VmKvm`, and emits the same
//! `Artifact::VmImages` — so the user surface is identical to Linux.
//!
//! The `launch`/`snapshot`/`restore` paths that actually boot a VM require macOS;
//! off macOS they return [`BackendError::Unsupported`] (the crate still compiles
//! so `boatramp-node`'s `build_compute` can `cfg`-gate registration cleanly). The
//! orchestration — staging, IPAM, ref encode/decode, spawn-arg construction — is
//! cross-platform and unit-tested everywhere.
//!
//! `persistent_volumes: true`, `scale_to_zero: true`. Scale-to-zero is live: the
//! reconcile parks an idle replica via `snapshot` (pause, `saveMachineStateToURL:`,
//! stop) and wakes it via `restore` (recreate the VM with the SAME machine identity,
//! `restoreMachineStateFromURL:`, resume). The round-trip preserves the guest's exact
//! in-RAM state and is validated end-to-end (the `vz_live_snapshot_restore_roundtrip`
//! test in `tests/vz_live.rs`). See [`VzBackend::restore`].

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use boatramp_core::compute::{
    compute_instance_id, Artifact, BackendError, Capabilities, ComputeBackend, ComputeSpec,
    Endpoint, Health, Instance, InstanceHandle, IsolationClass, LaunchRequest, RootSource, Scheme,
    Snapshot, VolumeRef,
};
use boatramp_core::ipam::IpPool;
use boatramp_core::Storage;
use futures::StreamExt;

use crate::config::{env_cmdline_fragment, WorkerConfig, WorkerVolume};
use crate::{KernelVerifier, VZ_RUN_SUBCOMMAND};

/// The content-addressed Storage key for a blob hash (`<2hex>/<hash>`) — matches
/// `boatramp_core::deploy` + the firecracker backends.
fn blob_key(hash: &str) -> String {
    let prefix = &hash[..2.min(hash.len())];
    format!("{prefix}/{hash}")
}

/// VM id for a workload replica — the registry key. Project-qualified
/// (`<project>-<workload>-<replica>`) for a non-`default` project, but bare
/// `<workload>-<replica>` for the `default` project (byte-identical to
/// pre-v0.3.12), delegating to the host-tested `compute_instance_id`.
fn vm_id(project: &str, workload: &str, replica: u32) -> String {
    compute_instance_id(project, workload, replica)
}

/// Encode a launched VM's endpoint into the handle's `backend_ref` (`<ip>:<port>`).
fn encode_ref(ip: &str, port: u16) -> String {
    format!("{ip}:{port}")
}

/// Decode `<ip>:<port>`.
fn decode_ref(s: &str) -> Option<(String, u16)> {
    let (ip, port) = s.rsplit_once(':')?;
    Some((ip.to_string(), port.parse().ok()?))
}

/// Reject a volume whose `name`/`mount` could escape its sandboxed location
/// (mirrors the container + KVM backends). `name` backs
/// `<data_dir>/compute/volumes/<name>.img` (single path component); `mount` is an
/// absolute guest path with no `..`.
fn validate_volume(name: &str, mount: &str) -> Result<(), BackendError> {
    let name_ok = matches!(
        Path::new(name).components().collect::<Vec<_>>().as_slice(),
        [Component::Normal(_)]
    );
    if !name_ok {
        return Err(BackendError::Launch(format!(
            "invalid volume name {name:?}: must be a single path component"
        )));
    }
    let m = Path::new(mount);
    let mount_ok = m.is_absolute()
        && m.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
    if !mount_ok {
        return Err(BackendError::Launch(format!(
            "invalid volume mount {mount:?}: must be an absolute path with no `..`"
        )));
    }
    Ok(())
}

/// Materialize each persistent volume's ext4 image under `vol_dir` (`<name>.img`),
/// creating + formatting it once (via `mke2fs`) and reusing it thereafter — so
/// volume data persists across a replica's launches (keyed by name, not VM).
/// Blocking; call off the async runtime. Returns per-volume image path + guest mount.
fn ensure_volume_images(
    vol_dir: &Path,
    volumes: &[VolumeRef],
) -> Result<Vec<WorkerVolume>, String> {
    if volumes.is_empty() {
        return Ok(Vec::new());
    }
    std::fs::create_dir_all(vol_dir).map_err(|e| format!("create volumes dir: {e}"))?;
    let mut out = Vec::with_capacity(volumes.len());
    for v in volumes {
        let path = vol_dir.join(format!("{}.img", v.name));
        let path_str = path
            .to_str()
            .ok_or_else(|| format!("non-utf8 volume path for {:?}", v.name))?
            .to_string();
        if !path.exists() {
            let size = format!("{}m", v.size_mib.max(1));
            let status = std::process::Command::new("mke2fs")
                .args(["-t", "ext4", "-F", "-q", &path_str, &size])
                .status()
                .map_err(|e| format!("spawn mke2fs for volume {:?}: {e}", v.name))?;
            if !status.success() {
                return Err(format!("mke2fs for volume {:?} exited {status}", v.name));
            }
        }
        out.push(WorkerVolume {
            image_path: path_str,
            mount: v.mount.clone(),
        });
    }
    Ok(out)
}

/// A running microVM: the `__vz-run` child + the resources to reclaim.
struct RunningVm {
    /// The `<self_exe> __vz-run` child running the VM. Killed / stdin-closed on stop.
    child: tokio::process::Child,
    /// Allocated guest IP (released on stop; held across a scale-to-zero snapshot).
    ip: std::net::Ipv4Addr,
    /// The config the VM was launched with — persisted on snapshot so a later
    /// [`restore`](VzBackend::restore) recreates the same VM to load the saved state.
    cfg: WorkerConfig,
}

/// The macOS-native VMM compute backend. Each replica runs as a re-exec'd
/// `boatramp __vz-run` process owning a `VZVirtualMachine` — a separate address
/// space + the hypervisor isolation boundary.
pub struct VzBackend {
    storage: Arc<dyn Storage>,
    /// This binary, re-execed as `__vz-run` to run each VM in its own process.
    self_exe: PathBuf,
    /// Root for staged blobs (`<data_dir>/compute/…`).
    data_dir: PathBuf,
    /// The vmnet gateway guests route through (the `.1` of `subnet`), in `ip=`.
    gateway: String,
    /// Per-node guest-IP pool.
    ipam: Mutex<IpPool>,
    /// Running VMs, keyed by [`vm_id`].
    running: Mutex<HashMap<String, RunningVm>>,
    /// Verify-before-boot gate: the staged kernel clears it before it loads.
    verifier: Arc<dyn KernelVerifier>,
    /// Whether a spec's `writable_root` is honored (single-tenant posture only).
    writable_root_allowed: bool,
}

impl VzBackend {
    /// Build a macOS VMM backend: stage blobs from `storage` under `data_dir`,
    /// hand out guest IPs from `subnet` (the vmnet range, e.g. `192.168.64.0/24`;
    /// its `.1` is the gateway), and run each VM by re-execing `self_exe` (this
    /// binary) as [`VZ_RUN_SUBCOMMAND`]. Every staged kernel clears `verifier`.
    pub fn new(
        storage: Arc<dyn Storage>,
        self_exe: PathBuf,
        data_dir: PathBuf,
        subnet: &str,
        verifier: Arc<dyn KernelVerifier>,
    ) -> Result<Self, BackendError> {
        let ipam = IpPool::new(subnet).map_err(|e| BackendError::Other(e.to_string()))?;
        let gateway = ipam.gateway().to_string();
        Ok(Self {
            storage,
            self_exe,
            data_dir,
            gateway,
            ipam: Mutex::new(ipam),
            running: Mutex::new(HashMap::new()),
            verifier,
            writable_root_allowed: false,
        })
    }

    /// Allow a spec's `writable_root` to relax the read-only root (single-tenant
    /// posture). Off by default so the multi-tenant guard keeps the hardened root.
    pub fn with_writable_root_allowed(mut self, allowed: bool) -> Self {
        self.writable_root_allowed = allowed;
        self
    }

    /// Fetch blob `hash` to `<data_dir>/compute/<subdir>/<hash><ext>` (streamed;
    /// skipped if present), returning the host path. Identical to the KVM backend.
    async fn stage_blob(
        &self,
        hash: &str,
        subdir: &str,
        ext: &str,
    ) -> Result<String, BackendError> {
        let dir = self.data_dir.join("compute").join(subdir);
        let dest = dir.join(format!("{hash}{ext}"));
        if tokio::fs::try_exists(&dest).await.unwrap_or(false) {
            return Ok(dest.display().to_string());
        }
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| BackendError::Materialize(format!("create {}: {e}", dir.display())))?;
        let obj = self
            .storage
            .get(&blob_key(hash))
            .await
            .map_err(|e| BackendError::Materialize(format!("fetch blob {hash}: {e}")))?;
        let tmp = dir.join(format!(".{hash}{ext}.tmp"));
        let mut body = obj.body;
        {
            use tokio::io::AsyncWriteExt;
            let mut file = tokio::fs::File::create(&tmp)
                .await
                .map_err(|e| BackendError::Materialize(format!("create {}: {e}", tmp.display())))?;
            while let Some(chunk) = body.next().await {
                let chunk = chunk.map_err(|e| BackendError::Materialize(e.to_string()))?;
                file.write_all(&chunk)
                    .await
                    .map_err(|e| BackendError::Materialize(format!("write {hash}: {e}")))?;
            }
            file.flush()
                .await
                .map_err(|e| BackendError::Materialize(e.to_string()))?;
        }
        tokio::fs::rename(&tmp, &dest)
            .await
            .map_err(|e| BackendError::Materialize(format!("rename {hash}: {e}")))?;
        Ok(dest.display().to_string())
    }

    /// Build the `WorkerConfig` for a launch request (pure; testable off macOS).
    /// Extracted so the spawn-arg construction is validated without a VM.
    fn worker_config(
        &self,
        req: &LaunchRequest,
        rootfs_path: String,
        kernel_path: String,
        ip: std::net::Ipv4Addr,
        volumes: Vec<WorkerVolume>,
    ) -> WorkerConfig {
        // A stable platform identity, minted once here (the VM's whole life), so a
        // later scale-to-zero restore recreates the SAME identity VZ demands. macOS
        // only (VZ); off macOS `launch` is never registered, so `None` is fine.
        #[cfg(target_os = "macos")]
        let machine_id = Some(crate::vm::new_machine_id_hex());
        #[cfg(not(target_os = "macos"))]
        let machine_id: Option<String> = None;
        WorkerConfig {
            rootfs_path,
            kernel_path,
            cmdline_override: req.spec.kernel_cmdline.clone(),
            env_cmdline: env_cmdline_fragment(&req.spec.env),
            guest_ip: ip.to_string(),
            gateway: self.gateway.clone(),
            writable_root: req.spec.writable_root && self.writable_root_allowed,
            mem_mib: req.spec.mem_mib,
            vcpus: req.spec.vcpus as u8,
            volumes,
            restore_path: None,
            machine_id,
        }
    }
}

/// Encode a snapshot's recovery info into its `data_ref` (`<stem>|<ip>|<port>`).
/// `<stem>` is the path prefix of the two snapshot files (`<stem>.vzstate` = the
/// saved VM state, `<stem>.cfg` = the JSON `WorkerConfig` to recreate the VM).
fn encode_snap(stem: &str, ip: &str, port: u16) -> String {
    format!("{stem}|{ip}|{port}")
}

/// Decode `<stem>|<ip>|<port>` from a snapshot `data_ref`.
fn decode_snap(s: &str) -> Option<(String, String, u16)> {
    let mut it = s.rsplitn(3, '|');
    let port = it.next()?.parse().ok()?;
    let ip = it.next()?.to_string();
    let stem = it.next()?.to_string();
    Some((stem, ip, port))
}

#[async_trait]
impl ComputeBackend for VzBackend {
    fn id(&self) -> &'static str {
        "vmm-vz"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // A per-container hypervisor VM — the same strong isolation as the KVM
            // backend (satisfies untrusted / multi-tenant workloads).
            isolation: IsolationClass::VmKvm,
            // Scale-to-zero: park an idle replica (pause + `saveMachineStateToURL:` +
            // stop) and later wake it (recreate the VM with the SAME stable machine
            // identity + `restoreMachineStateFromURL:` + resume). The resumed guest
            // keeps its exact in-RAM state — validated end-to-end (see
            // `snapshot`/`restore` and `tests/vz_live.rs`). The stable
            // `VZGenericMachineIdentifier` is the key: VZ rejects a restore whose
            // identifier differs from the saved VM's.
            scale_to_zero: true,
            // Persistent volumes as writable virtio-block images.
            persistent_volumes: true,
            max_vcpus: None,
            max_mem_mib: None,
        }
    }

    async fn materialize(&self, spec: &ComputeSpec) -> Result<Artifact, BackendError> {
        // The microVM boots an ext4 rootfs; an OCI image must be built into one
        // first (`compute build`), so it is not runnable here directly.
        let rootfs_hash = match &spec.root {
            RootSource::Rootfs(hash) => hash,
            RootSource::Image(_) | RootSource::Tar(_) => {
                return Err(BackendError::Materialize(
                    "macOS VMM requires a rootfs image (RootSource::Rootfs)".into(),
                ))
            }
        };
        let rootfs_path = self.stage_blob(rootfs_hash, "rootfs", ".ext4").await?;
        let kernel_path = self.stage_blob(&spec.kernel, "kernels", "").await?;
        // Verify-before-boot: the staged kernel is ring-0 code, so it clears the
        // posture bar before any guest loads it. Failure aborts materialize.
        let kernel_bytes = tokio::fs::read(&kernel_path)
            .await
            .map_err(|e| BackendError::Materialize(format!("read staged kernel: {e}")))?;
        self.verifier
            .verify(&kernel_bytes, &spec.kernel)
            .map_err(|e| {
                BackendError::Materialize(format!("kernel failed verify-before-boot: {e}"))
            })?;
        Ok(Artifact::VmImages {
            rootfs_path,
            kernel_path,
        })
    }

    async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
        let (rootfs_path, kernel_path) = match &req.artifact {
            Artifact::VmImages {
                rootfs_path,
                kernel_path,
            } => (rootfs_path.clone(), kernel_path.clone()),
            _ => {
                return Err(BackendError::Launch(
                    "macOS VMM backend requires a VmImages artifact".into(),
                ))
            }
        };

        let id = vm_id(&req.project, &req.workload, req.replica);
        let ip = {
            let mut pool = self.ipam.lock().expect("ipam mutex");
            pool.allocate()
                .map_err(|e| BackendError::Launch(e.to_string()))?
        };
        let port = req.spec.port;

        // Materialize persistent volumes off the async runtime, before spawn.
        for v in &req.spec.volumes {
            validate_volume(&v.name, &v.mount)?;
        }
        let vol_dir = self.data_dir.join("compute").join("volumes");
        let vols_spec = req.spec.volumes.clone();
        let worker_volumes =
            tokio::task::spawn_blocking(move || ensure_volume_images(&vol_dir, &vols_spec))
                .await
                .map_err(|e| BackendError::Launch(format!("join: {e}")))?
                .map_err(BackendError::Launch)?;

        let cfg = self.worker_config(req, rootfs_path, kernel_path, ip, worker_volumes);

        // Spawn `boatramp __vz-run <json>` with stdin piped (the control channel:
        // closing it asks the worker to stop the guest cleanly).
        let spawn_result = spawn_worker(&self.self_exe, &cfg);
        let child = match spawn_result {
            Ok(child) => child,
            Err(err) => {
                self.ipam.lock().expect("ipam mutex").release(ip);
                return Err(BackendError::Launch(err));
            }
        };

        self.running
            .lock()
            .expect("running mutex")
            .insert(id, RunningVm { child, ip, cfg });

        Ok(Instance {
            handle: InstanceHandle {
                project: req.project.clone(),
                workload: req.workload.clone(),
                replica: req.replica,
                backend_ref: encode_ref(&ip.to_string(), port),
            },
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: ip.to_string(),
                port,
            },
        })
    }

    async fn stop(&self, handle: &InstanceHandle) -> Result<(), BackendError> {
        let id = vm_id(&handle.project, &handle.workload, handle.replica);
        let running = self.running.lock().expect("running mutex").remove(&id);
        let Some(mut running) = running else {
            return Ok(()); // already stopped / never launched — idempotent
        };
        // Drop stdin (the control channel) so the worker requests a clean guest
        // stop, then kill + reap to bound teardown, and reclaim the IP.
        drop(running.child.stdin.take());
        let _ = running.child.kill().await;
        let _ = running.child.wait().await;
        self.ipam.lock().expect("ipam mutex").release(running.ip);
        Ok(())
    }

    async fn health(&self, handle: &InstanceHandle) -> Result<Health, BackendError> {
        let (ip, port) = decode_ref(&handle.backend_ref).ok_or_else(|| {
            BackendError::Other(format!("bad handle ref {:?}", handle.backend_ref))
        })?;
        // A TCP connect to the app port is the liveness probe (identical to the
        // KVM backend; the gateway does richer health-checking on the pool).
        let connect = tokio::net::TcpStream::connect((ip.as_str(), port));
        match tokio::time::timeout(Duration::from_secs(2), connect).await {
            Ok(Ok(_stream)) => Ok(Health::Healthy),
            Ok(Err(_)) => Ok(Health::Unhealthy),
            Err(_) => Ok(Health::Unknown), // timed out — indeterminate
        }
    }

    /// **Snapshot** (scale-to-zero park): ask the worker to pause + write its VM
    /// state (`saveMachineStateToURL:`) to `<stem>.vzstate`, persist the
    /// `WorkerConfig` to `<stem>.cfg` (a [`restore`](Self::restore) recreates the
    /// same VM to load it), and wait for the worker to exit. The guest IP stays
    /// reserved so the restore reuses it (the guest keeps that IP in its saved
    /// state). `Ok(None)` if the replica isn't running.
    async fn snapshot(&self, handle: &InstanceHandle) -> Result<Option<Snapshot>, BackendError> {
        let (_ip, port) = decode_ref(&handle.backend_ref).ok_or_else(|| {
            BackendError::Other(format!("bad handle ref {:?}", handle.backend_ref))
        })?;
        let id = vm_id(&handle.project, &handle.workload, handle.replica);
        let running = self.running.lock().expect("running mutex").remove(&id);
        let Some(mut running) = running else {
            return Ok(None); // not running — nothing to snapshot
        };
        let ip = running.ip;

        let dir = self.data_dir.join("compute").join("snapshots");
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| BackendError::Other(format!("create snapshots dir: {e}")))?;
        let stem = dir.join(&id).display().to_string();
        let state_path = format!("{stem}.vzstate");
        let cfg_path = format!("{stem}.cfg");
        // Persist the config so a restore can recreate the same VM (its attachments
        // must match the saved state). `saveMachineStateToURL:` requires the target
        // not already exist, so clear any stale state file from a prior park.
        let cfg_json =
            serde_json::to_vec(&running.cfg).map_err(|e| BackendError::Other(e.to_string()))?;
        tokio::fs::write(&cfg_path, cfg_json)
            .await
            .map_err(|e| BackendError::Other(format!("write {cfg_path}: {e}")))?;
        let _ = tokio::fs::remove_file(&state_path).await;

        // Request the save over the control channel, then wait for the worker to
        // pause + write the state file + exit.
        {
            use tokio::io::AsyncWriteExt;
            let mut stdin = running
                .child
                .stdin
                .take()
                .ok_or_else(|| BackendError::Other("no control channel".into()))?;
            stdin
                .write_all(format!("snapshot {state_path}\n").as_bytes())
                .await
                .map_err(|e| BackendError::Other(format!("send snapshot command: {e}")))?;
            stdin
                .flush()
                .await
                .map_err(|e| BackendError::Other(format!("flush snapshot command: {e}")))?;
        }
        let status = running
            .child
            .wait()
            .await
            .map_err(|e| BackendError::Other(format!("wait worker: {e}")))?;
        if !status.success() {
            // Save failed; the VM is gone, so reclaim the IP and report the error
            // (the reconcile then relaunches rather than parking).
            self.ipam.lock().expect("ipam mutex").release(ip);
            return Err(BackendError::Other(format!(
                "worker exited {status} during snapshot"
            )));
        }
        Ok(Some(Snapshot {
            project: handle.project.clone(),
            workload: handle.workload.clone(),
            replica: handle.replica,
            data_ref: encode_snap(&stem, &ip.to_string(), port),
        }))
    }

    /// **Restore** (scale-to-zero wake): read the persisted config, re-reserve the
    /// guest IP, and spawn a worker in restore mode — it recreates the VM and
    /// `restoreMachineStateFromURL:` + resumes from `<stem>.vzstate`. Returns the
    /// resumed replica at its original endpoint.
    ///
    /// The persisted `WorkerConfig` carries the VM's stable machine identity, which
    /// the worker feeds back into `VZGenericPlatformConfiguration` on restore — VZ
    /// requires it to match the saved VM's, and that match is what makes a Linux-guest
    /// `restoreMachineStateFromURL:` succeed rather than fail with "invalid argument".
    async fn restore(&self, snapshot: &Snapshot) -> Result<Instance, BackendError> {
        let (stem, ip, port) = decode_snap(&snapshot.data_ref).ok_or_else(|| {
            BackendError::Other(format!("bad snapshot ref {:?}", snapshot.data_ref))
        })?;
        let addr: std::net::Ipv4Addr = ip
            .parse()
            .map_err(|e| BackendError::Other(format!("bad snapshot ip {ip}: {e}")))?;
        let id = vm_id(&snapshot.project, &snapshot.workload, snapshot.replica);
        let state_path = format!("{stem}.vzstate");
        let cfg_path = format!("{stem}.cfg");

        let cfg_bytes = tokio::fs::read(&cfg_path)
            .await
            .map_err(|e| BackendError::Other(format!("read {cfg_path}: {e}")))?;
        let mut cfg: WorkerConfig =
            serde_json::from_slice(&cfg_bytes).map_err(|e| BackendError::Other(e.to_string()))?;
        cfg.restore_path = Some(state_path);

        // Re-reserve the guest IP so the pool won't reissue it while restoring.
        self.ipam.lock().expect("ipam mutex").reserve(addr);

        let child = match spawn_worker(&self.self_exe, &cfg) {
            Ok(child) => child,
            Err(err) => {
                self.ipam.lock().expect("ipam mutex").release(addr);
                return Err(BackendError::Launch(err));
            }
        };
        self.running.lock().expect("running mutex").insert(
            id,
            RunningVm {
                child,
                ip: addr,
                cfg,
            },
        );

        Ok(Instance {
            handle: InstanceHandle {
                project: snapshot.project.clone(),
                workload: snapshot.workload.clone(),
                replica: snapshot.replica,
                backend_ref: encode_ref(&ip, port),
            },
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: ip,
                port,
            },
        })
    }
}

/// Spawn the `__vz-run` worker for `cfg` with stdin piped. On macOS the child
/// boots the VM ([`crate::vm::run_worker`]); off macOS the child's `__vz-run`
/// entrypoint reports "unsupported" and exits — but `launch` is never reached off
/// macOS because `build_compute` `cfg`-gates registration.
fn spawn_worker(self_exe: &Path, cfg: &WorkerConfig) -> Result<tokio::process::Child, String> {
    let json = serde_json::to_string(cfg).map_err(|e| e.to_string())?;
    tokio::process::Command::new(self_exe)
        .arg(VZ_RUN_SUBCOMMAND)
        .arg(json)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", self_exe.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn vm_id_is_workload_dash_replica() {
        assert_eq!(vm_id("default", "web", 0), "web-0");
        assert_eq!(vm_id("default", "api-v2", 3), "api-v2-3");
        assert_eq!(vm_id("acme", "web", 0), "acme-web-0");
        assert_ne!(vm_id("acme", "web", 0), vm_id("beta", "web", 0));
    }

    #[test]
    fn backend_ref_round_trips() {
        let r = encode_ref("192.168.64.5", 8080);
        assert_eq!(r, "192.168.64.5:8080");
        assert_eq!(decode_ref(&r), Some(("192.168.64.5".to_string(), 8080)));
        assert_eq!(decode_ref("garbage"), None);
    }

    #[test]
    fn blob_key_is_two_hex_prefixed() {
        assert_eq!(blob_key("abcdef"), "ab/abcdef");
        assert_eq!(blob_key("a"), "a/a"); // short hash: prefix clamps
    }

    #[test]
    fn validate_volume_rejects_traversal() {
        assert!(validate_volume("db", "/data").is_ok());
        assert!(validate_volume("../etc", "/data").is_err());
        assert!(validate_volume("a/b", "/data").is_err());
        assert!(validate_volume("db", "relative").is_err());
        assert!(validate_volume("db", "/data/../etc").is_err());
    }

    #[test]
    fn capabilities_are_strong_vm_with_s2z_and_volumes() {
        // Strong per-VM isolation + persistent volumes + scale-to-zero (the VZ
        // save/restore round-trip is validated live — see `capabilities` and
        // `tests/vz_live.rs`).
        let caps = Capabilities {
            isolation: IsolationClass::VmKvm,
            scale_to_zero: true,
            persistent_volumes: true,
            max_vcpus: None,
            max_mem_mib: None,
        };
        assert!(caps.isolation.is_strong());
        assert!(caps.scale_to_zero);
        assert!(caps.persistent_volumes);
    }

    #[test]
    fn snapshot_ref_round_trips() {
        let r = encode_snap("/d/compute/snapshots/web-0", "192.168.64.5", 8080);
        assert_eq!(r, "/d/compute/snapshots/web-0|192.168.64.5|8080");
        assert_eq!(
            decode_snap(&r),
            Some((
                "/d/compute/snapshots/web-0".to_string(),
                "192.168.64.5".to_string(),
                8080
            ))
        );
        assert_eq!(decode_snap("garbage"), None);
    }

    /// The spawn-arg construction: the worker config carries the right cmdline
    /// fragment, gateway, and vcpu/mem — validated without spawning a process.
    #[test]
    fn worker_config_carries_env_and_gateway() {
        let mut env = BTreeMap::new();
        env.insert("PORT".to_string(), "8080".to_string());
        let cfg = WorkerConfig {
            rootfs_path: "/x/rootfs.ext4".into(),
            kernel_path: "/x/vmlinux".into(),
            cmdline_override: None,
            env_cmdline: env_cmdline_fragment(&env),
            guest_ip: "192.168.64.5".into(),
            gateway: "192.168.64.1".into(),
            writable_root: false,
            mem_mib: 256,
            vcpus: 2,
            volumes: vec![],
            restore_path: None,
            machine_id: None,
        };
        // The env fragment is present and gateway/vcpu/mem are threaded through.
        assert!(cfg.env_cmdline.starts_with(" boatramp.env="));
        assert_eq!(cfg.gateway, "192.168.64.1");
        assert_eq!(cfg.vcpus, 2);
        assert_eq!(cfg.mem_mib, 256);
        // Round-trips as the single JSON argv element the worker parses.
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(serde_json::from_str::<WorkerConfig>(&json).unwrap(), cfg);
    }
}
