//! The VMM [`ComputeBackend`].
//!
//! Wraps the Firecracker [`Executor`] behind `boatramp_core::compute`'s
//! backend trait: [`materialize`](VmmBackend::materialize) stages the rootfs +
//! kernel blobs from [`Storage`] to host files; [`launch`](VmmBackend::launch)
//! allocates a guest IP, builds the machine + tap, and drives the (blocking)
//! executor on a blocking thread; [`stop`](VmmBackend::stop) reconstructs the VM
//! from its handle; [`health`](VmmBackend::health) TCP-probes the app port. The
//! orchestration is pure-testable; the boot itself is the KVM-host seam.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use boatramp_core::compute::{
    Artifact, BackendError, Capabilities, ComputeBackend, ComputeSpec, Endpoint, Health, Instance,
    InstanceHandle, IsolationClass, LaunchRequest, Scheme, Snapshot,
};
use boatramp_core::Storage;
use futures::StreamExt;
use tokio::io::AsyncWriteExt;

use boatramp_core::ipam::IpPool;

use crate::config::{FcMachine, MachineResources};
use crate::executor::{Executor, Pid, RunningVm, SystemHost};
use crate::net::TapNetwork;

/// Size of each VM's ephemeral scratch drive (MiB).
const SCRATCH_MIB: u64 = 256;

/// The content-addressed Storage key for a blob hash (`<2hex>/<hash>`), matching
/// `boatramp_core::deploy`.
fn blob_key(hash: &str) -> String {
    let prefix = &hash[..2.min(hash.len())];
    format!("{prefix}/{hash}")
}

/// VM id for a workload replica (`<workload>-<replica>`); also the tap-name +
/// API-socket stem.
fn vm_id(workload: &str, replica: u32) -> String {
    format!("{workload}-{replica}")
}

/// Encode a launched VM's recovery info into the handle's `backend_ref`
/// (`<pid>@<ip>:<port>`) so `stop`/`health` work without in-memory state.
fn encode_ref(pid: u32, ip: &str, port: u16) -> String {
    format!("{pid}@{ip}:{port}")
}

/// Decode `<pid>@<ip>:<port>` back into `(pid, ip, port)`.
fn decode_ref(s: &str) -> Option<(u32, String, u16)> {
    let (pid, rest) = s.split_once('@')?;
    let (ip, port) = rest.rsplit_once(':')?;
    Some((pid.parse().ok()?, ip.to_string(), port.parse().ok()?))
}

/// The VMM compute backend: a Firecracker executor + blob staging + per-node IPAM.
pub struct VmmBackend {
    executor: Arc<Executor<SystemHost>>,
    storage: Arc<dyn Storage>,
    /// Root for staged blobs + scratch images (`<data_dir>/compute/…`).
    data_dir: PathBuf,
    /// Bridge each VM tap is enslaved to.
    bridge: String,
    /// Per-node guest-IP pool.
    ipam: Mutex<IpPool>,
}

impl VmmBackend {
    /// Build a VMM backend over `executor`, staging blobs from `storage` under
    /// `data_dir`, attaching taps to `bridge`, and handing out guest IPs from
    /// `subnet` (e.g. `10.0.0.0/24`).
    pub fn new(
        executor: Executor<SystemHost>,
        storage: Arc<dyn Storage>,
        data_dir: PathBuf,
        bridge: String,
        subnet: &str,
    ) -> Result<Self, BackendError> {
        let ipam = IpPool::new(subnet).map_err(|e| BackendError::Other(e.to_string()))?;
        Ok(Self {
            executor: Arc::new(executor),
            storage,
            data_dir,
            bridge,
            ipam: Mutex::new(ipam),
        })
    }

    /// Fetch blob `hash` to `<data_dir>/compute/<subdir>/<hash><ext>` (streamed;
    /// skipped if already present), returning the host path.
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

        // Stream to a temp file, then atomically rename into place.
        let tmp = dir.join(format!(".{hash}{ext}.tmp"));
        let mut file = tokio::fs::File::create(&tmp)
            .await
            .map_err(|e| BackendError::Materialize(format!("create {}: {e}", tmp.display())))?;
        let mut body = obj.body;
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|e| BackendError::Materialize(e.to_string()))?;
            file.write_all(&chunk)
                .await
                .map_err(|e| BackendError::Materialize(format!("write {hash}: {e}")))?;
        }
        file.flush()
            .await
            .map_err(|e| BackendError::Materialize(e.to_string()))?;
        drop(file);
        tokio::fs::rename(&tmp, &dest)
            .await
            .map_err(|e| BackendError::Materialize(format!("rename {hash}: {e}")))?;
        Ok(dest.display().to_string())
    }
}

#[async_trait]
impl ComputeBackend for VmmBackend {
    fn id(&self) -> &'static str {
        "vmm"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            isolation: IsolationClass::VmKvm,
            // Firecracker full-snapshot/restore (pause→create / load→resume) backs
            // scale-to-zero; persistent volumes are not yet supported.
            scale_to_zero: true,
            persistent_volumes: false,
            max_vcpus: None,
            max_mem_mib: None,
        }
    }

    async fn materialize(&self, spec: &ComputeSpec) -> Result<Artifact, BackendError> {
        let rootfs_path = self.stage_blob(&spec.rootfs, "rootfs", ".ext4").await?;
        let kernel_path = self.stage_blob(&spec.kernel, "kernels", "").await?;
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
                    "VMM backend requires a VmImages artifact".into(),
                ))
            }
        };

        let id = vm_id(&req.workload, req.replica);
        let ip = {
            let mut pool = self.ipam.lock().expect("ipam mutex");
            pool.allocate()
                .map_err(|e| BackendError::Launch(e.to_string()))?
        };
        let mac = IpPool::mac_for(ip);
        let scratch = self
            .data_dir
            .join("compute")
            .join("scratch")
            .join(format!("{id}.ext4"));
        let tap = TapNetwork::for_vm(&id, &self.bridge);
        let resources = MachineResources {
            kernel_path,
            rootfs_path,
            scratch_path: scratch.display().to_string(),
            tap_name: tap.tap_name.clone(),
            guest_mac: mac,
            guest_ip: ip.to_string(),
        };
        let machine = FcMachine::from_spec(&req.spec, &resources);

        // The executor is blocking (process spawn + socket waits): run it off the
        // async runtime. Create the scratch image in the same blocking task.
        let executor = self.executor.clone();
        let id_for_task = id.clone();
        let joined = tokio::task::spawn_blocking(move || -> Result<RunningVm, String> {
            make_scratch(&scratch, SCRATCH_MIB)?;
            executor
                .launch(&id_for_task, &machine, &tap)
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| BackendError::Launch(format!("join: {e}")))?;

        let running = match joined {
            Ok(running) => running,
            Err(err) => {
                // Launch failed (the executor already tore down its own tap);
                // return the guest IP to the pool.
                self.ipam.lock().expect("ipam mutex").release(ip);
                return Err(BackendError::Launch(err));
            }
        };

        let port = req.spec.port;
        Ok(Instance {
            handle: InstanceHandle {
                workload: req.workload.clone(),
                replica: req.replica,
                backend_ref: encode_ref(running.pid.0, &ip.to_string(), port),
            },
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: ip.to_string(),
                port,
            },
        })
    }

    async fn stop(&self, handle: &InstanceHandle) -> Result<(), BackendError> {
        let (pid, ip, _port) = decode_ref(&handle.backend_ref).ok_or_else(|| {
            BackendError::Stop(format!("bad handle ref {:?}", handle.backend_ref))
        })?;
        let id = vm_id(&handle.workload, handle.replica);
        let tap = TapNetwork::for_vm(&id, &self.bridge);
        let running = RunningVm {
            id: id.clone(),
            pid: Pid(pid),
            api_socket: self.executor.config().api_socket(&id),
            net_teardown: tap.teardown_commands(),
        };
        let executor = self.executor.clone();
        tokio::task::spawn_blocking(move || executor.stop(&running))
            .await
            .map_err(|e| BackendError::Stop(format!("join: {e}")))?
            .map_err(|e| BackendError::Stop(e.to_string()))?;
        // Return the guest IP to the pool.
        if let Ok(addr) = ip.parse() {
            self.ipam.lock().expect("ipam mutex").release(addr);
        }
        Ok(())
    }

    async fn health(&self, handle: &InstanceHandle) -> Result<Health, BackendError> {
        let (_pid, ip, port) = decode_ref(&handle.backend_ref).ok_or_else(|| {
            BackendError::Other(format!("bad handle ref {:?}", handle.backend_ref))
        })?;
        // A TCP connect to the app port is the liveness probe (the gateway does
        // its own richer health-checking on the upstream pool).
        let connect = tokio::net::TcpStream::connect((ip.as_str(), port));
        match tokio::time::timeout(Duration::from_secs(2), connect).await {
            Ok(Ok(_stream)) => Ok(Health::Healthy),
            Ok(Err(_)) => Ok(Health::Unhealthy),
            Err(_) => Ok(Health::Unknown), // timed out — indeterminate
        }
    }

    async fn snapshot(&self, handle: &InstanceHandle) -> Result<Option<Snapshot>, BackendError> {
        let (pid, ip, port) = decode_ref(&handle.backend_ref).ok_or_else(|| {
            BackendError::Other(format!("bad handle ref {:?}", handle.backend_ref))
        })?;
        let id = vm_id(&handle.workload, handle.replica);
        let dir = self.data_dir.join("compute").join("snapshots");
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| BackendError::Other(format!("create snapshots dir: {e}")))?;
        let snap_path = dir.join(format!("{id}.snap")).display().to_string();
        let mem_path = dir.join(format!("{id}.mem")).display().to_string();

        let tap = TapNetwork::for_vm(&id, &self.bridge);
        let running = RunningVm {
            id: id.clone(),
            pid: Pid(pid),
            api_socket: self.executor.config().api_socket(&id),
            net_teardown: tap.teardown_commands(),
        };
        let executor = self.executor.clone();
        let (sp, mp) = (snap_path.clone(), mem_path.clone());
        // The executor is blocking (API socket round-trips): run it off-runtime.
        tokio::task::spawn_blocking(move || executor.snapshot(&running, &sp, &mp))
            .await
            .map_err(|e| BackendError::Other(format!("join: {e}")))?
            .map_err(|e| BackendError::Other(e.to_string()))?;

        Ok(Some(Snapshot {
            workload: handle.workload.clone(),
            replica: handle.replica,
            data_ref: encode_snap(&snap_path, &mem_path, &ip, port),
        }))
    }

    async fn restore(&self, snapshot: &Snapshot) -> Result<Instance, BackendError> {
        let (snap_path, mem_path, ip, port) = decode_snap(&snapshot.data_ref).ok_or_else(|| {
            BackendError::Other(format!("bad snapshot ref {:?}", snapshot.data_ref))
        })?;
        let id = vm_id(&snapshot.workload, snapshot.replica);
        // Re-reserve the guest IP so the pool won't hand it to another VM while
        // this replica is (was) scaled to zero.
        if let Ok(addr) = ip.parse() {
            self.ipam.lock().expect("ipam mutex").reserve(addr);
        }
        let tap = TapNetwork::for_vm(&id, &self.bridge);
        let executor = self.executor.clone();
        let (id_task, sp, mp) = (id.clone(), snap_path.clone(), mem_path.clone());
        let joined = tokio::task::spawn_blocking(move || {
            executor
                .restore(&id_task, &tap, &sp, &mp)
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| BackendError::Other(format!("join: {e}")))?;

        let running = match joined {
            Ok(running) => running,
            Err(err) => {
                // Restore failed (the executor tore down its own tap); release the
                // IP we reserved.
                if let Ok(addr) = ip.parse() {
                    self.ipam.lock().expect("ipam mutex").release(addr);
                }
                return Err(BackendError::Launch(err));
            }
        };

        Ok(Instance {
            handle: InstanceHandle {
                workload: snapshot.workload.clone(),
                replica: snapshot.replica,
                backend_ref: encode_ref(running.pid.0, &ip, port),
            },
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: ip,
                port,
            },
        })
    }
}

/// Encode a snapshot's recovery info (`<snap>|<mem>|<ip>|<port>`) into the
/// [`Snapshot::data_ref`] so `restore` is self-contained (the snapshot + memory
/// files to load, and the guest IP\:port to re-advertise).
fn encode_snap(snap_path: &str, mem_path: &str, ip: &str, port: u16) -> String {
    format!("{snap_path}|{mem_path}|{ip}|{port}")
}

/// Decode `<snap>|<mem>|<ip>|<port>`.
fn decode_snap(s: &str) -> Option<(String, String, String, u16)> {
    let mut it = s.split('|');
    let snap = it.next()?.to_string();
    let mem = it.next()?.to_string();
    let ip = it.next()?.to_string();
    let port = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((snap, mem, ip, port))
}

/// Create a sparse `size_mib` ext4 scratch image with `mke2fs` (e2fsprogs).
fn make_scratch(path: &Path, size_mib: u64) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("scratch dir: {e}"))?;
    }
    let blocks = (size_mib * 1024).to_string(); // 1 KiB blocks
    let status = std::process::Command::new("mke2fs")
        .args(["-F", "-q", "-t", "ext4"])
        .arg(path)
        .arg(&blocks)
        .status()
        .map_err(|e| format!("spawning mke2fs: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("mke2fs exited with {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_id_is_workload_dash_replica() {
        assert_eq!(vm_id("web", 0), "web-0");
        assert_eq!(vm_id("api-v2", 3), "api-v2-3");
    }

    #[test]
    fn backend_ref_round_trips() {
        let r = encode_ref(4242, "10.0.0.5", 8080);
        assert_eq!(r, "4242@10.0.0.5:8080");
        assert_eq!(decode_ref(&r), Some((4242, "10.0.0.5".to_string(), 8080)));
        assert_eq!(decode_ref("garbage"), None);
        assert_eq!(decode_ref("4242@10.0.0.5"), None, "missing port");
    }

    #[test]
    fn blob_key_is_two_char_sharded() {
        assert_eq!(blob_key("abcdef"), "ab/abcdef");
        assert_eq!(&blob_key(&"d".repeat(64))[..3], "dd/");
    }

    #[test]
    fn snapshot_ref_round_trips() {
        let r = encode_snap(
            "/d/snapshots/web-0.snap",
            "/d/snapshots/web-0.mem",
            "10.0.0.5",
            8080,
        );
        assert_eq!(
            decode_snap(&r),
            Some((
                "/d/snapshots/web-0.snap".to_string(),
                "/d/snapshots/web-0.mem".to_string(),
                "10.0.0.5".to_string(),
                8080
            ))
        );
        assert_eq!(decode_snap("too|few|parts"), None, "missing port");
        assert_eq!(decode_snap("a|b|c|1|extra"), None, "too many parts");
    }
}
