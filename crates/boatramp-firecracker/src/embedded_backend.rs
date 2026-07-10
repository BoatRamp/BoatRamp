//! The **embedded** VMM [`ComputeBackend`]: run each replica as an
//! [`EmbeddedVmm`] microVM under KVM — no
//! external `firecracker` process, no API socket.
//!
//! It reuses the external [`VmmBackend`](crate::backend::VmmBackend)'s plumbing —
//! [`IpPool`] for guest IPs, [`TapNetwork`] for the host tap, `Storage` blob
//! staging for the rootfs + kernel — but runs the VMM itself instead of spawning
//! firecracker. For untrusted-multi-tenant isolation each VM runs in its **own
//! jailed subprocess**: [`launch`](EmbeddedVmmBackend::launch) creates the tap
//! (the one privileged step) then spawns `self_exe __vmm-run <WorkerConfig>`,
//! which ([`run_jailed_worker`]) attaches the tap, builds + boots the guest, then
//! **drops all capabilities + installs the run-loop seccomp filter** before
//! entering the run loop — a separate address space + dropped caps + seccomp, so
//! a guest escape can't reach other tenants' memory or the host syscall surface.
//! [`stop`](EmbeddedVmmBackend::stop) SIGKILLs the subprocess (PID-tracked in a
//! small registry) and reclaims the tap + IP.
//!
//! Linux + `/dev/kvm`, behind the `backend` + `embedded` features. The
//! orchestration (staging, IP/tap allocation, spawn, teardown) is the testable
//! part; the boot itself is the KVM-host (`compute-live`) seam.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use boatramp_core::compute::{
    Artifact, BackendError, Capabilities, ComputeBackend, ComputeSpec, Endpoint, Health, Instance,
    InstanceHandle, IsolationClass, LaunchRequest, Scheme, Snapshot, VolumeRef,
};
use boatramp_core::ipam::IpPool;
use boatramp_core::Storage;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use vm_memory::Address;

use crate::device_manager::{DeviceManager, VirtioDeviceOps};
use crate::embedded::mmio_cmdline_arg;
use crate::embedded_vmm::EmbeddedVmm;
use crate::net::{HostCommand, TapNetwork};
use crate::tap::Tap;
use crate::virtio_block::{VirtioBlock, SECTOR_SIZE};
use crate::virtio_net::VirtioNet;

/// The re-exec subcommand the backend invokes for each VM: `<self_exe> __vmm-run
/// <json-WorkerConfig>`. The host binary (and the test's `vmm-worker` bin) route
/// it to [`run_jailed_worker`].
pub const VMM_RUN_SUBCOMMAND: &str = "__vmm-run";

/// MiB → bytes (guest memory sizing).
const MIB: u64 = 1024 * 1024;
/// The virtio-net device's index on the bus (block is 0, net is 1).
const NET_INDEX: usize = 1;

/// The content-addressed Storage key for a blob hash (`<2hex>/<hash>`), matching
/// `boatramp_core::deploy` + the external [`VmmBackend`](crate::backend).
fn blob_key(hash: &str) -> String {
    let prefix = &hash[..2.min(hash.len())];
    format!("{prefix}/{hash}")
}

/// VM id for a workload replica (`<workload>-<replica>`) — the registry key + the
/// tap-name stem.
fn vm_id(workload: &str, replica: u32) -> String {
    format!("{workload}-{replica}")
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

/// Encode a snapshot's recovery info (`<stem>|<ip>|<port>`) into its `data_ref`.
/// `<stem>` is the path prefix of the two snapshot files (`<stem>.snap` = the
/// state+RAM stream, `<stem>.cfg` = the worker config).
fn encode_snap(stem: &str, ip: &str, port: u16) -> String {
    format!("{stem}|{ip}|{port}")
}

/// Decode `<stem>|<ip>|<port>`.
fn decode_snap(s: &str) -> Option<(String, String, u16)> {
    let mut parts = s.split('|');
    let stem = parts.next()?.to_string();
    let ip = parts.next()?.to_string();
    let port = parts.next()?.parse().ok()?;
    Some((stem, ip, port))
}

/// Parse an `aa:bb:cc:dd:ee:ff` MAC string into 6 bytes.
fn parse_mac(mac: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    for (i, octet) in mac.split(':').take(6).enumerate() {
        out[i] = u8::from_str_radix(octet, 16).unwrap_or(0);
    }
    out
}

/// The default embedded kernel cmdline: serial console, root on the first virtio
/// block device (read-only), and the static guest IP via the kernel `ip=`
/// autoconfig (gateway = the bridge address). The virtio-MMIO `device=` fragments
/// are appended separately (they depend on the device bus layout).
fn default_cmdline(guest_ip: &str, gateway: &str) -> String {
    format!(
        "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro \
         ip={guest_ip}::{gateway}:255.255.255.0::eth0:off"
    )
}

/// Reject a volume whose `name` or `mount` could escape its sandboxed location
/// (mirroring the container backend). The `name` backs
/// `<data_dir>/compute/volumes/<name>.img`, so it must be a single path component
/// (no `/`, `.`, `..`); the `mount` is an absolute guest path with no `..`.
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

/// Materialize each persistent volume's ext4 image under `vol_dir`
/// (`<name>.img`), creating + formatting it once (via `mke2fs`, the documented
/// host seam) and reusing it thereafter — so volume data persists across a
/// replica's launches/restarts (keyed by volume name, not VM). Blocking — call
/// off the async runtime. Returns the per-volume image path + guest mount.
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
            // A fresh, empty ext4 of the requested size (mke2fs creates the file).
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

/// A running embedded microVM: the jailed subprocess + the resources to reclaim.
struct RunningVm {
    /// The `<self_exe> __vmm-run` child running the VM (killed on stop).
    child: Child,
    /// The child's stdin — the control channel a snapshot request is written to.
    stdin: Option<ChildStdin>,
    /// The worker config the VM was launched with (persisted on snapshot so a
    /// later [`restore`](EmbeddedVmmBackend::restore) can respawn the same VM).
    cfg: WorkerConfig,
    /// Allocated guest IP (released on stop; held across a snapshot).
    ip: std::net::Ipv4Addr,
    /// The host tap (torn down on stop / snapshot, re-created on restore).
    tap: TapNetwork,
}

/// The embedded VMM compute backend. Each replica runs as a **jailed subprocess**
/// (re-exec of `self_exe __vmm-run`): a separate address space + dropped caps +
/// the run-loop seccomp filter, so an untrusted guest's escape can't reach other
/// tenants' memory or the host's syscall surface.
pub struct EmbeddedVmmBackend {
    storage: Arc<dyn Storage>,
    /// This binary, re-execed as `__vmm-run` to run each VM in its own process.
    self_exe: PathBuf,
    /// Root for staged blobs (`<data_dir>/compute/…`).
    data_dir: PathBuf,
    /// Bridge each VM tap is enslaved to.
    bridge: String,
    /// The bridge's gateway address (guests route through it; goes in `ip=`).
    gateway: String,
    /// Per-node guest-IP pool.
    ipam: Mutex<IpPool>,
    /// Running VMs, keyed by [`vm_id`].
    running: Mutex<HashMap<String, RunningVm>>,
    /// Verify-before-boot gate: the staged kernel must clear it before it loads.
    verifier: Arc<dyn crate::KernelVerifier>,
}

impl EmbeddedVmmBackend {
    /// Build an embedded VMM backend: stage blobs from `storage` under `data_dir`,
    /// attach taps to `bridge` (whose address `gateway` the guests route through),
    /// hand out guest IPs from `subnet` (e.g. `10.0.0.0/24`), and run each VM by
    /// re-execing `self_exe` (this binary) as [`VMM_RUN_SUBCOMMAND`]. Every staged
    /// kernel clears `verifier` (verify-before-boot) before a guest is launched.
    pub fn new(
        storage: Arc<dyn Storage>,
        self_exe: PathBuf,
        data_dir: PathBuf,
        bridge: String,
        gateway: String,
        subnet: &str,
        verifier: Arc<dyn crate::KernelVerifier>,
    ) -> Result<Self, BackendError> {
        let ipam = IpPool::new(subnet).map_err(|e| BackendError::Other(e.to_string()))?;
        Ok(Self {
            storage,
            self_exe,
            data_dir,
            bridge,
            gateway,
            ipam: Mutex::new(ipam),
            running: Mutex::new(HashMap::new()),
            verifier,
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

/// Set up the tap + spawn the jailed `__vmm-run` child for `cfg`. stdin is the
/// control channel (snapshot requests) and stdout the snapshot-out channel, both
/// piped. For a **restore**, `restore_file` is dup2'd onto [`RESTORE_FD`] in the
/// child (via `pre_exec`) so it can read the snapshot stream there. Blocking —
/// call off the async runtime.
#[cfg(target_os = "linux")]
fn spawn_worker(
    self_exe: &Path,
    cfg: &WorkerConfig,
    tap: &TapNetwork,
    restore_file: Option<File>,
) -> Result<Child, String> {
    for cmd in tap.setup_commands() {
        run_host_command(&cmd)?;
    }
    let json = serde_json::to_string(cfg).map_err(|e| e.to_string())?;
    let mut command = Command::new(self_exe);
    command
        .arg(VMM_RUN_SUBCOMMAND)
        .arg(json)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    if let Some(file) = restore_file {
        // SAFETY: `pre_exec` runs post-fork / pre-exec; `dup2` is async-signal-safe
        // and touches only this child's fd table. `file` is moved in so it stays
        // open until exec; RESTORE_FD is not `CLOEXEC`, so it survives into the VM.
        unsafe {
            command.pre_exec(move || {
                nix::unistd::dup2(file.as_raw_fd(), RESTORE_FD)
                    .map(|_| ())
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
            });
        }
    }
    command
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", self_exe.display()))
}

/// Run a host command best-effort, mapping a non-zero exit to an error string.
fn run_host_command(cmd: &HostCommand) -> Result<(), String> {
    let status = std::process::Command::new(&cmd.program)
        .args(&cmd.args)
        .status()
        .map_err(|e| format!("spawn {}: {e}", cmd.program))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{} exited with {status}", cmd.display()))
    }
}

/// Everything the jailed `__vmm-run` child needs to build + run one VM. Passed as
/// a single JSON argv element (no quoting concerns), so the backend and the child
/// stay in lock-step across the re-exec boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    /// Host path to the (already-staged) ext4/squashfs rootfs.
    pub rootfs_path: String,
    /// Host path to the guest `vmlinux`.
    pub kernel_path: String,
    /// Kernel cmdline override (`None` ⇒ the default serial + `root=/dev/vda` +
    /// static `ip=`); the virtio-MMIO `device=` fragments are always appended.
    pub cmdline_override: Option<String>,
    /// The pre-created host tap to attach to (parent enslaves it to the bridge).
    pub tap_name: String,
    /// The guest's static IP (kernel `ip=` autoconfig; also derives the MAC).
    pub guest_ip: String,
    /// The bridge gateway the guest routes through.
    pub gateway: String,
    /// Guest memory (MiB) + vCPUs.
    pub mem_mib: u32,
    /// vCPU count.
    pub vcpus: u8,
    /// When `true`, **restore**: read a snapshot stream from [`RESTORE_FD`]
    /// and resume the VM, instead of building it fresh from the kernel + rootfs.
    #[serde(default)]
    pub restore: bool,
    /// Persistent volumes attached as writable virtio-block devices
    /// (`/dev/vdb`, `/dev/vdc`, …) after the rootfs + net, in order.
    #[serde(default)]
    pub volumes: Vec<WorkerVolume>,
}

/// One persistent volume as the jailed worker needs it: the (already-created)
/// host image to attach writably + the guest path it is mounted at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerVolume {
    /// Host path to the volume's ext4 image (`<data_dir>/compute/volumes/<name>.img`).
    pub image_path: String,
    /// Guest mount point (validated absolute, no `..`).
    pub mount: String,
}

/// The inherited fd the restore child reads its snapshot stream from. The parent
/// `dup2`s the snapshot file onto it via `pre_exec` (stdin stays the control
/// channel, stdout the snapshot-out channel — keeping the jailed child to
/// `read`/`write`, never `open`, on the snapshot path).
const RESTORE_FD: RawFd = 3;
/// The newline control command the parent writes to the child's stdin to request
/// a snapshot (the child captures + streams it to stdout, then exits).
const SNAPSHOT_CMD: &str = "snapshot";

/// Write the framed snapshot stream: `[u32 meta_len][meta JSON =
/// Vec<DeviceState>][u64 vmstate_len][vmstate POD][guest RAM]`. The device state +
/// VM CPU/chip state precede the (large) RAM so the reader can reconstruct
/// incrementally. Mirrors [`read_snapshot_header`] + [`EmbeddedVmm::restore`].
fn write_snapshot_stream(
    w: &mut dyn std::io::Write,
    device_states: &[crate::device_manager::DeviceState],
    vmm: &EmbeddedVmm,
) -> Result<(), String> {
    let meta = serde_json::to_vec(device_states).map_err(|e| format!("encode devices: {e}"))?;
    let meta_len = u32::try_from(meta.len()).map_err(|e| format!("meta too large: {e}"))?;
    w.write_all(&meta_len.to_le_bytes())
        .and_then(|()| w.write_all(&meta))
        .map_err(|e| format!("write meta: {e}"))?;

    let snap = vmm.capture_state().map_err(|e| format!("capture: {e}"))?;
    let mut vmbuf = Vec::new();
    snap.write_to(&mut vmbuf)
        .map_err(|e| format!("encode vm state: {e}"))?;
    w.write_all(&(vmbuf.len() as u64).to_le_bytes())
        .and_then(|()| w.write_all(&vmbuf))
        .map_err(|e| format!("write vm state: {e}"))?;

    vmm.dump_ram(w).map_err(|e| format!("dump ram: {e}"))?;
    w.flush().map_err(|e| format!("flush snapshot: {e}"))
}

/// Read the header of a snapshot stream — the device state + VM CPU/chip state —
/// leaving `r` positioned at the guest RAM (handed straight to
/// [`EmbeddedVmm::restore`] as the memory reader).
fn read_snapshot_header(
    r: &mut dyn std::io::Read,
) -> Result<
    (
        Vec<crate::device_manager::DeviceState>,
        crate::embedded_snapshot::VmSnapshot,
    ),
    String,
> {
    let mut len4 = [0u8; 4];
    r.read_exact(&mut len4)
        .map_err(|e| format!("read meta len: {e}"))?;
    let mut meta = vec![0u8; u32::from_le_bytes(len4) as usize];
    r.read_exact(&mut meta)
        .map_err(|e| format!("read meta: {e}"))?;
    let device_states =
        serde_json::from_slice(&meta).map_err(|e| format!("decode devices: {e}"))?;

    let mut len8 = [0u8; 8];
    r.read_exact(&mut len8)
        .map_err(|e| format!("read vm state len: {e}"))?;
    let mut vmbuf = vec![0u8; u64::from_le_bytes(len8) as usize];
    r.read_exact(&mut vmbuf)
        .map_err(|e| format!("read vm state: {e}"))?;
    let vmsnap = crate::embedded_snapshot::VmSnapshot::read_from(&mut vmbuf.as_slice())
        .map_err(|e| format!("decode vm state: {e}"))?;
    Ok((device_states, vmsnap))
}

/// Watch the child's **stdin** for the [`SNAPSHOT_CMD`] line; on it, flag the
/// request and wind the run loop down (set `stop` + kick the vCPUs, exactly like
/// the external stop path). Run on its own thread *after* the seccomp filter is
/// installed, so it inherits the sandbox (it only `read`s stdin + signals vCPUs).
#[cfg(target_os = "linux")]
fn watch_for_snapshot_command(
    stop: Arc<AtomicBool>,
    vcpu_tid: Arc<AtomicU64>,
    requested: Arc<AtomicBool>,
) {
    use std::io::BufRead;
    let mut line = String::new();
    let stdin = std::io::stdin();
    let mut locked = stdin.lock();
    loop {
        line.clear();
        match locked.read_line(&mut line) {
            Ok(0) => return, // EOF: parent closed the control channel
            Ok(_) => {
                if line.trim() == SNAPSHOT_CMD {
                    requested.store(true, std::sync::atomic::Ordering::SeqCst);
                    stop.store(true, std::sync::atomic::Ordering::SeqCst);
                    crate::embedded_vmm::interrupt_vcpu(&vcpu_tid);
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// Drop **every** capability of the calling (worker) process — called after the
/// tap is attached (the only privileged step), before the guest runs. Order
/// matters: clear Bounding/Ambient/Inheritable *first* (dropping the bounding set
/// needs `CAP_SETPCAP`, still in Effective), then Effective + Permitted last.
#[cfg(target_os = "linux")]
fn drop_all_caps() -> Result<(), String> {
    for set in [
        caps::CapSet::Ambient,
        caps::CapSet::Bounding,
        caps::CapSet::Inheritable,
    ] {
        caps::clear(None, set).map_err(|e| format!("clear caps {set:?}: {e}"))?;
    }
    caps::clear(None, caps::CapSet::Effective).map_err(|e| format!("clear effective caps: {e}"))?;
    caps::clear(None, caps::CapSet::Permitted).map_err(|e| format!("clear permitted caps: {e}"))?;
    Ok(())
}

/// Run one VM **in this process**, to be invoked from the re-exec'd `__vmm-run`
/// child (or the test's `vmm-worker` bin): attach the tap, assemble the virtio
/// bus (block rootfs + net), build + boot the guest, then **jail this process** —
/// drop all capabilities + install the run-loop seccomp filter — and enter the
/// run loop. Runs until the guest exits or the process is killed (the backend's
/// `stop` SIGKILLs it). The separate address space + dropped caps + seccomp are
/// the untrusted-multi-tenant isolation boundary. Linux + `/dev/kvm`.
#[cfg(target_os = "linux")]
pub fn run_jailed_worker(cfg: WorkerConfig) -> Result<(), String> {
    // Attach our fds to the (parent-created) tap: TX for the device, RX poller.
    let tap = Tap::open(&cfg.tap_name).map_err(|e| e.to_string())?;
    let tx_tap = tap.try_clone().map_err(|e| e.to_string())?;
    let rx_tap = tap.try_clone().map_err(|e| e.to_string())?;

    // virtio-block (read-only rootfs) + virtio-net on the bus.
    let rootfs = File::open(&cfg.rootfs_path).map_err(|e| format!("open rootfs: {e}"))?;
    let sectors = rootfs
        .metadata()
        .map_err(|e| format!("stat rootfs: {e}"))?
        .len()
        / SECTOR_SIZE;
    let block: Box<dyn VirtioDeviceOps> = Box::new(VirtioBlock::new(rootfs, sectors, true));
    let mac = parse_mac(&IpPool::mac_for(
        cfg.guest_ip
            .parse()
            .map_err(|e| format!("bad guest ip: {e}"))?,
    ));
    let net: Box<dyn VirtioDeviceOps> = Box::new(VirtioNet::new(mac, tx_tap));

    // Bus order: rootfs (vda, read-only), net, then each persistent volume as a
    // **writable** virtio-block device (vdb, vdc, … — net carries no `vdX`, so the
    // block enumeration stays rootfs-then-volumes).
    let mut devices: Vec<Box<dyn VirtioDeviceOps>> = vec![block, net];
    for vol in &cfg.volumes {
        let img = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&vol.image_path)
            .map_err(|e| format!("open volume {}: {e}", vol.image_path))?;
        let vsectors = img
            .metadata()
            .map_err(|e| format!("stat volume {}: {e}", vol.image_path))?
            .len()
            / SECTOR_SIZE;
        devices.push(Box::new(VirtioBlock::new(img, vsectors, false)));
    }
    let mut manager = DeviceManager::new(devices).map_err(|e| e.to_string())?;

    // Either restore a snapshotted VM or build it fresh from kernel+rootfs.
    // Both finish with a paused VM + a device manager wired to the same bus.
    let mut vmm = if cfg.restore {
        // SAFETY: the parent dup2'd the snapshot file onto RESTORE_FD; we own it.
        let mut snap = unsafe { File::from_raw_fd(RESTORE_FD) };
        let (device_states, vmsnap) = read_snapshot_header(&mut snap)?;
        let vmm = EmbeddedVmm::restore(&vmsnap, &mut snap).map_err(|e| format!("restore: {e}"))?;
        manager
            .restore_device_states(&device_states)
            .map_err(|e| format!("restore devices: {e}"))?;
        vmm
    } else {
        // cmdline = base (override or default) + the virtio-MMIO device fragments.
        let mmio: String = manager
            .windows()
            .iter()
            .map(mmio_cmdline_arg)
            .collect::<Vec<_>>()
            .join(" ");
        let base = cfg
            .cmdline_override
            .clone()
            .unwrap_or_else(|| default_cmdline(&cfg.guest_ip, &cfg.gateway));
        let cmdline = format!("{base} {mmio}");

        let vmm = EmbeddedVmm::with_irqchip(u64::from(cfg.mem_mib) * MIB, cfg.vcpus)
            .map_err(|e| format!("create vm: {e}"))?;
        let entry = vmm
            .load_kernel(Path::new(&cfg.kernel_path))
            .map_err(|e| format!("load kernel: {e}"))?;
        vmm.write_boot_params(&cmdline)
            .map_err(|e| format!("boot params: {e}"))?;
        vmm.setup_registers(entry.raw_value())
            .map_err(|e| format!("registers: {e}"))?;
        vmm
    };

    // Jail this process now that all privileged setup is done: drop caps, then
    // confine to the run-loop syscalls (the RX poller + the snapshot-control
    // thread spawned below inherit it).
    drop_all_caps()?;
    crate::embedded_seccomp::install().map_err(|e| e.to_string())?;

    // Run until the guest exits, a snapshot is requested, or the process is killed
    // (the stop path SIGKILLs). The guest serial is discarded by default; set
    // `BOATRAMP_VMM_SERIAL` to tee it to this process's stderr (for boot debugging).
    let manager = Arc::new(Mutex::new(manager));
    let stop = Arc::new(AtomicBool::new(false));
    let vcpu_tid = Arc::new(AtomicU64::new(0));
    let snapshot_requested = Arc::new(AtomicBool::new(false));
    {
        let (stop, vcpu_tid, requested) =
            (stop.clone(), vcpu_tid.clone(), snapshot_requested.clone());
        std::thread::Builder::new()
            .name("snapshot-control".into())
            .spawn(move || watch_for_snapshot_command(stop, vcpu_tid, requested))
            .map_err(|e| format!("spawn control thread: {e}"))?;
    }
    let sink: Box<dyn std::io::Write + Send> = if std::env::var_os("BOATRAMP_VMM_SERIAL").is_some()
    {
        Box::new(std::io::stderr())
    } else {
        Box::new(std::io::sink())
    };
    let exit = vmm
        .run_with_net(
            manager.clone(),
            Some((NET_INDEX, rx_tap)),
            stop,
            vcpu_tid,
            sink,
        )
        .map_err(|e| e.to_string())?;

    // A requested snapshot: the run loop has stopped + reclaimed the (paused)
    // vCPUs, so capture the device + VM state and stream it to stdout (the parent
    // captures it into the snapshot file). `open` is off the seccomp allow-list —
    // streaming over the inherited stdout keeps the child to `write`.
    if snapshot_requested.load(std::sync::atomic::Ordering::SeqCst) {
        let device_states = manager.lock().expect("device manager").save_device_states();
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        write_snapshot_stream(&mut out, &device_states, &vmm)?;
        return Ok(());
    }
    // Log how the guest ended (a clean Shutdown — e.g. a guest panic with
    // `panic=1 reboot=k` — would otherwise be a silent exit).
    eprintln!("vmm-worker: guest exited: {exit:?}");
    Ok(())
}

#[async_trait]
impl ComputeBackend for EmbeddedVmmBackend {
    fn id(&self) -> &'static str {
        "vmm-embedded"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            isolation: IsolationClass::VmKvm,
            // Snapshot the paused VM (vCPU + chip + device-model state + RAM)
            // to disk + restore it into a fresh jailed worker that resumes.
            scale_to_zero: true,
            // Persistent volumes as writable virtio-block images.
            persistent_volumes: true,
            max_vcpus: None,
            max_mem_mib: None,
        }
    }

    async fn materialize(&self, spec: &ComputeSpec) -> Result<Artifact, BackendError> {
        let rootfs_path = self.stage_blob(&spec.rootfs, "rootfs", ".ext4").await?;
        let kernel_path = self.stage_blob(&spec.kernel, "kernels", "").await?;
        // Verify-before-boot: the staged kernel is ring-0 code, so it clears the
        // posture bar (content hash — always; allow-list + signature under strict)
        // before any guest loads it. A failure aborts materialize; nothing boots.
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
                    "embedded VMM backend requires a VmImages artifact".into(),
                ))
            }
        };

        let id = vm_id(&req.workload, req.replica);
        let ip = {
            let mut pool = self.ipam.lock().expect("ipam mutex");
            pool.allocate()
                .map_err(|e| BackendError::Launch(e.to_string()))?
        };
        let tap = TapNetwork::for_vm(&id, &self.bridge);
        let port = req.spec.port;

        // Materialize persistent volumes: validate + create/reuse each
        // image off the async runtime, before the VM is spawned.
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

        let cfg = WorkerConfig {
            rootfs_path,
            kernel_path,
            cmdline_override: req.spec.kernel_cmdline.clone(),
            tap_name: tap.tap_name.clone(),
            guest_ip: ip.to_string(),
            gateway: self.gateway.clone(),
            mem_mib: req.spec.mem_mib,
            vcpus: req.spec.vcpus as u8,
            restore: false,
            volumes: worker_volumes,
        };

        // Create + enslave the host tap (the privileged bit, in the parent), then
        // spawn the jailed `__vmm-run` child that attaches to it + runs the VM.
        let (tap_for_setup, self_exe, cfg_for_spawn) =
            (tap.clone(), self.self_exe.clone(), cfg.clone());
        let spawned = tokio::task::spawn_blocking(move || {
            spawn_worker(&self_exe, &cfg_for_spawn, &tap_for_setup, None)
        })
        .await
        .map_err(|e| BackendError::Launch(format!("join: {e}")))?;

        let mut child = match spawned {
            Ok(child) => child,
            Err(err) => {
                // Roll back the tap + the allocated IP.
                for cmd in tap.teardown_commands() {
                    let _ = run_host_command(&cmd);
                }
                self.ipam.lock().expect("ipam mutex").release(ip);
                return Err(BackendError::Launch(err));
            }
        };

        let stdin = child.stdin.take();
        self.running.lock().expect("running mutex").insert(
            id,
            RunningVm {
                child,
                stdin,
                cfg,
                ip,
                tap,
            },
        );

        Ok(Instance {
            handle: InstanceHandle {
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
        let id = vm_id(&handle.workload, handle.replica);
        let running = self.running.lock().expect("running mutex").remove(&id);
        let Some(mut running) = running else {
            return Ok(()); // already stopped / never launched — idempotent
        };

        // Kill the VM subprocess (it has no signal handler → terminates) + reap it,
        // off the async runtime.
        tokio::task::spawn_blocking(move || {
            let _ = running.child.kill();
            let _ = running.child.wait();
            for cmd in running.tap.teardown_commands() {
                let _ = run_host_command(&cmd);
            }
            running.ip
        })
        .await
        .map(|ip| self.ipam.lock().expect("ipam mutex").release(ip))
        .map_err(|e| BackendError::Stop(format!("join: {e}")))?;
        Ok(())
    }

    async fn health(&self, handle: &InstanceHandle) -> Result<Health, BackendError> {
        let (ip, port) = decode_ref(&handle.backend_ref).ok_or_else(|| {
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

    /// **Snapshot** a running replica for scale-to-zero: tell the jailed
    /// worker to pause + capture (vCPU + chip + device-model state + RAM), capture
    /// the stream it writes to stdout into `<stem>.snap`, persist its config to
    /// `<stem>.cfg`, then reap it + tear the tap down. The guest IP stays reserved
    /// (the snapshot owns it) so [`restore`](Self::restore) keeps the same address.
    async fn snapshot(&self, handle: &InstanceHandle) -> Result<Option<Snapshot>, BackendError> {
        let (_ip, port) = decode_ref(&handle.backend_ref).ok_or_else(|| {
            BackendError::Other(format!("bad handle ref {:?}", handle.backend_ref))
        })?;
        let id = vm_id(&handle.workload, handle.replica);
        let running = self.running.lock().expect("running mutex").remove(&id);
        let Some(running) = running else {
            return Ok(None); // not running — nothing to snapshot
        };
        let ip = running.ip;

        let dir = self.data_dir.join("compute").join("snapshots");
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| BackendError::Other(format!("create snapshots dir: {e}")))?;
        let stem = dir.join(&id).display().to_string();
        let snap_path = format!("{stem}.snap");
        let cfg_path = format!("{stem}.cfg");
        // Persist the worker config so a restore can respawn without in-memory state.
        let cfg_json =
            serde_json::to_vec(&running.cfg).map_err(|e| BackendError::Other(e.to_string()))?;
        tokio::fs::write(&cfg_path, cfg_json)
            .await
            .map_err(|e| BackendError::Other(format!("write {cfg_path}: {e}")))?;

        let snap_target = snap_path.clone();
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            let mut running = running;
            // Request the snapshot over the control channel.
            let mut stdin = running.stdin.take().ok_or("no control channel")?;
            stdin
                .write_all(format!("{SNAPSHOT_CMD}\n").as_bytes())
                .and_then(|()| stdin.flush())
                .map_err(|e| format!("send snapshot command: {e}"))?;
            // Stream the worker's snapshot output into the file as it writes it
            // (must drain concurrently — the RAM far exceeds the pipe buffer).
            let mut out = running.child.stdout.take().ok_or("no worker stdout")?;
            let mut file =
                File::create(&snap_target).map_err(|e| format!("create {snap_target}: {e}"))?;
            std::io::copy(&mut out, &mut file).map_err(|e| format!("capture snapshot: {e}"))?;
            file.sync_all().ok();
            let status = running
                .child
                .wait()
                .map_err(|e| format!("wait worker: {e}"))?;
            // Reclaim the tap (re-created on restore); the IP stays reserved.
            for cmd in running.tap.teardown_commands() {
                let _ = run_host_command(&cmd);
            }
            if !status.success() {
                return Err(format!("worker exited {status} during snapshot"));
            }
            Ok(())
        })
        .await
        .map_err(|e| BackendError::Other(format!("join: {e}")))?
        .map_err(BackendError::Other)?;

        Ok(Some(Snapshot {
            workload: handle.workload.clone(),
            replica: handle.replica,
            data_ref: encode_snap(&stem, &ip.to_string(), port),
        }))
    }

    /// **Restore** a snapshotted replica: read its persisted config, re-create
    /// the tap, re-reserve the IP, and spawn a jailed worker in restore mode with
    /// the `<stem>.snap` stream on [`RESTORE_FD`] — it reconstructs the VM + device
    /// model and resumes from the captured RIP.
    async fn restore(&self, snapshot: &Snapshot) -> Result<Instance, BackendError> {
        let (stem, ip, port) = decode_snap(&snapshot.data_ref).ok_or_else(|| {
            BackendError::Other(format!("bad snapshot ref {:?}", snapshot.data_ref))
        })?;
        let addr: std::net::Ipv4Addr = ip
            .parse()
            .map_err(|e| BackendError::Other(format!("bad snapshot ip {ip}: {e}")))?;
        let id = vm_id(&snapshot.workload, snapshot.replica);
        let snap_path = format!("{stem}.snap");
        let cfg_path = format!("{stem}.cfg");

        let cfg_bytes = tokio::fs::read(&cfg_path)
            .await
            .map_err(|e| BackendError::Other(format!("read {cfg_path}: {e}")))?;
        let mut cfg: WorkerConfig =
            serde_json::from_slice(&cfg_bytes).map_err(|e| BackendError::Other(e.to_string()))?;
        cfg.restore = true;

        // Re-reserve the guest IP so the pool won't reissue it while restoring.
        self.ipam.lock().expect("ipam mutex").reserve(addr);
        let tap = TapNetwork::for_vm(&id, &self.bridge);

        let (self_exe, tap_for_spawn, cfg_for_spawn) =
            (self.self_exe.clone(), tap.clone(), cfg.clone());
        let spawned = tokio::task::spawn_blocking(move || -> Result<Child, String> {
            let file = File::open(&snap_path).map_err(|e| format!("open {snap_path}: {e}"))?;
            spawn_worker(&self_exe, &cfg_for_spawn, &tap_for_spawn, Some(file))
        })
        .await
        .map_err(|e| BackendError::Other(format!("join: {e}")))?;

        let mut child = match spawned {
            Ok(child) => child,
            Err(err) => {
                for cmd in tap.teardown_commands() {
                    let _ = run_host_command(&cmd);
                }
                self.ipam.lock().expect("ipam mutex").release(addr);
                return Err(BackendError::Launch(err));
            }
        };

        let stdin = child.stdin.take();
        self.running.lock().expect("running mutex").insert(
            id,
            RunningVm {
                child,
                stdin,
                cfg,
                ip: addr,
                tap,
            },
        );

        Ok(Instance {
            handle: InstanceHandle {
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
        let r = encode_ref("10.0.0.5", 8080);
        assert_eq!(r, "10.0.0.5:8080");
        assert_eq!(decode_ref(&r), Some(("10.0.0.5".to_string(), 8080)));
        assert_eq!(decode_ref("garbage"), None);
    }

    #[test]
    fn snapshot_ref_round_trips() {
        let r = encode_snap("/data/compute/snapshots/web-0", "10.0.0.5", 8080);
        assert_eq!(
            decode_snap(&r),
            Some((
                "/data/compute/snapshots/web-0".to_string(),
                "10.0.0.5".to_string(),
                8080
            ))
        );
        assert_eq!(decode_snap("nope"), None);
    }

    #[test]
    fn blob_key_is_two_char_sharded() {
        assert_eq!(blob_key("abcdef"), "ab/abcdef");
    }

    #[test]
    fn parse_mac_decodes_octets() {
        assert_eq!(
            parse_mac("02:00:0a:00:00:05"),
            [0x02, 0x00, 0x0a, 0x00, 0x00, 0x05]
        );
    }

    #[test]
    fn default_cmdline_has_root_and_static_ip() {
        let c = default_cmdline("10.0.0.5", "10.0.0.1");
        assert!(c.contains("root=/dev/vda ro"));
        assert!(c.contains("ip=10.0.0.5::10.0.0.1:255.255.255.0::eth0:off"));
    }

    #[test]
    fn validate_volume_accepts_clean_and_rejects_escapes() {
        assert!(validate_volume("data", "/var/lib/data").is_ok());
        // Name must be a single path component (backs `<dir>/<name>.img`).
        assert!(validate_volume("../etc", "/data").is_err());
        assert!(validate_volume("a/b", "/data").is_err());
        assert!(validate_volume(".", "/data").is_err());
        // Mount must be an absolute guest path with no `..`.
        assert!(validate_volume("data", "relative/path").is_err());
        assert!(validate_volume("data", "/var/../etc").is_err());
    }

    #[test]
    fn no_volumes_materialize_to_empty() {
        let dir = std::env::temp_dir().join("br-vol-test-empty");
        assert!(ensure_volume_images(&dir, &[]).unwrap().is_empty());
    }
}
