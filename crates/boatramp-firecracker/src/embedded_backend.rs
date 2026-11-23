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
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use boatramp_core::Storage;
use boatramp_core::compute::{
    Artifact, BackendError, Capabilities, ComputeBackend, ComputeSpec, ContentStageLocks, Endpoint,
    Health, Instance, InstanceHandle, IsolationClass, LaunchRequest, RootSource, RootSourceKind,
    Scheme, Snapshot, SnapshotArtifact, SourceSupport, VolumeRef, compute_instance_id,
};
use boatramp_core::ipam::{IpAuthority, IpPool};
use boatramp_core::registry_auth::RegistryAuth;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use vm_memory::Address;

use crate::device_manager::{DeviceManager, VirtioDeviceOps};
use crate::embedded::mmio_cmdline_arg;
use crate::embedded_vmm::EmbeddedVmm;
use crate::net::{HostCommand, TapNetwork};
use crate::tap::Tap;
use crate::virtio_block::{SECTOR_SIZE, VirtioBlock};
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

/// VM id for a workload replica — the registry key + the tap-name stem.
/// Project-qualified for a non-`default` project (so two projects' same-named
/// workloads never share a registry slot / tap), but the bare `<workload>-<replica>`
/// for `default` (byte-identical to pre-v0.3.12). Delegates to the host-tested
/// [`compute_instance_id`].
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
    /// The guest-IP authority for this bridge/subnet — **shared** (A5) with the
    /// co-located native `container` backend when `build_compute` injects one, so a
    /// tap and a veth on the same L2 can never be handed the same address. Its own
    /// `Arc<Mutex<IpPool>>` provides the interior mutability the launch/stop paths need.
    ipam: IpAuthority,
    /// Running VMs, keyed by [`vm_id`].
    running: Mutex<HashMap<String, RunningVm>>,
    /// Verify-before-boot gate: the staged kernel must clear it before it loads.
    verifier: Arc<dyn crate::KernelVerifier>,
    /// Per-content staging locks: with the decoupled pull the reconcile loop stages blobs
    /// concurrently, so every microVM racing to stage the one shared kernel (or a shared rootfs)
    /// would otherwise stream into the same `.tmp` at once. These serialize same-content stagers
    /// so exactly one streams and the rest reuse the published blob (see [`ContentStageLocks`]).
    stage_locks: ContentStageLocks,
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
        let pool = IpPool::new(subnet).map_err(|e| BackendError::Other(e.to_string()))?;
        Ok(Self {
            storage,
            self_exe,
            data_dir,
            bridge,
            gateway,
            // A private authority by default; `with_ip_authority` swaps in the shared one.
            ipam: IpAuthority::over(pool),
            running: Mutex::new(HashMap::new()),
            verifier,
            stage_locks: ContentStageLocks::new(),
        })
    }

    /// Use a **shared** [`IpAuthority`] instead of this backend's private pool (A5),
    /// so the co-located native `container` backend and this VMM backend draw from and
    /// release to ONE address pool on their shared bridge/subnet — never handing out
    /// the same `10.0.0.x` on the same L2. `build_compute` builds one authority per
    /// bridge/subnet and injects a clone here. The authority must be over the same
    /// subnet this backend was constructed with.
    pub fn with_ip_authority(mut self, authority: IpAuthority) -> Self {
        self.ipam = authority;
        self
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
        // Fast path: an already-staged blob is reused with no lock.
        if tokio::fs::try_exists(&dest).await.unwrap_or(false) {
            return Ok(dest.display().to_string());
        }
        // Serialize same-content stagers (the decoupled pull stages concurrently): without this,
        // N microVMs sharing a kernel/rootfs each `File::create` the same `.tmp` and interleave
        // writes → a corrupt published blob. The winner streams + renames; the rest reuse it.
        let lock = self
            .stage_locks
            .lock_for(&format!("blob:{subdir}:{hash}{ext}"));
        let _guard = lock.lock().await;
        // Double-check under the lock: a peer may have published while we waited.
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

    /// **Boot sweep** (U17): reclaim the leftovers of a prior node incarnation before
    /// the reconcile loop allocates. The in-memory registry doesn't survive a restart,
    /// so after a node crash/restart its `__vmm-run` workers keep running — orphaned
    /// microVMs still holding taps on the shared bridge — and their taps linger. This
    /// SIGKILLs every `__vmm-run` worker (there are none of ours yet — the backend was
    /// just built) and deletes every `tap-*` device + its per-tap anti-spoof table not
    /// in the (currently empty) registry, so a reissued IP/MAC can't collide with a
    /// stale peer. Best-effort + idempotent; called once from `build_compute`, mirroring
    /// the container backend's startup cgroup sweep. The PDEATHSIG re-arm in
    /// `run_jailed_worker` handles the common case going forward; this is the backstop
    /// for workers that predate it or raced its arming.
    ///
    /// ASSUMES ONE boatramp node process per host: it SIGKILLs *any* `__vmm-run` worker
    /// (other than itself) and deletes *any* `tap-*` device on the box. Running a second
    /// boatramp node on the same host would have its workers/taps reaped here, so this
    /// is only ever called at node boot, before this backend has launched anything.
    pub fn sweep_orphans(&self) {
        // 1) Kill prior-incarnation workers (identified by their `__vmm-run` argv).
        let self_pid = std::process::id();
        let entries = read_proc_cmdlines();
        let orphans = crate::net::orphan_vmm_worker_pids(&entries, VMM_RUN_SUBCOMMAND, self_pid);
        for pid in &orphans {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(*pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        // 2) Reclaim stale taps + their per-tap anti-spoof tables. The registry is empty
        //    at this point, but take its tap names anyway so this is correct if ever
        //    re-run after launches exist.
        let live: std::collections::BTreeSet<String> = self
            .running
            .lock()
            .expect("running mutex")
            .values()
            .map(|r| r.tap.tap_name.clone())
            .collect();
        let ifaces = list_net_ifaces();
        let stale = crate::net::stale_vmm_taps(&ifaces, &live);
        for tap in &stale {
            // Delete the per-tap anti-spoof table (U16) first, then the device. Both are
            // best-effort — a tap with no filter table just no-ops the first command.
            let _ = run_host_command(&HostCommand::new(
                "nft",
                &["delete", "table", "bridge", &format!("brl2-{tap}")],
            ));
            let _ = run_host_command(&HostCommand::new("ip", &["link", "del", tap]));
        }
        if !orphans.is_empty() || !stale.is_empty() {
            // This crate has no `tracing` dep; the node logs via its own subscriber, so a
            // plain stderr line is the seam here (as elsewhere in this module).
            eprintln!(
                "vmm-embedded: swept {} orphaned worker(s) + {} stale tap(s) at startup",
                orphans.len(),
                stale.len()
            );
        }
    }
}

/// Read every readable `/proc/<pid>/cmdline` as `(pid, argv)` — the host seam the boot
/// sweep's pure [`orphan_vmm_worker_pids`](crate::net::orphan_vmm_worker_pids)
/// selection consumes. A `cmdline` is NUL-separated argv; unreadable/again-gone entries
/// are skipped. Kept thin (no selection logic) so the selection stays host-testable.
#[cfg(target_os = "linux")]
fn read_proc_cmdlines() -> Vec<(u32, Vec<String>)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue; // non-numeric /proc entry (not a pid)
        };
        let Ok(raw) = std::fs::read(entry.path().join("cmdline")) else {
            continue; // the process exited, or we can't read it
        };
        let argv: Vec<String> = raw
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        if !argv.is_empty() {
            out.push((pid, argv));
        }
    }
    out
}

/// The host's network-interface names (`/sys/class/net/*`) — the host seam the boot
/// sweep's pure [`stale_vmm_taps`](crate::net::stale_vmm_taps) selection consumes.
#[cfg(target_os = "linux")]
fn list_net_ifaces() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect()
}

/// Set up the tap + spawn the jailed `__vmm-run` child for `cfg`.
///
/// The [`WorkerConfig`] — which carries the workload's per-binding identity bearer
/// **tokens** in its `env` — is delivered to the child as the **first line on its
/// stdin**, NOT as an argv element (U18): an argv element leaks into the host's
/// `/proc/<pid>/cmdline`, readable by any process on a multi-tenant node (mirrors
/// the container backend's stdin plan delivery). After line 1, stdin stays the
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
    // Compact (single-line) JSON — `serde_json::to_string` never embeds a literal
    // newline (newlines inside strings are escaped), so it is exactly line 1.
    let json = serde_json::to_string(cfg).map_err(|e| e.to_string())?;
    let mut command = Command::new(self_exe);
    command
        .arg(VMM_RUN_SUBCOMMAND)
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
    let mut child = command
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", self_exe.display()))?;
    // Hand the config over stdin (line 1) before returning the child; the caller
    // keeps the same stdin pipe as the subsequent snapshot-control channel.
    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| "worker stdin not piped".to_string())?;
    stdin
        .write_all(json.as_bytes())
        .and_then(|()| stdin.write_all(b"\n"))
        .and_then(|()| stdin.flush())
        .map_err(|e| format!("send worker config over stdin: {e}"))?;
    Ok(child)
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
        Err(format!("{} exited with {status}", cmd))
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
    /// The ` boatramp.env=<hex>` cmdline fragment delivering the workload's runtime
    /// `env` to the guest init (empty ⇒ none). See [`crate::config::env_cmdline_fragment`].
    #[serde(default)]
    pub env_cmdline: String,
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

/// Read the [`WorkerConfig`] the backend handed the jailed child as the **first
/// line on stdin** (U18 — off argv, so the per-binding bearer tokens in `env` never
/// land in the host's `/proc/<pid>/cmdline`). The `__vmm-run` dispatch calls this,
/// then [`run_jailed_worker`]; the control thread that watches stdin for the later
/// `snapshot` line reads from the SAME process-global stdin, so its buffered
/// read-ahead continues seamlessly after this line. Mirrors the container worker's
/// stdin plan read.
#[cfg(target_os = "linux")]
pub fn read_worker_config_from_stdin() -> Result<WorkerConfig, String> {
    use std::io::BufRead;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("read worker config from stdin: {e}"))?;
    if line.is_empty() {
        return Err("worker config: stdin closed before the config line arrived".into());
    }
    serde_json::from_str(line.trim_end()).map_err(|e| format!("invalid worker config: {e}"))
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
    // Record the node (parent) pid up front so we can detect, after arming the
    // parent-death signal below, that the parent already exited (U17).
    let parent_pid = nix::unistd::getppid();
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
        // Append the runtime-env fragment (`vminit` decodes + merges it over the baked
        // env) — the launch-time env channel for microVMs.
        let cmdline = format!("{base} {mmio}{}", cfg.env_cmdline);

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
    // Re-arm the parent-death signal AFTER the cap-drop (U17): a `pre_exec`
    // `PR_SET_PDEATHSIG` both races the fork and is CLEARED by the credential change
    // in `drop_all_caps`, so without this a node (parent) crash would orphan this
    // microVM with a live tap. `drop_all_caps` only drops capabilities (no uid/seccomp
    // change), so arming here, before the seccomp filter, needs no `prctl` on the
    // allow-list and survives the filter install (which changes no credentials).
    nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL)
        .map_err(|e| format!("arm PR_SET_PDEATHSIG: {e}"))?;
    // Close the residual race: if the node already exited between our fork and the
    // arm above, the death signal will never fire — so if we've been reparented, bail
    // now rather than linger as an orphaned VM holding a tap + guest IP.
    if nix::unistd::getppid() != parent_pid {
        return Err("node (parent) exited before PDEATHSIG was armed; aborting worker".into());
    }
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
        Capabilities::new(IsolationClass::VmKvm)
            // Snapshot the paused VM (vCPU + chip + device-model state + RAM)
            // to disk + restore it into a fresh jailed worker that resumes.
            .with_scale_to_zero(true)
            // Persistent volumes as writable virtio-block images.
            .with_persistent_volumes(true)
            // Directly scheduled against the node ledger — a preemption participant.
            .with_preemptible(true)
    }

    fn source_support(&self) -> SourceSupport {
        // A micro-VM boots a prebuilt **rootfs** block image (`RootSource::Rootfs`);
        // `materialize` rejects an image/tar source, and it never pulls from a registry,
        // so no pull credential applies. Rootfs-only, not credential-capable.
        SourceSupport::new(vec![RootSourceKind::Rootfs])
            .with_private_registry_credential(false)
            .with_primary_source(Some(RootSourceKind::Rootfs))
    }

    /// Adopt the IPs of already-running embedded-VMM replicas into this backend's
    /// (shared) IP pool at boot (U17): the in-memory registry does NOT survive a node
    /// restart, so without this a fresh pool would re-hand a prior incarnation's live
    /// `10.0.0.x` — and, since the MAC is `f(IP)`, its MAC too — to a DIFFERENT
    /// workload. `IpAuthority::reserve_in_use` skips the gateway + out-of-subnet
    /// addresses, so passing the full fleet is safe + idempotent (it also shares the
    /// pool with the co-located container backend, so each reserves the other's IPs).
    async fn reserve_in_use(&self, replicas: &[(String, String, u32, std::net::Ipv4Addr)]) {
        let ips: Vec<std::net::Ipv4Addr> = replicas.iter().map(|(_, _, _, ip)| *ip).collect();
        self.ipam.reserve_in_use(&ips);
    }

    async fn materialize(
        &self,
        _project: &str,
        _workload: &str,
        spec: &ComputeSpec,
        _pull_auth: Option<&RegistryAuth>,
    ) -> Result<Artifact, BackendError> {
        // The microVM boots an `ext4` rootfs; an OCI image reference must be built into
        // one first (`compute build`), so it is not runnable here directly. It never pulls
        // from a registry, so `_pull_auth` does not apply.
        let rootfs_hash = match &spec.root {
            RootSource::Rootfs(hash) => hash,
            RootSource::Image(_) | RootSource::Tar(_) => {
                return Err(BackendError::Materialize(
                    "embedded VMM requires a rootfs image (RootSource::Rootfs)".into(),
                ));
            }
        };
        let rootfs_path = self.stage_blob(rootfs_hash, "rootfs", ".ext4").await?;
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
                ));
            }
        };

        let id = vm_id(&req.project, &req.workload, req.replica);
        let ip = self
            .ipam
            .allocate()
            .map_err(|e| BackendError::Launch(e.to_string()))?;
        // Bind the tap to exactly this guest's IP + (deterministic) MAC with a per-tap
        // anti-spoof filter (U16), installed fail-closed before the tap joins the bridge
        // so a guest can't impersonate a neighbor at L2 (the predictable `02:00:<ip>` MAC)
        // or L3 (a forged source/ARP IP).
        let tap =
            TapNetwork::for_vm_filtered(&id, &self.bridge, &ip.to_string(), &IpPool::mac_for(ip));
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
            env_cmdline: crate::config::env_cmdline_fragment_bounded(&req.spec.env)
                .map_err(BackendError::Launch)?,
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
                self.ipam.release(ip);
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

        Ok(Instance::new(
            InstanceHandle::new(
                req.project.clone(),
                req.workload.clone(),
                req.replica,
                encode_ref(&ip.to_string(), port),
            ),
            Endpoint::new(Scheme::Http, ip.to_string(), port),
        ))
    }

    async fn stop(&self, handle: &InstanceHandle) -> Result<(), BackendError> {
        let id = vm_id(&handle.project, &handle.workload, handle.replica);
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
        .map(|ip| self.ipam.release(ip))
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
        let id = vm_id(&handle.project, &handle.workload, handle.replica);
        let running = self.running.lock().expect("running mutex").remove(&id);
        let Some(running) = running else {
            return Ok(None); // not running — nothing to snapshot
        };
        let ip = running.ip;

        let dir = self.data_dir.join("compute").join("snapshots");
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| BackendError::Other(format!("create snapshots dir: {e}")))?;
        // A snapshot is sensitive: `.cfg` carries the full WorkerConfig (per-binding
        // bearer TOKENS in `env`) and `.snap` is raw guest RAM. Lock the directory to
        // `0700` and each file to `0600` so no non-root host process can read the
        // tokens / RAM (closes the same U18 token-leak class as the argv fix). The dir
        // perms are set explicitly (not umask-subject); the files are created `0600`
        // from the start (never world-readable, even transiently).
        tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|e| BackendError::Other(format!("secure snapshots dir perms: {e}")))?;
        let stem = dir.join(&id).display().to_string();
        let snap_path = format!("{stem}.snap");
        let cfg_path = format!("{stem}.cfg");
        // Persist the worker config so a restore can respawn without in-memory state.
        let cfg_json =
            serde_json::to_vec(&running.cfg).map_err(|e| BackendError::Other(e.to_string()))?;
        let mut cfg_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&cfg_path)
            .await
            .map_err(|e| BackendError::Other(format!("create {cfg_path}: {e}")))?;
        cfg_file
            .write_all(&cfg_json)
            .await
            .map_err(|e| BackendError::Other(format!("write {cfg_path}: {e}")))?;
        cfg_file
            .flush()
            .await
            .map_err(|e| BackendError::Other(format!("flush {cfg_path}: {e}")))?;

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
            // `0600`: the snapshot is raw guest RAM (secrets) — never world-readable.
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&snap_target)
                .map_err(|e| format!("create {snap_target}: {e}"))?;
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

        // `exported` defaults false (home-node-only); the reconcile flips it via
        // `with_exported` once the artifact is exported to tenant Storage (U14).
        Ok(Some(Snapshot::new(
            handle.project.clone(),
            handle.workload.clone(),
            handle.replica,
            encode_snap(&stem, &ip.to_string(), port),
        )))
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
        let id = vm_id(&snapshot.project, &snapshot.workload, snapshot.replica);
        let snap_path = format!("{stem}.snap");
        let cfg_path = format!("{stem}.cfg");

        let cfg_bytes = tokio::fs::read(&cfg_path)
            .await
            .map_err(|e| BackendError::Other(format!("read {cfg_path}: {e}")))?;
        let mut cfg: WorkerConfig =
            serde_json::from_slice(&cfg_bytes).map_err(|e| BackendError::Other(e.to_string()))?;
        cfg.restore = true;

        // Re-reserve the guest IP so the pool won't reissue it while restoring.
        self.ipam.reserve(addr);
        // Same per-tap anti-spoof binding as launch (U16) — the restored guest keeps its
        // IP, so it keeps the same pinned (IP, MAC).
        let tap = TapNetwork::for_vm_filtered(&id, &self.bridge, &ip, &IpPool::mac_for(addr));

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
                self.ipam.release(addr);
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

        Ok(Instance::new(
            InstanceHandle::new(
                snapshot.project.clone(),
                snapshot.workload.clone(),
                snapshot.replica,
                encode_ref(&ip, port),
            ),
            Endpoint::new(Scheme::Http, ip, port),
        ))
    }

    /// U14 cross-node s2z: the microVM snapshot is two local files under
    /// `<data-dir>/compute/snapshots/` — `<id>.snap` (raw guest RAM) and `<id>.cfg` (the
    /// worker config: kernel/rootfs refs + the per-binding env). Both are self-contained
    /// (the kernel/rootfs blobs are content-addressed and re-`materialize`d on any node), so
    /// the pair is all a resume node needs. The `data_ref` is rewritten to THIS node's paths
    /// on import (ip/port preserved) so `restore` reads the fetched files here.
    async fn snapshot_artifact(
        &self,
        snapshot: &Snapshot,
    ) -> Result<Option<SnapshotArtifact>, BackendError> {
        let (_stem, ip, port) = decode_snap(&snapshot.data_ref).ok_or_else(|| {
            BackendError::Other(format!("bad snapshot ref {:?}", snapshot.data_ref))
        })?;
        let id = vm_id(&snapshot.project, &snapshot.workload, snapshot.replica);
        let dir = self.data_dir.join("compute").join("snapshots");
        let local_stem = dir.join(&id).display().to_string();
        Ok(Some(SnapshotArtifact::new(
            dir,
            vec![format!("{id}.snap"), format!("{id}.cfg")],
            encode_snap(&local_stem, &ip, port),
        )))
    }

    /// Both snapshot files present on this node's local disk ⇒ no cross-node fetch needed.
    /// Checks THIS node's own stem (derived from the identity + local `data_dir`), not the
    /// path baked into `data_ref` — which, on a resume node, still names the node that parked
    /// it. So on a node that doesn't hold the artifact this returns `false` and the reconcile
    /// fetches it from tenant Storage before `restore`.
    async fn snapshot_present(&self, snapshot: &Snapshot) -> Result<bool, BackendError> {
        let id = vm_id(&snapshot.project, &snapshot.workload, snapshot.replica);
        let stem = self
            .data_dir
            .join("compute")
            .join("snapshots")
            .join(&id)
            .display()
            .to_string();
        let snap = tokio::fs::try_exists(format!("{stem}.snap"))
            .await
            .unwrap_or(false);
        let cfg = tokio::fs::try_exists(format!("{stem}.cfg"))
            .await
            .unwrap_or(false);
        Ok(snap && cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_id_is_workload_dash_replica() {
        // Default project keeps the bare id (byte-identical to pre-v0.3.12);
        // a non-default project qualifies it so two projects' `web/0` never collide.
        assert_eq!(vm_id("default", "web", 0), "web-0");
        assert_eq!(vm_id("default", "api-v2", 3), "api-v2-3");
        assert_eq!(vm_id("acme", "web", 0), "acme-web-0");
        assert_ne!(vm_id("acme", "web", 0), vm_id("beta", "web", 0));
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
