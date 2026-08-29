//! The native container [`ComputeBackend`].
//!
//! `materialize` stages the spec's rootfs **tar** blob from [`Storage`] and
//! unpacks it to a per-image directory; `launch` builds a [`SandboxPlan`], wires
//! the host side of a veth pair into the bridge, re-execs `boatramp __sandbox`
//! (the self-jail worker), performs the netns handshake (move the peer in +
//! configure `eth0` while the worker waits, then signal "go"), and returns the
//! routable endpoint; `stop` kills the instance's cgroup + tears down the veth;
//! `health` TCP-probes the app port. All netlink/process work is library-based;
//! the actual jail + boot is the Linux seam (`container_live`).

use std::net::Ipv4Addr;
use std::os::fd::AsFd;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use boatramp_core::compute::{
    Artifact, BackendError, Capabilities, ComputeBackend, ComputeSpec, Endpoint, Health, Instance,
    InstanceHandle, IsolationClass, LaunchRequest, RootSource, Scheme, Snapshot,
};
use boatramp_core::ipam::IpPool;
use boatramp_core::Storage;
use futures::StreamExt;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::logsink;
use crate::net::VethNetwork;
use crate::sandbox::{SandboxPlan, VolumeMount};

/// The entrypoint runs as root **inside** the container's user view (caps are
/// dropped + seccomp installed by the worker, so it holds no host privilege).
/// Matches the default most OCI images expect; a spec `user` overrides it.
const GUEST_UID: u32 = 0;
const GUEST_GID: u32 = 0;

/// Parse a `ComputeSpec.user` (`"uid"` or `"uid:gid"`, numeric) into the namespace
/// `(uid, gid)` the entrypoint runs as, `gid` defaulting to `uid`. Absent or
/// non-numeric ⇒ the container default (namespace-root), so the entrypoint keeps the
/// prior behaviour.
fn spec_uid_gid(spec: &ComputeSpec) -> (u32, u32) {
    let Some(user) = spec.user.as_deref() else {
        return (GUEST_UID, GUEST_GID);
    };
    match user.split_once(':') {
        Some((u, g)) => match (u.parse(), g.parse()) {
            (Ok(u), Ok(g)) => (u, g),
            _ => (GUEST_UID, GUEST_GID),
        },
        None => user.parse().map_or((GUEST_UID, GUEST_GID), |u| (u, u)),
    }
}

/// Content-addressed Storage key for a blob hash (`<2hex>/<hash>`).
fn blob_key(hash: &str) -> String {
    let prefix = &hash[..2.min(hash.len())];
    format!("{prefix}/{hash}")
}

/// Container id for a workload replica (`<workload>-<replica>`): the veth-name +
/// cgroup + hostname stem.
fn container_id(workload: &str, replica: u32) -> String {
    format!("{workload}-{replica}")
}

/// Decode a running instance's `backend_ref` (`<ip>:<port>`).
fn decode_ref(s: &str) -> Option<(String, u16)> {
    let (ip, port) = s.rsplit_once(':')?;
    Some((ip.to_string(), port.parse().ok()?))
}

/// Encode the persistent part of a snapshot ref: `<image-dir>|<rootfs>`. The
/// running IP/port are appended by `snapshot` (`|<ip>|<port>`).
fn encode_snap(image_dir: &str, rootfs: &str) -> String {
    format!("{image_dir}|{rootfs}")
}

/// Decode a snapshot `data_ref` (`<image-dir>|<rootfs>|<ip>|<port>`).
fn decode_snap(s: &str) -> Option<(String, String, String, u16)> {
    let mut it = s.rsplitn(4, '|');
    let port = it.next()?.parse().ok()?;
    let ip = it.next()?.to_string();
    let rootfs = it.next()?.to_string();
    let image_dir = it.next()?.to_string();
    Some((image_dir, rootfs, ip, port))
}

/// Reject a volume whose `name` or `mount` could escape its sandboxed location
///. The `name` backs `<data_dir>/compute/volumes/<name>`, so it
/// must be a single normal path component (no `/`, `..`, `.`, or absolute path —
/// else the host bind source escapes `data_dir`). The `mount` is joined onto the
/// rootfs, so it must be absolute with only normal components (no `..`/`.` — else
/// the bind target escapes the container rootfs).
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

/// The native container backend: rootfs staging + per-node IPAM + veth wiring,
/// re-execing this binary as the self-jail worker.
pub struct ContainerBackend {
    storage: Arc<dyn Storage>,
    /// Root for staged rootfs dirs (`<data_dir>/compute/rootfs/<hash>`).
    data_dir: PathBuf,
    /// Bridge each veth host end is enslaved to.
    bridge: String,
    /// Guest subnet (e.g. `10.0.0.0/24`) — gateway + prefix for in-netns config.
    prefix: u8,
    gateway: Ipv4Addr,
    /// Path to this `boatramp` binary, re-execed as `__sandbox` (and, for a
    /// scale-to-zero wake, as `__criu-net-setup`).
    self_exe: PathBuf,
    /// Per-node guest-IP pool.
    ipam: Mutex<IpPool>,
    /// A usable `criu` (present + `criu check` passed) enables scale-to-zero;
    /// `None` leaves the backend without it (the scheduler routes such workloads
    /// elsewhere). Detected once at construction.
    criu: Option<crate::criu::Criu>,
    /// Whether a spec's `cap_add` is honored here. Set from the isolation posture
    /// (single-tenant only); off under the multi-tenant guard, so a cap-add spec is
    /// forced back to the dropped-`ALL` default.
    cap_add_allowed: bool,
}

impl ContainerBackend {
    /// Build a container backend staging rootfs blobs from `storage` under
    /// `data_dir`, attaching veth host ends to `bridge`, handing out guest IPs
    /// from `subnet`, and re-execing `self_exe` (this binary) as the worker.
    pub fn new(
        storage: Arc<dyn Storage>,
        data_dir: PathBuf,
        bridge: String,
        subnet: &str,
        self_exe: PathBuf,
    ) -> Result<Self, BackendError> {
        let net: ipnet::Ipv4Net = subnet
            .parse()
            .map_err(|_| BackendError::Other(format!("bad subnet {subnet}")))?;
        let ipam = IpPool::new(subnet).map_err(|e| BackendError::Other(e.to_string()))?;
        Ok(Self {
            storage,
            data_dir,
            bridge,
            prefix: net.prefix_len(),
            gateway: ipam.gateway(),
            self_exe,
            ipam: Mutex::new(ipam),
            criu: crate::criu::Criu::detect(),
            cap_add_allowed: false,
        })
    }

    /// Allow a spec's `cap_add` to retain capabilities on top of the dropped-`ALL`
    /// default here (single-tenant posture). Off by default, so the multi-tenant guard
    /// keeps every capability dropped.
    pub fn with_cap_add_allowed(mut self, allowed: bool) -> Self {
        self.cap_add_allowed = allowed;
        self
    }

    /// Stage the rootfs **tar** blob `hash` and unpack it to
    /// `<data_dir>/compute/rootfs/<hash>/` (idempotent — skipped if already
    /// unpacked). Returns the rootfs directory.
    ///
    /// Readiness is gated by the `.boatramp-ready` marker, written only after a
    /// fully successful extraction. Any failure (download/decompressed-size/
    /// entry-count cap, path-escaping entry, or io) tears the partial,
    /// marker-less staging dir + temp blob back down so a half-extracted dir can
    /// never be mistaken for ready and a retry starts clean.
    async fn stage_rootfs(&self, hash: &str) -> Result<PathBuf, BackendError> {
        let dir = self.data_dir.join("compute").join("rootfs").join(hash);
        let ready = dir.join(".boatramp-ready");
        if tokio::fs::try_exists(&ready).await.unwrap_or(false) {
            return Ok(dir);
        }
        let tmp = self
            .data_dir
            .join("compute")
            .join("rootfs")
            .join(format!(".{hash}.tar.gz"));
        match self.stage_rootfs_inner(hash, &dir, &ready, &tmp).await {
            Ok(()) => Ok(dir),
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                let _ = tokio::fs::remove_dir_all(&dir).await;
                Err(e)
            }
        }
    }

    /// The staging body: download (capped) → unpack (capped + traversal-safe) →
    /// write the ready marker. Cleanup of a partial dir on failure is the
    /// caller's job (see [`stage_rootfs`]).
    async fn stage_rootfs_inner(
        &self,
        hash: &str,
        dir: &Path,
        ready: &Path,
        tmp: &Path,
    ) -> Result<(), BackendError> {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| BackendError::Materialize(format!("create {}: {e}", dir.display())))?;

        let obj = self
            .storage
            .get(&blob_key(hash))
            .await
            .map_err(|e| BackendError::Materialize(format!("fetch rootfs {hash}: {e}")))?;
        // Fast-fail when storage already reports an oversized blob, before we
        // write a single byte to disk.
        if obj
            .meta
            .size
            .is_some_and(|size| size > MAX_COMPRESSED_BYTES)
        {
            return Err(ArchiveError::CompressedTooLarge {
                limit: MAX_COMPRESSED_BYTES,
            }
            .into());
        }
        // Stream the blob to a temp tar, aborting if it exceeds the compressed
        // cap (the authoritative check — storage metadata may be absent/wrong).
        let mut file = tokio::fs::File::create(tmp)
            .await
            .map_err(|e| BackendError::Materialize(format!("create {}: {e}", tmp.display())))?;
        stream_capped(obj.body, &mut file, MAX_COMPRESSED_BYTES).await?;
        drop(file);

        // Unpack (blocking) off the runtime, enforcing the decompressed-size +
        // entry-count caps and rejecting path-escaping (traversal/symlink)
        // entries.
        let unpack_dir = dir.to_path_buf();
        let unpack_tmp = tmp.to_path_buf();
        tokio::task::spawn_blocking(move || {
            unpack_tar_gz(&unpack_tmp, &unpack_dir, ArchiveCaps::DEFAULT)
        })
        .await
        .map_err(|e| BackendError::Materialize(format!("join: {e}")))??;
        let _ = tokio::fs::remove_file(tmp).await;
        tokio::fs::write(ready, b"1")
            .await
            .map_err(|e| BackendError::Materialize(format!("mark ready: {e}")))?;
        Ok(())
    }

    /// Materialize an **OCI image** reference into an unpacked rootfs directory at
    /// `<data_dir>/compute/images/<sha256(ref)>/` — pull the image over the registry
    /// HTTP API and overlay its layers (honoring whiteouts), with no Docker daemon.
    /// Idempotent and keyed by the image reference: a completed pull is reused (gated
    /// by the `.boatramp-ready` marker), so relaunching the same image never re-pulls.
    ///
    /// The pull builds into a sibling temp dir and is published to its final path with
    /// an atomic rename only after the ready marker is written, so a partial or
    /// interrupted pull can never be mistaken for a complete rootfs.
    async fn stage_image(&self, image: &str) -> Result<PathBuf, BackendError> {
        let key = boatramp_types::manifest::sha256_hex(image.as_bytes());
        let images = self.data_dir.join("compute").join("images");
        let dir = images.join(&key);
        if tokio::fs::try_exists(dir.join(".boatramp-ready"))
            .await
            .unwrap_or(false)
        {
            return Ok(dir);
        }
        tokio::fs::create_dir_all(&images)
            .await
            .map_err(|e| BackendError::Materialize(format!("create {}: {e}", images.display())))?;
        let tmp = images.join(format!(".{key}.tmp"));
        // Clear any leftover partial from a prior interrupted pull.
        let _ = tokio::fs::remove_dir_all(&tmp).await;
        match boatramp_firecracker::oci::build_rootfs_dir(image, &tmp).await {
            Ok(()) => {
                tokio::fs::write(tmp.join(".boatramp-ready"), b"1")
                    .await
                    .map_err(|e| BackendError::Materialize(format!("mark ready: {e}")))?;
                // Publish atomically; replace any stale directory at the final path.
                let _ = tokio::fs::remove_dir_all(&dir).await;
                tokio::fs::rename(&tmp, &dir).await.map_err(|e| {
                    BackendError::Materialize(format!("publish rootfs {}: {e}", dir.display()))
                })?;
                Ok(dir)
            }
            Err(e) => {
                let _ = tokio::fs::remove_dir_all(&tmp).await;
                Err(BackendError::Materialize(format!(
                    "pull OCI image {image}: {e}"
                )))
            }
        }
    }
}

#[async_trait]
impl ComputeBackend for ContainerBackend {
    fn id(&self) -> &'static str {
        "container"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            isolation: IsolationClass::Namespace,
            // CRIU checkpoint/restore parks an idle container to disk + wakes it
            // with in-RAM state intact — advertised only when a working `criu` was
            // detected (see `Criu::detect`), so we never promise a park we can't
            // wake.
            scale_to_zero: self.criu.is_some(),
            // Volumes are host directories bind-mounted into the jail before
            // `pivot_root`; they persist across launches (keyed by volume name).
            persistent_volumes: true,
            max_vcpus: None,
            max_mem_mib: None,
        }
    }

    async fn materialize(&self, spec: &ComputeSpec) -> Result<Artifact, BackendError> {
        // Two rootfs sources produce a directory the worker `pivot_root`s into:
        // a **tar** blob from the shared store (staged + unpacked), or an **OCI
        // image** reference (pulled over the registry HTTP API + its layers
        // overlaid — no Docker daemon). A `Rootfs` block image is the micro-VM's.
        let dir =
            match &spec.root {
                RootSource::Tar(hash) => self.stage_rootfs(hash).await?,
                RootSource::Image(image) => self.stage_image(image).await?,
                RootSource::Rootfs(_) => return Err(BackendError::Materialize(
                    "container backend requires a tar rootfs archive or an OCI image reference \
                     (RootSource::Tar | RootSource::Image)"
                        .into(),
                )),
            };
        Ok(Artifact::Rootfs {
            dir: dir.display().to_string(),
        })
    }

    async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
        let rootfs = match &req.artifact {
            Artifact::Rootfs { dir } => dir.clone(),
            _ => {
                return Err(BackendError::Launch(
                    "container backend requires a Rootfs artifact".into(),
                ))
            }
        };
        let id = container_id(&req.workload, req.replica);
        let ip = {
            let mut pool = self.ipam.lock().expect("ipam mutex");
            pool.allocate()
                .map_err(|e| BackendError::Launch(e.to_string()))?
        };

        // Run the launch, releasing the IP + tearing down on any failure.
        match self.launch_inner(req, &id, &rootfs, ip).await {
            Ok(instance) => Ok(instance),
            Err(e) => {
                let veth = VethNetwork::for_vm(&id, &self.bridge);
                let _ = veth.teardown().await;
                self.ipam.lock().expect("ipam mutex").release(ip);
                Err(e)
            }
        }
    }

    async fn stop(&self, handle: &InstanceHandle) -> Result<(), BackendError> {
        let id = container_id(&handle.workload, handle.replica);
        // Kill every process in the instance's cgroup (cgroup v2 `cgroup.kill`),
        // then remove the cgroup + tear down the veth.
        let cgroup = format!("/sys/fs/cgroup/boatramp/{id}");
        let _ = std::fs::write(format!("{cgroup}/cgroup.kill"), b"1");
        let _ = std::fs::remove_dir(&cgroup);
        // Discard the captured guest log (best-effort; the pumps see EOF when the
        // cgroup is killed and their writer task then drains + exits).
        let _ = std::fs::remove_file(logsink::log_path(&self.logs_dir(), &id));
        VethNetwork::for_vm(&id, &self.bridge)
            .teardown()
            .await
            .map_err(|e| BackendError::Stop(e.to_string()))?;
        if let Some(ip) = handle.backend_ref.split(':').next() {
            if let Ok(addr) = ip.parse() {
                self.ipam.lock().expect("ipam mutex").release(addr);
            }
        }
        Ok(())
    }

    async fn health(&self, handle: &InstanceHandle) -> Result<Health, BackendError> {
        let addr = &handle.backend_ref; // "ip:port"
        let connect = tokio::net::TcpStream::connect(addr.as_str());
        match tokio::time::timeout(Duration::from_secs(2), connect).await {
            Ok(Ok(_)) => Ok(Health::Healthy),
            Ok(Err(_)) => Ok(Health::Unhealthy),
            Err(_) => Ok(Health::Unknown),
        }
    }

    /// **Snapshot** (scale-to-zero park): CRIU-dump the container's process tree to
    /// an image directory, freeing its resources. Finds the container's pid1 (the
    /// pidns init) in its cgroup, dumps it (which kills the tree), tears down the
    /// veth, and keeps the guest IP reserved so [`restore`](Self::restore) reuses it.
    /// `Ok(None)` if scale-to-zero is unavailable or the container isn't running.
    async fn snapshot(&self, handle: &InstanceHandle) -> Result<Option<Snapshot>, BackendError> {
        let Some(criu) = self.criu.clone() else {
            return Ok(None); // no CRIU → not a parkable backend
        };
        let (ip, port) = decode_ref(&handle.backend_ref).ok_or_else(|| {
            BackendError::Other(format!("bad handle ref {:?}", handle.backend_ref))
        })?;
        let id = container_id(&handle.workload, handle.replica);
        let cgroup = format!("/sys/fs/cgroup/boatramp/{id}");
        let data_dir = self.data_dir.clone();
        let bridge = self.bridge.clone();
        let id_for_dump = id.clone();

        // The CRIU work is blocking; run it off the async runtime.
        let dumped = tokio::task::spawn_blocking(move || -> Result<Option<String>, String> {
            let Some(pid1) = crate::criu::find_pid1(Path::new(&format!("{cgroup}/cgroup.procs")))
            else {
                return Ok(None); // not running
            };
            let rootfs = crate::criu::rootfs_of(pid1)
                .ok_or_else(|| format!("no rootfs mount for pid {pid1}"))?;
            let image_dir = data_dir.join("compute").join("criu").join(&id_for_dump);
            let _ = std::fs::remove_dir_all(&image_dir);
            criu.dump(pid1, &rootfs, &image_dir)?;
            Ok(Some(encode_snap(&image_dir.display().to_string(), &rootfs)))
        })
        .await
        .map_err(|e| BackendError::Other(format!("join: {e}")))?
        .map_err(BackendError::Other)?;

        let Some(stem) = dumped else {
            return Ok(None);
        };
        // Container is gone; tear down the veth but hold the IP for the wake.
        let _ = VethNetwork::for_vm(&id, &bridge).teardown().await;
        Ok(Some(Snapshot {
            workload: handle.workload.clone(),
            replica: handle.replica,
            data_ref: format!("{stem}|{ip}|{port}"),
        }))
    }

    /// **Restore** (scale-to-zero wake): recreate the veth, then CRIU-restore the
    /// container from its image. The restore runs an action-script
    /// (`boatramp __criu-net-setup`) at CRIU's namespace-setup hook to move the veth
    /// peer into the fresh netns + re-add `eth0` (reusing the launch-time wiring).
    /// Returns the resumed replica at its original endpoint.
    async fn restore(&self, snapshot: &Snapshot) -> Result<Instance, BackendError> {
        let criu = self.criu.clone().ok_or(BackendError::Unsupported)?;
        let (image_dir, rootfs, ip, port) = decode_snap(&snapshot.data_ref).ok_or_else(|| {
            BackendError::Other(format!("bad snapshot ref {:?}", snapshot.data_ref))
        })?;
        let addr: Ipv4Addr = ip
            .parse()
            .map_err(|e| BackendError::Other(format!("bad snapshot ip {ip}: {e}")))?;
        let id = container_id(&snapshot.workload, snapshot.replica);

        // Re-reserve the IP and recreate the host veth (the peer lands in the
        // restored netns via the action-script below).
        self.ipam.lock().expect("ipam mutex").reserve(addr);
        let veth = VethNetwork::for_vm(&id, &self.bridge);
        if let Err(e) = veth.host_setup().await {
            self.ipam.lock().expect("ipam mutex").release(addr);
            return Err(BackendError::Launch(format!("veth host setup: {e}")));
        }

        // Restore into an empty net namespace (the container's httpd socket is
        // bound to INADDR_ANY, so it needs no eth0 to resume).
        let restored =
            tokio::task::spawn_blocking(move || criu.restore(Path::new(&image_dir), &rootfs))
                .await
                .map_err(|e| BackendError::Other(format!("join: {e}")))?;
        let pid = match restored {
            Ok(pid) => pid,
            Err(e) => {
                let _ = veth.teardown().await;
                self.ipam.lock().expect("ipam mutex").release(addr);
                return Err(BackendError::Other(format!("criu restore: {e}")));
            }
        };

        // Re-attach networking from the host (CRIU left the netns empty): move the
        // veth peer into the restored container's netns + rename it to eth0 with the
        // original IP — the same wiring the launch path does with the worker pid.
        let restore_net = async {
            veth.move_peer_into_netns(pid)
                .await
                .map_err(|e| format!("move veth peer: {e}"))?;
            configure_in_netns(pid, &veth.peer_veth, addr, self.prefix, self.gateway)
        };
        if let Err(e) = restore_net.await {
            // Best-effort: kill the restored container + release the IP so a retry
            // starts clean.
            let cgroup = format!("/sys/fs/cgroup/boatramp/{id}");
            let _ = std::fs::write(format!("{cgroup}/cgroup.kill"), b"1");
            let _ = veth.teardown().await;
            self.ipam.lock().expect("ipam mutex").release(addr);
            return Err(BackendError::Launch(format!("restore netns setup: {e}")));
        }

        Ok(Instance {
            handle: InstanceHandle {
                workload: snapshot.workload.clone(),
                replica: snapshot.replica,
                backend_ref: format!("{ip}:{port}"),
            },
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: ip,
                port,
            },
        })
    }
}

impl ContainerBackend {
    /// Root for per-container guest-log files (`<data_dir>/compute/logs`).
    fn logs_dir(&self) -> PathBuf {
        self.data_dir.join("compute").join("logs")
    }

    /// The host backing directory for persistent volume `name`
    /// (`<data_dir>/compute/volumes/<name>`) — keyed by volume name (not VM), so
    /// it persists across launches/replicas.
    fn volume_dir(&self, name: &str) -> PathBuf {
        self.data_dir.join("compute").join("volumes").join(name)
    }

    /// Ensure each of the spec's persistent volumes has a backing directory and
    /// map it to the in-guest mount point the worker binds in (before
    /// `pivot_root`). The bind is a plain directory, so `size_mib` is advisory
    /// here (block-device size enforcement is the VMM volume path); the data
    /// persists across restarts because it lives outside the ephemeral rootfs.
    async fn stage_volumes(&self, spec: &ComputeSpec) -> Result<Vec<VolumeMount>, BackendError> {
        let mut mounts = Vec::with_capacity(spec.volumes.len());
        for vol in &spec.volumes {
            validate_volume(&vol.name, &vol.mount)?;
            let dir = self.volume_dir(&vol.name);
            tokio::fs::create_dir_all(&dir).await.map_err(|e| {
                BackendError::Launch(format!("create volume {} dir: {e}", vol.name))
            })?;
            mounts.push(VolumeMount {
                source: dir.display().to_string(),
                mount: vol.mount.clone(),
            });
        }
        Ok(mounts)
    }

    /// Wire the guest-log sink: a single writer appends to
    /// `<logs_dir>/<id>.log`, fed by one pump per stream. The pumps own the
    /// worker's stdout/stderr pipes and run until the guest exits (EOF).
    async fn spawn_log_capture<O, E>(
        &self,
        id: &str,
        stdout: O,
        stderr: E,
    ) -> Result<(), BackendError>
    where
        O: tokio::io::AsyncBufRead + Unpin + Send + 'static,
        E: tokio::io::AsyncBufRead + Unpin + Send + 'static,
    {
        let logs_dir = self.logs_dir();
        tokio::fs::create_dir_all(&logs_dir)
            .await
            .map_err(|e| BackendError::Launch(format!("create logs dir: {e}")))?;
        let path = logsink::log_path(&logs_dir, id);
        let file = tokio::fs::File::create(&path).await.map_err(|e| {
            BackendError::Launch(format!("create guest log {}: {e}", path.display()))
        })?;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(logsink::write_lines(file, rx));
        let (id_out, tx_out) = (id.to_string(), tx.clone());
        tokio::spawn(async move {
            let _ = logsink::pump(stdout, &id_out, "stdout", tx_out).await;
        });
        let id_err = id.to_string();
        tokio::spawn(async move {
            let _ = logsink::pump(stderr, &id_err, "stderr", tx).await;
        });
        Ok(())
    }

    /// The launch body (host veth → spawn worker → netns handshake → signal go).
    async fn launch_inner(
        &self,
        req: &LaunchRequest,
        id: &str,
        rootfs: &str,
        ip: Ipv4Addr,
    ) -> Result<Instance, BackendError> {
        let (uid, gid) = spec_uid_gid(&req.spec);
        let mut plan = SandboxPlan::for_spec(&req.spec, rootfs, id, uid, gid);
        plan.volumes = self.stage_volumes(&req.spec).await?;
        // Honor `cap_add` only where the posture allows it (single-tenant); otherwise
        // the dropped-`ALL` default stands. Bounded by the worker's user namespace.
        if self.cap_add_allowed {
            plan.cap_add = req.spec.cap_add.clone();
        }
        let veth = VethNetwork::for_vm(id, &self.bridge);
        veth.host_setup()
            .await
            .map_err(|e| BackendError::Launch(format!("veth host setup: {e}")))?;

        let mut child = tokio::process::Command::new(&self.self_exe)
            .arg("__sandbox")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| BackendError::Launch(format!("spawn worker: {e}")))?;
        let pid = child
            .id()
            .ok_or_else(|| BackendError::Launch("worker has no pid".into()))?;
        let mut cstdin = child
            .stdin
            .take()
            .ok_or_else(|| BackendError::Launch("worker stdin".into()))?;
        let mut cstdout = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| BackendError::Launch("worker stdout".into()))?,
        );
        let cstderr = BufReader::new(
            child
                .stderr
                .take()
                .ok_or_else(|| BackendError::Launch("worker stderr".into()))?,
        );

        // Send the plan (line 1) and wait for the worker to signal it has unshared.
        let plan_json =
            serde_json::to_string(&plan).map_err(|e| BackendError::Launch(e.to_string()))?;
        cstdin
            .write_all(format!("{plan_json}\n").as_bytes())
            .await
            .map_err(|e| BackendError::Launch(format!("send plan: {e}")))?;
        let mut ready = String::new();
        cstdout
            .read_line(&mut ready)
            .await
            .map_err(|e| BackendError::Launch(format!("await ready: {e}")))?;
        if ready.trim() != "ready" {
            // The worker died in `prepare` (cgroup/unshare/userns) before signaling
            // ready; surface its stderr so the failure reason isn't swallowed.
            let mut why = String::new();
            let mut lines = cstderr.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                why.push_str(&line);
                why.push('\n');
            }
            return Err(BackendError::Launch(format!(
                "worker did not signal ready (got {ready:?}); worker stderr:\n{}",
                why.trim_end()
            )));
        }

        // Write the user-namespace id maps from here (the privileged launcher). The
        // worker cannot self-write a range map after `unshare(CLONE_NEWUSER)` (it
        // lacks CAP_SETUID in the parent ns → EPERM); we hold it, so we write its
        // `/proc/<pid>/{uid,gid}_map` directly. Same pid-based handshake as the netns
        // setup below.
        if plan.namespaces.user {
            write_userns_maps(pid)
                .map_err(|e| BackendError::Launch(format!("write userns maps: {e}")))?;
        }

        // Move the veth peer into the worker's netns + configure eth0/lo there.
        veth.move_peer_into_netns(pid)
            .await
            .map_err(|e| BackendError::Launch(format!("move veth peer: {e}")))?;
        configure_in_netns(pid, &veth.peer_veth, ip, self.prefix, self.gateway)
            .map_err(|e| BackendError::Launch(format!("netns config: {e}")))?;

        // Networking is ready — release the worker to jail + exec the entrypoint.
        cstdin
            .write_all(b"go\n")
            .await
            .map_err(|e| BackendError::Launch(format!("signal go: {e}")))?;
        cstdin
            .flush()
            .await
            .map_err(|e| BackendError::Launch(format!("flush go: {e}")))?;
        // The worker's stdin is done with (the guest sees EOF on fd 0).
        drop(cstdin);

        // Capture the guest's stdout/stderr into the per-container log sink. This
        // also keeps reading the worker's stdout pipe — required, or the guest's
        // first write past the pipe buffer would `EPIPE`. The pumps + writer own
        // the pipe handles and run until the guest exits (EOF), so we can detach
        // the child handle without killing or awaiting it.
        self.spawn_log_capture(id, cstdout, cstderr).await?;
        drop(child);

        let port = req.spec.port;
        Ok(Instance {
            handle: InstanceHandle {
                workload: req.workload.clone(),
                replica: req.replica,
                backend_ref: format!("{ip}:{port}"),
            },
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: ip.to_string(),
                port,
            },
        })
    }
}

/// Resource caps for staging a rootfs archive. Defaults are
/// deliberately generous for a real rootfs yet bounded so a malicious or
/// oversized blob can't exhaust disk, memory, or unpack time. Not configurable
/// (a single fixed policy keeps the staging path uniform across deploy targets);
/// the per-call [`ArchiveCaps`] parameter exists so tests can inject tiny caps
/// without building gigabyte fixtures.
///
/// Max **compressed** bytes of the gzip blob streamed to disk before unpack. A
/// base rootfs (distro + app layers) is tens of MiB; 512 MiB leaves wide
/// headroom for fat images while capping the download a hostile blob can force —
/// which also bounds decompression work, since the input is bounded.
const MAX_COMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
/// Max **decompressed** total (summed `entry.size()`). Caps the classic gzip
/// "bomb" (a tiny blob that expands enormously); 2 GiB comfortably fits a large
/// rootfs while bounding the disk an attacker can fill.
const MAX_DECOMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Max number of tar **entries**. A real rootfs has tens of thousands of files;
/// 100k bounds the "many tiny entries" inode-exhaustion / slow-unpack variant
/// without rejecting realistic images.
const MAX_ENTRY_COUNT: u64 = 100_000;

/// Per-**unpack** resource caps (decompressed size + entry count). Production
/// uses [`ArchiveCaps::DEFAULT`]; tests inject tiny values to exercise the cap
/// paths cheaply. The compressed cap is not here — it guards the *download*
/// stream and is passed explicitly to [`stream_capped`].
#[derive(Clone, Copy, Debug)]
struct ArchiveCaps {
    /// Max summed decompressed size of all entries.
    max_decompressed_bytes: u64,
    /// Max number of tar entries.
    max_entries: u64,
}

impl ArchiveCaps {
    /// The production policy (the `MAX_*` constants above).
    const DEFAULT: ArchiveCaps = ArchiveCaps {
        max_decompressed_bytes: MAX_DECOMPRESSED_BYTES,
        max_entries: MAX_ENTRY_COUNT,
    };
}

/// Why staging a rootfs archive was rejected. Kept typed (rather than building
/// `BackendError` strings inline) so the cap checks — and their tests — can
/// match on the specific cause. The foreign `BackendError` only exposes a
/// string-carrying `Materialize` variant for staging failures, so the type is
/// preserved through all cap logic and flattened to a string only at that
/// boundary (see the `From` impl below).
#[derive(Debug)]
enum ArchiveError {
    /// The compressed blob streamed from storage exceeded `limit` bytes.
    CompressedTooLarge { limit: u64 },
    /// The summed decompressed size of the entries exceeded `limit` bytes.
    ArchiveTooLarge { limit: u64 },
    /// The archive held more than `limit` entries.
    TooManyEntries { limit: u64 },
    /// A tar entry's path escaped the target directory (`..`/absolute or a write
    /// through a symlink pointing outside).
    PathEscape(PathBuf),
    /// An underlying io / tar-format error.
    Io(std::io::Error),
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchiveError::CompressedTooLarge { limit } => {
                write!(f, "rootfs blob exceeds compressed cap ({limit} bytes)")
            }
            ArchiveError::ArchiveTooLarge { limit } => {
                write!(f, "rootfs archive exceeds decompressed cap ({limit} bytes)")
            }
            ArchiveError::TooManyEntries { limit } => {
                write!(
                    f,
                    "rootfs archive exceeds entry-count cap ({limit} entries)"
                )
            }
            ArchiveError::PathEscape(p) => write!(
                f,
                "rootfs archive entry {} escapes the target directory",
                p.display()
            ),
            ArchiveError::Io(e) => write!(f, "rootfs archive io: {e}"),
        }
    }
}

impl std::error::Error for ArchiveError {}

impl From<ArchiveError> for BackendError {
    fn from(e: ArchiveError) -> Self {
        BackendError::Materialize(e.to_string())
    }
}

/// Stream `body` (a content-addressed blob) into `file`, aborting with
/// [`ArchiveError::CompressedTooLarge`] as soon as more than `max_compressed`
/// bytes have arrived — so a hostile blob can't fill the disk before unpack even
/// gets a chance to apply its own caps.
async fn stream_capped(
    mut body: boatramp_core::ByteStream,
    file: &mut tokio::fs::File,
    max_compressed: u64,
) -> Result<(), BackendError> {
    let mut written: u64 = 0;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| BackendError::Materialize(e.to_string()))?;
        written = written.saturating_add(chunk.len() as u64);
        if written > max_compressed {
            return Err(ArchiveError::CompressedTooLarge {
                limit: max_compressed,
            }
            .into());
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| BackendError::Materialize(format!("write blob: {e}")))?;
    }
    file.flush()
        .await
        .map_err(|e| BackendError::Materialize(e.to_string()))?;
    Ok(())
}

/// Unpack a gzipped tar at `tar_path` into `dir` (blocking), enforcing the
/// decompressed-size + entry-count caps in `caps` and rejecting any entry that
/// would escape `dir`.
///
/// Rather than the blanket `Archive::unpack(dir)`, entries are walked manually so
/// the running decompressed-byte total + entry count can be checked *before*
/// each entry is written, and each entry is extracted with
/// [`tar::Entry::unpack_in`], which the `tar` crate documents as refusing to
/// write outside `dir`: it returns `Ok(false)` for a path that escapes via
/// `..`/absolute components, and `Err` for a write that would traverse a symlink
/// out of `dir`. Either is treated as a rejected (malicious) archive.
fn unpack_tar_gz(tar_path: &Path, dir: &Path, caps: ArchiveCaps) -> Result<(), ArchiveError> {
    // `unpack_in` canonicalizes `dir` and fails if it is absent, so ensure it
    // exists (the blanket `unpack` created it for us).
    std::fs::create_dir_all(dir).map_err(ArchiveError::Io)?;
    let file = std::fs::File::open(tar_path).map_err(ArchiveError::Io)?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let mut total: u64 = 0;
    let mut count: u64 = 0;
    for entry in archive.entries().map_err(ArchiveError::Io)? {
        let mut entry = entry.map_err(ArchiveError::Io)?;
        count += 1;
        if count > caps.max_entries {
            return Err(ArchiveError::TooManyEntries {
                limit: caps.max_entries,
            });
        }
        // The tar payload is size-prefixed, so the header size is authoritative
        // for how many bytes this entry will write; check the running total
        // before extracting so an oversized entry is never written.
        total = total.saturating_add(entry.size());
        if total > caps.max_decompressed_bytes {
            return Err(ArchiveError::ArchiveTooLarge {
                limit: caps.max_decompressed_bytes,
            });
        }
        if !entry.unpack_in(dir).map_err(ArchiveError::Io)? {
            let p = entry
                .path()
                .map(|p| p.into_owned())
                .unwrap_or_else(|_| PathBuf::from("<non-utf8>"));
            return Err(ArchiveError::PathEscape(p));
        }
    }
    Ok(())
}

/// Write the worker's user-namespace uid/gid maps from the launcher. The worker
/// unshared `CLONE_NEWUSER` but can't self-write a range map (no CAP_SETUID in the
/// parent ns after the unshare); the launcher still holds CAP_SETUID/SETGID in the
/// parent, so it writes `/proc/<pid>/{uid,gid}_map` for it (uid first). No
/// `setgroups=deny` is needed — a privileged writer may set gid_map directly.
fn write_userns_maps(pid: u32) -> Result<(), String> {
    let line = crate::worker::userns_map_line();
    std::fs::write(format!("/proc/{pid}/uid_map"), &line).map_err(|e| format!("uid_map: {e}"))?;
    std::fs::write(format!("/proc/{pid}/gid_map"), &line).map_err(|e| format!("gid_map: {e}"))?;
    Ok(())
}

/// Configure `eth0` (rename the peer, address, up, default route) + bring `lo`
/// up **inside** the worker's netns. Runs on a dedicated thread that `setns`es
/// into `/proc/<pid>/ns/net` (per-thread, so the launcher's netns is untouched)
/// and drives `rtnetlink` on a current-thread runtime.
fn configure_in_netns(
    pid: u32,
    peer: &str,
    ip: Ipv4Addr,
    prefix: u8,
    gateway: Ipv4Addr,
) -> Result<(), String> {
    let peer = peer.to_string();
    std::thread::scope(|scope| {
        scope
            .spawn(move || -> Result<(), String> {
                let nsfd = std::fs::File::open(format!("/proc/{pid}/ns/net"))
                    .map_err(|e| format!("open netns: {e}"))?;
                nix::sched::setns(nsfd.as_fd(), nix::sched::CloneFlags::CLONE_NEWNET)
                    .map_err(|e| format!("setns: {e}"))?;
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("netns runtime: {e}"))?;
                rt.block_on(async move {
                    let (conn, handle, _) =
                        rtnetlink::new_connection().map_err(|e| format!("netlink: {e}"))?;
                    tokio::spawn(conn);
                    rename_up_addr_route(&handle, &peer, ip, prefix, gateway).await
                })
            })
            .join()
            .map_err(|_| "netns config thread panicked".to_string())?
    })
}

/// The in-netns netlink sequence (rename peer→eth0, addr, up, default route, lo up).
async fn rename_up_addr_route(
    handle: &rtnetlink::Handle,
    peer: &str,
    ip: Ipv4Addr,
    prefix: u8,
    gateway: Ipv4Addr,
) -> Result<(), String> {
    use futures::TryStreamExt;
    let index = |name: String| async move {
        let mut links = handle.link().get().match_name(name.clone()).execute();
        match links.try_next().await {
            Ok(Some(msg)) => Ok(msg.header.index),
            Ok(None) => Err(format!("no link {name}")),
            Err(e) => Err(format!("get link {name}: {e}")),
        }
    };
    let peer_idx = index(peer.to_string()).await?;
    handle
        .link()
        .set(peer_idx)
        .name("eth0".to_string())
        .execute()
        .await
        .map_err(|e| format!("rename eth0: {e}"))?;
    handle
        .address()
        .add(peer_idx, std::net::IpAddr::V4(ip), prefix)
        .execute()
        .await
        .map_err(|e| format!("addr add: {e}"))?;
    handle
        .link()
        .set(peer_idx)
        .up()
        .execute()
        .await
        .map_err(|e| format!("eth0 up: {e}"))?;
    handle
        .route()
        .add()
        .v4()
        .gateway(gateway)
        .execute()
        .await
        .map_err(|e| format!("default route: {e}"))?;
    let lo_idx = index("lo".to_string()).await?;
    handle
        .link()
        .set(lo_idx)
        .up()
        .execute()
        .await
        .map_err(|e| format!("lo up: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::compute::{IsolationRequirement, RestartPolicy};
    use boatramp_core::{GetObject, ObjectMeta, PutMeta, StorageError};
    use bytes::Bytes;
    use std::collections::BTreeMap;

    /// A `Storage` that serves one in-memory blob for every `get` — enough to
    /// exercise the `materialize` rootfs-staging path with no privilege (the
    /// full jail+launch is the `container_live` privileged seam).
    struct OneBlob(Vec<u8>);

    #[async_trait]
    impl Storage for OneBlob {
        async fn get(&self, _key: &str) -> Result<GetObject, StorageError> {
            let bytes = Bytes::from(self.0.clone());
            let size = self.0.len() as u64;
            let body: boatramp_core::ByteStream =
                futures::stream::once(async move { Ok(bytes) }).boxed();
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
            _: boatramp_core::ByteStream,
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

    /// A gzipped tar holding a single executable at `bin/hello`.
    fn rootfs_tar_gz() -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        {
            let mut builder = tar::Builder::new(&mut enc);
            let content = b"#!/bin/true\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "bin/hello", &content[..])
                .unwrap();
            builder.finish().unwrap();
        }
        enc.finish().unwrap()
    }

    /// A unique temp dir for a test's `data_dir` (no external `tempfile` dep).
    fn unique_dir(label: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("boatramp-ctest-{label}-{pid}-{nanos}"))
    }

    fn spec_for(hash: &str) -> ComputeSpec {
        ComputeSpec {
            version: 1,
            root: RootSource::Tar(hash.into()),
            kernel: String::new(),
            kernel_cmdline: None,
            vcpus: 1,
            mem_mib: 64,
            entrypoint: vec!["/bin/hello".into()],
            env: BTreeMap::new(),
            port: 8080,
            restart: RestartPolicy::Always,
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

    #[test]
    fn spec_uid_gid_parses_user_or_defaults_to_namespace_root() {
        let mut spec = spec_for(&"a".repeat(64));
        // Absent ⇒ namespace-root default.
        assert_eq!(spec_uid_gid(&spec), (GUEST_UID, GUEST_GID));
        spec.user = Some("999".into());
        assert_eq!(spec_uid_gid(&spec), (999, 999));
        spec.user = Some("1000:1001".into());
        assert_eq!(spec_uid_gid(&spec), (1000, 1001));
        // A non-numeric user falls back to the default (never a parse panic).
        spec.user = Some("postgres".into());
        assert_eq!(spec_uid_gid(&spec), (GUEST_UID, GUEST_GID));
    }

    #[tokio::test]
    async fn materialize_stages_and_unpacks_rootfs_idempotently() {
        let data_dir = unique_dir("data");
        let backend = ContainerBackend::new(
            Arc::new(OneBlob(rootfs_tar_gz())),
            data_dir.clone(),
            "br-boatramp".into(),
            "10.0.0.0/24",
            PathBuf::from("/proc/self/exe"),
        )
        .expect("backend");
        let hash = "d".repeat(64);
        let spec = spec_for(&hash);

        let art = backend.materialize(&spec).await.expect("materialize");
        let dir = match &art {
            Artifact::Rootfs { dir } => PathBuf::from(dir),
            other => panic!("expected Rootfs, got {other:?}"),
        };
        assert!(dir.join("bin/hello").is_file(), "entrypoint unpacked");
        assert!(
            dir.join(".boatramp-ready").is_file(),
            "ready marker written"
        );

        // Idempotent: a second materialize re-uses the staged dir.
        let art2 = backend.materialize(&spec).await.expect("materialize 2");
        assert_eq!(art, art2);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    /// Live (network): the container backend pulls a real OCI image over the registry
    /// HTTP API — no Docker daemon — and overlays its layers into a rootfs directory the
    /// worker can `pivot_root` into. Validates the `RootSource::Image` path
    /// (`materialize` → `stage_image` → `oci::build_rootfs_dir`). Ignored by default
    /// (pulls ~150 MB of `pgvector/pgvector:pg16` from a public registry).
    #[tokio::test]
    #[ignore = "network: pulls pgvector/pgvector:pg16 from a public registry"]
    async fn materialize_pulls_an_oci_image_rootfs() {
        let data_dir = unique_dir("image");
        let backend = ContainerBackend::new(
            Arc::new(OneBlob(Vec::new())), // unused for the Image path (no Storage read)
            data_dir.clone(),
            "br-boatramp".into(),
            "10.0.0.0/24",
            PathBuf::from("/proc/self/exe"),
        )
        .expect("backend");
        let mut spec = spec_for(&"d".repeat(64));
        spec.root = RootSource::Image("pgvector/pgvector:pg16".into());

        let art = backend.materialize(&spec).await.expect("materialize image");
        let dir = match &art {
            Artifact::Rootfs { dir } => PathBuf::from(dir),
            other => panic!("expected Rootfs, got {other:?}"),
        };
        // The base postgres layer overlaid — the server binary + the image entrypoint.
        assert!(
            dir.join("usr/lib/postgresql/16/bin/postgres").is_file(),
            "postgres server binary present"
        );
        assert!(
            dir.join("usr/local/bin/docker-entrypoint.sh").is_file(),
            "postgres image entrypoint present"
        );
        // The pgvector layer overlaid on top of the base — the extension control file.
        assert!(
            dir.join("usr/share/postgresql/16/extension/vector.control")
                .is_file(),
            "pgvector extension layer applied over the base"
        );
        assert!(
            dir.join(".boatramp-ready").is_file(),
            "ready marker written"
        );

        // Idempotent: a second materialize re-uses the pulled rootfs (no re-pull).
        let art2 = backend
            .materialize(&spec)
            .await
            .expect("materialize image 2");
        assert_eq!(art, art2);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn stage_volumes_creates_backing_dirs_and_maps_mounts() {
        use boatramp_core::compute::VolumeRef;
        let data_dir = unique_dir("vol");
        let backend = ContainerBackend::new(
            Arc::new(OneBlob(Vec::new())),
            data_dir.clone(),
            "br-boatramp".into(),
            "10.0.0.0/24",
            PathBuf::from("/proc/self/exe"),
        )
        .expect("backend");
        let mut spec = spec_for(&"d".repeat(64));
        spec.volumes = vec![
            VolumeRef {
                mount: "/data".into(),
                name: "db".into(),
                size_mib: 128,
            },
            VolumeRef {
                mount: "/cache".into(),
                name: "cache".into(),
                size_mib: 64,
            },
        ];

        let mounts = backend.stage_volumes(&spec).await.expect("stage volumes");
        assert_eq!(mounts.len(), 2);
        // Each maps the host backing dir → the in-guest mount, and the dir exists.
        assert_eq!(mounts[0].mount, "/data");
        assert!(mounts[0].source.ends_with("/compute/volumes/db"));
        assert!(PathBuf::from(&mounts[0].source).is_dir());
        assert!(mounts[1].source.ends_with("/compute/volumes/cache"));
        assert!(PathBuf::from(&mounts[1].source).is_dir());

        // Idempotent: staging again re-uses the existing dirs.
        let again = backend.stage_volumes(&spec).await.expect("stage volumes 2");
        assert_eq!(again, mounts);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn validate_volume_rejects_traversal_in_name_and_mount() {
        // Good cases.
        assert!(validate_volume("db", "/data").is_ok());
        assert!(validate_volume("cache-1", "/var/lib/app").is_ok());
        // Name must be a single component — no separators / `..` / absolute.
        assert!(validate_volume("../etc", "/data").is_err());
        assert!(validate_volume("a/b", "/data").is_err());
        assert!(validate_volume("/abs", "/data").is_err());
        assert!(validate_volume(".", "/data").is_err());
        // Mount must be absolute with no `..`/`.`.
        assert!(validate_volume("db", "relative").is_err());
        assert!(validate_volume("db", "/../escape").is_err());
        assert!(validate_volume("db", "/a/../b").is_err());
    }

    // --- rootfs tar caps + malicious-archive rejection ---

    /// Build a gzipped tar from an in-memory `tar::Builder`.
    fn gzip(
        build: impl FnOnce(&mut tar::Builder<&mut flate2::write::GzEncoder<Vec<u8>>>),
    ) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        {
            let mut b = tar::Builder::new(&mut enc);
            build(&mut b);
            b.finish().unwrap();
        }
        enc.finish().unwrap()
    }

    /// Write `bytes` to a unique temp `.tar.gz` and return its path.
    fn write_tmp_tar(label: &str, bytes: &[u8]) -> PathBuf {
        let p = unique_dir(label).with_extension("tar.gz");
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn unpack_tar_gz_unpacks_happy_path() {
        let dir = unique_dir("unpack-ok");
        let tar = write_tmp_tar("unpack-ok", &rootfs_tar_gz());
        unpack_tar_gz(&tar, &dir, ArchiveCaps::DEFAULT).expect("unpack");
        assert!(dir.join("bin/hello").is_file());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&tar);
    }

    #[test]
    fn unpack_tar_gz_rejects_path_traversal() {
        // `Builder::append_data` refuses `..`, so inject the raw traversal name
        // into the GNU header and write it with the unchecked `append`.
        let bytes = gzip(|b| {
            let content = b"pwned";
            let mut h = tar::Header::new_gnu();
            h.set_size(content.len() as u64);
            h.set_mode(0o644);
            {
                let gnu = h.as_gnu_mut().unwrap();
                let name = b"../escape.txt";
                gnu.name[..name.len()].copy_from_slice(name);
            }
            h.set_cksum();
            b.append(&h, &content[..]).unwrap();
        });
        let parent = unique_dir("trav-parent");
        std::fs::create_dir_all(&parent).unwrap();
        let dir = parent.join("rootfs");
        let tar = write_tmp_tar("trav", &bytes);

        let res = unpack_tar_gz(&tar, &dir, ArchiveCaps::DEFAULT);
        assert!(
            matches!(res, Err(ArchiveError::PathEscape(_))),
            "expected PathEscape, got {res:?}"
        );
        // The escaped file must NOT have been written into the parent dir.
        assert!(
            !parent.join("escape.txt").exists(),
            "traversal entry escaped the target dir"
        );
        let _ = std::fs::remove_dir_all(&parent);
        let _ = std::fs::remove_file(&tar);
    }

    #[test]
    fn unpack_tar_gz_rejects_symlink_escape() {
        let outside = unique_dir("sym-outside");
        std::fs::create_dir_all(&outside).unwrap();
        let target = outside.join("secret.txt");

        let bytes = gzip(|b| {
            // A symlink "link" -> <outside dir> ...
            let mut h = tar::Header::new_gnu();
            h.set_size(0);
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_mode(0o777);
            b.append_link(&mut h, "link", &outside).unwrap();
            // ... then a file "link/secret.txt" that would write *through* the
            // symlink, escaping the target dir.
            let content = b"escaped via symlink";
            let mut h2 = tar::Header::new_gnu();
            h2.set_size(content.len() as u64);
            h2.set_mode(0o644);
            h2.set_cksum();
            b.append_data(&mut h2, "link/secret.txt", &content[..])
                .unwrap();
        });

        let dir = unique_dir("sym-rootfs");
        let tar = write_tmp_tar("sym", &bytes);
        let res = unpack_tar_gz(&tar, &dir, ArchiveCaps::DEFAULT);
        // `unpack_in` rejects the through-symlink write (Err or Ok(false)).
        assert!(res.is_err(), "expected rejection, got {res:?}");
        assert!(
            !target.exists(),
            "symlink let a write escape to {}",
            target.display()
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
        let _ = std::fs::remove_file(&tar);
    }

    #[test]
    fn unpack_tar_gz_rejects_decompression_bomb() {
        // A tiny archive (64-byte payload) rejected by a tiny injected cap — no
        // gigabyte allocation needed to exercise the decompressed-size guard.
        let bytes = gzip(|b| {
            let content = [0u8; 64];
            let mut h = tar::Header::new_gnu();
            h.set_size(content.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "big.bin", &content[..]).unwrap();
        });
        let dir = unique_dir("bomb");
        let tar = write_tmp_tar("bomb", &bytes);
        let caps = ArchiveCaps {
            max_decompressed_bytes: 16,
            ..ArchiveCaps::DEFAULT
        };
        let res = unpack_tar_gz(&tar, &dir, caps);
        assert!(
            matches!(res, Err(ArchiveError::ArchiveTooLarge { limit: 16 })),
            "expected ArchiveTooLarge, got {res:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&tar);
    }

    #[test]
    fn unpack_tar_gz_rejects_too_many_entries() {
        let bytes = gzip(|b| {
            for i in 0..5 {
                let content = b"x";
                let mut h = tar::Header::new_gnu();
                h.set_size(content.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, format!("f{i}"), &content[..])
                    .unwrap();
            }
        });
        let dir = unique_dir("manyent");
        let tar = write_tmp_tar("manyent", &bytes);
        let caps = ArchiveCaps {
            max_entries: 3,
            ..ArchiveCaps::DEFAULT
        };
        let res = unpack_tar_gz(&tar, &dir, caps);
        assert!(
            matches!(res, Err(ArchiveError::TooManyEntries { limit: 3 })),
            "expected TooManyEntries, got {res:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&tar);
    }

    #[tokio::test]
    async fn stream_capped_aborts_when_oversized() {
        let p = unique_dir("stream").with_extension("bin");
        let mut file = tokio::fs::File::create(&p).await.unwrap();
        let chunks: Vec<Result<Bytes, StorageError>> = vec![
            Ok(Bytes::from(vec![1u8; 10])),
            Ok(Bytes::from(vec![2u8; 10])),
        ];
        let body: boatramp_core::ByteStream = futures::stream::iter(chunks).boxed();
        let res = stream_capped(body, &mut file, 16).await;
        assert!(res.is_err(), "expected compressed-cap error, got {res:?}");
        assert!(res.unwrap_err().to_string().contains("compressed cap"));
        drop(file);
        let _ = std::fs::remove_file(&p);
    }

    #[tokio::test]
    async fn stream_capped_writes_under_cap() {
        let p = unique_dir("streamok").with_extension("bin");
        let mut file = tokio::fs::File::create(&p).await.unwrap();
        let chunks: Vec<Result<Bytes, StorageError>> = vec![Ok(Bytes::from(vec![1u8; 10]))];
        let body: boatramp_core::ByteStream = futures::stream::iter(chunks).boxed();
        stream_capped(body, &mut file, 16).await.expect("under cap");
        drop(file);
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 10);
        let _ = std::fs::remove_file(&p);
    }
}
