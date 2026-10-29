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
use std::os::fd::{AsFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use boatramp_core::Storage;
use boatramp_core::compute::{
    Artifact, BackendError, Capabilities, ComputeBackend, ComputeSpec, DataDirOwnership, Endpoint,
    ExecOutput, ForeignOwnedEntry, Health, Instance, InstanceHandle, IsolationClass, LaunchRequest,
    RootSource, Scheme, Snapshot, VolumeInfo, compute_instance_id, compute_volume_scope,
};
use boatramp_core::ipam::{IpAuthority, IpPool};
use boatramp_core::registry_auth::RegistryAuth;
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

/// The Linux UTS nodename limit (`__NEW_UTS_LEN`): `sethostname(2)` rejects a name
/// longer than this with `EINVAL`. Because the container id IS the hostname
/// ([`SandboxPlan::for_spec`] passes it to the UTS namespace), an id over this length
/// aborts container init before the guest binds — a silent crash-loop. 64 is the exact
/// kernel bound (a 64-byte name is accepted; 65+ is not).
const HOSTNAME_MAX: usize = 64;

/// Container id for a workload replica: the veth-name + cgroup + hostname + log stem.
/// Project-qualified for a non-`default` project (so two projects' same-named
/// workloads never share a cgroup/veth/hostname), but the bare `<workload>-<replica>`
/// for `default` — preserving existing default-project deployments byte-identical.
/// Delegates to the host-tested [`compute_instance_id`], then clamps to the UTS
/// hostname limit so a long id can't fail `sethostname`.
fn container_id(project: &str, workload: &str, replica: u32) -> String {
    clamp_container_id(compute_instance_id(project, workload, replica))
}

/// Clamp a container id to [`HOSTNAME_MAX`] so it is always a legal UTS hostname. A
/// per-tenant `Single` id embeds the project twice (`<project>-<compute>-<project>_<hash>-<replica>`
/// — the qualifier prefix plus the project-derived tenant ident), which overruns 64
/// bytes for a long project name. A short id is returned verbatim (readable, and
/// byte-identical to every currently-working deployment); a longer one keeps a readable
/// head and appends a stable base-36 digest of the **whole** id, so distinct long ids
/// never collapse to the same hostname/cgroup/veth (the same reasoning + digest the
/// veth-name derivation uses — see [`crate::net`]). Deterministic: the same id always
/// clamps identically, so teardown/relaunch/GC stay idempotent. Every consumer derives
/// from `container_id`, so hostname, cgroup path, veth input, and log path clamp
/// together and stay consistent.
fn clamp_container_id(id: String) -> String {
    if id.len() <= HOSTNAME_MAX {
        return id;
    }
    // A base-36 digest of the full id (11 chars ≈ 57 bits — collision-resistant across
    // distinct long ids), joined to a readable head that fills the rest of the budget.
    const DIGEST: usize = 11;
    let head = HOSTNAME_MAX - 1 - DIGEST; // room for "-" + the digest
    // Ids are validated ASCII (`[a-z0-9-_]`), so a byte slice is a char boundary; guard
    // anyway so a surprise multi-byte char can't panic.
    let head = id
        .get(..head)
        .unwrap_or_else(|| id.get(..head.min(id.len())).unwrap_or(&id));
    let clamped = format!("{head}-{}", crate::net::hash_b36(&id, DIGEST));
    tracing::debug!(
        original = %id,
        clamped = %clamped,
        "container id exceeded the UTS hostname limit; clamped with a stable digest"
    );
    clamped
}

/// The pure A2 GC decision: given the `(project,workload,replica)` keys this
/// backend still holds an IP for (`tracked`), the keys that are intentionally
/// **parked** (scale-to-zero `Zero`, which MUST keep their IP for the wake), and a
/// `container_alive` predicate (does a live container exist for this key), return the
/// keys whose IP should be reclaimed — those that are neither parked nor backed by a
/// live container. Conservative: a key is reclaimed only when the predicate says the
/// container is gone. Kept pure so it is host-testable (the cgroup probe is Linux-only).
fn gc_reclaim_keys(
    tracked: &[(String, String, u32)],
    parked: &std::collections::BTreeSet<(String, String, u32)>,
    container_alive: impl Fn(&(String, String, u32)) -> bool,
) -> Vec<(String, String, u32)> {
    tracked
        .iter()
        .filter(|k| !parked.contains(*k) && !container_alive(k))
        .cloned()
        .collect()
}

/// Whether a live container exists for cgroup id `id` (the A2 GC's "is it gone?"
/// probe). A launched container has a `/sys/fs/cgroup/boatramp/<id>` cgroup whose
/// `cgroup.procs` lists at least one live pid; `stop`/`snapshot` remove the cgroup
/// (and a crashed init's cgroup empties). So the container is considered **alive**
/// iff the cgroup dir exists AND `cgroup.procs` is non-empty. On a non-Linux host
/// (no cgroups) the probe can't decide, so it returns `true` — the GC then never
/// reclaims, staying conservative (the backend itself is Linux-only in practice).
#[cfg(target_os = "linux")]
fn container_cgroup_alive(id: &str) -> bool {
    let procs = format!("/sys/fs/cgroup/boatramp/{id}/cgroup.procs");
    match std::fs::read_to_string(&procs) {
        // A live cgroup has at least one pid; an empty file ⇒ the tree exited.
        Ok(contents) => contents.split_whitespace().next().is_some(),
        // No cgroup dir / file ⇒ stopped or never launched ⇒ not alive.
        Err(_) => false,
    }
}

/// Non-Linux stub: no cgroups to probe, so treat every container as alive (the GC
/// never reclaims off-Linux — the container backend only truly runs on Linux).
#[cfg(not(target_os = "linux"))]
fn container_cgroup_alive(_id: &str) -> bool {
    true
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
/// The bare volume name every managed database is handed ([`managed_db_spec`]'s
/// `VolumeRef { name: "data", … }`). Before volumes were keyed per `(project, workload)`,
/// EVERY default-project / shared managed DB backed this one name at the flat
/// `<data_dir>/compute/volumes/data` directory — the cross-tenant collision this module
/// closes. It is the only legacy flat name whose adoption is CONTENDED (many workloads
/// shared it), so its migration requires a proven single claimant; any other flat name
/// (a non-default `Single` tenant's globally-unique `<compute>-<ident>`) adopts 1:1.
const LEGACY_SHARED_VOLUME_NAME: &str = "data";

/// Prefix for a per-`(project, workload)` volume SCOPE directory
/// (`<volumes>/@<scope>/<name>`). `@` is outside the resource-slug / `sanitize_ident`
/// alphabet (`[A-Za-z0-9_-]`) that every volume and workload name is drawn from, so a scope
/// directory can never collide with — and nest a scoped volume inside — a LEGACY FLAT volume
/// dir (`<volumes>/<name>`, the migration source) that shares the same `volumes/` root. This
/// keeps the scoped layout and the legacy flat layout in disjoint namespaces.
const SCOPE_DIR_PREFIX: &str = "@";

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

/// Validate a spec-declared volume (its `name` + `mount`) BEFORE it is used to build any
/// host path. This is the single choke point for both the migration
/// ([`ContainerBackend::adopt_legacy_volumes`]) and the launch
/// ([`ContainerBackend::stage_volumes`]) paths — each MUST call it before constructing a
/// `volume_dir`/`scoped_volume_dir` from `name`, because the on-disk `vol.name` is otherwise
/// unconstrained (nothing slug-checks a `ComputeSpec` volume name at ingress). It rejects:
///  * a traversing / multi-component / absolute `name` or `mount` ([`validate_volume`]) — so a
///    `".."` name can't escape `<volumes>/`, and
///  * a `name` starting with the reserved scope-dir prefix `@` ([`SCOPE_DIR_PREFIX`]) — so a
///    guest/spec can never name a volume `@<victimscope>` whose backing dir would ALIAS another
///    workload's scope directory (a crafted-name cross-tenant transfer).
fn validate_spec_volume(name: &str, mount: &str) -> Result<(), BackendError> {
    validate_volume(name, mount)?;
    if name.starts_with(SCOPE_DIR_PREFIX) {
        return Err(BackendError::Launch(format!(
            "invalid volume name {name:?}: the {SCOPE_DIR_PREFIX:?} prefix is reserved for \
             per-(project, workload) volume scopes"
        )));
    }
    Ok(())
}

/// Reject a volume **scope** (`<project>@<workload>` / `<workload>`) that could escape the
/// volumes root. The scope is joined as a directory under `<data_dir>/compute/volumes/`
/// (the parent of each scoped volume dir), so — like a volume name — it must be a single
/// normal path component (no `/`, `..`, `.`, or absolute path). Project/workload names are
/// validated `[a-z0-9-]` upstream, so a well-formed scope always passes; this is a
/// defense-in-depth guard matching [`validate_volume`]'s name check.
fn validate_volume_scope(scope: &str) -> Result<(), BackendError> {
    if matches!(
        Path::new(scope).components().collect::<Vec<_>>().as_slice(),
        [Component::Normal(_)]
    ) {
        Ok(())
    } else {
        Err(BackendError::Launch(format!(
            "invalid volume scope {scope:?}: must be a single path component"
        )))
    }
}

/// The per-node guest-IP lifecycle: an [`IpPool`] plus the
/// `(project,workload,replica) → ip` assignment map. Keying by **project** first
/// closes the cross-tenant collision where two projects' same-named workloads
/// (`web/0` in each) shared a slot → an IP collision. The map is what keeps a
/// replica's endpoint **stable** across a relaunch and prevents a live address being
/// re-handed to a different workload (the container-IP collision). The allocation
/// *decisions* are the pure, host-tested [`IpPool`] methods
/// (`reserve_in_use`/`is_free`/`allocate`) — this struct only tracks ownership so a
/// stop can release an IP only when it is truly the last user, and a relaunch can
/// reclaim its own address in place. Guarded by the backend's `Mutex`, so concurrent
/// launches each observe/commit under the lock and can never be handed the same
/// address.
struct IpLifecycle {
    /// The **shared** address authority for this bridge/subnet (A5). Every co-located
    /// backend (container veths + embedded/macOS VMM taps) holds a clone of the SAME
    /// authority, so an address handed to one is never re-handed to another on the same
    /// L2. The `(project,workload,replica)` ownership map below stays per-backend (it is
    /// the container backend's stable-endpoint / last-user bookkeeping); only the pool
    /// underneath is shared.
    authority: IpAuthority,
    assigned: std::collections::BTreeMap<(String, String, u32), Ipv4Addr>,
}

impl IpLifecycle {
    fn new(authority: IpAuthority) -> Self {
        Self {
            authority,
            assigned: std::collections::BTreeMap::new(),
        }
    }

    /// Adopt the endpoint IPs of already-known replicas into the shared pool (boot
    /// startup), keyed by `(project,workload,replica)` so each can later reclaim its
    /// own address (and two projects' same-named workloads stay distinct).
    /// `reserve_in_use` skips the gateway + any IP outside this pool's CIDR (a replica
    /// on another backend/subnet), so passing the whole fleet is safe. Feeding the
    /// SHARED authority is what reserves a running VMM guest's IP before the container
    /// backend allocates (and vice-versa).
    fn adopt(&mut self, replicas: &[(String, String, u32, Ipv4Addr)]) {
        let ips: Vec<Ipv4Addr> = replicas.iter().map(|(_, _, _, ip)| *ip).collect();
        self.authority.reserve_in_use(&ips);
        for (p, w, r, ip) in replicas {
            // Only record an address this pool manages (in-subnet, non-gateway); an
            // out-of-subnet endpoint (another backend/subnet) isn't ours to track.
            if self.authority.manages(*ip) {
                self.assigned.insert((p.clone(), w.clone(), *r), *ip);
            }
        }
    }

    /// Allocate the IP for a launching replica: reclaim its own recorded address
    /// (stable across a relaunch) when it still holds it or the address is free;
    /// otherwise allocate a fresh, node-unique one. A pre-existing collision (the
    /// recorded address held by another live replica) is broken here by re-homing
    /// this replica to a unique address.
    fn launch(
        &mut self,
        project: &str,
        workload: &str,
        replica: u32,
    ) -> Result<Ipv4Addr, BackendError> {
        let key = (project.to_string(), workload.to_string(), replica);
        let recorded = self.assigned.get(&key).copied();
        let ip = match recorded {
            // This replica's own address (no other live holder): reclaim it. Ensure
            // it is reserved (a prior stop may have released it) — this is exactly
            // `allocate_stable`, which reuses a free preferred address or, if it is
            // still reserved (by this replica's adoption), leaves it held.
            Some(ip) if self.owns(&key, ip) => {
                self.authority.reserve(ip); // idempotent — keeps a released-then-reclaimed IP held
                ip
            }
            // Recorded but held by *another* live replica (a stale collision), or no
            // record at all: let the pool decide — reuse `recorded` iff it is free,
            // else a fresh unique address. Never re-homes onto a live IP.
            _ => self
                .authority
                .allocate_stable(recorded)
                .map_err(|e| BackendError::Launch(e.to_string()))?,
        };
        self.assigned.insert(key, ip);
        Ok(ip)
    }

    /// Free `ip` on a failed launch, but only if no live replica still holds it, and
    /// forget the `(project,workload,replica)` record so a retry re-decides cleanly.
    fn launch_failed(&mut self, project: &str, workload: &str, replica: u32, ip: Ipv4Addr) {
        self.assigned
            .remove(&(project.to_string(), workload.to_string(), replica));
        self.release_if_last(ip);
    }

    /// Stop: forget the replica and release its address — only when no other live
    /// replica still maps to it (so tearing down one side of a stale collision can't
    /// free the address the surviving replica holds). `backend_ref` is `<ip>:<port>`.
    fn stop(&mut self, project: &str, workload: &str, replica: u32, backend_ref: &str) {
        let key = (project.to_string(), workload.to_string(), replica);
        // Prefer the recorded assignment; fall back to the handle's ref (older
        // records, or a replica this process never launched itself).
        let ip = self
            .assigned
            .remove(&key)
            .or_else(|| backend_ref.split(':').next().and_then(|s| s.parse().ok()));
        if let Some(ip) = ip {
            self.release_if_last(ip);
        }
    }

    /// Re-reserve `ip` for a scale-to-zero **restore** (the wake reuses the parked
    /// replica's original endpoint), recording ownership.
    fn reserve_for(&mut self, project: &str, workload: &str, replica: u32, ip: Ipv4Addr) {
        self.authority.reserve(ip);
        self.assigned
            .insert((project.to_string(), workload.to_string(), replica), ip);
    }

    /// Whether `key` is the only recorded holder of `ip`.
    fn owns(&self, key: &(String, String, u32), ip: Ipv4Addr) -> bool {
        !self
            .assigned
            .iter()
            .any(|(k, &held)| k != key && held == ip)
    }

    /// Release `ip` only if no remaining assignment holds it (last-user rule).
    fn release_if_last(&mut self, ip: Ipv4Addr) {
        if !self.assigned.values().any(|&held| held == ip) {
            self.authority.release(ip);
        }
    }

    /// The `(project,workload,replica)` keys this backend currently tracks as holding
    /// an address — the input to the A2 pool-vs-reality GC (which of them still have a
    /// live container). Cheap clone under the backend mutex.
    fn assigned_keys(&self) -> Vec<(String, String, u32)> {
        self.assigned.keys().cloned().collect()
    }

    /// Release the address recorded for `key` (unconditionally forgetting the record),
    /// used by the A2 GC once it has decided the container is gone and the replica is
    /// not intentionally parked. Applies the same last-user rule so tearing down one
    /// side of a stale collision can't free the surviving holder's address. Returns the
    /// address that was recorded (whether or not it was actually released), for logging.
    fn gc_release(&mut self, key: &(String, String, u32)) -> Option<Ipv4Addr> {
        let ip = self.assigned.remove(key)?;
        self.release_if_last(ip);
        Some(ip)
    }

    /// Allocate a **transient** address for a one-shot ephemeral container (an
    /// export/import client), WITHOUT recording it in the `(project,workload,replica)`
    /// ownership map: an ephemeral run is not a persisted replica, so it is never adopted
    /// at boot nor reclaimed by the A2 GC — [`release_ephemeral`](Self::release_ephemeral)
    /// returns it the moment the run ends. Drawn from the SAME shared authority as every
    /// replica, so it can never collide with a live workload's address while it is held.
    fn allocate_ephemeral(&mut self) -> Result<Ipv4Addr, BackendError> {
        self.authority
            .allocate()
            .map_err(|e| BackendError::Launch(e.to_string()))
    }

    /// Return a transient ephemeral address to the shared pool. Unconditional (an
    /// ephemeral address is never shared with a tracked replica, so the last-user rule
    /// does not apply) and idempotent.
    fn release_ephemeral(&mut self, ip: Ipv4Addr) {
        self.authority.release(ip);
    }
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
    /// Per-node guest-IP lifecycle: the pool plus the `(workload,replica) → ip`
    /// assignment map that keeps a replica's endpoint **stable** across a relaunch
    /// and **unique** node-wide. Adopted from persisted state at startup (see
    /// [`ContainerBackend::reserve_in_use`]).
    ipam: Mutex<IpLifecycle>,
    /// A usable `criu` (present + `criu check` passed) enables scale-to-zero;
    /// `None` leaves the backend without it (the scheduler routes such workloads
    /// elsewhere). Detected once at construction.
    criu: Option<crate::criu::Criu>,
    /// Whether a spec's `cap_add` is honored here. Set from the isolation posture
    /// (single-tenant only); off under the multi-tenant guard, so a cap-add spec is
    /// forced back to the dropped-`ALL` default.
    cap_add_allowed: bool,
    /// The host id container uid/gid `0` maps onto. Default [`USERNS_HOST_BASE`] (rootless
    /// — in-container root is unprivileged host `100000`). A single-tenant operator may opt
    /// into `0` (in-container root = host root) via [`Self::with_host_root`]. Governs the
    /// userns map, the volume pre-chown, and the rootfs ownership shift.
    userns_base: u32,
    /// The internal-DNS suffix to write into each container's `/etc/resolv.conf`
    /// (`nameserver <gateway>` + `search <project>.<domain>`), pointing the guest at
    /// the resolver on the bridge gateway. `Some(domain)` ⇒ write it at launch
    /// (internal DNS on); `None` ⇒ leave the image's resolv.conf (feature off). Set by
    /// [`Self::with_internal_dns`] from `compute.internal_dns` / `compute.dns_domain`.
    internal_dns_domain: Option<String>,
    /// **Air-gap override** for the one-shot [`run_ephemeral`](ComputeBackend::run_ephemeral)
    /// client image → a **preloaded rootfs**, so an export/import can run with NO registry
    /// pull. Keyed by the exact client image reference the driver asks for (e.g.
    /// `pgvector/pgvector:pg16`); the value is either an **absolute host path** to an
    /// already-unpacked rootfs directory (used verbatim, never pulled), or a **Storage
    /// blob hash** of a rootfs tar the backend stages the same way `materialize` stages a
    /// `RootSource::Tar` (`stage_rootfs`). Empty (the default) ⇒ every client image is
    /// resolved by the on-demand OCI pull+build path (`stage_image`). Set by
    /// [`Self::with_client_image_rootfs`] from the `[compute] client_image_rootfs` config.
    client_image_rootfs: std::collections::BTreeMap<String, String>,
    /// Whether a one-shot [`run_ephemeral`](ComputeBackend::run_ephemeral) client image MUST be
    /// provenance-pinned: preloaded via [`client_image_rootfs`](Self::client_image_rootfs) (no
    /// pull) or referenced by an `@sha256:` **digest** (a content-addressed pull the registry
    /// cannot substitute). Set from the multi-tenant posture (`strict`): there, an unauthenticated
    /// on-demand pull of a mutable tag is refused, because a compromised/MITM'd registry could
    /// swap in a malicious image that runs with the managed-DB credential in its environment and
    /// egress to the database. Off (the default) under the single-tenant/operator posture, which
    /// keeps the convenient tag pull. Set by [`Self::with_require_pinned_client_image`].
    require_pinned_client_image: bool,
    /// Wall-clock backstop for a single [`run_ephemeral`](ComputeBackend::run_ephemeral)
    /// invocation (one export/import client run). Generous by default
    /// ([`EPHEMERAL_RUN_TIMEOUT`]); an operator raises it for a very large migration so the
    /// backstop never kills legitimate work (the real unreachable-DSN hang is bounded far
    /// tighter by the client's own connect timeout). Set by [`Self::with_ephemeral_timeout`].
    ephemeral_timeout: Duration,
    /// The ONE `(project, workload)` authorized to **adopt the legacy shared `data`
    /// volume** — the pre-v0.46 bare `<data_dir>/compute/volumes/data` directory that every
    /// default-project / shared managed database shared before volumes were keyed per
    /// `(project, workload)` ([`crate::backend`] volume scope). `None` means no workload may
    /// adopt it: either there is no legacy data, or its owner is **ambiguous** (≥2 co-located
    /// managed DBs, none designated) and the node could not prove which one initialized the
    /// cluster — in which case a managed DB whose own scoped volume is empty but a non-empty
    /// legacy `data` dir still exists **fails closed** rather than fresh-initializing over an
    /// unclaimed neighbor's cluster (see [`Self::adopt_legacy_volume_if_claimed`]). Decided
    /// once at node boot from the `databases` config (sole managed DB ⇒ it; else the operator
    /// `adopt_legacy_data_volume` designation; else `None`). Set by
    /// [`Self::with_legacy_data_claimant`].
    legacy_data_claimant: Option<(String, String)>,
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
        let pool = IpPool::new(subnet).map_err(|e| BackendError::Other(e.to_string()))?;
        let gateway = pool.gateway();
        // Default to a private authority over `subnet`; `with_ip_authority` replaces it
        // with the shared one so co-located VMM backends draw from the same pool (A5).
        let authority = IpAuthority::over(pool);
        Ok(Self {
            storage,
            data_dir,
            bridge,
            prefix: net.prefix_len(),
            gateway,
            self_exe,
            ipam: Mutex::new(IpLifecycle::new(authority)),
            criu: crate::criu::Criu::detect(),
            cap_add_allowed: false,
            userns_base: crate::worker::USERNS_HOST_BASE,
            internal_dns_domain: None,
            client_image_rootfs: std::collections::BTreeMap::new(),
            require_pinned_client_image: false,
            ephemeral_timeout: EPHEMERAL_RUN_TIMEOUT,
            legacy_data_claimant: None,
        })
    }

    /// Authorize exactly ONE `(project, workload)` to adopt the legacy shared `data` volume
    /// (the pre-per-workload bare `<data_dir>/compute/volumes/data` directory). The node
    /// decides this once at boot from the `databases` config — the sole managed DB, else the
    /// operator-designated `adopt_legacy_data_volume` binding, else `None` (ambiguous ⇒ no
    /// adoption, fail closed). See [`legacy_data_claimant`](Self::legacy_data_claimant).
    #[must_use]
    pub fn with_legacy_data_claimant(mut self, claimant: Option<(String, String)>) -> Self {
        self.legacy_data_claimant = claimant;
        self
    }

    /// Require a one-shot client image to be provenance-pinned (preloaded via the air-gap map or
    /// referenced by an `@sha256:` digest), refusing an unauthenticated on-demand pull of a mutable
    /// tag. The node sets this from the multi-tenant posture (`strict`). See
    /// [`require_pinned_client_image`](Self::require_pinned_client_image).
    #[must_use]
    pub fn with_require_pinned_client_image(mut self, require: bool) -> Self {
        self.require_pinned_client_image = require;
        self
    }

    /// Enable writing each container's `/etc/resolv.conf` to point at the internal
    /// DNS resolver on the bridge gateway, with a `search <project>.<domain>` suffix
    /// (`compute.internal_dns` on). `None` (the default) leaves the image's resolv.conf
    /// untouched. The node passes the effective `compute.dns_domain` here when the
    /// internal resolver is active.
    pub fn with_internal_dns(mut self, domain: Option<String>) -> Self {
        self.internal_dns_domain = domain;
        self
    }

    /// Supply the **air-gap** map of export/import client image reference → a preloaded
    /// rootfs (an absolute unpacked-rootfs path, or a Storage blob hash of a rootfs tar),
    /// so [`run_ephemeral`](ComputeBackend::run_ephemeral) resolves those images with no
    /// registry pull. Empty (the default) keeps the on-demand OCI pull+build path. Wired
    /// from `[compute] client_image_rootfs`. See [`Self::client_image_rootfs`].
    pub fn with_client_image_rootfs(
        mut self,
        map: std::collections::BTreeMap<String, String>,
    ) -> Self {
        self.client_image_rootfs = map;
        self
    }

    /// Set the wall-clock backstop for a single `run_ephemeral` invocation (0 ⇒ keep the
    /// generous built-in default [`EPHEMERAL_RUN_TIMEOUT`]). Mirrors the docker backend's
    /// `with_ephemeral_timeout`.
    pub fn with_ephemeral_timeout(mut self, timeout: Duration) -> Self {
        if !timeout.is_zero() {
            self.ephemeral_timeout = timeout;
        }
        self
    }

    /// Replace this backend's private IP pool with a **shared** [`IpAuthority`] (A5),
    /// so every backend placing guests on the same bridge/subnet (this container
    /// backend + the embedded / macOS VMM backends) draws from and releases to ONE
    /// address pool and can never hand out the same `10.0.0.x` on the same L2. The
    /// `(project,workload,replica)` ownership map is reset (empty at construction, so
    /// this loses nothing) and rebuilt over the shared authority. `build_compute`
    /// builds one authority per bridge/subnet and calls this on the container backend
    /// with a clone of it. The authority MUST be over the same subnet this backend was
    /// constructed with (they share `cfg.subnet`); the gateway/prefix are unchanged.
    pub fn with_ip_authority(mut self, authority: IpAuthority) -> Self {
        self.ipam = Mutex::new(IpLifecycle::new(authority));
        self
    }

    /// Allow a spec's `cap_add` to retain capabilities on top of the dropped-`ALL`
    /// default here (single-tenant posture). Off by default, so the multi-tenant guard
    /// keeps every capability dropped.
    pub fn with_cap_add_allowed(mut self, allowed: bool) -> Self {
        self.cap_add_allowed = allowed;
        self
    }

    /// Opt into **host-root** containers (a single-tenant / trusted posture): map the
    /// container's user namespace `0 → host 0` instead of the rootless `0 → host 100000`.
    /// In-container root is then real host root — like a stock Docker container — which
    /// removes the rootfs ownership shift (the image is already host-root-owned). It trades
    /// the rootless isolation guarantee for running your own trusted image, so it is
    /// off by default; the rootless base stands unless an operator opts in.
    pub fn with_host_root(mut self, host_root: bool) -> Self {
        self.userns_base = if host_root {
            0
        } else {
            crate::worker::USERNS_HOST_BASE
        };
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
    async fn stage_rootfs(&self, hash: &str, base: u32) -> Result<PathBuf, BackendError> {
        // Keyed by the userns base too: the unpacked tree is ownership-shifted for that
        // base (see `shift_rootfs`), so a different base needs its own staging. `base` is the
        // workload's EFFECTIVE base (normally `self.userns_base`, but a per-launch derived
        // base on the reused-volume path — see `resolve_volume_mapping`).
        let dir = self
            .data_dir
            .join("compute")
            .join("rootfs")
            .join(format!("{hash}.b{base}"));
        let ready = dir.join(".boatramp-ready");
        if tokio::fs::try_exists(&ready).await.unwrap_or(false) {
            return Ok(dir);
        }
        let tmp = self
            .data_dir
            .join("compute")
            .join("rootfs")
            .join(format!(".{hash}.tar.gz"));
        match self
            .stage_rootfs_inner(hash, &dir, &ready, &tmp, base)
            .await
        {
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
        base: u32,
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
            unpack_tar_gz(&unpack_tmp, &unpack_dir, ArchiveCaps::DEFAULT)?;
            // Shift the extracted ownership into the container's mapped host range so the
            // guest's namespace-root owns its rootfs (a no-op when base == 0).
            shift_rootfs(&unpack_dir, base).map_err(ArchiveError::Io)
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
    async fn stage_image(&self, image: &str, base: u32) -> Result<PathBuf, BackendError> {
        // Keyed by the image reference AND the userns base (the overlaid tree is
        // ownership-shifted for that base — see `shift_rootfs`). `base` is the workload's
        // EFFECTIVE base (normally `self.userns_base`, but a per-launch derived base on the
        // reused-volume path — see `resolve_volume_mapping`).
        let key = boatramp_types::manifest::sha256_hex(image.as_bytes());
        let images = self.data_dir.join("compute").join("images");
        let dir = images.join(format!("{key}.b{base}"));
        if tokio::fs::try_exists(dir.join(".boatramp-ready"))
            .await
            .unwrap_or(false)
        {
            return Ok(dir);
        }
        tokio::fs::create_dir_all(&images)
            .await
            .map_err(|e| BackendError::Materialize(format!("create {}: {e}", images.display())))?;
        let tmp = images.join(format!(".{key}.b{base}.tmp"));
        // Clear any leftover partial from a prior interrupted pull.
        let _ = tokio::fs::remove_dir_all(&tmp).await;
        match boatramp_firecracker::oci::build_rootfs_dir(image, &tmp).await {
            Ok(()) => {
                // Shift the overlaid ownership into the container's mapped host range so
                // the guest's namespace-root owns its rootfs (a no-op when base == 0).
                let shift_dir = tmp.clone();
                tokio::task::spawn_blocking(move || shift_rootfs(&shift_dir, base))
                    .await
                    .map_err(|e| BackendError::Materialize(format!("join: {e}")))?
                    .map_err(|e| BackendError::Materialize(format!("shift rootfs: {e}")))?;
                tokio::fs::write(tmp.join(".boatramp-ready"), b"1")
                    .await
                    .map_err(|e| BackendError::Materialize(format!("mark ready: {e}")))?;
                // Publish atomically; replace any stale directory at the final path.
                let _ = tokio::fs::remove_dir_all(&dir).await;
                tokio::fs::rename(&tmp, &dir).await.map_err(|e| {
                    BackendError::Materialize(format!("publish rootfs {}: {e}", dir.display()))
                })?;
                // Persist the image's OCI runtime config (`Env`/`WorkingDir`) as a sidecar
                // next to the staged rootfs, so an ephemeral one-shot can seed the client's
                // `PATH` + cwd from it WITHOUT a re-pull on the cached-rootfs fast path.
                // Best-effort: a fetch/write failure here is recovered by an on-demand fetch
                // in `client_image_config`, and a hard miss degrades to the default env.
                self.persist_image_config_sidecar(image).await;
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

    /// Path to the on-disk sidecar caching a staged image's OCI runtime config
    /// (`<data_dir>/compute/images/<sha256(ref)>.b<base>.imgcfg.json`) — a SIBLING of the
    /// staged rootfs directory, so the config never appears inside the guest filesystem.
    fn image_config_sidecar(&self, image: &str) -> PathBuf {
        let key = boatramp_types::manifest::sha256_hex(image.as_bytes());
        self.data_dir
            .join("compute")
            .join("images")
            .join(format!("{key}.b{}.imgcfg.json", self.userns_base))
    }

    /// Fetch the image's OCI config from the registry and write the sidecar (best-effort,
    /// never errors). Called at stage time; the ephemeral path reads the sidecar back.
    async fn persist_image_config_sidecar(&self, image: &str) {
        if let Ok(cfg) = boatramp_firecracker::oci::pull_image_config(image).await
            && let Ok(json) = serde_json::to_vec(&cfg)
        {
            let _ = tokio::fs::write(self.image_config_sidecar(image), json).await;
        }
    }

    /// Resolve the client image's OCI runtime config (`Env`, `WorkingDir`) for an ephemeral
    /// one-shot. Prefer the on-disk sidecar (written at stage time); on a miss — an image
    /// staged by a pre-0.35.2 server, a sidecar write that failed — fetch once from the
    /// registry and cache it. An air-gap preloaded rootfs (no registry to query) or an
    /// offline fetch yields the DEFAULT (empty) config, so the one-shot runs with just the
    /// caller's env + the libc default `PATH`, exactly as before this fix (never fails the
    /// run). A `@sha256:`-pinned image makes this fetch content-addressed; the multi-tenant
    /// mutable-tag refusal already fired in `resolve_client_rootfs` before we reach here.
    async fn client_image_config(&self, image: &str) -> boatramp_firecracker::oci::ImageConfig {
        let sidecar = self.image_config_sidecar(image);
        if let Ok(bytes) = tokio::fs::read(&sidecar).await
            && let Ok(cfg) =
                serde_json::from_slice::<boatramp_firecracker::oci::ImageConfig>(&bytes)
        {
            return cfg;
        }
        if self.client_image_rootfs.contains_key(image) {
            // Air-gap preloaded rootfs — there is no registry to fetch the config from.
            return boatramp_firecracker::oci::ImageConfig::default();
        }
        match boatramp_firecracker::oci::pull_image_config(image).await {
            Ok(cfg) => {
                if let Ok(json) = serde_json::to_vec(&cfg) {
                    let _ = tokio::fs::write(&sidecar, json).await;
                }
                cfg
            }
            Err(_) => boatramp_firecracker::oci::ImageConfig::default(),
        }
    }
}

/// Merge an image config's `KEY=VALUE` environment (the base — notably `PATH`) with the
/// caller's `(KEY, VALUE)` overrides applied on top: an override REPLACES the same-key
/// image entry, a new key is appended. Mirrors `oci::effective_env` over the backend's
/// pair shape. The caller's connection vars (`PG*`/`MYSQL*`) thus win, while the image
/// supplies the `PATH` the client binaries live on. A malformed image entry (no `=`) is
/// skipped.
fn merge_env(image_env: &[String], overrides: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = image_env
        .iter()
        .filter_map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    for (k, v) in overrides {
        match out.iter_mut().find(|(ek, _)| ek == k) {
            Some(slot) => slot.1 = v.clone(),
            None => out.push((k.clone(), v.clone())),
        }
    }
    out
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

    async fn materialize(
        &self,
        project: &str,
        workload: &str,
        spec: &ComputeSpec,
        pull_auth: Option<&RegistryAuth>,
    ) -> Result<Artifact, BackendError> {
        // The native container backend pulls an OCI image over its OWN daemonless registry
        // HTTP client, which does not yet carry registry credentials. Rather than silently
        // pull a private image anonymously (and fail opaquely, or — worse — succeed against a
        // same-named public image), FAIL CLOSED when a credential was resolved for an image
        // source: a private image must run on the `docker` backend until the daemonless
        // puller learns auth (a documented follow-up). A public image (`pull_auth == None`)
        // is unaffected; a non-image source never carries auth.
        if pull_auth.is_some() && matches!(spec.root, RootSource::Image(_)) {
            return Err(BackendError::Materialize(
                "the native container backend cannot apply a registry credential; \
                 run this private-image workload on the `docker` backend"
                    .into(),
            ));
        }
        // Key this workload's persistent volumes by the collision-free `(project, workload)`
        // scope (the SAME identity the container id/cgroup/veth use) so two co-located managed
        // DBs never share a host directory. Migrate any reused volume from the legacy flat
        // layout into the scoped layout FIRST — before the derive below reads the scoped dir —
        // so the rootfs base, the userns map, and the volume all agree on the migrated data.
        let scope = compute_volume_scope(project, workload);
        self.adopt_legacy_volumes(project, workload, &scope, spec)
            .await?;
        // Two rootfs sources produce a directory the worker `pivot_root`s into:
        // a **tar** blob from the shared store (staged + unpacked), or an **OCI
        // image** reference (pulled over the registry HTTP API + its layers
        // overlaid — no Docker daemon). A `Rootfs` block image is the micro-VM's.
        // Stage a probe rootfs at the CONFIGURED base first: it is the default rootfs AND the
        // source we read the image's DB runtime uid from (`/etc/passwd`), which the mapping
        // derive needs (and whose content is identical across ownership-shift bases).
        let probe = self.stage_rootfs_source(spec, self.userns_base).await?;
        // Resolve the workload's userns mapping ONCE here (threaded to launch via the staged
        // rootfs's `.b<base>` path, which `launch_inner` re-asserts): the configured base
        // normally, but a per-launch base DERIVED from a REUSED volume's own owner so the rootfs,
        // the userns map, and the volume all agree and the reused data is read as-is (no chown).
        let mapping = self.resolve_volume_mapping(&scope, spec, &probe).await?;
        let dir = if mapping.base == self.userns_base {
            probe
        } else {
            self.stage_rootfs_source(spec, mapping.base).await?
        };
        Ok(Artifact::Rootfs {
            dir: dir.display().to_string(),
        })
    }

    /// Adopt the endpoint IPs of already-known replicas at startup so this
    /// fresh-on-boot pool reflects addresses already in use before it allocates any
    /// new one — closing the container-IP collision — and remember each replica's
    /// address so a relaunch reclaims the same endpoint (stable). Only the IPs in
    /// this backend's subnet are reserved (the rest are skipped by
    /// `IpPool::reserve_in_use`).
    async fn reserve_in_use(&self, replicas: &[(String, String, u32, Ipv4Addr)]) {
        self.ipam.lock().expect("ipam mutex").adopt(replicas);
    }

    /// Reclaim pool addresses whose container is actually gone (A2). Snapshots the
    /// `(project,workload,replica)` keys this backend still holds an IP for, keeps every
    /// **parked** (`Zero`) key untouched, probes the cgroup for the rest (a live
    /// container has a `/sys/fs/cgroup/boatramp/<id>` directory with a non-empty
    /// `cgroup.procs`), and releases the address of any key with no live container. The
    /// decision is the pure, host-tested [`gc_reclaim_keys`]; only the cgroup probe is
    /// the Linux seam. Runs entirely under the ipam mutex snapshot + a cheap fs stat, so
    /// it never blocks a launch for long.
    async fn gc_ip_pool(&self, parked: &[(String, String, u32)]) {
        let tracked = self.ipam.lock().expect("ipam mutex").assigned_keys();
        if tracked.is_empty() {
            return;
        }
        let parked: std::collections::BTreeSet<(String, String, u32)> =
            parked.iter().cloned().collect();
        let reclaim = gc_reclaim_keys(&tracked, &parked, |k| {
            container_cgroup_alive(&container_id(&k.0, &k.1, k.2))
        });
        if reclaim.is_empty() {
            return;
        }
        let mut ipam = self.ipam.lock().expect("ipam mutex");
        for key in reclaim {
            if let Some(ip) = ipam.gc_release(&key) {
                tracing::warn!(
                    project = %key.0,
                    workload = %key.1,
                    replica = key.2,
                    ip = %ip,
                    "compute IPAM GC: reclaimed a stale-reserved address — no live container \
                     and the replica is not parked (its container is gone)"
                );
            }
        }
    }

    async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
        let rootfs = match &req.artifact {
            Artifact::Rootfs { dir } => dir.clone(),
            _ => {
                return Err(BackendError::Launch(
                    "container backend requires a Rootfs artifact".into(),
                ));
            }
        };
        let id = container_id(&req.project, &req.workload, req.replica);
        // Allocate a **stable + node-unique** IP: reclaim this replica's own recorded
        // address across a relaunch, else a fresh one that can't collide with any live
        // replica (adopted at startup — see `reserve_in_use`). Keyed by project so two
        // projects' same-named workloads never share a slot. Under the mutex, so
        // concurrent launches each commit a distinct address.
        let ip = {
            let mut ipam = self.ipam.lock().expect("ipam mutex");
            ipam.launch(&req.project, &req.workload, req.replica)?
        };

        // Run the launch, releasing the IP + tearing down on any failure.
        match self.launch_inner(req, &id, &rootfs, ip).await {
            Ok(instance) => Ok(instance),
            Err(e) => {
                let veth = VethNetwork::for_vm(&id, &self.bridge);
                let _ = veth.teardown().await;
                self.ipam.lock().expect("ipam mutex").launch_failed(
                    &req.project,
                    &req.workload,
                    req.replica,
                    ip,
                );
                Err(e)
            }
        }
    }

    async fn stop(&self, handle: &InstanceHandle) -> Result<(), BackendError> {
        let id = container_id(&handle.project, &handle.workload, handle.replica);
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
        // Release the replica's IP — but only if no other live replica still holds
        // it (the last-user rule, so tearing down one side of a stale collision can't
        // free the surviving replica's address). Forgets the ownership record.
        self.ipam.lock().expect("ipam mutex").stop(
            &handle.project,
            &handle.workload,
            handle.replica,
            &handle.backend_ref,
        );
        Ok(())
    }

    async fn health(&self, handle: &InstanceHandle) -> Result<Health, BackendError> {
        let addr = &handle.backend_ref; // "ip:port"
        let connect = tokio::net::TcpStream::connect(addr.as_str());
        match tokio::time::timeout(Duration::from_secs(2), connect).await {
            Ok(Ok(_)) => Ok(Health::Healthy),
            // Surface WHY the readiness probe failed — the raw connect error
            // (EHOSTUNREACH vs ECONNREFUSED vs …) is the fly-guest reachability
            // discriminator. Without this the failure reason was swallowed and every
            // `SELECT` only saw "no healthy replica".
            Ok(Err(e)) => {
                tracing::warn!(
                    addr = %addr,
                    error = %e,
                    "compute health: TCP connect to the container failed"
                );
                Ok(Health::Unhealthy)
            }
            Err(_) => {
                tracing::warn!(
                    addr = %addr,
                    timeout_secs = 2,
                    "compute health: TCP connect to the container timed out"
                );
                Ok(Health::Unknown)
            }
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
        let id = container_id(&handle.project, &handle.workload, handle.replica);
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
            project: handle.project.clone(),
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
        let id = container_id(&snapshot.project, &snapshot.workload, snapshot.replica);

        // Re-reserve the IP (recording ownership for this replica) and recreate the
        // host veth (the peer lands in the restored netns via the action-script below).
        self.ipam.lock().expect("ipam mutex").reserve_for(
            &snapshot.project,
            &snapshot.workload,
            snapshot.replica,
            addr,
        );
        let veth = VethNetwork::for_vm(&id, &self.bridge);
        if let Err(e) = veth.host_setup().await {
            self.ipam.lock().expect("ipam mutex").stop(
                &snapshot.project,
                &snapshot.workload,
                snapshot.replica,
                &format!("{addr}:{port}"),
            );
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
                self.ipam.lock().expect("ipam mutex").stop(
                    &snapshot.project,
                    &snapshot.workload,
                    snapshot.replica,
                    &format!("{addr}:{port}"),
                );
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
            self.ipam.lock().expect("ipam mutex").stop(
                &snapshot.project,
                &snapshot.workload,
                snapshot.replica,
                &format!("{addr}:{port}"),
            );
            return Err(BackendError::Launch(format!("restore netns setup: {e}")));
        }

        Ok(Instance {
            handle: InstanceHandle {
                project: snapshot.project.clone(),
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

    /// **Exec** (docker-exec style): run `argv` inside the already-running
    /// container for `handle`, feeding `stdin` and buffering stdout/stderr + the
    /// exit code. Resolves the container's pid1 from its cgroup
    /// (`/sys/fs/cgroup/boatramp/<id>/cgroup.procs` → [`crate::criu::find_pid1`]),
    /// then joins its namespaces (user first, then the rest; a `fork` after the pid
    /// ns so the command is pid-in-namespace) and `execvp`s — reusing the launch
    /// path's `setns` machinery rather than shelling out to `nsenter`. The blocking
    /// `fork`/pipe work runs on a blocking thread. See [`crate::exec`].
    async fn exec(
        &self,
        handle: &InstanceHandle,
        argv: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<ExecOutput, BackendError> {
        let id = container_id(&handle.project, &handle.workload, handle.replica);
        let argv = argv.to_vec();
        let stdin = stdin.map(<[u8]>::to_vec);
        tokio::task::spawn_blocking(move || {
            crate::exec::exec_in_container(&id, &argv, stdin.as_deref())
        })
        .await
        .map_err(|e| BackendError::Other(format!("exec: join: {e}")))?
    }

    /// Run a **one-shot ephemeral client container** from `image` (no persisted
    /// workload, no replica identity) — the native-backend engine for project
    /// export/import. Resolves the client image to a rootfs (an on-demand OCI pull by
    /// default; a preloaded air-gap rootfs when `image` is in
    /// [`client_image_rootfs`](Self::client_image_rootfs)), launches a **hardened
    /// one-shot** jail on it running `argv` with `env` and veth egress to reach the
    /// database, **streams** `stdin` in and stdout out (never buffering — a multi-GB
    /// `pg_dump`/`pg_restore` flows with bounded memory), captures the exit code
    /// (non-zero is a legitimate code, returned as `Ok(code)`), and tears the container
    /// down on every path. See the trait contract on
    /// [`ComputeBackend::run_ephemeral`](boatramp_core::compute::ComputeBackend::run_ephemeral).
    async fn run_ephemeral(
        &self,
        image: &str,
        argv: &[String],
        env: &[(String, String)],
        stdin: Option<&mut (dyn futures::io::AsyncRead + Send + Unpin)>,
        stdout: &mut (dyn futures::io::AsyncWrite + Send + Unpin),
    ) -> Result<i32, BackendError> {
        if argv.is_empty() {
            return Err(BackendError::Other("run_ephemeral: empty argv".into()));
        }
        // Resolve the client image to an unpacked rootfs (air-gap map, else OCI pull).
        let rootfs = self.resolve_client_rootfs(image).await?;
        let rootfs = rootfs.display().to_string();

        // Seed the client's environment + cwd from the pulled image's OCI config so a bare
        // `pg_dump`/`pg_restore`/`psql`/`mysql*` (no absolute path) resolves against the
        // image's own `PATH` (e.g. `/usr/lib/postgresql/16/bin` on `pgvector/pgvector`)
        // instead of failing with `127`. The caller's env (the PG*/MYSQL* connection vars)
        // is overlaid on top and WINS on any key conflict; the worker's `execvpe` performs
        // the actual `PATH` search. A default (empty) config leaves behavior as before.
        let image_cfg = self.client_image_config(image).await;
        let merged_env = merge_env(&image_cfg.env, env);

        // A unique id (cgroup / veth / hostname / log stem) + a transient IP drawn from
        // the SAME shared pool as every replica, so it can't collide with a live workload.
        let id = ephemeral_container_id();
        let ip = self.ipam.lock().expect("ipam mutex").allocate_ephemeral()?;

        // Run the one-shot; GUARANTEE teardown (veth + cgroup + IP) on every path — a
        // leaked ephemeral container (or a wedged run against an unreachable DSN) must
        // never hold a veth, a cgroup, or a pool address.
        let outcome = self
            .run_ephemeral_inner(
                &id,
                &rootfs,
                ip,
                image,
                argv,
                &merged_env,
                &image_cfg.workdir,
                stdin,
                stdout,
            )
            .await;
        self.ephemeral_teardown(&id, ip).await;
        outcome
    }

    /// List the persistent volumes this node backs: the directories under
    /// `<data_dir>/compute/volumes/`, each with its recursive on-disk size. Keyed
    /// by volume name (not VM), so this is the same directory `stage_volumes`
    /// creates + `volume_dir` addresses. A missing volumes dir (nothing ever
    /// staged) is simply an empty list, not an error.
    async fn list_volumes(&self) -> Result<Vec<VolumeInfo>, BackendError> {
        let root = self.volumes_dir();
        let mut dir = match tokio::fs::read_dir(&root).await {
            Ok(d) => d,
            // No volumes dir yet ⇒ nothing staged ⇒ empty list.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(BackendError::Other(format!(
                    "read volumes dir {}: {e}",
                    root.display()
                )));
            }
        };
        let mut out = Vec::new();
        while let Some(entry) = dir
            .next_entry()
            .await
            .map_err(|e| BackendError::Other(format!("scan volumes dir: {e}")))?
        {
            // Only directories are volumes; a stray file is ignored.
            let ft = entry
                .file_type()
                .await
                .map_err(|e| BackendError::Other(format!("stat volume entry: {e}")))?;
            if !ft.is_dir() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue; // skip a non-UTF-8 name (never staged by us)
            };
            let path = entry.path();
            let size_bytes = tokio::task::spawn_blocking(move || dir_size_bytes(&path))
                .await
                .map_err(|e| BackendError::Other(format!("size join: {e}")))?;
            out.push(VolumeInfo { name, size_bytes });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Remove the backing directory for persistent volume `name`
    /// (`<data_dir>/compute/volumes/<name>`), returning whether it existed. Reuses
    /// [`validate_volume`] so `name` can't traverse out of the volumes root. The
    /// caller (the node volume capability) is responsible for the "still in use"
    /// refusal; this is the raw on-disk removal.
    async fn remove_volume(&self, name: &str) -> Result<bool, BackendError> {
        // Reject a traversing / multi-component name before touching the fs (a
        // fixed mount is fine — only `name` is load-bearing here).
        validate_volume(name, "/")?;
        let dir = self.volume_dir(name);
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(BackendError::Other(format!(
                "remove volume {} dir: {e}",
                dir.display()
            ))),
        }
    }

    /// See [`ComputeBackend::data_dir_ownership`]. Scan each of the spec's volume backing
    /// directories for entries not owned by the guest process's mapped host uid:gid
    /// (`userns_base + guest_uid/gid` — the same target `stage_volumes` pre-chowns to) and
    /// report the first volume carrying a foreign-owned file, with a sample; otherwise
    /// report the last clean scan so `db status` can state the data directory is NOT the
    /// cause. READ-ONLY (no chown). `None` when the spec declares no volumes, or when
    /// ownership-shifting is unavailable on this node (unprivileged — the uids aren't
    /// shifted, so an owner mismatch isn't meaningful), or when a volume's backing
    /// directory can't be scanned (not yet created / vanished — not a fault we can assert).
    async fn data_dir_ownership(
        &self,
        project: &str,
        workload: &str,
        spec: &ComputeSpec,
    ) -> Option<DataDirOwnership> {
        if spec.volumes.is_empty() || !can_shift_ownership() {
            return None;
        }
        let (guest_uid, guest_gid) = spec_uid_gid(spec);
        // A read-only health sample against the configured mapped owner. With the reused-volume
        // repair ([`Self::resolve_volume_mapping`]) a mismatched reused volume is instead served
        // by a derived base (read as-is) or fails closed at launch, so this diagnostic — only
        // consulted when a replica is stuck up-but-not-answering — is a best-effort sample for an
        // operator, not an authoritative mapping (it does not re-derive, which would need the
        // staged rootfs to detect the runtime uid).
        let host_uid = self.userns_base + guest_uid;
        let host_gid = self.userns_base + guest_gid;
        // Scan the per-(project, workload) SCOPED backing dir — the one the launch actually
        // mounts — not the legacy flat path.
        let scope = compute_volume_scope(project, workload);
        let mut clean: Option<DataDirOwnership> = None;
        for vol in &spec.volumes {
            // Validate the name before building a path from it (consistent with the adopt/stage
            // choke points) — this read-only diagnostic must not scan outside the scope dir.
            if validate_spec_volume(&vol.name, &vol.mount).is_err() {
                continue;
            }
            let dir = self.scoped_volume_dir(&scope, &vol.name);
            let name = vol.name.clone();
            // The walk is blocking (a stat per entry); keep it off the reconcile's async
            // runtime. A scan error (dir not yet created / vanished mid-walk) ⇒ skip this
            // volume rather than reporting a phantom fault.
            let Ok(Ok(scan)) = tokio::task::spawn_blocking(move || {
                crate::data_dir::scan_data_dir_ownership(
                    &dir,
                    host_uid,
                    host_gid,
                    crate::data_dir::OWNERSHIP_SCAN_BUDGET,
                )
            })
            .await
            else {
                continue;
            };
            let obs = DataDirOwnership {
                volume: name,
                ok: scan.foreign == 0,
                expected_uid: host_uid,
                expected_gid: host_gid,
                foreign_count: scan.foreign,
                sample: scan
                    .sample
                    .map(|(path, uid, gid)| ForeignOwnedEntry { path, uid, gid }),
            };
            if !obs.ok {
                return Some(obs);
            }
            clean = Some(obs);
        }
        clean
    }

    /// Node-authorized BULK migration of managed-tenant legacy volume dirs into the scoped
    /// layout (F4). `authorized` carries `(project, workload, volume_name)` triples the NODE
    /// derived from its OWN trusted control-plane state (registered managed workloads gated by a
    /// node-minted sealed credential, plus the node-trusted legacy-`data` claimant) — NEVER from
    /// a workload spec. For each triple whose legacy flat dir exists and whose scoped dir does
    /// not, it performs the SAME atomic, refuse-on-exist rename as the launch-time adoption
    /// ([`Self::adopt_one_legacy_volume`]): bytes + ownership preserved, read-as-is; never a
    /// copy/chown/merge/delete. This proactively prevents the launch-time fail-closed for
    /// node-provisioned managed tenants (whose node-global legacy dirs the launch path cannot
    /// adopt from an untrusted spec). Each name + scope is validated before a path is built, so a
    /// malformed/forged triple can neither traverse nor alias a scope dir. Idempotent (an
    /// already-scoped dir is skipped); a per-triple failure (e.g. refuse-on-exist race) is logged
    /// and skipped so one bad triple can't block the rest — the launch-time path is the backstop.
    async fn migrate_legacy_volumes(&self, authorized: &[(String, String, String)]) -> usize {
        let mut migrated = 0usize;
        for (project, workload, vol_name) in authorized {
            // Validate the volume name (traversal + reserved-`@`-prefix) and the derived scope
            // BEFORE building any path — defense in depth, even though these are node-derived.
            // The mount is irrelevant to a migration, so a benign absolute placeholder is used.
            if validate_spec_volume(vol_name, "/").is_err() {
                continue;
            }
            let scope = compute_volume_scope(project, workload);
            if validate_volume_scope(&scope).is_err() {
                continue;
            }
            let scoped = self.scoped_volume_dir(&scope, vol_name);
            // Already in the scoped layout (migrated earlier, or launch-time created): nothing to do.
            if tokio::fs::try_exists(&scoped).await.unwrap_or(false) {
                continue;
            }
            let legacy = self.volume_dir(vol_name);
            // Nothing to carry over (absent/empty legacy dir): the workload will create its scoped
            // dir fresh at launch.
            if !dir_has_entries(&legacy).await {
                continue;
            }
            match self
                .adopt_one_legacy_volume(&legacy, &scoped, project, workload, vol_name)
                .await
            {
                Ok(()) => migrated += 1,
                Err(e) => tracing::warn!(
                    target: "boatramp::repair",
                    project,
                    workload,
                    volume = vol_name.as_str(),
                    error = %e,
                    "F4 bulk migration skipped this volume (the launch-time adoption is the \
                     backstop); likely a concurrent migration or a pre-existing destination"
                ),
            }
        }
        if migrated > 0 {
            tracing::info!(
                target: "boatramp::repair",
                migrated,
                "F4: migrated managed-tenant legacy volume dirs into the per-(project,workload) \
                 scoped layout (atomic rename; data + ownership preserved)"
            );
        }
        migrated
    }
}

impl ContainerBackend {
    /// Root for per-container guest-log files (`<data_dir>/compute/logs`).
    fn logs_dir(&self) -> PathBuf {
        self.data_dir.join("compute").join("logs")
    }

    /// The root holding every persistent volume's backing directory
    /// (`<data_dir>/compute/volumes/`).
    fn volumes_dir(&self) -> PathBuf {
        self.data_dir.join("compute").join("volumes")
    }

    /// The host backing directory for persistent volume `name`
    /// (`<data_dir>/compute/volumes/<name>`) — the **legacy, pre-v0.46 flat layout**
    /// keyed by volume name alone. Retained for the operator volume-reclamation surface
    /// (`list_volumes`/`remove_volume`, which address a backing dir by its on-disk name)
    /// and as the MIGRATION SOURCE: a reused volume written under the flat layout is
    /// adopted into the per-`(project, workload)` scoped layout on first launch (see
    /// [`Self::scoped_volume_dir`] / [`Self::adopt_legacy_volume_if_claimed`]). This flat
    /// keying is exactly the cross-tenant collision the scoped layout closes — two
    /// co-located workloads naming a volume identically (`"data"`) shared one directory —
    /// so it is NEVER used to stage a launch anymore.
    fn volume_dir(&self, name: &str) -> PathBuf {
        self.volumes_dir().join(name)
    }

    /// The host backing directory for persistent volume `name` of the workload scoped by
    /// `scope` (= [`compute_volume_scope`]`(project, workload)`):
    /// `<data_dir>/compute/volumes/@<scope>/<name>`. Nesting the volume under the
    /// `(project, workload)` scope — the SAME identity the container id / cgroup / veth / IP
    /// use ([`compute_instance_id`]) — is what gives two co-located managed databases (each
    /// handed the bare volume name `"data"`) their own PGDATA on disk, closing the
    /// cross-tenant collision (fail-closed DoS / fail-open disclosure / two postmasters on
    /// one cluster → corruption).
    ///
    /// The scope SEGMENT is prefixed with `@` ([`SCOPE_DIR_PREFIX`]) — a byte that never
    /// appears in a resource-slug / `sanitize_ident` volume or workload name
    /// (`[A-Za-z0-9_-]`) — so a scope DIRECTORY (`@<scope>`) can never coincide with a LEGACY
    /// FLAT volume dir (`<name>`, the pre-v0.46 migration source) living in the same
    /// `volumes/` root. Without it, a workload whose scope string equalled some other
    /// workload's flat volume name would nest INTO that volume's data dir (data relocation /
    /// corruption on a later adoption). `scope` is a single, filesystem-safe path component
    /// (validated by [`validate_volume_scope`]), so the nested path has no `..`/`.`/absolute
    /// escape.
    fn scoped_volume_dir(&self, scope: &str, name: &str) -> PathBuf {
        self.volumes_dir()
            .join(format!("{SCOPE_DIR_PREFIX}{scope}"))
            .join(name)
    }

    /// One-time, idempotent **migration** of a workload's persistent volumes from the
    /// legacy flat layout (`<volumes>/<name>`, keyed by volume name alone) into the
    /// per-`(project, workload)` scoped layout (`<volumes>/<scope>/<name>`). Run at the
    /// START of both [`materialize`](ComputeBackend::materialize) and `launch_inner`, before
    /// the userns-base derive reads the scoped dir, so the rootfs/map/volume all agree on the
    /// migrated data end-to-end. Safe to call repeatedly: once the scoped dir exists it is a
    /// no-op.
    ///
    /// Each volume's name + mount is validated FIRST ([`validate_spec_volume`]) so no `".."` or
    /// `@<scope>` name can build a path that escapes `<volumes>/` or aliases another workload's
    /// scope dir. Then, for each volume whose scoped dir does NOT yet exist but whose legacy
    /// flat dir holds data:
    /// * **the contended shared `"data"` volume** (the literal name EVERY managed DB is handed)
    ///   — adopted ONLY by the one `(project, workload)` the NODE proved is its owner
    ///   ([`legacy_data_claimant`](Self::legacy_data_claimant) — TRUSTED, derived from the node's
    ///   own `databases` config, NEVER from this spec). A non-owner (generic or managed) that
    ///   finds a non-empty legacy `data` dir **fails closed**; an ambiguous owner (`None`) fails
    ///   every contender closed until an operator designates one. The data is left byte-for-byte
    ///   in place.
    /// * **ANY other (non-`"data"`) legacy flat dir** — NEVER auto-adopted from a workload spec.
    ///   The backend cannot prove, from an UNTRUSTED spec, that this workload owns a node-global
    ///   legacy dir: every in-spec signal — `vol.name` AND `db_user_for_spec`'s PGDATA-env /
    ///   `postgres`-entrypoint markers — is attacker-FORGEABLE, so none may decide this tenancy
    ///   boundary (a crafted DB-shaped spec could otherwise set `vol.name` to a victim tenant's
    ///   digest-unique legacy dir and rename-steal it). It fails closed on ANY existing legacy
    ///   flat dir (an empty/absent one just creates the scoped dir fresh). A node-provisioned
    ///   managed `Single` tenant's legacy dir is migrated by an explicit operator pre-stage (or a
    ///   node-side bulk migration — tracked follow-up), never by spec-driven adoption.
    ///
    /// Adoption is an **atomic, refuse-on-exist rename** — never a copy, chown, merge, or
    /// delete: the data dir keeps its exact bytes AND its existing owner, so the derive-base
    /// repair still reads it as-is (no re-chown of a neighbor's data into a new uid range). If
    /// the destination already exists the rename ABORTS (never overlays two clusters into one).
    async fn adopt_legacy_volumes(
        &self,
        project: &str,
        workload: &str,
        scope: &str,
        spec: &ComputeSpec,
    ) -> Result<(), BackendError> {
        // Validate the scope as a single safe path component BEFORE any filesystem op below
        // builds a `<volumes>/@<scope>/…` path (defense in depth; `scope` is already derived
        // from slug-validated project/workload names).
        validate_volume_scope(scope)?;
        for vol in &spec.volumes {
            // Validate the volume NAME + mount BEFORE constructing ANY path from it — the
            // on-disk `vol.name` is otherwise unconstrained, so an unvalidated `".."` would
            // escape `<volumes>/` and an `@<victimscope>` name would alias another workload's
            // scope dir (the rename would then STEAL the victim's whole scope). This runs ahead
            // of the `volume_dir`/`scoped_volume_dir` construction below.
            validate_spec_volume(&vol.name, &vol.mount)?;
            let scoped = self.scoped_volume_dir(scope, &vol.name);
            // Already in the scoped layout (migrated earlier, or fresh-created by a prior
            // launch): nothing to adopt.
            if tokio::fs::try_exists(&scoped).await.unwrap_or(false) {
                continue;
            }
            let legacy = self.volume_dir(&vol.name);
            // No legacy data to carry over ⇒ a fresh volume; `stage_volumes` creates the
            // scoped dir. A legacy dir that exists but holds nothing is likewise treated as
            // fresh (we never adopt an empty shell, so a stray empty `data` can't block).
            if !dir_has_entries(&legacy).await {
                continue;
            }
            if vol.name != LEGACY_SHARED_VOLUME_NAME {
                // ANY non-`"data"` legacy flat dir is NEVER auto-adopted from this spec. The
                // backend cannot prove, from an UNTRUSTED spec, that this workload owns a
                // node-global legacy dir: the only in-spec signals (`vol.name`, and
                // `db_user_for_spec`'s PGDATA-env / `postgres`-entrypoint markers) are all
                // attacker-FORGEABLE, so none may decide this tenancy boundary. Otherwise a
                // crafted DB-shaped spec could set `vol.name` to a victim tenant's digest-unique
                // legacy dir (a deterministic public function of the victim's project) and rename
                // (steal) it — cross-tenant disclosure at rest + the owner's data orphaned. Fail
                // closed. A node-provisioned managed `Single` tenant's legacy dir is migrated by
                // an explicit operator pre-stage (or a node-side bulk migration — tracked
                // follow-up), never by spec-driven adoption. (`validate_spec_volume` above already
                // rejected a traversing / reserved-`@` name, so `scoped`/`legacy` are safe paths.)
                return Err(BackendError::Launch(format!(
                    "refusing to launch {project}/{workload}: a non-empty LEGACY volume exists at \
                     {} but boatramp will not adopt a non-`data` legacy directory from a workload \
                     spec — it cannot prove, from an untrusted spec, that this workload owns that \
                     node-global directory (its name could be another tenant's), and guessing \
                     could hand one tenant's data to another. Your data is left untouched. \
                     Remedy: if this workload truly owns the directory, pre-stage it by moving {} \
                     to {} before launch; otherwise remove the stale directory.",
                    legacy.display(),
                    legacy.display(),
                    scoped.display()
                )));
            }
            // The contended shared `"data"` dir (the literal name EVERY managed DB is handed):
            // adopt ONLY if the NODE proved this `(project, workload)` is its sole owner
            // (`legacy_data_claimant` — TRUSTED, derived from the node's own `databases` config,
            // never from this spec). A GENERIC workload running arbitrary tenant code is never the
            // claimant, so it can never rename the legacy MANAGED cluster (e.g. the control-plane
            // DB) into its own scope. A non-claimant fails closed; the owner is designated via
            // `adopt_legacy_data_volume` (or pre-stages manually).
            let is_claimant = self
                .legacy_data_claimant
                .as_ref()
                .is_some_and(|(p, w)| p == project && w == workload);
            if !is_claimant {
                return Err(BackendError::Launch(format!(
                    "refusing to launch {project}/{workload}: a non-empty LEGACY shared volume \
                     exists at {} but this workload is not its proven owner. Two or more \
                     co-located workloads shared that directory before per-workload volume \
                     isolation, so boatramp will not guess which one initialized the cluster \
                     (guessing would hand one tenant's data to another). Your data is left \
                     untouched. Remedy: set `adopt_legacy_data_volume = true` on the ONE \
                     `databases` binding that owns this cluster and redeploy. For a workload with \
                     no `databases` binding to designate, pre-stage it manually by moving {} to {} \
                     before launch; or remove the stale directory if it holds no wanted data.",
                    legacy.display(),
                    legacy.display(),
                    scoped.display()
                )));
            }
            self.adopt_one_legacy_volume(&legacy, &scoped, project, workload, &vol.name)
                .await?;
        }
        Ok(())
    }

    /// Adopt a single legacy flat volume dir into its scoped location by an **atomic,
    /// refuse-on-exist rename**. Creates the scope parent, ABORTS if the destination already
    /// exists (never merges two clusters), then renames — preserving the data's exact bytes
    /// and owner (no copy/chown), so the derive-base repair reads it as-is.
    async fn adopt_one_legacy_volume(
        &self,
        legacy: &Path,
        scoped: &Path,
        project: &str,
        workload: &str,
        name: &str,
    ) -> Result<(), BackendError> {
        if let Some(parent) = scoped.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                BackendError::Launch(format!("create volume scope dir {}: {e}", parent.display()))
            })?;
        }
        // Refuse-on-exist: a destination that already exists must never be overlaid/merged
        // (that would fuse two clusters). The common idempotent case — the scoped dir already
        // present — is handled by the caller's pre-check; reaching here with it present means a
        // concurrent relaunch won the race, so fail closed and let the next reconcile tick (which
        // will find the scoped dir and skip) proceed.
        if tokio::fs::try_exists(scoped).await.unwrap_or(false) {
            return Err(BackendError::Launch(format!(
                "refusing to adopt legacy volume {name:?} for {project}/{workload}: destination \
                 {} already exists (a concurrent launch migrated it); not overlaying two data \
                 directories. Retry.",
                scoped.display()
            )));
        }
        tokio::fs::rename(legacy, scoped).await.map_err(|e| {
            BackendError::Launch(format!(
                "adopt legacy volume {name:?} for {project}/{workload}: rename {} -> {}: {e}",
                legacy.display(),
                scoped.display()
            ))
        })?;
        tracing::info!(
            target: "boatramp::repair",
            project,
            workload,
            volume = name,
            from = %legacy.display(),
            to = %scoped.display(),
            "migrated a managed-database volume from the legacy flat layout to the per-(project,\
             workload) scoped layout (atomic rename; data + ownership preserved, read as-is)"
        );
        Ok(())
    }

    /// Ensure each of the spec's persistent volumes has a backing directory and
    /// map it to the in-guest mount point the worker binds in (before
    /// `pivot_root`). The bind is a plain directory, so `size_mib` is advisory
    /// here (block-device size enforcement is the VMM volume path); the data
    /// persists across restarts because it lives outside the ephemeral rootfs.
    async fn stage_volumes(
        &self,
        scope: &str,
        spec: &ComputeSpec,
        mapping: &ResolvedMapping,
    ) -> Result<Vec<VolumeMount>, BackendError> {
        // A dir owned outside the container's user-namespace map range is `nobody` inside, so the
        // workload can't read it — EPERM (`global/pg_filenode.map: Permission denied`).
        //
        // Each `mapping.chowns[i]` (decided by `resolve_mapping_decision`, PER volume) says
        // whether we touch that volume's ownership:
        //  * None — a REUSED volume read AS-IS: `base` was DERIVED from the volume's own existing
        //    owner so the data already maps onto the workload's runtime uid. We DO NOT chown; the
        //    user's data dir is left byte-for-byte unchanged (data-preserving + idempotent).
        //  * Some((uid, gid)) — a FRESH dir (needs an owned dir to init into) or an in-place
        //    REMAP of host-owned data the mapping can't express. `chown_tree_to` relabels to that
        //    host `(uid, gid)`, SKIPPING entries already correct (never a reinit — only ownership
        //    changes, never content). A remap is only ever reached as host root.
        //
        // The backing dir is the per-`(project, workload)` SCOPED dir
        // (`<volumes>/<scope>/<name>`), never the legacy flat `<volumes>/<name>` — any reused
        // flat data was already migrated into the scoped layout by `adopt_legacy_volumes`
        // before this point.
        validate_volume_scope(scope)?;
        let mut mounts = Vec::with_capacity(spec.volumes.len());
        for (i, vol) in spec.volumes.iter().enumerate() {
            // Validate name + mount + the reserved `@` prefix before building any path (the
            // same choke point the migration uses — see [`validate_spec_volume`]).
            validate_spec_volume(&vol.name, &vol.mount)?;
            let dir = self.scoped_volume_dir(scope, &vol.name);
            tokio::fs::create_dir_all(&dir).await.map_err(|e| {
                BackendError::Launch(format!("create volume {} dir: {e}", vol.name))
            })?;
            if let Some(Some((host_uid, host_gid))) = mapping.chowns.get(i).copied() {
                chown_tree_to(&dir, host_uid, host_gid).map_err(|e| {
                    BackendError::Launch(format!(
                        "chown volume {} to {host_uid}:{host_gid}: {e}",
                        vol.name
                    ))
                })?;
            }
            mounts.push(VolumeMount {
                source: dir.display().to_string(),
                mount: vol.mount.clone(),
            });
        }
        Ok(mounts)
    }

    /// Stage this spec's rootfs source (tar blob or OCI image) ownership-shifted for `base`.
    async fn stage_rootfs_source(
        &self,
        spec: &ComputeSpec,
        base: u32,
    ) -> Result<PathBuf, BackendError> {
        match &spec.root {
            RootSource::Tar(hash) => self.stage_rootfs(hash, base).await,
            RootSource::Image(image) => self.stage_image(image, base).await,
            RootSource::Rootfs(_) => Err(BackendError::Materialize(
                "container backend requires a tar rootfs archive or an OCI image reference \
                 (RootSource::Tar | RootSource::Image)"
                    .into(),
            )),
        }
    }

    /// Detect the managed database's RUNTIME (post-privilege-drop) `(uid, gid)` from the staged
    /// image's `/etc/passwd` — the id the DB process actually runs as, which the derive maps the
    /// data onto. ASSERTS the image's real id instead of assuming 999 or using the entrypoint/spec
    /// uid (which, for a root-entrypoint image, is 0 while the DB runs as e.g. `postgres`:999).
    /// `None` if the engine or user can't be resolved. `/etc/passwd` content is identical across
    /// ownership-shift bases, so any staged rootfs works.
    async fn db_runtime_ids(&self, rootfs_dir: &Path, spec: &ComputeSpec) -> Option<(u32, u32)> {
        let user = db_user_for_spec(spec)?;
        let passwd = tokio::fs::read_to_string(rootfs_dir.join("etc/passwd"))
            .await
            .ok()?;
        parse_passwd_ids(&passwd, user)
    }

    /// The `(uid, gid)` this workload's **init process** — the stock entrypoint the worker
    /// `execve`s — is launched as (the uid its `docker-entrypoint.sh` sees as `id -u`).
    ///
    /// For a managed database whose spec leaves `user` unset, that is the DB's DETECTED image
    /// RUNTIME uid ([`Self::db_runtime_ids`], e.g. postgres `999`) rather than the spec's
    /// namespace-root default (`0`). Launched as that uid, the stock postgres/mysql entrypoint
    /// takes its NON-root branch (`[ "$(id -u)" = '0' ]` is false): it SKIPS the root-only
    /// `chmod 700 $PGDATA` + `find … -exec chown` + `gosu`/`su-exec` privilege drop — the steps
    /// that need `CAP_CHOWN`/`CAP_FOWNER`/`CAP_DAC_OVERRIDE`/`CAP_SETUID`, which a cap-dropped
    /// multi-tenant node does not grant — and runs `initdb` + the server directly as that uid, on
    /// the volume already pre-owned `base + runtime` ([`resolve_mapping_decision`]). So a FRESH
    /// init works under the dropped-`ALL` posture (initdb as `999` on a `999`-owned dir, no
    /// capability needed) and a REUSED cluster still comes up (existing cluster detected →
    /// skip-init → exec as `999`); the path needs no capabilities, so it is identical on
    /// cap-dropped and non-cap-dropped nodes (posture-independent).
    ///
    /// An operator-set `user` always wins (mirrors
    /// [`PrivilegeDirective::apply`](boatramp_core::compute::PrivilegeDirective::apply) — the
    /// reconcile never clobbers an explicit `user`/`cap_add`). A non-DB workload, or a managed
    /// image whose runtime uid can't be read from `/etc/passwd`, keeps the spec's own
    /// `(uid, gid)`, so every non-managed launch is byte-for-byte unchanged.
    ///
    /// `rootfs_dir` is the SAME staged rootfs [`Self::resolve_volume_mapping`] reads the runtime
    /// uid + derives the volume mapping from, so the launch uid always equals the uid the data
    /// dir is owned as — the entrypoint owns its data dir with no chown.
    async fn init_process_ids(&self, spec: &ComputeSpec, rootfs_dir: &Path) -> (u32, u32) {
        let spec_ids = spec_uid_gid(spec);
        // An operator-set `user` is authoritative (and the fast path for any workload that
        // already pins its uid): never override it with the detected image uid.
        if spec.user.is_some() {
            return spec_ids;
        }
        // `db_runtime_ids` is `Some` only for a managed DB (gated on `db_user_for_spec`); `None`
        // (a non-DB workload, or a managed image whose `/etc/passwd` can't be read) keeps the
        // spec's own ids, leaving the launch unchanged.
        self.db_runtime_ids(rootfs_dir, spec)
            .await
            .unwrap_or(spec_ids)
    }

    /// Resolve the user-namespace mapping to launch this workload's container with, chosen so a
    /// REUSED persistent volume's data dir is read **as-is** without rewriting its ownership.
    ///
    /// # Reused-volume repair (the v0.45.0 managed-DB regression fix)
    /// v0.45.0's `stage_volumes` recursively chowns a reused volume to `userns_base + guest_uid`.
    /// On a rootless node a data dir written under a DIFFERENT mapping — a prior `userns_base`, a
    /// reused volume carried across a `fly machine update` — sits at a host owner OUTSIDE the
    /// container's map range (→ `nobody` inside): the stock image's root-path entrypoint
    /// `chown -R` then `EPERM`s on the unmappable data-root, and the DB (post-privilege-drop)
    /// can't read its own files (`global/pg_filenode.map: Permission denied`). Relaunching a
    /// previously-healthy DB regresses the same way.
    ///
    /// The data-preserving repair, made the **primary, always-on** strategy for a reused volume
    /// (host-root nodes too): DERIVE the per-launch base `D` so that `D + pg_uid` equals the data
    /// dir's EXISTING consistent owner, where `pg_uid` is the DB's RUNTIME uid detected from the
    /// image ([`Self::db_runtime_ids`]) — NOT the entrypoint/spec uid. Then the data maps onto
    /// the uid the DB runs as, so it is read with **NO chown** and **NO reinit**, left
    /// byte-for-byte unchanged (idempotent), and the entrypoint's own `chown -R` now operates on
    /// in-map files (a harmless no-op). The rootfs is staged + ownership-shifted for `D`
    /// ([`Self::materialize`]) and the userns map is written with `D` ([`Self::launch_inner`]),
    /// so the mapping, the rootfs, and the volume all agree.
    ///
    /// Scoped to this workload's OWN volume dirs — the per-`(project, workload)`
    /// `compute/volumes/<scope>/<name>`, never a sibling tenant's (two co-located managed DBs
    /// no longer share one `compute/volumes/data`). The pure decision + its fail-closed guards
    /// live in [`resolve_mapping_decision`]; this method is the I/O that feeds it (detect the
    /// runtime id + scan each volume's owner, budget-bounded).
    async fn resolve_volume_mapping(
        &self,
        scope: &str,
        spec: &ComputeSpec,
        rootfs_dir: &Path,
    ) -> Result<ResolvedMapping, BackendError> {
        let (guest_uid, guest_gid) = spec_uid_gid(spec);
        if spec.volumes.is_empty() {
            return Ok(ResolvedMapping {
                base: self.userns_base,
                chowns: Vec::new(),
            });
        }
        // The id the workload's process ends up running as, which a REUSED volume's data must map
        // onto. A managed DB's stock entrypoint drops to a fixed image user — detect THAT from
        // the image (refuse to guess if the image can't be read). Any OTHER workload runs AS its
        // spec `user` (= `guest_uid`), so that IS its runtime uid — which keeps the data-preserving
        // derive (read-as-is) working for non-DB stateful workloads too, instead of refusing.
        let runtime = if db_user_for_spec(spec).is_some() {
            self.db_runtime_ids(rootfs_dir, spec).await
        } else {
            Some((guest_uid, guest_gid))
        };
        let mut volumes = Vec::with_capacity(spec.volumes.len());
        for vol in &spec.volumes {
            // Validate the name + mount before building a path from it — keep the guard LOCAL to
            // this owner-scan, not dependent on `adopt_legacy_volumes` having run first (a future
            // caller that skips adopt must not scan from an unvalidated `..`/`@scope` name).
            validate_spec_volume(&vol.name, &vol.mount)?;
            let dir = self.scoped_volume_dir(scope, &vol.name);
            let name = vol.name.clone();
            let consensus = tokio::task::spawn_blocking(move || {
                crate::data_dir::scan_consistent_owner(
                    &dir,
                    crate::data_dir::CONSISTENT_OWNER_SCAN_BUDGET,
                )
            })
            .await
            .map_err(|e| BackendError::Launch(format!("scan volume {name} owner: {e}")))?
            .map_err(|e| BackendError::Launch(format!("scan volume {name} owner: {e}")))?;
            volumes.push((vol.name.clone(), consensus));
        }
        let mapping = resolve_mapping_decision(
            &volumes,
            guest_uid,
            guest_gid,
            runtime,
            self.userns_base == 0,
            self.userns_base,
            can_shift_ownership(),
        )?;
        // Surface the FULL per-volume mapping decision on the daemon's default subscriber. The
        // target MUST be under `boatramp::*` — the default `boatramp=info` filter (main.rs) matches
        // `boatramp::guest`/`boatramp::repair` but NOT the implicit `boatramp_container::backend`
        // module target, so an operator reading `fly logs` never saw the derive decision at all.
        // Logged unconditionally (every volume, every launch) so a chosen base == configured base
        // (fresh/remap) is as visible as a derived one — the field an operator needs to diagnose a
        // reused-volume mount failure without host-side `ls` (which a distroless, exec-disabled node
        // cannot run).
        for (idx, (name, consensus)) in volumes.iter().enumerate() {
            let chown = mapping.chowns.get(idx).copied().flatten();
            tracing::info!(
                target: "boatramp::repair",
                volume = name.as_str(),
                scope,
                scoped_path = %self.scoped_volume_dir(scope, name).display(),
                consensus = ?consensus,
                runtime_uid = runtime.map(|(u, _)| u),
                runtime_gid = runtime.map(|(_, g)| g),
                configured_base = self.userns_base,
                chosen_base = mapping.base,
                chown = ?chown,
                "reused-volume mapping decision: scoped_path is the per-(project,workload) backing \
                 dir (collision-free); chown=None ⇒ data read AS-IS (no chown/reinit); \
                 chosen_base != configured_base ⇒ the data dir's existing owner was mapped onto the \
                 runtime uid; chown=Some ⇒ a fresh/remap volume chowned under the chosen base"
            );
        }
        Ok(mapping)
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
        // Launch the init process (the stock entrypoint) as the uid it should RUN as. For a
        // managed DB with no operator-set `user` that is the image's DETECTED runtime uid (e.g.
        // postgres 999) — so the entrypoint takes its non-root path and inits/serves directly
        // without the capabilities a cap-dropped node withholds (see `init_process_ids`). A non-DB
        // workload keeps the spec's namespace-root default, so its launch is unchanged.
        let (uid, gid) = self.init_process_ids(&req.spec, Path::new(rootfs)).await;
        // The per-(project, workload) volume scope (the SAME identity as `id`/cgroup/veth).
        // Re-run the idempotent legacy-flat→scoped migration here too (a no-op once the scoped
        // dir exists) so a launch that did not route through this process's `materialize` still
        // adopts reused data before the derive reads it.
        let scope = compute_volume_scope(&req.project, &req.workload);
        self.adopt_legacy_volumes(&req.project, &req.workload, &scope, &req.spec)
            .await?;
        // The workload's resolved userns mapping, re-resolved from the SAME staged rootfs
        // `materialize` produced (its `.b<base>` path pins the base). Re-assert the two agree:
        // if a concurrent/overlapping relaunch changed the volume's owner between materialize and
        // now, the rootfs base and the freshly-derived base could diverge (rootfs shifted for one
        // base, map/volume for another → a boot failure). Fail closed + retry instead (LOW-1).
        let mapping = self
            .resolve_volume_mapping(&scope, &req.spec, Path::new(rootfs))
            .await?;
        if let Some(staged) = parse_rootfs_base(Path::new(rootfs))
            && staged != mapping.base
        {
            return Err(BackendError::Launch(format!(
                "user-namespace base diverged between materialize (rootfs staged for base \
                 {staged}) and launch (resolved {}): the volume's ownership changed under a \
                 concurrent relaunch. Refusing to boot a mismatched rootfs/mapping; retry.",
                mapping.base
            )));
        }
        let mut plan = SandboxPlan::for_spec(&req.spec, rootfs, id, uid, gid);
        plan.volumes = self.stage_volumes(&scope, &req.spec, &mapping).await?;
        // Point the guest at boatramp's internal DNS on the bridge gateway (when the
        // resolver is enabled), scoped to this container's project so a bare peer name
        // resolves within the tenant. Written per-container by the worker (the staged
        // rootfs is shared across projects). `None` ⇒ leave the image's resolv.conf.
        if let Some(domain) = &self.internal_dns_domain {
            plan.resolv_conf = Some(crate::resolvconf::render(
                self.gateway,
                &req.project,
                domain,
            ));
        }
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
            write_userns_maps(pid, mapping.base)
                .map_err(|e| BackendError::Launch(format!("write userns maps: {e}")))?;
        }

        // Move the veth peer into the worker's netns + configure eth0/lo there.
        veth.move_peer_into_netns(pid)
            .await
            .map_err(|e| BackendError::Launch(format!("move veth peer: {e}")))?;
        configure_in_netns(pid, &veth.peer_veth, ip, self.prefix, self.gateway)
            .map_err(|e| BackendError::Launch(format!("netns config: {e}")))?;

        // One-shot network-state dump (diagnostics): reveal the exact L2/L3 state and the
        // host→container reachability result right after the netns is configured, so a
        // reachability failure (e.g. EHOSTUNREACH on a fly guest) is diagnosable from the
        // boot logs. Gated by `BOATRAMP_COMPUTE_NET_DEBUG` (default ON for this rc); a
        // Linux-only best-effort that never fails the launch.
        let port = req.spec.port;
        net_debug_dump(&req.workload, pid, &self.bridge, &veth.host_veth, ip, port).await;

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

        Ok(Instance {
            handle: InstanceHandle {
                project: req.project.clone(),
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

    /// Resolve a [`run_ephemeral`](ComputeBackend::run_ephemeral) client `image` to an
    /// unpacked rootfs directory the worker can `pivot_root` into.
    ///
    /// Air-gap first: if `image` is in [`client_image_rootfs`](Self::client_image_rootfs),
    /// use the preloaded rootfs and DO NOT pull — an absolute path is an already-unpacked
    /// rootfs directory (used verbatim), anything else is a Storage blob hash of a rootfs
    /// tar staged exactly like a `RootSource::Tar` ([`stage_rootfs`](Self::stage_rootfs)).
    /// Otherwise the default: pull the OCI image + overlay its layers on demand
    /// ([`stage_image`](Self::stage_image), the same path `materialize` uses).
    async fn resolve_client_rootfs(&self, image: &str) -> Result<PathBuf, BackendError> {
        if let Some(preloaded) = self.client_image_rootfs.get(image) {
            let p = Path::new(preloaded);
            if p.is_absolute() {
                // A preloaded, already-unpacked rootfs directory — used as-is, never pulled.
                if tokio::fs::try_exists(p).await.unwrap_or(false) {
                    return Ok(p.to_path_buf());
                }
                return Err(BackendError::Materialize(format!(
                    "air-gap client rootfs for {image:?} not found at {preloaded}"
                )));
            }
            // A Storage blob hash of a rootfs tar — staged like a RootSource::Tar. A one-shot
            // ephemeral client has no persistent volume, so it always uses the configured base.
            return self.stage_rootfs(preloaded, self.userns_base).await;
        }
        // Not air-gap-mapped: an on-demand registry pull. Under the multi-tenant posture, refuse
        // a MUTABLE tag — a compromised/MITM'd registry could substitute a malicious image that
        // runs with the managed-DB credential in its environment and egress to the database. A
        // `@sha256:` digest makes the pull content-addressed (the registry cannot swap the bytes
        // without failing the digest), so it is accepted; otherwise require the operator to
        // preload the image via `[compute] client_image_rootfs`.
        if self.require_pinned_client_image && !image.contains("@sha256:") {
            return Err(BackendError::Materialize(format!(
                "multi-tenant posture: refusing an unauthenticated on-demand pull of client image \
                 {image:?}. Preload it via `[compute] client_image_rootfs`, or pin it by digest \
                 (`<image>@sha256:<hex>`), so a registry cannot substitute the bytes."
            )));
        }
        // Default: daemonless OCI pull + layer overlay, cached + idempotent. The one-shot
        // ephemeral client has no persistent volume, so it always uses the configured base.
        self.stage_image(image, self.userns_base).await
    }

    /// The one-shot body: build the hardened sandbox plan, (optionally) set up the
    /// dedicated stdin pipe, wire the host veth, spawn + hand off to the `__sandbox`
    /// worker over the netns handshake, then stream stdin↔stdout and capture the exit
    /// code, all bounded by [`ephemeral_timeout`](Self::ephemeral_timeout). The caller
    /// ([`run_ephemeral`](ComputeBackend::run_ephemeral)) owns teardown on every path.
    #[allow(clippy::too_many_arguments)]
    async fn run_ephemeral_inner(
        &self,
        id: &str,
        rootfs: &str,
        ip: Ipv4Addr,
        image: &str,
        argv: &[String],
        env: &[(String, String)],
        workdir: &str,
        mut stdin: Option<&mut (dyn futures::io::AsyncRead + Send + Unpin)>,
        stdout: &mut (dyn futures::io::AsyncWrite + Send + Unpin),
    ) -> Result<i32, BackendError> {
        use futures::io::AsyncReadExt as FuturesReadExt;
        use futures::io::AsyncWriteExt as FuturesWriteExt;
        use std::os::fd::AsRawFd;
        use std::os::unix::process::ExitStatusExt;
        use tokio::io::AsyncReadExt as TokioReadExt;

        // --- The hardened one-shot sandbox plan. ---
        // A minimal synthetic spec feeds `SandboxPlan::for_spec`, so the one-shot inherits
        // the SAME hardened baseline as a launched workload: the pivoted (shared, never
        // mutated) rootfs, `/proc`·`/sys` ro, `/tmp`·`/run`·`/dev` tmpfs, cgroup cpu/mem/PID
        // caps, the default-deny seccomp allow-list, and the rootless user namespace. The
        // client runs as namespace-root (`0 → host base`) with EVERY capability dropped
        // (`cap_add` is left empty regardless of posture — a dump/restore client never
        // needs a privileged entrypoint), and NO persistent volume.
        let spec = ComputeSpec {
            version: 1,
            root: RootSource::Image(image.to_string()),
            kernel: String::new(),
            kernel_cmdline: None,
            vcpus: 1,
            mem_mib: EPHEMERAL_MEM_MIB,
            entrypoint: argv.to_vec(),
            env: env.iter().cloned().collect(),
            port: 0,
            restart: boatramp_core::compute::RestartPolicy::Never,
            startup_grace_secs: 0,
            scale_to_zero: false,
            volumes: Vec::new(),
            writable_root: false,
            cap_add: Vec::new(),
            user: None,
            isolation: boatramp_core::compute::IsolationRequirement::Trusted,
            prefer_backend: None,
            pull_secret: None,
            bindings: Vec::new(),
            post_launch: Vec::new(),
        };
        let mut plan = SandboxPlan::for_spec(&spec, rootfs, id, GUEST_UID, GUEST_GID);
        // Read-only rootfs: a one-shot client never writes its rootfs (dumps stream to
        // stdout, scratch to the writable `/tmp`·`/run` tmpfs), and it pivots into the
        // SHARED cached staged image — so a read-only root keeps a buggy/hostile client
        // from mutating that cache. Matches the docker backend's `readonly_rootfs`.
        plan.readonly_root = true;
        // Start the client in the image's `WorkingDir` (empty ⇒ the pivoted root `/`); the
        // worker honors it best-effort just before `execvpe`.
        plan.workdir = workdir.to_string();
        // Point the client at the internal resolver on the bridge gateway when enabled, so
        // an external DSN hostname resolves (the resolver forwards external queries). A
        // one-shot has no project scope, so the empty project drops the `search` line and
        // keeps only the gateway `nameserver` (see `resolvconf::render`). `None` ⇒ leave
        // whatever the client image shipped.
        if let Some(domain) = &self.internal_dns_domain {
            plan.resolv_conf = Some(crate::resolvconf::render(self.gateway, "", domain));
        }

        // --- Dedicated stdin pipe (only when the caller streams a payload). ---
        // The worker inherits the READ end (non-CLOEXEC) and `dup2`s it onto the guest's
        // fd 0 (`SandboxPlan::exec_stdin_fd`), so the payload channel is fully decoupled
        // from the launcher↔worker handshake on the worker's own fd 0/1 — a multi-GB
        // restore can never race the worker's buffered `read_line("go")` and lose bytes.
        // The WRITE end is CLOEXEC so the worker never inherits it; dropping it (the sole
        // writer) is what gives the guest's stdin a clean EOF.
        let mut stdin_writer: Option<tokio::net::unix::pipe::Sender> = None;
        let read_end_guard;
        if stdin.is_some() {
            let (read_end, write_end) = nix::unistd::pipe()
                .map_err(|e| BackendError::Other(format!("ephemeral stdin pipe: {e}")))?;
            set_cloexec(write_end.as_raw_fd())
                .map_err(|e| BackendError::Other(format!("ephemeral stdin pipe cloexec: {e}")))?;
            plan.exec_stdin_fd = Some(read_end.as_raw_fd());
            stdin_writer = Some(
                tokio::net::unix::pipe::Sender::from_owned_fd(write_end)
                    .map_err(|e| BackendError::Other(format!("ephemeral stdin sender: {e}")))?,
            );
            // Keep the read end alive across the spawn below so the worker inherits it.
            read_end_guard = Some(read_end);
        } else {
            read_end_guard = None;
        }

        // --- Host veth + worker spawn + netns handshake (mirrors `launch_inner`). ---
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
        // The worker has forked and inherited the stdin-pipe read end; release the
        // launcher's own copy so the guest's stdin sees EOF once we drop the write end.
        drop(read_end_guard);

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
        let mut cstderr = child
            .stderr
            .take()
            .ok_or_else(|| BackendError::Launch("worker stderr".into()))?;

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
            // The worker died in `prepare` before signaling ready; surface its stderr.
            let mut why = String::new();
            let _ = cstderr.read_to_string(&mut why).await;
            let _ = veth.teardown().await;
            return Err(BackendError::Launch(format!(
                "worker did not signal ready (got {ready:?}); worker stderr:\n{}",
                why.trim_end()
            )));
        }

        // Write the userns id maps + move the veth peer into the worker's netns +
        // configure eth0/lo there — identical to the launch path: the client needs egress
        // to reach the database (an external DSN, or a co-located DB's bridge IP).
        if plan.namespaces.user {
            write_userns_maps(pid, self.userns_base)
                .map_err(|e| BackendError::Launch(format!("write userns maps: {e}")))?;
        }
        veth.move_peer_into_netns(pid)
            .await
            .map_err(|e| BackendError::Launch(format!("move veth peer: {e}")))?;
        configure_in_netns(pid, &veth.peer_veth, ip, self.prefix, self.gateway)
            .map_err(|e| BackendError::Launch(format!("netns config: {e}")))?;

        // Networking ready — release the worker to jail + exec the client.
        cstdin
            .write_all(b"go\n")
            .await
            .map_err(|e| BackendError::Launch(format!("signal go: {e}")))?;
        cstdin
            .flush()
            .await
            .map_err(|e| BackendError::Launch(format!("flush go: {e}")))?;
        // The handshake is done with the worker's own stdin; the guest's real stdin is the
        // dedicated pipe (or EOF when none). Dropping it EOFs the worker monitor's fd 0.
        drop(cstdin);

        // --- Stream stdin in, stdout out, drain stderr, await the exit code — all
        //     concurrently, bounded by the backstop timeout. Feeding stdin alongside the
        //     stdout drain avoids a full-pipe deadlock on a large piped restore. ---
        let mut stderr_tail: Vec<u8> = Vec::new();
        let run = async {
            // (a) STREAM the restore payload in (never buffered), then EOF.
            let writer = async {
                if let Some(reader) = stdin.as_mut() {
                    use tokio::io::AsyncWriteExt as TokioWriteExt;
                    let sender = stdin_writer
                        .as_mut()
                        .expect("stdin sender present when stdin is");
                    let mut buf = [0u8; 64 * 1024];
                    loop {
                        let n = reader.read(&mut buf).await.map_err(|e| {
                            BackendError::Other(format!("ephemeral stdin read: {e}"))
                        })?;
                        if n == 0 {
                            break;
                        }
                        sender.write_all(&buf[..n]).await.map_err(|e| {
                            BackendError::Other(format!("ephemeral stdin write: {e}"))
                        })?;
                    }
                }
                // Drop the write end → the guest's stdin sees EOF.
                stdin_writer.take();
                Ok::<(), BackendError>(())
            };
            // (b) TRUE-stream the client's stdout straight to the sink (never buffered).
            let reader =
                async {
                    let mut buf = [0u8; 64 * 1024];
                    loop {
                        let n = cstdout.read(&mut buf).await.map_err(|e| {
                            BackendError::Other(format!("ephemeral stdout read: {e}"))
                        })?;
                        if n == 0 {
                            break;
                        }
                        stdout.write_all(&buf[..n]).await.map_err(|e| {
                            BackendError::Other(format!("ephemeral sink write: {e}"))
                        })?;
                    }
                    stdout
                        .flush()
                        .await
                        .map_err(|e| BackendError::Other(format!("ephemeral sink flush: {e}")))?;
                    Ok::<(), BackendError>(())
                };
            // (c) Capture a bounded stderr tail for diagnostics only (best-effort).
            let stderr_drain = async {
                let mut buf = [0u8; 8192];
                while let Ok(n) = cstderr.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stderr_tail.len() < EPHEMERAL_STDERR_CAP {
                        let take = (EPHEMERAL_STDERR_CAP - stderr_tail.len()).min(n);
                        stderr_tail.extend_from_slice(&buf[..take]);
                    }
                }
            };
            // (d) The worker monitor exits with the guest's code; a signal → 128+signal.
            let waiter = async {
                let status = child
                    .wait()
                    .await
                    .map_err(|e| BackendError::Other(format!("ephemeral wait: {e}")))?;
                Ok::<i32, BackendError>(
                    status
                        .code()
                        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
                )
            };
            let (w, r, _e, code) = tokio::join!(writer, reader, stderr_drain, waiter);
            w?;
            r?;
            code
        };

        let outcome = tokio::time::timeout(self.ephemeral_timeout, run).await;

        match outcome {
            Ok(Ok(code)) => Ok(code),
            Ok(Err(e)) if stderr_tail.is_empty() => Err(e),
            Ok(Err(e)) => {
                // A bounded stderr tail aids diagnosis. The credential rode in `env`, never
                // a string, so it cannot reach here — but run the tail through the DSN
                // redactor anyway (defense-in-depth) in case a client tool ever echoed one.
                let tail =
                    boatramp_core::redact::redact_dsn(&String::from_utf8_lossy(&stderr_tail));
                Err(BackendError::Other(format!("{e}; stderr: {tail}")))
            }
            Err(_) => {
                // Timed out: kill the worker monitor now (the cgroup.kill in teardown reaps
                // the jailed tree). The borrow of `child` ended when `run` was dropped.
                let _ = child.start_kill();
                Err(BackendError::Other(format!(
                    "ephemeral run timed out after {}s (killed)",
                    self.ephemeral_timeout.as_secs()
                )))
            }
        }
    }

    /// Tear down a one-shot ephemeral container: kill its cgroup's process tree + remove
    /// the cgroup (as [`stop`](ComputeBackend::stop) does), tear down the veth, and
    /// release its transient IP. Best-effort per field so one failure can't strand
    /// another — an ephemeral run must never leak a cgroup, a veth, or a pool address.
    async fn ephemeral_teardown(&self, id: &str, ip: Ipv4Addr) {
        let cgroup = format!("/sys/fs/cgroup/boatramp/{id}");
        let _ = std::fs::write(format!("{cgroup}/cgroup.kill"), b"1");
        let _ = std::fs::remove_dir(&cgroup);
        let _ = VethNetwork::for_vm(id, &self.bridge).teardown().await;
        self.ipam.lock().expect("ipam mutex").release_ephemeral(ip);
    }

    /// Boot-time sweep of one-shot resources orphaned by a HARD node crash mid-`run_ephemeral`
    /// (the happy path always runs [`ephemeral_teardown`]). A stale ephemeral IP is already
    /// reclaimed by the IPAM GC, and a crashed run's veth PAIR is removed with its container network
    /// namespace (a veth dies with either peer's netns). What persists is the empty `ephm-*` cgroup
    /// directory under `/sys/fs/cgroup/boatramp/` — a cgroup is not refcounted to the process — so
    /// over repeated crashes these accumulate. This kills any survivor pinned to each and removes
    /// the directory. Best-effort; safe to call once at startup, before the backend serves any
    /// request, so no in-flight one-shot can race it. Only `ephm-`-prefixed directories are touched
    /// — never a live workload cgroup (`<workload>-<n>`).
    pub fn sweep_orphaned_ephemeral_cgroups(&self) {
        let swept = sweep_ephemeral_cgroups_in(Path::new("/sys/fs/cgroup/boatramp"));
        if swept > 0 {
            tracing::info!(
                swept,
                "swept orphaned one-shot (ephemeral) cgroups at startup"
            );
        }
    }
}

/// The `ephm-*` one-shot cgroup directories directly under `root` — NEVER a live workload cgroup
/// (`<workload>-<n>`). This PURE SELECTION is separated from the kill+rmdir so the prefix selectivity
/// (the security-relevant property — never sweep a live workload cgroup) is unit-testable against a
/// plain temp dir, without the cgroupfs-specific mechanics (on real cgroupfs `cgroup.kill` is a
/// pseudo-file and `rmdir` removes an empty cgroup; a temp dir models neither). Empty when `root` is
/// absent (no delegated cgroup subtree, or not a cgroup host).
fn ephemeral_cgroup_dirs(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("ephm-"))
        })
        .map(|e| e.path())
        .collect()
}

/// Remove every `ephm-*` cgroup directory under `root` (selected by [`ephemeral_cgroup_dirs`]),
/// returning the count removed. Each is killed (`cgroup.kill`) then `rmdir`'d — cgroupfs `rmdir`
/// removes an empty cgroup even though its pseudo-control-files remain. Silent when `root` is absent.
fn sweep_ephemeral_cgroups_in(root: &Path) -> usize {
    let mut swept = 0usize;
    for dir in ephemeral_cgroup_dirs(root) {
        // Kill any survivor still pinned to the cgroup, then remove the (now empty) cgroup.
        let _ = std::fs::write(dir.join("cgroup.kill"), b"1");
        if std::fs::remove_dir(&dir).is_ok() {
            swept += 1;
        }
    }
    swept
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

/// The container backend runs as host root in production — namespaces, cgroups, and
/// `pivot_root` all require it. Ownership shifting into the guest user namespace's mapped
/// range only makes sense, and only succeeds, under that privilege; when not root (unit
/// tests, unprivileged dev) no userns mapping is ever created, so there is nothing to
/// shift and the chown would only fail EPERM. Gate the ownership steps on it — but note
/// that once we *are* root, a chown failure is a real error and still propagates.
fn can_shift_ownership() -> bool {
    nix::unistd::geteuid().is_root()
}

/// The user-namespace mapping [`ContainerBackend::resolve_volume_mapping`] chose for a
/// workload: the single `base` to map the container (and shift the rootfs) with — all the
/// workload's volumes share ONE userns map — plus a PER-VOLUME chown decision (`chowns[i]` for
/// `spec.volumes[i]`). A REUSED volume read as-is via the derived base has `None` — its data is
/// never mutated; a FRESH volume, or an in-place remap of host-owned data, has
/// `Some((uid, gid))`. Per-volume so a reused data dir and a fresh sibling can share one base
/// yet be handled differently (the fresh one chowns, the reused one is read as-is).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedMapping {
    base: u32,
    chowns: Vec<Option<(u32, u32)>>,
}

/// Why deriving a per-launch user-namespace base from a reused volume's existing owner was
/// refused — the pure, security-critical validation behind the reused-volume repair
/// ([`ContainerBackend::resolve_volume_mapping`]). Each variant is a fail-closed refusal, never
/// a silent fallback: the launch stops with an actionable error rather than mapping the database
/// onto an owner the mapping cannot safely express. The caller may instead REMAP (host root
/// only) for an `Unmappable`/`WouldMapHostRoot`/`BelowFloor` owner, which relabels ownership in
/// place but never reinitializes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaseDeriveError {
    /// No single base maps the database's runtime uid onto the owner: the owner uid/gid is
    /// below the runtime id (would underflow), or the uid and gid offsets differ (one
    /// `0 base count` map line shifts uid and gid by the SAME amount, so they must agree).
    Unmappable,
    /// The base would be `0` — in-container root mapped onto HOST root (host 0) — on a node NOT
    /// configured for the host-root posture. Refused to preserve rootless isolation.
    WouldMapHostRoot,
    /// The base is below [`USERNS_HOST_BASE`] (off host-root), i.e. it would map the container
    /// onto low/system host uids outside the dedicated per-container window. Refused as
    /// defense-in-depth: a derived base is only trusted within the rootless subuid range.
    BelowFloor,
    /// The mapped window `[base, base + USERNS_COUNT)` would overflow `u32`.
    RangeOverflow,
}

/// Derive the user-namespace base `D` such that the database's **runtime** `(pg_uid, pg_gid)`
/// (the uid it runs as AFTER the image entrypoint drops privileges — NOT the entrypoint/spec
/// uid, which for a root-entrypoint image is 0) maps onto the data dir's existing
/// `(owner_uid, owner_gid)` — i.e. `D + pg == owner` — so the data is read as-is. Validates the
/// security invariants against `userns_base` (the configured rootless base) and `host_root`
/// (the host-root posture, under which base 0 and a sub-floor base are legitimate). Pure (no
/// I/O) so the security logic is unit-tested on every host.
fn derive_base(
    owner_uid: u32,
    owner_gid: u32,
    pg_uid: u32,
    pg_gid: u32,
    host_root: bool,
    userns_base: u32,
) -> Result<u32, BaseDeriveError> {
    // One `0 base count` map line shifts uid and gid by the same `base`, so both must solve
    // to the same non-negative offset.
    let base = match (owner_uid.checked_sub(pg_uid), owner_gid.checked_sub(pg_gid)) {
        (Some(bu), Some(bg)) if bu == bg => bu,
        _ => return Err(BaseDeriveError::Unmappable),
    };
    if !host_root {
        if base == 0 {
            return Err(BaseDeriveError::WouldMapHostRoot);
        }
        if base < userns_base {
            return Err(BaseDeriveError::BelowFloor);
        }
    }
    if base.checked_add(crate::worker::USERNS_COUNT - 1).is_none() {
        return Err(BaseDeriveError::RangeOverflow);
    }
    Ok(base)
}

/// Render a [`BaseDeriveError`] into an operator-actionable launch error naming the volume, the
/// data dir's actual owner, the database's runtime uid, and the remedies.
fn derive_error_message(
    volume: &str,
    owner_uid: u32,
    owner_gid: u32,
    pg_uid: u32,
    pg_gid: u32,
    err: BaseDeriveError,
) -> String {
    match err {
        BaseDeriveError::Unmappable => format!(
            "volume {volume:?} data dir is owned {owner_uid}:{owner_gid} but the database runs \
             as {pg_uid}:{pg_gid}: no single user-namespace base maps it onto that owner (the \
             owner must be >= the runtime id and the uid/gid offsets must match). Your data is \
             left untouched. Remedies: re-provision/restore the volume under the current \
             mapping, or run this node host-root."
        ),
        BaseDeriveError::WouldMapHostRoot => format!(
            "volume {volume:?} data dir is owned {owner_uid}:{owner_gid}, equal to the database \
             runtime id {pg_uid}:{pg_gid} with no offset: deriving a mapping would put \
             in-container root on HOST root (base 0), breaking rootless isolation. Your data is \
             left untouched. Remedies: re-provision the volume under the rootless mapping, or \
             set the host-root posture explicitly if that is intended."
        ),
        BaseDeriveError::BelowFloor => format!(
            "volume {volume:?} data dir owner {owner_uid}:{owner_gid} (database runs as \
             {pg_uid}:{pg_gid}) derives a user-namespace base below the rootless subuid floor, \
             which would map the container onto low/system host uids. Refused as a hardening \
             guard; your data is left untouched. Remedies: re-provision the volume under the \
             rootless mapping, or run this node host-root."
        ),
        BaseDeriveError::RangeOverflow => format!(
            "volume {volume:?} data dir owner {owner_uid}:{owner_gid} derives a user-namespace \
             base that overflows the mappable id range for runtime id {pg_uid}:{pg_gid}; \
             re-provision the volume with a smaller owner id."
        ),
    }
}

/// The in-image OS username the managed DB's entrypoint drops privileges to (`gosu`/`su-exec`
/// target), inferred from the spec's engine. `None` for a non-managed-DB spec.
fn db_user_for_spec(spec: &ComputeSpec) -> Option<&'static str> {
    if spec.env.contains_key("PGDATA") || spec.entrypoint.iter().any(|a| a == "postgres") {
        return Some("postgres");
    }
    if spec
        .entrypoint
        .iter()
        .any(|a| a == "mysqld" || a == "mariadbd")
    {
        return Some("mysql");
    }
    None
}

/// Parse `/etc/passwd` contents for `user`'s `(uid, gid)` (fields 3 and 4). Pure.
fn parse_passwd_ids(passwd: &str, user: &str) -> Option<(u32, u32)> {
    for line in passwd.lines() {
        let mut f = line.split(':');
        if f.next() == Some(user) {
            let _pw = f.next()?;
            let uid = f.next()?.parse().ok()?;
            let gid = f.next()?.parse().ok()?;
            return Some((uid, gid));
        }
    }
    None
}

/// Parse the userns base a staged rootfs dir was shifted for, from its `…​.b<base>` suffix
/// (written by [`ContainerBackend::stage_rootfs`]/`stage_image`). Pure.
fn parse_rootfs_base(dir: &Path) -> Option<u32> {
    let name = dir.file_name()?.to_str()?;
    name.rsplit_once(".b")?.1.parse().ok()
}

/// The PURE decision behind [`ContainerBackend::resolve_volume_mapping`] — given each volume's
/// owner [`consensus`](crate::data_dir::OwnerConsensus), the workload's `runtime` `(uid, gid)`
/// (the id its process runs as: the DB user detected from the image for a managed DB, else the
/// spec's own guest uid — `None` only for a DB whose runtime uid couldn't be read), the
/// fresh-init `(guest_uid, guest_gid)`, and the posture, pick the [`ResolvedMapping`] or the
/// fail-closed reason. The workload gets ONE `base` (all reused volumes must agree); each
/// volume's chown is decided independently (`chowns[i]` for `volumes[i]`):
///
/// * **Empty (fresh)** — chown to `base + guest` (needs an owned dir to init into).
/// * **Uniform (reused)** — DERIVE `D = owner − runtime` and read AS-IS (chown `None`). If the
///   owner is unmappable (underflow / base-0 / below the subuid floor / overflow) the launch is
///   REFUSED unless `can_remap` (host root), in which case the data is remapped in place to
///   `base + runtime` (relabel only — never a reinit).
/// * **Mixed** — refused: no single base makes it all readable.
/// * **Conflicting volumes** — refused only when two REUSED volumes derive DIFFERENT bases (a
///   container has ONE userns map); a fresh/remap sibling adopts the derived base, never
///   conflicts.
///
/// Scoped to this workload's OWN volumes (the caller passes only this workload's `spec.volumes`,
/// each a distinct `compute/volumes/<name>` dir — never a sibling tenant's). Pure (no I/O) so
/// the fail-closed plumbing is unit-tested on every host.
fn resolve_mapping_decision(
    volumes: &[(String, crate::data_dir::OwnerConsensus)],
    guest_uid: u32,
    guest_gid: u32,
    runtime: Option<(u32, u32)>,
    host_root: bool,
    userns_base: u32,
    can_remap: bool,
) -> Result<ResolvedMapping, BackendError> {
    use crate::data_dir::OwnerConsensus;
    enum Kind {
        Fresh,
        ReadAsIs,
        Remap,
    }
    // First pass: classify each volume and agree on the single base the reused ones derive.
    let mut kinds = Vec::with_capacity(volumes.len());
    let mut derived: Option<u32> = None;
    for (name, consensus) in volumes {
        let kind = match consensus {
            OwnerConsensus::Empty => Kind::Fresh,
            OwnerConsensus::Mixed {
                first_uid,
                first_gid,
                conflict_path,
                conflict_uid,
                conflict_gid,
            } => {
                return Err(BackendError::Launch(format!(
                    "volume {name:?} data dir has MIXED ownership, so no single user-namespace \
                     mapping makes it readable: the root is owned {first_uid}:{first_gid} but \
                     {conflict_path:?} is {conflict_uid}:{conflict_gid}. Refusing to launch \
                     (your data is left untouched — never reinitialized). Remedies: \
                     re-provision/restore the volume to one owner, or run this node host-root.",
                )));
            }
            OwnerConsensus::Uniform {
                uid: owner_uid,
                gid: owner_gid,
                ..
            } => {
                let (run_uid, run_gid) = runtime.ok_or_else(|| {
                    BackendError::Launch(format!(
                        "volume {name:?} is a reused data dir but the database's runtime uid \
                         could not be determined from the image's /etc/passwd; refusing to \
                         derive a mapping (your data is left untouched)."
                    ))
                })?;
                match derive_base(
                    *owner_uid,
                    *owner_gid,
                    run_uid,
                    run_gid,
                    host_root,
                    userns_base,
                ) {
                    Ok(d) => {
                        // All reused volumes must derive the SAME base (one userns map); a
                        // fresh/remap sibling imposes none, so only reused ones can conflict.
                        match derived {
                            Some(prev) if prev != d => {
                                return Err(BackendError::Launch(format!(
                                    "workload has reused volumes that need CONFLICTING \
                                     user-namespace bases ({prev} vs {d}): a container has ONE \
                                     mapping, so its reused volumes must share one owner. \
                                     Re-provision them to a single owner (data left untouched).",
                                )));
                            }
                            _ => derived = Some(d),
                        }
                        Kind::ReadAsIs
                    }
                    Err(_) if can_remap => Kind::Remap,
                    Err(e) => {
                        return Err(BackendError::Launch(derive_error_message(
                            name, *owner_uid, *owner_gid, run_uid, run_gid, e,
                        )));
                    }
                }
            }
        };
        kinds.push(kind);
    }
    // The workload base: the (agreed) derived base from reused volumes, else the configured one.
    let base = derived.unwrap_or(userns_base);
    let chowns = kinds
        .into_iter()
        .map(|k| match k {
            Kind::ReadAsIs => None,
            // Pre-own a FRESH dir AS the workload's RUNTIME uid under the workload base, NOT the
            // entrypoint/spec `guest_uid`. A managed DB's stock entrypoint drops to its image
            // runtime uid (e.g. postgres:999) and, on a cap-dropped node (no CAP_CHOWN), cannot
            // re-own PGDATA itself — a dir left at `base + guest_uid` (= base+0 for a root
            // entrypoint) is container-root-owned and the entrypoint's `chown` EPERMs before
            // initdb. Owning the fresh dir at `base + runtime` mirrors exactly the ownership a
            // REUSED dir is read at (chown=None on an `owner == base + runtime` dir), so initdb
            // needs no chown. `runtime` is the detected managed-DB uid, or the spec guest uid for
            // a non-DB workload (set in `resolve_volume_mapping`), so `base + runtime` equals the
            // old `base + guest` for non-DB — unchanged there. Fall back to guest only when a
            // managed image's uid is unreadable.
            Kind::Fresh => Some(match runtime {
                Some((u, g)) => (base.saturating_add(u), base.saturating_add(g)),
                None => (
                    base.saturating_add(guest_uid),
                    base.saturating_add(guest_gid),
                ),
            }),
            // Remap an unmappable reused dir to the runtime user UNDER the workload base, so it
            // is readable as-is afterwards (relabel only — never a reinit). `runtime` is `Some`
            // here (an unmappable Uniform already required it above).
            Kind::Remap => runtime.map(|(u, g)| (base.saturating_add(u), base.saturating_add(g))),
        })
        .collect();
    Ok(ResolvedMapping { base, chowns })
}

/// Whether `dir` exists and holds at least one entry — the cheap "is there data to
/// adopt?" probe for the legacy-volume migration. A missing directory, or one that exists
/// but is empty (a fresh/abandoned shell), is `false`: the migration never adopts an empty
/// directory, so a stray empty legacy `data` dir can neither be mistaken for a cluster nor
/// block a fresh managed DB. Reads only the first directory entry (no recursion).
async fn dir_has_entries(dir: &Path) -> bool {
    match tokio::fs::read_dir(dir).await {
        Ok(mut rd) => matches!(rd.next_entry().await, Ok(Some(_))),
        Err(_) => false, // missing / unreadable ⇒ nothing to adopt
    }
}

/// Sum the on-disk size (bytes) of every regular file under `dir`, recursively
/// (blocking). Symlinks are counted by their own size, never followed, so a
/// symlink inside a volume can't inflate the total or escape into the wider fs.
/// A directory that vanishes mid-walk (concurrent removal) contributes what was
/// read so far rather than erroring — the size is advisory for the operator
/// listing, not a correctness invariant.
fn dir_size_bytes(dir: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let mut total: u64 = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in rd.flatten() {
            // `DirEntry::metadata` does not follow symlinks (unlike `Path::metadata`),
            // so a symlink is counted by its own size, never traversed.
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.file_type().is_dir() {
                stack.push(entry.path());
            } else {
                total = total.saturating_add(meta.size());
            }
        }
    }
    total
}

/// Shift every entry's on-disk uid/gid up by `base` (recursively, not following
/// symlinks), so a rootfs extracted as host root (image uids `0..65535`) is owned by the
/// container user namespace's mapped host range (`base..base+65535`). Then the guest's
/// namespace-root (host `base`) owns the image's root-owned files, and non-root image
/// uids (e.g. `postgres` 999) map correctly. A no-op when `base == 0` (the host-root
/// mapping — the image is already host-root-owned) or when unprivileged (no userns to
/// map into). Runs blocking, off the runtime.
fn shift_rootfs(dir: &Path, base: u32) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if base == 0 || !can_shift_ownership() {
        return Ok(());
    }
    // Shift an id within one container range; leave anything already out of range
    // untouched (it can't be represented inside the guest regardless).
    let shift = |id: u32| if id < 65_536 { base + id } else { id };
    let relabel = |path: &Path, meta: &std::fs::Metadata| -> std::io::Result<()> {
        std::os::unix::fs::lchown(path, Some(shift(meta.uid())), Some(shift(meta.gid())))
    };
    relabel(dir, &std::fs::symlink_metadata(dir)?)?;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let path = entry?.path();
            let meta = std::fs::symlink_metadata(&path)?;
            relabel(&path, &meta)?;
            if meta.file_type().is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

/// Recursively set every entry under `dir` (and `dir` itself) to `(uid, gid)`, not
/// following symlinks, **skipping entries already correctly owned** so an already-correct
/// volume costs only a stat per entry (no `lchown` churn). This is the robust managed-DB
/// volume pre-chown: it repairs a reused/restored/cloned data directory whose files were
/// written under a different owner, which would otherwise EPERM the rootless DB process
/// reading its own data directory. Runs blocking at launch time (infrequent for a
/// never-scale-to-zero managed DB), off the hot path.
fn chown_tree_to(dir: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let fix = |path: &Path, meta: &std::fs::Metadata| -> std::io::Result<()> {
        if meta.uid() != uid || meta.gid() != gid {
            std::os::unix::fs::lchown(path, Some(uid), Some(gid))?;
        }
        Ok(())
    };
    fix(dir, &std::fs::symlink_metadata(dir)?)?;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let path = entry?.path();
            let meta = std::fs::symlink_metadata(&path)?;
            fix(&path, &meta)?;
            if meta.file_type().is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

/// Write the worker's user-namespace uid/gid maps from the launcher. The worker
/// unshared `CLONE_NEWUSER` but can't self-write a range map (no CAP_SETUID in the
/// parent ns after the unshare); the launcher still holds CAP_SETUID/SETGID in the
/// parent, so it writes `/proc/<pid>/{uid,gid}_map` for it (uid first). No
/// `setgroups=deny` is needed — a privileged writer may set gid_map directly.
fn write_userns_maps(pid: u32, base: u32) -> Result<(), String> {
    let line = crate::worker::userns_map_line(base);
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

/// The env var that gates the one-shot network-state dump. Default **ON** for this
/// diagnostic rc — set it to `0`/`false`/`off`/`no` to silence the dump.
const NET_DEBUG_ENV: &str = "BOATRAMP_COMPUTE_NET_DEBUG";

/// Whether the one-shot network dump is enabled. Default ON (any value other than an
/// explicit disable keeps it on), so a normal managed-DB launch's logs carry it without
/// a special build; an operator who finds it noisy can turn it off.
fn net_debug_enabled() -> bool {
    match std::env::var(NET_DEBUG_ENV) {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    }
}

/// One-shot, best-effort **network-state dump** for a freshly-configured container, so
/// the boot logs reveal the exact L2/L3 state and host→container reachability result —
/// the discriminator for a fly-guest reachability failure (EHOSTUNREACH vs
/// connection-refused vs timeout). Runs once per launch (right after `configure_in_netns`)
/// when [`net_debug_enabled`]. Every line is prefixed `compute-net-debug:` for grepping.
///
/// **In-process only — no external command is ever spawned.** boatramp's OCI image is a
/// minimal static-musl build with no `iproute2`/`nsenter`/shell, so shelling out to
/// `ip`/`bridge`/`nsenter` would only ever log "command not found" on the real fly guest.
/// Instead every datum is read straight from the kernel:
///
/// - **HOST side** — the compute bridge and the host veth are queried over `rtnetlink`
///   (the same connection pattern `host_setup`/`configure_in_netns` use): existence,
///   `IFF_UP` + oper-state, and the host veth's `master` (controller) ifindex, resolved
///   back to a name so it can be compared with the bridge's index. The bridge's IPv4
///   address(es) come from `rtnetlink` too (confirming it carries the gateway `.1`). The
///   host ARP/neighbour state for the container IP is parsed from `/proc/net/arp`
///   (`Flags 0x2` = resolved, `0x0` = incomplete — decisive for EHOSTUNREACH).
///   All of these run in the launcher's (host) netns, which is exactly where the bridge
///   and host veth live.
/// - **CONTAINER side** — read from `/proc/<pid>/net/*`, which reflects that pid's netns
///   with no `setns`: `/proc/<pid>/net/dev` for the interface names (is `eth0` present ⇒
///   the veth peer moved in?), `/proc/<pid>/net/fib_trie` for the container-netns LOCAL
///   IPv4 addresses (did `eth0` actually get its IP?), and `/proc/<pid>/net/route` raw
///   (the hex-encoded routing table incl. the default route) as a backstop.
/// - **SELF-TEST** — a host→container TCP connect to `ip:port`, logging the EXACT error
///   string AND `raw_os_error()` so the failure mode is unambiguous (113 EHOSTUNREACH vs
///   111 ECONNREFUSED vs timeout).
///
/// The whole `backend` module is already Linux-gated (`lib.rs`), so this lives only on
/// Linux (the `/proc/<pid>/net/*` and netlink reads it uses are Linux-only). Every read
/// is best-effort: any failure is logged and the launch continues.
async fn net_debug_dump(
    workload: &str,
    pid: u32,
    bridge: &str,
    host_veth: &str,
    ip: Ipv4Addr,
    port: u16,
) {
    use futures::TryStreamExt;
    use netlink_packet_route::link::{LinkAttribute, LinkFlag};

    if !net_debug_enabled() {
        return;
    }

    macro_rules! dbg_line {
        ($($arg:tt)*) => {
            tracing::info!(
                target: "boatramp_container::net_debug",
                "compute-net-debug: {}",
                format_args!($($arg)*)
            )
        };
    }

    dbg_line!("BEGIN dump for workload {workload:?} pid {pid} container {ip}:{port}");

    // --- HOST side (rtnetlink, host netns) --------------------------------
    // A single netlink connection drives every host-side query. If it can't be opened
    // we fall back to the /sys/class/net reads below for the up/enslaved state.
    match rtnetlink::new_connection() {
        Ok((conn, handle, _)) => {
            tokio::spawn(conn);

            // Fetch one link by name → (ifindex, up?, oper-state, master ifindex).
            async fn link_facts(
                handle: &rtnetlink::Handle,
                name: &str,
            ) -> Result<(u32, bool, String, Option<u32>), String> {
                let mut stream = handle.link().get().match_name(name.to_string()).execute();
                match stream.try_next().await {
                    Ok(Some(msg)) => {
                        let index = msg.header.index;
                        let up = msg.header.flags.contains(&LinkFlag::Up);
                        let mut oper = "unknown".to_string();
                        let mut master = None;
                        for attr in &msg.attributes {
                            match attr {
                                LinkAttribute::OperState(state) => oper = format!("{state:?}"),
                                LinkAttribute::Controller(idx) => master = Some(*idx),
                                _ => {}
                            }
                        }
                        Ok((index, up, oper, master))
                    }
                    Ok(None) => Err("no such link".to_string()),
                    Err(e) => Err(format!("netlink error: {e}")),
                }
            }

            // Resolve an ifindex back to a name (for the veth's master → bridge compare).
            async fn link_name(handle: &rtnetlink::Handle, index: u32) -> Option<String> {
                let mut stream = handle.link().get().match_index(index).execute();
                match stream.try_next().await {
                    Ok(Some(msg)) => msg.attributes.iter().find_map(|a| match a {
                        LinkAttribute::IfName(n) => Some(n.clone()),
                        _ => None,
                    }),
                    _ => None,
                }
            }

            // Bridge link facts.
            let bridge_idx = match link_facts(&handle, bridge).await {
                Ok((idx, up, oper, _master)) => {
                    dbg_line!(
                        "host bridge {bridge} link: exists, ifindex {idx}, up={up}, oper-state={oper}"
                    );
                    Some(idx)
                }
                Err(e) => {
                    dbg_line!("host bridge {bridge} link: {e}");
                    None
                }
            };

            // Host veth link facts + master (enslaved-to-bridge?) resolution.
            match link_facts(&handle, host_veth).await {
                Ok((idx, up, oper, master)) => {
                    let master_desc = match master {
                        Some(m) => {
                            let name = link_name(&handle, m).await;
                            let enslaved = bridge_idx == Some(m);
                            match name {
                                Some(n) => format!(
                                    "master={n} (ifindex {m}), enslaved-to-{bridge}={enslaved}"
                                ),
                                None => {
                                    format!("master-ifindex={m}, enslaved-to-{bridge}={enslaved}")
                                }
                            }
                        }
                        None => "master=none (NOT enslaved)".to_string(),
                    };
                    dbg_line!(
                        "host veth {host_veth} link: exists, ifindex {idx}, up={up}, oper-state={oper}, {master_desc} (bridge ifindex {bridge_idx:?})"
                    );
                }
                Err(e) => dbg_line!("host veth {host_veth} link: {e}"),
            }

            // Bridge IPv4 address(es) — confirm it carries the gateway `.1`.
            match bridge_idx {
                Some(idx) => {
                    let mut stream = handle.address().get().set_link_index_filter(idx).execute();
                    let mut addrs: Vec<String> = Vec::new();
                    loop {
                        match stream.try_next().await {
                            Ok(Some(msg)) => {
                                let prefix = msg.header.prefix_len;
                                for attr in &msg.attributes {
                                    if let netlink_packet_route::address::AddressAttribute::Address(
                                        addr,
                                    ) = attr
                                        && addr.is_ipv4()
                                    {
                                        addrs.push(format!("{addr}/{prefix}"));
                                    }
                                }
                            }
                            Ok(None) => break,
                            Err(e) => {
                                addrs.push(format!("(netlink error: {e})"));
                                break;
                            }
                        }
                    }
                    if addrs.is_empty() {
                        dbg_line!("host bridge {bridge} IPv4 addrs: (none)");
                    } else {
                        dbg_line!("host bridge {bridge} IPv4 addrs: {}", addrs.join(", "));
                    }
                }
                None => {
                    dbg_line!("host bridge {bridge} IPv4 addrs: (skipped — bridge ifindex unknown)")
                }
            }
        }
        Err(e) => {
            // Netlink unavailable: fall back to /sys/class/net for the host bridge + veth
            // up/enslaved state (the host netns, which is correct for both).
            dbg_line!("host rtnetlink connection failed ({e}); falling back to /sys/class/net");
            for iface in [bridge, host_veth] {
                let oper = std::fs::read_to_string(format!("/sys/class/net/{iface}/operstate"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|e| format!("(read err: {e})"));
                let master = std::fs::read_link(format!("/sys/class/net/{iface}/master"))
                    .ok()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                    .unwrap_or_else(|| "none".to_string());
                dbg_line!("host {iface} (sysfs): operstate={oper}, master={master}");
            }
        }
    }

    // Host ARP/neighbour state for the container IP (decisive for EHOSTUNREACH):
    // /proc/net/arp is plain text — `IP HWtype Flags HWaddr Mask Device`.
    // Flags 0x2 = resolved/REACHABLE, 0x0 = incomplete/failed.
    let ip_str = ip.to_string();
    match std::fs::read_to_string("/proc/net/arp") {
        Ok(arp) => {
            let mut found = None;
            for line in arp.lines().skip(1) {
                let mut cols = line.split_whitespace();
                if cols.next() == Some(ip_str.as_str()) {
                    // remaining: HWtype Flags HWaddr Mask Device
                    let rest: Vec<&str> = cols.collect();
                    found = Some(rest.join(" "));
                    break;
                }
            }
            match found {
                Some(rest) => dbg_line!(
                    "host ARP for {ip_str}: {rest} (Flags 0x2 = resolved/REACHABLE, 0x0 = incomplete)"
                ),
                None => dbg_line!("host ARP for {ip_str}: no ARP entry (L2 unresolved)"),
            }
        }
        Err(e) => dbg_line!("host ARP for {ip_str}: (read /proc/net/arp err: {e})"),
    }

    // --- CONTAINER side (/proc/<pid>/net/*, the container's netns) ---------
    // Interface names present in the container netns (is eth0 there ⇒ peer moved in?).
    match std::fs::read_to_string(format!("/proc/{pid}/net/dev")) {
        Ok(dev) => {
            let ifaces: Vec<String> = dev
                .lines()
                .skip(2) // two header lines
                .filter_map(|l| l.split(':').next())
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
                .collect();
            dbg_line!(
                "container(pid {pid}) net/dev ifaces (KEY: is eth0 present?): {}",
                if ifaces.is_empty() {
                    "(none)".to_string()
                } else {
                    ifaces.join(", ")
                }
            );
        }
        Err(e) => dbg_line!("container(pid {pid}) net/dev: (read err: {e})"),
    }

    // Container-netns LOCAL IPv4 addresses via fib_trie: the `/32 host LOCAL` leaves are
    // the addresses actually assigned to interfaces in this netns (did eth0 get its IP?).
    match std::fs::read_to_string(format!("/proc/{pid}/net/fib_trie")) {
        Ok(trie) => {
            let locals = parse_fib_trie_locals(&trie);
            dbg_line!(
                "container(pid {pid}) fib_trie LOCAL addrs (KEY: did eth0 come up with {ip}?): {}",
                if locals.is_empty() {
                    "(none)".to_string()
                } else {
                    locals.join(", ")
                }
            );
        }
        Err(e) => dbg_line!("container(pid {pid}) fib_trie: (read err: {e})"),
    }

    // Raw routing table (hex-encoded) as a backstop — carries the default route too.
    match std::fs::read_to_string(format!("/proc/{pid}/net/route")) {
        Ok(route) => {
            let one_line = route.lines().collect::<Vec<_>>().join(" ¦ ");
            dbg_line!("container(pid {pid}) net/route (raw, hex-encoded): {one_line}");
        }
        Err(e) => dbg_line!("container(pid {pid}) net/route: (read err: {e})"),
    }

    // --- SELF-TEST: host→container TCP connect, exact error + errno --------
    let target = format!("{ip}:{port}");
    let connect = tokio::net::TcpStream::connect(&target);
    let probe = match tokio::time::timeout(Duration::from_secs(2), connect).await {
        Ok(Ok(_)) => "OK (connected)".to_string(),
        Ok(Err(e)) => format!("FAILED: {e} (os error: {:?})", e.raw_os_error()),
        Err(_) => "FAILED: timed out after 2s".to_string(),
    };
    dbg_line!("SELF-TEST host->container TCP connect {target}: {probe}");
    dbg_line!("END dump for workload {workload:?}");
}

/// Parse the LOCAL IPv4 leaves out of a `/proc/<pid>/net/fib_trie` dump. The file is an
/// indented tree; each leaf is a `|-- <ip>` line followed by one or more
/// `/<plen> <type> LOCAL` (or `/<plen> universe ...`) lines. We collect the `<ip>/<plen>`
/// pairs whose type line contains `LOCAL` — those are the addresses assigned to an
/// interface in this netns (as opposed to routes/broadcast). Best-effort text parse.
fn parse_fib_trie_locals(trie: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current_ip: Option<String> = None;
    for line in trie.lines() {
        let trimmed = line.trim_start_matches([' ', '|', '+', '-']);
        let trimmed = trimmed.trim();
        // A leaf address line: the token after the tree glyphs is a bare IPv4 literal.
        if let Some(first) = trimmed.split_whitespace().next()
            && first.parse::<Ipv4Addr>().is_ok()
        {
            current_ip = Some(first.to_string());
            continue;
        }
        // A prefix line under the current leaf: `/<plen> <scope> <type>`.
        if trimmed.starts_with('/')
            && trimmed.contains("LOCAL")
            && let Some(ip) = &current_ip
        {
            let plen = trimmed
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_start_matches('/');
            out.push(format!("{ip}/{plen}"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// One-shot ephemeral client-container support (run_ephemeral)
// ---------------------------------------------------------------------------

/// Memory cap (MiB) for a one-shot `run_ephemeral` client container — a `pg_dump`/
/// `pg_restore`/`mysql`/`psql` process streams, so this is generous without being
/// unbounded. Mirrors the docker backend's 512 MiB ephemeral cap.
const EPHEMERAL_MEM_MIB: u32 = 512;

/// The generous DEFAULT wall-clock backstop for a single `run_ephemeral` invocation
/// (overridable via [`ContainerBackend::with_ephemeral_timeout`]). The real
/// "unreachable DSN" hang is bounded far tighter by the client's own connect timeout, so
/// this exists only to guarantee a wedged client / stuck stream can never pin a container
/// (and its veth / cgroup / pool address) forever. Deliberately large so a legitimate
/// multi-hour dump of a big database is not killed mid-flight. Matches the docker backend.
const EPHEMERAL_RUN_TIMEOUT: Duration = Duration::from_secs(6 * 3600);

/// Cap on captured stderr from an ephemeral run (diagnostics only — stdout is the
/// streamed payload). Bounds memory if a failing client floods stderr.
const EPHEMERAL_STDERR_CAP: usize = 64 * 1024;

/// A monotonic suffix so two concurrent ephemeral runs never collide on an id (which keys
/// the cgroup / veth / hostname). Combined with the process-clock nanos.
static EPHEMERAL_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A unique container id for a one-shot ephemeral run (the cgroup / veth / hostname / log
/// stem). `ephm-<nanos>-<seq>` is ASCII `[a-z0-9-]` and clamped to the UTS hostname limit
/// like every other container id, so it is always a legal hostname + interface-name input.
fn ephemeral_container_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = EPHEMERAL_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    clamp_container_id(format!("ephm-{nanos}-{seq}"))
}

/// Set `FD_CLOEXEC` on `fd` so a subsequent `execve` (the re-exec'd `__sandbox` worker)
/// does NOT inherit it. Used on the launcher-held **write** end of the ephemeral stdin
/// pipe: if the worker inherited that write end, the guest's stdin would never see EOF
/// when the launcher finishes streaming (a hung restore). The read end is left
/// non-CLOEXEC so the worker DOES inherit it (and `dup2`s it onto the guest's fd 0).
fn set_cloexec(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: `fd` is a live, owned pipe fd; `F_SETFD`/`FD_CLOEXEC` is a pure flag set.
    let rc = unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFD, nix::libc::FD_CLOEXEC) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::compute::{IsolationRequirement, RestartPolicy};
    use boatramp_core::{GetObject, ObjectMeta, PutMeta, StorageError};
    use bytes::Bytes;
    use std::collections::BTreeMap;

    #[test]
    fn merge_env_seeds_image_path_and_caller_vars_win() {
        // The image supplies `PATH` (where the client binaries live); the caller supplies
        // only the connection vars. The result carries BOTH, so a bare `pg_dump` resolves.
        let image_env = vec![
            "PATH=/usr/local/bin:/usr/lib/postgresql/16/bin:/usr/bin:/bin".to_string(),
            "LANG=en_US.utf8".to_string(),
            "PGDATA=/var/lib/postgresql/data".to_string(),
        ];
        let overrides = vec![
            ("PGHOST".to_string(), "db.internal".to_string()),
            ("PGPASSWORD".to_string(), "s3cret".to_string()),
            // A caller override of an image key MUST win.
            ("PGDATA".to_string(), "/tmp/ignored".to_string()),
        ];
        let merged = merge_env(&image_env, &overrides);
        let lookup = |k: &str| {
            merged
                .iter()
                .find(|(ek, _)| ek == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(
            lookup("PATH"),
            Some("/usr/local/bin:/usr/lib/postgresql/16/bin:/usr/bin:/bin"),
            "the image PATH must survive so execvpe can find the client binary"
        );
        assert_eq!(lookup("PGHOST"), Some("db.internal"));
        assert_eq!(lookup("PGPASSWORD"), Some("s3cret"));
        assert_eq!(
            lookup("PGDATA"),
            Some("/tmp/ignored"),
            "a caller override replaces the same-key image entry"
        );
        // No duplicate key for the overridden entry.
        assert_eq!(merged.iter().filter(|(k, _)| k == "PGDATA").count(), 1);
    }

    #[test]
    fn merge_env_handles_empty_image_env_and_malformed_entries() {
        // No image config (air-gap / default) ⇒ just the caller's env, unchanged.
        let only_caller = merge_env(&[], &[("PGHOST".to_string(), "h".to_string())]);
        assert_eq!(only_caller, vec![("PGHOST".to_string(), "h".to_string())]);
        // An image entry without '=' is skipped, not panicked on.
        let merged = merge_env(&["BROKEN".to_string(), "PATH=/bin".to_string()], &[]);
        assert_eq!(merged, vec![("PATH".to_string(), "/bin".to_string())]);
    }

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
            startup_grace_secs: 30,
            scale_to_zero: false,
            volumes: vec![],
            writable_root: false,
            cap_add: Vec::new(),
            user: None,
            isolation: IsolationRequirement::Trusted,
            prefer_backend: None,
            pull_secret: None,
            bindings: vec![],
            post_launch: vec![],
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

    const UB: u32 = crate::worker::USERNS_HOST_BASE; // 100_000

    #[test]
    fn derive_base_maps_the_runtime_uid_onto_the_volumes_existing_owner() {
        // The reused-volume repair: a data dir owned at a prior subuid base's target (200000 +
        // the RUNTIME postgres uid 999) derives base 200000 so postgres 999 maps onto 200999
        // with NO chown — regardless of the entrypoint/spec uid.
        assert_eq!(
            derive_base(200_999, 200_999, 999, 999, false, UB),
            Ok(200_000)
        );
        // A healthy volume at the configured rootless target (100000+999) derives the SAME
        // configured base — a relaunch is a no-op, never a regression.
        assert_eq!(
            derive_base(100_999, 100_999, 999, 999, false, UB),
            Ok(100_000)
        );
    }

    #[test]
    fn derive_base_fails_closed_on_unsafe_or_unmappable_owners() {
        // Owner == runtime id (no offset) ⇒ base 0 ⇒ in-container root → HOST root: refused off
        // host-root (the caller then REMAPs as host root instead; see the decision test).
        assert_eq!(
            derive_base(999, 999, 999, 999, false, UB),
            Err(BaseDeriveError::WouldMapHostRoot)
        );
        // Host-root posture (base 0) is the ONE place a 0 base is legitimate.
        assert_eq!(derive_base(999, 999, 999, 999, true, 0), Ok(0));
        // A base in (0, USERNS_HOST_BASE) would map onto low/system host uids ⇒ floor refusal.
        assert_eq!(
            derive_base(70_999, 70_999, 999, 999, false, UB),
            Err(BaseDeriveError::BelowFloor)
        );
        // …but host-root posture has no floor.
        assert_eq!(derive_base(70_999, 70_999, 999, 999, true, 0), Ok(70_000));
        // Owner below the runtime id ⇒ underflow ⇒ no base can map it.
        assert_eq!(
            derive_base(500, 500, 999, 999, false, UB),
            Err(BaseDeriveError::Unmappable)
        );
        // uid and gid demand DIFFERENT offsets ⇒ one map line can't satisfy both.
        assert_eq!(
            derive_base(200_999, 201_000, 999, 999, false, UB),
            Err(BaseDeriveError::Unmappable)
        );
        // An owner so high the mapped 65536-id window overflows u32 ⇒ refused.
        assert_eq!(
            derive_base(u32::MAX, u32::MAX, 0, 0, false, UB),
            Err(BaseDeriveError::RangeOverflow)
        );
    }

    #[test]
    fn parse_passwd_and_rootfs_base_helpers() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\npostgres:x:999:999:PG:/var/lib/postgresql:/bin/bash\n";
        assert_eq!(parse_passwd_ids(passwd, "postgres"), Some((999, 999)));
        assert_eq!(parse_passwd_ids(passwd, "root"), Some((0, 0)));
        assert_eq!(parse_passwd_ids(passwd, "mysql"), None);
        assert_eq!(
            parse_rootfs_base(Path::new("/x/abc.b200000")),
            Some(200_000)
        );
        assert_eq!(parse_rootfs_base(Path::new("/x/abc.b0")), Some(0));
        assert_eq!(parse_rootfs_base(Path::new("/x/no-suffix")), None);
    }

    // The fail-closed PLUMBING of the mapping decision (not just the pure arithmetic): injecting
    // an `OwnerConsensus` + the detected runtime ids, with NO filesystem/root needed.
    use crate::data_dir::OwnerConsensus;
    fn vol(name: &str, c: OwnerConsensus) -> (String, OwnerConsensus) {
        (name.to_string(), c)
    }

    #[test]
    fn mapping_decision_reads_reused_as_is_via_derived_base() {
        // Reused at a prior subuid base (200999 = 200000 + postgres 999): derive base 200000,
        // read AS-IS (chown None).
        let v = [vol(
            "data",
            OwnerConsensus::Uniform {
                uid: 200_999,
                gid: 200_999,
                entries: 10,
            },
        )];
        let m = resolve_mapping_decision(&v, 0, 0, Some((999, 999)), false, UB, true).expect("ok");
        assert_eq!(
            m,
            ResolvedMapping {
                base: 200_000,
                chowns: vec![None]
            },
            "reused data read as-is at the derived base, never chowned"
        );
    }

    #[test]
    fn mapping_decision_non_db_reused_maps_via_the_spec_uid() {
        // A NON-DB stateful workload (runtime == its own spec/guest uid, passed by the caller as
        // the fallback): a reused volume maps (read as-is), NOT refused. Here guest 1000, reused
        // owner 201000 → derive base 200000.
        let v = [vol(
            "state",
            OwnerConsensus::Uniform {
                uid: 201_000,
                gid: 201_000,
                entries: 10,
            },
        )];
        let m = resolve_mapping_decision(&v, 1000, 1000, Some((1000, 1000)), false, UB, true)
            .expect("non-DB reused must map, not refuse");
        assert_eq!(
            m,
            ResolvedMapping {
                base: 200_000,
                chowns: vec![None]
            }
        );
    }

    #[test]
    fn mapping_decision_reused_plus_fresh_sibling_no_false_conflict() {
        // A reused data volume + a FRESH sibling must NOT false-conflict: both share the derived
        // base; the reused one reads as-is (None), the fresh one chowns to base+guest.
        let v = [
            vol(
                "data",
                OwnerConsensus::Uniform {
                    uid: 200_999,
                    gid: 200_999,
                    entries: 10,
                },
            ),
            vol("cache", OwnerConsensus::Empty),
        ];
        let m = resolve_mapping_decision(&v, 999, 999, Some((999, 999)), false, UB, true)
            .expect("reused + fresh sibling must launch");
        assert_eq!(
            m,
            ResolvedMapping {
                base: 200_000,
                chowns: vec![None, Some((200_999, 200_999))]
            },
            "shared base 200000; reused read as-is, fresh chowned to base+guest"
        );
    }

    #[test]
    fn mapping_decision_fresh_volume_chowns_to_the_configured_base() {
        let v = [vol("data", OwnerConsensus::Empty)];
        let m =
            resolve_mapping_decision(&v, 999, 999, Some((999, 999)), false, UB, true).expect("ok");
        assert_eq!(
            m,
            ResolvedMapping {
                base: UB,
                chowns: vec![Some((UB + 999, UB + 999))]
            }
        );
    }

    #[test]
    fn mapping_decision_fresh_managed_db_chowns_to_runtime_uid_not_entrypoint() {
        // A managed DB with a ROOT entrypoint: spec/guest uid 0, but the DB runs as the DETECTED
        // image runtime uid (postgres 999). A FRESH dir must be pre-owned as `base + RUNTIME`
        // (base+999), NOT `base + guest` (base+0 = container root) — else a cap-dropped entrypoint
        // (no CAP_CHOWN) can't re-own PGDATA to postgres and initdb EPERMs. This reproduces the
        // Provisor `control`/bramp-db crash-loop: Empty consensus, guest 0, runtime 999.
        let v = [vol("data", OwnerConsensus::Empty)];
        let m = resolve_mapping_decision(&v, 0, 0, Some((999, 999)), false, UB, true)
            .expect("fresh managed-DB dir maps");
        assert_eq!(
            m,
            ResolvedMapping {
                base: UB,
                chowns: vec![Some((UB + 999, UB + 999))]
            },
            "fresh managed-DB dir pre-owned as base+runtime (postgres 999), not base+guest (root 0)"
        );
        // The OLD code chowned to base+guest = UB+0 = UB (container root), which a cap-dropped
        // entrypoint could not re-own → the crash-loop. Mutation: revert to guest_uid here.
    }

    #[test]
    fn mapping_decision_mixed_ownership_is_refused() {
        let v = [vol(
            "data",
            OwnerConsensus::Mixed {
                first_uid: 200_999,
                first_gid: 200_999,
                conflict_path: "global/pg_filenode.map".into(),
                conflict_uid: 0,
                conflict_gid: 0,
            },
        )];
        let e = resolve_mapping_decision(&v, 0, 0, Some((999, 999)), false, UB, true)
            .expect_err("mixed must fail closed");
        assert!(format!("{e}").contains("MIXED ownership"), "got {e}");
    }

    #[test]
    fn mapping_decision_owner_equals_runtime_remaps_not_base_zero() {
        // Owner == runtime id (999) ⇒ base-0 derive refused; host root REMAPS in place to
        // userns_base+runtime (NOT a base-0 host-root mapping).
        let v = [vol(
            "data",
            OwnerConsensus::Uniform {
                uid: 999,
                gid: 999,
                entries: 10,
            },
        )];
        let m =
            resolve_mapping_decision(&v, 0, 0, Some((999, 999)), false, UB, true).expect("remap");
        assert_eq!(
            m,
            ResolvedMapping {
                base: UB,
                chowns: vec![Some((UB + 999, UB + 999))]
            },
            "owner==runtime is remapped in place (base stays the rootless base, never 0)"
        );
        // …but WITHOUT host root (can_remap=false) it fails closed — never base 0, never reinit.
        let e = resolve_mapping_decision(&v, 0, 0, Some((999, 999)), false, UB, false)
            .expect_err("no remap without host root");
        assert!(format!("{e}").contains("HOST root"), "got {e}");
    }

    #[test]
    fn mapping_decision_conflicting_volumes_are_refused() {
        let v = [
            vol(
                "data",
                OwnerConsensus::Uniform {
                    uid: 200_999,
                    gid: 200_999,
                    entries: 5,
                },
            ),
            vol(
                "wal",
                OwnerConsensus::Uniform {
                    uid: 300_999,
                    gid: 300_999,
                    entries: 5,
                },
            ),
        ];
        let e = resolve_mapping_decision(&v, 0, 0, Some((999, 999)), false, UB, true)
            .expect_err("two owners need two bases");
        assert!(format!("{e}").contains("CONFLICTING"), "got {e}");
    }

    #[test]
    fn mapping_decision_reused_without_detectable_runtime_uid_fails_closed() {
        let v = [vol(
            "data",
            OwnerConsensus::Uniform {
                uid: 200_999,
                gid: 200_999,
                entries: 5,
            },
        )];
        let e = resolve_mapping_decision(&v, 0, 0, None, false, UB, true)
            .expect_err("no runtime uid ⇒ refuse to guess");
        assert!(format!("{e}").contains("runtime uid"), "got {e}");
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

        let art = backend
            .materialize("default", "pg", &spec, None)
            .await
            .expect("materialize");
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
        let art2 = backend
            .materialize("default", "pg", &spec, None)
            .await
            .expect("materialize 2");
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

        let art = backend
            .materialize("default", "pg", &spec, None)
            .await
            .expect("materialize image");
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
            .materialize("default", "pg", &spec, None)
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

        // Per-volume chowns (here both read-as-is — the chown path itself is the root-gated live
        // seam); a mapping with one entry per volume exercises the multi-volume plumbing.
        let mapping = ResolvedMapping {
            base: backend.userns_base,
            chowns: vec![None, None],
        };
        let mounts = backend
            .stage_volumes("acme-pg", &spec, &mapping)
            .await
            .expect("stage volumes");
        assert_eq!(mounts.len(), 2);
        // Each maps the host backing dir → the in-guest mount, and the dir exists. The backing
        // dir is now nested under the per-(project, workload) SCOPE, closing the cross-tenant
        // collision where two workloads' same-named volumes shared one flat dir.
        assert_eq!(mounts[0].mount, "/data");
        assert!(mounts[0].source.ends_with("/compute/volumes/@acme-pg/db"));
        assert!(PathBuf::from(&mounts[0].source).is_dir());
        assert!(
            mounts[1]
                .source
                .ends_with("/compute/volumes/@acme-pg/cache")
        );
        assert!(PathBuf::from(&mounts[1].source).is_dir());

        // Idempotent: staging again re-uses the existing dirs.
        let again = backend
            .stage_volumes("acme-pg", &spec, &mapping)
            .await
            .expect("stage volumes 2");
        assert_eq!(again, mounts);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    /// A rootfs dir with an `/etc/passwd` giving `postgres` the `999:999` the stock
    /// postgres/mysql images run as. Returns the dir (the caller removes it).
    fn rootfs_with_passwd(label: &str) -> PathBuf {
        let dir = unique_dir(label);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(
            dir.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\n\
             postgres:x:999:999::/var/lib/postgresql:/bin/bash\n",
        )
        .unwrap();
        dir
    }

    #[tokio::test]
    async fn init_process_ids_launches_a_managed_db_as_its_detected_runtime_uid() {
        let data_dir = unique_dir("launchids");
        let backend = ContainerBackend::new(
            Arc::new(OneBlob(Vec::new())),
            data_dir.clone(),
            "br-boatramp".into(),
            "10.0.0.0/24",
            PathBuf::from("/proc/self/exe"),
        )
        .expect("backend");
        let rootfs = rootfs_with_passwd("launchids-rootfs");

        // A managed DB (PGDATA env ⇒ `db_user_for_spec` = postgres), no operator `user`: launched
        // AS the DETECTED image runtime uid (999), NOT the namespace-root default (0). Running as
        // 999 makes the stock entrypoint take its non-root path (skips the cap-needing
        // chown/chmod/gosu), so a FRESH init works on a cap-dropped node. 999 is also exactly the
        // uid the data dir is pre-owned as (`base + runtime`), so the entrypoint owns its data.
        let db = spec_with_volume_kind("data", true);
        assert_eq!(db.user, None, "a managed-DB spec leaves user unset");
        assert_eq!(
            backend.init_process_ids(&db, &rootfs).await,
            (999, 999),
            "a managed DB launches as its detected runtime uid, not container-root"
        );

        // A non-DB workload keeps the spec's namespace-root default (0,0) — byte-for-byte
        // unchanged (`db_runtime_ids` is `None`, so the detection never fires).
        let generic = spec_with_volume_kind("data", false);
        assert_eq!(
            backend.init_process_ids(&generic, &rootfs).await,
            (GUEST_UID, GUEST_GID),
            "a non-DB workload's launch uid is unchanged"
        );

        // An operator-set `user` always wins, even for a managed DB (mirrors
        // `PrivilegeDirective::apply`'s operator-wins rule).
        let mut pinned = spec_with_volume_kind("data", true);
        pinned.user = Some("1234:1234".into());
        assert_eq!(
            backend.init_process_ids(&pinned, &rootfs).await,
            (1234, 1234),
            "an explicit operator user is honored over the detected image uid"
        );

        // A managed DB whose image `/etc/passwd` can't be read falls back to the spec's own ids
        // (never a panic, never a blind guess).
        let no_passwd = unique_dir("launchids-nopw");
        std::fs::create_dir_all(&no_passwd).unwrap();
        assert_eq!(
            backend
                .init_process_ids(&spec_with_volume_kind("data", true), &no_passwd)
                .await,
            (GUEST_UID, GUEST_GID),
            "an unreadable image /etc/passwd falls back to the spec uid"
        );

        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&rootfs);
        let _ = std::fs::remove_dir_all(&no_passwd);
    }

    // --- Legacy-volume migration (the cross-tenant collision fix) -----------------------

    /// Build a volume-management backend over a fresh data dir, with an optional
    /// legacy-`data` claimant.
    fn migration_backend(
        data_dir: &std::path::Path,
        claimant: Option<(&str, &str)>,
    ) -> ContainerBackend {
        ContainerBackend::new(
            Arc::new(OneBlob(Vec::new())),
            data_dir.to_path_buf(),
            "br-boatramp".into(),
            "10.0.0.0/24",
            PathBuf::from("/proc/self/exe"),
        )
        .expect("backend")
        .with_legacy_data_claimant(claimant.map(|(p, w)| (p.to_string(), w.to_string())))
    }

    /// A single-volume spec whose volume is named `vol`. `managed` makes it a managed-DB spec
    /// (a `PGDATA` env so [`db_user_for_spec`] detects it), which the contended-`"data"`
    /// claimant rule keys on; otherwise it is a GENERIC compute spec (a `/bin/hello`
    /// entrypoint), for which the `"data"` volume adopts 1:1 and never fails closed.
    fn spec_with_volume_kind(vol: &str, managed: bool) -> ComputeSpec {
        use boatramp_core::compute::VolumeRef;
        let mut s = spec_for(&"d".repeat(64));
        if managed {
            s.env
                .insert("PGDATA".into(), "/var/lib/postgresql/data".into());
        }
        s.volumes = vec![VolumeRef {
            mount: "/var/lib/postgresql/data".into(),
            name: vol.into(),
            size_mib: 128,
        }];
        s
    }

    /// A single-volume MANAGED-DB spec whose volume is named `vol`.
    fn spec_with_volume(vol: &str) -> ComputeSpec {
        spec_with_volume_kind(vol, true)
    }

    /// Seed a legacy flat volume dir `<volumes>/<name>` with a sentinel file; return the
    /// sentinel's path so a test can assert it survived the migration byte-for-byte.
    fn seed_legacy_volume(data_dir: &std::path::Path, name: &str, sentinel: &str) -> PathBuf {
        let dir = data_dir.join("compute").join("volumes").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("PG_VERSION");
        std::fs::write(&f, sentinel).unwrap();
        f
    }

    #[tokio::test]
    async fn migration_db_shaped_spec_cannot_steal_a_non_data_legacy_dir() {
        // The blocking-HIGH attack: a MANAGED/DB-shaped spec (PGDATA env ⇒ `db_user_for_spec`
        // Some) must NOT be able to adopt a non-`"data"` node-global legacy dir by setting
        // `vol.name` to a victim's digest-unique name. `db_user_for_spec` is attacker-forgeable,
        // so it cannot gate this tenancy boundary — the backend adopts a non-`"data"` legacy dir
        // from NO spec (managed-looking or not); only the node-trusted `"data"` claimant adopts.
        // (Mutation: re-add the `else if db_user_for_spec(spec).is_none()` branch and a DB-shaped
        // spec steals `<volumes>/pg-victim_abc`.)
        let data_dir = unique_dir("mig-steal");
        let backend = migration_backend(&data_dir, None);
        // Victim tenant's EXCLUSIVE, unmigrated legacy Single dir (digest-unique name).
        seed_legacy_volume(&data_dir, "pg-victim_abc", "VICTIM-PII");
        // Attacker (a DIFFERENT project) crafts a DB-shaped spec naming the victim's dir.
        let db_shaped = spec_with_volume("pg-victim_abc"); // managed shape (PGDATA env)
        let err = backend
            .adopt_legacy_volumes("attacker", "evil", "attacker@evil", &db_shaped)
            .await
            .expect_err("a DB-shaped spec must NOT adopt a non-`data` legacy dir");
        assert!(
            format!("{err}").contains("will not adopt a non-`data` legacy directory"),
            "actionable fail-closed refusal, got: {err}"
        );
        // Victim's data is byte-untouched; the attacker got no scoped dir (nothing stolen).
        assert_eq!(
            std::fs::read_to_string(data_dir.join("compute/volumes/pg-victim_abc/PG_VERSION"))
                .unwrap(),
            "VICTIM-PII"
        );
        assert!(!data_dir.join("compute/volumes/@attacker@evil").exists());
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn migration_adopts_shared_data_only_for_the_proven_claimant() {
        // The contended `"data"` dir is adopted by the designated claimant...
        let data_dir = unique_dir("mig-claim");
        let backend = migration_backend(&data_dir, Some(("default", "pg")));
        seed_legacy_volume(&data_dir, "data", "PROVISOR-CLUSTER");
        let spec = spec_with_volume("data");

        backend
            .adopt_legacy_volumes("default", "pg", "pg", &spec)
            .await
            .expect("claimant adopts the shared data volume");
        let scoped = data_dir.join("compute/volumes/@pg/data/PG_VERSION");
        assert_eq!(
            std::fs::read_to_string(&scoped).unwrap(),
            "PROVISOR-CLUSTER",
            "the owner's cluster is preserved under its scoped dir"
        );
        assert!(
            !data_dir.join("compute/volumes/data").exists(),
            "legacy shared dir migrated away"
        );
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn migration_refuses_shared_data_for_a_non_claimant_and_preserves_it() {
        // ...and a NON-owner fails closed, leaving the shared data byte-for-byte in place
        // (this is the control-plane-colocated case: `control` must not seize `default`'s
        // cluster). This is the mutation-sensitive invariant — neutering the claimant check
        // would let `control` adopt a neighbor's data.
        let data_dir = unique_dir("mig-refuse");
        let backend = migration_backend(&data_dir, Some(("default", "pg")));
        seed_legacy_volume(&data_dir, "data", "PROVISOR-CLUSTER");
        let spec = spec_with_volume("data");

        let err = backend
            .adopt_legacy_volumes("default", "control", "control", &spec)
            .await
            .expect_err("a non-owner must fail closed, not adopt");
        assert!(
            format!("{err}").contains("not its proven owner"),
            "actionable refusal, got: {err}"
        );
        // The owner's data is untouched; `control` got no scoped dir.
        assert_eq!(
            std::fs::read_to_string(data_dir.join("compute/volumes/data/PG_VERSION")).unwrap(),
            "PROVISOR-CLUSTER"
        );
        assert!(!data_dir.join("compute/volumes/@control").exists());
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn migration_fails_closed_for_shared_data_when_owner_is_ambiguous() {
        // No claimant (ambiguous ⇒ `None`): EVERY contender for the shared `data` dir fails
        // closed, so the data is never fresh-initialized over / orphaned.
        let data_dir = unique_dir("mig-ambig");
        let backend = migration_backend(&data_dir, None);
        seed_legacy_volume(&data_dir, "data", "CLUSTER");
        let spec = spec_with_volume("data");
        for wl in ["pg", "control"] {
            backend
                .adopt_legacy_volumes("default", wl, wl, &spec)
                .await
                .expect_err("ambiguous shared data ⇒ fail closed");
        }
        assert_eq!(
            std::fs::read_to_string(data_dir.join("compute/volumes/data/PG_VERSION")).unwrap(),
            "CLUSTER"
        );
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn migration_generic_data_volume_fails_closed_and_cannot_steal_a_managed_cluster() {
        // A GENERIC (non-managed-DB) compute workload that names a volume "data" must NOT be
        // able to adopt the contended legacy `data` cluster — it runs arbitrary tenant code and
        // is never the claimant, so adopting a legacy MANAGED cluster (e.g. the control-plane
        // DB) would be a cross-tenant disclosure at rest + orphan the real owner. The
        // contended-"data" rule is gated on the NAME ALONE, so this fails closed. (Mutation:
        // re-add an `is_managed_db &&` guard and this workload would STEAL the cluster.)
        let data_dir = unique_dir("mig-generic");
        // Claimant is the MANAGED owner default/pg — NOT the generic workload.
        let backend = migration_backend(&data_dir, Some(("default", "pg")));
        seed_legacy_volume(&data_dir, "data", "MANAGED-CLUSTER");
        let generic = spec_with_volume_kind("data", false);

        let err = backend
            .adopt_legacy_volumes("acme", "web", "acme@web", &generic)
            .await
            .expect_err("a generic non-owner must FAIL CLOSED on a legacy `data` cluster");
        assert!(
            format!("{err}").contains("not its proven owner"),
            "actionable refusal, got: {err}"
        );
        // The managed owner's cluster is untouched (not stolen); the generic workload got no
        // scoped dir.
        assert_eq!(
            std::fs::read_to_string(data_dir.join("compute/volumes/data/PG_VERSION")).unwrap(),
            "MANAGED-CLUSTER"
        );
        assert!(!data_dir.join("compute/volumes/@acme@web").exists());

        // ...and the PROVEN managed claimant can still adopt its own cluster.
        let managed = spec_with_volume("data");
        backend
            .adopt_legacy_volumes("default", "pg", "pg", &managed)
            .await
            .expect("the proven claimant adopts the legacy cluster");
        assert_eq!(
            std::fs::read_to_string(data_dir.join("compute/volumes/@pg/data/PG_VERSION")).unwrap(),
            "MANAGED-CLUSTER"
        );
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn migration_generic_workload_cannot_adopt_a_custom_named_legacy_dir() {
        // F1: a GENERIC workload's claim to a NON-`"data"` flat name is unprovable — names like
        // `pgdata`/`cache` are tenant-chosen (not globally unique) and the legacy layout was
        // node-global, so `<volumes>/<name>` may be ANOTHER tenant's data. A generic workload
        // must NOT auto-adopt an existing legacy flat dir (renaming it on first-declare steals
        // it — the same crafted-name theft as `"data"`, for non-`"data"` names). (Mutation: let
        // a generic spec fall through to the 1:1 adopt and tenant B steals tenant A's `pgdata`.)
        let data_dir = unique_dir("mig-f1");
        let backend = migration_backend(&data_dir, None);
        // Tenant A's EXCLUSIVE legacy volume named "pgdata" (never collided pre-fix).
        seed_legacy_volume(&data_dir, "pgdata", "TENANT-A-DATA");
        // Tenant B's generic workload declares the same name, co-located, launches first.
        let generic = spec_with_volume_kind("pgdata", false);
        let err = backend
            .adopt_legacy_volumes("beta", "web", "beta@web", &generic)
            .await
            .expect_err("a generic workload must NOT steal a custom-named legacy dir");
        assert!(
            format!("{err}").contains("will not adopt a non-`data` legacy directory"),
            "actionable generic refusal, got: {err}"
        );
        // Tenant A's data is byte-untouched; B got no scoped dir (nothing stolen/renamed).
        assert_eq!(
            std::fs::read_to_string(data_dir.join("compute/volumes/pgdata/PG_VERSION")).unwrap(),
            "TENANT-A-DATA"
        );
        assert!(!data_dir.join("compute/volumes/@beta@web").exists());

        // With NO legacy dir, a generic workload proceeds normally (adopt is a no-op; stage
        // creates the scoped dir fresh) — it only fails closed on an EXISTING legacy dir.
        let data_dir2 = unique_dir("mig-f1-fresh");
        let backend2 = migration_backend(&data_dir2, None);
        let generic2 = spec_with_volume_kind("cache", false);
        backend2
            .adopt_legacy_volumes("beta", "web", "beta@web", &generic2)
            .await
            .expect("a generic workload with no legacy dir proceeds (fresh)");
        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&data_dir2);
    }

    #[tokio::test]
    async fn migration_rejects_traversing_or_reserved_prefix_volume_names() {
        // HIGH: the adopt path builds host paths from `vol.name`, so it MUST validate the name
        // before constructing any path — a `".."` name would escape `<volumes>/`, and an
        // `@<victimscope>` name would ALIAS another workload's scope dir (the rename would
        // steal the victim's whole scope). Both must be rejected on the adopt path.
        let data_dir = unique_dir("mig-badname");
        let backend = migration_backend(&data_dir, None);
        // Seed a victim scope dir that an `@`-named volume would try to alias/rename.
        let victim = data_dir.join("compute/volumes/@victim/data");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("PG_VERSION"), "VICTIM-DATA").unwrap();

        for bad in ["..", "@victim", "a/b"] {
            let spec = spec_with_volume_kind(bad, false);
            let err = backend
                .adopt_legacy_volumes("acme", "web", "acme@web", &spec)
                .await
                .unwrap_err();
            assert!(
                format!("{err}").contains("invalid volume"),
                "name {bad:?} must be rejected as an invalid volume, got: {err}"
            );
        }
        // The victim's scope was never touched by the `@victim`-named attempt.
        assert_eq!(
            std::fs::read_to_string(victim.join("PG_VERSION")).unwrap(),
            "VICTIM-DATA"
        );
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn migration_is_a_noop_when_fresh_or_empty() {
        let data_dir = unique_dir("mig-fresh");
        let backend = migration_backend(&data_dir, None);
        let spec = spec_with_volume("data");
        // No legacy dir at all ⇒ Ok, nothing created (stage_volumes makes the scoped dir).
        backend
            .adopt_legacy_volumes("default", "pg", "pg", &spec)
            .await
            .expect("fresh ⇒ no-op");
        assert!(!data_dir.join("compute/volumes/@pg/data").exists());
        // An EMPTY legacy `data` dir is treated as fresh (never adopted), so it can neither be
        // mistaken for a cluster nor block a non-claimant.
        std::fs::create_dir_all(data_dir.join("compute/volumes/data")).unwrap();
        backend
            .adopt_legacy_volumes("default", "control", "control", &spec)
            .await
            .expect("empty legacy data ⇒ no-op, no refusal");
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn migration_refuses_to_overlay_an_existing_destination() {
        // Refuse-on-exist: adopting onto a destination that already exists must ABORT, never
        // merge two clusters into one.
        let data_dir = unique_dir("mig-exist");
        let backend = migration_backend(&data_dir, None);
        let legacy = data_dir.join("compute/volumes/legacy");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("f"), "x").unwrap();
        let scoped = data_dir.join("compute/volumes/@acme-pg/legacy");
        std::fs::create_dir_all(&scoped).unwrap();
        std::fs::write(scoped.join("other"), "y").unwrap();

        let err = backend
            .adopt_one_legacy_volume(&legacy, &scoped, "acme", "pg", "legacy")
            .await
            .expect_err("destination exists ⇒ refuse-on-exist");
        assert!(format!("{err}").contains("already exists"), "got: {err}");
        // Both dirs intact — nothing merged.
        assert!(legacy.join("f").exists() && scoped.join("other").exists());
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn bulk_migrate_legacy_volumes_moves_only_authorized_preserving_data() {
        // F4: the node-side bulk migration (`migrate_legacy_volumes`) moves each node-authorized
        // `(project, workload, volume_name)` triple's legacy flat dir to its scoped dir — a true
        // multi-tenant fixture (distinct digest names + distinct sentinel data + a default `data`
        // cluster), asserting ZERO cross-tenant mixing, that an UNAUTHORIZED legacy dir is left
        // untouched, and that it is idempotent + input-validated.
        let data_dir = unique_dir("mig-bulk");
        let backend = migration_backend(&data_dir, None);
        seed_legacy_volume(&data_dir, "pg-acme_a", "ACME");
        seed_legacy_volume(&data_dir, "pg-beta_b", "BETA");
        seed_legacy_volume(&data_dir, "data", "NODE-DEFAULT-PG");
        seed_legacy_volume(&data_dir, "unauth", "SOMEONE-ELSE"); // NOT in the authorized set
        let authorized = vec![
            (
                "acme".to_string(),
                "pg-acme_a".to_string(),
                "pg-acme_a".to_string(),
            ),
            (
                "beta".to_string(),
                "pg-beta_b".to_string(),
                "pg-beta_b".to_string(),
            ),
            // the node-default pg claimant for the legacy `data` cluster: (default, pg) ⇒ scope "pg"
            ("default".to_string(), "pg".to_string(), "data".to_string()),
            // a forged/bad name must be skipped, never traverse:
            ("x".to_string(), "x".to_string(), "..".to_string()),
        ];

        let n = backend.migrate_legacy_volumes(&authorized).await;
        assert_eq!(n, 3, "exactly the 3 valid authorized tenants migrated");

        // Each moved to its OWN scoped dir with its OWN sentinel — zero cross-mixing.
        let read = |p: &str| std::fs::read_to_string(data_dir.join(p)).unwrap();
        assert_eq!(
            read("compute/volumes/@acme@pg-acme_a/pg-acme_a/PG_VERSION"),
            "ACME"
        );
        assert_eq!(
            read("compute/volumes/@beta@pg-beta_b/pg-beta_b/PG_VERSION"),
            "BETA"
        );
        assert_eq!(
            read("compute/volumes/@pg/data/PG_VERSION"),
            "NODE-DEFAULT-PG"
        );
        // Legacy flat dirs of the migrated tenants are gone; the UNAUTHORIZED one is untouched.
        assert!(!data_dir.join("compute/volumes/pg-acme_a").exists());
        assert!(!data_dir.join("compute/volumes/data").exists());
        assert_eq!(read("compute/volumes/unauth/PG_VERSION"), "SOMEONE-ELSE");

        // Idempotent: a re-run migrates nothing and disturbs nothing.
        assert_eq!(backend.migrate_legacy_volumes(&authorized).await, 0);
        assert_eq!(
            read("compute/volumes/@acme@pg-acme_a/pg-acme_a/PG_VERSION"),
            "ACME"
        );
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn list_and_remove_volumes_over_the_backing_dir() {
        let data_dir = unique_dir("volmgmt");
        let backend = ContainerBackend::new(
            Arc::new(OneBlob(Vec::new())),
            data_dir.clone(),
            "br-boatramp".into(),
            "10.0.0.0/24",
            PathBuf::from("/proc/self/exe"),
        )
        .expect("backend");

        // Nothing staged yet ⇒ empty list (no volumes dir), never an error.
        assert!(backend.list_volumes().await.expect("list empty").is_empty());

        // Stage two backing dirs with known content sizes.
        let vols = data_dir.join("compute").join("volumes");
        std::fs::create_dir_all(vols.join("db/sub")).unwrap();
        std::fs::write(vols.join("db/a.bin"), vec![7u8; 100]).unwrap();
        std::fs::write(vols.join("db/sub/b.bin"), vec![7u8; 23]).unwrap();
        std::fs::create_dir_all(vols.join("cache")).unwrap();
        std::fs::write(vols.join("cache/c.bin"), vec![1u8; 5]).unwrap();
        // A stray non-directory entry at the root is ignored (not a volume).
        std::fs::write(vols.join("stray-file"), b"x").unwrap();

        let listed = backend.list_volumes().await.expect("list");
        assert_eq!(listed.len(), 2, "two volume dirs, stray file ignored");
        // Sorted by name: cache then db.
        assert_eq!(listed[0].name, "cache");
        assert_eq!(listed[0].size_bytes, 5);
        assert_eq!(listed[1].name, "db");
        assert_eq!(listed[1].size_bytes, 123, "recursive sum across subdirs");

        // Remove one → it's gone; the other survives.
        assert!(backend.remove_volume("db").await.expect("remove db"));
        assert!(!vols.join("db").exists());
        let after = backend.list_volumes().await.expect("list after");
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].name, "cache");

        // Removing an absent volume reports "did not exist" (idempotent, no error).
        assert!(!backend.remove_volume("db").await.expect("remove absent"));

        // A traversing name is rejected before touching the fs.
        assert!(backend.remove_volume("../etc").await.is_err());
        assert!(backend.remove_volume("a/b").await.is_err());

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn chown_tree_to_walks_the_whole_tree_and_skips_correct_owner() {
        // Build a Postgres-data-dir-shaped nested tree and target the CURRENT owner (what
        // freshly-created files already have), so the walk visits every entry while the
        // skip-already-correct path makes it a no-op — provable WITHOUT root. The foreign-uid
        // REPAIR (chowning files written under a different owner) needs root and is covered
        // by the live Linux gate; here we prove the traversal reaches every nested entry
        // (the bug was a top-dir-only chown that never descended into `global/`, `base/…`).
        use std::os::unix::fs::MetadataExt;
        let tmp = std::env::temp_dir().join(format!("brchown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("global")).unwrap();
        std::fs::write(tmp.join("global").join("pg_filenode.map"), b"x").unwrap();
        std::fs::write(tmp.join("PG_VERSION"), b"16").unwrap();
        std::fs::create_dir_all(tmp.join("base").join("1")).unwrap();
        std::fs::write(tmp.join("base").join("1").join("1259"), b"y").unwrap();
        let me = std::fs::symlink_metadata(tmp.join("PG_VERSION")).unwrap();
        // No-op chown to the current owner: must succeed and leave the deep file intact.
        chown_tree_to(&tmp, me.uid(), me.gid()).expect("recursive chown walk reaches every entry");
        let deep = std::fs::symlink_metadata(tmp.join("base").join("1").join("1259")).unwrap();
        assert_eq!(
            deep.uid(),
            me.uid(),
            "walk descended to the nested cluster file"
        );
        assert!(tmp.join("global").join("pg_filenode.map").exists());
        let _ = std::fs::remove_dir_all(&tmp);
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

    // -----------------------------------------------------------------------
    // A2: pool-vs-reality GC. The pure `gc_reclaim_keys` decides which tracked keys
    // to reclaim given a parked set + a container-alive predicate; the
    // `IpLifecycle::gc_release` wiring then applies the last-user rule. The cgroup
    // probe itself is the Linux seam (`container_cgroup_alive`), verified by review.
    // -----------------------------------------------------------------------

    fn key(p: &str, w: &str, r: u32) -> (String, String, u32) {
        (p.to_string(), w.to_string(), r)
    }

    #[test]
    fn container_id_is_clamped_to_the_uts_hostname_limit() {
        // A short id (every currently-working deployment, incl. the 52-byte production
        // case) is byte-identical — no digest, fully readable.
        assert_eq!(container_id("default", "web", 0), "web-0");
        assert_eq!(container_id("acme", "pg", 0), "acme-pg-0");

        // The exampleorg-preview case: a long project makes the per-tenant Single id
        // embed the project twice and overrun 64 bytes → it must be clamped, not passed
        // to `sethostname` verbatim (which EINVALs and crash-loops the container). The
        // tenant ident tail is padded here so the raw id comfortably exceeds the limit.
        let project = "exampleorg-preview";
        let workload = "pg-exampleorg_preview_enzr6qk3m2p8x7v9w1y3z5"; // 44-char tenant ident
        let raw = compute_instance_id(project, workload, 0);
        assert!(
            raw.len() > HOSTNAME_MAX,
            "precondition: the raw id must overrun (got {})",
            raw.len()
        );
        let clamped = container_id(project, workload, 0);
        assert!(
            clamped.len() <= HOSTNAME_MAX,
            "clamped id must be a legal hostname (got {})",
            clamped.len()
        );
        // Deterministic: idempotent teardown/relaunch/GC depend on it.
        assert_eq!(clamped, container_id(project, workload, 0));
        // The readable head is preserved (a prefix of the raw id).
        assert!(raw.starts_with(&clamped[..20]));

        // Collision-resistant: two long ids sharing a >52-char prefix but diverging only
        // in the tail must NOT collapse to the same hostname (a plain truncate would).
        let pad = "pg-exampleorg_preview_commonprefixpaddddddddd_"; // 46 chars, shared
        let a = container_id(project, &format!("{pad}aaaa"), 0);
        let b = container_id(project, &format!("{pad}bbbb"), 0);
        assert!(a.len() <= HOSTNAME_MAX && b.len() <= HOSTNAME_MAX);
        assert_eq!(a[..20], b[..20], "shared readable head");
        assert_ne!(a, b, "distinct long ids must clamp to distinct hostnames");
    }

    #[test]
    fn gc_reclaims_only_dead_and_not_parked() {
        let tracked = vec![
            key("default", "pg", 0),  // alive → keep
            key("default", "web", 0), // dead + not parked → RECLAIM
            key("acme", "cache", 0),  // dead but PARKED → keep (its IP is held for the wake)
        ];
        let parked: std::collections::BTreeSet<_> = [key("acme", "cache", 0)].into_iter().collect();
        // Only default/pg/0 has a "live container".
        let alive = |k: &(String, String, u32)| *k == key("default", "pg", 0);

        let reclaim = gc_reclaim_keys(&tracked, &parked, alive);
        assert_eq!(
            reclaim,
            vec![key("default", "web", 0)],
            "reclaim only the dead, non-parked replica"
        );
    }

    #[test]
    fn gc_reclaims_nothing_when_all_alive_or_parked() {
        let tracked = vec![key("default", "a", 0), key("default", "b", 0)];
        let parked: std::collections::BTreeSet<_> = [key("default", "b", 0)].into_iter().collect();
        // a is alive; b is parked → nothing to reclaim.
        let alive = |k: &(String, String, u32)| *k == key("default", "a", 0);
        assert!(gc_reclaim_keys(&tracked, &parked, alive).is_empty());
    }

    #[test]
    fn gc_release_frees_a_dead_replicas_ip_but_respects_last_user() {
        // Two replicas share .2 (a stale collision on disk). GC-releasing the first
        // must NOT free .2 while the second still holds it (last-user rule); releasing
        // the second then frees it.
        let mut life = IpLifecycle::new(IpAuthority::new("10.0.0.0/24").unwrap());
        life.reserve_for("default", "a", 0, Ipv4Addr::new(10, 0, 0, 2));
        life.reserve_for("default", "b", 0, Ipv4Addr::new(10, 0, 0, 2));

        let freed_a = life.gc_release(&key("default", "a", 0));
        assert_eq!(freed_a, Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(
            !life.authority.is_free(Ipv4Addr::new(10, 0, 0, 2)),
            ".2 still held by b (last-user rule)"
        );
        let freed_b = life.gc_release(&key("default", "b", 0));
        assert_eq!(freed_b, Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(
            life.authority.is_free(Ipv4Addr::new(10, 0, 0, 2)),
            ".2 freed once its last holder is reclaimed"
        );
        // Reclaiming an untracked key is a no-op (returns None).
        assert_eq!(life.gc_release(&key("default", "gone", 9)), None);
    }

    #[test]
    fn ephemeral_container_id_is_unique_clamped_and_prefixed() {
        let a = ephemeral_container_id();
        let b = ephemeral_container_id();
        // Recognizable as a one-shot + never collides with a workload id (`<workload>-N`).
        assert!(a.starts_with("ephm-"), "got {a}");
        // Always a legal UTS hostname (clamped) and an ifname-safe input.
        assert!(a.len() <= HOSTNAME_MAX && b.len() <= HOSTNAME_MAX);
        // The monotonic sequence guarantees two back-to-back ids never collide.
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn resolve_client_rootfs_uses_an_absolute_airgap_path_verbatim() {
        // An absolute air-gap path is a preloaded rootfs used AS-IS (never pulled): map a
        // client image to an existing dir and assert resolve returns exactly it.
        let dir = unique_dir("airgap-rootfs");
        std::fs::create_dir_all(&dir).unwrap();
        let image = "pgvector/pgvector:pg16";
        let backend = ContainerBackend::new(
            Arc::new(OneBlob(Vec::new())),
            unique_dir("airgap-data"),
            "br-test".into(),
            "10.0.0.0/24",
            PathBuf::from("/bin/true"),
        )
        .unwrap()
        .with_client_image_rootfs(BTreeMap::from([(
            image.to_string(),
            dir.display().to_string(),
        )]));
        let got = backend
            .resolve_client_rootfs(image)
            .await
            .expect("air-gap rootfs resolves");
        assert_eq!(got, dir, "the preloaded rootfs is used verbatim (no pull)");

        // A mapped-but-missing absolute path fails CLOSED (never silently falls back to a
        // pull — an air-gap operator asked for this exact rootfs).
        let backend = backend.with_client_image_rootfs(BTreeMap::from([(
            image.to_string(),
            "/nonexistent/air-gap/rootfs".to_string(),
        )]));
        assert!(
            backend.resolve_client_rootfs(image).await.is_err(),
            "a missing preloaded rootfs must error, not fall back to a pull"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_ephemeral_rejects_empty_argv() {
        let backend = ContainerBackend::new(
            Arc::new(OneBlob(Vec::new())),
            unique_dir("ephm-argv"),
            "br-test".into(),
            "10.0.0.0/24",
            PathBuf::from("/bin/true"),
        )
        .unwrap();
        let mut sink: Vec<u8> = Vec::new();
        let err = backend
            .run_ephemeral("busybox:latest", &[], &[], None, &mut sink)
            .await
            .expect_err("empty argv is rejected before any pull/launch");
        assert!(matches!(err, BackendError::Other(m) if m.contains("empty argv")));
    }

    #[test]
    fn ephemeral_ip_alloc_release_does_not_touch_the_replica_map() {
        // An ephemeral IP is transient: allocated from the shared pool but NEVER recorded
        // in the (project,workload,replica) ownership map, so it is not adopted/GC'd as a
        // replica — and released the moment the run ends.
        let mut life = IpLifecycle::new(IpAuthority::new("10.0.0.0/24").unwrap());
        let ip = life.allocate_ephemeral().expect("allocate ephemeral");
        assert!(!life.authority.is_free(ip), "held while the run is live");
        assert!(
            life.assigned_keys().is_empty(),
            "an ephemeral IP must not enter the replica ownership map"
        );
        life.release_ephemeral(ip);
        assert!(life.authority.is_free(ip), "released when the run ends");
    }

    #[tokio::test]
    async fn container_backend_shares_the_injected_ip_authority() {
        // A5 wiring at the backend seam: a ContainerBackend built with a shared
        // authority reserves into THAT pool, so a peer view (another backend's clone)
        // sees the reservation — proving the container backend no longer owns a private
        // pool once `with_ip_authority` is used.
        let shared = IpAuthority::new("10.0.0.0/24").unwrap();
        let backend = ContainerBackend::new(
            Arc::new(OneBlob(Vec::new())),
            unique_dir("ipauth"),
            "br-test".into(),
            "10.0.0.0/24",
            std::path::PathBuf::from("/bin/true"),
        )
        .unwrap()
        .with_ip_authority(shared.clone());
        // Adopt a running replica through the backend (feeds the shared pool).
        backend
            .reserve_in_use(&[("default".into(), "pg".into(), 0, Ipv4Addr::new(10, 0, 0, 2))])
            .await;
        // The peer view (a co-located VMM backend would hold this clone) sees .2 taken.
        assert!(
            !shared.is_free(Ipv4Addr::new(10, 0, 0, 2)),
            "the container backend reserved into the SHARED pool"
        );
    }

    /// GATE (M1): under the multi-tenant posture (`with_require_pinned_client_image(true)`), a
    /// one-shot client image resolved by an unauthenticated on-demand pull of a MUTABLE tag is
    /// refused BEFORE any network pull; an `@sha256:`-pinned ref or a preloaded air-gap mapping is
    /// accepted. The single-tenant default keeps the convenient tag pull.
    #[tokio::test]
    async fn ephemeral_client_image_pin_policy() {
        let data_dir = unique_dir("pinpolicy");
        let mk = |require: bool, map: std::collections::BTreeMap<String, String>| {
            ContainerBackend::new(
                Arc::new(OneBlob(Vec::new())),
                data_dir.clone(),
                "br-boatramp".into(),
                "10.0.0.0/24",
                PathBuf::from("/proc/self/exe"),
            )
            .expect("backend")
            .with_require_pinned_client_image(require)
            .with_client_image_rootfs(map)
        };

        // Strict + a mutable tag + no air-gap mapping ⇒ refused before any pull.
        let strict = mk(true, std::collections::BTreeMap::new());
        let err = strict
            .resolve_client_rootfs("postgres:16")
            .await
            .expect_err("mutable tag must be refused under the pin policy");
        assert!(
            matches!(&err, BackendError::Materialize(m) if m.contains("multi-tenant")),
            "refusal names the posture, got: {err:?}"
        );

        // Strict + a preloaded air-gap rootfs (absolute dir) ⇒ accepted (bypasses the pull).
        let preload = unique_dir("airgap-rootfs");
        std::fs::create_dir_all(&preload).unwrap();
        let mapped = mk(
            true,
            std::collections::BTreeMap::from([(
                "postgres:16".to_string(),
                preload.display().to_string(),
            )]),
        );
        assert_eq!(
            mapped.resolve_client_rootfs("postgres:16").await.unwrap(),
            preload,
            "an air-gap-mapped image bypasses the pin policy"
        );

        // A digest-pinned ref passes the policy gate (the subsequent pull is a separate concern;
        // here we only assert the policy does NOT refuse it — the error, if any, is a pull error,
        // never the multi-tenant refusal).
        let pinned = mk(true, std::collections::BTreeMap::new());
        if let Err(BackendError::Materialize(m)) = pinned
            .resolve_client_rootfs("postgres:16@sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .await
        {
            assert!(
                !m.contains("multi-tenant"),
                "a digest-pinned ref must pass the pin policy; got a posture refusal: {m}"
            );
        }

        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&preload);
    }

    /// GATE (L2): the boot sweep SELECTS only `ephm-*` one-shot cgroups, never a live workload cgroup
    /// (`<workload>-<n>`), and is silent when the cgroup subtree is absent. Asserts the PURE SELECTION
    /// (`ephemeral_cgroup_dirs`) — the security-relevant property — not the cgroupfs kill+rmdir
    /// mechanics: a plain temp dir cannot model cgroupfs (there `cgroup.kill` is a real file, not a
    /// pseudo-file, so the sweep's write would leave the dir non-empty and `rmdir` would fail, whereas
    /// on real cgroupfs `rmdir` removes the empty cgroup). So selectivity is what we gate here.
    #[test]
    fn ephemeral_cgroup_sweep_is_prefix_selective() {
        let root = unique_dir("cgroup-sweep");
        for d in ["ephm-123-0", "ephm-456-1", "pg-0", "web-2"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }

        let selected: std::collections::BTreeSet<String> = ephemeral_cgroup_dirs(&root)
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(String::from))
            .collect();
        let want: std::collections::BTreeSet<String> =
            ["ephm-123-0".to_string(), "ephm-456-1".to_string()]
                .into_iter()
                .collect();
        assert_eq!(
            selected, want,
            "only ephm-* one-shot cgroups are selected; a live workload cgroup (pg-0/web-2) is \
             never swept"
        );

        // Absent subtree ⇒ empty selection + the sweep is a silent 0 (no panic).
        assert!(ephemeral_cgroup_dirs(&root.join("does-not-exist")).is_empty());
        assert_eq!(sweep_ephemeral_cgroups_in(&root.join("does-not-exist")), 0);

        let _ = std::fs::remove_dir_all(&root);
    }
}
