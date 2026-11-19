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
use crate::registry_auth::{RegistryAuth, RegistryAuthResolver};

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

/// The per-workload **guest-log redaction set**: the resolved VALUES of env vars whose
/// SOURCE is a secret (the `{{sql.*}}` managed-DB DSN/password, an unsealed
/// `boatramp:<name>` secret-store ref, an external-vault value, a managed-service
/// generated key), collected at env-resolution time (see [`launch_one`]) so a backend
/// can redact them out of the forwarded guest-log stream.
///
/// Provenance, not name: a value lands here ONLY when it was *injected by a
/// secret-bearing resolver* (the binding resolver or the managed-DB server-init env) —
/// never an operator-set literal. The distinction is exactly the one `launch_one`
/// already makes when folding the resolved env into the spec (a hand-set literal wins and
/// is NOT collected; an injected/templated value IS).
///
/// Held in a [`Zeroizing`](zeroize::Zeroizing) buffer so the plaintext is scrubbed from
/// memory when the request drops, and carries a **redacting [`Debug`]** so it never
/// prints a secret value (it is a transient launch-request field, never persisted or
/// serialized). The zeroizing is **best-effort**: the same values are co-resident,
/// unzeroized, in the sibling [`LaunchRequest::spec`]'s `env` map (a plain `BTreeMap` the
/// backend must hand to the container/VM as its environment, by design) — that is the
/// larger residue, inherent to injecting env at all. This buffer just avoids keeping an
/// extra non-scrubbed copy and keeps the set out of `Debug`/serialization.
#[derive(Clone, Default)]
pub struct RedactionSet(zeroize::Zeroizing<Vec<String>>);

impl RedactionSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self(zeroize::Zeroizing::new(Vec::new()))
    }

    /// Record one secret-sourced resolved value.
    pub fn push(&mut self, value: String) {
        self.0.push(value);
    }

    /// The collected secret VALUES (to build a backend-side matcher from). Backends feed
    /// these into `boatramp_guestlog::Redactor::build`, which applies the min-length floor
    /// and de-dups.
    #[must_use]
    pub fn values(&self) -> &[String] {
        &self.0
    }

    /// Whether nothing was collected (a workload with no secret-sourced env).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many secret-sourced values were collected (diagnostics only — never exposes a
    /// value).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Redacting `Debug`: a count, never a value — so the set cannot leak through a
/// `{:?}` of the enclosing [`LaunchRequest`].
impl std::fmt::Debug for RedactionSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RedactionSet(<{} secret-sourced values>)", self.0.len())
    }
}

/// The request to launch one replica.
#[derive(Debug, Clone)]
pub struct LaunchRequest {
    /// The owning project — the first dimension of the replica identity, so two
    /// projects each with a same-named workload can't collide on the backend's
    /// derived id/cgroup/veth/IP. `default` yields the bare, pre-project identity
    /// (see [`compute_instance_id`]).
    pub project: String,
    /// Workload name (for naming / teardown / logging).
    pub workload: String,
    /// Replica ordinal within the workload (`0..replicas`).
    pub replica: u32,
    /// The immutable spec to run.
    pub spec: ComputeSpec,
    /// The materialized artifact for `spec`.
    pub artifact: Artifact,
    /// The secret-sourced env VALUES to redact from this workload's forwarded guest-log
    /// stream (see [`RedactionSet`]). Populated by [`launch_one`] from the resolved
    /// binding / managed-DB env; empty for a workload with no secret-sourced env. A
    /// backend builds its per-workload log redactor from this (unless the node-global
    /// redaction opt-out is set). Transient — never persisted or serialized.
    pub redaction: RedactionSet,
}

/// An opaque handle to a launched replica (for `stop`/`health`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceHandle {
    /// The owning project — the first dimension of the replica identity, closing
    /// the cross-tenant collision where two projects' same-named workloads derived
    /// the same backend id/cgroup/veth/IP. `#[serde(default)]` keeps pre-v0.3.12
    /// records deserializing; the reconcile/adoption **backfills** it from the
    /// replica-state KV key (`project/<proj>/…`) when empty, so a legacy record gets
    /// its real project — never `""` — before any id is derived. Schema stays v1.
    #[serde(default)]
    pub project: String,
    /// Workload name.
    pub workload: String,
    /// Replica ordinal.
    pub replica: u32,
    /// Backend-specific reference (pid / container id / CF instance id / …).
    pub backend_ref: String,
}

/// The backend-derived identity stem for a replica, unique across projects:
/// `<project>-<workload>-<replica>` for a non-`default` project, but the bare
/// `<workload>-<replica>` for the reserved `default` project (and for an empty
/// project string — a not-yet-backfilled legacy handle — which is treated as
/// `default`). This stem keys the cgroup path, the container/VM id, the hostname,
/// the veth/tap stem, and the guest log filename; the bare default form keeps
/// existing default-project deployments byte-identical on disk (mirroring how the
/// managed-volume/credential names keep `default` bare). Components are all
/// cgroup/interface/hostname-safe (resource names are `[a-z0-9-]`) and carry no `/`
/// ([`validate_resource_name`]).
///
/// NOTE — the `-` join is NOT injective: because a slug may contain an interior `-`,
/// `("a","b-c")` and `("a-b","c")` both derive `a-b-c-<replica>`. So two *distinct*
/// non-`default` `(project, workload)` pairs can, for crafted names, collapse to the same
/// id/cgroup/veth/hostname. This pre-existing identity keying inherits that collision; it is
/// NOT changed here (re-encoding would move every existing container's on-disk cgroup/veth/
/// hostname). The per-volume scope ([`compute_volume_scope`]) uses an injective `@` join
/// instead, since it is new and data-at-rest keying must not alias across tenants.
pub fn compute_instance_id(project: &str, workload: &str, replica: u32) -> String {
    if project.is_empty() || project == crate::project::DEFAULT_PROJECT {
        format!("{workload}-{replica}")
    } else {
        format!("{project}-{workload}-{replica}")
    }
}

/// The RFC 1035 single-label limit: one dot-separated component of a hostname is at most
/// **63 octets**. Docker 29's libnetwork refuses to publish an embedded-DNS service-discovery
/// record for a label longer than this (Docker 28 and earlier silently tolerated it), so a
/// per-project-network ALIAS over 63 octets never resolves on 29.x — a sibling gets NXDOMAIN
/// even though the container's endpoint joined the network and `docker inspect` shows the
/// alias. This was empirically confirmed on a Docker 29.9.1 host (a 69-char alias failed to
/// register; a 13-char one resolved; the only discriminator was the length, not the charset).
pub const DNS_LABEL_MAX_LEN: usize = 63;

/// Whether `s` is a resolvable single DNS label on a docker embedded-DNS network: 1..=63
/// octets, each byte ASCII alphanumeric or `-`/`_`, not starting or ending with `-`. (`_`
/// is deliberately accepted — boatramp's sanitized tenant idents contain it and Docker 29's
/// embedded DNS registers it fine; the empirically-decisive constraint is the 63-octet
/// length, which this enforces as [`DNS_LABEL_MAX_LEN`].)
pub fn is_valid_dns_label(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > DNS_LABEL_MAX_LEN {
        return false;
    }
    if b[0] == b'-' || b[b.len() - 1] == b'-' {
        return false;
    }
    b.iter()
        .all(|&c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// The service-discovery ALIAS a co-located workload is published under on its per-project
/// docker network — and, identically, the hostname a sibling composes into the managed-DB
/// DSN it resolves. It MUST be a valid DNS label (≤ [`DNS_LABEL_MAX_LEN`] octets) or Docker
/// 29's embedded DNS will not register it (see [`DNS_LABEL_MAX_LEN`]).
///
/// The compute workload NAME is the stable identity (container name, deploy-store key,
/// per-tenant volume, sealed credential) and is intentionally left long and byte-stable. For
/// a `Single`-isolation managed database that name is `<compute>-<sanitized-tenant-ident>`
/// where BOTH halves already carry a 25-char digest, so it routinely exceeds 63 octets
/// (`bramp-db-<25>-<body>_<25>` ≈ 69). Resolving a workload by that over-long name is exactly
/// what broke on Docker 29.9.1 — the alias was the full workload name.
///
/// This maps a workload name to a short, STABLE, DNS-valid alias used for BOTH the network
/// endpoint alias (`boatramp-docker`'s `launch`) AND the DSN host a consumer resolves
/// (`NodeTenantSqlResolver::connection_parts`), so the two always MATCH:
///
/// - A name that already fits (≤ 63 octets) is returned UNCHANGED — so every current working
///   name (a short user workload, a `Shared` server's plain `<compute>`) stays byte-identical
///   and behavior/existing deployments are unaffected. This is also why Docker 28 was always
///   fine: its names registered regardless of length.
/// - A longer name is replaced by `bramp-db-<25-char base-36 digest of the full name>` (34
///   octets): a fixed-width, collision-resistant (128-bit SHA-256-derived) label in the
///   `[a-z0-9-]` grammar with a letter lead. Being a pure function of the workload name, the
///   launch alias and the DSN host derive the IDENTICAL string.
///
/// Uniqueness only has to hold WITHIN one project's isolated network; the 128-bit digest makes
/// a collision between two distinct workload names cryptographically negligible, and colliding
/// with a short literal `bramp-db-<…>` workload would require an operator to name a workload
/// the exact 25-char digest — not a reachable accident.
pub fn managed_db_alias(workload: &str) -> String {
    if workload.len() <= DNS_LABEL_MAX_LEN {
        return workload.to_string();
    }
    use sha2::{Digest, Sha256};
    // Leading 128 bits of SHA-256, re-encoded base-36 at a fixed 25-char width (36^25 > 2^128),
    // mirroring the managed-DB workload digest scheme so operators see a familiar shape.
    let hex = hex::encode(Sha256::digest(workload.as_bytes()));
    let mut n = u128::from_str_radix(&hex[..32], 16).expect("32 hex chars are a valid u128");
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut buf = [b'0'; 25];
    let mut i = buf.len();
    while n > 0 && i > 0 {
        i -= 1;
        buf[i] = DIGITS[(n % 36) as usize];
        n /= 36;
    }
    format!(
        "bramp-db-{}",
        String::from_utf8(buf.to_vec()).expect("base-36 digits are ASCII")
    )
}

/// The **per-(project, workload) scope** a backend keys a persistent volume's host
/// backing directory under, so two co-located workloads that name a volume identically
/// never collide on one host directory. It identifies `(project, workload)` (a volume
/// persists across a workload's replicas, so no replica ordinal): the bare `<workload>` for
/// the reserved `default` project (and for an empty project string — a not-yet-backfilled
/// legacy handle — treated as `default`), and `<project>@<workload>` for a non-`default`
/// project.
///
/// The join uses `@`, NOT `-`, and this is load-bearing: `@` is outside the resource-slug
/// alphabet (`[A-Za-z0-9_-]`) that both components are drawn from, so the join is INJECTIVE —
/// distinct `(project, workload)` pairs always map to distinct scopes. A `-` join is not
/// (`("a","b-c")` and `("a-b","c")` would both give `a-b-c`), which would reopen the very
/// cross-tenant collision this closes for crafted multi-project names. `@` also keeps a
/// non-`default` scope disjoint from every bare-`default` scope (which, being a lone slug,
/// never contains `@`). The scope is a single, filesystem-safe path component accepted by the
/// backend's `validate_volume_scope`.
///
/// Closing a cross-tenant collision: every managed database is handed a volume literally
/// named `"data"` (see [`managed_db_spec`]) and the native container backend used to back
/// it at `<data_dir>/compute/volumes/data` keyed by that bare name alone — so two
/// co-located managed DBs (a control-plane DB and a default-project DB, two shared servers,
/// …) shared ONE PGDATA on disk. Keying the backing directory by this scope gives each
/// `(project, workload)` its own directory. The bare `default` form keeps existing
/// default-project deployments byte-identical on disk, mirroring the managed-volume/credential
/// naming.
pub fn compute_volume_scope(project: &str, workload: &str) -> String {
    if project.is_empty() || project == crate::project::DEFAULT_PROJECT {
        workload.to_string()
    } else {
        format!("{project}@{workload}")
    }
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
    /// The owning project, carried so a `restore` derives the same project-qualified
    /// identity ([`compute_instance_id`]) / IPAM key the launch used. `#[serde(default)]`
    /// keeps pre-v0.3.12 parked records deserializing (empty ⇒ treated as `default`);
    /// backfilled alongside the handle from the replica-state key. Schema stays v1.
    #[serde(default)]
    pub project: String,
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

/// Why an operator [`ComputeControl`] operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// The workload's backend doesn't support the operation (e.g. a platform backend
    /// with no explicit `stop`).
    #[error("the {0} backend does not support this operation")]
    Unsupported(String),
    /// Any other failure (backend error, store error, …).
    #[error("compute control failed: {0}")]
    Other(String),
}

/// The operator-facing "kick the reconcile plane" capability — a targeted,
/// operator-triggered counterpart to the periodic reconcile. Backs
/// `POST /api/compute/maintenance/restart` (admin-scoped). The node implementation
/// resolves the replica, stops it via its backend, and drops its persisted observed
/// state, so the next reconcile pass relaunches a fresh replica (re-running IPAM) —
/// the live workaround for a wedged replica or a stale IP assignment.
#[async_trait]
pub trait ComputeControl: Send + Sync {
    /// Restart replica `replica` of `workload` in `project`: stop it and delete its
    /// observed state so the reconcile loop relaunches it. `Ok(false)` if no such
    /// replica is persisted (nothing to restart).
    async fn restart(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
    ) -> Result<bool, ControlError>;
}

/// A candidate / reaped ORPHANED replica in a [`ComputeReaper`] report. An orphan is a
/// replica whose DESIRED workload is absent (`compute get` 404) AND whose backing
/// container is affirmatively gone — stranded state the reconcile plane ignores (it
/// converges only against desired workloads). Carries no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrphanReplica {
    /// Owning project.
    pub project: String,
    /// Workload name (no desired record exists for it).
    pub workload: String,
    /// Replica ordinal.
    pub replica: u32,
    /// The backend id that ran it (`"container"`, `"docker"`, …).
    pub backend: String,
    /// Seconds since launch (`now − started_at`), or `None` for a legacy record with no
    /// `started_at` (which — because `started_at` predates orphaning — proves the record
    /// is OLD, never a just-launched replica).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<u64>,
    /// The scoped volume-staging directory (`@<scope>`) this replica's PGDATA / data
    /// occupies, for operator visibility — freed only when the reaper's opt-in volume
    /// reclamation is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_scope: Option<String>,
}

/// What the reaper did (or would do) to one orphan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReapDisposition {
    /// Dry-run / report-only: identified as reapable but NOT touched.
    WouldReap,
    /// Actually reaped (record dropped + container torn down).
    Reaped,
    /// A candidate that was SKIPPED fail-closed, with the reason (e.g. it gained a
    /// desired workload, its container is live/unknown, or it is not yet past grace).
    Skipped { reason: String },
}

/// One orphan's line in a [`ReapReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReapEntry {
    /// The orphan.
    pub orphan: OrphanReplica,
    /// What happened to it.
    pub disposition: ReapDisposition,
    /// Whether the scoped volume staging was freed (opt-in reclamation + not dry-run).
    #[serde(default)]
    pub volume_reclaimed: bool,
}

/// The result of a reaper pass. `dry_run` echoes the mode so a consumer can tell a
/// report-only run from a destructive one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReapReport {
    /// Whether this pass was dry-run (report-only).
    pub dry_run: bool,
    /// Per-orphan outcomes (reaped / would-reap / skipped).
    pub entries: Vec<ReapEntry>,
}

impl ReapReport {
    /// Orphans that were (or would be) reaped — i.e. the fail-closed decision admitted
    /// them. Excludes skipped candidates.
    #[must_use]
    pub fn admitted(&self) -> impl Iterator<Item = &ReapEntry> {
        self.entries.iter().filter(|e| {
            matches!(
                e.disposition,
                ReapDisposition::Reaped | ReapDisposition::WouldReap
            )
        })
    }
}

/// Which replicas a reap pass targets.
#[derive(Debug, Clone)]
pub enum ReapTarget {
    /// Scan every project's replicas for orphans.
    All,
    /// A single operator-named replica (the `boatramp compute reap` lever). Still
    /// re-checked fail-closed (no desired workload + container gone) before any destroy —
    /// naming a replica never bypasses the safety checks.
    One {
        project: String,
        workload: String,
        replica: u32,
    },
}

/// Options for a reap pass.
#[derive(Debug, Clone)]
pub struct ReapOptions {
    /// Which replicas to consider.
    pub target: ReapTarget,
    /// Minimum orphan age (seconds) required before acting (the race guard).
    pub grace_secs: u64,
    /// Report-only when `true` — nothing is destroyed.
    pub dry_run: bool,
    /// Also free the orphan's scoped volume staging (PGDATA). Off ⇒ the record +
    /// container are reaped but the volume is preserved (reported, not deleted).
    pub reclaim_volumes: bool,
}

/// Why a reaper operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ReaperError {
    /// A control-plane store failure while listing/deleting replica state.
    #[error("reaper store error: {0}")]
    Store(String),
    /// A backend failure while probing liveness / stopping / freeing staging.
    #[error("reaper backend error: {0}")]
    Backend(String),
}

/// The DESTRUCTIVE orphaned-compute-replica reaper (node-health-alerting Stage 2,
/// secondary ask). Backs both the leader-gated alerting loop's opt-in auto-reap and the
/// operator `boatramp compute reap` lever (`POST /api/compute/maintenance/reap`,
/// System·Admin). The node implementation ([`NodeComputeReaper`](../../boatramp_node))
/// is conservative BY CONSTRUCTION — it reaps a replica only when ALL hold, re-checked
/// at the moment of the destroy (fail-closed, so a wrong reap can never destroy a
/// running workload):
/// 1. the replica is `phase == Running` (a parked `Zero` replica is never reaped — its
///    container is *expected* to be absent);
/// 2. its DESIRED workload is absent (`get_compute_workload` ⇒ `None`);
/// 3. its backing container is AFFIRMATIVELY gone ([`ComputeBackend::replica_alive`] ⇒
///    `Some(false)`; `None`/`Some(true)` ⇒ skip); and
/// 4. it is past the grace window.
///
/// Every reap is AUDITED (a `tracing` record per orphan), and the default call path is
/// DRY-RUN (report-only). `scan` is the non-destructive observer the orphan *alert*
/// signal uses.
#[async_trait]
pub trait ComputeReaper: Send + Sync {
    /// Identify the current orphaned replicas (no destroy). The orphan ALERT signal +
    /// `boatramp compute reap --dry-run`-style listing read this. `grace_secs` bounds
    /// the age below which a replica is not yet considered an orphan.
    async fn scan(&self, grace_secs: u64) -> Result<Vec<OrphanReplica>, ReaperError>;

    /// Reap (or, in dry-run, report) orphaned replicas per `opts`. Re-derives
    /// orphan-ness fail-closed per replica immediately before any destroy.
    async fn reap(&self, opts: ReapOptions) -> Result<ReapReport, ReaperError>;
}

#[async_trait]
pub trait ComputeBackend: Send + Sync {
    /// Stable backend id (`"vmm"` / `"container"` / `"cloudflare"` / `"docker"`).
    fn id(&self) -> &'static str;

    /// What this backend can do here (used by the scheduler + policy gate).
    fn capabilities(&self) -> Capabilities;

    /// Stage `spec`'s artifact into whatever this backend boots from, for the replica
    /// identified by `(project, workload)`. Idempotent + content-addressed (cache/dedup by
    /// spec id). The identity is threaded in so a backend that backs persistent volumes on
    /// local disk (the native `container` backend) can key each volume's backing directory
    /// by the collision-free [`compute_volume_scope`] — the SAME identity its container
    /// id/cgroup/veth already use — closing the cross-tenant collision where two co-located
    /// workloads that name a volume identically (every managed DB's `"data"`) shared one
    /// host directory. A backend that delegates storage (cloudflare/docker) or derives
    /// nothing from the volume ignores the identity.
    ///
    /// `pull_auth` is the HOST-RESOLVED registry credential for an
    /// [`RootSource::Image`] pull (`None` ⇒ an anonymous/public pull, or a non-registry
    /// source). It is resolved fail-closed before launch (see
    /// [`RegistryAuthResolver`]), so a backend receives either a credential it MUST use
    /// to pull a private image, `None` for a public one, or the launch never reaches
    /// here (a referenced-but-missing credential already failed closed). A backend that
    /// pulls from a registry (docker) authenticates with it; a backend that cannot apply
    /// it to its pull path MUST fail closed rather than silently pull anonymously when it
    /// is `Some`.
    async fn materialize(
        &self,
        project: &str,
        workload: &str,
        spec: &ComputeSpec,
        pull_auth: Option<&RegistryAuth>,
    ) -> Result<Artifact, BackendError>;

    /// **Adopt** the guest IPs already assigned to persisted/running replicas of
    /// this backend, so a fresh-on-boot IP pool reflects addresses in use before it
    /// hands out any new one. Called once at node startup with every known replica as
    /// `(project, workload, replica, endpoint_ip)`; the backend reserves the ones it
    /// owns (those in its own subnet), skipping the rest, and remembers each replica's
    /// address — keyed by `(project, workload, replica)` so two projects' same-named
    /// workloads never share a slot — so a relaunch reclaims the same endpoint (stable)
    /// rather than a fresh one. Without this a backend that rebuilds its pool each
    /// process start (the native `container` backend) could re-hand a live address to
    /// a different workload — the container-IP collision. Backends that don't own a
    /// per-node IP pool (docker / cloudflare delegate addressing) default to a no-op,
    /// so they are unaffected.
    async fn reserve_in_use(&self, _replicas: &[(String, String, u32, std::net::Ipv4Addr)]) {}

    /// **Reconcile the IP pool against reality** (A2): reclaim addresses this backend
    /// still holds for replicas whose container is actually gone. Adoption reserves the
    /// IP of every persisted replica at boot; a replica whose container has since
    /// crashed (or whose state was removed out-of-band) would otherwise keep its IP
    /// reserved for the life of the process, slowly leaking the pool. This is called
    /// periodically with `parked` — the `(project, workload, replica)` keys that are
    /// intentionally down (scale-to-zero `Zero`) and MUST keep their IP for the wake —
    /// so the backend releases only the addresses it holds for a key that is **neither**
    /// live (no running container) **nor** parked. Backends without a per-node IP pool
    /// default to a no-op. Conservative by construction: a key is reclaimed only when
    /// the backend is sure the container is gone.
    async fn gc_ip_pool(&self, _parked: &[(String, String, u32)]) {}

    /// Launch one replica; returns its handle + routable endpoint.
    async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError>;

    /// Stop + clean up a replica (idempotent; safe on a half-launched instance).
    async fn stop(&self, handle: &InstanceHandle) -> Result<(), BackendError>;

    /// Liveness/readiness of a running replica.
    async fn health(&self, handle: &InstanceHandle) -> Result<Health, BackendError>;

    /// Whether a RUNNING replica's live **deployment shape** is OUTDATED versus `spec` and
    /// must be RECREATED even though its spec pointer is unchanged and it is healthy —
    /// a backend-specific auto-heal signal the reconcile folds into its recreate decision
    /// (see [`reconcile_plan`]'s `force_recreate`). The docker backend returns `true` for a
    /// container whose PRIMARY network is not the per-project network: such a container (one
    /// created by a release before the per-project net became the *primary* attachment) is
    /// up but cannot resolve its siblings by name, and only a recreate — which re-runs
    /// `launch` with the net as primary — fixes it. This lets the fix auto-heal pre-upgrade
    /// containers on the first reconcile after the upgrade, with NO manual `docker rm`.
    /// Idempotent: once the replica is on the current deployment shape it returns `false`
    /// and the reconcile is a no-op. The recreate is volume-SAFE (`stop` removes only the
    /// container, never its persistent volume). Default `false` — a backend with nothing to
    /// re-shape never forces a recreate, so non-docker backends are unaffected.
    async fn needs_redeploy(&self, _handle: &InstanceHandle, _spec: &ComputeSpec) -> bool {
        false
    }

    /// Re-discover a RUNNING replica's live routable [`Endpoint`], for the reconcile to
    /// detect an endpoint that drifted out from under the stored record **while the
    /// container keeps running under a stable identity** (so [`health`](Self::health)
    /// never flips and no Stop/Launch is planned). The motivating case is the docker
    /// `Published` mode: it publishes an **ephemeral** host port (`-p 127.0.0.1::<port>`,
    /// `host_port "0"`), and docker **REASSIGNS that host port on every in-place
    /// `--restart` restart** — an app that crash-exits (e.g. an OOM `137`) is relaunched
    /// by its restart policy under the SAME container name with a NEW host port. The
    /// container is `running` again, so `health` (run-state only) keeps reporting
    /// `Healthy` and nothing recreates it — yet the stored [`Endpoint`] still points at
    /// the dead old port, so the gateway dials it and 502s **forever** (the only recovery
    /// is a manual `compute restart`, which drops the state so the next reconcile Launches
    /// a fresh replica and re-discovers the port). The reconcile calls this each tick for
    /// a running replica and RE-POINTS the stored endpoint when it differs, so routing
    /// follows the live port with no container churn.
    ///
    /// `None` (the default) means the endpoint **cannot drift** for this backend (a fixed
    /// in-container port, `Bridge` mode, an external DSN) or the replica is **not
    /// currently resolvable** (down / restarting / gone) — in which case the stored
    /// endpoint is left as-is and the normal health + plan path owns it. A backend MUST
    /// return `None` rather than a guess, so a transient inspect failure never clobbers a
    /// good endpoint.
    async fn observed_endpoint(&self, _handle: &InstanceHandle) -> Option<Endpoint> {
        None
    }

    /// **Affirmative liveness** of a replica's backing container/VM, for the orphan
    /// reaper's fail-closed "is it gone?" decision — DISTINCT from [`health`](Self::health),
    /// which conflates *gone* with merely *unreachable*. Returns:
    /// - `Some(true)` — the container/VM is affirmatively LIVE (a process is running);
    /// - `Some(false)` — it is affirmatively GONE (no backing process/cgroup at all);
    /// - `None` — this backend cannot determine liveness (no local view, or an
    ///   un-probeable host).
    ///
    /// The reaper destroys a replica only on an explicit `Some(false)` — `None` (unknown)
    /// and `Some(true)` (live) both FAIL CLOSED (never reap). Default `None` so a backend
    /// that cannot prove a container is gone never licenses a reap.
    async fn replica_alive(&self, _handle: &InstanceHandle) -> Option<bool> {
        None
    }

    /// Remove the persistent **scoped** volume staging directory for `(project,
    /// workload)` — the `<volumes>/@<scope>/…` backing a managed DB's PGDATA — returning
    /// whether anything existed. Used ONLY by the orphan reaper's opt-in volume
    /// reclamation (the orphan has no desired workload referencing it). Distinct from
    /// [`remove_volume`](Self::remove_volume), which addresses the legacy FLAT
    /// `<volumes>/<name>` path and refuses a reserved `@`-prefixed name. Default
    /// `Ok(false)` so a backend without local volume staging frees nothing.
    async fn remove_scoped_volume(&self, _scope: &str) -> Result<bool, BackendError> {
        Ok(false)
    }

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

    /// Run a **one-shot ephemeral container** from `image` (no persisted workload,
    /// no replica identity), streaming its stdout to `stdout` as it is produced, and
    /// return the command's exit code. The lifeblood of project export/import: the
    /// client-image `pg_dump`/`pg_restore`/`psql` runs here, reaching the database
    /// over the network while its credential rides in `env` (never argv).
    ///
    /// Contract:
    /// - `argv` is the command + args (no shell).
    /// - `env` is the process environment as `(KEY, VALUE)` pairs — this is where a
    ///   DSN / `PGPASSWORD` belongs, so the credential never shows in `ps`/`inspect`
    ///   argv. Callers MUST NOT place a credential in `argv`.
    /// - `stdin`, when present, is a **reader streamed** to the command's standard input
    ///   as it is read (never buffered whole — a multi-gigabyte restore flows in with
    ///   bounded memory, symmetric with `stdout`), then the stream is half-closed (EOF).
    ///   It is fed **concurrently** with draining stdout so a large piped restore cannot
    ///   deadlock on a full pipe.
    /// - `stdout` receives the command's standard output **as a true byte stream** —
    ///   chunks are written straight through as they arrive, never buffered whole, so a
    ///   multi-gigabyte dump flows to the sink (a file / tar member) with bounded memory.
    ///   Standard error is captured (bounded) for diagnostics only.
    ///
    /// The container runs on the hardened baseline (dropped caps, read-only root,
    /// `no-new-privileges`, PID cap) with **no published port**, and is auto-removed on
    /// exit (with a best-effort force-remove fallback + a kill on timeout) so a hung run
    /// against an unreachable DSN can neither leak a container nor hang forever.
    ///
    /// Only the shared-kernel backend that can run an ad-hoc client container
    /// implements it (remote `docker`); the native `container`, VM, and edge backends
    /// return [`BackendError::Unsupported`]. The caller gates this behind the admin
    /// `System·Admin` export/import surface.
    async fn run_ephemeral(
        &self,
        _image: &str,
        _argv: &[String],
        _env: &[(String, String)],
        _stdin: Option<&mut (dyn futures::io::AsyncRead + Send + Unpin)>,
        _stdout: &mut (dyn futures::io::AsyncWrite + Send + Unpin),
    ) -> Result<i32, BackendError> {
        Err(BackendError::Unsupported)
    }

    /// Resolve a **direct, intra-backend-reachable host** for a running replica — e.g. a
    /// docker container's bridge IP — so another workload the same backend launches (a
    /// one-shot [`run_ephemeral`](Self::run_ephemeral) client) can reach it even when the
    /// operator-facing [`Endpoint`] is a host-loopback publish a sibling container cannot
    /// route to (the `Published` docker endpoint mode). `None` (the default) means the
    /// operator endpoint is already directly reachable (external DSNs, `Bridge` mode),
    /// so the caller uses it verbatim.
    async fn replica_direct_host(&self, _handle: &InstanceHandle) -> Option<String> {
        None
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

    /// Inspect a volume-backed workload's persistent data directory for a
    /// **data-dir-ownership fault** — files not owned by the guest process's uid:gid,
    /// which make a rootless managed database (Postgres/MySQL as uid `999`) `EPERM`
    /// reading its own cluster files. Returns a [`DataDirOwnership`] observation (`ok`
    /// plus, on a fault, a count and a sample) for a backend that owns an on-node volume
    /// directory (the native `container` backend); every other backend returns `None`
    /// (not applicable — it owns no local data directory to inspect, e.g. edge/VM
    /// backends, or docker where the daemon owns the volume).
    ///
    /// **Read-only**: it NEVER chowns — the repair is the launch-time pre-chown
    /// ([`stage_volumes`](ComputeBackend::launch)) or an operator volume/image fix, not
    /// this read. The reconcile calls it only while a managed replica is up-but-not-
    /// answering, and `db status` surfaces the result so an operator can tell a
    /// data-dir-ownership stall from a slow init — the signal `/api/repair` cannot give.
    async fn data_dir_ownership(
        &self,
        _project: &str,
        _workload: &str,
        _spec: &ComputeSpec,
    ) -> Option<DataDirOwnership> {
        None
    }

    /// **Node-authorized bulk migration** of managed-tenant legacy volume directories into the
    /// per-`(project, workload)` scoped layout (the proactive counterpart to the launch-time
    /// adoption). The node passes the `authorized` triples `(project, workload, volume_name)` it
    /// derived ENTIRELY from its OWN trusted control-plane state — never from a workload spec —
    /// so this safely migrates the digest-named managed-`Single` tenant directories that the
    /// launch-time path (correctly) REFUSES to adopt from an untrusted spec. For each triple
    /// whose legacy flat directory exists and whose scoped directory does not, a backend that
    /// backs on-node volumes performs the SAME atomic, refuse-on-exist rename as the launch path
    /// (bytes + ownership preserved, read-as-is; never a copy/chown/merge/delete). Idempotent
    /// (re-run safe: an already-scoped directory is skipped), and it touches ONLY the directories
    /// named by `authorized`. Backends that delegate storage default to a no-op. Returns the
    /// number of directories migrated.
    async fn migrate_legacy_volumes(&self, _authorized: &[(String, String, String)]) -> usize {
        0
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
        if let Some(pref) = &spec.prefer_backend
            && let Some(b) = self.backends.iter().find(|b| &b.id == pref && eligible(b))
        {
            return Some(b.id.clone());
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

/// A `(vCPU, memory-MiB)` resource amount — either a node's **remaining** schedulable
/// capacity or the reservation a replica holds against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Reservation {
    /// vCPUs.
    pub vcpus: u32,
    /// Memory in MiB.
    pub mem_mib: u32,
}

impl Reservation {
    /// The reservation `spec` holds — its declared vCPU/memory, floored at 1 each so an
    /// unspecified (`0`) dimension still occupies a slot, matching the placement fit check.
    fn of_spec(spec: &ComputeSpec) -> Self {
        Self {
            vcpus: spec.vcpus.max(1),
            mem_mib: spec.mem_mib.max(1),
        }
    }
}

/// Conservative reservation charged against a node for a **running** replica whose
/// reservation cannot be resolved — neither its own launched spec (`active_spec`) nor its
/// workload's current active spec is retrievable. Counting such a replica as **zero** would
/// overstate the node's free capacity and re-open the very over-subscription cumulative
/// bin-packing prevents, so the pre-pass charges this non-trivial floor (1 vCPU + 1 GiB —
/// one typical small workload, matching the node inventory's default memory floor) and
/// surfaces the replica in the reconcile report. It is a last resort: a legacy record's
/// `active_spec` is backfilled to the workload's active spec on observation, and a live
/// workload's active spec resolves — so it bites only a genuinely orphaned replica whose
/// spec blob is gone. Tunable should an operator's unresolved replicas run materially larger.
const UNRESOLVED_RESERVATION: Reservation = Reservation {
    vcpus: 1,
    mem_mib: 1024,
};

/// Per-node **remaining** schedulable capacity for a single reconcile pass, threaded
/// (mutable) across the pass's per-workload placement loop so that cumulative placements of
/// **different** workloads can no longer over-subscribe one node — true cumulative
/// bin-packing. Seeded from each node's advertised free vCPUs/memory
/// ([`advertised`](Self::advertised)), then debited by the reservations of every already-
/// running replica (the reconcile pre-pass) and by each new placement
/// ([`place_replicas_in`]).
///
/// The previous scheduler read each node's *advertised* figure fresh for every workload and
/// decremented only a throwaway copy, so N workloads that each fit a node alone could
/// collectively exceed it (each saw the full node). This type is the shared ledger that
/// closes that gap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeCapacities {
    remaining: BTreeMap<u64, Reservation>,
}

impl NodeCapacities {
    /// Seed remaining capacity from each node's **advertised** free vCPUs/memory. No replica
    /// reservations are debited yet — the reconcile pre-pass does that via [`reserve`](Self::reserve).
    pub fn advertised(nodes: &[Node]) -> Self {
        Self {
            remaining: nodes
                .iter()
                .map(|n| {
                    (
                        n.id,
                        Reservation {
                            vcpus: n.free_vcpus,
                            mem_mib: n.free_mem_mib,
                        },
                    )
                })
                .collect(),
        }
    }

    /// Remaining capacity on `node` (zero for an unknown node — never a placement target).
    fn get(&self, node: u64) -> Reservation {
        self.remaining.get(&node).copied().unwrap_or_default()
    }

    /// Whether `node` currently has room for `res`.
    fn fits(&self, node: u64, res: Reservation) -> bool {
        let have = self.get(node);
        have.vcpus >= res.vcpus && have.mem_mib >= res.mem_mib
    }

    /// Debit `res` from `node`'s remaining capacity (**saturating** at zero, so a node that a
    /// prior over-subscription already over-committed never underflows into a huge free
    /// figure). A node absent from the ledger is ignored — it is not a placement target.
    pub fn reserve(&mut self, node: u64, res: Reservation) {
        if let Some(r) = self.remaining.get_mut(&node) {
            r.vcpus = r.vcpus.saturating_sub(res.vcpus);
            r.mem_mib = r.mem_mib.saturating_sub(res.mem_mib);
        }
    }
}

/// Place `count` replicas of `spec` (subject to `placement` + `policy`) across `nodes`.
/// Eligibility = satisfies the placement constraints, currently fits the spec's CPU/mem,
/// **and** offers a policy-allowed backend whose isolation satisfies the spec. Worst-fit
/// (most-free node first) spreads load; capacity is decremented per placement. Returns fewer
/// than `count` when capacity/eligible backends run out (the caller surfaces the shortfall).
///
/// This is the single-call convenience wrapper: it starts from each node's advertised free
/// capacity afresh, so it does **not** account for replicas already running or for other
/// workloads placed this pass. The reconcile loop instead uses [`place_replicas_in`] with a
/// shared, pre-debited [`NodeCapacities`] to get true cumulative bin-packing.
pub fn place_replicas(
    count: u32,
    placement: &PlacementConstraints,
    spec: &ComputeSpec,
    nodes: &[Node],
    policy: &BackendPolicy,
) -> Vec<Placement> {
    let mut capacity = NodeCapacities::advertised(nodes);
    place_replicas_in(count, placement, spec, nodes, policy, &mut capacity)
}

/// Place `count` replicas of `spec` against the **shared** remaining-capacity ledger
/// `capacity`, debiting each placement from it so later placements (of this or any later
/// workload in the same reconcile pass) see the reduced capacity — the core of cumulative
/// bin-packing. Eligibility and worst-fit spread are as [`place_replicas`]; the only
/// difference is that remaining capacity is read from, and written back to, `capacity`
/// rather than a throwaway copy of each node's advertised figure.
///
/// Worst-fit picks the node with the most remaining vCPUs (then memory); ties are broken by
/// **lowest node id**, so placement is deterministic and independent of the membership
/// slice's order — a workload that can't fit everywhere lands on the same node across
/// reconciles and doesn't flap.
pub fn place_replicas_in(
    count: u32,
    placement: &PlacementConstraints,
    spec: &ComputeSpec,
    nodes: &[Node],
    policy: &BackendPolicy,
    capacity: &mut NodeCapacities,
) -> Vec<Placement> {
    let need = Reservation::of_spec(spec);

    // Placement-eligible nodes (region/label constraints), kept in membership order; the
    // per-node remaining capacity is read from (and debited to) the shared `capacity`.
    let eligible: Vec<&Node> = nodes
        .iter()
        .filter(|n| placement.allows(n.region.as_deref(), &n.labels))
        .collect();

    let mut placements = Vec::new();
    for _ in 0..count {
        // Worst-fit among nodes that currently fit `need` AND offer an eligible backend:
        // most-remaining-vCPU first, then memory, then lowest id (deterministic tie-break).
        let pick = eligible
            .iter()
            .filter(|n| capacity.fits(n.id, need) && n.pick_backend(spec, policy).is_some())
            .max_by(|a, b| {
                let (ra, rb) = (capacity.get(a.id), capacity.get(b.id));
                ra.vcpus
                    .cmp(&rb.vcpus)
                    .then(ra.mem_mib.cmp(&rb.mem_mib))
                    // Lower id wins the tie: make it compare as the greater element.
                    .then(b.id.cmp(&a.id))
            });
        match pick {
            Some(node) => {
                let backend = node
                    .pick_backend(spec, policy)
                    .expect("filtered to nodes with an eligible backend");
                placements.push(Placement {
                    node: node.id,
                    backend,
                });
                capacity.reserve(node.id, need);
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

/// Service-level readiness of a replica — **distinct from
/// [`ObservedInstance::healthy`]**, which is the backend's runner/TCP-level "the
/// process is up" (a bare `TcpStream::connect` for the native container backend; the
/// container being `running` for docker). The reconcile advances a replica through
/// these states after launch:
///
/// - [`Starting`](Readiness::Starting) → launched, service not yet readiness-probed.
/// - [`ServiceReady`](Readiness::ServiceReady) → the service answers its readiness
///   probe (a managed DB: a real `SELECT 1`; a generic workload: the backend health
///   check), but its post-launch actions have not completed.
/// - [`Provisioned`](Readiness::Provisioned) → service-ready AND every post-launch
///   action has completed. This is what the gated surfaces treat as *usable*.
/// - [`ProvisionFailed`](Readiness::ProvisionFailed) → a post-launch action failed;
///   surfaced (e.g. `db status`), retried on the next reconcile tick, and blocks the
///   gated surfaces.
/// - [`LaunchFailed`](Readiness::LaunchFailed) → the backend `launch` itself ERRORED
///   (image-pull denied, no node capacity accepted it, a backend fault) so no instance
///   ever started; carries the backend error. Persisted by the reconcile as a durable
///   marker — *without* it a failed launch left no replica state at all, so `compute
///   status` showed "no replicas" and `db status` a bare `pending`, with the real
///   reason living only in a transient log line (the multi-hour blind spot this closes).
///   Retried every tick like a broken launch; always blocks the gated surfaces.
///
/// *Which* surfaces require which level is configurable (the readiness-gate policy),
/// defaulting to [`Provisioned`](Readiness::Provisioned) for all of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Readiness {
    /// Launched; the service has not yet passed its service-level readiness probe.
    Starting,
    /// The service answers its readiness probe, but post-launch actions are not done.
    ServiceReady,
    /// Service-ready AND every post-launch action has completed — *usable*.
    Provisioned,
    /// A post-launch action failed; carries the reason. Retried next tick; gated.
    ProvisionFailed {
        /// Human-readable failure reason (no credential material).
        reason: String,
    },
    /// The backend `launch` ERRORED — no instance ever started (e.g. an image pull was
    /// denied, no eligible node accepted the placement, or a backend fault). Carries the
    /// backend error message so `compute status` / `db status` surface *why* a replica is
    /// missing instead of silently showing nothing. The reconcile persists this as a
    /// durable marker (phase stays [`Running`](ReplicaPhase::Running) with `healthy:
    /// false`) and retries the launch on the next tick; a successful relaunch overwrites
    /// it with a fresh [`Starting`](Readiness::Starting) record. Always gated (never
    /// routed): it has no live endpoint.
    LaunchFailed {
        /// Human-readable backend launch error (carries no credential material — the
        /// registry-auth layer's errors name only secret refs, never values).
        reason: String,
    },
}

impl Readiness {
    /// Whether this replica has completed its post-launch actions and is usable by a
    /// surface that requires full provisioning (the strict default gate).
    pub fn is_provisioned(&self) -> bool {
        matches!(self, Self::Provisioned)
    }

    /// Whether the service answered its readiness probe at least once — `ServiceReady`,
    /// `Provisioned`, OR `ProvisionFailed` (all three got past the `SELECT 1` probe; only
    /// `Starting` has not). A surface whose readiness-gate is relaxed to `service_ready`
    /// deliberately admits a replica that is up even if its post-launch provisioning did
    /// not complete; the strict `Provisioned` default still excludes `ProvisionFailed`.
    pub fn is_service_ready(&self) -> bool {
        matches!(
            self,
            Self::ServiceReady | Self::Provisioned | Self::ProvisionFailed { .. }
        )
    }
}

/// Back-compat default for [`ObservedInstance::readiness`]: a record written before the
/// field existed was an already-running replica, so it deserializes as
/// [`Provisioned`](Readiness::Provisioned) — it keeps routing across the upgrade, and
/// the next reconcile tick recomputes its real readiness. Keeps the stored schema v1.
fn readiness_provisioned_backcompat() -> Readiness {
    Readiness::Provisioned
}

/// Reduce a managed workload's observed replica states to the single most-informative
/// readiness signal (PLAN-managed-dependency-readiness WS4) — the shared primitive behind
/// every readiness-polling surface (`db status`'s `database_status`, `OperatorSql::readiness`)
/// so they report the identical, once-tested semantics instead of each re-deriving it.
/// Most-informative-wins: a FAILURE with its reason — a
/// [`LaunchFailed`](Readiness::LaunchFailed) (the launch never started) or a
/// [`ProvisionFailed`](Readiness::ProvisionFailed) (a post-launch action failed) — surfaces
/// over a sibling that is merely [`Starting`](Readiness::Starting);
/// [`Provisioned`](Readiness::Provisioned) means at least one replica is usable. `None` ⇒ no
/// RUNNING replica recorded (not launched yet, scaled to zero, or registered under a scope the
/// caller doesn't track) — "pending", distinct from `Starting` (launched but not yet probed).
/// A [`LaunchFailed`](Readiness::LaunchFailed) replica IS recorded `Running` (a durable failure
/// marker), so a launch that never started surfaces its reason here instead of looking like
/// "pending" / "no replicas".
pub fn reduce_readiness(states: &[ObservedInstance]) -> Option<Readiness> {
    let running: Vec<&Readiness> = states
        .iter()
        .filter(|s| s.phase == ReplicaPhase::Running)
        .map(|s| &s.readiness)
        .collect();
    if running.is_empty() {
        return None;
    }
    // A failure (with its reason) is the most actionable signal — surface it over a
    // merely-starting or provisioned sibling. `LaunchFailed` (the launch Err'd) takes
    // precedence over `ProvisionFailed` (it started but post-launch failed): a workload
    // that never came up at all is the more fundamental fault to report first.
    if let Some(failed) = running
        .iter()
        .find(|r| matches!(r, Readiness::LaunchFailed { .. }))
        .or_else(|| {
            running
                .iter()
                .find(|r| matches!(r, Readiness::ProvisionFailed { .. }))
        })
    {
        return Some((*failed).clone());
    }
    if running.iter().any(|r| r.is_provisioned()) {
        return Some(Readiness::Provisioned);
    }
    if running.iter().any(|r| r.is_service_ready()) {
        return Some(Readiness::ServiceReady);
    }
    Some(Readiness::Starting)
}

/// A **read-only** data-dir-ownership health observation for a volume-backed managed
/// database replica, surfaced by `boatramp db status`.
///
/// A managed database runs rootless inside its container (Postgres/MySQL as uid:gid
/// `999:999`), so its launch pre-chowns the volume's data directory to the guest process's
/// mapped host owner (`stage_volumes` → `chown_tree_to` in the container backend). When a
/// data directory instead carries **foreign-owned** files — a volume restored/cloned from
/// an env-export, carried over from a different user-namespace base, or a custom image
/// whose real uid differs from the assumed default — the database process gets `EPERM`
/// reading its own cluster files (`global/pg_filenode.map: Permission denied`), never
/// answers, and the replica is stuck [`Starting`](Readiness::Starting). That stall is
/// indistinguishable from a slow init on its own.
///
/// This observation names the data-dir-ownership fault explicitly (which volume, how many
/// foreign entries, a sample offending path + its actual owner), so an operator sees the
/// root cause and the fix — a **filesystem** repair (relaunch re-chowns the volume, or
/// correct the volume/image uid). That is exactly the blind spot `/api/repair` leaves: it
/// reconciles only in-pg provisioning drift (roles / ownership / grants), **never**
/// filesystem permissions.
///
/// Purely diagnostic: computing it NEVER chowns — repair stays the launch-time
/// `stage_volumes` path and the operator's volume/image fix, not this status read. The
/// uids are **host-level** (the on-disk owners after the user-namespace shift), so
/// `expected_*` and a sample entry's `uid`/`gid` compare like-for-like.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataDirOwnership {
    /// The volume whose data directory was scanned.
    pub volume: String,
    /// `true` iff every scanned entry is owned by the expected guest uid:gid. `false`
    /// means the database process will `EPERM` reading its own files — a filesystem repair
    /// is needed before it can ever become ready.
    pub ok: bool,
    /// The (host-level, namespace-mapped) uid the guest database process runs as — what
    /// the data directory's files SHOULD be owned by.
    pub expected_uid: u32,
    /// See [`expected_uid`](Self::expected_uid) — the expected gid.
    pub expected_gid: u32,
    /// Count of entries found NOT owned by the expected uid:gid, up to the scan's
    /// early-stop budget (`0` iff `ok`; a lower bound when the budget was hit).
    pub foreign_count: u64,
    /// A sample foreign-owned entry (its path relative to the volume root — no
    /// host-absolute path is leaked — plus its actual owner), set when `!ok`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample: Option<ForeignOwnedEntry>,
}

/// One foreign-owned entry sampled by a [`DataDirOwnership`] scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignOwnedEntry {
    /// Path relative to the volume's data-directory root.
    pub path: String,
    /// The entry's actual owner uid (host-level).
    pub uid: u32,
    /// The entry's actual owner gid (host-level).
    pub gid: u32,
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
    /// Service-level readiness, **distinct from `healthy`** (which is runner/TCP-level).
    /// Advanced by the reconcile's readiness pass (service-readiness probe + post-launch
    /// actions). `#[serde(default = …)]` deserializes older records (no field) as
    /// [`Provisioned`](Readiness::Provisioned) so an already-running replica keeps
    /// routing across the upgrade; the next tick recomputes it. Schema stays v1.
    #[serde(default = "readiness_provisioned_backcompat")]
    pub readiness: Readiness,
    /// A **read-only** data-dir-ownership health observation ([`DataDirOwnership`]), set by
    /// the reconcile only while a managed-database replica is up (`healthy`) but its
    /// service is not yet answering ([`Starting`](Readiness::Starting)) — the one window
    /// where a filesystem data-dir-ownership fault (foreign-owned files the rootless
    /// database process can't read) is the suspect behind an otherwise-opaque stall.
    /// `Some` with `ok == false` names the fault so `db status` shows the root cause
    /// `/api/repair` can't (it fixes only in-pg drift, never filesystem permissions).
    /// Cleared to `None` once the replica answers (it could read its data directory, so
    /// ownership is fine) or for a backend/workload with no on-node data directory to
    /// inspect. `#[serde(default)]` keeps older records deserializing — schema stays v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<DataDirOwnership>,
    /// The snapshot to restore from — `Some` iff `phase == Zero`.
    #[serde(default)]
    pub snapshot: Option<Snapshot>,
    /// The workload's **active spec pointer** ([`ComputeWorkload::active`], a
    /// `computever/<hash>` id) this replica was LAUNCHED from — recorded by
    /// `launch_one`. It is what lets the reconcile detect a REDEPLOY: when the
    /// workload's `active` later differs from this (an operator flipped the pointer to
    /// a new spec), [`reconcile_plan`] RECREATES the replica (stop + relaunch) so the
    /// NEW spec actually runs. Without it a spec change was invisible — an already-
    /// `healthy` replica was kept, and a shared-kernel backend's own restart policy
    /// (docker `restart: always`) merely restarted the OLD container IN PLACE, so the
    /// redeploy never re-ran `launch` (and, for docker, never re-attached the
    /// per-project network). The recreate is volume-SAFE: `stop` removes only the
    /// container/VM, never its persistent volume, so a managed DB's data survives.
    /// `None` — a legacy record written before this field, or a restored replica whose
    /// source spec is unknown — is treated as "matches" (never a spurious recreate);
    /// the reconcile BACKFILLS it to the current `active` on the next observation so a
    /// SUBSEQUENT redeploy is still detected. `#[serde(default)]` keeps older records
    /// deserializing — schema stays v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_spec: Option<String>,
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

/// One replica the planner needed to (re)launch but could **not place** this pass — a
/// capacity / eligibility shortfall. Surfaced by [`reconcile_plan`] (in
/// [`ReconcilePlan::unscheduled`]) so the driver records + logs it instead of silently
/// truncating the unplaced tail (the bug that hid a stuck workload from `compute status`
/// with zero diagnostics for hours).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unscheduled {
    /// Workload name.
    pub workload: String,
    /// The replica ordinal that got no placement.
    pub replica: u32,
    /// Human-readable reason (no eligible backend had capacity for the spec's needs).
    pub reason: String,
}

/// The output of [`reconcile_plan`]: the actions the driver executes **plus** the replicas
/// it could not place. Making the shortfall an explicit field (rather than letting the
/// zipped-and-truncated tail vanish) is what lets the driver turn a silent placement
/// failure into a logged, reported one.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReconcilePlan {
    /// The actions to execute against the backends, in order.
    pub actions: Vec<Action>,
    /// Replicas that needed a (re)launch but got no placement this pass. Empty on the
    /// happy path; non-empty names exactly which ordinals a capacity/eligibility shortfall
    /// left unscheduled, each with a reason.
    pub unscheduled: Vec<Unscheduled>,
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
/// if capacity runs out, the unplaced ordinals are returned in
/// [`ReconcilePlan::unscheduled`] (NOT silently dropped) so the driver surfaces the
/// shortfall.
///
/// A replica persisted in [`Readiness::LaunchFailed`] (a durable marker for a launch that
/// `Err`'d — see [`reconcile_once`]) is, while in range, treated as a free ordinal to
/// **relaunch** regardless of restart policy: it never started, so it is neither "healthy"
/// to keep nor a completed run-to-completion job to leave terminal, and nothing is Stopped
/// for it (there is no live instance) — exactly the retry a failed launch got before it was
/// recorded. Out of range (scaled down) it is Stopped like any replica, cleaning up the
/// stale marker.
///
/// `now` is the current wall-clock unix seconds, compared against each replica's
/// `started_at` for the startup-grace check.
///
/// `force_recreate` is the set of in-range replica ordinals the driver has independently
/// determined must be RECREATED regardless of health or spec pointer — the backend's
/// [`needs_redeploy`](ComputeBackend::needs_redeploy) auto-heal signal (e.g. a docker
/// container stuck on the wrong PRIMARY network). Such a replica is stopped and relaunched
/// exactly like a spec-changed one. Empty ⇒ the recreate trigger is the spec pointer alone.
///
/// This convenience form sizes placement from each node's **advertised** free capacity
/// afresh (so it sees neither already-running replicas nor other workloads reconciled this
/// pass). The reconcile loop instead calls [`reconcile_plan_in`] with a shared, pre-debited
/// [`NodeCapacities`] ledger so cumulative placement across workloads can't over-subscribe a
/// node.
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
    force_recreate: &BTreeSet<u32>,
) -> ReconcilePlan {
    let mut capacity = NodeCapacities::advertised(nodes);
    reconcile_plan_in(
        workload,
        spec,
        nodes,
        policy,
        observed,
        activity,
        caps,
        now,
        force_recreate,
        &mut capacity,
    )
}

/// [`reconcile_plan`], but placing new replicas against the **shared** remaining-capacity
/// ledger `capacity` (debiting each launch from it) instead of each node's advertised figure.
/// The reconcile loop seeds one ledger per pass — advertised capacity minus every running
/// replica's reservation — and threads it through this call for every workload, so a
/// workload placed earlier in the pass reduces the capacity a later workload sees. Every
/// classification/redeploy/scale-to-zero rule is identical to [`reconcile_plan`] (including the
/// [`ReconcilePlan::unscheduled`] surfacing of a capacity/eligibility shortfall); only the
/// placement capacity source differs.
#[allow(clippy::too_many_arguments)]
pub fn reconcile_plan_in(
    workload: &ComputeWorkload,
    spec: &ComputeSpec,
    nodes: &[Node],
    policy: &BackendPolicy,
    observed: &[ObservedInstance],
    activity: WorkloadActivity,
    caps: &BTreeMap<String, Capabilities>,
    now: u64,
    force_recreate: &BTreeSet<u32>,
    capacity: &mut NodeCapacities,
) -> ReconcilePlan {
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
        // A durable LAUNCH-FAILURE marker (`launch` Err'd; no instance ever started — see
        // `reconcile_once`). While in range, skip it here so it is added to NO keep/terminal
        // set and NO Stop is emitted (there is nothing running to stop): its ordinal then
        // lands in `need` below and is relaunched — the exact retry a failed launch had
        // before it was recorded, and independent of restart policy (a run-to-completion job
        // that never STARTED is not a completed one). Out of range (scaled down / deleted) it
        // falls through to the normal out-of-range `Stop` so the stale marker is cleaned up.
        if ord < desired && matches!(inst.readiness, Readiness::LaunchFailed { .. }) {
            continue;
        }
        // A REDEPLOY check: this replica was launched from a spec pointer that no
        // longer matches the workload's current `active` (an operator flipped it to a
        // new spec). It must be RECREATED (stopped here → relaunched below from the new
        // spec), NOT kept — keeping it is the bug where a changed spec was invisible and
        // a shared-kernel backend's own restart policy merely restarted the OLD
        // container in place (so the redeploy never re-ran `launch`). `None` (legacy /
        // restored record whose source spec is unknown) never counts as stale, so it is
        // never spuriously recreated — the reconcile backfills it to the current
        // `active` on observation. Does NOT apply to a `Zero` (parked) replica: it has
        // no live container and wakes via `Restore`, handled below.
        let stale_spec = inst
            .active_spec
            .as_deref()
            .is_some_and(|launched| launched != workload.active)
            // …or the driver flagged this ordinal for an auto-heal recreate (the backend's
            // `needs_redeploy` — e.g. a docker container on the wrong primary network).
            || force_recreate.contains(&ord);
        if ord >= desired {
            // Out of range (also discards a Zero replica's snapshot — Stop is
            // idempotent and the driver forgets the state).
            actions.push(Action::Stop {
                handle: inst.handle.clone(),
            });
        } else if inst.phase == ReplicaPhase::Zero {
            zeroed.insert(ord);
            // Wake on activity; otherwise stay parked.
            if matches!(activity, WorkloadActivity::Active)
                && let Some(snapshot) = inst.snapshot.clone()
            {
                // A wake restores the replica to Running (same node that holds its
                // snapshot), so it reclaims the node's CPU/mem the pre-pass did NOT charge
                // for a parked Zero replica. Debit the shared ledger here — exactly as a
                // Launch does — so a later-ordered workload this pass sees the slot as taken
                // and can't be placed on top of the waking replica (residual over-subscription).
                capacity.reserve(inst.node, Reservation::of_spec(spec));
                actions.push(Action::Restore {
                    snapshot,
                    node: inst.node,
                    backend: inst.backend.clone(),
                });
            }
        } else if inst.healthy && !stale_spec {
            healthy.insert(ord);
            // Sleep on sustained idle (opt-in + capable backend).
            if matches!(activity, WorkloadActivity::Idle) && sleeps(&inst.backend) {
                actions.push(Action::Snapshot {
                    handle: inst.handle.clone(),
                });
            }
        } else if matches!(spec.restart, RestartPolicy::Never) && !inst.healthy {
            // Run-to-completion that has EXITED (unhealthy + `Never`): leave it terminal,
            // never relaunch — even on a spec change (re-running a finished batch job on a
            // redeploy is not the intent; a new spec for a run-to-completion workload takes
            // effect when it is next launched, not by resurrecting a completed run).
            terminal.insert(ord);
        } else if stale_spec {
            // REDEPLOY: a running (healthy, starting, or merely unhealthy-and-restartable)
            // replica of a now-superseded spec. Stop it so its ordinal is relaunched below
            // from the new spec — the recreate the in-place restart never did. The data
            // volume survives (`stop` removes only the container, never its volume).
            actions.push(Action::Stop {
                handle: inst.handle.clone(),
            });
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
        return ReconcilePlan {
            actions,
            unscheduled: Vec::new(),
        };
    }

    // Place the needed count against the SHARED remaining-capacity ledger, then zip ordinals
    // with placements. The two features compose here: `place_replicas_in` consults (and debits)
    // the cumulative ledger, so when the ledger can't fit a replica — a genuine over-subscription
    // / capacity shortfall across workloads — it returns FEWER placements than `need`. The
    // leading ordinals get their `Launch` (each debiting `capacity` so a later workload this pass
    // sees the reduced node), and the unplaced tail is NOT silently dropped (the bug that hid a
    // stuck workload for hours) but returned in `unscheduled` so the driver logs + reports it.
    let placements = place_replicas_in(
        need.len() as u32,
        &workload.placement,
        spec,
        nodes,
        policy,
        capacity,
    );
    let placed = placements.len();
    for (ord, place) in need.iter().zip(placements) {
        actions.push(Action::Launch {
            workload: workload.name.clone(),
            replica: *ord,
            node: place.node,
            backend: place.backend,
        });
    }
    // The ordinals past the placed count had no eligible backend with capacity. Name the
    // resource need so the operator sees what to add (the same `need_cpu`/`need_mem` floor
    // `place_replicas` uses).
    let unscheduled: Vec<Unscheduled> = need[placed..]
        .iter()
        .map(|ord| Unscheduled {
            workload: workload.name.clone(),
            replica: *ord,
            reason: format!(
                "no eligible backend with capacity (needs {}vcpu/{}MiB)",
                spec.vcpus.max(1),
                spec.mem_mib.max(1)
            ),
        })
        .collect();
    ReconcilePlan {
        actions,
        unscheduled,
    }
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

/// One binding resolver's contribution to the **unified managed-env render stage**
/// (PLAN-compute-managed-resources Phase 3): the `{surface}.*` template variables it
/// exposes (e.g. `kv.url`, `kv.token`, `blob.endpoint`, `sql.dsn`) and the default
/// `(env_key, value)` pairs it injects when the operator set no template for that key.
///
/// The render stage unions every resolver's [`vars`](Self::vars) into ONE variable map,
/// unseals any `{{secret.NAME}}` the operator referenced, renders each templated `env`
/// value ONCE against that union (so an operator may interleave surfaces in a single
/// value — `"{{sql.host}} {{kv.token}}"`), then folds each resolver's
/// [`defaults`](Self::defaults) for the keys the operator did not set. Keeping vars and
/// defaults distinct (rather than a resolver pre-rendering its own slice) is what lets
/// the render happen in exactly one place and fail CLOSED on an unknown key.
#[derive(Debug, Default, Clone)]
pub struct SurfaceContribution {
    /// The `{surface}.{key}` template variables this resolver exposes (no `{{}}`
    /// delimiters — bare keys like `kv.url`). Unioned across resolvers by the render
    /// stage; a later resolver's key wins on a collision (surfaces never share a key).
    pub vars: std::collections::BTreeMap<String, String>,
    /// The default `(env_key, value)` pairs to inject when the operator set no value for
    /// `env_key` (a hand-set literal or an operator template for that key always wins).
    pub defaults: Vec<(String, String)>,
}

impl SurfaceContribution {
    /// Fold another contribution into this one (the chain merge): extend the var map
    /// (later keys win) and concatenate the defaults.
    pub fn merge(&mut self, other: Self) {
        self.vars.extend(other.vars);
        self.defaults.extend(other.defaults);
    }
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

    /// Like [`resolve`](Self::resolve), but also given the workload's operator-declared
    /// `env` so a resolver can **render operator templates** against the resolved binding
    /// (e.g. a managed-DB DSN composed from `{{sql.host}}` / `{{sql.user}}` / … plus
    /// referenced sealed secrets — all filled SERVER-SIDE at launch). A value it returns
    /// whose matching `env` entry contains a `{{…}}` placeholder **replaces** that entry
    /// at launch (see `launch_one`); other returned pairs are injected only when the key
    /// is absent (a hand-set literal always wins). The default delegates to
    /// [`resolve`](Self::resolve) (ignores `env`), so a resolver that does no templating —
    /// every shim — needs no change.
    async fn resolve_with_env(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
        _env: &std::collections::BTreeMap<String, String>,
    ) -> Vec<(String, String)> {
        self.resolve(project, workload, replica, bindings).await
    }

    /// Contribute this resolver's [`SurfaceContribution`] — the `{surface}.*` template
    /// variables + per-surface default env for `bindings` — to the unified render stage
    /// (PLAN-compute-managed-resources Phase 3), registering the SAME per-replica shim
    /// state (token / minted credential) `resolve` would. `env` is the operator-declared
    /// env (so a surface that must mint only at launch can gate on it being non-empty),
    /// though most resolvers ignore it (their vars are env-independent). The default impl
    /// contributes NO vars and takes [`resolve`](Self::resolve)'s output as the defaults —
    /// so a resolver that does no templating (the libsql sql-shim) needs no change and the
    /// render stage still injects its endpoint/token as a default.
    async fn contribute(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
        _env: &std::collections::BTreeMap<String, String>,
    ) -> SurfaceContribution {
        SurfaceContribution {
            vars: std::collections::BTreeMap::new(),
            defaults: self.resolve(project, workload, replica, bindings).await,
        }
    }

    /// Release the shim state for a torn-down replica.
    async fn release(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
    );
}

/// Combine several [`ComputeBindingResolver`]s into one. `resolve` concatenates each inner
/// resolver's env and `release` releases each. Every concrete resolver (the sql-shim, the
/// blob-shim) already filters to its OWN [`BindingKind`] and ignores the rest, so a
/// workload that declares both a `sql` and a `blob` binding is served by both shims from a
/// single `resolve` call. This lets the node hand the reconcile ONE resolver even though
/// the sql-shim and blob-shim are distinct — the reconcile takes a single
/// `Option<&dyn ComputeBindingResolver>`.
pub struct ChainedBindingResolver {
    resolvers: Vec<Arc<dyn ComputeBindingResolver>>,
}

impl ChainedBindingResolver {
    /// Chain the given resolvers, dropping any `None`. Returns `None` when none remain (the
    /// feature stays off), the sole resolver unwrapped when exactly one remains (no wrapper
    /// overhead), else a chained composite.
    pub fn chain(
        resolvers: impl IntoIterator<Item = Option<Arc<dyn ComputeBindingResolver>>>,
    ) -> Option<Arc<dyn ComputeBindingResolver>> {
        let mut resolvers: Vec<_> = resolvers.into_iter().flatten().collect();
        match resolvers.len() {
            0 => None,
            1 => resolvers.pop(),
            _ => Some(Arc::new(Self { resolvers })),
        }
    }
}

#[async_trait]
impl ComputeBindingResolver for ChainedBindingResolver {
    async fn resolve(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
    ) -> Vec<(String, String)> {
        let mut env = Vec::new();
        for resolver in &self.resolvers {
            env.extend(resolver.resolve(project, workload, replica, bindings).await);
        }
        env
    }

    async fn resolve_with_env(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
        workload_env: &std::collections::BTreeMap<String, String>,
    ) -> Vec<(String, String)> {
        let mut env = Vec::new();
        for resolver in &self.resolvers {
            env.extend(
                resolver
                    .resolve_with_env(project, workload, replica, bindings, workload_env)
                    .await,
            );
        }
        env
    }

    async fn contribute(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
        workload_env: &std::collections::BTreeMap<String, String>,
    ) -> SurfaceContribution {
        // Union every inner resolver's `{surface}.*` vars + per-surface defaults into ONE
        // contribution, so the render stage above renders the operator `env` once against
        // the whole set (each shim already filters to its own `BindingKind`).
        let mut out = SurfaceContribution::default();
        for resolver in &self.resolvers {
            out.merge(
                resolver
                    .contribute(project, workload, replica, bindings, workload_env)
                    .await,
            );
        }
        out
    }

    async fn release(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
    ) {
        for resolver in &self.resolvers {
            resolver.release(project, workload, replica, bindings).await;
        }
    }
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
/// One orphaned per-replica dynamic DB credential the sweep dropped (or, in dry-run, would
/// drop) — the audit line for [`ManagedDbEnvResolver::sweep_orphan_dynamic_db_creds`]. Carries
/// no secret (the role NAME is not sensitive; the sealed password never appears).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweptDynamicCred {
    /// The consumer/tenant project the credential was minted for.
    pub project: String,
    /// The managed server workload (the `compute` binding) the role lived on.
    pub compute: String,
    /// The replica identity ([`compute_instance_id`]) whose stop/absence orphaned the cred.
    pub instance_id: String,
    /// The dropped dynamic role / user name (non-secret).
    pub role: String,
    /// `true` when the role + sealed password were actually dropped; `false` in a dry-run
    /// (identified as reapable but left untouched).
    pub dropped: bool,
}

/// The concrete impl lives in `boatramp-node`, where the handler sql config + the
/// sealed-credential store are; the reconcile only calls this trait.
#[async_trait]
pub trait ManagedDbEnvResolver: Send + Sync {
    /// Server-init env for `workload` if it is a managed database, else empty.
    async fn managed_db_env(&self, project: &str, workload: &str) -> Vec<(String, String)>;

    /// The privilege strategy that lets `workload`'s stock DB image initialize on a
    /// shared-kernel backend, or `None` if `workload` is not a managed database.
    /// Defaulted so a non-DB resolver needs no change. The reconcile applies it to the
    /// **launch** spec only (never the stored one), and only when the operator has not
    /// already set `user`/`cap_add`. Async because resolving whether `workload` is a
    /// managed database may require a control-plane lookup (an APPLIED, deploy-store
    /// managed db on an env-configured node, which carries no node-static config entry).
    async fn managed_db_privilege(
        &self,
        _project: &str,
        _workload: &str,
    ) -> Option<PrivilegeDirective> {
        None
    }

    /// Probe a **managed-DB** workload's *service-level* readiness by connecting to
    /// `endpoint` and running a real `SELECT 1` — a TCP-open `healthy` is not enough (a
    /// DB that can't read its data directory still listens but errors every query, the
    /// data-dir-ownership failure mode). `None` when `workload` is not a managed database
    /// (the reconcile then uses the generic `healthy` signal); `Some(true)` when the
    /// server answers, `Some(false)` when it does not yet. **Connects directly to the
    /// launching instance** — the readiness pass runs before the replica is
    /// [`Provisioned`](Readiness::Provisioned), so it must NOT go through the
    /// `Provisioned`-gated routing resolver (it is what *produces* `Provisioned`).
    async fn probe_managed_ready(
        &self,
        _project: &str,
        _workload: &str,
        _endpoint: &Endpoint,
    ) -> Option<bool> {
        None
    }

    /// Run a **managed-DB** workload's derived post-launch DDL — the `CREATE DATABASE`
    /// (and, where applicable, role setup) for the database this `(project, workload)`
    /// hosts — against `endpoint`, **idempotently** (relaunch re-enters this every time;
    /// "already exists" is tolerated). Called once [`probe_managed_ready`] reports the
    /// service answers. `Ok(())` ⇒ provisioned; `Err(reason)` ⇒ surfaced as
    /// [`ProvisionFailed`](Readiness::ProvisionFailed) and retried next tick. A no-op
    /// `Ok(())` when `workload` is not a managed database, or when there is nothing to
    /// create here (e.g. the shared server, whose per-tenant databases provision lazily
    /// on first connect). Connects directly to the instance (carve-out, as above).
    async fn provision_managed(
        &self,
        _project: &str,
        _workload: &str,
        _endpoint: &Endpoint,
    ) -> Result<(), String> {
        Ok(())
    }

    /// **Mint** this replica's per-replica DYNAMIC database credential at launch, for a
    /// workload that CONSUMES a managed database (PLAN-compute-managed-db phase 2). Called
    /// once per launch, BEFORE binding resolution, so a DSN injector reads the freshly-
    /// minted (sealed) per-replica credential. `bindings` are the launching workload's
    /// declared bindings — the node impl resolves each `sql` binding to the managed DB it
    /// names and mints that tenant's per-replica role. A workload that consumes no managed database
    /// — and every cell where phase 2 does not apply (a bring-your-own `url_env` binding,
    /// the reserved default tenant, `Single` isolation) — is a no-op `Ok(())`. An `Err`
    /// FAILS the launch CLOSED (a consumer must not serve without its credential). The node
    /// impl delegates to
    /// [`boatramp_node::dynamic_creds::mint_dynamic_role`](../../boatramp_node/dynamic_creds/fn.mint_dynamic_role.html).
    /// Defaulted to a no-op so a resolver that does not implement phase 2 is unaffected.
    async fn mint_dynamic_db_cred(
        &self,
        _project: &str,
        _workload: &str,
        _bindings: &[ComputeBinding],
        _replica: u32,
    ) -> Result<(), String> {
        Ok(())
    }

    /// **Revoke + drop** this replica's dynamic database credential at stop (PLAN-compute-
    /// managed-db phase 2) — the `DROP OWNED` / `DROP ROLE` (or `DROP USER`) that keeps a
    /// stopped replica's role from lingering. Idempotent: a non-consumer workload, an
    /// already-dropped role, and an already-deleted credential are all no-ops, so it is safe
    /// to call again (and from the orphan reaper). A revoke error is non-fatal to the
    /// reconcile (the replica is already stopped; the next sweep retries). The node impl
    /// delegates to
    /// [`boatramp_node::dynamic_creds::revoke_dynamic_role`](../../boatramp_node/dynamic_creds/fn.revoke_dynamic_role.html).
    /// Defaulted no-op.
    async fn revoke_dynamic_db_cred(
        &self,
        _project: &str,
        _workload: &str,
        _bindings: &[ComputeBinding],
        _replica: u32,
    ) -> Result<(), String> {
        Ok(())
    }

    /// **Sweep** orphaned per-replica dynamic DB credentials (PLAN-compute-managed-db phase 2,
    /// Security HIGH-1) — the reconciliation backstop that keeps a MISSED stop (a node crash,
    /// a node loss, a permanent scale-down, a workload deletion, or a stop whose revoke errored
    /// on a transient DB outage) from leaking an operates-as-owner login role + its sealed
    /// password INDEFINITELY. Enumerates the sealed dynamic-cred keys and DROPS (revoke DDL +
    /// delete the sealed password) every one whose owning replica is **gone**:
    /// `live` is the set of `(consumer_project, compute_instance_id)` PAIRS for every PERSISTED
    /// replica record (the reaper gathers it in the same pass), and a cred whose
    /// `(consumer_project, instance_id)` pair is in that set is KEPT — so the sweep is
    /// tenant-correct (it drops only a cred whose owning replica no longer exists, never one
    /// belonging to a live or parked replica, even on another node). The pair — not the bare
    /// `instance_id` — is the key because [`compute_instance_id`]'s hyphen-join aliases across
    /// project/workload splits (`("acme-web","api")` and `("acme","web-api")` both yield
    /// `acme-web-api`), so a bare-id live set could let one tenant's live replica mask another
    /// tenant's orphan; pairing with the (raw, un-joined) consumer project disambiguates.
    /// Idempotent (the underlying revoke is: an already-gone role + an
    /// already-deleted password are no-ops). `dry_run` identifies the orphans and returns them
    /// with `dropped = false` WITHOUT touching anything. Hooked into the orphan reaper's `All`
    /// pass. Defaulted no-op so a resolver that does not implement phase 2 is unaffected.
    async fn sweep_orphan_dynamic_db_creds(
        &self,
        _live: &std::collections::HashSet<(String, String)>,
        _dry_run: bool,
    ) -> Result<Vec<SweptDynamicCred>, String> {
        Ok(Vec::new())
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

/// Why picking the export/import **client image** for a detected server version failed.
/// A version-detect that can't be mapped to a safe client image REFUSES rather than
/// guessing — a client older than the server cannot restore its dump (new catalog
/// features, archive-format version), so guessing would silently corrupt a migration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VersionMapError {
    /// The server version banner could not be parsed into a version number.
    #[error("unrecognized server version banner {0:?}: cannot select a matching client image")]
    Unparsable(String),
    /// The detected server major is older than the oldest client image we ship a tag
    /// for (we never guess an ancient client).
    #[error(
        "server major {0} is too old: no matching export/import client image is available \
         (minimum supported Postgres major is {1})"
    )]
    TooOld(u32, u32),
    /// The detected server major is newer than the newest client image we can name — we
    /// refuse rather than pick an older client that could not read the newer server's
    /// dump (a client MUST be >= the server).
    #[error(
        "server major {0} is newer than any export/import client image this build can name \
         (maximum known Postgres major is {1}); refusing to pick an older client that could \
         not restore its dump — upgrade boatramp or widen the client-image map"
    )]
    TooNew(u32, u32),
    /// The MySQL-shaped server is actually **MariaDB** (a distinct wire/dump dialect). A
    /// `mysql`/`mysqldump` client can MISDUMP or misrestore it, so we REFUSE rather than
    /// silently use the wrong client — MariaDB support needs its own client image.
    #[error(
        "server is MariaDB ({0:?}), not MySQL: refusing to dump/restore it with a mysql client \
         (distinct dialect); MariaDB export/import needs a dedicated mariadb client (not yet \
         supported)"
    )]
    MariaDb(String),
}

/// Oldest Postgres major this build will select an export/import client image for.
/// pgvector publishes per-major tags; pre-10 servers use a different `server_version_num`
/// encoding and are long out of support, so they are refused.
pub const PG_CLIENT_MIN_MAJOR: u32 = 13;
/// Newest Postgres major this build knows a `pgvector/pgvector:pg<major>` tag exists for.
/// A server beyond this is refused (not downgraded to an older client) — bump this, and
/// re-verify the tag exists, when a newer major ships.
pub const PG_CLIENT_MAX_MAJOR: u32 = 18;

/// Map a Postgres server's `SHOW server_version_num` banner to the stock client image
/// whose `pg_dump`/`pg_restore` can safely dump+restore it — a pgvector image at the
/// **same major** (which satisfies "client major >= server major", the load-bearing
/// invariant: an older client cannot read a newer server's dump).
///
/// `server_version_num` is Postgres' integer form: for pg >= 10 it is
/// `major * 10000 + minor` (e.g. `160004` → major 16). Pre-10 banners (which encode the
/// major differently and are out of support) and any major outside the known
/// `pgvector/pgvector:pg<major>` tag range are REFUSED with a clear
/// [`VersionMapError`] rather than guessing a mismatched client.
///
/// Extensible: MySQL (`SELECT VERSION()` → `mysql:<maj.min>`) is the documented
/// fast-follow; MariaDB is an explicit unsupported-until-detected edge. Keep this pure
/// (no IO) so the version-match invariant is unit-mutation-gated in the merge gate.
pub fn pg_client_image_for_server_version(
    server_version_num: &str,
) -> Result<String, VersionMapError> {
    let trimmed = server_version_num.trim();
    let n: u32 = trimmed
        .parse()
        .map_err(|_| VersionMapError::Unparsable(server_version_num.to_string()))?;
    // Pre-10 encodes as major*10000 + minor*100 + patch (e.g. 9.6.24 -> 90624), so a
    // value below 100000 is a pre-10 server — out of support, refused.
    if n < 100_000 {
        let major = n / 10_000;
        return Err(VersionMapError::TooOld(major, PG_CLIENT_MIN_MAJOR));
    }
    let major = n / 10_000;
    if major < PG_CLIENT_MIN_MAJOR {
        return Err(VersionMapError::TooOld(major, PG_CLIENT_MIN_MAJOR));
    }
    if major > PG_CLIENT_MAX_MAJOR {
        return Err(VersionMapError::TooNew(major, PG_CLIENT_MAX_MAJOR));
    }
    Ok(format!("pgvector/pgvector:pg{major}"))
}

/// Oldest MySQL major this build will select a client image for (pre-5 is long dead).
pub const MYSQL_CLIENT_MIN_MAJOR: u32 = 5;

/// The leading run of ASCII digits of `s`, parsed (`"0-log"` → `0`, `""` → `None`).
fn leading_u32(s: &str) -> Option<u32> {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Map a MySQL server's `SELECT VERSION()` banner to the stock `mysql:<maj>.<min>` client
/// image whose `mysqldump`/`mysql` can dump+restore it (same major.minor — a client >=
/// the server). A **MariaDB** banner (the version string contains `MariaDB`, e.g.
/// `"10.11.6-MariaDB-…"`) is REFUSED with [`VersionMapError::MariaDb`] — its dialect needs
/// a dedicated client, never a silent mysql dump. A pre-5 or unparsable banner is refused.
/// Pure (no IO) so it is unit-mutation-gated in the merge gate.
pub fn mysql_client_image_for_server_version(version: &str) -> Result<String, VersionMapError> {
    let v = version.trim();
    if v.to_ascii_lowercase().contains("mariadb") {
        return Err(VersionMapError::MariaDb(version.to_string()));
    }
    // A MySQL banner leads with "maj.min[.patch][-suffix]" (e.g. "8.0.35", "8.4.0",
    // "5.7.44", "8.0.35-0ubuntu0.1"). Take the leading digit runs of the first two dot
    // segments.
    let mut segs = v.split('.');
    let major = segs
        .next()
        .and_then(leading_u32)
        .ok_or_else(|| VersionMapError::Unparsable(version.to_string()))?;
    let minor = segs
        .next()
        .and_then(leading_u32)
        .ok_or_else(|| VersionMapError::Unparsable(version.to_string()))?;
    if major < MYSQL_CLIENT_MIN_MAJOR {
        return Err(VersionMapError::TooOld(major, MYSQL_CLIENT_MIN_MAJOR));
    }
    Ok(format!("mysql:{major}.{minor}"))
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
    delta_capture: bool,
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
    let (mut entrypoint, env) = match engine {
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
                // AUTH: the official `mysql:8.0` image defaults new accounts to
                // `caching_sha2_password`, whose FIRST auth over plain TCP needs either TLS or the
                // server's RSA public key (`--get-server-public-key`). Our clients
                // ([`MysqlConnection::conn_args`]) connect over the isolated per-project network with
                // only host/port/user + `MYSQL_PWD` — no TLS, no public-key exchange — so a
                // caching_sha2 account cannot authenticate (every managed-mysql access, not just the
                // export/import path, would fail). Default new accounts (root + every `CREATE USER …
                // IDENTIFIED BY …`, which name no explicit plugin) to `mysql_native_password` so
                // password auth works over the plain-TCP intra-project link — the SAME
                // trust-the-isolated-network posture managed Postgres already uses. UNCONDITIONAL:
                // every managed mysql needs auth, delta-capture or not.
                // TODO(mysql-8.4): `--default-authentication-plugin` is deprecated and REMOVED in
                // MySQL 8.4 (replaced by `authentication_policy`). A future image bump past 8.0 must
                // instead serve caching_sha2 with TLS on the intra-project link (or the client must
                // pass `--get-server-public-key`) — do NOT simply drop this flag onto an 8.4 image.
                "--default-authentication-plugin=mysql_native_password".to_string(),
            ],
            BTreeMap::from([(
                "PATH".to_string(),
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            )]),
        ),
    };
    // SQL true-delta capture opt-in (PLAN-sql-true-delta Stage 1): enable the engine's row-level
    // change stream so a delta export can ship a WAL/binlog true-delta instead of a full dump.
    // These are START-ONLY server settings, so a flip of `delta_capture` remints this
    // content-addressed spec and the DB must relaunch to adopt them (the restart primitive). Off
    // by default so a DB nobody delta-exports pays no WAL amplification / binlog disk.
    if delta_capture {
        match engine {
            ManagedDbEngine::Postgres => {
                // Logical decoding + room for the per-export capture slots. `wal_level=logical`
                // is the load-bearing one (default is `replica`, which cannot be decoded).
                for flag in [
                    "wal_level=logical",
                    "max_wal_senders=10",
                    "max_replication_slots=10",
                ] {
                    entrypoint.push("-c".to_string());
                    entrypoint.push(flag.to_string());
                }
                // §4 disk-fill guard (PLAN-sql-true-delta, MANDATORY): a logical slot pins WAL
                // from its `restart_lsn` forward, so a forgotten / un-drained capture slot would
                // fill the data disk — the EXACT incident this whole export program exists to
                // fix. `max_slot_wal_keep_size` (PG13+) is the HARD, server-enforced ceiling:
                // once a slot would pin more WAL than this, Postgres invalidates it (its
                // `pg_replication_slots.wal_status` → `lost`) and RECLAIMS the WAL — so disk
                // safety is NOT best-effort. A delta capture that finds its slot lost/gone then
                // FALLS BACK to a full dump for that member (true-delta is best-effort; disk
                // safety is not). The budget is a fraction of the data volume (a quarter),
                // clamped to a sane band, so a tiny volume still gets a floor and a large one
                // never pins an unbounded amount of WAL between a base and its delta.
                let ceiling_mib = (volume_size_mib / 4).clamp(256, 8192);
                entrypoint.push("-c".to_string());
                entrypoint.push(format!("max_slot_wal_keep_size={ceiling_mib}MB"));
            }
            ManagedDbEngine::Mysql => {
                // Row-format binlog + GTID so a delta can ship the binlog events since a base
                // GTID. `server-id` must be nonzero for binary logging.
                //
                // `log_bin_trust_function_creators=ON` is REQUIRED for the export/import path to
                // carry a database's triggers + stored routines across the non-superuser shadow
                // restore: with binary logging ENABLED, MySQL 8.0 refuses a `CREATE TRIGGER` /
                // `CREATE FUNCTION` from a non-SUPER user (ERROR 1419) UNLESS this is on — and the
                // ephemeral least-privilege apply user deliberately lacks `SUPER`/
                // `SYSTEM_VARIABLES_ADMIN` (which is GLOBAL-only, so the apply cannot set this
                // itself). It is BENIGN under `--binlog-format=ROW` (the determinism concern it
                // guards is a STATEMENT-binlog issue — row events log the effect, not the call), and
                // it does NOT grant foreign-DEFINER ability (that stays gated by `SET_USER_ID`), so
                // the driver's `DEFINER=` rewrite + post-swap re-point is still required. Only added
                // alongside binary logging; a binlog-OFF server does not hit ERROR 1419 and needs no
                // such setting.
                entrypoint.extend(
                    [
                        "--log-bin",
                        "--binlog-format=ROW",
                        "--gtid-mode=ON",
                        "--enforce-gtid-consistency=ON",
                        "--server-id=1",
                        "--log-bin-trust-function-creators=ON",
                    ]
                    .into_iter()
                    .map(str::to_string),
                );
            }
        }
    }
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
        pull_secret: None,
        bindings: vec![],
        post_launch: vec![],
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
#[allow(clippy::too_many_arguments)]
pub async fn reconcile_once(
    deploy: &DeployStore,
    backends: &BackendRegistry,
    nodes: &[Node],
    policy: &BackendPolicy,
    activity: &dyn ActivitySource,
    resolver: Option<&dyn ComputeBindingResolver>,
    managed_db: Option<&dyn ManagedDbEnvResolver>,
    registry_auth: Option<&dyn RegistryAuthResolver>,
) -> Result<ReconcileReport, crate::error::DeployError> {
    let mut report = ReconcileReport::default();
    // Per-backend capabilities (the planner gates scale-to-zero on them).
    let caps: BTreeMap<String, Capabilities> = backends
        .iter()
        .map(|(id, b)| (id.clone(), b.capabilities()))
        .collect();
    // The `(project, workload, replica)` keys that are intentionally **parked**
    // (scale-to-zero `Zero`), accumulated across every project. A parked replica keeps
    // its IP reserved for the wake, so the post-loop pool-vs-reality GC (A2) must never
    // reclaim it — it feeds this set to each backend's `gc_ip_pool`.
    let mut parked_keys: Vec<(String, String, u32)> = Vec::new();

    // Every project's workloads (compute is project-scoped in 0.2.0), fetched once.
    let mut workloads = deploy.list_compute_workloads_all().await?;
    // DETERMINISTIC placement order. With one shared capacity ledger (below) the order in
    // which workloads consume contended capacity is observable, so sort by (project,
    // workload name) — a total order that is stable across reconciles and independent of the
    // store's iteration order. A workload that doesn't fit when capacity is tight stays
    // unplaced on the same stable basis each tick (it doesn't flap), and freed capacity is
    // handed to the earliest such workload in this order.
    workloads.sort_by(|(pa, wa), (pb, wb)| pa.cmp(pb).then_with(|| wa.name.cmp(&wb.name)));

    // BIN-PACKING PRE-PASS. Seed one shared remaining-capacity ledger for the whole pass:
    // each node's advertised free capacity MINUS the reservation of every currently-running
    // replica (across all projects/workloads). Threaded (mutable) through every workload's
    // `reconcile_plan_in` below, so cumulative placement can no longer over-subscribe a node
    // — the bug where each workload saw the node's full advertised capacity, so N workloads
    // that each fit alone could collectively exceed it. The reservations are resolved by spec
    // hash (cached) with a fail-safe floor for an unresolvable one (`running_replica_reservation`).
    let mut capacity = NodeCapacities::advertised(nodes);
    {
        // Resolved reservation per spec content-hash (or confirmed-missing), cached across the
        // pre-pass so a workload's many replicas (same `active_spec`) don't each re-fetch.
        let mut spec_res_cache: BTreeMap<String, Option<Reservation>> = BTreeMap::new();
        for (project_name, workload) in &workloads {
            let project = ProjectRef::new(project_name);
            // The workload's current active spec — the fallback reservation for a running
            // replica whose OWN launched spec can't be resolved.
            let workload_spec = deploy.get_compute_spec(&workload.active).await?;
            for state in deploy.list_replica_states(project, &workload.name).await? {
                // Only a RUNNING replica occupies vCPU/memory; a Zero (parked) or terminal
                // one holds none (its reserved IP is tracked separately via `parked_keys`).
                if state.phase != ReplicaPhase::Running {
                    continue;
                }
                let res = running_replica_reservation(
                    deploy,
                    &mut spec_res_cache,
                    &state,
                    workload_spec.as_ref(),
                    &mut report,
                )
                .await?;
                capacity.reserve(state.node, res);
            }
        }
    }

    // The owning project threads through every replica-state read/write below.
    for (project_name, workload) in workloads {
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
        // Ordinals the backend reports as running an OUTDATED deployment shape (the
        // `needs_redeploy` auto-heal — e.g. a docker container on the wrong primary
        // network): the planner recreates them like a spec-changed replica.
        let mut force_recreate: BTreeSet<u32> = BTreeSet::new();
        for state in &mut observed {
            if state.phase == ReplicaPhase::Zero {
                // Record the parked replica so the A2 GC keeps its IP reserved.
                parked_keys.push((
                    project_name.clone(),
                    state.handle.workload.clone(),
                    state.handle.replica,
                ));
                continue;
            }
            // A durable launch-FAILURE marker has no live backend instance to probe:
            // skip the health / endpoint / readiness / data-dir refresh entirely so its
            // reason is NOT clobbered to `Starting` by `advance_readiness` (which reads
            // `!healthy` and falls back to `Starting`). The record stays untouched — the
            // operator sees the persisted reason on `compute status` / `db status` — and the
            // planner below relaunches its ordinal to retry; a successful relaunch overwrites
            // this record with a fresh `Starting` one.
            if matches!(state.readiness, Readiness::LaunchFailed { .. }) {
                continue;
            }
            if let Some(backend) = backends.get(&state.backend) {
                let mut changed = false;
                // Auto-heal probe: a backend may report that this running replica's live
                // deployment shape is stale (docker: wrong primary network) and must be
                // recreated even though it is healthy and its spec pointer is unchanged.
                if backend.needs_redeploy(&state.handle, &spec).await {
                    force_recreate.insert(state.handle.replica);
                }
                // 1) Refresh the runner/TCP-level health. The endpoint/DNS resolvers read
                // `healthy` from the STORE, not from this in-memory refresh, so a replica
                // that becomes reachable *after* launch must have that recovery written
                // back. `launch_one` probes *before* the guest binds its port and persists
                // `healthy: false`; without persisting the refresh that pre-bind `false`
                // sticks forever (a running healthy replica needs no Launch/Stop, so
                // nothing else writes it). Persist only on a change to stay cheap.
                if let Ok(health) = backend.health(&state.handle).await {
                    let now_healthy = matches!(health, Health::Healthy);
                    if now_healthy != state.healthy {
                        state.healthy = now_healthy;
                        changed = true;
                    }
                }
                // 1b) Re-point the endpoint if the running replica's live address drifted
                // out from under the stored record. The gateway routes to the STORED
                // `endpoint` (see `compute_endpoints`), so an endpoint that moves while the
                // container keeps running under a stable identity must be written back or
                // the gateway dials a dead address. The concrete case: docker's `Published`
                // mode publishes an EPHEMERAL host port that docker REASSIGNS on every
                // in-place `--restart` restart — an OOM-crashing app (`137`) is relaunched
                // by its restart policy under the same container name with a NEW host port,
                // the container is `running` again (so the health refresh above keeps
                // `healthy: yes` and nothing plans a Stop/Launch), yet the stored endpoint
                // still points at the dead old port → the gateway 502s forever (healing
                // only on a manual `compute restart`). Re-pointing makes routing follow the
                // live port with no container churn. Only for a `Running` replica; `None`
                // ⇒ the endpoint can't drift (fixed port / Bridge / external) or the
                // replica isn't currently resolvable — leave the stored endpoint untouched.
                if state.phase == ReplicaPhase::Running
                    && let Some(ep) = backend.observed_endpoint(&state.handle).await
                    && ep != state.endpoint
                {
                    state.endpoint = ep;
                    changed = true;
                }
                // 2) Advance SERVICE-level readiness (distinct from `healthy`). A managed
                // DB gets a real `SELECT 1` probe + its derived post-launch provisioning
                // DDL; a generic workload is usable as soon as it is `healthy`. Only
                // advances while not yet `Provisioned` — idempotent DDL is not re-run every
                // tick once done — and a relaunch resets a replica to `Starting`, so a
                // replaced container re-provisions. This is where "runner up" becomes
                // "ready": the gated surfaces route only once a replica is `Provisioned`.
                let new_readiness =
                    advance_readiness(backend.as_ref(), managed_db, &project_name, &spec, state)
                        .await;
                if new_readiness != state.readiness {
                    state.readiness = new_readiness;
                    changed = true;
                }
                // 3) Data-dir-ownership diagnosis (READ-ONLY). A rootless managed database
                //    whose data directory carries foreign-owned files `EPERM`s reading its
                //    own cluster files and FATALs *before* it ever binds its port — so the
                //    signature is "launched but not listening" (`!healthy` while `Running`),
                //    NOT a healthy-but-recovering server (which has its port up and simply
                //    answers "starting up"). Scan only once the replica is past its startup
                //    grace, so a normally-initializing container (briefly not-yet-listening)
                //    isn't scanned and a large, healthy data directory in recovery is never
                //    walked. A still-not-listening replica past its grace is genuinely stuck,
                //    and a data-dir-ownership fault is the prime suspect — the signal
                //    `/api/repair` can't give (it reconciles only in-pg drift, never
                //    filesystem permissions). Clears once the port comes up (the database
                //    could read its data directory, so ownership is fine). Backends with no
                //    on-node data directory return `None`. NEVER chowns — repair is a
                //    relaunch (re-chowns) or an operator volume/image fix.
                let data_dir = if should_diagnose_data_dir(
                    state.healthy,
                    state.started_at,
                    crate::time::now_unix(),
                    u64::from(spec.startup_grace_secs),
                ) {
                    backend
                        .data_dir_ownership(&project_name, &state.handle.workload, &spec)
                        .await
                } else {
                    None
                };
                if data_dir != state.data_dir {
                    state.data_dir = data_dir;
                    changed = true;
                }
                // 4) Backfill the active-spec pointer on a legacy record (written before
                //    the field existed). Adopt the workload's CURRENT `active` — the
                //    conservative choice: it never spuriously RECREATES an already-running
                //    replica, and from here the field tracks real redeploys, so a
                //    SUBSEQUENT spec change is detected (`reconcile_plan`). A newly launched
                //    replica already carries its pointer (set by `launch_one`), so this is a
                //    one-time catch-up per pre-upgrade replica, never a steady-state write.
                if state.active_spec.is_none() {
                    state.active_spec = Some(workload.active.clone());
                    changed = true;
                }
                if changed && let Err(e) = deploy.set_replica_state(project, state).await {
                    report.errors.push(format!(
                        "{}/{}: persist state: {e}",
                        state.handle.workload, state.handle.replica
                    ));
                }
            }
        }

        // Keep the shim registry populated for every running replica (idempotent),
        // so a workload's bindings keep working across a server restart while the
        // guest is still up.
        if let Some(resolver) = resolver
            && !spec.bindings.is_empty()
        {
            for state in &observed {
                // A launch-failure marker is `Running` (a durable diagnostic phase) but has
                // no live guest to bind — skip it; a successful relaunch resolves bindings.
                if state.phase == ReplicaPhase::Running
                    && !matches!(state.readiness, Readiness::LaunchFailed { .. })
                {
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

        let workload_activity = activity.activity(&workload.name).await;
        let plan = reconcile_plan_in(
            &workload,
            &spec,
            nodes,
            policy,
            &observed,
            workload_activity,
            &caps,
            crate::time::now_unix(),
            &force_recreate,
            &mut capacity,
        );
        // Surface every replica the planner could NOT place (capacity/eligibility
        // shortfall — including a cumulative-ledger over-subscription rejection) — a structured
        // per-ordinal `warn!` at the site AND an entry in `report.errors`, so the aggregated
        // "compute reconcile: partial" WARN fires instead of a stuck workload silently
        // vanishing from `compute status` with no reason.
        for u in &plan.unscheduled {
            tracing::warn!(
                project = %project_name,
                workload = %u.workload,
                replica = u.replica,
                reason = %u.reason,
                "compute: replica not scheduled",
            );
            report.errors.push(format!(
                "{}/{}: not scheduled: {}",
                u.workload, u.replica, u.reason
            ));
        }
        for action in plan.actions {
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
                    // Phase 2 (PLAN-compute-managed-db): mint this replica's DYNAMIC database
                    // credential BEFORE binding resolution, so a DSN injector reads the
                    // freshly-sealed per-replica credential. Fail CLOSED — a consumer must not
                    // launch without its credential. A non-consumer workload is a no-op.
                    if let Some(m) = managed_db
                        && let Err(e) = m
                            .mint_dynamic_db_cred(&project_name, &wl, &spec.bindings, replica)
                            .await
                    {
                        report
                            .errors
                            .push(format!("{wl}/{replica}: mint dynamic db cred: {e}"));
                        continue;
                    }
                    let node_region = region_of_node(nodes, node);
                    // Resolve declared bindings → env injected into the guest (registers
                    // the shim token for this replica).
                    let mut launch_env = match resolver {
                        Some(r) if !spec.bindings.is_empty() => {
                            r.resolve_with_env(
                                &project_name,
                                &wl,
                                replica,
                                &spec.bindings,
                                &spec.env,
                            )
                            .await
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
                    let privilege = match managed_db {
                        Some(m) => m.managed_db_privilege(&project_name, &wl).await,
                        None => None,
                    };
                    // Resolve the registry pull credential for an image-sourced workload,
                    // HOST-SIDE, honoring the project `pull_secret` then the operator host
                    // map, else anonymous. A referenced-but-missing/unauthorized credential
                    // fails CLOSED here (the replica is not launched), never a silent
                    // anonymous pull. A non-image source needs no auth (resolver skipped).
                    let pull_auth = match (registry_auth, &spec.root) {
                        (Some(ra), RootSource::Image(reference)) => {
                            match ra
                                .resolve(&project_name, reference, spec.pull_secret.as_deref())
                                .await
                            {
                                // Resolved a credential → authenticated pull.
                                Ok(Some(auth)) => Some(auth),
                                // No credential resolved → an ANONYMOUS pull. SCOPE the warning
                                // to the ACTIONABLE cases so it doesn't drown in noise (a public
                                // `docker.io/library/*` image legitimately pulls anonymously, and
                                // a crash-looping public workload relaunches every tick):
                                //   (a) a `pull_secret` was NAMED yet nothing resolved — an
                                //       anomaly worth flagging (the production sealed resolver
                                //       fails CLOSED on a named-but-missing secret via the `Err`
                                //       arm below, so this catches a resolver that returned
                                //       anonymous despite a named secret); OR
                                //   (b) the image host is a NON-DEFAULT (typically private)
                                //       registry, where an anonymous pull is far more likely a
                                //       misconfiguration than an intentional public pull.
                                // A bare default-registry (`docker.io`) image with no
                                // `pull_secret` is the expected public case → `debug!`, not a
                                // warning.
                                Ok(None) => {
                                    let host = crate::registry_auth::registry_host_of(reference);
                                    let named_but_unresolved =
                                        spec.pull_secret.as_deref().is_some_and(|s| !s.is_empty());
                                    let non_default_host =
                                        host != crate::registry_auth::DEFAULT_REGISTRY_HOST;
                                    if named_but_unresolved || non_default_host {
                                        tracing::warn!(
                                            project = %project_name,
                                            workload = %wl,
                                            replica,
                                            host = %host,
                                            image = %reference,
                                            pull_secret_named = named_but_unresolved,
                                            "no registry credential resolved for image; \
                                             attempting anonymous pull",
                                        );
                                    } else {
                                        tracing::debug!(
                                            project = %project_name,
                                            workload = %wl,
                                            replica,
                                            host = %host,
                                            image = %reference,
                                            "anonymous pull of a public default-registry image \
                                             (no pull_secret configured)",
                                        );
                                    }
                                    None
                                }
                                Err(e) => {
                                    report
                                        .errors
                                        .push(format!("{wl}/{replica}: registry auth: {e}"));
                                    continue;
                                }
                            }
                        }
                        // Defense-in-depth (Security MEDIUM-1): a workload that NAMES a
                        // `pull_secret` but reaches a reconcile with NO registry-auth resolver
                        // wired at all must FAIL CLOSED — never pull anonymously and silently
                        // ignore the named secret. (The production node always wires a resolver,
                        // which also fails closed for an operator host match; this guards a lean
                        // or misconfigured reconcile for the project-scoped reference the spec
                        // makes visible here.)
                        (None, RootSource::Image(_)) if spec.pull_secret.is_some() => {
                            report.errors.push(format!(
                                "{wl}/{replica}: registry auth: pull_secret {:?} is named but no \
                                 registry-auth resolver is configured on this node; refusing to \
                                 pull anonymously",
                                spec.pull_secret.as_deref().unwrap_or_default()
                            ));
                            continue;
                        }
                        _ => None,
                    };
                    match launch_one(
                        b.as_ref(),
                        &project_name,
                        &wl,
                        replica,
                        node,
                        node_region,
                        &spec,
                        &workload.active,
                        &launch_env,
                        privilege.as_ref(),
                        pull_auth.as_ref(),
                    )
                    .await
                    {
                        Ok(state) => match deploy.set_replica_state(project, &state).await {
                            Ok(()) => report.launched += 1,
                            Err(e) => report.errors.push(format!("{wl}/{replica}: persist: {e}")),
                        },
                        Err(e) => {
                            // The backend `launch` ERRORED — no instance started (image-pull
                            // denied, no node accepted the placement, a backend fault). Two
                            // things make this visible instead of a silent gap:
                            //
                            //  1) a structured per-failure `warn!` AT the site (project /
                            //     workload / replica / backend / image ref / error), not just
                            //     the aggregated "partial" line; and
                            //  2) a DURABLE `LaunchFailed` replica record carrying the reason,
                            //     so `compute status` shows the ordinal with its failure and
                            //     `db status` reports `launch_failed` + reason (instead of "no
                            //     replicas" / a bare `pending`). The planner relaunches it next
                            //     tick (the same retry a failed launch always got); a success
                            //     overwrites this record with a fresh `Starting` one.
                            //
                            // The reason is the backend error verbatim — the registry-auth layer
                            // already sanitizes its errors to name only secret REFS (never a
                            // credential value), and image refs / registry messages are not
                            // secret.
                            let reason = e.to_string();
                            tracing::warn!(
                                project = %project_name,
                                workload = %wl,
                                replica,
                                backend = %backend,
                                image = %spec.root.as_str(),
                                error = %reason,
                                "compute: replica launch failed",
                            );
                            let failed = ObservedInstance {
                                handle: InstanceHandle {
                                    project: project_name.clone(),
                                    workload: wl.clone(),
                                    replica,
                                    backend_ref: String::new(),
                                },
                                node,
                                backend: backend.clone(),
                                endpoint: Endpoint {
                                    scheme: Scheme::Http,
                                    host: String::new(),
                                    port: 0,
                                },
                                region: None,
                                healthy: false,
                                started_at: None,
                                phase: ReplicaPhase::Running,
                                readiness: Readiness::LaunchFailed { reason },
                                data_dir: None,
                                snapshot: None,
                                active_spec: Some(workload.active.clone()),
                            };
                            report.errors.push(format!("{wl}/{replica}: launch: {e}"));
                            if let Err(pe) = deploy.set_replica_state(project, &failed).await {
                                report
                                    .errors
                                    .push(format!("{wl}/{replica}: persist launch failure: {pe}"));
                            }
                        }
                    }
                }
                Action::Stop { handle } => {
                    if let Some(b) = observed
                        .iter()
                        .find(|o| o.handle == handle)
                        .and_then(|o| backends.get(&o.backend))
                        && let Err(e) = b.stop(&handle).await
                    {
                        report
                            .errors
                            .push(format!("{}/{}: stop: {e}", handle.workload, handle.replica));
                    }
                    // Revoke this replica's shim tokens (idempotent; independent of the DB cred).
                    if let Some(resolver) = resolver
                        && !spec.bindings.is_empty()
                    {
                        resolver
                            .release(
                                &project_name,
                                &handle.workload,
                                handle.replica,
                                &spec.bindings,
                            )
                            .await;
                    }
                    // Phase 2 (PLAN-compute-managed-db, Security HIGH-1): revoke + drop this
                    // replica's DYNAMIC database credential BEFORE forgetting the replica, so a
                    // revoke failure (e.g. a transient DB outage) is RETRIABLE: the replica
                    // record is kept, the next reconcile re-plans this Stop and retries the
                    // revoke, and the credential never lingers un-dropped past a forgotten
                    // record. The revoke is idempotent (a non-consumer / already-gone role /
                    // already-deleted password are all no-ops), so re-running is harmless. A
                    // stop that is MISSED entirely (crash, node loss, permanent scale-down) is
                    // caught by the orphan reaper's dynamic-cred sweep, which drops any cred
                    // whose replica record is gone.
                    if let Some(m) = managed_db
                        && let Err(e) = m
                            .revoke_dynamic_db_cred(
                                &project_name,
                                &handle.workload,
                                &spec.bindings,
                                handle.replica,
                            )
                            .await
                    {
                        report.errors.push(format!(
                            "{}/{}: revoke dynamic db cred (replica kept for retry): {e}",
                            handle.workload, handle.replica
                        ));
                        // Keep the replica record so the next pass retries; do NOT forget it.
                        continue;
                    }
                    // Credential is gone (or there was none) — now it is safe to forget the
                    // replica. A delete failure is surfaced but still terminal for this pass.
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
                        Ok(Some(mut snapshot)) => {
                            // Stamp the owning project on the parked snapshot so a later
                            // `restore` derives the same project-qualified identity/IPAM
                            // key the launch used (independent of the backend).
                            snapshot.project = project_name.clone();
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
                            // Stamp the owning project on the restored handle so the
                            // persisted record stays consistent (the backend's restore
                            // works off the snapshot ref alone).
                            let mut handle = instance.handle;
                            handle.project = snapshot.project.clone();
                            let state = ObservedInstance {
                                handle,
                                node,
                                backend: backend.clone(),
                                endpoint: instance.endpoint,
                                region: region_of_node(nodes, node),
                                healthy: true,
                                started_at: Some(crate::time::now_unix()),
                                phase: ReplicaPhase::Running,
                                // A woken replica re-advances through the readiness pass
                                // so its (idempotent) post-launch actions re-run.
                                readiness: Readiness::Starting,
                                // Recomputed by the next reconcile tick's readiness pass.
                                data_dir: None,
                                snapshot: None,
                                // A woken replica is brought back as the workload's CURRENT
                                // active spec (restore converges to desired state), so it is
                                // not immediately flagged stale and recreated.
                                active_spec: Some(workload.active.clone()),
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

    // A2 pool-vs-reality reconciliation: after converging every workload, ask each
    // backend to reclaim any IP it still holds for a replica whose container is gone
    // (crashed, or state removed out-of-band) and that is NOT intentionally parked
    // (`parked_keys`). Adoption reserves every persisted replica's IP at boot, and a
    // stop releases on the reconcile path — but a crash between reconciles would leak
    // the address until the backend restarts; this sweeps those. Conservative: a
    // backend reclaims only when it is sure the container is gone, and never a parked
    // replica (whose IP is held for its wake). Backends without a per-node pool no-op.
    for backend in backends.values() {
        backend.gc_ip_pool(&parked_keys).await;
    }

    Ok(report)
}

/// The resource reservation to charge a **running** replica against its node in the
/// cumulative bin-packing pre-pass ([`reconcile_once`]). Resolution order:
///
/// 1. the replica's OWN launched spec, keyed by its `active_spec` content hash and cached
///    (resolved or confirmed-missing) so a workload's many replicas don't each re-fetch;
/// 2. the workload's current active spec — a same-workload proxy, and for a stale replica
///    about to be recreated, exactly the sizing it will take on;
/// 3. the conservative [`UNRESOLVED_RESERVATION`] floor, with the replica surfaced in the
///    report.
///
/// **Fail-safe:** an unresolvable replica is never charged ZERO — that would overstate the
/// node's free capacity and re-open the over-subscription this pass exists to prevent. A
/// legacy record's `active_spec` is backfilled to the workload's active spec on observation
/// and a live workload's active spec resolves, so the floor bites only a genuinely orphaned
/// replica whose spec blob is gone.
async fn running_replica_reservation(
    deploy: &DeployStore,
    cache: &mut BTreeMap<String, Option<Reservation>>,
    state: &ObservedInstance,
    workload_spec: Option<&ComputeSpec>,
    report: &mut ReconcileReport,
) -> Result<Reservation, crate::error::DeployError> {
    // 1) The replica's own launched spec, by content hash (cached: resolved or missing).
    if let Some(hash) = state.active_spec.as_deref() {
        let resolved = match cache.get(hash) {
            Some(cached) => *cached,
            None => {
                let r = deploy
                    .get_compute_spec(hash)
                    .await?
                    .map(|s| Reservation::of_spec(&s));
                cache.insert(hash.to_string(), r);
                r
            }
        };
        if let Some(r) = resolved {
            return Ok(r);
        }
    }
    // 2) Fall back to the workload's current active spec (best same-workload proxy).
    if let Some(spec) = workload_spec {
        return Ok(Reservation::of_spec(spec));
    }
    // 3) FAIL-SAFE: neither resolves — charge a conservative floor, never zero, and surface it.
    report.errors.push(format!(
        "{}/{}: bin-packing: cannot resolve reservation (launched spec {} and workload active \
         spec both missing); charging conservative {}MiB/{}vCPU floor to avoid over-subscription",
        state.handle.workload,
        state.handle.replica,
        state.active_spec.as_deref().unwrap_or("<none>"),
        UNRESOLVED_RESERVATION.mem_mib,
        UNRESOLVED_RESERVATION.vcpus,
    ));
    Ok(UNRESOLVED_RESERVATION)
}

/// Whether the reconcile should run the **read-only** data-dir-ownership diagnosis for a
/// `Running` replica this tick. A rootless managed database whose data directory carries
/// foreign-owned files `EPERM`s its own cluster files and FATALs *before* binding its
/// port, so the fault signature is "launched but not listening" (`!healthy`) that persists
/// past the replica's startup grace. A healthy server (port up) is never scanned — it
/// could read its data directory, so ownership is fine — and neither is a normally-
/// initializing one still inside its grace. A record with no `started_at` (older/restored)
/// is treated as past-grace. Pure, so the window is unit-tested without a full reconcile.
fn should_diagnose_data_dir(
    healthy: bool,
    started_at: Option<u64>,
    now: u64,
    grace_secs: u64,
) -> bool {
    !healthy && started_at.is_none_or(|at| now.saturating_sub(at) >= grace_secs)
}

/// The region of node `id` in `nodes`, for tagging a replica's endpoint (FA-8).
fn region_of_node(nodes: &[Node], id: u64) -> Option<String> {
    nodes
        .iter()
        .find(|n| n.id == id)
        .and_then(|n| n.region.clone())
}

/// Compute a Running replica's new [`Readiness`] from its current `healthy` and — for a
/// managed database — a real service probe (`SELECT 1`) followed by its derived
/// post-launch provisioning. Pure of persistence: the caller writes the result back only
/// on a change. Idempotent and safe to call every tick (it skips the DDL once a replica
/// is already [`Provisioned`](Readiness::Provisioned)).
async fn advance_readiness(
    backend: &dyn ComputeBackend,
    managed_db: Option<&dyn ManagedDbEnvResolver>,
    project: &str,
    spec: &ComputeSpec,
    state: &ObservedInstance,
) -> Readiness {
    if !state.healthy {
        // Runner up but the service is not confirmed (a never-ready launch, or a DB that
        // stopped answering). Fall back to Starting so the gated surfaces stop routing.
        return Readiness::Starting;
    }
    // Already provisioned: done — don't re-run idempotent actions every tick. A relaunch
    // resets this to `Starting` (see `launch_one`), so a replaced replica re-provisions.
    if state.readiness.is_provisioned() {
        return Readiness::Provisioned;
    }
    let workload = &state.handle.workload;
    // 1) Service-readiness probe + the DERIVED managed-DB provisioning (CREATE DATABASE /
    //    roles). A generic workload (or no resolver) has no managed step here.
    if let Some(m) = managed_db {
        match m
            .probe_managed_ready(project, workload, &state.endpoint)
            .await
        {
            // Not a managed database → generic path (fall through to post-launch actions).
            None => {}
            // Listens but does not answer yet — still initializing, OR cannot read its data
            // directory (the data-dir-ownership failure surfaces here as a stuck `Starting`
            // instead of a silent healthy-but-broken container).
            Some(false) => return Readiness::Starting,
            // The service answers → run the derived provisioning DDL (idempotent).
            Some(true) => {
                if let Err(reason) = m
                    .provision_managed(project, workload, &state.endpoint)
                    .await
                {
                    return Readiness::ProvisionFailed { reason };
                }
            }
        }
    }
    // 2) The GENERAL user-declared post-launch actions (ComputeSpec::post_launch), run for
    //    both managed and generic workloads once service-ready, before `Provisioned`.
    //    Idempotent (re-run on every relaunch) — see `PostLaunchAction`.
    if let Err(reason) = run_post_launch(backend, spec, state).await {
        return Readiness::ProvisionFailed { reason };
    }
    Readiness::Provisioned
}

/// Run a workload's user-declared [`post_launch`](ComputeSpec::post_launch) actions
/// against its launched instance, in order, stopping at the first failure. Idempotent by
/// contract (the caller re-runs it on every relaunch). An empty list is a no-op.
async fn run_post_launch(
    backend: &dyn ComputeBackend,
    spec: &ComputeSpec,
    state: &ObservedInstance,
) -> Result<(), String> {
    for action in &spec.post_launch {
        match action {
            PostLaunchAction::Exec { argv } => {
                match backend.exec(&state.handle, argv, None).await {
                    Ok(out) if out.exit_code == 0 => {}
                    Ok(out) => {
                        // A trimmed stderr tail for diagnosis (the operator's own command's
                        // output — no boatramp secret material).
                        let tail = String::from_utf8_lossy(&out.stderr);
                        let tail = tail.trim();
                        let tail = &tail[tail.len().saturating_sub(200)..];
                        return Err(format!(
                            "post-launch exec {argv:?} exited {}: {tail}",
                            out.exit_code
                        ));
                    }
                    Err(e) => return Err(format!("post-launch exec {argv:?}: {e}")),
                }
            }
        }
    }
    Ok(())
}

/// Materialize + launch one replica, returning its observed state.
#[allow(clippy::too_many_arguments)]
async fn launch_one(
    backend: &dyn ComputeBackend,
    project: &str,
    workload: &str,
    replica: u32,
    node: u64,
    node_region: Option<String>,
    spec: &ComputeSpec,
    active_spec: &str,
    extra_env: &[(String, String)],
    privilege: Option<&PrivilegeDirective>,
    pull_auth: Option<&RegistryAuth>,
) -> Result<ObservedInstance, BackendError> {
    // The launch wall-clock time, so the next reconcile tick can grant this replica a
    // startup grace before treating it as a broken launch (see `reconcile_plan`).
    let started_at = crate::time::now_unix();
    let artifact = backend
        .materialize(project, workload, spec, pull_auth)
        .await?;
    // Fold the resolved binding env into the launched spec. A hand-set **literal** always
    // wins (never clobbered by a binding default) — EXCEPT a value that is an operator
    // **template** (contains a `{{…}}` placeholder): that is replaced by the resolver's
    // SERVER-SIDE-rendered value (the filled DSN / unsealed secret), since the raw
    // template is not what the workload should receive. A key the operator did not set is
    // injected as the binding default. No pre-existing workload has `{{` in an env value,
    // so this only activates the new managed-DB templating path.
    let mut spec = spec.clone();
    // Collect the secret-sourced redaction set AS we fold: a value from `extra_env` that
    // is actually APPLIED to the guest env (it rendered an operator template, or filled an
    // unset key) is secret-sourced — it came from the binding resolver / managed-DB
    // server-init env, not an operator literal — so it is recorded for guest-log redaction.
    // A hand-set operator literal that WINS is NOT recorded (provenance, not name). This
    // reuses the exact distinction the fold already makes; see [`RedactionSet`].
    let mut redaction = RedactionSet::new();
    for (k, v) in extra_env {
        match spec.env.get(k) {
            // Operator templated this var — take the rendered (secret-sourced) value.
            Some(existing) if existing.contains("{{") => {
                spec.env.insert(k.clone(), v.clone());
                redaction.push(v.clone());
            }
            // Hand-set literal — operator wins, keep it (NOT secret-sourced).
            Some(_) => {}
            // Unset — inject the binding default (secret-sourced).
            None => {
                spec.env.insert(k.clone(), v.clone());
                redaction.push(v.clone());
            }
        }
    }
    // A managed-DB privilege strategy (rootless user / cap allowlist) — launch spec
    // only; never overrides an operator-set `user`/`cap_add`.
    if let Some(p) = privilege {
        p.apply(&mut spec);
    }
    let instance = backend
        .launch(&LaunchRequest {
            project: project.to_string(),
            workload: workload.to_string(),
            replica,
            spec: spec.clone(),
            artifact,
            redaction,
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
    // The reconcile is the source of truth for the owning project; stamp it on the
    // returned handle so the persisted record always carries it (independent of the
    // backend) and the key/state stay consistent.
    let mut handle = instance.handle;
    handle.project = project.to_string();
    Ok(ObservedInstance {
        handle,
        node,
        backend: backend.id().to_string(),
        endpoint: instance.endpoint,
        region: node_region,
        healthy,
        started_at: Some(started_at),
        phase: ReplicaPhase::Running,
        // Freshly launched: the reconcile's readiness pass probes service-readiness +
        // runs post-launch actions to advance this to Provisioned (or ProvisionFailed).
        readiness: Readiness::Starting,
        // Diagnosed by the reconcile only if this replica stays stuck up-but-not-answering.
        data_dir: None,
        snapshot: None,
        // Stamp the spec pointer this replica was launched from, so the next time the
        // workload's `active` differs the reconcile RECREATES it (the redeploy path).
        active_spec: Some(active_spec.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_client_image_matches_the_server_major() {
        // pg16 server (160004) -> the pg16 client, NOT an older one. This is the
        // load-bearing version-match: the anti-hollow gate mutates this to pick a lower
        // major (e.g. pg13) and the live round-trip's restore then errors.
        assert_eq!(
            pg_client_image_for_server_version("160004").unwrap(),
            "pgvector/pgvector:pg16"
        );
        assert_eq!(
            pg_client_image_for_server_version("170001").unwrap(),
            "pgvector/pgvector:pg17"
        );
        // The default managed image is pg16 — detection must agree with it.
        assert_eq!(
            pg_client_image_for_server_version("160000").unwrap(),
            "pgvector/pgvector:pg16"
        );
        // Whitespace in the banner is tolerated.
        assert_eq!(
            pg_client_image_for_server_version("  150002\n").unwrap(),
            "pgvector/pgvector:pg15"
        );
    }

    #[test]
    fn pg_client_image_refuses_rather_than_guesses() {
        // Unparsable banner.
        assert!(matches!(
            pg_client_image_for_server_version("not-a-number"),
            Err(VersionMapError::Unparsable(_))
        ));
        // Pre-10 (9.6.24 -> 90624) is too old.
        assert!(matches!(
            pg_client_image_for_server_version("90624"),
            Err(VersionMapError::TooOld(9, _))
        ));
        // A major below the client-image floor.
        assert!(matches!(
            pg_client_image_for_server_version("120004"),
            Err(VersionMapError::TooOld(12, PG_CLIENT_MIN_MAJOR))
        ));
        // A major beyond what we can name an image for: refuse (never downgrade the
        // client below the server — it could not read the newer dump).
        assert!(matches!(
            pg_client_image_for_server_version("990000"),
            Err(VersionMapError::TooNew(99, PG_CLIENT_MAX_MAJOR))
        ));
    }

    #[test]
    fn mysql_client_image_matches_major_minor_and_refuses_mariadb() {
        // maj.min image at the server's version (ignore patch + suffix).
        assert_eq!(
            mysql_client_image_for_server_version("8.0.35").unwrap(),
            "mysql:8.0"
        );
        assert_eq!(
            mysql_client_image_for_server_version("8.4.0").unwrap(),
            "mysql:8.4"
        );
        assert_eq!(
            mysql_client_image_for_server_version("5.7.44").unwrap(),
            "mysql:5.7"
        );
        assert_eq!(
            mysql_client_image_for_server_version("8.0.35-0ubuntu0.1").unwrap(),
            "mysql:8.0"
        );
        // MariaDB is REFUSED (a distinct dialect) — never silently dumped with mysql.
        assert!(matches!(
            mysql_client_image_for_server_version("10.11.6-MariaDB-1:10.11.6+maria~ubu2204"),
            Err(VersionMapError::MariaDb(_))
        ));
        assert!(matches!(
            mysql_client_image_for_server_version("11.4.2-MariaDB"),
            Err(VersionMapError::MariaDb(_))
        ));
        // Pre-5 and unparsable are refused.
        assert!(matches!(
            mysql_client_image_for_server_version("4.1.22"),
            Err(VersionMapError::TooOld(4, MYSQL_CLIENT_MIN_MAJOR))
        ));
        assert!(matches!(
            mysql_client_image_for_server_version("not-a-version"),
            Err(VersionMapError::Unparsable(_))
        ));
    }

    #[test]
    fn compute_instance_id_qualifies_by_project_but_keeps_default_bare() {
        // The default-project identity is BYTE-IDENTICAL to the pre-v0.3.12 bare
        // `<workload>-<replica>` (so existing deployments' cgroup/veth/hostname/IP
        // slot are undisturbed). An empty project string (a not-yet-backfilled legacy
        // handle) is treated as `default`, so it too stays bare.
        assert_eq!(compute_instance_id("default", "web", 0), "web-0");
        assert_eq!(compute_instance_id("", "web", 0), "web-0");
        assert_eq!(compute_instance_id("default", "api-v2", 3), "api-v2-3");

        // A non-default project is qualified with the project prefix, so two projects'
        // same-named workloads derive DISTINCT ids (→ distinct cgroup/veth/hostname).
        assert_eq!(compute_instance_id("acme", "web", 0), "acme-web-0");
        assert_eq!(compute_instance_id("beta", "web", 0), "beta-web-0");
        assert_ne!(
            compute_instance_id("acme", "web", 0),
            compute_instance_id("beta", "web", 0),
            "same-named workloads in different projects must NOT collide on id"
        );
        // And the qualified form never collides with the bare default form.
        assert_ne!(
            compute_instance_id("acme", "web", 0),
            compute_instance_id("default", "web", 0)
        );
    }

    /// The Docker-29 service-discovery fix (RFC 1035 63-octet label cap): a short, valid
    /// workload name is published as-is (so every pre-existing deployment and the green gate
    /// are byte-unchanged), while a name over 63 octets — the real `Single` managed-DB shape
    /// `bramp-db-<25>-<body>_<25>` — is mapped to a short, STABLE, DNS-valid alias. This is the
    /// VERSION-INDEPENDENT guard: it fails on ANY host (no docker needed) if the emitted alias
    /// could ever exceed a DNS label, which is exactly what Docker 29.9.1 refuses to register.
    #[test]
    fn managed_db_alias_fits_a_dns_label_and_is_stable() {
        // Short/valid names pass straight through — no behavior change anywhere.
        assert_eq!(managed_db_alias("web"), "web");
        assert_eq!(managed_db_alias("pg"), "pg");
        let shared = "bramp-db-abcdefghijklmnopqrstuvwxy"; // 34 octets (≤ 63): unchanged
        assert!(shared.len() <= DNS_LABEL_MAX_LEN);
        assert_eq!(managed_db_alias(shared), shared);

        // A realistic >63-octet `Single` managed-DB workload name: `<compute>-<ident>` where
        // BOTH halves carry a 25-char digest — the exact shape that broke on Docker 29.9.1.
        let h = "abcdefghijklmnopqrstuvwxy"; // 25 base-36 chars
        let long = format!("bramp-db-{h}-acme_{h}");
        assert!(
            long.len() > DNS_LABEL_MAX_LEN,
            "fixture must exceed the 63-octet DNS label cap (the bug): got {}",
            long.len()
        );
        let alias = managed_db_alias(&long);
        assert!(
            alias.len() <= DNS_LABEL_MAX_LEN,
            "the emitted alias MUST fit a DNS label or Docker 29 drops its SD record: {alias} ({} octets)",
            alias.len()
        );
        assert!(
            is_valid_dns_label(&alias),
            "the emitted alias must be a valid DNS label: {alias}"
        );
        assert!(alias.starts_with("bramp-db-"), "greppable prefix: {alias}");
        // Pure + stable across calls (the launch alias and the DSN host must agree, forever).
        assert_eq!(alias, managed_db_alias(&long));
        // Distinct long workloads ⇒ distinct aliases (per-project uniqueness).
        let long2 = format!("bramp-db-{h}-beta_{h}");
        assert_ne!(
            managed_db_alias(&long),
            managed_db_alias(&long2),
            "distinct managed-DB workloads must not collide on their SD alias"
        );
    }

    #[test]
    fn is_valid_dns_label_enforces_the_63_octet_cap() {
        assert!(is_valid_dns_label("pg"));
        assert!(is_valid_dns_label("bramp-db-acme_0123456789abcdef")); // `_` is accepted
        assert!(is_valid_dns_label(&"a".repeat(DNS_LABEL_MAX_LEN)));
        assert!(!is_valid_dns_label(&"a".repeat(DNS_LABEL_MAX_LEN + 1))); // 64 octets: invalid
        assert!(!is_valid_dns_label("")); // empty
        assert!(!is_valid_dns_label("-lead")); // leading hyphen
        assert!(!is_valid_dns_label("trail-")); // trailing hyphen
    }

    #[test]
    fn compute_volume_scope_is_injective_over_project_and_workload() {
        // Bare `<workload>` for the default project (and an empty/legacy project);
        // `<project>@<workload>` otherwise — an `@` join, outside the slug alphabet.
        assert_eq!(compute_volume_scope("default", "pg"), "pg");
        assert_eq!(compute_volume_scope("", "pg"), "pg");
        assert_eq!(compute_volume_scope("acme", "pg"), "acme@pg");

        // The collision the scope closes: two co-located DEFAULT-project managed DBs — each
        // handed the bare volume name `"data"` — used to share one backing dir; keyed by the
        // workload they are now DISTINCT.
        assert_ne!(
            compute_volume_scope("default", "pg"),
            compute_volume_scope("default", "control"),
            "two default-project managed DBs must get distinct volume scopes"
        );
        // Two projects' same-named workloads never collide, and never collide with the bare
        // default form.
        assert_ne!(
            compute_volume_scope("acme", "pg"),
            compute_volume_scope("beta", "pg")
        );
        assert_ne!(
            compute_volume_scope("acme", "pg"),
            compute_volume_scope("default", "pg")
        );
        // INJECTIVE even for crafted names with interior `-`: a `-` join would alias
        // ("a","b-c") with ("a-b","c"); the `@` join keeps them distinct (the bug a `-`
        // join would reopen).
        assert_ne!(
            compute_volume_scope("a", "b-c"),
            compute_volume_scope("a-b", "c"),
            "the @ join must be injective where a - join is not"
        );
        assert_eq!(compute_volume_scope("a", "b-c"), "a@b-c");
        assert_eq!(compute_volume_scope("a-b", "c"), "a-b@c");
    }

    #[test]
    fn managed_db_spec_is_launchable_and_privilege_deferred() {
        // Postgres: default image, port, one volume at the data dir, explicit
        // entrypoint (the shared-kernel backends don't apply OCI config), and
        // `user`/`cap_add` LEFT UNSET so the privilege directive owns them.
        let pg = managed_db_spec(ManagedDbEngine::Postgres, None, 2048, false);
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
        let my = managed_db_spec(ManagedDbEngine::Mysql, Some("mysql:8.4"), 512, false);
        assert_eq!(my.root, RootSource::Image("mysql:8.4".into()));
        // delta_capture=false ⇒ no replication flags in either engine's argv.
        assert!(!pg.entrypoint.iter().any(|a| a == "wal_level=logical"));
        assert!(!my.entrypoint.iter().any(|a| a.starts_with("--log-bin")));
        assert_eq!(my.port, 3306);
        assert_eq!(my.volumes[0].mount, "/var/lib/mysql");

        // Per-engine startup graces (slow first `initdb`): Postgres 60, MySQL 120 —
        // both above the generic 30 a plain compute spec carries.
        assert_eq!(pg.startup_grace_secs, 60);
        assert_eq!(my.startup_grace_secs, 120);
        assert_eq!(default_startup_grace_secs(), 30);
        assert_eq!(spec(1, 64).startup_grace_secs, 30);
    }

    /// `delta_capture=true` adds the engine's row-level-change flags to the launch argv (so a
    /// delta export can ship a WAL/binlog true-delta), and — because these are start-only server
    /// settings baked into the content-addressed spec — it CHANGES the spec id, which is exactly
    /// what forces a relaunch to adopt the change (the restart primitive).
    #[test]
    fn delta_capture_adds_replication_argv_and_remints_the_spec() {
        let pg_off = managed_db_spec(ManagedDbEngine::Postgres, None, 2048, false);
        let pg_on = managed_db_spec(ManagedDbEngine::Postgres, None, 2048, true);
        assert!(pg_on.entrypoint.iter().any(|a| a == "wal_level=logical"));
        assert!(
            pg_on
                .entrypoint
                .iter()
                .any(|a| a == "max_replication_slots=10")
        );
        // §4 disk-fill guard: delta_capture MUST set a hard WAL-pinned ceiling so a forgotten
        // slot cannot fill the disk (a quarter of the 2048 MiB volume = 512 MiB, within the band).
        assert!(
            pg_on
                .entrypoint
                .iter()
                .any(|a| a == "max_slot_wal_keep_size=512MB"),
            "delta_capture must cap WAL a slot can pin (disk-fill guard); argv: {:?}",
            pg_on.entrypoint
        );
        // The clamp floors a tiny volume and caps a huge one.
        let tiny = managed_db_spec(ManagedDbEngine::Postgres, None, 64, true);
        assert!(
            tiny.entrypoint
                .iter()
                .any(|a| a == "max_slot_wal_keep_size=256MB"),
            "a tiny volume still gets the 256 MiB floor"
        );
        let huge = managed_db_spec(ManagedDbEngine::Postgres, None, 1_048_576, true);
        assert!(
            huge.entrypoint
                .iter()
                .any(|a| a == "max_slot_wal_keep_size=8192MB"),
            "a huge volume is capped at the 8192 MiB ceiling"
        );
        // delta_capture OFF never pins WAL.
        assert!(
            !pg_off
                .entrypoint
                .iter()
                .any(|a| a.starts_with("max_slot_wal_keep_size"))
        );
        assert_ne!(
            pg_off.id(),
            pg_on.id(),
            "flipping delta_capture must remint the spec so a relaunch adopts it"
        );

        let my_on = managed_db_spec(ManagedDbEngine::Mysql, None, 512, true);
        assert!(my_on.entrypoint.iter().any(|a| a == "--log-bin"));
        assert!(my_on.entrypoint.iter().any(|a| a == "--binlog-format=ROW"));
        assert!(my_on.entrypoint.iter().any(|a| a == "--gtid-mode=ON"));
        // With binary logging on, a non-SUPER CREATE TRIGGER/FUNCTION (the export/import carry path)
        // needs log_bin_trust_function_creators=ON (ERROR 1419 otherwise). Benign under ROW binlog.
        assert!(
            my_on
                .entrypoint
                .iter()
                .any(|a| a == "--log-bin-trust-function-creators=ON"),
            "a binlog-on managed mysqld must trust function/trigger creators so the non-superuser \
             shadow restore can carry triggers + routines"
        );
        // A binlog-OFF managed mysqld does not hit ERROR 1419, so it carries no such flag.
        let my_off = managed_db_spec(ManagedDbEngine::Mysql, None, 512, false);
        assert!(
            !my_off
                .entrypoint
                .iter()
                .any(|a| a.starts_with("--log-bin-trust-function-creators"))
        );
        // AUTH (UNCONDITIONAL — every managed mysql, delta or not): the `mysql:8.0` image defaults
        // accounts to caching_sha2_password, which our plain-TCP (no-TLS, no-pubkey) clients cannot
        // authenticate against, so the spec defaults them to mysql_native_password. Present for BOTH
        // delta and non-delta mysql; never on a pg spec.
        for my in [&my_on, &my_off] {
            assert!(
                my.entrypoint
                    .iter()
                    .any(|a| a == "--default-authentication-plugin=mysql_native_password"),
                "every managed mysqld must default accounts to native_password for plain-TCP auth: {:?}",
                my.entrypoint
            );
        }
        assert!(
            !pg_on
                .entrypoint
                .iter()
                .any(|a| a.contains("authentication-plugin")),
            "the mysql auth-plugin flag must never leak onto a Postgres spec"
        );
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
            pull_secret: None,
            bindings: vec![],
            post_launch: vec![],
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
        assert!(
            place_replicas(
                2,
                &PlacementConstraints::default(),
                &s,
                &nodes,
                &BackendPolicy::default()
            )
            .is_empty()
        );
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
                project: "default".into(),
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
            // A healthy baseline replica is fully provisioned (what the reconcile tests
            // expect); the readiness-specific tests set this explicitly.
            readiness: if healthy {
                Readiness::Provisioned
            } else {
                Readiness::Starting
            },
            data_dir: None,
            snapshot: None,
            // Baseline helper: unset (treated as "matches" — the spec-change tests set
            // this explicitly to exercise the recreate path).
            active_spec: None,
        }
    }

    /// A scaled-to-zero observed replica (phase `Zero` + a snapshot to wake from).
    fn zeroed(workload: &str, replica: u32, node: u64) -> ObservedInstance {
        let mut o = observed(workload, replica, node, false);
        o.phase = ReplicaPhase::Zero;
        o.snapshot = Some(Snapshot {
            project: "default".into(),
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
            &BTreeSet::new(),
        )
        .actions
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
            &BTreeSet::new(),
        )
        .actions;
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
            &BTreeSet::new(),
        )
        .actions;
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
            &BTreeSet::new(),
        )
        .actions;
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
            &BTreeSet::new(),
        )
        .actions;
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
            &BTreeSet::new(),
        )
        .actions;
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
            &BTreeSet::new(),
        )
        .actions;
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Stop { handle } if handle.replica == 1))
        );
        assert!(
            !actions.iter().any(|a| matches!(a, Action::Restore { .. })),
            "out-of-range parked replica is stopped, not restored"
        );
    }

    #[test]
    fn unplaceable_workload_is_reported_unscheduled_not_silently_dropped() {
        // The PRIMARY bug: with no node able to place the replica, the planner used to zip
        // `need` against an empty placement list and silently drop the tail — the workload
        // then vanished from `compute status` with zero diagnostics. The fix surfaces the
        // unplaced ordinal in `ReconcilePlan::unscheduled` (so the driver logs + reports it).
        // Mutating the fix to drop the `unscheduled` tail turns this RED.
        let nodes: Vec<Node> = vec![];
        let plan = reconcile_plan(
            &workload(1, Default::default()),
            &spec(2, 512),
            &nodes,
            &BackendPolicy::default(),
            &[],
            WorkloadActivity::Active,
            &BTreeMap::new(),
            u64::MAX,
            &BTreeSet::new(),
        );
        assert!(
            !plan
                .actions
                .iter()
                .any(|a| matches!(a, Action::Launch { .. })),
            "no capacity ⇒ no Launch emitted: {:?}",
            plan.actions
        );
        assert_eq!(
            plan.unscheduled.len(),
            1,
            "the unplaced ordinal must be surfaced, not silently dropped: {:?}",
            plan.unscheduled
        );
        let u = &plan.unscheduled[0];
        assert_eq!(u.replica, 0);
        assert!(
            u.reason.contains("no eligible backend with capacity"),
            "names the shortfall: {}",
            u.reason
        );
        assert!(
            u.reason.contains("2vcpu/512MiB"),
            "names the resource need so the operator sees what to add: {}",
            u.reason
        );
    }

    #[test]
    fn partial_placement_launches_what_fits_and_reports_the_rest() {
        // One node with room for exactly ONE replica of a 2-vcpu spec; the workload wants 2.
        // The head still launches; the unplaced tail is REPORTED (not dropped) so a partial
        // scale-up is visible rather than a quietly-short replica set.
        let nodes = vec![vmm(1, "eu", 2, 4096)];
        let plan = reconcile_plan(
            &workload(2, Default::default()),
            &spec(2, 512),
            &nodes,
            &BackendPolicy::default(),
            &[],
            WorkloadActivity::Active,
            &BTreeMap::new(),
            u64::MAX,
            &BTreeSet::new(),
        );
        let launches = plan
            .actions
            .iter()
            .filter(|a| matches!(a, Action::Launch { .. }))
            .count();
        assert_eq!(launches, 1, "exactly one replica fits: {:?}", plan.actions);
        assert_eq!(
            plan.unscheduled.len(),
            1,
            "the second replica is reported unscheduled: {:?}",
            plan.unscheduled
        );
        assert_eq!(plan.unscheduled[0].replica, 1);
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

    /// Bug A: a REDEPLOY (the workload's `active` spec pointer changed) must RECREATE an
    /// existing healthy replica — Stop the old one AND relaunch its ordinal from the new
    /// spec — not keep it. This is the path the pre-fix planner was blind to (a healthy
    /// replica was simply kept, so a changed spec never re-ran `launch`, and docker's own
    /// restart policy merely restarted the stale container in place).
    #[test]
    fn reconcile_recreates_on_spec_hash_change() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        // Workload's active is "h" (the `workload` helper), but the replica was launched
        // from an older pointer → stale → recreate.
        let obs = vec![ObservedInstance {
            active_spec: Some("computever/old".into()),
            ..observed("w", 0, 1, true)
        }];
        let actions = plan(
            &workload(1, Default::default()),
            &spec(1, 256),
            &nodes,
            &BackendPolicy::default(),
            &obs,
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Stop { handle } if handle.replica == 0)),
            "the stale replica is stopped: {actions:?}"
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Launch { replica: 0, .. })),
            "and its ordinal relaunched from the new spec: {actions:?}"
        );
    }

    /// Bug A idempotency: when the replica's recorded spec pointer MATCHES the workload's
    /// current `active`, a healthy at-desired workload stays a strict no-op (no spurious
    /// recreate even though the field is now populated).
    #[test]
    fn reconcile_is_noop_when_spec_hash_unchanged() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let obs = vec![ObservedInstance {
            active_spec: Some("h".into()), // == workload().active
            ..observed("w", 0, 1, true)
        }];
        let actions = plan(
            &workload(1, Default::default()),
            &spec(1, 256),
            &nodes,
            &BackendPolicy::default(),
            &obs,
        );
        assert!(actions.is_empty(), "unchanged spec → no-op: {actions:?}");
    }

    /// Bug A back-compat: a legacy record with no recorded spec pointer (`None`) is never
    /// counted stale, so it is never spuriously recreated (the reconcile backfills it to
    /// the current `active` so a *subsequent* real change is caught).
    #[test]
    fn reconcile_does_not_recreate_a_legacy_none_spec_replica() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let obs = vec![observed("w", 0, 1, true)]; // active_spec: None
        let actions = plan(
            &workload(1, Default::default()),
            &spec(1, 256),
            &nodes,
            &BackendPolicy::default(),
            &obs,
        );
        assert!(
            actions.is_empty(),
            "legacy None spec left alone: {actions:?}"
        );
    }

    /// Bug A scope guard: an EXITED run-to-completion job (`RestartPolicy::Never`,
    /// unhealthy) is left terminal even when its spec pointer is stale — a redeploy must
    /// not resurrect a finished batch run (the new spec takes effect on its next launch).
    #[test]
    fn reconcile_does_not_resurrect_an_exited_never_job_on_spec_change() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        let mut s = spec(1, 256);
        s.restart = RestartPolicy::Never;
        let obs = vec![ObservedInstance {
            active_spec: Some("computever/old".into()),
            ..observed("w", 0, 1, false) // exited (unhealthy) run-to-completion
        }];
        let actions = plan(
            &workload(1, Default::default()),
            &s,
            &nodes,
            &BackendPolicy::default(),
            &obs,
        );
        assert!(
            actions.is_empty(),
            "an exited Never job is not recreated on a spec change: {actions:?}"
        );
    }

    /// Bug A auto-heal (Bug C companion): a HEALTHY replica whose spec pointer MATCHES the
    /// desired `active` is still RECREATED when the driver flags its ordinal in
    /// `force_recreate` (the backend's `needs_redeploy` — a docker container stuck on the
    /// wrong primary network). With an empty set the same replica is a strict no-op, so the
    /// signal is the only thing that moves it (idempotent once re-shaped).
    #[test]
    fn reconcile_recreates_when_force_recreate_flags_the_ordinal() {
        let nodes = vec![vmm(1, "eu", 8, 8192)];
        // Healthy, spec pointer == workload().active ("h") → normally kept.
        let obs = vec![ObservedInstance {
            active_spec: Some("h".into()),
            ..observed("w", 0, 1, true)
        }];
        // Empty set → no-op (the baseline the auto-heal must not disturb).
        let none = reconcile_plan(
            &workload(1, Default::default()),
            &spec(1, 256),
            &nodes,
            &BackendPolicy::default(),
            &obs,
            WorkloadActivity::Active,
            &BTreeMap::new(),
            u64::MAX,
            &BTreeSet::new(),
        )
        .actions;
        assert!(none.is_empty(), "no force flag → no-op: {none:?}");
        // Ordinal 0 flagged → recreate (Stop + relaunch).
        let forced = reconcile_plan(
            &workload(1, Default::default()),
            &spec(1, 256),
            &nodes,
            &BackendPolicy::default(),
            &obs,
            WorkloadActivity::Active,
            &BTreeMap::new(),
            u64::MAX,
            &BTreeSet::from([0u32]),
        )
        .actions;
        assert!(
            forced
                .iter()
                .any(|a| matches!(a, Action::Stop { handle } if handle.replica == 0)),
            "the flagged replica is stopped: {forced:?}"
        );
        assert!(
            forced
                .iter()
                .any(|a| matches!(a, Action::Launch { replica: 0, .. })),
            "and relaunched (re-running launch → correct primary network): {forced:?}"
        );
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
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Stop { handle } if handle.replica == 1))
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Launch { replica: 1, .. }))
        );
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
            &BTreeSet::new(),
        )
        .actions;
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
            &BTreeSet::new(),
        )
        .actions;
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
            &BTreeSet::new(),
        )
        .actions;
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Stop { handle } if handle.replica == 0)),
            "None started_at preserves the prior immediate relaunch: {actions:?}"
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Launch { replica: 0, .. }))
        );
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
            &BTreeSet::new(),
        )
        .actions;
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
        async fn materialize(
            &self,
            _project: &str,
            _workload: &str,
            _spec: &ComputeSpec,
            _pull_auth: Option<&RegistryAuth>,
        ) -> Result<Artifact, BackendError> {
            Ok(Artifact::Image {
                reference: "img:latest".into(),
            })
        }
        async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
            Ok(Instance {
                handle: InstanceHandle {
                    project: req.project.clone(),
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
        // Controllable exec for the post-launch-action tests: argv `["fail", …]` exits
        // non-zero (with a stderr tail), anything else exits 0.
        async fn exec(
            &self,
            _handle: &InstanceHandle,
            argv: &[String],
            _stdin: Option<&[u8]>,
        ) -> Result<ExecOutput, BackendError> {
            let fail = argv.first().map(String::as_str) == Some("fail");
            Ok(ExecOutput {
                exit_code: if fail { 1 } else { 0 },
                stdout: Vec::new(),
                stderr: if fail { b"boom".to_vec() } else { Vec::new() },
            })
        }
    }

    #[tokio::test]
    async fn fake_backend_round_trips_through_the_trait() {
        let backend: Box<dyn ComputeBackend> = Box::new(FakeBackend);
        assert_eq!(backend.id(), "fake");
        let s = spec(1, 128);
        let artifact = backend
            .materialize("default", "fake", &s, None)
            .await
            .unwrap();
        let inst = backend
            .launch(&LaunchRequest {
                project: "default".into(),
                workload: "w".into(),
                replica: 0,
                spec: s,
                artifact,
                redaction: Default::default(),
            })
            .await
            .unwrap();
        assert_eq!(inst.endpoint.url(), "http://127.0.0.1:8080");
        assert_eq!(backend.health(&inst.handle).await.unwrap(), Health::Healthy);
        backend.stop(&inst.handle).await.unwrap();
        // Default snapshot/restore: unsupported.
        assert!(backend.snapshot(&inst.handle).await.unwrap().is_none());
    }

    /// A backend that records the `LaunchRequest.redaction` set + the final `spec.env`
    /// it was handed, so a test can assert what `launch_one` collected for redaction.
    #[derive(Clone, Default)]
    struct RedactionCaptureBackend {
        redaction: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        env: std::sync::Arc<std::sync::Mutex<BTreeMap<String, String>>>,
    }

    #[async_trait]
    impl ComputeBackend for RedactionCaptureBackend {
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
        async fn materialize(
            &self,
            _project: &str,
            _workload: &str,
            _spec: &ComputeSpec,
            _pull_auth: Option<&RegistryAuth>,
        ) -> Result<Artifact, BackendError> {
            Ok(Artifact::Image {
                reference: "img:latest".into(),
            })
        }
        async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
            *self.redaction.lock().unwrap() = req.redaction.values().to_vec();
            *self.env.lock().unwrap() = req.spec.env.clone();
            Ok(Instance {
                handle: InstanceHandle {
                    project: req.project.clone(),
                    workload: req.workload.clone(),
                    replica: req.replica,
                    backend_ref: "fake".into(),
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

    /// Provenance scoping: `launch_one` collects into `LaunchRequest.redaction` exactly the
    /// resolved values that are SECRET-SOURCED — a value that rendered an operator template
    /// (`{{…}}`) or filled an unset key — and NEVER an operator-set literal that won. This
    /// is the seam the guest-log redaction binds to; if the collection is removed the set is
    /// empty and this test goes RED (mutation-sensitive).
    #[tokio::test]
    async fn launch_one_collects_secret_sourced_env_not_operator_literals() {
        let backend = RedactionCaptureBackend::default();
        let mut s = spec(1, 128);
        // One operator TEMPLATE (filled by a secret-sourced resolver) + one operator
        // hardcoded LITERAL (operator wins; not secret).
        s.env.insert("DB_URL".into(), "{{sql.dsn}}".into());
        s.env.insert("LOG_LEVEL".into(), "debug".into());

        // The resolver's output: the rendered DSN replaces the template; an injected TOKEN
        // fills an unset key; a LOG_LEVEL default is OVERRIDDEN by the operator literal.
        let dsn = "postgres://app:S3cr3t@bramp-db-abc.flycast:5432/app".to_string();
        let token = "minted-token-0123456789abcdef".to_string();
        let extra_env = vec![
            ("DB_URL".to_string(), dsn.clone()),
            ("TOKEN".to_string(), token.clone()),
            ("LOG_LEVEL".to_string(), "info-from-resolver".to_string()),
        ];

        let _ = launch_one(
            &backend, "default", "w", 0, 1, None, &s, "spec-a", &extra_env, None, None,
        )
        .await
        .expect("launch");

        let collected = backend.redaction.lock().unwrap().clone();
        assert!(
            collected.contains(&dsn),
            "the rendered secret DSN must be collected: {collected:?}"
        );
        assert!(
            collected.contains(&token),
            "the injected token (unset key) must be collected: {collected:?}"
        );
        assert!(
            !collected.iter().any(|v| v == "debug"),
            "an operator LITERAL must NOT be collected: {collected:?}"
        );
        assert!(
            !collected.iter().any(|v| v == "info-from-resolver"),
            "a resolver default OVERRIDDEN by an operator literal must NOT be collected: {collected:?}"
        );
        assert_eq!(collected.len(), 2, "exactly the two secret-sourced values");

        // And the operator literal survived into the launched env (fold unchanged).
        let env = backend.env.lock().unwrap().clone();
        assert_eq!(env.get("LOG_LEVEL").map(String::as_str), Some("debug"));
        assert_eq!(
            env.get("DB_URL"),
            Some(&dsn),
            "template rendered to the secret value"
        );
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
        async fn materialize(
            &self,
            _project: &str,
            _workload: &str,
            _spec: &ComputeSpec,
            _pull_auth: Option<&RegistryAuth>,
        ) -> Result<Artifact, BackendError> {
            Ok(Artifact::Image {
                reference: "img:latest".into(),
            })
        }
        async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
            Ok(Instance {
                handle: InstanceHandle {
                    project: req.project.clone(),
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
        let unready = launch_one(
            &NotReadyBackend,
            "default",
            "pg",
            0,
            1,
            None,
            &s,
            "computever/h",
            &[],
            None,
            None,
        )
        .await
        .unwrap();
        assert!(
            !unready.healthy,
            "a launched-but-unready replica is recorded unhealthy so the next tick relaunches it"
        );
        assert_eq!(unready.phase, ReplicaPhase::Running);

        // A ready backend still records healthy:true (the happy path is unchanged).
        let ready = launch_one(
            &FakeBackend,
            "default",
            "pg",
            0,
            1,
            None,
            &s,
            "computever/h",
            &[],
            None,
            None,
        )
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
            &BTreeSet::new(),
        )
        .actions;
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
        async fn materialize(
            &self,
            _project: &str,
            _workload: &str,
            _spec: &ComputeSpec,
            _pull_auth: Option<&RegistryAuth>,
        ) -> Result<Artifact, BackendError> {
            Ok(Artifact::Image {
                reference: "img:latest".into(),
            })
        }
        async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
            Ok(Instance {
                handle: InstanceHandle {
                    project: req.project.clone(),
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
                project: handle.project.clone(),
                workload: handle.workload.clone(),
                replica: handle.replica,
                data_ref: format!("snap-{}", handle.replica),
            }))
        }
        async fn restore(&self, snapshot: &Snapshot) -> Result<Instance, BackendError> {
            Ok(Instance {
                handle: InstanceHandle {
                    project: snapshot.project.clone(),
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

    /// A backend that PLACES fine but whose `launch` always ERRORS (an image-pull denial),
    /// so no instance ever starts — the shape behind the live incident's silent gap.
    struct FailingLaunchBackend;

    #[async_trait]
    impl ComputeBackend for FailingLaunchBackend {
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
        async fn materialize(
            &self,
            _project: &str,
            _workload: &str,
            _spec: &ComputeSpec,
            _pull_auth: Option<&RegistryAuth>,
        ) -> Result<Artifact, BackendError> {
            Ok(Artifact::Image {
                reference: "img:latest".into(),
            })
        }
        async fn launch(&self, _req: &LaunchRequest) -> Result<Instance, BackendError> {
            Err(BackendError::Launch(
                "image pull denied for ghcr.io/acme/app:1".into(),
            ))
        }
        async fn stop(&self, _handle: &InstanceHandle) -> Result<(), BackendError> {
            Ok(())
        }
        async fn health(&self, _handle: &InstanceHandle) -> Result<Health, BackendError> {
            Ok(Health::Unhealthy)
        }
    }

    /// Item 2: a launch that `Err`s must persist a DURABLE `LaunchFailed` replica carrying the
    /// reason — so `compute status` shows the ordinal with its failure and `db status`'s
    /// `reduce_readiness` reports `launch_failed` (instead of "no replicas" / a bare
    /// `pending`), and the failure is retried every tick without duplicating or vanishing.
    #[tokio::test]
    async fn failed_launch_persists_a_durable_launch_failed_record_and_retries() {
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(crate::kv::MemoryKv::new()));
        let hash = deploy.put_compute_spec(&spec(1, 128)).await.unwrap();
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
        backends.insert("fake".into(), Arc::new(FailingLaunchBackend));
        let nodes = vec![fake_node()];
        let policy = BackendPolicy::default();

        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &FixedActivity(WorkloadActivity::Active),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.launched, 0, "launch Err'd, nothing launched");
        assert!(
            r.errors.iter().any(|e| e.contains("launch:")),
            "the launch error is reported: {:?}",
            r.errors
        );

        // A durable record exists for the ordinal — NOT a silent gap.
        let states = deploy
            .list_replica_states(crate::project::ProjectRef::DEFAULT, "w")
            .await
            .unwrap();
        assert_eq!(
            states.len(),
            1,
            "the failed ordinal is persisted, not dropped"
        );
        assert_eq!(states[0].phase, ReplicaPhase::Running);
        assert!(!states[0].healthy);
        match &states[0].readiness {
            Readiness::LaunchFailed { reason } => {
                assert!(
                    reason.contains("image pull denied"),
                    "carries the backend reason: {reason}"
                );
            }
            other => panic!("expected LaunchFailed, got {other:?}"),
        }
        // `db status` / `OperatorSql::readiness` read through `reduce_readiness`: it must
        // surface the failure (with its reason) rather than look "pending"/"starting".
        match reduce_readiness(&states) {
            Some(Readiness::LaunchFailed { reason }) => {
                assert!(reason.contains("image pull denied"), "{reason}");
            }
            other => panic!("reduce_readiness should surface LaunchFailed, got {other:?}"),
        }

        // Next tick: the backend still fails. The marker is retried (relaunch attempted) and
        // re-persisted — still exactly ONE record, still LaunchFailed (no duplication, no
        // clobber to `Starting` by the observe-loop's readiness refresh).
        let r2 = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &FixedActivity(WorkloadActivity::Active),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(r2.launched, 0);
        let states = deploy
            .list_replica_states(crate::project::ProjectRef::DEFAULT, "w")
            .await
            .unwrap();
        assert_eq!(states.len(), 1, "retry does not duplicate the record");
        assert!(
            matches!(states[0].readiness, Readiness::LaunchFailed { .. }),
            "the durable reason survives the observe-loop refresh: {:?}",
            states[0].readiness
        );
    }

    /// A backend whose running replica's live endpoint DRIFTS out from under the stored
    /// record while it stays healthy — the docker `--restart` ephemeral-host-port
    /// reassignment shape: `launch` returns `:8080`, `health` is always `Healthy`, but
    /// `observed_endpoint` reports the replica now lives at `:9090` (docker reassigned the
    /// published host port on an in-place crash-restart under the same container name).
    struct DriftingEndpointBackend;

    #[async_trait]
    impl ComputeBackend for DriftingEndpointBackend {
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
        async fn materialize(
            &self,
            _project: &str,
            _workload: &str,
            _spec: &ComputeSpec,
            _pull_auth: Option<&RegistryAuth>,
        ) -> Result<Artifact, BackendError> {
            Ok(Artifact::Image {
                reference: "img:latest".into(),
            })
        }
        async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
            Ok(Instance {
                handle: InstanceHandle {
                    project: req.project.clone(),
                    workload: req.workload.clone(),
                    replica: req.replica,
                    backend_ref: format!("fake-{}", req.replica),
                },
                // The port the FIRST launch discovered.
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
            // The container is still `running` (docker's restart policy relaunched it in
            // place), so run-state health stays Healthy — the whole reason nothing else
            // re-points the endpoint.
            Ok(Health::Healthy)
        }
        async fn observed_endpoint(&self, _handle: &InstanceHandle) -> Option<Endpoint> {
            // The in-place restart reassigned the ephemeral host port: the live endpoint
            // is now :9090, not the :8080 the stored record still carries.
            Some(Endpoint {
                scheme: Scheme::Http,
                host: "127.0.0.1".into(),
                port: 9090,
            })
        }
    }

    /// Regression (docker-stale-endpoint): a reconcile tick must RE-POINT a running,
    /// still-healthy replica's stored endpoint to the backend's live endpoint when it
    /// drifted — docker reassigns the published ephemeral host port on every in-place
    /// `--restart` restart (an OOM-crashing app relaunches under the same container name
    /// with a NEW port), the container stays `running` (health keeps `yes`), and the
    /// gateway routes to the STORED endpoint — so without re-pointing it dials the dead
    /// old port and 502s forever. The fix must make routing follow the live port WITHOUT
    /// a Stop/Launch recreate. Fails before the fix (endpoint stuck at `:8080`).
    #[tokio::test]
    async fn reconcile_repoints_a_running_replicas_drifted_endpoint_without_churn() {
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(crate::kv::MemoryKv::new()));
        let s = spec(1, 128);
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
        let nodes = vec![fake_node()];
        let mut backends: BackendRegistry = BTreeMap::new();
        backends.insert("fake".into(), Arc::new(DriftingEndpointBackend));
        let policy = BackendPolicy::default();

        // Pass 1: launch the replica — it records the FIRST-discovered endpoint (:8080).
        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &AlwaysActive,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!((r.launched, r.stopped), (1, 0), "{:?}", r.errors);
        let after_launch = deploy
            .list_replica_states(crate::project::ProjectRef::DEFAULT, "w")
            .await
            .unwrap();
        assert_eq!(after_launch.len(), 1);
        assert_eq!(
            after_launch[0].endpoint.url(),
            "http://127.0.0.1:8080",
            "first launch records the discovered port"
        );

        // Pass 2: the replica is still running + healthy (docker relaunched it in place),
        // but its live endpoint drifted to :9090. The reconcile must re-point the STORED
        // endpoint to follow it — and must NOT recreate the replica to do so.
        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &AlwaysActive,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            (r.launched, r.stopped),
            (0, 0),
            "endpoint re-point must not churn the replica: {:?}",
            r.errors
        );
        let after_drift = deploy
            .list_replica_states(crate::project::ProjectRef::DEFAULT, "w")
            .await
            .unwrap();
        assert_eq!(after_drift.len(), 1, "same replica, not a recreate");
        assert!(
            after_drift[0].healthy,
            "stays healthy (container is running)"
        );
        assert_eq!(
            after_drift[0].endpoint.url(),
            "http://127.0.0.1:9090",
            "the stored endpoint must FOLLOW the drifted live port (the gateway routes to it)"
        );
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
            None,
        )
        .await
        .unwrap();
        assert_eq!(r3.stopped, 2);
        assert!(
            deploy
                .list_replica_states(crate::project::ProjectRef::DEFAULT, "w")
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Place a workload (desired `replicas` of a `mem_mib`-sized spec) in `deploy`, returning
    /// its stored spec hash. 1 vCPU each so memory is the binding constraint.
    async fn put_workload(deploy: &DeployStore, name: &str, mem_mib: u32, replicas: u32) -> String {
        let hash = deploy.put_compute_spec(&spec(1, mem_mib)).await.unwrap();
        deploy
            .set_compute_workload(
                crate::project::ProjectRef::DEFAULT,
                &ComputeWorkload {
                    version: 1,
                    name: name.into(),
                    active: hash.clone(),
                    replicas,
                    placement: Default::default(),
                },
            )
            .await
            .unwrap();
        hash
    }

    /// Cumulative bin-packing: two workloads that EACH fit the node alone but NOT together
    /// must not over-subscribe it. The node advertises 8192 MiB; each workload's single
    /// replica wants 5000 MiB (fits alone; 10000 together does not). The old scheduler sized
    /// every workload against the node's FULL advertised capacity afresh, so both launched
    /// and over-packed the node. With the shared pre-debited ledger, the first (by the
    /// deterministic (project, name) order) places and the second is left UNSCHEDULED.
    #[tokio::test]
    async fn cumulative_binpack_second_workload_is_not_over_subscribed() {
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(crate::kv::MemoryKv::new()));
        // Names chosen so "alpha" sorts before "beta" — alpha is the one that should place.
        put_workload(&deploy, "alpha", 5000, 1).await;
        put_workload(&deploy, "beta", 5000, 1).await;
        let nodes = vec![fake_node()]; // 8 vCPU / 8192 MiB
        let mut backends: BackendRegistry = BTreeMap::new();
        backends.insert("fake".into(), Arc::new(FakeBackend));
        let policy = BackendPolicy::default();

        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &AlwaysActive,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // Exactly ONE replica launched — not two (that would be the over-subscription bug).
        assert_eq!(
            r.launched, 1,
            "only the first workload fits; {:?}",
            r.errors
        );
        assert!(r.errors.is_empty(), "no spurious errors: {:?}", r.errors);
        let alpha = deploy
            .list_replica_states(crate::project::ProjectRef::DEFAULT, "alpha")
            .await
            .unwrap();
        let beta = deploy
            .list_replica_states(crate::project::ProjectRef::DEFAULT, "beta")
            .await
            .unwrap();
        assert_eq!(alpha.len(), 1, "alpha (sorted first) places");
        assert_eq!(
            beta.len(),
            0,
            "beta is unscheduled, not over-packed onto a full node"
        );
    }

    /// Freed capacity lets a previously-unschedulable workload place. After alpha is scaled
    /// to zero its reservation is still charged for the pass that STOPS it (the conservative,
    /// never-over-subscribe pre-pass counts every currently-running replica), so beta places
    /// the tick AFTER alpha's replica is actually gone — the safe one-tick lag.
    #[tokio::test]
    async fn cumulative_binpack_frees_capacity_for_a_pending_workload() {
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(crate::kv::MemoryKv::new()));
        let alpha_hash = put_workload(&deploy, "alpha", 5000, 1).await;
        put_workload(&deploy, "beta", 5000, 1).await;
        let nodes = vec![fake_node()];
        let mut backends: BackendRegistry = BTreeMap::new();
        backends.insert("fake".into(), Arc::new(FakeBackend));
        let policy = BackendPolicy::default();
        let run = async || {
            reconcile_once(
                &deploy,
                &backends,
                &nodes,
                &policy,
                &AlwaysActive,
                None,
                None,
                None,
            )
            .await
            .unwrap()
        };
        let beta_count = async || {
            deploy
                .list_replica_states(crate::project::ProjectRef::DEFAULT, "beta")
                .await
                .unwrap()
                .len()
        };

        // Pass 1: alpha places, beta can't (node full).
        let r1 = run().await;
        assert_eq!(r1.launched, 1);
        assert_eq!(
            beta_count().await,
            0,
            "beta blocked while alpha holds the node"
        );

        // Scale alpha to zero → free its capacity.
        deploy
            .set_compute_workload(
                crate::project::ProjectRef::DEFAULT,
                &ComputeWorkload {
                    version: 1,
                    name: "alpha".into(),
                    active: alpha_hash,
                    replicas: 0,
                    placement: Default::default(),
                },
            )
            .await
            .unwrap();

        // Pass 2: alpha's replica is STOPPED; its reservation is still charged this pass, so
        // beta is still blocked (the conservative, never-over-subscribe lag).
        let r2 = run().await;
        assert_eq!(r2.stopped, 1, "alpha's replica is stopped: {:?}", r2.errors);
        assert_eq!(r2.launched, 0);
        assert_eq!(
            beta_count().await,
            0,
            "beta still waits the tick alpha frees capacity"
        );

        // Pass 3: alpha is gone from the node → beta places on the freed capacity.
        let r3 = run().await;
        assert_eq!(
            r3.launched, 1,
            "beta places once alpha's capacity is free: {:?}",
            r3.errors
        );
        assert_eq!(beta_count().await, 1);
    }

    /// Fail-safe: a RUNNING replica whose spec cannot be resolved — its `active_spec` points at
    /// a missing blob AND its workload has no active spec either — must NOT be charged ZERO,
    /// which would overstate free capacity and re-open over-subscription. The pre-pass charges
    /// the conservative [`UNRESOLVED_RESERVATION`] floor (1024 MiB) and surfaces the replica.
    /// A pending 7500-MiB workload then does NOT fit (8192 − 1024 = 7168 free), whereas a zero
    /// charge (8192 free) would have wrongly admitted it — so this asserts the floor is applied.
    #[tokio::test]
    async fn cumulative_binpack_unresolvable_replica_charges_conservative_floor() {
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(crate::kv::MemoryKv::new()));
        // A workload with NO stored active spec (dangling pointer) + a running replica whose
        // own active_spec also dangles → neither resolves → the conservative floor applies.
        deploy
            .set_compute_workload(
                crate::project::ProjectRef::DEFAULT,
                &ComputeWorkload {
                    version: 1,
                    name: "ghost".into(),
                    active: "missing-spec-hash".into(),
                    replicas: 1,
                    placement: Default::default(),
                },
            )
            .await
            .unwrap();
        let mut running = observed("ghost", 0, 1, true);
        running.backend = "fake".into();
        running.active_spec = Some("also-missing".into());
        deploy
            .set_replica_state(crate::project::ProjectRef::DEFAULT, &running)
            .await
            .unwrap();
        // A pending workload wanting 7500 MiB — placeable ONLY if the ghost replica were
        // (wrongly) charged zero (8192 free). With the 1024 floor only 7168 is free, so it
        // must stay unscheduled. ("aaa_pending" sorts before "ghost".)
        put_workload(&deploy, "aaa_pending", 7500, 1).await;

        let nodes = vec![fake_node()]; // 8192 MiB; floor charges 1024 → 7168 free.
        let mut backends: BackendRegistry = BTreeMap::new();
        backends.insert("fake".into(), Arc::new(FakeBackend));
        let policy = BackendPolicy::default();

        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &AlwaysActive,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // The floor denied the pending workload the capacity a zero charge would have freed.
        let pending = deploy
            .list_replica_states(crate::project::ProjectRef::DEFAULT, "aaa_pending")
            .await
            .unwrap();
        assert_eq!(
            pending.len(),
            0,
            "pending workload stays unscheduled — the unresolvable replica was not charged zero"
        );
        assert_eq!(r.launched, 0);
        // The unresolvable replica is surfaced (not silently floored).
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("cannot resolve reservation")),
            "the unresolvable reservation is surfaced: {:?}",
            r.errors
        );
    }

    /// Security F1: a scale-to-zero **wake** (`Action::Restore`) must debit the shared ledger
    /// just like a Launch, or it re-opens over-subscription. A parked `Zero` replica holds no
    /// CPU/mem (correctly skipped by the pre-pass), but if its workload goes `Active` the same
    /// pass it restores to `Running` and reclaims the slot — so a later-ordered workload must
    /// NOT be placed on top of it. Here `alpha` has a 5000-MiB `Zero` replica parked on an
    /// 8192-MiB node and wakes this pass, while `beta` (sorts later, 5000 MiB) contends for the
    /// same node: beta must stay unscheduled (10 GiB would not fit the 8 GiB node).
    #[tokio::test]
    async fn cumulative_binpack_a_scale_to_zero_wake_consumes_capacity() {
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(crate::kv::MemoryKv::new()));
        let alpha_hash = put_workload(&deploy, "alpha", 5000, 1).await;
        put_workload(&deploy, "beta", 5000, 1).await;
        // Park alpha's replica 0 as Zero (carrying its snapshot) on node 1 under the "fake"
        // backend — the wake path the pre-pass deliberately doesn't charge until it restores.
        let mut parked = zeroed("alpha", 0, 1);
        parked.backend = "fake".into();
        parked.active_spec = Some(alpha_hash);
        deploy
            .set_replica_state(crate::project::ProjectRef::DEFAULT, &parked)
            .await
            .unwrap();

        let nodes = vec![fake_node()]; // 8192 MiB
        let mut backends: BackendRegistry = BTreeMap::new();
        // S2zBackend restores a parked replica (and launches beta's) under id "fake".
        backends.insert("fake".into(), Arc::new(S2zBackend));
        let policy = BackendPolicy::default();

        // Active → alpha wakes (Restore, debiting 5000 MiB); beta contends for the rest.
        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &FixedActivity(WorkloadActivity::Active),
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert_eq!(r.woke, 1, "alpha's Zero replica wakes: {:?}", r.errors);
        assert_eq!(
            r.launched, 0,
            "beta must NOT launch on top of the waking replica: {:?}",
            r.errors
        );
        let alpha = deploy
            .list_replica_states(crate::project::ProjectRef::DEFAULT, "alpha")
            .await
            .unwrap();
        assert_eq!(alpha.len(), 1);
        assert_eq!(alpha[0].phase, ReplicaPhase::Running, "alpha is awake");
        let beta = deploy
            .list_replica_states(crate::project::ProjectRef::DEFAULT, "beta")
            .await
            .unwrap();
        assert_eq!(
            beta.len(),
            0,
            "beta stays unscheduled — the wake was charged against the node"
        );
    }

    /// A managed-DB resolver that records every dynamic-cred revoke and fails or succeeds on
    /// command — to prove the Stop path's revoke is RETRIABLE (Security HIGH-1): a failing
    /// revoke must NOT forget the replica.
    struct RevokeSpyDb {
        fail: bool,
        revokes: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl ManagedDbEnvResolver for RevokeSpyDb {
        async fn managed_db_env(&self, _p: &str, _w: &str) -> Vec<(String, String)> {
            Vec::new()
        }
        async fn revoke_dynamic_db_cred(
            &self,
            _p: &str,
            _w: &str,
            _bindings: &[ComputeBinding],
            _r: u32,
        ) -> Result<(), String> {
            self.revokes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail {
                Err("db outage".into())
            } else {
                Ok(())
            }
        }
    }

    /// Security HIGH-1: on Stop the dynamic-cred revoke runs BEFORE the replica record is
    /// forgotten, so a FAILED revoke keeps the record for a retry on the next reconcile —
    /// the credential can never linger past a forgotten replica. A later pass whose revoke
    /// succeeds then forgets it.
    #[tokio::test]
    async fn reconcile_keeps_replica_when_dynamic_cred_revoke_fails_then_forgets_on_success() {
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
                    replicas: 1,
                    placement: Default::default(),
                },
            )
            .await
            .unwrap();
        let nodes = vec![fake_node()];
        let mut backends: BackendRegistry = BTreeMap::new();
        backends.insert("fake".into(), Arc::new(FakeBackend));
        let policy = BackendPolicy::default();

        // Launch the single replica (no managed DB involved in the launch).
        reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &AlwaysActive,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            deploy
                .list_replica_states(crate::project::ProjectRef::DEFAULT, "w")
                .await
                .unwrap()
                .len(),
            1
        );

        // Scale to zero → a Stop is planned. The revoke FAILS, so the replica is kept.
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
        let failing = RevokeSpyDb {
            fail: true,
            revokes: std::sync::atomic::AtomicUsize::new(0),
        };
        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &AlwaysActive,
            None,
            Some(&failing),
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.stopped, 0, "a failed revoke must NOT count as stopped");
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("revoke dynamic db cred")),
            "the retriable revoke failure must surface: {:?}",
            r.errors
        );
        assert_eq!(failing.revokes.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            deploy
                .list_replica_states(crate::project::ProjectRef::DEFAULT, "w")
                .await
                .unwrap()
                .len(),
            1,
            "the replica record must be KEPT so the next pass retries the revoke"
        );

        // Next pass: the revoke SUCCEEDS → the replica is finally forgotten.
        let ok = RevokeSpyDb {
            fail: false,
            revokes: std::sync::atomic::AtomicUsize::new(0),
        };
        let r2 = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &AlwaysActive,
            None,
            Some(&ok),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            r2.stopped, 1,
            "a succeeding revoke forgets the replica: {:?}",
            r2.errors
        );
        assert_eq!(ok.revokes.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            deploy
                .list_replica_states(crate::project::ProjectRef::DEFAULT, "w")
                .await
                .unwrap()
                .is_empty(),
            "the replica must be forgotten once its credential is revoked"
        );
    }

    /// A2: a backend that records the `gc_ip_pool` parked-key set it was handed, so we
    /// can assert the reconcile loop runs the pool-vs-reality GC and passes it exactly
    /// the intentionally-parked (`Zero`) replicas (whose IPs must be kept).
    struct GcSpyBackend {
        gc_parked: std::sync::Mutex<Option<Vec<(String, String, u32)>>>,
    }
    #[async_trait]
    impl ComputeBackend for GcSpyBackend {
        fn id(&self) -> &'static str {
            "fake"
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                isolation: IsolationClass::Namespace,
                scale_to_zero: true, // so a Zero replica is left parked, not stopped
                persistent_volumes: false,
                max_vcpus: None,
                max_mem_mib: None,
            }
        }
        async fn materialize(
            &self,
            _project: &str,
            _workload: &str,
            _spec: &ComputeSpec,
            _pull_auth: Option<&RegistryAuth>,
        ) -> Result<Artifact, BackendError> {
            Ok(Artifact::Image {
                reference: "img:latest".into(),
            })
        }
        async fn gc_ip_pool(&self, parked: &[(String, String, u32)]) {
            *self.gc_parked.lock().unwrap() = Some(parked.to_vec());
        }
        async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
            Ok(Instance {
                handle: InstanceHandle {
                    project: req.project.clone(),
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
    async fn reconcile_runs_ip_gc_with_the_parked_replicas() {
        // One workload with a persisted **parked** (Zero) replica: the reconcile's IP
        // GC must run and be told that replica is parked (so its IP is preserved).
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(crate::kv::MemoryKv::new()));
        let s = spec(1, 128);
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
        // Persist replica 0 as parked (Zero) with a snapshot, so the planner leaves it.
        let parked = ObservedInstance {
            handle: InstanceHandle {
                project: "default".into(),
                workload: "w".into(),
                replica: 0,
                backend_ref: "10.0.0.2:8080".into(),
            },
            node: 1,
            backend: "fake".into(),
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: "10.0.0.2".into(),
                port: 8080,
            },
            region: None,
            healthy: false,
            started_at: None,
            phase: ReplicaPhase::Zero,
            readiness: Readiness::Starting,
            data_dir: None,
            snapshot: Some(Snapshot {
                project: "default".into(),
                workload: "w".into(),
                replica: 0,
                data_ref: "snap".into(),
            }),
            active_spec: None,
        };
        deploy
            .set_replica_state(crate::project::ProjectRef::DEFAULT, &parked)
            .await
            .unwrap();

        let nodes = vec![fake_node()];
        let mut backends: BackendRegistry = BTreeMap::new();
        let spy = Arc::new(GcSpyBackend {
            gc_parked: std::sync::Mutex::new(None),
        });
        backends.insert("fake".into(), spy.clone());
        let policy = BackendPolicy::default();

        reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &FixedActivity(WorkloadActivity::Idle), // idle → the Zero replica stays parked
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let got = spy.gc_parked.lock().unwrap().clone();
        let got = got.expect("gc_ip_pool was called during the reconcile");
        assert!(
            got.contains(&("default".to_string(), "w".to_string(), 0)),
            "the parked (Zero) replica must be handed to gc_ip_pool so its IP is kept, got {got:?}"
        );
    }

    // --- Readiness lifecycle: `advance_readiness` (runner-up vs ready) ---------------

    /// A controllable [`ManagedDbEnvResolver`] for the readiness-pass tests. `probe` is
    /// the `probe_managed_ready` result (`None` ⇒ not a managed DB); `provision_ok`
    /// decides whether `provision_managed` succeeds. `provisions` counts provision calls
    /// so a test can assert the idempotent DDL is NOT re-run once already provisioned.
    struct FakeManagedDb {
        probe: Option<bool>,
        provision_ok: bool,
        provisions: std::sync::atomic::AtomicUsize,
    }
    impl FakeManagedDb {
        fn new(probe: Option<bool>, provision_ok: bool) -> Self {
            Self {
                probe,
                provision_ok,
                provisions: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }
    #[async_trait::async_trait]
    impl ManagedDbEnvResolver for FakeManagedDb {
        async fn managed_db_env(&self, _p: &str, _w: &str) -> Vec<(String, String)> {
            Vec::new()
        }
        async fn probe_managed_ready(&self, _p: &str, _w: &str, _e: &Endpoint) -> Option<bool> {
            self.probe
        }
        async fn provision_managed(&self, _p: &str, _w: &str, _e: &Endpoint) -> Result<(), String> {
            self.provisions
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.provision_ok {
                Ok(())
            } else {
                Err("boom".into())
            }
        }
    }

    /// `reduce_readiness` (PLAN-managed-dependency-readiness WS4) — the shared reduction
    /// behind every readiness-polling surface. No RUNNING replica at all ⇒ `None` ("pending"),
    /// distinct from an actually-`Starting` one.
    #[test]
    fn reduce_readiness_no_running_replica_is_pending() {
        assert_eq!(reduce_readiness(&[]), None);
        assert_eq!(reduce_readiness(&[zeroed("pg", 0, 1)]), None);
    }

    #[test]
    fn reduce_readiness_starting_replica_reports_starting() {
        let mut s = observed("pg", 0, 1, false);
        s.readiness = Readiness::Starting;
        assert_eq!(reduce_readiness(&[s]), Some(Readiness::Starting));
    }

    #[test]
    fn reduce_readiness_provisioned_wins_over_a_starting_sibling() {
        let mut starting = observed("pg", 0, 1, false);
        starting.readiness = Readiness::Starting;
        let mut provisioned = observed("pg", 1, 1, true);
        provisioned.readiness = Readiness::Provisioned;
        assert_eq!(
            reduce_readiness(&[starting, provisioned]),
            Some(Readiness::Provisioned)
        );
    }

    #[test]
    fn reduce_readiness_service_ready_without_provisioned() {
        let mut s = observed("pg", 0, 1, false);
        s.readiness = Readiness::ServiceReady;
        assert_eq!(reduce_readiness(&[s]), Some(Readiness::ServiceReady));
    }

    /// A `ProvisionFailed` reason is the most actionable signal, so it surfaces even when a
    /// sibling replica is merely `Starting` — an operator must see the failure, not a vague
    /// "still starting" that buries it.
    #[test]
    fn reduce_readiness_provision_failed_wins_and_carries_its_reason() {
        let mut starting = observed("pg", 0, 1, false);
        starting.readiness = Readiness::Starting;
        let mut failed = observed("pg", 1, 1, false);
        failed.readiness = Readiness::ProvisionFailed {
            reason: "data-dir ownership mismatch".into(),
        };
        assert_eq!(
            reduce_readiness(&[starting, failed]),
            Some(Readiness::ProvisionFailed {
                reason: "data-dir ownership mismatch".into()
            })
        );
    }

    /// A `Zero`-phase (scaled-down) replica is not counted even if its stored readiness were
    /// stale `Provisioned` — only `Running` replicas are consulted.
    #[test]
    fn reduce_readiness_ignores_non_running_phases() {
        let mut parked = zeroed("pg", 0, 1);
        parked.readiness = Readiness::Provisioned;
        assert_eq!(reduce_readiness(&[parked]), None);
    }

    #[tokio::test]
    async fn advance_readiness_managed_probe_then_provision_reaches_provisioned() {
        let backend = FakeBackend;
        let m = FakeManagedDb::new(Some(true), true);
        let mut s = observed("w", 0, 1, true);
        s.readiness = Readiness::Starting;
        let r = advance_readiness(&backend, Some(&m), "default", &spec(1, 128), &s).await;
        assert_eq!(r, Readiness::Provisioned);
        assert_eq!(m.provisions.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn advance_readiness_managed_provision_failure_surfaces_reason() {
        let backend = FakeBackend;
        let m = FakeManagedDb::new(Some(true), false);
        let mut s = observed("w", 0, 1, true);
        s.readiness = Readiness::Starting;
        let r = advance_readiness(&backend, Some(&m), "default", &spec(1, 128), &s).await;
        assert_eq!(
            r,
            Readiness::ProvisionFailed {
                reason: "boom".into()
            }
        );
    }

    #[tokio::test]
    async fn advance_readiness_probe_false_stays_starting() {
        // Listens (healthy TCP) but does not answer `SELECT 1` — the data-dir-ownership
        // failure mode. Must NOT advance to provisioned, and must not run the DDL.
        let backend = FakeBackend;
        let m = FakeManagedDb::new(Some(false), true);
        let mut s = observed("w", 0, 1, true);
        s.readiness = Readiness::Starting;
        let r = advance_readiness(&backend, Some(&m), "default", &spec(1, 128), &s).await;
        assert_eq!(r, Readiness::Starting);
        assert_eq!(m.provisions.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn advance_readiness_generic_healthy_is_provisioned() {
        // A non-managed workload (probe None) and a reconcile with no managed resolver
        // both reach Provisioned as soon as the runner is healthy — no routing regression
        // for generic workloads once gating is applied.
        let backend = FakeBackend;
        let m = FakeManagedDb::new(None, true);
        let mut s = observed("w", 0, 1, true);
        s.readiness = Readiness::Starting;
        assert_eq!(
            advance_readiness(&backend, Some(&m), "default", &spec(1, 128), &s).await,
            Readiness::Provisioned
        );
        assert_eq!(
            advance_readiness(&backend, None, "default", &spec(1, 128), &s).await,
            Readiness::Provisioned
        );
    }

    #[tokio::test]
    async fn advance_readiness_unhealthy_falls_back_to_starting() {
        let backend = FakeBackend;
        let m = FakeManagedDb::new(Some(true), true);
        let s = observed("w", 0, 1, false); // not healthy
        assert_eq!(
            advance_readiness(&backend, Some(&m), "default", &spec(1, 128), &s).await,
            Readiness::Starting
        );
    }

    #[test]
    fn data_dir_diagnosis_runs_only_when_unlistening_past_the_startup_grace() {
        // The data-dir-ownership fault FATALs the database before it binds its port, so the
        // signature is "launched but not listening" (`!healthy`) that persists past the
        // startup grace — NOT a healthy server still answering "starting up" during recovery.
        let grace = 30;
        // Healthy (port up) → never diagnosed, even long past the grace (it can read its
        // data directory, so ownership is definitively fine).
        assert!(!should_diagnose_data_dir(true, Some(0), 10_000, grace));
        // Launched but not listening, still inside the startup grace → not yet (a normally
        // initializing container is briefly not-yet-listening; don't scan / false-warn).
        assert!(!should_diagnose_data_dir(
            false,
            Some(100),
            100 + grace - 1,
            grace
        ));
        // Launched but STILL not listening once past the grace → diagnose (genuinely stuck;
        // a data-dir-ownership fault is the prime suspect).
        assert!(should_diagnose_data_dir(
            false,
            Some(100),
            100 + grace,
            grace
        ));
        // No launch timestamp (older record / restored replica) → treated as past-grace.
        assert!(should_diagnose_data_dir(false, None, 0, grace));
    }

    #[tokio::test]
    async fn advance_readiness_already_provisioned_does_not_rerun_ddl() {
        // Once Provisioned, the idempotent DDL must NOT be re-run every tick: a resolver
        // whose provision would FAIL must never be called, and the state stays Provisioned.
        let backend = FakeBackend;
        let m = FakeManagedDb::new(Some(true), false);
        let s = observed("w", 0, 1, true); // `observed` sets healthy ⇒ Provisioned
        assert_eq!(s.readiness, Readiness::Provisioned);
        let r = advance_readiness(&backend, Some(&m), "default", &spec(1, 128), &s).await;
        assert_eq!(r, Readiness::Provisioned);
        assert_eq!(
            m.provisions.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "provisioning DDL must not re-run once the replica is already Provisioned"
        );
    }

    #[tokio::test]
    async fn advance_readiness_runs_post_launch_exec_then_provisioned() {
        // A generic healthy workload with a user-declared post-launch Exec that succeeds
        // reaches Provisioned (the general primitive, no managed DB involved).
        let backend = FakeBackend;
        let mut sp = spec(1, 128);
        sp.post_launch = vec![PostLaunchAction::Exec {
            argv: vec!["ok".into()],
        }];
        let mut s = observed("w", 0, 1, true);
        s.readiness = Readiness::Starting;
        assert_eq!(
            advance_readiness(&backend, None, "default", &sp, &s).await,
            Readiness::Provisioned
        );
    }

    #[tokio::test]
    async fn advance_readiness_post_launch_exec_failure_is_provision_failed() {
        let backend = FakeBackend;
        let mut sp = spec(1, 128);
        sp.post_launch = vec![PostLaunchAction::Exec {
            argv: vec!["fail".into()],
        }];
        let mut s = observed("w", 0, 1, true);
        s.readiness = Readiness::Starting;
        match advance_readiness(&backend, None, "default", &sp, &s).await {
            Readiness::ProvisionFailed { reason } => {
                assert!(reason.contains("exited 1"), "{reason}");
            }
            other => panic!("expected ProvisionFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn advance_readiness_managed_then_post_launch_both_run() {
        // A managed DB with a post-launch Exec: the derived DDL runs AND the user action
        // runs, in that order, before Provisioned.
        let backend = FakeBackend;
        let m = FakeManagedDb::new(Some(true), true);
        let mut sp = spec(1, 128);
        sp.post_launch = vec![PostLaunchAction::Exec {
            argv: vec!["ok".into()],
        }];
        let mut s = observed("w", 0, 1, true);
        s.readiness = Readiness::Starting;
        assert_eq!(
            advance_readiness(&backend, Some(&m), "default", &sp, &s).await,
            Readiness::Provisioned
        );
        assert_eq!(m.provisions.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
