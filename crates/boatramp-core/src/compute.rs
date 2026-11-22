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
    /// Whether boatramp **directly schedules** this backend's replicas against its own
    /// [`NodeCapacities`] ledger — the gate for the priority **preemption** pass. `true`
    /// (vmm / native container / docker / vz): boatramp owns both the capacity accounting AND
    /// the eviction, so a replica on this backend can be a preemptor and a preemption VICTIM.
    /// `false` (cloudflare / kubernetes): a DELEGATED backend — boatramp owns neither its
    /// capacity nor its eviction, so such a workload is NEVER a preemptor and NEVER a victim
    /// (it never enters the preemption pass). For the k8s backend the operator priority TIER is
    /// instead mapped to a native k8s `PriorityClass` on the generated Deployment/StatefulSet,
    /// delegating preemption to the cluster's own scheduler. Gated exactly like
    /// [`scale_to_zero`](Self::scale_to_zero) / [`persistent_volumes`](Self::persistent_volumes).
    pub preemptible: bool,
}

/// Which [`RootSource`] kinds a backend can actually run, plus whether it can apply a
/// per-project registry pull credential ([`ComputeSpec::pull_secret`]) to a private-image
/// pull. The scheduler gates placement on this (see [`Node::pick_backend`]) so a workload
/// is never placed on a backend whose `materialize` would reject its source — or, for a
/// private image, on a backend that cannot apply the credential and would crash-loop.
/// Sourced from the backend itself ([`ComputeBackend::source_support`]) so the scheduler's
/// view cannot drift from the backend's real `materialize` contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSupport {
    /// The [`RootSource`] kinds this backend's `materialize` accepts. A spec whose
    /// `root` kind is absent here is rejected at `materialize` (a guaranteed crash), so
    /// the scheduler treats the backend as ineligible for it.
    pub accepted_sources: Vec<RootSourceKind>,
    /// Whether this backend can apply a per-project registry pull credential
    /// ([`ComputeSpec::pull_secret`]) to a private-image pull. `false` ⇒ an `Image` +
    /// `pull_secret` workload must not be placed here (the native container + kubernetes
    /// backends refuse a per-project credential at `materialize` and would fail closed).
    pub private_registry_credential: bool,
    /// This backend's PRIMARY (native) source kind — the one the CLI's source→substrate
    /// derivation maps to it (`Image`→docker/cloudflare/kubernetes, `Tar`→native
    /// container, `Rootfs`→firecracker/VMM). A pure placement **tie-break**, NOT an
    /// eligibility exclusion: when several backends are eligible for a spec's source, the
    /// scheduler prefers the one whose primary source matches — so a public `Image` lands
    /// on an image-native backend rather than the native container backend (which can
    /// also run a public image) when both are present, preserving the documented
    /// `image()`→docker behavior on a dual node. `None` ⇒ no affinity (the permissive
    /// default; the backend falls to sorted order). A backend that accepts a source it is
    /// not primary for stays eligible for it, so a container-only node still places an
    /// image.
    pub primary_source: Option<RootSourceKind>,
}

impl SourceSupport {
    /// The permissive support used as the [`ComputeBackend::source_support`] default:
    /// every source kind, credential-capable, no primary-source affinity — i.e. the exact
    /// behavior before the source/credential placement gate existed. Every PRODUCTION
    /// backend overrides `source_support` with its true contract; this default serves only
    /// the in-crate test-double backends (whose value the scheduler never reads — those
    /// tests build their [`BackendKind`]s directly), so they keep behaving exactly as
    /// before.
    pub fn any() -> Self {
        Self {
            accepted_sources: vec![
                RootSourceKind::Image,
                RootSourceKind::Tar,
                RootSourceKind::Rootfs,
            ],
            private_registry_credential: true,
            primary_source: None,
        }
    }
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
pub struct RedactionSet {
    /// The collected secret VALUES, zeroized on drop (see the type-level note).
    values: zeroize::Zeroizing<Vec<String>>,
    /// Whether this workload's PROJECT has a stored guest-log redaction **opt-out** (a
    /// System·Admin per-project setting, loaded by [`reconcile_once`] from the deploy store
    /// — see [`DeployStore::get_project_log_redaction`](crate::deploy::DeployStore::get_project_log_redaction)).
    ///
    /// This is an **advisory preference**, NOT the decision: it is honored (redaction is
    /// disabled for the workload) ONLY when the node globally admits per-project overrides
    /// (`[compute].allow_per_project_redaction_override`). The backend composes the two-tier
    /// decision via [`boatramp_guestlog::should_redact`] — a per-project opt-out can never
    /// re-enable redaction past a node-global off, nor take effect on a node that does not
    /// admit overrides. Default `false` (no opt-out → redaction follows the node default), so
    /// a workload with no record behaves exactly as before. Not a secret, so it is safe in
    /// the redacting [`Debug`] below.
    project_opt_out: bool,
}

impl RedactionSet {
    /// An empty set (no secret-sourced values; no per-project opt-out).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one secret-sourced resolved value.
    pub fn push(&mut self, value: String) {
        self.values.push(value);
    }

    /// The collected secret VALUES (to build a backend-side matcher from). Backends feed
    /// these into `boatramp_guestlog::Redactor::build`, which applies the min-length floor
    /// and de-dups.
    #[must_use]
    pub fn values(&self) -> &[String] {
        &self.values
    }

    /// Whether nothing was collected (a workload with no secret-sourced env). Independent of
    /// [`project_opt_out`](Self::project_opt_out) — an empty set means "no secret to redact",
    /// not "redaction disabled".
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// How many secret-sourced values were collected (diagnostics only — never exposes a
    /// value).
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Record this workload's PROJECT redaction opt-out preference (advisory — honored by a
    /// backend only under the node-global admission gate). See the field doc.
    pub fn set_project_opt_out(&mut self, opt_out: bool) {
        self.project_opt_out = opt_out;
    }

    /// Whether this workload's PROJECT requested a redaction opt-out. Advisory — a backend
    /// honors it only when the node admits per-project overrides (see
    /// [`boatramp_guestlog::should_redact`]).
    #[must_use]
    pub fn project_opt_out(&self) -> bool {
        self.project_opt_out
    }
}

/// Redacting `Debug`: a value count + the (non-secret) opt-out flag, never a value — so the
/// set cannot leak through a `{:?}` of the enclosing [`LaunchRequest`].
impl std::fmt::Debug for RedactionSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RedactionSet(<{} secret-sourced values>, project_opt_out={})",
            self.values.len(),
            self.project_opt_out
        )
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
    /// stream, plus the workload's per-project redaction opt-out preference (see
    /// [`RedactionSet`]). Populated by [`launch_one`] from the resolved binding / managed-DB
    /// env (values) and the per-project setting (opt-out); the values are empty for a workload
    /// with no secret-sourced env. A backend composes the two-tier decision from these + its
    /// node-global flags via [`boatramp_guestlog::should_redact`]. Transient — never persisted
    /// or serialized.
    pub redaction: RedactionSet,
    /// The workload's resolved priority CLASS name (`system`/`standard`/`spot`), threaded from
    /// the mutable workload at launch so a DELEGATED backend can map it to its own priority
    /// primitive. The k8s backend maps it to a native `PriorityClass` (`boatramp-<class>`) on
    /// the generated Deployment/StatefulSet, delegating preemption to the cluster scheduler; the
    /// directly-scheduled backends (vmm/container/docker/vz) ignore it (boatramp's own
    /// preemption engine handles their priority). `None` ⇒ the operator default class (no
    /// explicit PriorityClass set). Transient — never persisted or serialized.
    pub priority_class: Option<String>,
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

    /// Which [`RootSource`] kinds this backend can run, and whether it can apply a
    /// per-project registry pull credential ([`ComputeSpec::pull_secret`]) — the
    /// scheduler's source + credential placement gate (see [`SourceSupport`] and
    /// [`Node::pick_backend`]). The default is [`SourceSupport::any`] (the permissive,
    /// pre-gate behavior, used only by test doubles); every production backend overrides
    /// it with its true `materialize` contract so the scheduler can never place a
    /// workload on a backend that would reject its source or its pull credential.
    fn source_support(&self) -> SourceSupport {
        SourceSupport::any()
    }

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

/// The **operator** backend-selection policy in force for one scope (a node's
/// `[compute.policy]`, or a per-project record), plus the isolation posture. The HARD
/// outer bound on placement: capability eligibility ∧ this policy ∧ the isolation posture
/// is the eligible set a tenant `prefer`/`require` then refines WITHIN — never past.
///
/// Default permits any capable backend (back-compat: no policy = today's behavior). The
/// latent [`force`](Self::force) field is **unwired** (v0.67.0 PLAN: redundant with
/// `allow: [one]`, and its "overrides allow/forbid" precedence is a footgun); it remains in
/// the struct for wire-compat but is NOT consulted by [`permits`](Self::permits) or
/// [`Node::pick_backend`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackendPolicy {
    /// If set, ONLY these backend ids are permitted (an allowlist). Omit ⇒ all capable
    /// backends are permitted. A hard operator gate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    /// Backend ids that are NEVER permitted (a denylist). Omit ⇒ none denied. A hard
    /// operator gate; composes as the UNION across scopes (node ∪ per-project).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub forbid: Vec<String>,
    /// A **soft** operator default preference: among the eligible backends, prefer this one
    /// (a node-scope affinity such as "default images to the daemonless native container,
    /// keep docker available"). Never widens eligibility — ignored when the named backend is
    /// not eligible. Narrower scope wins: a per-project `prefer` overrides the node `prefer`
    /// (resolved at [`compose_project`](Self::compose_project) time), and a tenant
    /// `prefer`/`require` on the spec overrides both.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefer: Option<String>,
    /// **Unwired** (see the struct doc): a latent "the only permitted backend" field, NOT
    /// consulted by selection. Kept for wire-compat; use `allow: [one]` instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force: Option<String>,
    /// Require a **strong** isolation class (VM/platform) for every placement,
    /// making shared-kernel backends (native namespace / Docker) ineligible even
    /// for a workload that only declares `Trusted`. Set by the
    /// operator security posture (`!allow_shared_kernel_compute`); default `false`
    /// preserves the prior behavior. Closes the "misclassified workload lands on
    /// a weak backend" gap. A NODE/posture concern — a per-project policy can never
    /// RELAX it (a [`ProjectBackendPolicy`] structurally carries no isolation field).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_strong_isolation: bool,
}

impl BackendPolicy {
    /// Whether backend `id` is permitted by this policy's HARD operator gates (`forbid`
    /// then `allow`). The unwired [`force`](Self::force) field is deliberately NOT consulted.
    pub fn permits(&self, id: &str) -> bool {
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

    /// Overlay a node operator `[compute.policy]`'s allow/forbid/prefer onto this policy
    /// (which carries the isolation posture), producing the node-scope operator policy. A
    /// `None` allow/prefer leaves the field untouched; a non-empty `forbid` is unioned in.
    /// Used at serve wiring to fold `[compute.policy]` into the posture-derived base.
    #[must_use]
    pub fn with_overlay(
        mut self,
        allow: Option<Vec<String>>,
        forbid: &[String],
        prefer: Option<String>,
    ) -> Self {
        if allow.is_some() {
            self.allow = allow;
        }
        for f in forbid {
            if !self.forbid.iter().any(|x| x == f) {
                self.forbid.push(f.clone());
            }
        }
        if prefer.is_some() {
            self.prefer = prefer;
        }
        self
    }

    /// Compose this NODE-scope operator policy with a PER-PROJECT operator policy, producing
    /// the effective operator bound for a workload — **operator-first, narrowing-only**:
    ///
    /// - `allow`: the INTERSECTION of the two allowlists (a backend must pass BOTH). `None`
    ///   means "all"; so `node=None ∧ project=Some(P) ⇒ Some(P)`, `node=Some(N) ∧
    ///   project=None ⇒ Some(N)`, both `Some ⇒ Some(N ∩ P)` (possibly empty ⇒ nothing
    ///   eligible, fail-closed).
    /// - `forbid`: the UNION (either scope forbidding a backend forbids it).
    /// - `prefer`: the per-project `prefer` wins when set, else the node `prefer` (narrower
    ///   scope overrides wider).
    /// - `require_strong_isolation`: kept from the node/posture (a project policy carries
    ///   none and can never relax it).
    ///
    /// The per-project layer can only ever NARROW — it cannot re-admit a node-forbidden
    /// backend nor relax the isolation posture. This is the authority split enforced
    /// structurally.
    #[must_use]
    pub fn compose_project(&self, project: &ProjectBackendPolicy) -> Self {
        let allow = match (&self.allow, &project.allow) {
            (None, None) => None,
            (Some(n), None) => Some(n.clone()),
            (None, Some(p)) => Some(p.clone()),
            (Some(n), Some(p)) => Some(n.iter().filter(|id| p.contains(id)).cloned().collect()),
        };
        let mut forbid = self.forbid.clone();
        for f in &project.forbid {
            if !forbid.iter().any(|x| x == f) {
                forbid.push(f.clone());
            }
        }
        Self {
            allow,
            forbid,
            prefer: project.prefer.clone().or_else(|| self.prefer.clone()),
            force: self.force.clone(),
            require_strong_isolation: self.require_strong_isolation,
        }
    }
}

/// A **per-project operator** backend policy (operator/System·Admin-set, stored alongside
/// the project's authz policy). Structurally a narrowing-only triple — `allow` / `forbid` /
/// `prefer` — with NO isolation field, so a per-project record can never relax the node's
/// isolation posture: it only ever intersects allows / unions forbids / overrides the soft
/// prefer, composed operator-first by [`BackendPolicy::compose_project`]. The single
/// mechanism (no second selection path): it folds into the same [`BackendPolicy`] the
/// scheduler already selects on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectBackendPolicy {
    /// If set, only these backend ids are permitted in this project (intersected with the
    /// node allowlist). Omit ⇒ no project-level allowlist (defer to the node bound).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    /// Backend ids this project forbids (unioned with the node denylist). Omit ⇒ none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub forbid: Vec<String>,
    /// A soft per-project default preference among eligible backends; overrides the node
    /// `prefer`, overridden by a tenant spec `prefer`/`require`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefer: Option<String>,
    /// The **priority-class ceiling** this project may request — the operator-gated cap on
    /// which [`PriorityClass`] a tenant's `compute set --priority-class` may name. A request
    /// for a class whose tier EXCEEDS this ceiling's tier is REFUSED fail-closed at
    /// `put_compute`, naming the allowed maximum. `None` ⇒ the node default ceiling
    /// ([`PriorityClassCatalog::default_ceiling`], i.e. `standard`) — so by default a project
    /// can request `standard`/`spot` but NOT the operator-reserved `system`. The operator
    /// raises it (e.g. to `system`) for a trusted project exactly as it sets `allow`/`forbid`.
    /// Stored on the SAME per-project operator record as the backend policy (one mechanism, no
    /// second store); carried through [`BackendPolicy::compose_project`] untouched (it bounds
    /// `compute set`, not placement). Omit ⇒ the node default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority_ceiling: Option<String>,
}

impl ProjectBackendPolicy {
    /// Whether this project policy carries no constraints (the back-compat "no policy" shape),
    /// so a stored-empty record composes to exactly the node bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_none()
            && self.forbid.is_empty()
            && self.prefer.is_none()
            && self.priority_ceiling.is_none()
    }
}

/// A **per-project guest-log redaction** setting (v0.70.0 two-tier opt-out, owner-settled):
/// the per-project *tier* of the three-tier redaction posture. Set by System·Admin (stored
/// alongside the project's backend policy / tenancy schema), it records only whether this
/// project **opts out** of guest-log secret redaction.
///
/// The opt-out is **advisory** and **narrowing-only**: the reconcile loads it and carries it
/// on each launch, but a backend honors it (disables redaction for the project) ONLY when the
/// node globally admits per-project overrides
/// (`[compute].allow_per_project_redaction_override`, default **off**) AND the node-global
/// default (`[compute].redact_guest_log_secrets`, default **on**) is on. So:
/// - on a node that does NOT admit overrides, a stored opt-out is IGNORED (redaction stays on);
/// - a per-project opt-out can never re-enable redaction past a node-global off;
/// - it affects only THIS project's workloads, never another tenant's.
///
/// The decision itself lives in [`boatramp_guestlog::should_redact`], the single source of
/// truth both backends gate on. An absent record (the back-compat shape) is exactly
/// `opt_out = false` (redaction follows the node default).
///
/// `#[non_exhaustive]`: this per-project record may grow more knobs (a future per-project
/// placeholder, extra opt-in values); marking it now keeps adding a field a non-breaking
/// change for the published `boatramp-core` crate — construct it from [`Default`] +
/// field-set, or (within the crate / via serde) a literal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct ProjectLogRedaction {
    /// Whether this project opts OUT of guest-log secret redaction. Honored only under the
    /// node-global admission gate (see the type doc). Default `false`.
    pub opt_out: bool,
}

// ---------------------------------------------------------------------------
// Priority classes + the global placement comparator (v0.70.0)
// ---------------------------------------------------------------------------

/// The preemption AUTHORITY a priority [`PriorityClass`] carries — the operator-set axis that
/// decides, together with tier ordering, whether a workload of this class may EVICT another.
/// Deliberately conservative by construction: the default-tier-vs-default-tier cross-project
/// case can NEVER preempt (two `standard` tenants are fully isolated), because cross-tenant
/// preemption needs BOTH [`CrossTenantOptIn`](Self::CrossTenantOptIn) AND a strictly-higher
/// tier — the DoS/fairness-safe default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreemptionMode {
    /// Never preempts anything (a strictly best-effort tier that only ever waits for room).
    Disabled,
    /// May preempt only a STRICTLY-LOWER-`rank` workload in its OWN project — the tenant's own
    /// budget, always safe (a tenant reshuffling its own workloads). The default, and the only
    /// authority `standard`/`spot` carry: two different projects are never touched.
    #[default]
    WithinProject,
    /// Everything [`WithinProject`](Self::WithinProject) does, PLUS the operator opt-in to
    /// preempt a STRICTLY-LOWER-TIER workload in ANOTHER project (cross-tenant). `rank` is
    /// IGNORED across projects — only the operator tier ordering authorizes a cross-tenant
    /// eviction. Never reaches an equal-or-higher tier in any project.
    CrossTenantOptIn,
}

impl PreemptionMode {
    /// Whether a class with this mode may preempt a lower-`rank` sibling in its own project.
    pub fn preempts_within_project(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Whether a class with this mode may preempt a strictly-lower-TIER workload in ANOTHER
    /// project (the operator cross-tenant opt-in).
    pub fn preempts_cross_tenant(self) -> bool {
        matches!(self, Self::CrossTenantOptIn)
    }
}

/// One operator-defined **priority class** — the node/compute-config tier a workload's
/// [`Priority::class`] names (mirroring [`BackendPolicy`] as an operator concern). It is the
/// cross-tenant authority unit: the `tier` orders placement globally (higher wins, across
/// every project), `preemption` is the eviction authority it carries, and `default` marks the
/// single class an un-annotated workload resolves to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorityClass {
    /// The placement TIER — a signed rank ordering EVERY project's workloads of this class
    /// against every other class (higher is scheduled/kept first). The operator-owned
    /// cross-tenant axis.
    pub tier: i32,
    /// The preemption authority this class carries (default [`PreemptionMode::WithinProject`]).
    #[serde(default)]
    pub preemption: PreemptionMode,
    /// Whether this is the operator DEFAULT class — the one an un-annotated workload (and an
    /// unknown/relaxed class name) resolves to. Exactly one built-in carries it (`standard`).
    #[serde(default)]
    pub default: bool,
    /// Whether this class is OPERATOR-RESERVED — a tenant can request it only when its project
    /// ceiling is explicitly raised to it (the tier check already enforces this, since a
    /// reserved class sits above the default ceiling; kept as explicit metadata/intent).
    #[serde(default)]
    pub operator_only: bool,
}

/// The operator catalog of [`PriorityClass`]es in force on a node — `name → class`. Mirrors
/// the operator [`BackendPolicy`] as a node/compute-config concern. The built-in catalog
/// ([`Self::builtin`]) is the owner-set three-tier default: **`system`** (top tier,
/// operator-reserved, cross-tenant opt-in) · **`standard`** (the default tier, within-project
/// preemption) · **`spot`** (bottom tier, within-project, freely preemptible as a victim). An
/// operator may override the tiers/modes via node config, but the NAMES and relative order of
/// these three are the stable contract the CLI + docs speak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorityClassCatalog {
    classes: BTreeMap<String, PriorityClass>,
}

impl Default for PriorityClassCatalog {
    fn default() -> Self {
        Self::builtin()
    }
}

impl PriorityClassCatalog {
    /// The owner-set built-in catalog: `system` / `standard` / `spot`. `standard` is the
    /// default (un-annotated workloads land here, tier 0), `system` the operator-reserved top
    /// (tier 100, the only class opted into cross-tenant preemption), `spot` the freely-
    /// preemptible bottom (tier -100). The relative order (`system` > `standard` > `spot`) and
    /// these exact names are the stable contract.
    pub fn builtin() -> Self {
        let mut classes = BTreeMap::new();
        classes.insert(
            "system".to_string(),
            PriorityClass {
                tier: 100,
                preemption: PreemptionMode::CrossTenantOptIn,
                default: false,
                operator_only: true,
            },
        );
        classes.insert(
            "standard".to_string(),
            PriorityClass {
                tier: 0,
                preemption: PreemptionMode::WithinProject,
                default: true,
                operator_only: false,
            },
        );
        classes.insert(
            "spot".to_string(),
            PriorityClass {
                tier: -100,
                preemption: PreemptionMode::WithinProject,
                default: false,
                operator_only: false,
            },
        );
        Self { classes }
    }

    /// Build a catalog from operator-supplied classes, falling back to the built-ins when the
    /// map is empty (back-compat: no config ⇒ the owner-set default catalog). Used by the
    /// server when wiring node `[compute]` config; the reconcile engine uses [`Self::builtin`].
    pub fn from_classes(classes: BTreeMap<String, PriorityClass>) -> Self {
        if classes.is_empty() {
            Self::builtin()
        } else {
            Self { classes }
        }
    }

    /// Look up a class by name.
    pub fn get(&self, name: &str) -> Option<&PriorityClass> {
        self.classes.get(name)
    }

    /// The operator DEFAULT class name (the one with `default: true`), falling back to
    /// `"standard"` if no class is flagged (a malformed operator catalog never panics).
    pub fn default_class_name(&self) -> &str {
        self.classes
            .iter()
            .find(|(_, c)| c.default)
            .map(|(n, _)| n.as_str())
            .unwrap_or("standard")
    }

    /// The default per-project **ceiling** class name — the cap a project with no explicit
    /// `priority_ceiling` may request. The operator default class (`standard`): a project
    /// cannot self-assign a tier above `standard` (so never `system`) unless the operator
    /// raises its ceiling.
    pub fn default_ceiling(&self) -> &str {
        self.default_class_name()
    }

    /// Resolve a workload's [`Priority`] to its `(class_name, class)` — the requested class if
    /// present and KNOWN, else the operator default. An unknown class name fails SAFE to the
    /// default (never a panic, never a privileged fallback).
    pub fn resolve<'a>(&'a self, priority: &'a Priority) -> (&'a str, &'a PriorityClass) {
        let default_name = self.default_class_name();
        let name = priority
            .class
            .as_deref()
            .filter(|n| self.classes.contains_key(*n))
            .unwrap_or(default_name);
        // `default_class_name` falls back to "standard"; if even that is absent (empty catalog
        // can't occur — `from_classes` guards it), synthesize a neutral default so the resolve
        // is total.
        let class = self.classes.get(name).unwrap_or(&NEUTRAL_STANDARD);
        (name, class)
    }

    /// Resolve a workload's [`Priority`] to its EFFECTIVE `(class_name, class)` CLAMPED to a
    /// project `ceiling`: if the stored class's tier EXCEEDS the ceiling's tier, the workload
    /// resolves AS the ceiling class — losing any over-ceiling tier AND preemption authority. This
    /// is the RECONCILE-time half of the per-project ceiling that completes revocation: the
    /// write-time [`check_request`](Self::check_request) gate only bounds a NEW request, so a class
    /// stored while the ceiling was temporarily HIGHER (then the operator lowers it back) would
    /// otherwise KEEP its over-ceiling authority until the workload is re-set/deleted. Clamping
    /// here makes a stored `system` in a now-`standard`-ceiling project behave AS `standard`
    /// (within-project only) at placement + preemption time. `ceiling` is the project's CURRENT
    /// ceiling class name (`None` ⇒ the node [`Self::default_ceiling`]); a missing or unknown
    /// ceiling name fails SAFE to the node default ceiling — never a silent grant (the same
    /// fail-closed posture as the write path). The clamp only ever LOWERS a tier (a stored class
    /// at/under the ceiling is returned unchanged), so an all-default fleet resolves identically
    /// to [`resolve`](Self::resolve) — zero churn on upgrade.
    pub fn resolve_clamped<'a>(
        &'a self,
        priority: &'a Priority,
        ceiling: Option<&str>,
    ) -> (&'a str, &'a PriorityClass) {
        let (name, class) = self.resolve(priority);
        // The project's effective ceiling class, FAIL-CLOSED to the node default ceiling when the
        // configured name is absent or unknown (never a widening of a project's authority).
        let ceiling_lookup = ceiling
            .filter(|n| self.classes.contains_key(*n))
            .unwrap_or_else(|| self.default_ceiling());
        let (ceiling_name, ceiling_class) = self
            .classes
            .get_key_value(ceiling_lookup)
            .map(|(n, c)| (n.as_str(), c))
            .unwrap_or(("standard", &NEUTRAL_STANDARD));
        if class.tier > ceiling_class.tier {
            (ceiling_name, ceiling_class)
        } else {
            (name, class)
        }
    }

    /// The operator TIER a workload's priority resolves to (higher wins globally).
    pub fn tier_of(&self, priority: &Priority) -> i32 {
        self.resolve(priority).1.tier
    }

    /// The preemption authority a workload's priority resolves to.
    pub fn preemption_of(&self, priority: &Priority) -> PreemptionMode {
        self.resolve(priority).1.preemption
    }

    /// Validate a tenant `compute set --priority-class <requested>` against a project ceiling —
    /// the fail-closed per-project gate. `requested` is the requested class name (`None` ⇒ the
    /// default, always allowed); `ceiling` is the project's ceiling class name (`None` ⇒ the
    /// node [`Self::default_ceiling`]). Returns `Ok(())` iff the requested class is KNOWN and
    /// its tier does NOT exceed the ceiling's tier; otherwise an operator-facing message naming
    /// the allowed maximum (never leaks another tenant's data).
    pub fn check_request(
        &self,
        requested: Option<&str>,
        ceiling: Option<&str>,
    ) -> Result<(), String> {
        let Some(req_name) = requested else {
            return Ok(()); // the operator default is always requestable
        };
        let Some(req_class) = self.get(req_name) else {
            let known: Vec<&str> = self.class_names();
            return Err(format!(
                "unknown priority class `{req_name}`; valid classes: {}",
                known.join(", ")
            ));
        };
        let ceiling_name = ceiling.unwrap_or_else(|| self.default_ceiling());
        let ceiling_tier = self.get(ceiling_name).map(|c| c.tier).unwrap_or(0);
        if req_class.tier > ceiling_tier {
            return Err(format!(
                "priority class `{req_name}` (tier {}) exceeds this project's ceiling `{ceiling_name}` (tier {ceiling_tier}); the operator must raise the project ceiling to allow it",
                req_class.tier
            ));
        }
        Ok(())
    }

    /// Every class name, sorted (stable for messages/tests).
    pub fn class_names(&self) -> Vec<&str> {
        self.classes.keys().map(String::as_str).collect()
    }

    /// Whether a workload with `preemptor` priority in `preemptor_project` MAY preempt a victim
    /// workload with `victim` priority in `victim_project` under the TENANCY BOUNDARY (resolves
    /// both classes, then applies [`can_preempt`]). The public, testable form the dry-run
    /// preview + any external authority check use.
    pub fn may_preempt(
        &self,
        preemptor: &Priority,
        preemptor_project: &str,
        victim: &Priority,
        victim_project: &str,
    ) -> bool {
        let (_, pc) = self.resolve(preemptor);
        let (_, vc) = self.resolve(victim);
        can_preempt(
            pc.tier,
            preemptor.rank,
            pc.preemption,
            preemptor_project,
            vc.tier,
            victim.rank,
            victim_project,
        )
    }

    /// [`may_preempt`](Self::may_preempt) but with CEILING-CLAMPED resolves on BOTH sides, so a
    /// preview weighs a stored over-ceiling class exactly as reconcile's [`plan_preemptions`]
    /// does (which clamps both preemptor and victim via [`resolve_clamped`](Self::resolve_clamped)
    /// against each project's current ceiling). The VICTIM clamp is the one that matters for
    /// parity: without it a victim whose stored class exceeds its project ceiling reads at its
    /// (higher) stored tier and wrongly appears un-preemptible, so a dry-run preview UNDER-COUNTS
    /// relative to what reconcile would actually evict. `preemptor_ceiling` / `victim_ceiling` are
    /// each project's current ceiling class name (`None` ⇒ the node default ceiling, fail-closed);
    /// an all-at/under-ceiling fleet behaves identically to [`may_preempt`].
    pub fn may_preempt_clamped(
        &self,
        preemptor: &Priority,
        preemptor_project: &str,
        preemptor_ceiling: Option<&str>,
        victim: &Priority,
        victim_project: &str,
        victim_ceiling: Option<&str>,
    ) -> bool {
        let (_, pc) = self.resolve_clamped(preemptor, preemptor_ceiling);
        let (_, vc) = self.resolve_clamped(victim, victim_ceiling);
        can_preempt(
            pc.tier,
            preemptor.rank,
            pc.preemption,
            preemptor_project,
            vc.tier,
            victim.rank,
            victim_project,
        )
    }
}

/// The neutral fallback class a totally-malformed catalog resolve lands on (tier 0, within-
/// project) — unreachable in practice ([`PriorityClassCatalog::from_classes`] guarantees a
/// non-empty catalog and the built-ins always carry `standard`), present so `resolve` is total
/// without an `Option`/panic.
static NEUTRAL_STANDARD: PriorityClass = PriorityClass {
    tier: 0,
    preemption: PreemptionMode::WithinProject,
    default: true,
    operator_only: false,
};

/// The **global placement comparator key** for a workload — the total order that replaces the
/// pre-priority `(project, name)` sort in [`reconcile_once`]. Ordered so that:
///
/// `operator_tier DESC → project ASC → rank DESC → name ASC`
///
/// The key is returned in a form where the natural `Ord` of the tuple yields that order: tier
/// and rank are NEGATED (so a higher tier/rank sorts EARLIER under ascending tuple order). The
/// fairness boundary is this ordering, not a runtime check: because `project` outranks `rank`,
/// a tenant's huge `rank` reshuffles ONLY its own workloads and can never leapfrog another
/// project's. With every workload on the default class (tier 0) and rank 0, the key reduces to
/// `(0, project, 0, name)` — exactly today's `(project, name)` order, so the change is
/// non-regressive and evicts/reorders nothing on upgrade.
pub fn workload_priority_key(
    catalog: &PriorityClassCatalog,
    project: &str,
    workload: &ComputeWorkload,
) -> (i32, String, i32, String) {
    let tier = catalog.tier_of(&workload.priority);
    (
        // Negate so a HIGHER tier compares as the SMALLER (earlier) key.
        tier.saturating_neg(),
        project.to_string(),
        workload.priority.rank.saturating_neg(),
        workload.name.clone(),
    )
}

/// The CEILING-CLAMPED global comparator key — [`workload_priority_key`] with the workload's
/// effective TIER clamped to the project `ceiling` (see
/// [`PriorityClassCatalog::resolve_clamped`]). The reconcile placement sort and the preemption
/// engine's victim ordering use this (not the raw key) so a stored over-ceiling class loses its
/// placement PRECEDENCE exactly as it loses its preemption AUTHORITY — a stored `system` in a
/// now-`standard`-ceiling project sorts as `standard`. `ceiling` `None` ⇒ the node default
/// ceiling (fail-closed). `rank` and `name` are unchanged (the clamp is tier-only); an
/// at/under-ceiling workload yields exactly [`workload_priority_key`]'s key.
pub fn workload_priority_key_clamped(
    catalog: &PriorityClassCatalog,
    project: &str,
    workload: &ComputeWorkload,
    ceiling: Option<&str>,
) -> (i32, String, i32, String) {
    let (_, class) = catalog.resolve_clamped(&workload.priority, ceiling);
    (
        // Negate so a HIGHER tier compares as the SMALLER (earlier) key.
        class.tier.saturating_neg(),
        project.to_string(),
        workload.priority.rank.saturating_neg(),
        workload.name.clone(),
    )
}

/// Why a backend is — or is NOT — a placement candidate for a spec under the operator policy,
/// the isolation posture, and the capability floor. The **single** verdict the scheduler
/// selects on ([`Node::pick_backend`]) and the placement-explain surfaces (`compute get`, and
/// the no-placement `not scheduled: …` reason) report, so selection and legibility can never
/// drift. `Eligible` ⇒ a valid candidate; any other variant is the FIRST hard gate the
/// backend failed, evaluated operator-first (policy → posture → capability floor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "kebab-case")]
pub enum BackendEligibility {
    /// Passes every hard gate — a valid placement candidate.
    Eligible,
    /// Excluded by the NODE-scope operator policy (`[compute.policy]` allow/forbid).
    ForbiddenByNodePolicy,
    /// Excluded by the PER-PROJECT operator backend policy (allow/forbid).
    ForbiddenByProjectPolicy,
    /// The spec needs stronger isolation than this backend provides — the workload's own
    /// `isolation` requirement, or the operator strict posture (`require_strong_isolation`)
    /// which excludes shared-kernel backends regardless of the spec.
    IsolationInsufficient,
    /// The backend's `materialize` cannot run this spec's root source kind (an image backend
    /// can't run a tar/rootfs; firecracker only a rootfs; …).
    CannotRunSource,
    /// A PRIVATE image (an `Image` source naming a `pull_secret`) but this backend cannot
    /// apply a per-project registry pull credential (native container / kubernetes refuse it).
    NoCredential,
    /// The spec declares persistent volumes this backend cannot attach.
    NoPersistentVolume,
    /// The spec opts into scale-to-zero this backend cannot provide.
    NoScaleToZero,
}

impl BackendEligibility {
    /// Whether this verdict is a valid placement candidate.
    #[must_use]
    pub fn is_eligible(self) -> bool {
        matches!(self, Self::Eligible)
    }

    /// A short, operator-facing phrase for the no-placement reason (`compute status` /
    /// `not scheduled: …`). Carries no credential material.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::ForbiddenByNodePolicy => "forbidden by node policy",
            Self::ForbiddenByProjectPolicy => "forbidden by project policy",
            Self::IsolationInsufficient => "isolation insufficient",
            Self::CannotRunSource => "cannot run this source kind",
            Self::NoCredential => "no credential for a private image",
            Self::NoPersistentVolume => "no persistent-volume support",
            Self::NoScaleToZero => "no scale-to-zero support",
        }
    }
}

/// Classify one backend against the COMPOSED operator policy (node ∩ per-project) + the
/// spec + the isolation posture — the single hard-eligibility predicate. The forbid verdict
/// it returns ([`BackendEligibility::ForbiddenByNodePolicy`]) is a placeholder the attributed
/// [`explain_backend`] refines to node-vs-project; [`Node::pick_backend`] only reads
/// [`BackendEligibility::is_eligible`], so the placeholder never affects selection. Gates are
/// checked operator-first: policy → isolation posture → capability floor.
fn classify_backend_composed(
    b: &BackendKind,
    spec: &ComputeSpec,
    policy: &BackendPolicy,
) -> BackendEligibility {
    if !policy.permits(&b.id) {
        // Attribution (node vs project) is resolved by `explain_backend`, which has both
        // layers; the composed path only needs "forbidden", so pick a stable placeholder.
        return BackendEligibility::ForbiddenByNodePolicy;
    }
    if !b.isolation.satisfies(spec.isolation)
        || (policy.require_strong_isolation && !b.isolation.is_strong())
    {
        return BackendEligibility::IsolationInsufficient;
    }
    if !b.accepted_sources.contains(&spec.root.kind()) {
        return BackendEligibility::CannotRunSource;
    }
    // A PRIVATE image needs a credential-capable backend (the gate bites only where a
    // credential is actually applied — an `Image` source with a `pull_secret`).
    if spec.pull_secret.is_some()
        && matches!(spec.root, RootSource::Image(_))
        && !b.private_registry_credential
    {
        return BackendEligibility::NoCredential;
    }
    if !spec.volumes.is_empty() && !b.persistent_volumes {
        return BackendEligibility::NoPersistentVolume;
    }
    if spec.scale_to_zero && !b.scale_to_zero {
        return BackendEligibility::NoScaleToZero;
    }
    BackendEligibility::Eligible
}

/// Classify one backend with node-vs-project forbid **attribution** — the explain surface's
/// verdict. Composes the two operator layers (so the same hard gates as selection apply),
/// then, for a forbid, names the scope that caused it (node bound first — operator-first).
#[must_use]
pub fn explain_backend(
    b: &BackendKind,
    spec: &ComputeSpec,
    node: &BackendPolicy,
    project: &ProjectBackendPolicy,
) -> BackendEligibility {
    let composed = node.compose_project(project);
    match classify_backend_composed(b, spec, &composed) {
        BackendEligibility::ForbiddenByNodePolicy => {
            // The node bound is the OUTER one; attribute to it first.
            if !node.permits(&b.id) {
                BackendEligibility::ForbiddenByNodePolicy
            } else {
                BackendEligibility::ForbiddenByProjectPolicy
            }
        }
        other => other,
    }
}

/// One candidate backend's placement verdict for a workload — the per-backend row
/// `compute get` surfaces so an operator sees WHY each backend was or wasn't chosen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCandidate {
    /// Backend id.
    pub backend: String,
    /// The hard-eligibility verdict (with node-vs-project forbid attribution).
    #[serde(flatten)]
    pub eligibility: BackendEligibility,
    /// Whether this backend is the one the scheduler WOULD choose among the eligible set
    /// (capacity aside). Exactly one eligible candidate is `selected` when any is eligible.
    pub selected: bool,
}

/// The workload-level placement explanation — the per-candidate verdicts plus the backend
/// the scheduler would choose — surfaced on `compute get` and persisted each reconcile so a
/// stuck (no-placement) workload is legible even with zero replicas. Capacity is NOT folded
/// in here (it is node-level and surfaced in the `not scheduled: …` reason); this answers
/// "which backends may run this workload, and which would be picked".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementExplain {
    /// Every distinct advertised backend (by id, across the node inventory), each with its
    /// verdict, sorted by id for a stable view.
    pub candidates: Vec<BackendCandidate>,
    /// The backend the scheduler would choose among the eligible candidates (capacity
    /// aside), or `None` ⇒ no eligible backend (a legible no-placement; see each candidate's
    /// reason). A tenant `require_backend` that is not eligible yields `None` here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chosen: Option<String>,
}

/// Build the workload-level [`PlacementExplain`] from the node inventory + both operator
/// layers + the spec: classify each DISTINCT backend id (first advertisement wins) with
/// attribution, then mark the one [`choose_backend`] would pick among the eligible set. The
/// same classify + choose the scheduler uses, so the explanation never drifts from the
/// decision.
#[must_use]
pub fn explain_placement(
    nodes: &[Node],
    spec: &ComputeSpec,
    node_policy: &BackendPolicy,
    project_policy: &ProjectBackendPolicy,
) -> PlacementExplain {
    // Distinct backend kinds across the inventory, keyed by id (first advertisement wins),
    // in sorted-id order for a stable, deterministic view.
    let mut kinds: BTreeMap<String, &BackendKind> = BTreeMap::new();
    for n in nodes {
        for b in &n.backends {
            kinds.entry(b.id.clone()).or_insert(b);
        }
    }
    let composed = node_policy.compose_project(project_policy);
    let eligible: Vec<&BackendKind> = kinds
        .values()
        .filter(|b| classify_backend_composed(b, spec, &composed).is_eligible())
        .copied()
        .collect();
    let chosen = choose_backend(&eligible, spec, &composed);
    let candidates = kinds
        .values()
        .map(|b| BackendCandidate {
            backend: b.id.clone(),
            eligibility: explain_backend(b, spec, node_policy, project_policy),
            selected: chosen.as_deref() == Some(b.id.as_str()),
        })
        .collect();
    PlacementExplain { candidates, chosen }
}

/// Choose one backend from an ALREADY-eligible set, applying the soft-preference precedence
/// (capacity aside) — the single ordering authority [`Node::pick_backend`] and
/// [`explain_placement`] share:
///
/// tenant `require_backend` (must be present in the set, else `None` — fail-closed)
/// → tenant `prefer_backend`
/// → operator `prefer` (per-project overrides node, already folded into `policy.prefer`)
/// → the `primary_source` source-affinity tie-break
/// → sorted-id order (deterministic last resort).
fn choose_backend(
    eligible: &[&BackendKind],
    spec: &ComputeSpec,
    policy: &BackendPolicy,
) -> Option<String> {
    if eligible.is_empty() {
        return None;
    }
    // Tenant HARD require: run on exactly this backend or NOWHERE. Because `eligible` already
    // applied the operator allow/forbid + isolation posture + capability floor, a `require` of
    // an operator-forbidden / isolation-insufficient / incapable backend is simply absent here
    // ⇒ `None` (a legible no-placement), NEVER an escape out of the operator bound.
    if let Some(req) = &spec.require_backend {
        return eligible.iter().find(|b| &b.id == req).map(|b| b.id.clone());
    }
    // Tenant SOFT prefer.
    if let Some(pref) = &spec.prefer_backend
        && let Some(b) = eligible.iter().find(|b| &b.id == pref)
    {
        return Some(b.id.clone());
    }
    // Operator SOFT prefer (per-project `prefer` overrides node `prefer`, folded in `compose_project`).
    if let Some(pref) = &policy.prefer
        && let Some(b) = eligible.iter().find(|b| &b.id == pref)
    {
        return Some(b.id.clone());
    }
    // Source-affinity tie-break: prefer a backend whose PRIMARY source matches the spec's.
    let kind = spec.root.kind();
    if let Some(b) = eligible.iter().find(|b| b.primary_source == Some(kind)) {
        return Some(b.id.clone());
    }
    // Deterministic last resort: lowest backend id.
    eligible.iter().map(|b| &b.id).min().cloned()
}

/// The legible reason a workload could not be placed — the v0.67.0 placement-explain's
/// no-placement surface (extends the v0.64.2 bare `not scheduled: no eligible backend with
/// capacity`). Distinguishes **why** across the candidate backends under the COMPOSED
/// operator `policy`:
///
/// - no backends advertised at all;
/// - a tenant `require_backend` that is not eligible (names the gate that excluded it, or
///   "not advertised") — the authority-split no-placement, NOT an escape;
/// - at least one eligible backend but no NODE had capacity (the classic shortfall);
/// - NO eligible backend — each candidate's hard gate named (policy / source / credential /
///   isolation / volume / scale-to-zero), so the incident's black-box stuck-at-0 is legible.
///
/// Node-vs-project forbid attribution is NOT made here (this path holds only the composed
/// policy); a forbid reads as "forbidden by operator policy". The per-scope attribution lives
/// in the persisted [`PlacementExplain`] that `compute get` surfaces.
fn no_placement_reason(nodes: &[Node], spec: &ComputeSpec, policy: &BackendPolicy) -> String {
    let need = format!("needs {}vcpu/{}MiB", spec.vcpus.max(1), spec.mem_mib.max(1));
    // Distinct advertised backends across the inventory, by id (sorted for a stable message).
    let mut kinds: BTreeMap<String, &BackendKind> = BTreeMap::new();
    for n in nodes {
        for b in &n.backends {
            kinds.entry(b.id.clone()).or_insert(b);
        }
    }
    if kinds.is_empty() {
        return format!("no compute backend advertised on any node ({need})");
    }
    // A forbid verdict can't be scope-attributed from the composed policy here — phrase it
    // neutrally (the per-scope reason is in the persisted PlacementExplain).
    let phrase = |v: BackendEligibility| -> &'static str {
        match v {
            BackendEligibility::ForbiddenByNodePolicy
            | BackendEligibility::ForbiddenByProjectPolicy => "forbidden by operator policy",
            other => other.describe(),
        }
    };
    let verdicts: Vec<(String, BackendEligibility)> = kinds
        .values()
        .map(|b| (b.id.clone(), classify_backend_composed(b, spec, policy)))
        .collect();
    // A HARD tenant require that did not land: name why the required backend is out.
    if let Some(req) = &spec.require_backend
        && !verdicts.iter().any(|(id, v)| id == req && v.is_eligible())
    {
        let why = verdicts
            .iter()
            .find(|(id, _)| id == req)
            .map_or("not advertised on any node", |(_, v)| phrase(*v));
        return format!("required backend `{req}` is not eligible: {why}");
    }
    if verdicts.iter().any(|(_, v)| v.is_eligible()) {
        // Eligible backends exist but no node had room (or the required one had none).
        return match &spec.require_backend {
            Some(req) => format!("required backend `{req}` has no node with capacity ({need})"),
            None => format!("no eligible backend with capacity ({need})"),
        };
    }
    // No eligible backend at all — name each candidate's gate.
    let detail = verdicts
        .iter()
        .map(|(id, v)| format!("{id}: {}", phrase(*v)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("no eligible backend ({detail})")
}

// ---------------------------------------------------------------------------
// Scheduler (backend-aware placement)
// ---------------------------------------------------------------------------

/// A backend a node offers, with the capabilities the scheduler gates placement
/// on: the isolation class it provides, plus whether it can back persistent
/// volumes and scale a workload to zero. Populated from the backend's
/// [`Capabilities`] at node advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The [`RootSource`] kinds this backend can run on this node. A spec whose `root`
    /// kind is not accepted would be rejected at `materialize` (a guaranteed crash), so
    /// the scheduler treats such a backend as ineligible for that spec. Populated from
    /// the backend's [`SourceSupport`] at node advertisement ([`ComputeBackend::source_support`]).
    pub accepted_sources: Vec<RootSourceKind>,
    /// Whether this backend can apply a per-project registry pull credential
    /// ([`ComputeSpec::pull_secret`]) to a private-image pull. A private-image workload
    /// placed on a `false` backend would fail closed at `materialize` (the native
    /// container + kubernetes backends refuse a per-project credential), so the scheduler
    /// treats it as ineligible for such a workload. Populated from [`SourceSupport`].
    pub private_registry_credential: bool,
    /// This backend's PRIMARY (native) source kind — the scheduler's placement tie-break
    /// (see [`SourceSupport::primary_source`] and [`Node::pick_backend`]). Prefers an
    /// image-native backend over the native container backend for an image when both are
    /// eligible, without excluding the container backend (so container-only nodes still
    /// place images). Populated from [`SourceSupport`].
    pub primary_source: Option<RootSourceKind>,
}

impl BackendKind {
    /// A backend advertisement for id `id` providing isolation class `isolation` — the
    /// supported constructor (`BackendKind` is `#[non_exhaustive]`, so downstream crates
    /// build it here, not with a struct literal). Defaults: no persistent volumes, no
    /// scale-to-zero, no accepted sources, no private-registry-credential support, no primary
    /// source — refine with the chainable `with_*` setters (typically from the backend's
    /// [`Capabilities`] + [`SourceSupport`] at advertisement).
    pub fn new(id: impl Into<String>, isolation: IsolationClass) -> Self {
        Self {
            id: id.into(),
            isolation,
            persistent_volumes: false,
            scale_to_zero: false,
            accepted_sources: Vec::new(),
            private_registry_credential: false,
            primary_source: None,
        }
    }

    /// Set whether this backend can attach persistent volumes.
    #[must_use]
    pub fn with_persistent_volumes(mut self, persistent_volumes: bool) -> Self {
        self.persistent_volumes = persistent_volumes;
        self
    }

    /// Set whether this backend can scale a workload to zero.
    #[must_use]
    pub fn with_scale_to_zero(mut self, scale_to_zero: bool) -> Self {
        self.scale_to_zero = scale_to_zero;
        self
    }

    /// Set the [`RootSource`] kinds this backend can run.
    #[must_use]
    pub fn with_accepted_sources(mut self, accepted_sources: Vec<RootSourceKind>) -> Self {
        self.accepted_sources = accepted_sources;
        self
    }

    /// Set whether this backend can apply a per-project registry pull credential.
    #[must_use]
    pub fn with_private_registry_credential(mut self, private_registry_credential: bool) -> Self {
        self.private_registry_credential = private_registry_credential;
        self
    }

    /// Set this backend's primary (native) source kind — the placement tie-break.
    #[must_use]
    pub fn with_primary_source(mut self, primary_source: Option<RootSourceKind>) -> Self {
        self.primary_source = primary_source;
        self
    }
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
    /// The backend to use for `spec` on this node under the (already-composed node ∩
    /// per-project) operator `policy` — the full v0.67.0 precedence chain:
    ///
    /// capability floor ∧ operator `allow`/`forbid` ∧ isolation posture = the HARD eligible
    /// set ([`classify_backend_composed`]) → tenant `require_backend` (must be in the set,
    /// else `None`) → tenant `prefer_backend` → operator `prefer` → the `primary_source`
    /// tie-break → sorted-id order ([`choose_backend`]).
    ///
    /// `None` ⇒ no eligible backend here (a legible no-placement). The operator gates live
    /// INSIDE the eligible set, so a tenant `require`/`prefer` can only ever pick WITHIN the
    /// operator bound + isolation posture — never climb out of it (the authority split).
    /// [`choose_backend`] is the same ordering [`explain_placement`] reports, so selection
    /// and the placement-explain can never drift.
    fn pick_backend(&self, spec: &ComputeSpec, policy: &BackendPolicy) -> Option<String> {
        let eligible: Vec<&BackendKind> = self
            .backends
            .iter()
            .filter(|b| classify_backend_composed(b, spec, policy).is_eligible())
            .collect();
        choose_backend(&eligible, spec, policy)
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
/// spec blob is gone. Operator-tunable via [`BinPackTuning::unresolved_reservation`] should
/// an operator's unresolved replicas run materially larger; this `const` is the back-compat
/// DEFAULT ([`BinPackTuning::default`] reproduces it exactly).
const UNRESOLVED_RESERVATION: Reservation = Reservation {
    vcpus: 1,
    mem_mib: 1024,
};

/// Operator-tunable knobs for one reconcile pass's cumulative bin-packing. Currently just the
/// conservative reservation floor charged to a **running** replica whose reservation can't be
/// resolved (see [`running_replica_reservation`]). [`Default`] reproduces the built-in
/// [`UNRESOLVED_RESERVATION`] floor EXACTLY, so an operator who configures nothing keeps
/// today's behavior — the floor is derived from the node's `[compute]` config at serve wiring
/// and threaded into [`reconcile_once`]. It is an **operator** knob (System·Admin, node-side),
/// never tenant-settable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinPackTuning {
    /// The floor charged to an unresolvable running replica — [`UNRESOLVED_RESERVATION`] by
    /// default. An operator raises it when their genuinely-orphaned replicas legitimately run
    /// larger than the conservative 1 vCPU + 1 GiB default, so the floor still prevents the
    /// over-subscription the bin-packing pre-pass exists to close. Charging **zero** would
    /// re-open that gap, so an operator who sets it is responsible for keeping it non-trivial.
    pub unresolved_reservation: Reservation,
}

impl Default for BinPackTuning {
    fn default() -> Self {
        Self {
            unresolved_reservation: UNRESOLVED_RESERVATION,
        }
    }
}

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

    /// CREDIT `res` back onto `node`'s remaining capacity (**saturating** add) — the inverse of
    /// [`reserve`](Self::reserve). Used by the preemption engine to free a to-be-evicted
    /// victim's reservation so the dry-run can test whether the preemptor then fits, and to
    /// build the credited ledger the reconcile driver hands to the main placement loop. Only
    /// ever credits a reservation that was previously charged (a running victim the pre-pass
    /// debited), so it never inflates a node past its advertised free figure in practice. A
    /// node absent from the ledger is ignored.
    pub fn credit(&mut self, node: u64, res: Reservation) {
        if let Some(r) = self.remaining.get_mut(&node) {
            r.vcpus = r.vcpus.saturating_add(res.vcpus);
            r.mem_mib = r.mem_mib.saturating_add(res.mem_mib);
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
    /// The replica was **preempted** (evicted) by a strictly-higher-priority workload and
    /// DRAINED (its container stopped; the persistent volume survived) — a durable marker,
    /// parallel to [`LaunchFailed`](Self::LaunchFailed), so `compute status` shows `PREEMPTED`
    /// (never a bare "unresolved") with the preemptor attribution instead of the ordinal
    /// silently vanishing. The reconcile retries the ordinal like a failed launch once its
    /// cooldown ([`PREEMPTION_COOLDOWN_SECS`]) expires and capacity frees; a successful
    /// relaunch overwrites it with a fresh [`Starting`](Self::Starting). A PARKED victim does
    /// NOT use this marker — it persists in [`ReplicaPhase::Zero`] and wakes via Restore.
    /// Always gated (never routed): it has no live endpoint. `by` is the operator phrase
    /// `"<project>/<workload>"` of the preemptor (a project-scoped surface redacts a
    /// cross-tenant preemptor to an aggregate).
    Preempted {
        /// The preemptor identity (`"<project>/<workload> (<class>, tier <N>)"`). A tenant-
        /// scoped render redacts a cross-tenant preemptor; the operator view names it.
        by: String,
        /// The preemptor's project — the single field a project-scoped surface compares against
        /// the viewing project to decide REDACTION (never shown; drives redaction only).
        preemptor_project: String,
        /// Wall-clock unix seconds the eviction happened — the anti-thrash COOLDOWN stamp on
        /// the replica record. While `now - since < `[`PREEMPTION_COOLDOWN_SECS`] the drained
        /// ordinal's relaunch is held off, so it is not immediately re-placed onto the node it
        /// was evicted from (which, with dry-run-before-evict + deterministic victim selection,
        /// keeps placement from oscillating). A PARKED victim needs no stamp — its wake is
        /// gated on the node having free capacity, which the preemptor holds until it leaves.
        since: u64,
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
        // A `Preempted` drain marker is a durable "evicted, not running" signal — surface it
        // (with its preemptor attribution) over a merely-starting/provisioned sibling, below the
        // launch/provision faults (a preemption is an expected, recoverable scheduling outcome).
        .or_else(|| {
            running
                .iter()
                .find(|r| matches!(r, Readiness::Preempted { .. }))
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

/// The per-workload **placement-explanation** key, project-scoped:
/// `project/<proj>/compute_placement/<workload>` → the latest [`PlacementExplain`] the
/// reconcile computed for it (v0.67.0). Written each pass so a STUCK (no-placement)
/// workload — which has zero replica-state rows — is still legible on `compute get`: it is
/// the one surface that survives the "stuck at 0" case the incident exposed. Pure status
/// (regenerated every reconcile), so a lost write self-heals on the next tick.
pub fn placement_explain_key(project: &str, workload: &str) -> String {
    format!("project/{project}/compute_placement/{workload}")
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
    /// **Preempt** a running replica to free its reservation for a strictly-higher-priority
    /// workload. Distinct from [`Stop`](Self::Stop) purely for OBSERVABILITY — it carries the
    /// preemptor identity + the disposition so an operator sees who evicted whom. A preemption
    /// is only ever planned after a DRY-RUN-before-evict proved the preemptor then fits (never
    /// a wasted eviction), by the global [`plan_preemptions`] engine. The driver executes it as
    /// a Snapshot+Zero ([`Park`](PreemptDisposition::Park)) or a graceful drain+Stop
    /// ([`Drain`](PreemptDisposition::Drain)); the victim's volumes always survive.
    Preempt {
        /// The running replica to evict.
        handle: InstanceHandle,
        /// How to evict it (park-to-snapshot vs graceful drain).
        disposition: PreemptDisposition,
        /// Who is preempting it (for the durable marker, events, and logs).
        preemptor: PreemptorRef,
    },
}

/// How a preemption victim is evicted — the disposition the [`plan_preemptions`] engine chooses
/// per victim and the driver executes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreemptDisposition {
    /// **Park** (preempt-to-snapshot): deregister from the endpoint set, Snapshot → Zero. The
    /// victim auto-recovers via the EXISTING wake path once its cooldown expires AND capacity
    /// frees. Chosen for a scale-to-zero-capable victim (its backend + spec support snapshot),
    /// so its in-RAM state survives the eviction.
    Park,
    /// **Drain**: deregister → SIGTERM → wait `grace` → Stop (the existing redeploy drain path;
    /// the persistent volume survives). Chosen when the victim cannot be parked. The victim's
    /// ordinal returns to `need` and surfaces as `PreemptedBy` until capacity frees and it is
    /// re-placed on a later pass.
    Drain {
        /// Graceful-shutdown grace in seconds before the Stop.
        grace: u32,
    },
}

/// The identity of the workload that triggered a preemption — carried on [`Action::Preempt`],
/// the durable [`Readiness::Preempted`] marker, and the events timeline so attribution ("who
/// evicted whom") is legible. Operator-facing; a TENANT-scoped surface REDACTS the cross-tenant
/// identity to an aggregate (see the CLI's tenant-redacted projection) — only the operator view
/// names another tenant's workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreemptorRef {
    /// The preemptor's owning project.
    pub project: String,
    /// The preemptor's workload name.
    pub workload: String,
    /// The preemptor's resolved operator tier (higher = stronger).
    pub tier: i32,
    /// The preemptor's resolved class name.
    pub class: String,
}

impl PreemptorRef {
    /// The operator phrase for this preemptor (`"<project>/<workload> (<class>, tier <N>)"`),
    /// used in the durable marker + logs. Carries no credential material.
    pub fn describe(&self) -> String {
        format!(
            "{}/{} ({}, tier {})",
            self.project, self.workload, self.class, self.tier
        )
    }
}

/// The cooldown (seconds) stamped on a just-preempted replica — the anti-thrash guard. A parked
/// victim's wake (Restore) and a drained victim's relaunch are both held off this long after the
/// eviction, so a victim cannot be immediately re-woken/re-placed onto the node it was evicted
/// from (which, combined with the dry-run-before-evict strict-improvement rule and deterministic
/// victim selection, keeps placement from oscillating). Also prevents a just-preempted replica
/// from itself triggering a preemption within the window.
pub const PREEMPTION_COOLDOWN_SECS: u64 = 60;

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

/// The STRUCTURED machine cause an ordinal could not be placed — the v0.70.0 reason enum, so a
/// shortfall surfaces a distinct, stable token instead of only a logged string (the biggest
/// pre-priority gap). Distinct from a persisted [`Readiness::Preempted`] marker (a victim that
/// WAS running and got drained — carried on its replica record); this enum classifies an ordinal
/// that was never placed this pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnplacedCause {
    /// Lost the capacity CONTEST to a strictly-higher-priority workload that consumed the
    /// contended node(s) this pass — the priority-specific shortfall (preemption could not free
    /// enough, or was not authorized). A legible "outbid", distinct from an absolute shortage.
    PriorityOutbid,
    /// No eligible backend had capacity for the spec's needs, independent of priority — the
    /// pre-priority reason, kept DISTINCT so an absolute shortage never reads as an outbid.
    InsufficientCapacity,
}

impl UnplacedCause {
    /// The stable machine token (`priority_outbid` / `insufficient_capacity`) a surface renders
    /// — kept stable across releases.
    pub fn token(self) -> &'static str {
        match self {
            Self::PriorityOutbid => "priority_outbid",
            Self::InsufficientCapacity => "insufficient_capacity",
        }
    }

    /// The short uppercase label the `compute status` REASON column shows (`OUTBID` /
    /// `INSUFFICIENT`) — never a bare "unresolved".
    pub fn label(self) -> &'static str {
        match self {
            Self::PriorityOutbid => "OUTBID",
            Self::InsufficientCapacity => "INSUFFICIENT",
        }
    }
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
    /// The STRUCTURED machine cause (v0.70.0 reason enum) — [`UnplacedCause::InsufficientCapacity`]
    /// by default (the per-workload planner's view); the global driver upgrades it to
    /// [`UnplacedCause::PriorityOutbid`] when a strictly-higher-priority workload consumed the
    /// contended capacity this pass.
    pub cause: UnplacedCause,
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
        // A durable PREEMPTION (drain) marker (evicted by a higher-priority workload — see
        // `plan_preemptions`). While within its anti-thrash COOLDOWN it is HELD (treated like a
        // `starting` replica: no Stop, and excluded from `need` so it is NOT immediately
        // re-placed onto the node it was evicted from — the oscillation guard). Past the
        // cooldown it is skipped like a `LaunchFailed` marker, so its ordinal lands in `need`
        // and is retried; a successful relaunch overwrites the marker with a fresh `Starting`,
        // and if capacity is still tight it simply surfaces `unscheduled` again. Out of range
        // (scaled down) it falls through to the normal out-of-range `Stop`, cleaning up the marker.
        if ord < desired
            && let Readiness::Preempted { since, .. } = &inst.readiness
        {
            if now.saturating_sub(*since) < PREEMPTION_COOLDOWN_SECS {
                starting.insert(ord);
            }
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
            // Wake on activity, but ONLY when the node still has room for it (capacity-gated).
            // The gate serves two ends: (1) a preempt-to-PARK victim stays parked until the
            // higher-priority workload that took its slot leaves and capacity frees — the
            // parked victim's recovery guard, needing no cooldown stamp because the preemptor
            // holds the slot; and (2) it closes the residual wake-oversubscription where a
            // normal scale-to-zero replica would reclaim a slot a higher-priority workload
            // already took this pass. A normal parked replica's own slot is free (the pre-pass
            // never charged a Zero replica), so it still wakes immediately on activity.
            if matches!(activity, WorkloadActivity::Active)
                && capacity.fits(inst.node, Reservation::of_spec(spec))
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
    // The ordinals past the placed count could not be placed. Name the LEGIBLE reason
    // (v0.67.0 placement-explain) — policy / source / credential / isolation / capacity —
    // instead of the old bare capacity line, so a stuck workload is never a black box. The
    // reason is computed once per plan (it is the same for every unplaced ordinal of this
    // spec) against the composed operator `policy`.
    let unscheduled: Vec<Unscheduled> = if placed < need.len() {
        let reason = no_placement_reason(nodes, spec, policy);
        need[placed..]
            .iter()
            .map(|ord| Unscheduled {
                workload: workload.name.clone(),
                replica: *ord,
                reason: reason.clone(),
                // The per-workload planner sees only an absolute shortfall; the global driver
                // upgrades this to `PriorityOutbid` when a higher-priority workload took the
                // contended capacity this pass (it has the cross-workload view to tell).
                cause: UnplacedCause::InsufficientCapacity,
            })
            .collect()
    } else {
        Vec::new()
    };
    ReconcilePlan {
        actions,
        unscheduled,
    }
}

// ---------------------------------------------------------------------------
// Preemption engine (pure — the priority tenancy boundary + anti-thrash)
// ---------------------------------------------------------------------------

/// One workload's snapshot for the global preemption pass — the inputs [`plan_preemptions`]
/// needs, gathered once by the reconcile driver in PRIORITY ORDER: its project, the mutable
/// workload (for priority/replicas/placement), the resolved spec, the EFFECTIVE operator policy
/// (node ∩ per-project), and its observed replicas.
#[derive(Debug, Clone, Copy)]
pub struct PreemptInput<'a> {
    /// Owning project.
    pub project: &'a str,
    /// The mutable workload (priority / replicas / placement / active).
    pub workload: &'a ComputeWorkload,
    /// The resolved active spec.
    pub spec: &'a ComputeSpec,
    /// The EFFECTIVE operator backend policy for this workload (node ∩ per-project).
    pub policy: &'a BackendPolicy,
    /// This workload's observed replicas.
    pub observed: &'a [ObservedInstance],
}

/// One planned eviction — a victim replica, how to evict it, and who preempted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPreemption {
    /// The victim's owning project.
    pub project: String,
    /// The victim replica to evict.
    pub handle: InstanceHandle,
    /// The node the victim runs on (whose capacity its eviction frees).
    pub node: u64,
    /// The backend running the victim.
    pub backend: String,
    /// The reservation this eviction frees (credited back to the node ledger).
    pub res: Reservation,
    /// How to evict it (park vs drain).
    pub disposition: PreemptDisposition,
    /// Who preempted it.
    pub preemptor: PreemptorRef,
}

/// The output of [`plan_preemptions`]: the victims to evict, the ledger CREDITED for their
/// freed reservations (the reconcile driver threads it into the main placement loop so the
/// preemptor places onto the freed capacity), and the `(project, workload)` set left OUTBID
/// (a shortfall priority contention caused that preemption could not — or was not authorized to
/// — resolve, so the driver tags those ordinals [`UnplacedCause::PriorityOutbid`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreemptionPlan {
    /// The victims to evict (deterministic, least-important-first, each proven to help).
    pub victims: Vec<PlannedPreemption>,
    /// The base ledger credited for every victim's reservation.
    pub credited: NodeCapacities,
    /// `(project, workload)` left outbid by priority contention this pass.
    pub outbid: BTreeSet<(String, String)>,
}

/// Whether an observed replica currently HOLDS node capacity (so it is a preemption VICTIM
/// candidate and counts toward its workload's "occupied" ordinals): a `Running` replica that is
/// NOT a durable failure/preemption marker (those never produced a live instance). A `Zero`
/// (parked) replica holds none.
fn holds_capacity(inst: &ObservedInstance) -> bool {
    inst.phase == ReplicaPhase::Running
        && !matches!(
            inst.readiness,
            Readiness::LaunchFailed { .. } | Readiness::Preempted { .. }
        )
}

/// How many NEW replicas a workload still needs placed this pass — `desired` minus the in-range
/// ordinals already occupied by a live/parked instance (a `Running` capacity-holder, or a `Zero`
/// replica that wakes via Restore). A redeploy (a `Running` replica of a superseded spec) counts
/// as occupied — it reuses its freed slot, needing no NEW capacity — so it never triggers
/// preemption. Approximate but sufficient to TRIGGER the engine; the authoritative placement is
/// still the main loop's [`reconcile_plan_in`].
fn preempt_need_count(input: &PreemptInput) -> u32 {
    let desired = input.workload.replicas;
    let mut occupied: BTreeSet<u32> = BTreeSet::new();
    for inst in input
        .observed
        .iter()
        .filter(|i| i.handle.workload == input.workload.name)
    {
        let ord = inst.handle.replica;
        if ord < desired && (holds_capacity(inst) || inst.phase == ReplicaPhase::Zero) {
            occupied.insert(ord);
        }
    }
    desired.saturating_sub(occupied.len() as u32)
}

/// The `min_available` floor a victim workload is protected by: its explicit
/// [`Priority::min_available`], else the class-derived default — `0` for a bottom-tier
/// (negative-tier, e.g. `spot`) class (freely preemptible), else the full `replicas` (protected,
/// matching `standard`/`system`). A HARD floor to a same-tier preemptor; ADVISORY to a
/// strictly-higher operator tier.
fn victim_floor(workload: &ComputeWorkload, class: &PriorityClass) -> u32 {
    workload
        .priority
        .min_available
        .unwrap_or(if class.tier < 0 { 0 } else { workload.replicas })
}

/// A preemption VICTIM candidate — one evictable replica with the facts the engine's selection,
/// min-available, and disposition logic read.
struct Candidate {
    project: String,
    workload: String,
    handle: InstanceHandle,
    node: u64,
    backend: String,
    res: Reservation,
    /// The victim's resolved operator tier (for the HARD-vs-ADVISORY floor decision).
    victim_tier: i32,
    /// Whether the victim can be PARKED (snapshot) rather than drained.
    can_park: bool,
    /// The victim spec's graceful-drain grace (seconds).
    drain_grace: u32,
    /// The victim's global priority key (for the least-important-first deterministic order).
    key: (i32, String, i32, String),
}

/// Whether a preemptor at `(p_tier, p_rank, p_mode, p_project)` may EVICT a victim workload at
/// `(v_tier, v_rank, v_project)` — the TENANCY BOUNDARY, enforced structurally:
///
/// - **Same project:** allowed iff the class may preempt within its project AND the preemptor's
///   `(tier, rank)` is STRICTLY greater — the tenant's own budget (safe; a tenant reshuffling
///   its own workloads). Within a project a higher `rank` (or higher class tier) wins.
/// - **Across projects:** allowed ONLY when the class is opted into cross-tenant preemption AND
///   the preemptor's TIER is strictly higher; `rank` is IGNORED across projects. So two
///   `standard` (equal-tier) tenants can NEVER preempt each other — the DoS/fairness-safe
///   default — and only an operator-opted higher tier (`system`) ever reaches another tenant.
fn can_preempt(
    p_tier: i32,
    p_rank: i32,
    p_mode: PreemptionMode,
    p_project: &str,
    v_tier: i32,
    v_rank: i32,
    v_project: &str,
) -> bool {
    if p_project == v_project {
        p_mode.preempts_within_project() && (p_tier, p_rank) > (v_tier, v_rank)
    } else {
        p_mode.preempts_cross_tenant() && p_tier > v_tier
    }
}

/// Whether, among `nodes`, the preemptor's `spec` could place on at least one PREEMPTIBLE
/// backend under its effective `policy`. A workload whose only eligible backends are DELEGATED
/// (cloudflare / kubernetes — `preemptible: false`) never preempts: boatramp owns neither their
/// capacity nor their eviction.
fn preemptor_uses_preemptible_backend(
    spec: &ComputeSpec,
    nodes: &[Node],
    policy: &BackendPolicy,
    caps: &BTreeMap<String, Capabilities>,
) -> bool {
    nodes.iter().any(|n| {
        n.pick_backend(spec, policy)
            .and_then(|b| caps.get(&b).map(|c| c.preemptible))
            .unwrap_or(false)
    })
}

/// The pure, global **preemption engine** — the priority slate's highest-stakes function. Given
/// every workload's snapshot in PRIORITY ORDER and the post-pre-pass capacity ledger, it decides
/// which lower-priority replicas to EVICT so a higher-priority workload can be placed, subject to
/// the tenancy boundary, `min_available` floors, backend-preemptibility, and — critically — the
/// DRY-RUN-BEFORE-EVICT strict-improvement rule that makes it anti-thrash: a victim is chosen
/// ONLY when freeing it actually advances the preemptor's placement (never a wasted eviction),
/// and victims are taken least-important-first by the deterministic global key. Returns the
/// victims, the ledger credited for their freed capacity, and the outbid set.
///
/// It simulates the main reconcile loop's cumulative placement (same priority order, same
/// [`place_replicas_in`]) against a working ledger, so the credited ledger it hands back is
/// exactly what the main loop reproduces — the engine decides the evictions; the main loop does
/// the authoritative placement. PURE: a function of the snapshot + the catalog + `now` only (the
/// sole carry-over is each replica's persisted preemption-cooldown marker, read via the snapshot).
///
/// `project_ceilings` maps `project → current priority-class ceiling` (the operator per-project
/// cap; a project absent from the map, or mapped to `None`, takes the node default ceiling). Every
/// workload's effective tier/authority is CLAMPED to its project ceiling via
/// [`PriorityClassCatalog::resolve_clamped`] — so a class stored above the project's NOW-current
/// ceiling (e.g. `system` stored while the ceiling was raised, then lowered back to `standard`)
/// loses its over-ceiling cross-tenant preemption authority here, not only at the write path. The
/// clamp only lowers a tier, so an all-default or at/under-ceiling fleet is unaffected.
pub fn plan_preemptions(
    inputs: &[PreemptInput],
    nodes: &[Node],
    caps: &BTreeMap<String, Capabilities>,
    catalog: &PriorityClassCatalog,
    project_ceilings: &BTreeMap<String, Option<String>>,
    base_ledger: &NodeCapacities,
    _now: u64,
) -> PreemptionPlan {
    // The project's CURRENT ceiling class name (`None` ⇒ the node default ceiling), used to clamp
    // every resolve below so a stored over-ceiling class loses its over-ceiling placement
    // precedence + preemption authority at reconcile.
    let ceiling_of = |project: &str| -> Option<&str> {
        project_ceilings.get(project).and_then(|c| c.as_deref())
    };
    // Working ledger: reserves each workload's placements AND credits chosen victims, mirroring
    // the main loop so later (lower-priority) workloads see the same contended capacity.
    let mut sim = base_ledger.clone();
    let mut victims: Vec<PlannedPreemption> = Vec::new();
    let mut outbid: BTreeSet<(String, String)> = BTreeSet::new();
    // Victim replicas already committed this pass (so a second preemptor can't double-free one),
    // and per-victim-workload eviction counts (for the running `min_available` floor).
    let mut evicted: BTreeSet<(String, String, u32)> = BTreeSet::new();
    // Workloads that reserved capacity this pass, as `(project, tier, rank)`. A later workload's
    // shortfall is `PriorityOutbid` (vs a plain `InsufficientCapacity`) ONLY when one of these
    // STRICTLY DOMINATES it — a higher tier, or a higher rank in its OWN project (same tier).
    // Two equal-tier workloads in DIFFERENT projects never dominate each other (the
    // fairness-safe default), so a shortfall between two `standard` tenants reads as an absolute
    // shortage, never an outbid.
    let mut placed_workloads: Vec<(String, i32, i32)> = Vec::new();

    for (idx, p) in inputs.iter().enumerate() {
        // CEILING-CLAMPED resolve: a class stored above the project's current ceiling resolves AS
        // the ceiling class, so an over-ceiling `system` preemptor loses its cross-tenant authority
        // (it becomes `standard` = within-project) — the reconcile-time completion of revocation.
        let (p_class_name, p_class) =
            catalog.resolve_clamped(&p.workload.priority, ceiling_of(p.project));
        let p_tier = p_class.tier;
        let p_rank = p.workload.priority.rank;
        let p_mode = p_class.preemption;

        // Whether some already-placed workload STRICTLY dominates this one (so an unresolved
        // shortfall is a true priority outbid, not just an absolute capacity shortage).
        let dominated = |placed: &[(String, i32, i32)]| -> bool {
            placed.iter().any(|(vp, vt, vr)| {
                *vt > p_tier || (vp == p.project && *vt == p_tier && *vr > p_rank)
            })
        };

        let need = preempt_need_count(p);
        if need == 0 {
            continue;
        }
        // Place what fits against the shared sim ledger (reserve it — mirror the main loop).
        let placed = place_replicas_in(
            need,
            &p.workload.placement,
            p.spec,
            nodes,
            p.policy,
            &mut sim,
        )
        .len();
        if placed > 0 {
            placed_workloads.push((p.project.to_string(), p_tier, p_rank));
        }
        let shortfall = need as usize - placed;
        if shortfall == 0 {
            continue;
        }
        // Can this workload even preempt? It must run on a preemptible backend and its class
        // must carry some preemption authority; otherwise its shortfall stands — flagged
        // `PriorityOutbid` only if a strictly-higher-priority workload took the capacity.
        if !p_mode.preempts_within_project()
            || !preemptor_uses_preemptible_backend(p.spec, nodes, p.policy, caps)
        {
            if dominated(&placed_workloads) {
                outbid.insert((p.project.to_string(), p.workload.name.clone()));
            }
            continue;
        }

        // Enumerate candidate victims: a capacity-holding replica of ANOTHER workload (any
        // project) that (a) runs on a preemptible backend and (b) the tenancy boundary admits.
        let mut candidates: Vec<Candidate> = Vec::new();
        for (vidx, v) in inputs.iter().enumerate() {
            if vidx == idx {
                continue; // never preempt one's own workload's replicas to place itself
            }
            // CEILING-CLAMPED victim tier: the cross-tenant eligibility check uses the victim's
            // effective (clamped) tier, so a victim whose stored class now exceeds its project
            // ceiling is weighed at the ceiling tier (consistent with the preemptor clamp above).
            let (_v_name, v_class) =
                catalog.resolve_clamped(&v.workload.priority, ceiling_of(v.project));
            let v_tier = v_class.tier;
            let v_rank = v.workload.priority.rank;
            if !can_preempt(p_tier, p_rank, p_mode, p.project, v_tier, v_rank, v.project) {
                continue;
            }
            let v_res = Reservation::of_spec(v.spec);
            for inst in v
                .observed
                .iter()
                .filter(|i| i.handle.workload == v.workload.name && holds_capacity(i))
            {
                // Skip a replica already committed as a victim by an earlier (higher-priority)
                // preemptor this pass — it can't be double-freed.
                let evkey = (
                    v.project.to_string(),
                    v.workload.name.clone(),
                    inst.handle.replica,
                );
                if evicted.contains(&evkey) {
                    continue;
                }
                // Only replicas on a PREEMPTIBLE backend are victims (boatramp owns their
                // capacity + eviction); a delegated backend's replica is never a victim.
                if !caps.get(&inst.backend).is_some_and(|c| c.preemptible) {
                    continue;
                }
                let can_park = v.spec.scale_to_zero
                    && caps.get(&inst.backend).is_some_and(|c| c.scale_to_zero);
                candidates.push(Candidate {
                    project: v.project.to_string(),
                    workload: v.workload.name.clone(),
                    handle: inst.handle.clone(),
                    node: inst.node,
                    backend: inst.backend.clone(),
                    res: v_res,
                    victim_tier: v_tier,
                    can_park,
                    drain_grace: v.spec.startup_grace_secs,
                    key: workload_priority_key_clamped(
                        catalog,
                        v.project,
                        v.workload,
                        ceiling_of(v.project),
                    ),
                });
            }
        }
        // Deterministic order: LEAST-important victim first (largest global key — recall the key
        // sorts higher-priority SMALLER), then lowest node id, then lowest replica ordinal.
        candidates.sort_by(|a, b| {
            b.key
                .cmp(&a.key)
                .then(a.node.cmp(&b.node))
                .then(a.handle.replica.cmp(&b.handle.replica))
        });

        // Running count per victim workload (for the min_available floor), net of replicas
        // ALREADY committed as victims this pass (by an earlier preemptor), and further
        // decremented as this preemptor chooses victims from it.
        let mut running_left: BTreeMap<(String, String), u32> = BTreeMap::new();
        for v in inputs {
            let n = v
                .observed
                .iter()
                .filter(|i| i.handle.workload == v.workload.name && holds_capacity(i))
                .count() as u32;
            let already = evicted
                .iter()
                .filter(|(pr, wl, _)| pr == v.project && wl == &v.workload.name)
                .count() as u32;
            running_left.insert(
                (v.project.to_string(), v.workload.name.clone()),
                n.saturating_sub(already),
            );
        }

        // DRY-RUN-BEFORE-EVICT with per-victim strict improvement: credit a candidate only when
        // it actually advances the preemptor's placement; stop once the full shortfall fits.
        let mut trial = sim.clone();
        let mut chosen: Vec<Candidate> = Vec::new();
        let mut fit = 0usize;
        for cand in candidates {
            if fit >= shortfall {
                break;
            }
            // min_available floor for this victim workload.
            let vkey = (cand.project.clone(), cand.workload.clone());
            let v_input = inputs
                .iter()
                .find(|v| v.project == cand.project && v.workload.name == cand.workload);
            let (floor, same_tier) = match v_input {
                Some(v) => {
                    // Clamp the victim to its project ceiling so both the min-available floor and
                    // the same-tier test weigh its EFFECTIVE tier (matching `can_preempt` above).
                    let (_n, vc) =
                        catalog.resolve_clamped(&v.workload.priority, ceiling_of(v.project));
                    (victim_floor(v.workload, vc), vc.tier == p_tier)
                }
                None => (0, false),
            };
            let left = running_left.get(&vkey).copied().unwrap_or(0);
            let after = left.saturating_sub(1);
            if after < floor {
                // Dropping below the floor. HARD when same tier (refuse); ADVISORY to a strictly
                // higher operator tier (allow, so `system` can still displace a node-holding
                // lower-tier workload — the standoff is surfaced legibly rather than deadlocked).
                if same_tier || !(p_tier > cand.victim_tier) {
                    continue;
                }
            }
            // Probe: does crediting this victim increase how much of the shortfall fits?
            let mut probe = trial.clone();
            probe.credit(cand.node, cand.res);
            let mut probe2 = probe.clone();
            let new_fit = place_replicas_in(
                shortfall as u32,
                &p.workload.placement,
                p.spec,
                nodes,
                p.policy,
                &mut probe2,
            )
            .len();
            if new_fit > fit {
                trial.credit(cand.node, cand.res);
                fit = new_fit;
                running_left.insert(vkey, after);
                chosen.push(cand);
            }
            // else: this victim does not help the preemptor — never evict it (no wasted eviction).
        }

        if fit >= shortfall && !chosen.is_empty() {
            // COMMIT: credit the sim ledger, record the victims, then reserve the preemptor's
            // now-fitting placements so a later workload this pass sees the capacity taken.
            // The preemptor is now a placed workload (it may itself dominate a later one).
            placed_workloads.push((p.project.to_string(), p_tier, p_rank));
            for cand in &chosen {
                sim.credit(cand.node, cand.res);
            }
            place_replicas_in(
                shortfall as u32,
                &p.workload.placement,
                p.spec,
                nodes,
                p.policy,
                &mut sim,
            );
            for cand in chosen {
                evicted.insert((
                    cand.project.clone(),
                    cand.workload.clone(),
                    cand.handle.replica,
                ));
                let disposition = if cand.can_park {
                    PreemptDisposition::Park
                } else {
                    PreemptDisposition::Drain {
                        grace: cand.drain_grace,
                    }
                };
                victims.push(PlannedPreemption {
                    project: cand.project,
                    handle: cand.handle,
                    node: cand.node,
                    backend: cand.backend,
                    res: cand.res,
                    disposition,
                    preemptor: PreemptorRef {
                        project: p.project.to_string(),
                        workload: p.workload.name.clone(),
                        tier: p_tier,
                        class: p_class_name.to_string(),
                    },
                });
            }
        } else {
            // Could not free enough (or nothing helped) — evict NOTHING (no wasted eviction).
            // The shortfall is a true `PriorityOutbid` only if a strictly-higher-priority
            // workload took the capacity; otherwise it is an absolute `InsufficientCapacity`.
            if dominated(&placed_workloads) {
                outbid.insert((p.project.to_string(), p.workload.name.clone()));
            }
        }
    }

    // The ledger the driver hands to the main loop: the post-pre-pass base credited for each
    // committed victim's reservation (the main loop re-reserves placements itself).
    let mut credited = base_ledger.clone();
    for v in &victims {
        credited.credit(v.node, v.res);
    }
    PreemptionPlan {
        victims,
        credited,
        outbid,
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
    /// Replicas **preempted** (parked or drained to free capacity for a higher-priority
    /// workload) this pass.
    pub preempted: usize,
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
    ComputeSpec::builder(
        RootSource::Image(image.unwrap_or_else(|| engine.default_image()).to_string()),
        1,
        512,
        engine.port(),
    )
    .entrypoint(entrypoint)
    .env(env)
    .startup_grace_secs(startup_grace_secs)
    .volumes(vec![VolumeRef::new(data_dir, "data", volume_size_mib)])
    .build()
}

/// Whether a workload that declares a `blob` [`ComputeBinding`] is likely **misnamed**: it
/// binds a blob store but its name matches no known site in the project. A `blob` (or `kv`)
/// binding resolves its namespace under the **workload name** as the site-identity segment
/// (`hblob/{project}/{workload}/…`, exactly as a `wasi:blobstore` handler uses its SITE name
/// — see `boatramp_server::blob_shim`), so a workload shares a site's container only when it
/// is NAMED AFTER that site; a name matching no site writes to an invisible, empty namespace
/// of its own with no error. Returns true only when there IS a `blob` binding **and**
/// `workload` is absent from `known_sites` — a likely-mistake signal the server logs at set
/// time. Pure and case-sensitive (site names are case-sensitive store keys), so it is
/// unit-testable without a store.
pub fn blob_bind_names_unknown_site(
    workload: &str,
    bindings: &[ComputeBinding],
    known_sites: &[String],
) -> bool {
    bindings.iter().any(|b| b.kind == BindingKind::Blob)
        && !known_sites.iter().any(|s| s == workload)
}

/// Persist a drained preemption victim's durable [`Readiness::Preempted`] MARKER — the record
/// (kept, not deleted) that makes `compute status` show `PREEMPTED` with the preemptor
/// attribution and that the reconcile retries once its cooldown expires + capacity frees. Built
/// from the victim's observed record with phase `Running` + `healthy: false` (like a
/// `LaunchFailed` marker), carrying the preemptor identity + the eviction timestamp (the
/// anti-thrash cooldown stamp).
async fn persist_preempt_marker(
    deploy: &DeployStore,
    project: ProjectRef<'_>,
    obs: &ObservedInstance,
    v: &PlannedPreemption,
    now: u64,
    report: &mut ReconcileReport,
) {
    let marker = ObservedInstance {
        healthy: false,
        phase: ReplicaPhase::Running,
        readiness: Readiness::Preempted {
            by: v.preemptor.describe(),
            preemptor_project: v.preemptor.project.clone(),
            since: now,
        },
        snapshot: None,
        data_dir: None,
        ..obs.clone()
    };
    match deploy.set_replica_state(project, &marker).await {
        Ok(()) => report.preempted += 1,
        Err(e) => report.errors.push(format!(
            "{}/{}: preempt-drain persist: {e}",
            v.handle.workload, v.handle.replica
        )),
    }
}

/// One reconcile pass: for every workload, refresh replica health, compute the
/// plan ([`reconcile_plan`]), and execute it against the chosen backends —
/// launching/stopping replicas and persisting their observed state (which the
/// gateway reads as the upstream pool). Per-action failures are collected (not
/// fatal) so one bad workload can't stall the rest; a top-level KV failure
/// aborts the pass. The caller leader-gates this (cron-style).
///
/// Before the per-workload loop a global PREEMPTION pass ([`plan_preemptions`]) may evict
/// lower-priority replicas to free capacity for higher-priority workloads (priority-ordered by
/// [`workload_priority_key`]); it threads a CREDITED capacity ledger into the loop.
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
    tuning: BinPackTuning,
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

    // The operator priority-class catalog in force (the owner-set built-in `system`/`standard`/
    // `spot` tiers). The reconcile engine uses the built-ins; operator tier/mode overrides via
    // node config compose into this catalog at the server wiring (a thin follow-on).
    let catalog = PriorityClassCatalog::builtin();

    // Every project's workloads (compute is project-scoped in 0.2.0), fetched once.
    let mut workloads = deploy.list_compute_workloads_all().await?;
    // Each project's CURRENT priority-class ceiling (the operator per-project cap), fetched once
    // and shared by BOTH the priority-ordered placement sort and the preemption engine. The
    // ceiling is authoritative at RECONCILE, not only at the write path: a class stored while the
    // project ceiling was temporarily HIGHER (then lowered back) is CLAMPED to the current ceiling
    // wherever a tier is resolved below, so it loses any over-ceiling placement precedence AND
    // cross-tenant preemption authority — completing the revocation the write-time `check_request`
    // gate alone cannot. A missing/unreadable per-project policy ⇒ `None` = the node default
    // ceiling (FAIL-CLOSED: the default is `standard`, never a silent grant of a higher tier).
    let mut project_ceilings: BTreeMap<String, Option<String>> = BTreeMap::new();
    for (project_name, _) in &workloads {
        if project_ceilings.contains_key(project_name) {
            continue;
        }
        let ceiling = match deploy
            .get_project_backend_policy(ProjectRef::new(project_name))
            .await
        {
            Ok(pp) => pp.and_then(|p| p.priority_ceiling),
            Err(_) => None,
        };
        project_ceilings.insert(project_name.clone(), ceiling);
    }
    // DETERMINISTIC, PRIORITY-ORDERED placement. With one shared capacity ledger (below) the
    // order in which workloads consume contended capacity is observable, so sort by the global
    // priority comparator — `operator_tier DESC → project → rank DESC → name` (see
    // [`workload_priority_key`]). Because `project` outranks `rank`, a tenant's huge `rank`
    // reshuffles only its OWN workloads and can never leapfrog another project — the fairness
    // boundary is this key ordering, not a runtime check. With all-default classes + rank 0 it
    // reduces to the prior `(project, name)` order, so the change is non-regressive: a
    // capacity-tight workload stays unplaced on the same stable basis each tick (it doesn't
    // flap), and freed capacity is handed to the earliest (highest-priority) such workload.
    workloads.sort_by(|(pa, wa), (pb, wb)| {
        let ca = project_ceilings.get(pa).and_then(|c| c.as_deref());
        let cb = project_ceilings.get(pb).and_then(|c| c.as_deref());
        workload_priority_key_clamped(&catalog, pa, wa, ca)
            .cmp(&workload_priority_key_clamped(&catalog, pb, wb, cb))
    });

    // Each workload's active spec + replica states, fetched exactly ONCE for this tick.
    struct WorkloadTickInputs {
        project_name: String,
        workload: ComputeWorkload,
        /// The workload's current active spec (`None` ⇒ its spec blob is missing — the main
        /// loop surfaces that and skips the workload; the pre-pass uses it as the running-
        /// replica fallback reservation).
        active_spec: Option<ComputeSpec>,
        /// The workload's observed replica states.
        replica_states: Vec<ObservedInstance>,
    }
    // SINGLE per-workload KV read for this tick. The bin-packing pre-pass and the per-workload
    // planning loop below both need each workload's active spec and replica states; read them
    // ONCE here and thread the result through both passes, halving the spec + replica-state
    // reads per workload per tick. This is OUTPUT-IDENTICAL, not merely cheaper: the pre-pass
    // is read-only, and the planning loop writes only the CURRENT workload's own replica states
    // (and launches/stops its own replicas) — never another workload's states, and never a spec
    // blob (specs are immutable, content-addressed). So nothing mutates a workload's spec or
    // states between the two reads this replaces, and a single read returns exactly what both
    // reads did (the pre-pass fully precedes the planning loop, so the planning loop's own
    // writes to a workload never predate that workload's cached read either).
    let tick_inputs: Vec<WorkloadTickInputs> = {
        let mut v = Vec::with_capacity(workloads.len());
        for (project_name, workload) in workloads {
            let project = ProjectRef::new(&project_name);
            let active_spec = deploy.get_compute_spec(&workload.active).await?;
            let replica_states = deploy.list_replica_states(project, &workload.name).await?;
            v.push(WorkloadTickInputs {
                project_name,
                workload,
                active_spec,
                replica_states,
            });
        }
        v
    };

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
        for wi in &tick_inputs {
            // The workload's current active spec (`wi.active_spec`) is the fallback reservation
            // for a running replica whose OWN launched spec can't be resolved.
            for state in &wi.replica_states {
                // Only a RUNNING replica with a LIVE instance occupies vCPU/memory. Skip:
                //  - a Zero (parked) or terminal replica (phase != Running) — it holds none
                //    (its reserved IP is tracked separately via `parked_keys`); and
                //  - a durable `LaunchFailed` MARKER — it is recorded `Running` as a diagnostic
                //    (see the launch-error arm below / PLAN launch-observability) but its
                //    `launch` never produced an instance, so it consumes no real capacity.
                //    Charging it would phantom-occupy the node AND double-count the ordinal,
                //    since `reconcile_plan_in` relaunches the failed ordinal THIS SAME pass
                //    (debiting the ledger again) — which on a tight node would wrongly leave the
                //    retry `unscheduled` and mask the real launch-failure reason. Skipping it is
                //    what makes cumulative bin-packing and launch-observability compose: the same
                //    "a LaunchFailed marker has no live instance" rule the observe loop, binding
                //    resolution, and the planner's classification already apply.
                //  - a durable `Preempted` (drain) MARKER — the victim's container was stopped
                //    by a preemption, so it holds no capacity either (its ordinal is retried
                //    like a failed launch once its cooldown expires and capacity frees).
                if state.phase != ReplicaPhase::Running
                    || matches!(
                        state.readiness,
                        Readiness::LaunchFailed { .. } | Readiness::Preempted { .. }
                    )
                {
                    continue;
                }
                let res = running_replica_reservation(
                    deploy,
                    &mut spec_res_cache,
                    state,
                    wi.active_spec.as_ref(),
                    tuning.unresolved_reservation,
                    &mut report,
                )
                .await?;
                capacity.reserve(state.node, res);
            }
        }
    }

    // PREEMPTION PASS (v0.70.0). Gather a priority-ordered snapshot of every workload — its
    // resolved spec, EFFECTIVE operator policy (node ∩ per-project), and observed replicas — and
    // run the pure global `plan_preemptions` engine against the post-pre-pass ledger. It decides
    // which lower-priority replicas to EVICT so a higher-priority workload fits, under the
    // tenancy boundary + min_available floors + dry-run-before-evict strict improvement. We then
    // execute the evictions (park→snapshot+zero / drain→stop+marker) and thread the CREDITED
    // ledger into the main loop, so the preemptor places onto the freed capacity. A workload
    // whose per-project policy read ERRORS is left OUT of the snapshot entirely — it is neither
    // preemptor nor victim this pass (fail-safe: never evict under an uncertain policy), mirroring
    // the main loop's fail-closed placement hold.
    struct PreemptOwned {
        project: String,
        workload: ComputeWorkload,
        spec: ComputeSpec,
        policy: BackendPolicy,
        observed: Vec<ObservedInstance>,
    }
    let now_unix = crate::time::now_unix();
    let mut preempt_owned: Vec<PreemptOwned> = Vec::new();
    {
        let mut policy_cache: BTreeMap<String, BackendPolicy> = BTreeMap::new();
        for wi in &tick_inputs {
            let project_name = &wi.project_name;
            let workload = &wi.workload;
            let project = ProjectRef::new(project_name);
            // Reuse the single per-tick fetch (binpack's `WorkloadTickInputs`): the pre-pass is
            // read-only and a workload's spec is immutable (content-addressed), so `wi.active_spec`
            // / `wi.replica_states` are exactly what a fresh read here would return — no third
            // per-workload store round-trip, keeping binpack's fetch-once invariant.
            let Some(spec) = wi.active_spec.clone() else {
                continue; // no spec → the main loop reports it; nothing to preempt for/with
            };
            let effective = if let Some(p) = policy_cache.get(project_name) {
                p.clone()
            } else {
                match deploy.get_project_backend_policy(project).await {
                    Ok(pp) => {
                        let e = policy.compose_project(&pp.unwrap_or_default());
                        policy_cache.insert(project_name.clone(), e.clone());
                        e
                    }
                    // Policy unavailable → skip this workload from the preemption pass entirely
                    // (fail-safe: never evict, never be evicted, under an uncertain policy).
                    Err(_) => continue,
                }
            };
            let observed = wi.replica_states.clone();
            preempt_owned.push(PreemptOwned {
                project: project_name.clone(),
                workload: workload.clone(),
                spec,
                policy: effective,
                observed,
            });
        }
    }
    let preempt_inputs: Vec<PreemptInput> = preempt_owned
        .iter()
        .map(|o| PreemptInput {
            project: &o.project,
            workload: &o.workload,
            spec: &o.spec,
            policy: &o.policy,
            observed: &o.observed,
        })
        .collect();
    let preemption = plan_preemptions(
        &preempt_inputs,
        nodes,
        &caps,
        &catalog,
        &project_ceilings,
        &capacity,
        now_unix,
    );
    // EXECUTE the evictions. Park snapshots+zeros a scale-to-zero-capable victim (it wakes via
    // the existing capacity-gated Restore once the preemptor leaves); Drain stops the container
    // (its persistent volume survives) and persists a durable `Preempted` marker so `compute
    // status` shows PREEMPTED with attribution and the ordinal is retried once its cooldown
    // expires and capacity frees. A victim that vanished between plan + execute is skipped.
    for v in &preemption.victims {
        let project = ProjectRef::new(&v.project);
        let owned = preempt_owned
            .iter()
            .find(|o| o.project == v.project && o.workload.name == v.handle.workload);
        let Some(obs) =
            owned.and_then(|o| o.observed.iter().find(|i| i.handle == v.handle).cloned())
        else {
            continue;
        };
        let Some(b) = backends.get(&v.backend) else {
            report.errors.push(format!(
                "{}/{}: preempt: no backend {:?}",
                v.handle.workload, v.handle.replica, v.backend
            ));
            continue;
        };
        match &v.disposition {
            PreemptDisposition::Park => match b.snapshot(&v.handle).await {
                Ok(Some(mut snapshot)) => {
                    snapshot.project = v.project.clone();
                    let parked = ObservedInstance {
                        healthy: false,
                        phase: ReplicaPhase::Zero,
                        snapshot: Some(snapshot),
                        ..obs
                    };
                    match deploy.set_replica_state(project, &parked).await {
                        Ok(()) => report.preempted += 1,
                        Err(e) => report.errors.push(format!(
                            "{}/{}: preempt-park persist: {e}",
                            v.handle.workload, v.handle.replica
                        )),
                    }
                }
                // Backend declined to snapshot (e.g. not running) — fall back to a drain so the
                // capacity is still freed; persist the durable marker.
                Ok(None) => {
                    let _ = b.stop(&v.handle).await;
                    persist_preempt_marker(deploy, project, &obs, v, now_unix, &mut report).await;
                }
                Err(e) => report.errors.push(format!(
                    "{}/{}: preempt-snapshot: {e}",
                    v.handle.workload, v.handle.replica
                )),
            },
            PreemptDisposition::Drain { grace: _ } => {
                // Deregister + stop (the existing redeploy drain path; the volume survives).
                if let Some(b2) = backends.get(&v.backend)
                    && let Err(e) = b2.stop(&v.handle).await
                {
                    report.errors.push(format!(
                        "{}/{}: preempt-stop: {e}",
                        v.handle.workload, v.handle.replica
                    ));
                }
                // Release the victim's shim tokens + revoke its dynamic DB cred (idempotent),
                // exactly as a normal Stop does — a relaunch re-mints them.
                if let Some(o) = owned {
                    if let Some(resolver) = resolver
                        && !o.spec.bindings.is_empty()
                    {
                        resolver
                            .release(
                                &v.project,
                                &v.handle.workload,
                                v.handle.replica,
                                &o.spec.bindings,
                            )
                            .await;
                    }
                    if let Some(m) = managed_db {
                        let _ = m
                            .revoke_dynamic_db_cred(
                                &v.project,
                                &v.handle.workload,
                                &o.spec.bindings,
                                v.handle.replica,
                            )
                            .await;
                    }
                }
                persist_preempt_marker(deploy, project, &obs, v, now_unix, &mut report).await;
            }
        }
    }
    // Thread the credited ledger into the main loop so the preemptor places onto freed capacity.
    capacity = preemption.credited;
    let outbid = preemption.outbid;

    // The owning project threads through every replica-state read/write below. Each workload's
    // active spec + replica states were already fetched ONCE into `tick_inputs` above (shared
    // with the pre-pass AND the preemption pass) — reuse them here rather than re-reading the store.
    for wi in tick_inputs {
        let WorkloadTickInputs {
            project_name,
            workload,
            active_spec,
            replica_states,
        } = wi;
        let project = ProjectRef::new(&project_name);
        let Some(spec) = active_spec else {
            report
                .errors
                .push(format!("{}: active spec missing", workload.name));
            continue;
        };

        // Observed replica state + a health refresh (skipping parked Zero
        // replicas — they're intentionally down).
        let mut observed = replica_states;
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

        // v0.67.0 backend-selection policy: compose the NODE operator policy (`policy`,
        // carrying the isolation posture + `[compute.policy]`) with this project's
        // PER-PROJECT operator policy — operator-first, narrowing-only (intersect allows /
        // union forbids / per-project `prefer` wins). The composed policy is what the
        // scheduler selects on, so a tenant `require`/`prefer` can only ever pick WITHIN the
        // operator bound.
        //
        // FAIL CLOSED on a store ERROR (distinct from `Ok(None)`): the per-project
        // `forbid`/`allow` is a security control — the ONLY per-project isolation-hardening
        // mechanism (there is deliberately no per-project posture field), and the write path
        // (`set_project_backend_policy` → `put_durable_checkpointed`) treats a lost write as
        // never-silently-revert-to-more-permissive. So an `Err` must NOT collapse to the empty
        // policy (which would drop the forbid/allow and place under the node bound alone —
        // fail-OPEN). Instead HOLD new placements for this workload: skip BEFORE
        // `reconcile_plan_in`, so no plan is computed ⇒ no new `Launch` AND no `Stop`/
        // scale-down — existing replicas keep running; only new placement is held during the
        // blip, which self-heals on the next tick. Mirrors the `get_compute_spec` skip
        // precedent in this loop. `Ok(None)` (no record) correctly composes to the node bound
        // (back-compat).
        let project_policy = match deploy.get_project_backend_policy(project).await {
            Ok(p) => p.unwrap_or_default(),
            Err(e) => {
                tracing::warn!(
                    project = %project_name,
                    workload = %workload.name,
                    error = %e,
                    "compute: backend policy unavailable — holding new placement (existing replicas untouched)",
                );
                // Surface via the same `not scheduled:` path the planner's shortfalls use.
                report.errors.push(format!(
                    "{}: not scheduled: backend policy unavailable — placement held",
                    workload.name
                ));
                continue;
            }
        };
        let effective_policy = policy.compose_project(&project_policy);
        // Persist the per-workload placement-explain (legibility that survives the stuck-at-0
        // case: a no-placement workload has zero replica rows but still gets this). Best-effort
        // status — a failed write self-heals next tick, so it never aborts the pass.
        let explain = explain_placement(nodes, &spec, policy, &project_policy);
        if let Err(e) = deploy
            .set_placement_explain(project, &workload.name, &explain)
            .await
        {
            tracing::debug!(workload = %workload.name, error = %e, "compute: persist placement-explain");
        }

        // The project's guest-log redaction OPT-OUT preference (v0.70.0 two-tier opt-out):
        // a System·Admin per-project record that the backend honors ONLY when the node admits
        // per-project overrides (`[compute].allow_per_project_redaction_override`). Loaded once
        // per workload and carried on every replica's launch request. FAIL SECURE on a read
        // error (and on an absent record): default to NOT opted out, so a store blip keeps
        // redaction ON (the secure state) rather than silently disabling a security control —
        // and, unlike the backend policy above, never HOLDS placement, since redaction is
        // defense-in-depth and must not block launches.
        let project_opt_out_redaction = match deploy.get_project_log_redaction(project).await {
            Ok(r) => r.map(|r| r.opt_out).unwrap_or(false),
            Err(e) => {
                tracing::debug!(
                    project = %project_name,
                    workload = %workload.name,
                    error = %e,
                    "compute: project log-redaction setting unavailable — defaulting to redaction ON",
                );
                false
            }
        };

        let workload_activity = activity.activity(&workload.name).await;
        let plan = reconcile_plan_in(
            &workload,
            &spec,
            nodes,
            &effective_policy,
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
        // Did a strictly-higher-priority workload consume the capacity this workload wanted?
        // The preemption engine marks such a workload OUTBID; upgrade its shortfall's structured
        // cause from the planner's default `InsufficientCapacity` to `PriorityOutbid` so the
        // reason enum distinguishes "lost the capacity contest" from an absolute shortage.
        let was_outbid = outbid.contains(&(project_name.clone(), workload.name.clone()));
        for u in &plan.unscheduled {
            let cause = if was_outbid {
                UnplacedCause::PriorityOutbid
            } else {
                u.cause
            };
            tracing::warn!(
                project = %project_name,
                workload = %u.workload,
                replica = u.replica,
                reason = %u.reason,
                cause = cause.token(),
                "compute: replica not scheduled",
            );
            // The human log line stays stable (`not scheduled: <reason>`); the machine cause
            // token (`priority_outbid` / `insufficient_capacity`) rides the structured `cause`
            // tracing field above and the `compute get` placement-explain, so a surface can
            // distinguish an outbid from an absolute shortage without parsing this string.
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
                    // The workload's resolved priority class, threaded so a delegated backend
                    // (k8s) can map it to its native PriorityClass. CEILING-CLAMPED so a stored
                    // over-ceiling class cannot smuggle its over-ceiling authority onto the
                    // delegated substrate either — the native PriorityClass tracks the same
                    // effective (clamped) tier the local engine enforces.
                    let priority_class = Some(
                        catalog
                            .resolve_clamped(
                                &workload.priority,
                                project_ceilings
                                    .get(project_name.as_str())
                                    .and_then(|c| c.as_deref()),
                            )
                            .0
                            .to_string(),
                    );
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
                        project_opt_out_redaction,
                        priority_class,
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
                // Preemptions are planned + executed in the dedicated global pass BEFORE this
                // per-workload loop (`plan_preemptions`), never emitted by `reconcile_plan_in`,
                // so this arm is unreachable in the main loop. Kept for match exhaustiveness.
                Action::Preempt { handle, .. } => {
                    tracing::debug!(
                        workload = %handle.workload,
                        replica = handle.replica,
                        "compute: unexpected Preempt action in the per-workload loop (ignored; handled in the preemption pass)",
                    );
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
/// 3. the conservative `floor` ([`BinPackTuning::unresolved_reservation`], defaulting to
///    [`UNRESOLVED_RESERVATION`]), with the replica surfaced in the report.
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
    floor: Reservation,
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
    // 3) FAIL-SAFE: neither resolves — charge the conservative floor, never zero, and surface it.
    report.errors.push(format!(
        "{}/{}: bin-packing: cannot resolve reservation (launched spec {} and workload active \
         spec both missing); charging conservative {}MiB/{}vCPU floor to avoid over-subscription",
        state.handle.workload,
        state.handle.replica,
        state.active_spec.as_deref().unwrap_or("<none>"),
        floor.mem_mib,
        floor.vcpus,
    ));
    Ok(floor)
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
    project_opt_out_redaction: bool,
    priority_class: Option<String>,
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
    // Carry this workload's PROJECT redaction opt-out preference (loaded once per workload by
    // the reconcile from the deploy store). Advisory — the backend honors it only under the
    // node-global admission gate (see `RedactionSet::project_opt_out` / `should_redact`).
    redaction.set_project_opt_out(project_opt_out_redaction);
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
            priority_class,
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

    fn blob_bind(name: &str) -> ComputeBinding {
        ComputeBinding::new(BindingKind::Blob).with_name(name)
    }

    #[test]
    fn blob_bind_site_mismatch_warns_only_on_a_blob_bind_with_an_unknown_name() {
        let sites = vec!["mailroom".to_string(), "shop".to_string()];
        // A blob-bound workload NAMED after a site is fine (shares that site's store).
        assert!(!blob_bind_names_unknown_site(
            "mailroom",
            &[blob_bind("")],
            &sites
        ));
        // A blob-bound workload whose name matches NO site is the footgun — warn.
        assert!(blob_bind_names_unknown_site(
            "mail-worker",
            &[blob_bind("inbox")],
            &sites
        ));
        // No blob binding ⇒ never warn, even for an unknown name (sql/kv/messaging don't
        // share this blob-shim site-identity footgun on the blob store).
        let sql = ComputeBinding::new(BindingKind::Sql);
        assert!(!blob_bind_names_unknown_site("mail-worker", &[sql], &sites));
        // Matching is case-sensitive (store keys are) — a case-mismatch is still a "no site".
        assert!(blob_bind_names_unknown_site(
            "Mailroom",
            &[blob_bind("")],
            &sites
        ));
    }

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
        ComputeSpec::builder(RootSource::Rootfs("r".repeat(64)), vcpus, mem_mib, 80)
            .kernel("k".repeat(64))
            .build()
    }

    fn workload(replicas: u32, placement: PlacementConstraints) -> ComputeWorkload {
        ComputeWorkload {
            version: 1,
            name: "w".into(),
            active: "h".into(),
            replicas,
            placement,
            priority: Default::default(),
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
                    // Fully-capable fixture: the volume / scale-to-zero / source /
                    // credential gates only *refuse* on absent capability, so a capable
                    // fixture leaves every existing placement test unaffected; negative
                    // cases build their own restricted `BackendKind`.
                    persistent_volumes: true,
                    scale_to_zero: true,
                    accepted_sources: vec![
                        RootSourceKind::Image,
                        RootSourceKind::Tar,
                        RootSourceKind::Rootfs,
                    ],
                    private_registry_credential: true,
                    // Neutral: no source affinity, so the tie-break is a no-op for the
                    // generic fixtures and existing placement tests keep their behavior.
                    primary_source: None,
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
    fn policy_permits_forbid_allow() {
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
        // `force` is UNWIRED (v0.67.0): it must NOT override `forbid`/`allow`. A policy that
        // forbids `vmm` still forbids it even with `force: vmm` set — the field is inert.
        let force = BackendPolicy {
            force: Some("vmm".into()),
            forbid: vec!["vmm".into()],
            ..Default::default()
        };
        assert!(
            !force.permits("vmm"),
            "force is unwired and does NOT override forbid"
        );
        // And `force` does not act as an implicit allowlist either: with no `allow`, every
        // non-forbidden backend stays permitted regardless of `force`.
        assert!(force.permits("container"));
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
                // Fully source/credential-capable: these negative fixtures exercise the
                // volume / scale-to-zero gates, so leave the source + credential gates
                // open (the source-aware tests build their own restricted `BackendKind`s).
                accepted_sources: vec![
                    RootSourceKind::Image,
                    RootSourceKind::Tar,
                    RootSourceKind::Rootfs,
                ],
                private_registry_credential: true,
                primary_source: None,
            }],
        }
    }

    #[test]
    fn volume_spec_needs_a_volume_capable_backend() {
        let mut s = spec(1, 128);
        s.volumes = vec![VolumeRef::new("/data", "db", 64)];
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
    fn policy_force_is_unwired_and_does_not_override_preference() {
        // v0.67.0: `force` is UNWIRED. A policy `force: vmm` must NOT override anything — the
        // spec's tenant `prefer_backend` is honored exactly as if `force` were unset. (The
        // historical "force vmm" intent is now `allow: ["vmm"]`.)
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
        let placed = place_replicas(
            1,
            &PlacementConstraints::default(),
            &s,
            std::slice::from_ref(&n),
            &policy,
        );
        assert_eq!(
            placed[0].backend, "container",
            "force is inert, so the spec preference still wins"
        );
        // And the historical intent — "only vmm" — is expressed with `allow`, which DOES bind.
        let allow_vmm = BackendPolicy {
            allow: Some(vec!["vmm".into()]),
            ..Default::default()
        };
        let placed = place_replicas(1, &PlacementConstraints::default(), &s, &[n], &allow_vmm);
        assert_eq!(
            placed[0].backend, "vmm",
            "allow:[vmm] (the force replacement) confines selection to vmm"
        );
    }

    /// A realistic native `container` backend (as `build_compute` advertises it): accepts
    /// a public `Image` (its `stage_image`/`oci::build_rootfs_dir` path) AND a `Tar`, is
    /// NOT private-registry-credential-capable (its `materialize` fails closed on a
    /// private image + credential), and is Tar-primary. Sorts FIRST — the real
    /// `"container" < "docker"` BTreeMap order that surfaced the v0.66.1 bug.
    fn container_backendkind() -> BackendKind {
        BackendKind {
            id: "container".into(),
            isolation: IsolationClass::Namespace,
            persistent_volumes: true,
            scale_to_zero: true,
            accepted_sources: vec![RootSourceKind::Image, RootSourceKind::Tar],
            private_registry_credential: false,
            primary_source: Some(RootSourceKind::Tar),
        }
    }

    /// A realistic `docker` backend: image-only, credential-capable, image-primary.
    fn docker_backendkind() -> BackendKind {
        BackendKind {
            id: "docker".into(),
            isolation: IsolationClass::Container,
            persistent_volumes: true,
            scale_to_zero: false,
            accepted_sources: vec![RootSourceKind::Image],
            private_registry_credential: true,
            primary_source: Some(RootSourceKind::Image),
        }
    }

    fn node_with_backends(backends: Vec<BackendKind>) -> Node {
        Node {
            id: 1,
            region: Some("eu".into()),
            labels: BTreeMap::new(),
            free_vcpus: 8,
            free_mem_mib: 8192,
            backends,
        }
    }

    /// Regression (v0.66.1 prod-down): an `image()` + `pull_secret` workload must NEVER
    /// land on the native `container` backend, which cannot apply a registry credential
    /// (`boatramp-container` backend.rs: "the native container backend cannot apply a
    /// registry credential; run this private-image workload on the `docker` backend") and
    /// crash-loops. v0.66.1 made the native `container` backend available, and backends
    /// iterate in sorted-id order (`container` < `docker`) — so a prior `pick_backend`
    /// that gated only on isolation/volumes/scale-to-zero picked `container` (first) for a
    /// trusted image+secret workload. The credential gate steers a PRIVATE image to the
    /// credential-capable backend (or fails closed when none is present), and the
    /// source-affinity tie-break steers a PUBLIC image to the image-native backend on a
    /// dual node — WITHOUT excluding `container`, so a container-only node still places a
    /// public image (the Security-review stranding fix: on fly.io the native container
    /// backend is the sole backend and managed DBs are public images).
    ///
    /// Mutation reasoning: drop the `private_registry_credential` clause and the
    /// CONTAINER-ONLY private-image assertion flips from `None` to `Some("container")` —
    /// exactly the crash-loop shape — so the test fails (the credential clause has teeth,
    /// and the tie-break does NOT mask it: a container-only node has no credential-capable
    /// alternative to prefer). Drop the `accepted_sources` clause and the `Rootfs`
    /// fail-closed assertion flips from `None` to `Some("container")` (an unsupported
    /// source would be placed), so the test fails. Both clauses are load-bearing.
    #[test]
    fn image_workload_never_picks_credential_incapable_native_container() {
        // Dual node: native `container` (sorts first) + `docker`.
        let dual = node_with_backends(vec![container_backendkind(), docker_backendkind()]);

        // (1) A PRIVATE image (names a `pull_secret`), trusted, no explicit preference —
        // the crash-looping shape. Despite `container` sorting first and satisfying the
        // trusted isolation requirement, it MUST land on the credential-capable `docker`.
        let mut private_image = spec(1, 128);
        private_image.root = RootSource::Image("registry.example.com/acme/private:1".into());
        private_image.pull_secret = Some("acme-pull".into());
        assert_eq!(private_image.isolation, IsolationRequirement::Trusted);
        assert_eq!(private_image.prefer_backend, None);
        assert_eq!(
            dual.pick_backend(&private_image, &BackendPolicy::default())
                .as_deref(),
            Some("docker"),
            "a private image+pull_secret workload must go to the credential-capable \
             docker backend, NEVER the native container backend (which crash-loops)"
        );

        // (2) A PUBLIC image (no pull_secret) on the dual node picks `docker` via the
        // source-affinity TIE-BREAK (docker is image-primary), not the first-sorted
        // `container` — which IS eligible (it accepts a public image) but is Tar-primary.
        // This is an ordering preference, not an exclusion (see assertion 4).
        let mut public_image = spec(1, 128);
        public_image.root = RootSource::Image("docker.io/library/nginx:1".into());
        assert_eq!(public_image.pull_secret, None);
        assert_eq!(
            dual.pick_backend(&public_image, &BackendPolicy::default())
                .as_deref(),
            Some("docker"),
            "a public image prefers the image-native docker backend on a dual node"
        );

        // (3) A tar source still picks the native container backend (the only tar-capable
        // backend here) — the normal `--tar` derivation is not regressed.
        let mut tar = spec(1, 128);
        tar.root = RootSource::Tar("t".repeat(64));
        assert_eq!(
            dual.pick_backend(&tar, &BackendPolicy::default())
                .as_deref(),
            Some("container"),
            "a tar source still picks the native container backend"
        );

        // (4) Container-ONLY node (fly.io: daemonless + kvmless). A PUBLIC image MUST
        // still place on `container` — the stranding fix. The tie-break finds no
        // image-primary backend eligible, so it falls back to the (only) eligible
        // `container`; the source clause keeps `container` eligible for an image.
        let container_only = node_with_backends(vec![container_backendkind()]);
        assert_eq!(
            container_only
                .pick_backend(&public_image, &BackendPolicy::default())
                .as_deref(),
            Some("container"),
            "a public image on a container-only node must place on container \
             (co-located managed DBs on fly.io are public images) — never stranded"
        );

        // (5) Container-ONLY node + a PRIVATE image: no credential-capable backend exists,
        // so the credential clause fails closed (no placement) rather than crash-looping
        // on `container`. THIS is where the credential clause has mutation teeth — drop it
        // and this flips to `Some("container")`.
        assert_eq!(
            container_only
                .pick_backend(&private_image, &BackendPolicy::default())
                .as_deref(),
            None,
            "a private image on a credential-incapable-only node fails closed (no \
             placement), never lands on the native container backend"
        );

        // (6) A `Rootfs` source on an image/tar-only node has no accepting backend →
        // fail closed. This gives the `accepted_sources` clause mutation teeth (drop it
        // and the tie-break fallback would place it on `container`).
        let mut rootfs = spec(1, 128);
        rootfs.root = RootSource::Rootfs("r".repeat(64));
        assert_eq!(
            dual.pick_backend(&rootfs, &BackendPolicy::default())
                .as_deref(),
            None,
            "a rootfs source has no accepting backend on an image/tar-only node → no \
             placement (never the native container backend)"
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
                preemptible: true,
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
        // With an EMPTY node inventory the v0.67.0 placement-explain names the precise
        // shortfall — no backend advertised at all — rather than the old generic
        // "no eligible backend with capacity".
        assert!(
            u.reason
                .contains("no compute backend advertised on any node"),
            "names the precise shortfall: {}",
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
                preemptible: true,
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
                priority_class: None,
            })
            .await
            .unwrap();
        assert_eq!(inst.endpoint.url(), "http://127.0.0.1:8080");
        assert_eq!(backend.health(&inst.handle).await.unwrap(), Health::Healthy);
        backend.stop(&inst.handle).await.unwrap();
        // Default snapshot/restore: unsupported.
        assert!(backend.snapshot(&inst.handle).await.unwrap().is_none());
    }

    /// A backend that records the `LaunchRequest.redaction` set (its values + the carried
    /// per-project opt-out flag) + the final `spec.env` it was handed, so a test can assert
    /// what `launch_one` collected for redaction.
    #[derive(Clone, Default)]
    struct RedactionCaptureBackend {
        redaction: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        opt_out: std::sync::Arc<std::sync::Mutex<bool>>,
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
                preemptible: true,
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
            *self.opt_out.lock().unwrap() = req.redaction.project_opt_out();
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
            &backend, "default", "w", 0, 1, None, &s, "spec-a", &extra_env, None, None, false,
            None,
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
        // This launch passed `project_opt_out = false`, so the carried flag is false.
        assert!(
            !*backend.opt_out.lock().unwrap(),
            "no per-project opt-out was requested for this launch"
        );
    }

    /// `launch_one` carries the per-project redaction OPT-OUT preference onto the
    /// `LaunchRequest.redaction` so a backend can compose the two-tier decision. Plumbing
    /// test: the reconcile loads the per-project setting once and passes it here; this binds
    /// that it reaches the request (not dropped), while the admission GATE itself lives in the
    /// backend's `should_redact` (unit-tested in `boatramp-guestlog`). Mutation-sensitive: if
    /// `launch_one` ignores the argument the carried flag stays false and this goes RED.
    #[tokio::test]
    async fn launch_one_carries_the_project_redaction_opt_out() {
        let backend = RedactionCaptureBackend::default();
        let mut s = spec(1, 128);
        s.env.insert("DB_URL".into(), "{{sql.dsn}}".into());
        let dsn = "postgres://app:S3cr3t@bramp-db-abc.flycast:5432/app".to_string();
        let extra_env = vec![("DB_URL".to_string(), dsn.clone())];

        // opt_out = true is carried onto the request...
        let _ = launch_one(
            &backend, "default", "w", 0, 1, None, &s, "spec-a", &extra_env, None, None, true, None,
        )
        .await
        .expect("launch");
        assert!(
            *backend.opt_out.lock().unwrap(),
            "the per-project opt-out preference must reach the LaunchRequest"
        );
        // ...and the secret value is STILL collected regardless (the backend, not launch_one,
        // decides whether to honor the opt-out — core always hands over the provenance set).
        assert!(
            backend.redaction.lock().unwrap().contains(&dsn),
            "core always collects the secret-sourced value; the opt-out is a backend decision"
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
                preemptible: true,
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
            false,
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
            false,
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
            priority: Default::default(),
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
                accepted_sources: vec![
                    RootSourceKind::Image,
                    RootSourceKind::Tar,
                    RootSourceKind::Rootfs,
                ],
                private_registry_credential: true,
                primary_source: None,
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
                preemptible: true,
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
                    priority: Default::default(),
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
            BinPackTuning::default(),
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
            BinPackTuning::default(),
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
            BinPackTuning::default(),
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
            BinPackTuning::default(),
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
                preemptible: true,
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
                    priority: Default::default(),
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
            BinPackTuning::default(),
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
            BinPackTuning::default(),
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
                preemptible: true,
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
                    priority: Default::default(),
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
            BinPackTuning::default(),
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
            BinPackTuning::default(),
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
                    priority: Default::default(),
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
            BinPackTuning::default(),
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
            BinPackTuning::default(),
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
                    priority: Default::default(),
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
            BinPackTuning::default(),
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
                    priority: Default::default(),
                },
            )
            .await
            .unwrap();
        hash
    }

    /// RUNTIME-PATH authority split (v0.67.0): a PER-PROJECT operator policy that forbids the
    /// only backend must leave the workload UNSCHEDULED through the real `reconcile_once` loop
    /// — not merely in the pure planner — AND the persisted placement-explain must attribute
    /// the exclusion to the project scope with `chosen: None`. Proves the per-project policy is
    /// actually loaded, composed, and enforced on execute, and that a tenant could not escape
    /// it (there is no second code path).
    #[tokio::test]
    async fn per_project_forbid_blocks_placement_at_runtime_and_is_legible() {
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(crate::kv::MemoryKv::new()));
        put_workload(&deploy, "w", 256, 1).await;
        // The per-project operator policy forbids the only backend the node offers ("fake").
        deploy
            .set_project_backend_policy(
                crate::project::ProjectRef::DEFAULT,
                &ProjectBackendPolicy {
                    allow: None,
                    forbid: vec!["fake".into()],
                    prefer: None,
                    priority_ceiling: None,
                },
            )
            .await
            .unwrap();
        let nodes = vec![fake_node()];
        let mut backends: BackendRegistry = BTreeMap::new();
        backends.insert("fake".into(), Arc::new(FakeBackend));
        // The NODE policy permits everything; the exclusion comes purely from the project.
        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &BackendPolicy::default(),
            &AlwaysActive,
            None,
            None,
            None,
            BinPackTuning::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            r.launched, 0,
            "a project-forbidden backend places nothing: {:?}",
            r.errors
        );
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("not scheduled") && e.contains("forbidden by operator policy")),
            "the no-placement reason is surfaced + legible: {:?}",
            r.errors
        );
        // The persisted placement-explain attributes the exclusion to the PROJECT scope.
        let ex = deploy
            .get_placement_explain(crate::project::ProjectRef::DEFAULT, "w")
            .await
            .unwrap()
            .expect("placement-explain persisted");
        assert_eq!(ex.chosen, None);
        assert_eq!(
            ex.candidates
                .iter()
                .find(|c| c.backend == "fake")
                .unwrap()
                .eligibility,
            BackendEligibility::ForbiddenByProjectPolicy,
        );
    }

    /// A [`KvStore`](crate::kv::KvStore) wrapper that returns a store `Err` from `get` for any
    /// key containing a substring, delegating everything else to an inner store — to exercise
    /// a TRANSIENT per-project-policy read fault in the reconcile loop.
    struct FailGetOnKey {
        inner: Arc<dyn crate::kv::KvStore>,
        needle: String,
    }

    #[async_trait]
    impl crate::kv::KvStore for FailGetOnKey {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, crate::error::KvError> {
            if key.contains(&self.needle) {
                return Err(crate::error::KvError::backend(
                    "injected transient read fault",
                ));
            }
            self.inner.get(key).await
        }
        async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), crate::error::KvError> {
            self.inner.put(key, value).await
        }
        async fn delete(&self, key: &str) -> Result<(), crate::error::KvError> {
            self.inner.delete(key).await
        }
        async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, crate::error::KvError> {
            self.inner.list_prefix(prefix).await
        }
    }

    /// MUST-FIX (v0.67.0 Security review): a per-project-policy read ERROR must FAIL CLOSED —
    /// HOLD new placement for the workload, NOT silently drop the project `forbid`/`allow` and
    /// place under the node bound alone (fail-open). The operator has forbidden "fake" (the
    /// only backend the node offers); a transient read fault must not let the workload land on
    /// it, and must not Stop any existing replica.
    ///
    /// Mutation reasoning: reverting the fix to `get_project_backend_policy(..).await.ok()
    /// .flatten().unwrap_or_default()` collapses the `Err` into the empty policy ⇒ the node
    /// bound (which permits "fake") applies ⇒ the free ordinal is LAUNCHED on the forbidden
    /// backend ⇒ `r.launched == 0` flips to `1` and the "placement held" reason disappears, so
    /// this test fails.
    #[tokio::test]
    async fn per_project_policy_read_error_holds_placement_fail_closed() {
        let inner: Arc<dyn crate::kv::KvStore> = Arc::new(crate::kv::MemoryKv::new());
        let kv: Arc<dyn crate::kv::KvStore> = Arc::new(FailGetOnKey {
            inner: inner.clone(),
            needle: "backend_policy".into(),
        });
        let deploy = DeployStore::new(Arc::new(NullStorage), kv);
        // The operator HAS forbidden "fake" (stored fine — the fault is on GET only). Two
        // replicas desired; ordinal 0 is already running, ordinal 1 is a free placement.
        deploy
            .set_project_backend_policy(
                crate::project::ProjectRef::DEFAULT,
                &ProjectBackendPolicy {
                    allow: None,
                    forbid: vec!["fake".into()],
                    prefer: None,
                    priority_ceiling: None,
                },
            )
            .await
            .unwrap();
        let hash = put_workload(&deploy, "w", 256, 2).await;
        let mut running = observed("w", 0, 1, true);
        running.backend = "fake".into();
        running.active_spec = Some(hash);
        deploy
            .set_replica_state(crate::project::ProjectRef::DEFAULT, &running)
            .await
            .unwrap();

        let nodes = vec![fake_node()];
        let mut backends: BackendRegistry = BTreeMap::new();
        backends.insert("fake".into(), Arc::new(FakeBackend));
        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &BackendPolicy::default(), // node bound permits "fake" — the exclusion is per-project
            &AlwaysActive,
            None,
            None,
            None,
            BinPackTuning::default(),
        )
        .await
        .unwrap();

        // HELD: no new placement (the free ordinal is NOT launched on the forbidden backend)…
        assert_eq!(
            r.launched, 0,
            "a policy read error must HOLD, never place on the node-allowed-but-project-forbidden backend: {:?}",
            r.errors
        );
        // …and no existing replica is stopped/scaled down (plan not computed at all).
        assert_eq!(
            r.stopped, 0,
            "existing replicas must keep running during the read blip"
        );
        // Legible held reason surfaced via the same `not scheduled:` path.
        assert!(
            r.errors.iter().any(|e| e.contains("placement held")),
            "the held reason must be legible: {:?}",
            r.errors
        );
        // The existing replica's state is untouched.
        assert!(
            !deploy
                .list_replica_states(crate::project::ProjectRef::DEFAULT, "w")
                .await
                .unwrap()
                .is_empty(),
            "the existing replica record survives the held pass"
        );
    }

    /// Cumulative bin-packing: two workloads that EACH fit the node alone but NOT together
    /// must not over-subscribe it. The node advertises 8192 MiB; each workload's single
    /// replica wants 5000 MiB (fits alone; 10000 together does not). The old scheduler sized
    /// every workload against the node's FULL advertised capacity afresh, so both launched
    /// and over-packed the node. With the shared pre-debited ledger, the first (by the
    /// deterministic (project, name) order) places and the second is left UNSCHEDULED.
    ///
    /// COMPOSITION with the launch/placement observability fix (v0.64.2): the ledger decides
    /// beta is *not placeable*, and that rejection is SURFACED through
    /// [`ReconcilePlan::unscheduled`] as a "not scheduled: no eligible backend with capacity"
    /// entry in `report.errors` (not silently dropped). The two are complementary — the ledger
    /// says *not placeable*, the observability says *why* — so this asserts beta is both
    /// unscheduled AND reported with the capacity reason.
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
            BinPackTuning::default(),
        )
        .await
        .unwrap();

        // Exactly ONE replica launched — not two (that would be the over-subscription bug).
        assert_eq!(
            r.launched, 1,
            "only the first workload fits; {:?}",
            r.errors
        );
        // COMPOSITION (b): the ledger's rejection of beta is SURFACED — not silently dropped —
        // as a single "not scheduled: no eligible backend with capacity" entry naming the
        // over-subscribed replica and its resource need. Exactly one such entry (beta/0), and
        // nothing else.
        assert_eq!(
            r.errors.len(),
            1,
            "the only error is beta's surfaced capacity shortfall: {:?}",
            r.errors
        );
        assert!(
            r.errors[0].starts_with("beta/0: not scheduled: no eligible backend with capacity"),
            "the ledger rejection is surfaced with the capacity reason: {:?}",
            r.errors
        );
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
                BinPackTuning::default(),
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
                    priority: Default::default(),
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
                    priority: Default::default(),
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
            BinPackTuning::default(),
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
            BinPackTuning::default(),
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

    /// COMPOSITION (cumulative bin-packing × launch-observability): a durable `LaunchFailed`
    /// marker is recorded `Running` (so `compute status` shows its reason) but represents a
    /// launch that NEVER produced a live instance — it holds NO real node capacity. The
    /// bin-packing pre-pass must therefore NOT charge it. If it did, the marker would both
    /// phantom-occupy the node AND be double-counted, because `reconcile_plan_in` relaunches
    /// the failed ordinal the SAME pass (debiting the ledger again); on a tight node the retry
    /// would then be left `unscheduled` — masking the real launch-failure reason behind a
    /// spurious "no capacity". Here `w`'s only replica is a 5000-MiB `LaunchFailed` marker on an
    /// 8192-MiB node: were the marker charged (5000 ⇒ 3192 free), the 5000-MiB retry would not
    /// fit and land unscheduled; skipping it leaves the full 8192 free so the retry is placed and
    /// (with a succeeding backend) relaunches, clearing the marker. Removing the pre-pass skip
    /// turns this RED (launched: 0, a "not scheduled" error).
    #[tokio::test]
    async fn launch_failed_marker_is_not_charged_in_the_binpack_prepass() {
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(crate::kv::MemoryKv::new()));
        let hash = deploy.put_compute_spec(&spec(1, 5000)).await.unwrap();
        deploy
            .set_compute_workload(
                crate::project::ProjectRef::DEFAULT,
                &ComputeWorkload {
                    version: 1,
                    name: "w".into(),
                    active: hash.clone(),
                    replicas: 1,
                    placement: Default::default(),
                    priority: Default::default(),
                },
            )
            .await
            .unwrap();
        // Pre-seed replica 0 as a durable LaunchFailed marker: phase `Running` (a diagnostic
        // phase), unhealthy, no live instance — exactly what the launch-error arm persists.
        let mut marker = observed("w", 0, 1, false);
        marker.backend = "fake".into();
        marker.active_spec = Some(hash);
        marker.readiness = Readiness::LaunchFailed {
            reason: "image pull denied for ghcr.io/acme/app:1".into(),
        };
        deploy
            .set_replica_state(crate::project::ProjectRef::DEFAULT, &marker)
            .await
            .unwrap();

        let nodes = vec![fake_node()]; // 8 vCPU / 8192 MiB
        let mut backends: BackendRegistry = BTreeMap::new();
        // A succeeding backend: the retry relaunches cleanly, so the marker is cleared — crisp
        // proof the pre-pass left the node's full capacity for the failed ordinal's retry.
        backends.insert("fake".into(), Arc::new(FakeBackend));
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
            BinPackTuning::default(),
        )
        .await
        .unwrap();

        // The failed ordinal was RE-launched (not phantom-blocked): exactly one launch, and
        // crucially NOT reported as a capacity shortfall.
        assert_eq!(
            r.launched, 1,
            "the LaunchFailed ordinal retries on the freed (never-charged) capacity: {:?}",
            r.errors
        );
        assert!(
            !r.errors.iter().any(|e| e.contains("not scheduled")),
            "a LaunchFailed marker must not phantom-occupy the node and block its own retry: {:?}",
            r.errors
        );
        // The marker is cleared by the successful relaunch — one fresh (non-failed) record.
        let states = deploy
            .list_replica_states(crate::project::ProjectRef::DEFAULT, "w")
            .await
            .unwrap();
        assert_eq!(states.len(), 1, "still exactly one record for the ordinal");
        assert!(
            !matches!(states[0].readiness, Readiness::LaunchFailed { .. }),
            "the successful retry overwrote the LaunchFailed marker: {:?}",
            states[0].readiness
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
                    priority: Default::default(),
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
            BinPackTuning::default(),
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
                    priority: Default::default(),
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
            BinPackTuning::default(),
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
            BinPackTuning::default(),
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
                preemptible: true,
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
                    priority: Default::default(),
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
            BinPackTuning::default(),
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

    // =====================================================================
    // v0.67.0 backend-selection POLICY (PLAN-backend-policy-dx)
    // =====================================================================

    /// A fully-capable node advertising vmm (strong), container (weak), docker (weak) —
    /// all accept every source kind (the `node()` fixture), so eligibility differences in
    /// these tests come from POLICY, not capability.
    fn tri_node() -> Node {
        node(
            1,
            "eu",
            8,
            8192,
            &[
                ("vmm", IsolationClass::VmKvm),
                ("container", IsolationClass::Namespace),
                ("docker", IsolationClass::Container),
            ],
        )
    }

    fn proj(allow: Option<&[&str]>, forbid: &[&str], prefer: Option<&str>) -> ProjectBackendPolicy {
        ProjectBackendPolicy {
            allow: allow.map(|a| a.iter().map(|s| (*s).to_string()).collect()),
            forbid: forbid.iter().map(|s| (*s).to_string()).collect(),
            prefer: prefer.map(str::to_string),
            priority_ceiling: None,
        }
    }

    /// BACK-COMPAT: no policy = today's behavior (every capable backend eligible). The
    /// deterministic last resort is sorted-id order, so the lowest id wins absent any
    /// preference.
    #[test]
    fn no_policy_is_backcompat_all_capable() {
        let n = tri_node();
        let s = spec(1, 128);
        assert_eq!(
            n.pick_backend(&s, &BackendPolicy::default()).as_deref(),
            Some("container"),
            "no policy ⇒ all capable; sorted-id last resort picks the lowest id"
        );
    }

    /// Node-scope operator `prefer` steers selection among eligible backends; a `prefer`
    /// naming an INELIGIBLE backend is ignored (never widens the set).
    #[test]
    fn node_prefer_is_honored_among_eligible_only() {
        let n = tri_node();
        let s = spec(1, 128);
        let prefer_vmm = BackendPolicy {
            prefer: Some("vmm".into()),
            ..Default::default()
        };
        assert_eq!(n.pick_backend(&s, &prefer_vmm).as_deref(), Some("vmm"));
        // Prefer a FORBIDDEN backend: the forbid (hard) wins, prefer is ignored, fall back.
        let prefer_forbidden = BackendPolicy {
            prefer: Some("vmm".into()),
            forbid: vec!["vmm".into()],
            ..Default::default()
        };
        assert_eq!(
            n.pick_backend(&s, &prefer_forbidden).as_deref(),
            Some("container"),
            "a prefer of a forbidden backend is ignored; it never re-admits it"
        );
    }

    /// `compose_project`: INTERSECTION of allows, UNION of forbids, per-project `prefer`
    /// overrides node `prefer`, and the node posture (`require_strong_isolation`) is kept.
    #[test]
    fn compose_project_intersects_allow_unions_forbid_overrides_prefer() {
        let node_policy = BackendPolicy {
            allow: Some(vec!["vmm".into(), "container".into()]),
            forbid: vec!["docker".into()],
            prefer: Some("vmm".into()),
            require_strong_isolation: true,
            ..Default::default()
        };
        let project = proj(Some(&["container", "docker"]), &["vmm"], Some("container"));
        let c = node_policy.compose_project(&project);
        // allow = {vmm,container} ∩ {container,docker} = {container}
        assert_eq!(c.allow, Some(vec!["container".to_string()]));
        // forbid = {docker} ∪ {vmm} = {docker,vmm}
        assert!(c.forbid.contains(&"docker".to_string()) && c.forbid.contains(&"vmm".to_string()));
        // prefer: project wins
        assert_eq!(c.prefer.as_deref(), Some("container"));
        // posture kept (a project policy can never relax it — it carries no such field)
        assert!(c.require_strong_isolation);
        // A missing allowlist on either side defers to the other.
        let only_node = BackendPolicy {
            allow: Some(vec!["vmm".into()]),
            ..Default::default()
        };
        assert_eq!(
            only_node
                .compose_project(&ProjectBackendPolicy::default())
                .allow,
            Some(vec!["vmm".to_string()])
        );
        assert_eq!(
            BackendPolicy::default()
                .compose_project(&proj(Some(&["docker"]), &[], None))
                .allow,
            Some(vec!["docker".to_string()])
        );
    }

    /// Precedence: tenant spec `prefer_backend` beats the operator `prefer`, which beats the
    /// node `prefer` (project overrides node, resolved in `compose_project`).
    #[test]
    fn prefer_precedence_tenant_over_project_over_node() {
        let n = tri_node();
        let node_policy = BackendPolicy {
            prefer: Some("vmm".into()),
            ..Default::default()
        };
        // project prefer overrides node prefer.
        let composed = node_policy.compose_project(&proj(None, &[], Some("container")));
        let s = spec(1, 128);
        assert_eq!(
            n.pick_backend(&s, &composed).as_deref(),
            Some("container"),
            "per-project prefer overrides the node prefer"
        );
        // tenant spec prefer overrides BOTH.
        let mut s_tenant = spec(1, 128);
        s_tenant.prefer_backend = Some("docker".into());
        assert_eq!(
            n.pick_backend(&s_tenant, &composed).as_deref(),
            Some("docker"),
            "tenant prefer overrides the operator prefer"
        );
    }

    /// Tenant HARD `require`: picks exactly that backend when eligible, else NO placement
    /// (never falls back elsewhere — distinct from `prefer`).
    #[test]
    fn tenant_require_picks_exactly_or_no_placement() {
        let n = tri_node();
        let mut s = spec(1, 128);
        s.require_backend = Some("vmm".into());
        assert_eq!(
            n.pick_backend(&s, &BackendPolicy::default()).as_deref(),
            Some("vmm"),
            "require picks exactly the named eligible backend"
        );
        // Require a backend that is not advertised ⇒ no placement, NOT a fallback.
        let mut s_absent = spec(1, 128);
        s_absent.require_backend = Some("nonesuch".into());
        assert_eq!(
            n.pick_backend(&s_absent, &BackendPolicy::default()),
            None,
            "require of an absent backend fails closed (no placement)"
        );
    }

    /// AUTHORITY SPLIT: a tenant `require` of an operator-FORBIDDEN backend must yield a
    /// legible no-placement — NEVER an escape onto the forbidden backend.
    #[test]
    fn tenant_require_cannot_escape_operator_forbid() {
        let n = tri_node();
        let mut s = spec(1, 128);
        s.require_backend = Some("vmm".into());
        let policy = BackendPolicy {
            forbid: vec!["vmm".into()],
            ..Default::default()
        };
        assert_eq!(
            n.pick_backend(&s, &policy),
            None,
            "require of an operator-forbidden backend is NO placement, never an escape"
        );
        // And via per-project forbid composed with the node bound (operator-first).
        let composed = BackendPolicy::default().compose_project(&proj(None, &["vmm"], None));
        assert_eq!(
            n.pick_backend(&s, &composed),
            None,
            "a per-project forbid is enforced against a tenant require just the same"
        );
    }

    /// AUTHORITY SPLIT: a tenant `prefer` of an operator-forbidden backend is ignored and
    /// falls back WITHIN the operator-permitted set — never onto the forbidden backend.
    #[test]
    fn tenant_prefer_cannot_escape_operator_forbid() {
        let n = tri_node();
        let mut s = spec(1, 128);
        s.prefer_backend = Some("vmm".into());
        let policy = BackendPolicy {
            forbid: vec!["vmm".into()],
            ..Default::default()
        };
        let picked = n.pick_backend(&s, &policy);
        assert!(
            picked.as_deref() != Some("vmm") && picked.is_some(),
            "tenant prefer of a forbidden backend falls back within the allowed set: {picked:?}"
        );
    }

    /// AUTHORITY SPLIT: a tenant `require` of an ISOLATION-INSUFFICIENT backend under the
    /// strict posture is no-placement, not a climb out of the posture.
    #[test]
    fn tenant_require_cannot_escape_isolation_posture() {
        let n = tri_node();
        let strict = BackendPolicy::from_shared_kernel_allowed(false); // require strong isolation
        // Require the shared-kernel `container` (Namespace, weak) under the strict posture.
        let mut weak = spec(1, 128);
        weak.require_backend = Some("container".into());
        assert_eq!(
            n.pick_backend(&weak, &strict),
            None,
            "require of a shared-kernel backend under the strict posture is refused, not an escape"
        );
        // Require the strong `vmm` under the same posture: permitted.
        let mut strong = spec(1, 128);
        strong.require_backend = Some("vmm".into());
        assert_eq!(
            n.pick_backend(&strong, &strict).as_deref(),
            Some("vmm"),
            "require of a strong-isolation backend is honored within the posture"
        );
    }

    /// node ∩ per-project composition at the PLACEMENT layer: a backend must pass BOTH the
    /// node allow and the project allow (intersection), and either scope's forbid excludes it
    /// (union).
    #[test]
    fn node_intersect_project_composition_at_placement() {
        let n = tri_node();
        let s = spec(1, 128);
        // Node allows {vmm,container}; project allows {container,docker} ⇒ only container.
        let node_policy = BackendPolicy {
            allow: Some(vec!["vmm".into(), "container".into()]),
            ..Default::default()
        };
        let composed =
            node_policy.compose_project(&proj(Some(&["container", "docker"]), &[], None));
        assert_eq!(
            n.pick_backend(&s, &composed).as_deref(),
            Some("container"),
            "intersection of allows leaves only container eligible"
        );
        // Union forbid: node forbids vmm, project forbids container ⇒ only docker left.
        let node_forbid = BackendPolicy {
            forbid: vec!["vmm".into()],
            ..Default::default()
        };
        let composed2 = node_forbid.compose_project(&proj(None, &["container"], None));
        assert_eq!(
            n.pick_backend(&s, &composed2).as_deref(),
            Some("docker"),
            "union of forbids leaves only docker eligible"
        );
    }

    /// `explain_placement` attributes forbids to the right SCOPE (node vs project), reports
    /// the per-candidate hard gate, and marks exactly the chosen backend selected.
    #[test]
    fn explain_placement_attributes_scope_and_marks_chosen() {
        let nodes = vec![tri_node()];
        let s = spec(1, 128);
        let node_policy = BackendPolicy {
            forbid: vec!["vmm".into()],
            ..Default::default()
        };
        let project = proj(None, &["container"], None);
        let ex = explain_placement(&nodes, &s, &node_policy, &project);
        let verdict = |id: &str| {
            ex.candidates
                .iter()
                .find(|c| c.backend == id)
                .map(|c| c.eligibility)
                .unwrap()
        };
        assert_eq!(verdict("vmm"), BackendEligibility::ForbiddenByNodePolicy);
        assert_eq!(
            verdict("container"),
            BackendEligibility::ForbiddenByProjectPolicy
        );
        assert_eq!(verdict("docker"), BackendEligibility::Eligible);
        assert_eq!(ex.chosen.as_deref(), Some("docker"));
        assert!(
            ex.candidates
                .iter()
                .find(|c| c.backend == "docker")
                .unwrap()
                .selected,
            "the chosen backend is marked selected"
        );
        assert!(
            ex.candidates.iter().filter(|c| c.selected).count() == 1,
            "exactly one candidate is selected when any is eligible"
        );
    }

    /// `explain_placement` surfaces the capability-floor reasons (source / credential /
    /// isolation), not just policy.
    #[test]
    fn explain_placement_surfaces_capability_reasons() {
        // container (no credential, Image+Tar) + docker (credential, Image).
        let nodes = vec![node_with_backends(vec![
            container_backendkind(),
            docker_backendkind(),
        ])];
        // A PRIVATE image: container lacks credential, docker has it.
        let mut private_image = spec(1, 128);
        private_image.root = RootSource::Image("r/acme/private:1".into());
        private_image.pull_secret = Some("acme".into());
        private_image.isolation = IsolationRequirement::Trusted;
        let ex = explain_placement(
            &nodes,
            &private_image,
            &BackendPolicy::default(),
            &ProjectBackendPolicy::default(),
        );
        let verdict = |id: &str| {
            ex.candidates
                .iter()
                .find(|c| c.backend == id)
                .map(|c| c.eligibility)
                .unwrap()
        };
        assert_eq!(verdict("container"), BackendEligibility::NoCredential);
        assert_eq!(verdict("docker"), BackendEligibility::Eligible);
        assert_eq!(ex.chosen.as_deref(), Some("docker"));

        // Isolation: a rootfs spec under the strict posture on a weak-only node.
        let weak_nodes = vec![node(
            1,
            "eu",
            8,
            8192,
            &[("container", IsolationClass::Namespace)],
        )];
        let strict = BackendPolicy::from_shared_kernel_allowed(false);
        let ex2 = explain_placement(
            &weak_nodes,
            &spec(1, 128),
            &strict,
            &ProjectBackendPolicy::default(),
        );
        assert_eq!(
            ex2.candidates[0].eligibility,
            BackendEligibility::IsolationInsufficient
        );
        assert_eq!(ex2.chosen, None, "no eligible backend ⇒ no chosen");
    }

    /// The no-placement REASON names WHY (policy / isolation / required-backend), extending
    /// the v0.64.2 observability — the legibility the incident needed.
    #[test]
    fn no_placement_reason_is_legible() {
        let w = workload(1, PlacementConstraints::default());
        let s = spec(1, 128);
        let plan_reason = |policy: &BackendPolicy, nodes: &[Node], spec: &ComputeSpec| {
            let plan = reconcile_plan(
                &w,
                spec,
                nodes,
                policy,
                &[],
                WorkloadActivity::Active,
                &BTreeMap::new(),
                0,
                &BTreeSet::new(),
            );
            plan.unscheduled.first().map(|u| u.reason.clone())
        };
        // All backends forbidden ⇒ "forbidden by operator policy".
        let forbid_all = BackendPolicy {
            forbid: vec!["vmm".into(), "container".into(), "docker".into()],
            ..Default::default()
        };
        let r = plan_reason(&forbid_all, &[tri_node()], &s).unwrap();
        assert!(
            r.contains("forbidden by operator policy"),
            "policy reason surfaced: {r}"
        );
        // Strict posture + a weak-only node ⇒ "isolation insufficient".
        let strict = BackendPolicy::from_shared_kernel_allowed(false);
        let weak = node(
            1,
            "eu",
            8,
            8192,
            &[("container", IsolationClass::Namespace)],
        );
        let r = plan_reason(&strict, &[weak], &s).unwrap();
        assert!(
            r.contains("isolation insufficient"),
            "isolation reason: {r}"
        );
        // A tenant require of an uneligible (forbidden) backend ⇒ names the required backend.
        let mut req = spec(1, 128);
        req.require_backend = Some("vmm".into());
        let r = plan_reason(
            &BackendPolicy {
                forbid: vec!["vmm".into()],
                ..Default::default()
            },
            &[tri_node()],
            &req,
        )
        .unwrap();
        assert!(
            r.contains("required backend `vmm` is not eligible"),
            "required-backend reason: {r}"
        );
    }

    /// A counting [`KvStore`](crate::kv::KvStore) wrapper: delegates every operation to an inner
    /// store but tallies the two reads `reconcile_once` must issue exactly ONCE per workload per
    /// tick — the compute SPEC fetch (`get` on a `computever/<hash>` key) and the per-workload
    /// REPLICA-STATE listing (`list_prefix` on a `.../compute_state/<workload>/` prefix).
    struct CountingKv {
        inner: Arc<dyn crate::kv::KvStore>,
        spec_gets: std::sync::atomic::AtomicUsize,
        replica_state_listings: std::sync::atomic::AtomicUsize,
    }

    impl CountingKv {
        fn new(inner: Arc<dyn crate::kv::KvStore>) -> Self {
            Self {
                inner,
                spec_gets: std::sync::atomic::AtomicUsize::new(0),
                replica_state_listings: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn reset(&self) {
            self.spec_gets
                .store(0, std::sync::atomic::Ordering::Relaxed);
            self.replica_state_listings
                .store(0, std::sync::atomic::Ordering::Relaxed);
        }
        fn spec_gets(&self) -> usize {
            self.spec_gets.load(std::sync::atomic::Ordering::Relaxed)
        }
        fn replica_state_listings(&self) -> usize {
            self.replica_state_listings
                .load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl crate::kv::KvStore for CountingKv {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, crate::kv::KvError> {
            // Compute spec keys are `computever/<hash>` (`spec_key`).
            if key.starts_with(&spec_key("")) {
                self.spec_gets
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            self.inner.get(key).await
        }
        async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), crate::kv::KvError> {
            self.inner.put(key, value).await
        }
        async fn delete(&self, key: &str) -> Result<(), crate::kv::KvError> {
            self.inner.delete(key).await
        }
        async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, crate::kv::KvError> {
            // A per-workload replica-state listing is `project/<p>/compute_state/<workload>/`;
            // exclude the project-wide `.../compute_state/` form (which `reconcile_once` never
            // uses) so only `list_replica_states` is tallied.
            if prefix.contains("/compute_state/") && !prefix.ends_with("/compute_state/") {
                self.replica_state_listings
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            self.inner.list_prefix(prefix).await
        }
    }

    /// 4c regression lock: `reconcile_once` fetches each workload's active spec AND its replica
    /// states exactly ONCE per tick. The bin-packing pre-pass and the per-workload planning loop
    /// now share a single read instead of each issuing its own (the former double-fetch), so N
    /// workloads issue N spec gets + N replica-state listings (not 2N) — and placement is
    /// unchanged (each workload still launches its replica through the deduped path).
    #[tokio::test]
    async fn reconcile_fetches_each_workloads_spec_and_states_once() {
        const N: usize = 3;
        let counting = Arc::new(CountingKv::new(Arc::new(crate::kv::MemoryKv::new())));
        let deploy = DeployStore::new(Arc::new(NullStorage), counting.clone());

        for i in 0..N {
            let hash = deploy.put_compute_spec(&spec(1, 128)).await.unwrap();
            deploy
                .set_compute_workload(
                    crate::project::ProjectRef::DEFAULT,
                    &ComputeWorkload {
                        version: 1,
                        name: format!("w{i}"),
                        active: hash,
                        replicas: 1,
                        placement: Default::default(),
                        priority: Default::default(),
                    },
                )
                .await
                .unwrap();
        }
        let nodes = vec![fake_node()];
        let mut backends: BackendRegistry = BTreeMap::new();
        backends.insert("fake".into(), Arc::new(FakeBackend));
        let policy = BackendPolicy::default();

        // Measure only the reconcile pass (setup writes above don't touch the tallied read
        // paths, but reset to be unambiguous).
        counting.reset();
        let r = reconcile_once(
            &deploy,
            &backends,
            &nodes,
            &policy,
            &AlwaysActive,
            None,
            None,
            None,
            BinPackTuning::default(),
        )
        .await
        .unwrap();
        // Capture the counters BEFORE the verification listings below (which would also count).
        let spec_gets = counting.spec_gets();
        let replica_state_listings = counting.replica_state_listings();

        // Placement is unchanged: every workload launches its one replica with no errors.
        assert_eq!(r.launched, N, "every workload launches: {:?}", r.errors);
        assert!(r.errors.is_empty(), "no errors: {:?}", r.errors);

        // THE DEDUP: exactly one active-spec fetch + one replica-states listing PER workload —
        // N, not the 2N the pre-pass + planning loop issued before sharing a single read.
        assert_eq!(
            spec_gets, N,
            "one active-spec fetch per workload (was 2N across pre-pass + planning loop)"
        );
        assert_eq!(
            replica_state_listings, N,
            "one replica-states listing per workload (was 2N)"
        );

        // Each workload really did place its replica (placement intact through the deduped path).
        for i in 0..N {
            let states = deploy
                .list_replica_states(crate::project::ProjectRef::DEFAULT, &format!("w{i}"))
                .await
                .unwrap();
            assert_eq!(states.len(), 1, "w{i} has exactly one running replica");
        }
    }

    /// 4b: the conservative reservation floor the bin-packing pre-pass charges a RUNNING replica
    /// whose reservation can't be resolved is OPERATOR-configurable via [`BinPackTuning`]. With
    /// the floor omitted ([`BinPackTuning::default`]) it is the built-in 1 vCPU + 1 GiB; a larger
    /// operator floor reserves more of the node, so a second workload that fits under the default
    /// no longer does. The floor is a `reconcile_once` parameter (wired from node `[compute]`
    /// config) — an operator knob, never derived from a tenant's workload spec.
    #[tokio::test]
    async fn unresolved_reservation_floor_is_operator_configurable() {
        // A fresh world per run: a 4 vCPU / 4096 MiB node, a workload `orphan` with one RUNNING
        // replica whose reservation is UNRESOLVABLE (its own launched spec AND its workload's
        // active spec are both absent from the store, so the pre-pass charges the floor), and a
        // second workload `fill` wanting one 3 vCPU / 3000 MiB replica.
        async fn run(tuning: BinPackTuning) -> ReconcileReport {
            let deploy =
                DeployStore::new(Arc::new(NullStorage), Arc::new(crate::kv::MemoryKv::new()));

            // `orphan`: active pointer to a spec that was never stored ⇒ the workload spec (the
            // reservation fallback) is unresolvable.
            deploy
                .set_compute_workload(
                    crate::project::ProjectRef::DEFAULT,
                    &ComputeWorkload {
                        version: 1,
                        name: "orphan".into(),
                        active: "missing-active-hash".into(),
                        replicas: 1,
                        placement: Default::default(),
                        priority: Default::default(),
                    },
                )
                .await
                .unwrap();
            // Its one RUNNING replica, whose OWN launched spec hash is also absent ⇒ neither spec
            // resolves and the pre-pass charges the configurable floor against node 1.
            let mut rep = observed("orphan", 0, 1, true);
            rep.backend = "fake".into();
            rep.active_spec = Some("missing-replica-hash".into());
            deploy
                .set_replica_state(crate::project::ProjectRef::DEFAULT, &rep)
                .await
                .unwrap();

            // `fill`: a valid workload wanting one 3 vCPU / 3000 MiB replica.
            let fill_hash = deploy.put_compute_spec(&spec(3, 3000)).await.unwrap();
            deploy
                .set_compute_workload(
                    crate::project::ProjectRef::DEFAULT,
                    &ComputeWorkload {
                        version: 1,
                        name: "fill".into(),
                        active: fill_hash,
                        replicas: 1,
                        placement: Default::default(),
                        priority: Default::default(),
                    },
                )
                .await
                .unwrap();

            let nodes = vec![node(
                1,
                "eu",
                4,
                4096,
                &[("fake", IsolationClass::Namespace)],
            )];
            let mut backends: BackendRegistry = BTreeMap::new();
            backends.insert("fake".into(), Arc::new(FakeBackend));
            let policy = BackendPolicy::default();
            reconcile_once(
                &deploy,
                &backends,
                &nodes,
                &policy,
                &AlwaysActive,
                None,
                None,
                None,
                tuning,
            )
            .await
            .unwrap()
        }

        // DEFAULT floor (1 vCPU / 1024 MiB): node 1 has (3 vCPU / 3072 MiB) left after charging
        // the orphan ⇒ `fill` (3 / 3000) fits and launches.
        let r_default = run(BinPackTuning::default()).await;
        assert_eq!(
            r_default.launched, 1,
            "under the default floor `fill` fits and launches: {:?}",
            r_default.errors
        );

        // A LARGER operator floor (4 vCPU / 4096 MiB) consumes the whole node, so `fill` no
        // longer fits — same workloads, same node, only the operator knob changed.
        let r_big = run(BinPackTuning {
            unresolved_reservation: Reservation {
                vcpus: 4,
                mem_mib: 4096,
            },
        })
        .await;
        assert_eq!(
            r_big.launched, 0,
            "a larger operator floor reserves the node, so `fill` can't place: {:?}",
            r_big.errors
        );
        assert!(
            r_big
                .errors
                .iter()
                .any(|e| e.contains("fill") && e.contains("not scheduled")),
            "the held workload is surfaced as not scheduled: {:?}",
            r_big.errors
        );
    }
}

// ===========================================================================
// Priority / preemption engine tests (v0.70.0) — the slate's highest-stakes
// feature: the tenancy boundary, the comparator, dry-run-before-evict + anti-
// thrash, dispositions, min_available, the capability gate, and the reason enum.
// ===========================================================================
#[cfg(test)]
mod priority_tests {
    use super::*;

    // ---- helpers -----------------------------------------------------------

    fn sp(vcpus: u32, mem: u32) -> ComputeSpec {
        ComputeSpec::builder(RootSource::Image("img:1".into()), vcpus, mem, 80).build()
    }

    /// A scale-to-zero-capable spec (so a vmm victim is PARKED rather than drained).
    fn sp_s2z(vcpus: u32, mem: u32) -> ComputeSpec {
        ComputeSpec::builder(RootSource::Image("img:1".into()), vcpus, mem, 80)
            .scale_to_zero(true)
            .build()
    }

    fn pri(class: Option<&str>, rank: i32, min_available: Option<u32>) -> Priority {
        Priority::new()
            .with_class(class.map(str::to_string))
            .with_rank(rank)
            .with_min_available(min_available)
    }

    fn wl(name: &str, replicas: u32, priority: Priority) -> ComputeWorkload {
        ComputeWorkload {
            version: 1,
            name: name.into(),
            active: "h".into(),
            replicas,
            placement: PlacementConstraints::default(),
            priority,
        }
    }

    fn wl_region(name: &str, replicas: u32, priority: Priority, region: &str) -> ComputeWorkload {
        let mut w = wl(name, replicas, priority);
        w.placement = PlacementConstraints {
            regions: vec![region.to_string()],
            labels: BTreeMap::new(),
        };
        w
    }

    fn running(
        project: &str,
        workload: &str,
        replica: u32,
        node: u64,
        backend: &str,
    ) -> ObservedInstance {
        ObservedInstance {
            handle: InstanceHandle {
                project: project.into(),
                workload: workload.into(),
                replica,
                backend_ref: format!("ref-{workload}-{replica}"),
            },
            node,
            backend: backend.into(),
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: "10.0.0.2".into(),
                port: 80,
            },
            region: None,
            healthy: true,
            started_at: None,
            phase: ReplicaPhase::Running,
            readiness: Readiness::Provisioned,
            data_dir: None,
            snapshot: None,
            active_spec: Some("h".into()),
        }
    }

    fn backend_kind(id: &str, iso: IsolationClass) -> BackendKind {
        BackendKind::new(id, iso)
            .with_persistent_volumes(true)
            .with_scale_to_zero(true)
            .with_accepted_sources(vec![
                RootSourceKind::Image,
                RootSourceKind::Tar,
                RootSourceKind::Rootfs,
            ])
            .with_private_registry_credential(true)
    }

    fn node_with(id: u64, region: &str, cpus: u32, mem: u32, backends: &[&str]) -> Node {
        Node {
            id,
            region: Some(region.into()),
            labels: BTreeMap::new(),
            free_vcpus: cpus,
            free_mem_mib: mem,
            backends: backends
                .iter()
                .map(|b| {
                    let iso = match *b {
                        "vmm" => IsolationClass::VmKvm,
                        "cloudflare" | "kubernetes" => IsolationClass::Platform,
                        _ => IsolationClass::Namespace,
                    };
                    backend_kind(b, iso)
                })
                .collect(),
        }
    }

    fn caps() -> BTreeMap<String, Capabilities> {
        let mut m = BTreeMap::new();
        m.insert(
            "vmm".to_string(),
            Capabilities {
                isolation: IsolationClass::VmKvm,
                scale_to_zero: true,
                persistent_volumes: true,
                max_vcpus: None,
                max_mem_mib: None,
                preemptible: true,
            },
        );
        m.insert(
            "container".to_string(),
            Capabilities {
                isolation: IsolationClass::Namespace,
                scale_to_zero: false,
                persistent_volumes: true,
                max_vcpus: None,
                max_mem_mib: None,
                preemptible: true,
            },
        );
        m.insert(
            "cloudflare".to_string(),
            Capabilities {
                isolation: IsolationClass::Platform,
                scale_to_zero: true,
                persistent_volumes: false,
                max_vcpus: None,
                max_mem_mib: None,
                preemptible: false,
            },
        );
        m
    }

    /// Every project's ceiling raised to the top class (`system`), so the reconcile-time ceiling
    /// CLAMP is a no-op — these engine tests then exercise the pure preemption logic exactly as
    /// before the clamp landed (a `system` workload HAS its cross-tenant authority ONLY because its
    /// project's ceiling permits it, which the write path enforced). The dedicated ceiling tests
    /// below instead LOWER a project's ceiling to prove the clamp revokes an over-ceiling class.
    fn open_ceilings() -> BTreeMap<String, Option<String>> {
        ["proj", "projA", "projB", "p1", "p2"]
            .into_iter()
            .map(|p| (p.to_string(), Some("system".to_string())))
            .collect()
    }

    /// Seed a ledger from advertised capacity minus the running victims' reservations (what the
    /// reconcile pre-pass produces).
    fn seeded(nodes: &[Node], running: &[(u64, &ComputeSpec)]) -> NodeCapacities {
        let mut c = NodeCapacities::advertised(nodes);
        for (node, spec) in running {
            c.reserve(*node, Reservation::of_spec(spec));
        }
        c
    }

    // ---- 1. comparator -----------------------------------------------------

    #[test]
    fn comparator_orders_by_tier_then_project_then_rank_then_name() {
        let cat = PriorityClassCatalog::builtin();
        let system = wl("z", 1, pri(Some("system"), 0, None));
        let standard = wl("a", 1, pri(None, 0, None));
        let spot = wl("a", 1, pri(Some("spot"), 0, None));
        let k_system = workload_priority_key(&cat, "projB", &system);
        let k_standard = workload_priority_key(&cat, "projA", &standard);
        let k_spot = workload_priority_key(&cat, "projA", &spot);
        assert!(k_system < k_standard, "system tier sorts before standard");
        assert!(k_standard < k_spot, "standard sorts before spot");
    }

    #[test]
    fn rollout_no_op_default_order_reduces_to_project_then_name() {
        let cat = PriorityClassCatalog::builtin();
        let a = wl("web", 1, Priority::default());
        let b = wl("api", 1, Priority::default());
        let ka = workload_priority_key(&cat, "p1", &a);
        let kb = workload_priority_key(&cat, "p1", &b);
        assert!(kb < ka, "same tier+project → ordered by name");
        assert_eq!(ka.0, 0, "neutral tier component");
        assert_eq!(ka.2, 0, "neutral rank component");
    }

    // ---- 2. a tenant's huge rank cannot leapfrog another project -----------

    #[test]
    fn huge_rank_cannot_leapfrog_another_project() {
        let cat = PriorityClassCatalog::builtin();
        let b_hot = wl("w", 1, pri(None, i32::MAX, None));
        let a_cold = wl("w", 1, pri(None, 0, None));
        let kb = workload_priority_key(&cat, "projB", &b_hot);
        let ka = workload_priority_key(&cat, "projA", &a_cold);
        assert!(ka < kb, "projA precedes projB despite projB's huge rank");
    }

    // ---- 3-5. tenancy boundary (may_preempt) -------------------------------

    #[test]
    fn same_project_higher_rank_may_preempt_lower() {
        let cat = PriorityClassCatalog::builtin();
        let hi = pri(None, 10, None);
        let lo = pri(None, 1, None);
        assert!(cat.may_preempt(&hi, "p", &lo, "p"));
        assert!(!cat.may_preempt(&lo, "p", &hi, "p"));
        assert!(
            !cat.may_preempt(&hi, "p", &hi, "p"),
            "equal rank never preempts (strict)"
        );
    }

    #[test]
    fn cross_project_needs_cross_tenant_opt_in_and_strictly_higher_tier() {
        let cat = PriorityClassCatalog::builtin();
        let system = pri(Some("system"), 0, None);
        let standard = pri(None, 0, None);
        let spot = pri(Some("spot"), 0, None);
        assert!(cat.may_preempt(&system, "p1", &standard, "p2"));
        assert!(cat.may_preempt(&system, "p1", &spot, "p2"));
        assert!(!cat.may_preempt(&standard, "p1", &spot, "p2"));
        let standard_hot = pri(None, i32::MAX, None);
        assert!(
            !cat.may_preempt(&standard_hot, "p1", &spot, "p2"),
            "rank ignored cross-project"
        );
    }

    #[test]
    fn two_standard_tenants_never_preempt_each_other() {
        let cat = PriorityClassCatalog::builtin();
        let a = pri(None, 0, None);
        let b = pri(None, 0, None);
        assert!(!cat.may_preempt(&a, "p1", &b, "p2"));
        assert!(!cat.may_preempt(&b, "p2", &a, "p1"));
    }

    // ---- 6. ceiling refusal ------------------------------------------------

    #[test]
    fn ceiling_refuses_a_class_above_the_cap() {
        let cat = PriorityClassCatalog::builtin();
        assert!(cat.check_request(None, None).is_ok());
        assert!(cat.check_request(Some("standard"), None).is_ok());
        assert!(cat.check_request(Some("spot"), None).is_ok());
        let err = cat.check_request(Some("system"), None).unwrap_err();
        assert!(
            err.contains("system") && err.contains("ceiling"),
            "names the refusal: {err}"
        );
        assert!(cat.check_request(Some("system"), Some("system")).is_ok());
        assert!(
            cat.check_request(Some("gold"), None).is_err(),
            "unknown class refused"
        );
    }

    // ---- 11. preemptible capability gate -----------------------------------

    #[test]
    fn delegated_backend_workload_never_enters_the_preemption_pass() {
        let cat = PriorityClassCatalog::builtin();
        let caps = caps();
        let nodes = vec![node_with(1, "r", 2, 1000, &["cloudflare"])];
        let vspec = sp(2, 1000);
        let pspec = sp(2, 1000);
        let victim = wl("v", 1, pri(None, 0, None));
        let preemptor = wl("p", 1, pri(Some("system"), 0, None));
        let vobs = vec![running("p2", "v", 0, 1, "cloudflare")];
        let pobs: Vec<ObservedInstance> = vec![];
        let np = BackendPolicy::default();
        let inputs = vec![
            PreemptInput {
                project: "p1",
                workload: &preemptor,
                spec: &pspec,
                policy: &np,
                observed: &pobs,
            },
            PreemptInput {
                project: "p2",
                workload: &victim,
                spec: &vspec,
                policy: &np,
                observed: &vobs,
            },
        ];
        let base = seeded(&nodes, &[(1, &vspec)]);
        let plan = plan_preemptions(&inputs, &nodes, &caps, &cat, &open_ceilings(), &base, 1000);
        assert!(
            plan.victims.is_empty(),
            "a delegated-backend workload is never a victim/preemptor"
        );
    }

    // ---- 3 (engine). same-project rank preemption with a real plan ---------

    #[test]
    fn engine_same_project_higher_rank_preempts_lower() {
        let cat = PriorityClassCatalog::builtin();
        let caps = caps();
        let nodes = vec![node_with(1, "r", 8, 8000, &["container"])];
        let vspec = sp(8, 8000);
        let pspec = sp(8, 8000);
        // The victim is explicitly evictable (min_available 0) — the tenant's own budget. A
        // DEFAULT standard victim is floor-protected at its replica count, so a same-tier rank
        // preemptor would (correctly) be blocked; the tenant opts the lower-rank workload into
        // preemptibility by lowering its floor.
        let victim = wl("v", 1, pri(None, 1, Some(0)));
        let preemptor = wl("p", 1, pri(None, 10, None));
        let vobs = vec![running("proj", "v", 0, 1, "container")];
        let pobs: Vec<ObservedInstance> = vec![];
        let np = BackendPolicy::default();
        let inputs = vec![
            PreemptInput {
                project: "proj",
                workload: &preemptor,
                spec: &pspec,
                policy: &np,
                observed: &pobs,
            },
            PreemptInput {
                project: "proj",
                workload: &victim,
                spec: &vspec,
                policy: &np,
                observed: &vobs,
            },
        ];
        let base = seeded(&nodes, &[(1, &vspec)]);
        let plan = plan_preemptions(&inputs, &nodes, &caps, &cat, &open_ceilings(), &base, 1000);
        assert_eq!(plan.victims.len(), 1, "the lower-rank sibling is preempted");
        assert_eq!(plan.victims[0].handle.workload, "v");
        assert!(matches!(
            plan.victims[0].disposition,
            PreemptDisposition::Drain { .. }
        ));
        assert_eq!(plan.victims[0].preemptor.workload, "p");
    }

    // ---- 4 (engine). cross-tenant only for CrossTenantOptIn higher tier ----

    #[test]
    fn engine_standard_cannot_preempt_across_tenants() {
        let cat = PriorityClassCatalog::builtin();
        let caps = caps();
        let nodes = vec![node_with(1, "r", 8, 8000, &["container"])];
        let vspec = sp(8, 8000);
        let pspec = sp(8, 8000);
        let victim = wl("v", 1, pri(None, 0, None));
        let vobs = vec![running("projB", "v", 0, 1, "container")];
        let pobs: Vec<ObservedInstance> = vec![];
        let np = BackendPolicy::default();
        let std_pre = wl("p", 1, pri(None, i32::MAX, None));
        let inputs = vec![
            PreemptInput {
                project: "projA",
                workload: &std_pre,
                spec: &pspec,
                policy: &np,
                observed: &pobs,
            },
            PreemptInput {
                project: "projB",
                workload: &victim,
                spec: &vspec,
                policy: &np,
                observed: &vobs,
            },
        ];
        let base = seeded(&nodes, &[(1, &vspec)]);
        let plan = plan_preemptions(&inputs, &nodes, &caps, &cat, &open_ceilings(), &base, 1000);
        assert!(
            plan.victims.is_empty(),
            "standard never preempts across tenants"
        );
    }

    #[test]
    fn engine_system_preempts_across_tenants() {
        let cat = PriorityClassCatalog::builtin();
        let caps = caps();
        let nodes = vec![node_with(1, "r", 8, 8000, &["container"])];
        let vspec = sp(8, 8000);
        let pspec = sp(8, 8000);
        let victim = wl("v", 1, pri(None, 0, None));
        let sys_pre = wl("p", 1, pri(Some("system"), 0, None));
        let vobs = vec![running("projB", "v", 0, 1, "container")];
        let pobs: Vec<ObservedInstance> = vec![];
        let np = BackendPolicy::default();
        let inputs = vec![
            PreemptInput {
                project: "projA",
                workload: &sys_pre,
                spec: &pspec,
                policy: &np,
                observed: &pobs,
            },
            PreemptInput {
                project: "projB",
                workload: &victim,
                spec: &vspec,
                policy: &np,
                observed: &vobs,
            },
        ];
        let base = seeded(&nodes, &[(1, &vspec)]);
        let plan = plan_preemptions(&inputs, &nodes, &caps, &cat, &open_ceilings(), &base, 1000);
        assert_eq!(plan.victims.len(), 1, "system preempts projB's standard");
        assert_eq!(plan.victims[0].project, "projB");
    }

    // ---- 7. dry-run-before-evict: never a wasted eviction ------------------

    #[test]
    fn preemption_never_evicts_a_victim_it_cannot_use() {
        let cat = PriorityClassCatalog::builtin();
        let caps = caps();
        let nodes = vec![
            node_with(1, "west", 2, 1000, &["container"]),
            node_with(2, "east", 8, 8000, &["container"]),
        ];
        let vspec = sp(8, 8000);
        let pspec = sp(8, 8000);
        let victim = wl("v", 1, pri(None, 0, None));
        let preemptor = wl_region("p", 1, pri(Some("system"), 0, None), "west");
        let vobs = vec![running("projB", "v", 0, 2, "container")];
        let filler = sp(2, 1000);
        let pobs: Vec<ObservedInstance> = vec![running("projA", "filler", 0, 1, "container")];
        let np = BackendPolicy::default();
        let inputs = vec![
            PreemptInput {
                project: "projA",
                workload: &preemptor,
                spec: &pspec,
                policy: &np,
                observed: &pobs,
            },
            PreemptInput {
                project: "projB",
                workload: &victim,
                spec: &vspec,
                policy: &np,
                observed: &vobs,
            },
        ];
        let base = seeded(&nodes, &[(1, &filler), (2, &vspec)]);
        let plan = plan_preemptions(&inputs, &nodes, &caps, &cat, &open_ceilings(), &base, 1000);
        assert!(
            plan.victims.is_empty(),
            "evicting the east victim can't help a west-pinned preemptor"
        );
    }

    // ---- 8. Park vs Drain disposition --------------------------------------

    #[test]
    fn park_a_scale_to_zero_capable_victim() {
        let cat = PriorityClassCatalog::builtin();
        let caps = caps();
        let nodes = vec![node_with(1, "r", 8, 8000, &["vmm"])];
        let vspec = sp_s2z(8, 8000);
        let pspec = sp(8, 8000);
        let victim = wl("v", 1, pri(None, 0, None));
        let preemptor = wl("p", 1, pri(Some("system"), 0, None));
        let vobs = vec![running("projB", "v", 0, 1, "vmm")];
        let pobs: Vec<ObservedInstance> = vec![];
        let np = BackendPolicy::default();
        let inputs = vec![
            PreemptInput {
                project: "projA",
                workload: &preemptor,
                spec: &pspec,
                policy: &np,
                observed: &pobs,
            },
            PreemptInput {
                project: "projB",
                workload: &victim,
                spec: &vspec,
                policy: &np,
                observed: &vobs,
            },
        ];
        let base = seeded(&nodes, &[(1, &vspec)]);
        let plan = plan_preemptions(&inputs, &nodes, &caps, &cat, &open_ceilings(), &base, 1000);
        assert_eq!(plan.victims.len(), 1);
        assert!(
            matches!(plan.victims[0].disposition, PreemptDisposition::Park),
            "s2z victim is PARKED"
        );
    }

    // ---- 9. min_available floor (hard same-tier, advisory higher tier) -----

    #[test]
    fn min_available_is_hard_within_same_tier() {
        let cat = PriorityClassCatalog::builtin();
        let caps = caps();
        let nodes = vec![node_with(1, "r", 4, 4000, &["container"])];
        let vspec = sp(2, 2000);
        let pspec = sp(2, 2000);
        let victim = wl("v", 2, pri(None, 1, Some(2)));
        let preemptor = wl("p", 1, pri(None, 10, None));
        let vobs = vec![
            running("proj", "v", 0, 1, "container"),
            running("proj", "v", 1, 1, "container"),
        ];
        let pobs: Vec<ObservedInstance> = vec![];
        let np = BackendPolicy::default();
        let inputs = vec![
            PreemptInput {
                project: "proj",
                workload: &preemptor,
                spec: &pspec,
                policy: &np,
                observed: &pobs,
            },
            PreemptInput {
                project: "proj",
                workload: &victim,
                spec: &vspec,
                policy: &np,
                observed: &vobs,
            },
        ];
        let base = seeded(&nodes, &[(1, &vspec), (1, &vspec)]);
        let plan = plan_preemptions(&inputs, &nodes, &caps, &cat, &open_ceilings(), &base, 1000);
        assert!(
            plan.victims.is_empty(),
            "a HARD min_available floor blocks a same-tier preemptor"
        );
    }

    #[test]
    fn min_available_is_advisory_to_a_strictly_higher_tier() {
        let cat = PriorityClassCatalog::builtin();
        let caps = caps();
        let nodes = vec![node_with(1, "r", 2, 2000, &["container"])];
        let vspec = sp(2, 2000);
        let pspec = sp(2, 2000);
        let victim = wl("v", 1, pri(Some("standard"), 0, Some(1)));
        let preemptor = wl("p", 1, pri(Some("system"), 0, None));
        let vobs = vec![running("projB", "v", 0, 1, "container")];
        let pobs: Vec<ObservedInstance> = vec![];
        let np = BackendPolicy::default();
        let inputs = vec![
            PreemptInput {
                project: "projA",
                workload: &preemptor,
                spec: &pspec,
                policy: &np,
                observed: &pobs,
            },
            PreemptInput {
                project: "projB",
                workload: &victim,
                spec: &vspec,
                policy: &np,
                observed: &vobs,
            },
        ];
        let base = seeded(&nodes, &[(1, &vspec)]);
        let plan = plan_preemptions(&inputs, &nodes, &caps, &cat, &open_ceilings(), &base, 1000);
        assert_eq!(
            plan.victims.len(),
            1,
            "a strictly-higher operator tier overrides the advisory floor"
        );
    }

    // ---- 10. anti-thrash convergence (>=3 passes, zero oscillation) --------

    #[test]
    fn anti_thrash_converges_with_zero_oscillation() {
        let cat = PriorityClassCatalog::builtin();
        let caps = caps();
        let nodes = vec![node_with(1, "r", 8, 8000, &["container"])];
        let vspec = sp(8, 8000);
        let pspec = sp(8, 8000);
        let victim = wl("v", 1, pri(None, 0, None));
        let preemptor = wl("p", 1, pri(Some("system"), 0, None));
        let np = BackendPolicy::default();

        let vobs1 = vec![running("projB", "v", 0, 1, "container")];
        let pobs1: Vec<ObservedInstance> = vec![];
        let inputs1 = vec![
            PreemptInput {
                project: "projA",
                workload: &preemptor,
                spec: &pspec,
                policy: &np,
                observed: &pobs1,
            },
            PreemptInput {
                project: "projB",
                workload: &victim,
                spec: &vspec,
                policy: &np,
                observed: &vobs1,
            },
        ];
        let base1 = seeded(&nodes, &[(1, &vspec)]);
        let plan1 = plan_preemptions(
            &inputs1,
            &nodes,
            &caps,
            &cat,
            &open_ceilings(),
            &base1,
            1000,
        );
        assert_eq!(plan1.victims.len(), 1, "pass 1 preempts the victim once");

        let vobs_after = vec![ObservedInstance {
            healthy: false,
            readiness: Readiness::Preempted {
                by: "projA/p (system, tier 100)".into(),
                preemptor_project: "projA".into(),
                since: 1000,
            },
            ..running("projB", "v", 0, 1, "container")
        }];
        let pobs_after = vec![running("projA", "p", 0, 1, "container")];
        for pass in 2..=3 {
            let inputs = vec![
                PreemptInput {
                    project: "projA",
                    workload: &preemptor,
                    spec: &pspec,
                    policy: &np,
                    observed: &pobs_after,
                },
                PreemptInput {
                    project: "projB",
                    workload: &victim,
                    spec: &vspec,
                    policy: &np,
                    observed: &vobs_after,
                },
            ];
            let base = seeded(&nodes, &[(1, &pspec)]);
            let plan =
                plan_preemptions(&inputs, &nodes, &caps, &cat, &open_ceilings(), &base, 2000);
            assert!(
                plan.victims.is_empty(),
                "pass {pass}: converged — no re-preemption, no oscillation"
            );
        }
    }

    #[test]
    fn mutation_guard_strict_improvement_prevents_flapping() {
        let cat = PriorityClassCatalog::builtin();
        let caps = caps();
        let nodes = vec![node_with(1, "r", 16, 16000, &["container"])];
        let vspec = sp(8, 8000);
        let pspec = sp(8, 8000);
        let victim = wl("v", 1, pri(None, 0, None));
        let preemptor = wl("p", 1, pri(Some("system"), 0, None));
        let vobs = vec![running("projB", "v", 0, 1, "container")];
        let pobs: Vec<ObservedInstance> = vec![];
        let np = BackendPolicy::default();
        let inputs = vec![
            PreemptInput {
                project: "projA",
                workload: &preemptor,
                spec: &pspec,
                policy: &np,
                observed: &pobs,
            },
            PreemptInput {
                project: "projB",
                workload: &victim,
                spec: &vspec,
                policy: &np,
                observed: &vobs,
            },
        ];
        let base = seeded(&nodes, &[(1, &vspec)]);
        let plan = plan_preemptions(&inputs, &nodes, &caps, &cat, &open_ceilings(), &base, 1000);
        assert!(
            plan.victims.is_empty(),
            "a preemptor that already fits never evicts (anti-thrash)"
        );
    }

    // ---- 13. reason enum tokens --------------------------------------------

    #[test]
    fn reason_enum_tokens_are_stable() {
        assert_eq!(UnplacedCause::PriorityOutbid.token(), "priority_outbid");
        assert_eq!(
            UnplacedCause::InsufficientCapacity.token(),
            "insufficient_capacity"
        );
        assert_eq!(UnplacedCause::PriorityOutbid.label(), "OUTBID");
        assert_eq!(UnplacedCause::InsufficientCapacity.label(), "INSUFFICIENT");
    }

    #[test]
    fn outbid_is_set_only_when_a_dominator_took_the_capacity() {
        let cat = PriorityClassCatalog::builtin();
        let caps = caps();
        let nodes = vec![node_with(1, "r", 8, 8000, &["container"])];
        let sspec = sp(8, 8000);
        let tspec = sp(8, 8000);
        let sys = wl("s", 1, pri(Some("system"), 0, None));
        let std = wl("t", 1, pri(None, 0, None));
        let sobs: Vec<ObservedInstance> = vec![];
        let tobs: Vec<ObservedInstance> = vec![];
        let np = BackendPolicy::default();
        let inputs = vec![
            PreemptInput {
                project: "p1",
                workload: &sys,
                spec: &sspec,
                policy: &np,
                observed: &sobs,
            },
            PreemptInput {
                project: "p2",
                workload: &std,
                spec: &tspec,
                policy: &np,
                observed: &tobs,
            },
        ];
        let base = seeded(&nodes, &[]);
        let plan = plan_preemptions(&inputs, &nodes, &caps, &cat, &open_ceilings(), &base, 1000);
        assert!(
            plan.outbid.contains(&("p2".to_string(), "t".to_string())),
            "standard outbid by a system workload that took the node: {:?}",
            plan.outbid
        );
    }

    // ---- 14. reconcile-time ceiling CLAMP (revocation completion) -----------

    #[test]
    fn resolve_clamped_lowers_an_over_ceiling_class() {
        let cat = PriorityClassCatalog::builtin();
        let system = pri(Some("system"), 0, None);
        // Granted (ceiling `system`): resolves AS system — full tier + cross-tenant authority.
        let (name, class) = cat.resolve_clamped(&system, Some("system"));
        assert_eq!(name, "system");
        assert_eq!(class.tier, 100);
        assert_eq!(class.preemption, PreemptionMode::CrossTenantOptIn);
        // Ceiling lowered to `standard` (or ABSENT ⇒ the node default `standard`): the stored
        // `system` clamps to `standard`, losing the over-ceiling tier AND cross-tenant authority.
        for ceiling in [Some("standard"), None] {
            let (name, class) = cat.resolve_clamped(&system, ceiling);
            assert_eq!(
                name, "standard",
                "clamped to the ceiling class ({ceiling:?})"
            );
            assert_eq!(class.tier, 0);
            assert_eq!(class.preemption, PreemptionMode::WithinProject);
        }
        // At/under the ceiling is UNAFFECTED (the clamp only ever lowers).
        let standard = pri(None, 0, None);
        assert_eq!(cat.resolve_clamped(&standard, Some("system")).0, "standard");
        let spot = pri(Some("spot"), 0, None);
        assert_eq!(cat.resolve_clamped(&spot, Some("standard")).0, "spot");
        // An unknown ceiling name fails SAFE to the node default ceiling — never a grant.
        assert_eq!(cat.resolve_clamped(&system, Some("bogus")).0, "standard");
    }

    #[test]
    fn clamped_comparator_demotes_an_over_ceiling_class() {
        let cat = PriorityClassCatalog::builtin();
        let system = wl("w", 1, pri(Some("system"), 0, None));
        // Ceiling grants `system` ⇒ sorts at the system tier (negated, earliest).
        let granted = workload_priority_key_clamped(&cat, "projA", &system, Some("system"));
        assert_eq!(granted.0, -100, "system tier (negated)");
        // Ceiling lowered to `standard` ⇒ the SAME stored class sorts as standard: it loses its
        // placement precedence exactly as it loses its preemption authority.
        let clamped = workload_priority_key_clamped(&cat, "projA", &system, Some("standard"));
        assert_eq!(clamped.0, 0, "clamped to the standard tier");
        // ...identical to the key an actual standard workload (same project+name) would get.
        let standard = wl("w", 1, pri(None, 0, None));
        assert_eq!(clamped, workload_priority_key(&cat, "projA", &standard));
    }

    #[test]
    fn engine_clamps_an_over_ceiling_system_to_within_project() {
        let cat = PriorityClassCatalog::builtin();
        let caps = caps();
        let nodes = vec![node_with(1, "r", 8, 8000, &["container"])];
        let vspec = sp(8, 8000);
        let pspec = sp(8, 8000);
        let victim = wl("v", 1, pri(None, 0, None));
        // STORED as `system` (set when projA's ceiling was raised), but projA's ceiling is now
        // lowered back to `standard` — the incomplete-revocation shape.
        let sys_pre = wl("p", 1, pri(Some("system"), 0, None));
        let vobs = vec![running("projB", "v", 0, 1, "container")];
        let pobs: Vec<ObservedInstance> = vec![];
        let np = BackendPolicy::default();
        let inputs = vec![
            PreemptInput {
                project: "projA",
                workload: &sys_pre,
                spec: &pspec,
                policy: &np,
                observed: &pobs,
            },
            PreemptInput {
                project: "projB",
                workload: &victim,
                spec: &vspec,
                policy: &np,
                observed: &vobs,
            },
        ];
        let base = seeded(&nodes, &[(1, &vspec)]);
        // projA ceiling LOWERED to standard (projB absent ⇒ node default standard).
        let lowered: BTreeMap<String, Option<String>> =
            [("projA".to_string(), Some("standard".to_string()))]
                .into_iter()
                .collect();
        let plan = plan_preemptions(&inputs, &nodes, &caps, &cat, &lowered, &base, 1000);
        assert!(
            plan.victims.is_empty(),
            "an over-ceiling `system` clamps to `standard` ⇒ no cross-tenant preemption"
        );
        // CONTROL: the SAME inputs with projA's ceiling GRANTED to `system` DO preempt projB —
        // proving the clamp (not some other gate) neutralized the eviction.
        let granted = plan_preemptions(&inputs, &nodes, &caps, &cat, &open_ceilings(), &base, 1000);
        assert_eq!(
            granted.victims.len(),
            1,
            "with the ceiling granted the stored system preempts projB"
        );
        assert_eq!(granted.victims[0].project, "projB");
    }

    #[test]
    fn engine_at_ceiling_workload_is_unaffected_by_the_clamp() {
        let cat = PriorityClassCatalog::builtin();
        let caps = caps();
        let nodes = vec![node_with(1, "r", 8, 8000, &["container"])];
        let vspec = sp(8, 8000);
        let pspec = sp(8, 8000);
        // Both workloads are `standard` (at the default ceiling); the preemptor outranks within
        // its own project and the victim opts into preemptibility (floor 0).
        let victim = wl("v", 1, pri(None, 1, Some(0)));
        let preemptor = wl("p", 1, pri(None, 10, None));
        let vobs = vec![running("proj", "v", 0, 1, "container")];
        let pobs: Vec<ObservedInstance> = vec![];
        let np = BackendPolicy::default();
        let inputs = vec![
            PreemptInput {
                project: "proj",
                workload: &preemptor,
                spec: &pspec,
                policy: &np,
                observed: &pobs,
            },
            PreemptInput {
                project: "proj",
                workload: &victim,
                spec: &vspec,
                policy: &np,
                observed: &vobs,
            },
        ];
        let base = seeded(&nodes, &[(1, &vspec)]);
        // An explicitly-lowered (standard) ceiling leaves an AT-ceiling (standard) workload's
        // within-project rank preemption fully intact — the clamp only ever lowers an OVER-ceiling
        // class, never restricts one already within its ceiling.
        let ceilings: BTreeMap<String, Option<String>> =
            [("proj".to_string(), Some("standard".to_string()))]
                .into_iter()
                .collect();
        let plan = plan_preemptions(&inputs, &nodes, &caps, &cat, &ceilings, &base, 1000);
        assert_eq!(
            plan.victims.len(),
            1,
            "within-ceiling preemption is unaffected"
        );
        assert_eq!(plan.victims[0].handle.workload, "v");
    }
}
