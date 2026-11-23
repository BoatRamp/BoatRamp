//! Compute workloads: legacy apps run as Firecracker microVMs.
//!
//! This is the wasm-clean **artifact model** — the content-addressed, immutable
//! [`ComputeSpec`] (rootfs/kernel/spec, exactly like a site deployment) and the
//! mutable [`ComputeWorkload`] desired state (active version + replicas +
//! placement). The executor that actually boots a microVM from a spec
//! (`boatramp-firecracker`, KVM-only) and the scheduler that places it are
//! native-only and live elsewhere; this module is just the shared types + their
//! content-addressing, so the CLI, control plane, and executor agree.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::manifest::sha256_hex;

/// KV key prefix for immutable, content-addressed compute specs. Stays **global**
/// (a content hash is a self-authenticating capability; specs dedup across projects).
pub const SPEC_PREFIX: &str = "computever/";

/// The mutable desired-state key for a workload, **project-scoped** (0.2.0):
/// `project/<proj>/compute/<name>`. `project` is a bare `&str` (this crate is
/// wasm-clean); `boatramp-core` callers pass `ProjectRef::as_str()`.
pub fn workload_key(project: &str, name: &str) -> String {
    format!("project/{project}/compute/{name}")
}

/// The prefix listing every workload's desired state in a project.
pub fn workloads_prefix(project: &str) -> String {
    format!("project/{project}/compute/")
}

/// The immutable spec key for a content hash (global CAS).
pub fn spec_key(hash: &str) -> String {
    format!("{SPEC_PREFIX}{hash}")
}

/// What to do when a workload's guest process exits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    /// Never restart (run-to-completion / job).
    Never,
    /// Restart only on a non-zero exit.
    OnFailure,
    /// Always keep it running (the default for a service).
    #[default]
    Always,
}

/// The isolation a workload **requires** — the floor the operator's site policy
/// and the available backends are matched against.
/// This is the workload's stated need, distinct from the isolation *class* a
/// backend provides.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationRequirement {
    /// Shared-kernel isolation is acceptable (a namespace/container is fine).
    /// The default — strong isolation is opt-in.
    #[default]
    Trusted,
    /// Strong isolation is required: only a microVM (KVM) or a managed platform
    /// may run this workload, never a shared-kernel container.
    Untrusted,
}

impl IsolationRequirement {
    /// Whether this is the default (`Trusted`) — used to omit it from the
    /// serialized spec so existing specs keep their content hash.
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }
}

/// The source of a workload's **root filesystem**. Each variant is one concrete
/// artifact form, matched 1:1 to the backends that accept it — modelled explicitly
/// rather than overloading one string, because an image reference, a tar archive, and
/// a rootfs block image are genuinely different things and a mismatch should be a
/// typed error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootSource {
    /// An **OCI image reference** (`repo:tag` or a digest) a runtime **pulls** from a
    /// registry; its unpacked layers become the root filesystem. Backends: `docker`,
    /// `cloudflare`. [`ComputeSpec::kernel`] does not apply.
    Image(String),
    /// A **tar rootfs archive** — a blob hash in the shared store — that the node
    /// **stages and unpacks** into a directory to run. Backend: the native `container`
    /// runtime. [`ComputeSpec::kernel`] does not apply.
    Tar(String),
    /// A **rootfs filesystem image** — a blob hash in the shared store — that the node
    /// **stages and attaches** as the guest's root **block device**. The filesystem is
    /// opaque to boatramp: the guest kernel mounts whatever it finds (`ext4` by
    /// default, since `compute build` uses `mke2fs`, but any kernel-supported
    /// filesystem works). Backend: the `firecracker` micro-VM, which pairs it with
    /// [`ComputeSpec::kernel`].
    Rootfs(String),
}

impl RootSource {
    /// The underlying reference string (an image reference for [`RootSource::Image`],
    /// a blob hash for [`RootSource::Tar`] / [`RootSource::Rootfs`]).
    pub fn as_str(&self) -> &str {
        match self {
            Self::Image(s) | Self::Tar(s) | Self::Rootfs(s) => s,
        }
    }

    /// This source's [`RootSourceKind`] — the artifact kind without the payload. The
    /// scheduler matches a backend's accepted kinds against a spec's source kind to
    /// avoid placing a workload on a backend whose `materialize` would reject its
    /// source (a guaranteed crash).
    pub fn kind(&self) -> RootSourceKind {
        match self {
            Self::Image(_) => RootSourceKind::Image,
            Self::Tar(_) => RootSourceKind::Tar,
            Self::Rootfs(_) => RootSourceKind::Rootfs,
        }
    }
}

/// The discriminant of a [`RootSource`] — its concrete artifact *kind* without the
/// payload. Each backend accepts a fixed set of these (an image runtime pulls an
/// [`Image`](RootSourceKind::Image); the native container runtime stages a
/// [`Tar`](RootSourceKind::Tar); a micro-VM boots a [`Rootfs`](RootSourceKind::Rootfs)),
/// the same 1:1 mapping the CLI's source→substrate derivation applies. The scheduler
/// gates placement on it so a workload only lands on a backend that can run its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootSourceKind {
    /// [`RootSource::Image`] — an OCI image reference a runtime pulls (docker,
    /// cloudflare, kubernetes).
    Image,
    /// [`RootSource::Tar`] — a tar rootfs archive the native `container` runtime stages
    /// and unpacks.
    Tar,
    /// [`RootSource::Rootfs`] — a rootfs filesystem image the `firecracker`/VMM micro-VM
    /// boots as its root block device.
    Rootfs,
}

/// How a backend obtains a workload's OCI **image** before launch — the opaque-compute
/// analogue of Kubernetes' `imagePullPolicy`. Applies only to a [`RootSource::Image`]
/// workload (a tar/rootfs source is staged from the content-addressed blob store and is
/// never pulled). The **default is [`Always`](PullPolicy::Always)**: boatramp re-pulls the
/// reference from its registry on every materialize, so a workload can never silently pick
/// up a *different* image that merely shares a `name:tag` in the node's **shared,
/// cross-tenant** local image store. Reusing a locally-present image — an air-gapped node,
/// a `docker load`'d / `k3d image import`'d image, or just saving a registry round-trip —
/// is therefore **opt-in**.
///
/// ## Tenancy caveat (read before opting in)
///
/// A node's Docker/containerd image store is **shared across every tenant** on that node.
/// Keyed by a **mutable** `name:tag`, a locally-cached image is ambient, poisonable state:
/// another tenant (or a stale earlier pull) can have populated `name:tag` with *different*
/// bytes, and [`IfNotPresent`](PullPolicy::IfNotPresent) / [`Never`](PullPolicy::Never) would
/// then reuse those bytes rather than the registry's. Local reuse is only **sound** for a
/// **digest-pinned** reference (`repo@sha256:…`), which names an immutable manifest the daemon
/// verifies. boatramp does not *refuse* a mutable-tag opt-in (the primary use case — a
/// `docker load`'d image built locally — carries no registry digest), but it **warns** at set
/// time ([`pull_reuse_is_unsound`]); prefer a digest wherever one exists.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PullPolicy {
    /// **Default.** Re-pull the image reference from its registry on every materialize; the
    /// node's shared local image store is never trusted as a source of truth. The safe
    /// default for a multi-tenant node, and the pre-`pull_policy` behavior.
    #[default]
    Always,
    /// Reuse a locally-present image and pull **only when it is absent** — the equivalent of
    /// Kubernetes' `IfNotPresent`. Opt-in; sound only for a digest-pinned reference (see the
    /// type docs' tenancy caveat).
    IfNotPresent,
    /// **Never** pull: require the image to be present in the node's local store already and
    /// fail the launch if it is absent. For a fully air-gapped / pre-loaded node. Opt-in; same
    /// tenancy caveat as [`IfNotPresent`](PullPolicy::IfNotPresent).
    Never,
}

impl PullPolicy {
    /// Whether this is the default ([`Always`](PullPolicy::Always)) — used to omit it from the
    /// serialized spec so existing specs keep their content hash (and an older server that does
    /// not know the field never sees it on the wire).
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Always)
    }

    /// Whether this policy lets a backend **reuse a locally-present image** instead of always
    /// pulling (`IfNotPresent` or `Never`). `Always` never reuses.
    pub fn allows_local_reuse(self) -> bool {
        matches!(self, Self::IfNotPresent | Self::Never)
    }
}

/// Whether an OCI image reference is **digest-pinned** (`…@sha256:…`) — an immutable manifest
/// reference, as opposed to a mutable `name:tag`. Local-image reuse under a non-`Always`
/// [`PullPolicy`] is only *sound* for a digest-pinned reference, because a mutable tag in the
/// node's shared image store is ambient cross-tenant state (see the [`PullPolicy`] tenancy
/// caveat). The check mirrors the docker backend's own digest-vs-tag split: a `@` marks a
/// digest reference.
pub fn image_is_digest_pinned(reference: &str) -> bool {
    reference.contains('@')
}

/// Whether reusing a locally-present image under `policy` for `reference` is **tenancy-unsound**
/// and should be warned about: the policy allows local reuse *and* the reference is a mutable
/// `name:tag` rather than a digest. Pure, so the set-time advisory and a backend share one rule.
pub fn pull_reuse_is_unsound(policy: PullPolicy, reference: &str) -> bool {
    policy.allows_local_reuse() && !image_is_digest_pinned(reference)
}

/// A persistent volume attached to the guest (a host block image, snapshotted
/// to blob storage for durability). Opt-in; the default rootfs is read-only with
/// an ephemeral scratch drive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct VolumeRef {
    /// In-guest mount point.
    pub mount: String,
    /// Volume name (the host tracks its backing image).
    pub name: String,
    /// Size in MiB (used when first provisioning).
    pub size_mib: u32,
}

impl VolumeRef {
    /// A persistent-volume reference. The supported constructor — `VolumeRef` is
    /// `#[non_exhaustive]`, so downstream crates construct it here rather than with a struct
    /// literal (any field added later stays non-breaking). The public fields remain settable.
    pub fn new(mount: impl Into<String>, name: impl Into<String>, size_mib: u32) -> Self {
        Self {
            mount: mount.into(),
            name: name.into(),
            size_mib,
        }
    }
}

/// The generic default startup grace (seconds) for a compute workload — the window a
/// freshly launched replica has to become healthy before the reconcile loop treats a
/// still-unhealthy one as a broken launch. Generic compute + micro-VM workloads use
/// this; the managed-database synthesizer overrides it per engine (slower `initdb`).
pub fn default_startup_grace_secs() -> u32 {
    30
}

/// An immutable, content-addressed compute workload version (the analogue of a
/// deployment manifest). Stored at `computever/<hash>`; the rootfs + kernel are
/// blob hashes in the shared blob store (deduped, cached forever).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ComputeSpec {
    /// Pinned schema discriminant (`v1`).
    #[serde(default = "crate::schema_version")]
    pub version: u32,
    /// The source of the workload's root filesystem: an OCI image reference, a tar
    /// rootfs archive, or a rootfs filesystem image, per the target substrate (see
    /// [`RootSource`]).
    pub root: RootSource,
    /// Blob hash of the `vmlinux` kernel (shared across workloads). Applies only to
    /// the micro-VM substrate (a [`RootSource::Rootfs`] source); ignored otherwise, so
    /// an image/tar workload omits it (empty ⇒ absent from the wire + the content hash).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kernel: String,
    /// Kernel boot cmdline override; `None` uses the executor default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_cmdline: Option<String>,
    /// Virtual CPUs.
    pub vcpus: u32,
    /// Guest memory in MiB.
    pub mem_mib: u32,
    /// The in-guest entrypoint (argv) the init execs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entrypoint: Vec<String>,
    /// Environment variables for the entrypoint.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// The TCP port the app listens on inside the guest (the gateway targets it).
    pub port: u16,
    /// Restart policy for the guest process.
    #[serde(default)]
    pub restart: RestartPolicy,
    /// Seconds a freshly launched replica is given to become healthy before the
    /// reconcile loop treats a `Running`-but-unhealthy replica as a broken launch to
    /// stop + relaunch. Within this grace the replica is "starting" (left alone), so a
    /// slow-initializing image — a stock database's first `initdb` — is not killed
    /// mid-init into a crash loop. Generic default is 30s (see [`default_startup_grace_secs`]);
    /// the managed-database synthesizer raises it per engine. `#[serde(default …)]` keeps
    /// older stored specs (no field) deserializing with the default — schema stays v1.
    #[serde(default = "default_startup_grace_secs")]
    pub startup_grace_secs: u32,
    /// Snapshot + stop when idle; restore on the next request (cold start).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub scale_to_zero: bool,
    /// Persistent volumes (opt-in).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<VolumeRef>,
    /// Allow a writable root filesystem instead of the hardened read-only-root
    /// default. Opt-in and honored **only under the single-tenant isolation
    /// posture** (a backend forces read-only root under the multi-tenant guard).
    /// The idiomatic path for app writes remains a [`VolumeRef`]; this is for images
    /// that write outside a declared volume. Default off; omitted from the wire + the
    /// content hash when false (back-compat).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub writable_root: bool,
    /// Linux capabilities to add back on top of the dropped-`ALL` default of the
    /// shared-kernel backends (docker / native container), so an image whose
    /// entrypoint needs a specific capability (e.g. a stock database that `chown`s its
    /// data dir and `gosu`-drops to its user) can init. Names are the short form
    /// without the `CAP_` prefix (`"CHOWN"`, `"SETUID"`, …). Honored **only under the
    /// single-tenant isolation posture** — the multi-tenant guard strips it, exactly
    /// like [`writable_root`](Self::writable_root). Empty ⇒ omitted from the wire + the
    /// content hash (back-compat).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cap_add: Vec<String>,
    /// Run the entrypoint as this user instead of the backend default. `"uid"` or
    /// `"uid:gid"` (numeric). On the shared-kernel backends this lets a stock image
    /// run rootless against a pre-owned volume — the entrypoint skips the `chown` +
    /// privilege-drop that would otherwise need capabilities, so it needs none. A
    /// hardening (not a relaxation), so it is honored under any posture. `None` ⇒ the
    /// backend default; omitted from the wire + the content hash (back-compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Isolation the workload requires; selects which backends are eligible.
    /// Default `Trusted`; omitted from the serialized
    /// spec when default, so existing specs keep their content hash.
    #[serde(default, skip_serializing_if = "IsolationRequirement::is_trusted")]
    pub isolation: IsolationRequirement,
    /// Optional **preferred** backend id (`vmm`/`container`/`cloudflare`/`docker`) — a
    /// SOFT tenant/workload preference: the scheduler honors it when the backend is in the
    /// operator-permitted + isolation-sufficient eligible set, else falls back to the next
    /// preference tier (per-project `prefer`, node `prefer`, then the source tie-break). It
    /// can never widen the operator bounds — a `prefer_backend` naming a backend the operator
    /// forbids is simply ignored. Set via `compute set --prefer-backend <id>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefer_backend: Option<String>,
    /// Optional **required** backend id — a HARD tenant/workload constraint: the workload
    /// must run on exactly this backend. If the named backend is NOT in the
    /// operator-permitted + isolation-sufficient eligible set (operator `allow`/`forbid`,
    /// the isolation posture, or the capability floor excludes it), the workload gets a
    /// **legible no-placement** — it is NEVER an escape hatch out of the operator bounds or
    /// the isolation posture (the authority split: operator policy is the outer bound,
    /// enforced BEFORE a tenant `require`/`prefer` can select). Distinct from
    /// [`prefer_backend`](Self::prefer_backend), which softly falls back; a `require_backend`
    /// that is ineligible fails closed rather than running elsewhere. Set via `compute set
    /// --require-backend <id>`. Omitted from the wire + the content hash when `None`
    /// (back-compat: existing specs keep their id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_backend: Option<String>,
    /// Optional **project-scoped registry pull credential reference** for an
    /// [`RootSource::Image`] source: the NAME of a sealed secret in THIS workload's
    /// own project secret store (`project/<proj>/secret/<name>`) whose plaintext is a
    /// JSON `{ "username": …, "password": … }` registry credential. At materialize
    /// time the host unseals it and authenticates the image pull (docker backend
    /// live; cloudflare at the deploy surface). The owning project comes from the
    /// workload's key, NEVER from this field — so a workload can only ever name a
    /// secret in its OWN project (tenancy is structural, exactly like
    /// [`ComputeBinding`]). A referenced-but-missing secret fails the pull CLOSED (no
    /// silent anonymous fallback). Only the NAME is stored here — never a credential —
    /// so it is safe on the wire and in the content hash. Ignored for a non-`Image`
    /// root. Empty/`None` ⇒ no project credential; the host then tries the operator
    /// node-wide `[compute].registry_auth` host map, else an anonymous pull. Omitted
    /// from the wire + the content hash when `None` (back-compat: existing specs keep
    /// their id; rotating the secret's VALUE never remints the spec, only its name
    /// would).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_secret: Option<String>,
    /// How a backend obtains the OCI **image** of a [`RootSource::Image`] workload before
    /// launch (see [`PullPolicy`]). The default [`PullPolicy::Always`] re-pulls from the
    /// registry every materialize — the safe posture on a node whose local image store is
    /// shared across tenants. Opting into [`PullPolicy::IfNotPresent`] /
    /// [`PullPolicy::Never`] lets a backend reuse a locally-present image (an air-gapped /
    /// `docker load`'d image) and is **sound only for a digest-pinned reference** — see the
    /// [`PullPolicy`] tenancy caveat. Ignored for a tar/rootfs source (staged from the blob
    /// store, never pulled). Omitted from the wire + the content hash when `Always`
    /// (back-compat: existing specs keep their id and an older server never sees the field).
    #[serde(default, skip_serializing_if = "PullPolicy::is_default")]
    pub pull_policy: PullPolicy,
    /// Managed resources this workload depends on — the opaque-process analogue of a
    /// handler's `imports`. boatramp resolves each to a **tenant-scoped** endpoint +
    /// credential at launch and injects the address into the guest env, so a workload
    /// reaches the managed `sql` (and, later, kv/blob/messaging) without a hand-glued
    /// URL. Empty ⇒ omitted from the wire + the content hash (back-compat).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<ComputeBinding>,
    /// Idempotent setup actions boatramp runs against this workload AFTER its runner
    /// reports up and it passes its service-readiness probe, and before the replica is
    /// marked ready (`Provisioned`) and routed to. The general, user-declared half of the
    /// post-launch primitive (a stock image's one-off init / migrate / warmup step); the
    /// managed-database `CREATE DATABASE` / role setup is a separate *derived* source that
    /// is not part of the content hash. Actions MUST be idempotent — a relaunch (crash,
    /// node move, reboot) re-enters the launch path and re-runs them (there is no
    /// first-launch marker). Empty ⇒ omitted from the wire + the content hash (back-compat).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_launch: Vec<PostLaunchAction>,
}

/// A single [`ComputeSpec::post_launch`] action. Extensible: `Exec` is the canonical
/// general kind (run a command in the launched container via the backend's `exec`);
/// future kinds (an HTTP warmup, a SQL script) are additive variants. `#[non_exhaustive]`
/// so adding one is non-breaking for downstream crates — a consumer matching on it keeps a
/// `_` arm (the runtime fails an action kind it does not understand, fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PostLaunchAction {
    /// Run a command inside the launched container via the backend's `exec` (needs a
    /// backend that supports exec — docker / native container; a backend without exec
    /// support fails the action, surfaced as the replica's provisioning failure). The
    /// command inherits the container's environment; a non-zero exit fails the action.
    Exec {
        /// The command + arguments to exec in the container.
        argv: Vec<String>,
    },
}

/// A managed-resource dependency a compute workload declares. It names a *resource*,
/// never a project: the owning project comes from the workload's key
/// (`project/<proj>/compute/<name>`), so a workload cannot request another tenant's
/// data. boatramp resolves it at launch and injects the endpoint into the guest env.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ComputeBinding {
    /// Which managed resource kind.
    pub kind: BindingKind,
    /// The named database/store within the kind (`""` = the site default, matching
    /// `sql.open("")`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The env var the resolved endpoint URL is injected as; `None` ⇒ the kind default
    /// (`sql` → `BOATRAMP_SQL_URL`). The credential is injected as `<url_env>_AUTH_TOKEN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_env: Option<String>,
    /// For a `sql` binding to a managed co-located Postgres/MySQL database only: the env var
    /// the **migration/DDL** connection URL (the owner-role analog for running schema
    /// migrations) is injected as. **Setting this field is the OPT-IN to the separate
    /// owner-login migration DSN (MEDIUM-2).** When it is `None` the migration DSN is NOT
    /// injected by default: a self-migrating app (WordPress-style) leaves it unset and uses
    /// the runtime DSN (`url_env`) — which under phase-2 operates AS the owner, so it can run
    /// its own DDL, and which revoke-on-stop cuts off when the replica stops. Set it (to the
    /// desired env var name) only for a workload that runs a DISTINCT migration step. On a
    /// per-site libsql binding (the shim path) it is ignored. An operator `env:` template
    /// referencing `{{sql.migration_dsn}}` injects the migration DSN regardless of this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_url_env: Option<String>,
}

/// The managed-resource kinds a [`ComputeBinding`] may name. `Sql`/`Kv`/`Blob`/`Messaging` each
/// have a live per-node shim resolver (`boatramp-server`'s `sql_shim`/`kv_shim`/`blob_shim`/
/// `messaging_shim`); `Invoke` (compute→function, Phase 3) is declared here per the plan but has
/// no resolver yet — a workload may declare it (it round-trips + hashes like any other binding),
/// but nothing injects its env until the Phase 3 resolver lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BindingKind {
    /// The managed `sql` database (per-site libsql, or a named external DB).
    Sql,
    /// Per-site key-value store.
    Kv,
    /// Per-site blob store.
    Blob,
    /// Per-site pub/sub + queues.
    Messaging,
    /// Function-to-function invoke (compute→function/compute, Phase 3). Declared only — no
    /// resolver yet (see the enum doc).
    Invoke,
}

impl ComputeBinding {
    /// A binding to the given managed-resource `kind` — the supported constructor
    /// (`ComputeBinding` is `#[non_exhaustive]`). Defaults: the kind's default store (`name`
    /// empty), the kind's default env var (`url_env` `None`), and no separate migration DSN
    /// (`migration_url_env` `None`). Refine with the chainable `with_*` setters.
    pub fn new(kind: BindingKind) -> Self {
        Self {
            kind,
            name: String::new(),
            url_env: None,
            migration_url_env: None,
        }
    }

    /// Set the named database/store within the kind (`""` = the site default).
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set the env var the resolved endpoint URL is injected as (`None` ⇒ the kind default).
    #[must_use]
    pub fn with_url_env(mut self, url_env: Option<String>) -> Self {
        self.url_env = url_env;
        self
    }

    /// Set the env var the migration/DDL connection URL is injected as — the opt-in to a
    /// separate owner-login migration DSN (`None` ⇒ not injected by default).
    #[must_use]
    pub fn with_migration_url_env(mut self, migration_url_env: Option<String>) -> Self {
        self.migration_url_env = migration_url_env;
        self
    }

    /// The env var the endpoint URL is injected as (explicit `url_env`, else the kind
    /// default). The auth token is injected as this name plus `_AUTH_TOKEN`.
    pub fn url_env(&self) -> String {
        self.url_env
            .clone()
            .unwrap_or_else(|| self.kind.default_url_env().to_string())
    }

    /// The env var the **migration/DDL** connection URL is injected as for a managed
    /// Postgres/MySQL `sql` binding: the explicit `migration_url_env`, else the derived
    /// default `<url_env()>_MIGRATION` (so `BOATRAMP_SQL_URL` → `BOATRAMP_SQL_URL_MIGRATION`,
    /// a custom `SIMERTEC_DATABASE_URL` → `SIMERTEC_DATABASE_URL_MIGRATION`).
    pub fn migration_url_env(&self) -> String {
        self.migration_url_env
            .clone()
            .unwrap_or_else(|| format!("{}_MIGRATION", self.url_env()))
    }
}

impl BindingKind {
    /// A **stable** 1-byte discriminant for this kind, used where a derivation must not shift if the
    /// enum is ever reordered or a variant renamed — the compute shims' token HMAC, where
    /// `format!("{:?}", kind)` would silently rotate every live token on a rename. Append-only:
    /// NEVER renumber an existing variant.
    pub fn stable_tag(self) -> u8 {
        match self {
            Self::Sql => 1,
            Self::Kv => 2,
            Self::Blob => 3,
            Self::Messaging => 4,
            Self::Invoke => 5,
        }
    }

    /// The default env var an endpoint of this kind is injected as.
    pub fn default_url_env(self) -> &'static str {
        match self {
            Self::Sql => "BOATRAMP_SQL_URL",
            Self::Kv => "BOATRAMP_KV_URL",
            Self::Blob => "BOATRAMP_BLOB_URL",
            Self::Messaging => "BOATRAMP_MESSAGING_URL",
            Self::Invoke => "BOATRAMP_INVOKE_URL",
        }
    }
}

impl ComputeSpec {
    /// The content hash of this spec — its `computever/<hash>` id. Computed over
    /// the canonical JSON so identical specs dedupe (like a deployment id).
    pub fn id(&self) -> String {
        let canonical = serde_json::to_vec(self).expect("ComputeSpec serializes");
        sha256_hex(&canonical)
    }

    /// Start building a spec from its required core — the root source + sizing + listen
    /// port. Every other field defaults (empty / `None` / the policy default) and is set with
    /// the returned [`ComputeSpecBuilder`]'s `with_*` methods. This is the supported
    /// construction path: `ComputeSpec` is `#[non_exhaustive]`, so a downstream crate cannot
    /// (and need not) use a struct literal, and a field added in a later release stays a
    /// non-breaking change.
    ///
    /// ```
    /// use boatramp_types::compute::{ComputeSpec, RootSource, PullPolicy};
    ///
    /// // A downstream crate builds a spec with NO struct literal (so a future field add is
    /// // non-breaking). Only the deviations from the defaults are set.
    /// let spec = ComputeSpec::builder(RootSource::Image("pgvector/pgvector:pg16".into()), 2, 1024, 5432)
    ///     .entrypoint(vec!["postgres".into()])
    ///     .require_backend(Some("container".into()))
    ///     .pull_policy(PullPolicy::IfNotPresent)
    ///     .build();
    /// assert_eq!(spec.vcpus, 2);
    /// assert_eq!(spec.port, 5432);
    /// assert_eq!(spec.require_backend.as_deref(), Some("container"));
    /// // Unset fields take their documented defaults.
    /// assert!(spec.env.is_empty());
    /// assert_eq!(spec.version, boatramp_types::schema_version());
    /// ```
    pub fn builder(root: RootSource, vcpus: u32, mem_mib: u32, port: u16) -> ComputeSpecBuilder {
        ComputeSpecBuilder {
            inner: Self {
                version: crate::schema_version(),
                root,
                kernel: String::new(),
                kernel_cmdline: None,
                vcpus,
                mem_mib,
                entrypoint: Vec::new(),
                env: BTreeMap::new(),
                port,
                restart: RestartPolicy::default(),
                startup_grace_secs: default_startup_grace_secs(),
                scale_to_zero: false,
                volumes: Vec::new(),
                writable_root: false,
                cap_add: Vec::new(),
                user: None,
                isolation: IsolationRequirement::default(),
                prefer_backend: None,
                require_backend: None,
                pull_secret: None,
                pull_policy: PullPolicy::default(),
                bindings: Vec::new(),
                post_launch: Vec::new(),
            },
        }
    }
}

/// Fluent builder for a [`ComputeSpec`] (`ComputeSpec::builder(...)`). Required fields are
/// taken at construction; every optional field has a `with_*` setter and otherwise keeps its
/// documented default. `build()` yields the spec. The ergonomic construction path for
/// downstream crates now that [`ComputeSpec`] is `#[non_exhaustive]`.
#[derive(Debug, Clone)]
pub struct ComputeSpecBuilder {
    inner: ComputeSpec,
}

impl ComputeSpecBuilder {
    /// Override the schema version (defaults to the current [`crate::schema_version`]).
    #[must_use]
    pub fn version(mut self, version: u32) -> Self {
        self.inner.version = version;
        self
    }
    /// Set the kernel blob hash (micro-VM source only; empty ⇒ absent).
    #[must_use]
    pub fn kernel(mut self, kernel: impl Into<String>) -> Self {
        self.inner.kernel = kernel.into();
        self
    }
    /// Set the kernel boot cmdline override.
    #[must_use]
    pub fn kernel_cmdline(mut self, cmdline: Option<String>) -> Self {
        self.inner.kernel_cmdline = cmdline;
        self
    }
    /// Set the in-guest entrypoint (argv).
    #[must_use]
    pub fn entrypoint(mut self, entrypoint: Vec<String>) -> Self {
        self.inner.entrypoint = entrypoint;
        self
    }
    /// Set the entrypoint environment.
    #[must_use]
    pub fn env(mut self, env: BTreeMap<String, String>) -> Self {
        self.inner.env = env;
        self
    }
    /// Set the restart policy.
    #[must_use]
    pub fn restart(mut self, restart: RestartPolicy) -> Self {
        self.inner.restart = restart;
        self
    }
    /// Set the startup grace (seconds).
    #[must_use]
    pub fn startup_grace_secs(mut self, secs: u32) -> Self {
        self.inner.startup_grace_secs = secs;
        self
    }
    /// Enable snapshot-and-stop-when-idle (scale to zero).
    #[must_use]
    pub fn scale_to_zero(mut self, scale_to_zero: bool) -> Self {
        self.inner.scale_to_zero = scale_to_zero;
        self
    }
    /// Set the persistent volumes.
    #[must_use]
    pub fn volumes(mut self, volumes: Vec<VolumeRef>) -> Self {
        self.inner.volumes = volumes;
        self
    }
    /// Allow a writable root filesystem (single-tenant only).
    #[must_use]
    pub fn writable_root(mut self, writable_root: bool) -> Self {
        self.inner.writable_root = writable_root;
        self
    }
    /// Set the added Linux capabilities (single-tenant only).
    #[must_use]
    pub fn cap_add(mut self, cap_add: Vec<String>) -> Self {
        self.inner.cap_add = cap_add;
        self
    }
    /// Run the entrypoint as this `uid`/`uid:gid`.
    #[must_use]
    pub fn user(mut self, user: Option<String>) -> Self {
        self.inner.user = user;
        self
    }
    /// Set the required isolation.
    #[must_use]
    pub fn isolation(mut self, isolation: IsolationRequirement) -> Self {
        self.inner.isolation = isolation;
        self
    }
    /// Set the soft preferred backend id.
    #[must_use]
    pub fn prefer_backend(mut self, prefer_backend: Option<String>) -> Self {
        self.inner.prefer_backend = prefer_backend;
        self
    }
    /// Set the hard required backend id.
    #[must_use]
    pub fn require_backend(mut self, require_backend: Option<String>) -> Self {
        self.inner.require_backend = require_backend;
        self
    }
    /// Set the project-scoped registry pull-credential secret name.
    #[must_use]
    pub fn pull_secret(mut self, pull_secret: Option<String>) -> Self {
        self.inner.pull_secret = pull_secret;
        self
    }
    /// Set the image pull policy.
    #[must_use]
    pub fn pull_policy(mut self, pull_policy: PullPolicy) -> Self {
        self.inner.pull_policy = pull_policy;
        self
    }
    /// Set the managed-resource bindings.
    #[must_use]
    pub fn bindings(mut self, bindings: Vec<ComputeBinding>) -> Self {
        self.inner.bindings = bindings;
        self
    }
    /// Set the post-launch actions.
    #[must_use]
    pub fn post_launch(mut self, post_launch: Vec<PostLaunchAction>) -> Self {
        self.inner.post_launch = post_launch;
        self
    }
    /// Finish building the [`ComputeSpec`].
    #[must_use]
    pub fn build(self) -> ComputeSpec {
        self.inner
    }
}

/// Placement constraints: where a workload's replicas may run. `#[non_exhaustive]`:
/// construct via [`PlacementConstraints::new`] + the `with_*` setters so a future
/// placement axis (anti-affinity, spread, taints/tolerations) stays non-breaking for
/// downstream crates (the sibling [`Priority`] follows the same contract).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct PlacementConstraints {
    /// If non-empty, only nodes in one of these regions are eligible.
    pub regions: Vec<String>,
    /// Required node labels (all must match a node's advertised labels).
    pub labels: BTreeMap<String, String>,
}

impl PlacementConstraints {
    /// The empty (unconstrained) placement — any node is eligible. The supported
    /// constructor now that `PlacementConstraints` is `#[non_exhaustive]`; refine with the
    /// chainable `with_*` setters rather than a struct literal, so a later axis is additive.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict placement to nodes in one of these regions (empty ⇒ any region).
    #[must_use]
    pub fn with_regions(mut self, regions: Vec<String>) -> Self {
        self.regions = regions;
        self
    }

    /// Require these node labels (all must match a node's advertised labels).
    #[must_use]
    pub fn with_labels(mut self, labels: BTreeMap<String, String>) -> Self {
        self.labels = labels;
        self
    }

    /// Whether a node with `node_region` + `node_labels` satisfies these
    /// constraints.
    pub fn allows(
        &self,
        node_region: Option<&str>,
        node_labels: &BTreeMap<String, String>,
    ) -> bool {
        if !self.regions.is_empty() {
            match node_region {
                Some(r) if self.regions.iter().any(|want| want == r) => {}
                _ => return false,
            }
        }
        self.labels
            .iter()
            .all(|(k, v)| node_labels.get(k).is_some_and(|nv| nv == v))
    }
}

/// A workload's **scheduling priority** — a two-axis key carried on the MUTABLE
/// [`ComputeWorkload`] (NEVER on the content-addressed [`ComputeSpec`]). Putting it here is
/// deliberate: a reprioritize is a cheap pointer update, not a spec remint — if priority lived
/// on the spec, bumping it would mint a new content hash and force a stop+relaunch of every
/// replica (catastrophic for a running service), and it would not even BE a priority of the
/// workload but of a frozen artifact. The two axes have different owners:
///
/// - **`class`** — the operator-owned, cross-tenant TIER name (`system` / `standard` / `spot`,
///   resolved against the node's [`crate` operator catalog]). `None` ⇒ the operator default
///   class (`standard`). A project can only request a class at or below its per-project
///   CEILING (default `standard`); the server refuses a request above it fail-closed, so a
///   tenant can never self-assign `system`. The class decides preemption AUTHORITY across
///   tenants.
/// - **`rank`** — a tenant-owned `i32` that orders a tenant's OWN workloads only. Because the
///   global placement comparator sorts by `operator_tier → project → rank → name`, a tenant's
///   huge `rank` reshuffles only its own workloads and can NEVER leapfrog another project — the
///   fairness boundary is the key ORDERING, not a runtime check.
///
/// `min_available` is the PodDisruptionBudget-equivalent: preemption refuses to drop a victim
/// workload below this many running replicas (a HARD floor within its own project/tier; only
/// ADVISORY to a strictly-higher operator tier, so a `system` workload can still displace a
/// node-hogging `spot`/`standard` rather than deadlock). `None` ⇒ the class-derived default.
///
/// An existing stored workload (written before this field) deserializes to the all-default
/// `Priority` — class `None` (⇒ operator default `standard`), rank `0`, no `min_available` — so
/// turning the feature on changes the relative order of NOTHING and evicts NOTHING on upgrade
/// (the least-surprise invariant). `#[non_exhaustive]`: construct via [`Priority::new`] +
/// `with_*` so a future axis stays non-breaking.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct Priority {
    /// The operator-owned cross-tenant class/tier NAME. `None` ⇒ the operator default class
    /// (`standard`). A project may only name a class at or below its ceiling; the server
    /// refuses a higher one fail-closed at `compute set`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// The tenant-owned rank — orders a tenant's OWN workloads only (higher wins). `0` default.
    /// Because `project` outranks `rank` in the global comparator, it can never leapfrog
    /// another project.
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub rank: i32,
    /// The minimum running replicas preemption must leave this workload — the PDB-equivalent
    /// floor. `None` ⇒ the class-derived default (`spot`→0, `standard`/`system`→protected at
    /// `replicas`). HARD within-project/same-tier; ADVISORY to a strictly-higher operator tier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_available: Option<u32>,
}

/// Omit a zero `rank` from the serialized workload (back-compat: an existing workload stays
/// byte-identical, schema v1).
fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

impl Priority {
    /// The all-default priority: operator default class (`None` ⇒ `standard`), rank 0, no
    /// explicit `min_available`. The value every pre-feature workload deserializes to.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the operator-owned class/tier name (`None` ⇒ the operator default).
    #[must_use]
    pub fn with_class(mut self, class: Option<String>) -> Self {
        self.class = class;
        self
    }

    /// Set the tenant-owned rank (orders the tenant's own workloads only).
    #[must_use]
    pub fn with_rank(mut self, rank: i32) -> Self {
        self.rank = rank;
        self
    }

    /// Set the minimum-available floor (`None` ⇒ the class-derived default).
    #[must_use]
    pub fn with_min_available(mut self, min_available: Option<u32>) -> Self {
        self.min_available = min_available;
        self
    }

    /// The requested class name, or `None` for the operator default.
    pub fn class(&self) -> Option<&str> {
        self.class.as_deref()
    }

    /// The tenant rank.
    pub fn rank(&self) -> i32 {
        self.rank
    }

    /// The explicit `min_available` floor, if any.
    pub fn min_available(&self) -> Option<u32> {
        self.min_available
    }

    /// Whether this is the all-default priority — used to omit it from the serialized workload
    /// so an existing record stays byte-identical (schema v1, zero churn on upgrade).
    pub fn is_default(&self) -> bool {
        self.class.is_none() && self.rank == 0 && self.min_available.is_none()
    }
}

/// The mutable desired state for a workload (`compute/<name>`): the active spec
/// version, replica count, and placement. Activation is a pointer flip to a new
/// spec hash — the same atomic, roll-back-able model as a site deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeWorkload {
    /// Pinned schema discriminant (`v1`).
    #[serde(default = "crate::schema_version")]
    pub version: u32,
    /// Human label (the workload name is the KV key).
    pub name: String,
    /// The active [`ComputeSpec`] content hash (`computever/<hash>`).
    pub active: String,
    /// Desired replica count.
    pub replicas: u32,
    /// Placement constraints.
    #[serde(default)]
    pub placement: PlacementConstraints,
    /// Scheduling [`Priority`] — the operator class/tier + tenant rank + min-available floor.
    /// A cheap pointer update (never a spec remint). Omitted from the wire when all-default, so
    /// an existing stored workload stays byte-identical and deserializes to the default
    /// (`standard`, rank 0) — zero churn/eviction on upgrade. `#[serde(default)]` keeps older
    /// records (no field) deserializing — schema stays v1.
    #[serde(default, skip_serializing_if = "Priority::is_default")]
    pub priority: Priority,
}

/// The default replica count for a workload (1) — a service runs one replica
/// unless the manifest / request asks for more.
pub fn default_replicas() -> u32 {
    1
}

/// The body of `PUT /api/compute/:name` — an immutable [`ComputeSpec`] plus the
/// desired replica count and [`PlacementConstraints`]. This is the SINGLE typed
/// schema for a compute workload's desired state: both the server handler
/// (`put_compute`) and the client manifest ([`crate::…::ApplyCompute`] mirrors
/// these fields) deserialize into it, so there is no schema duplication and the
/// client can fail fast on a malformed spec BEFORE the request leaves the host.
/// The server still runs its own semantic validation (kernel defaulting, name
/// screening) on top — the typed client parse is an additive gate, not a
/// replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutComputeRequest {
    /// The immutable workload spec (rootfs/kernel blob hashes + sizing).
    pub spec: ComputeSpec,
    /// Desired replica count (default 1).
    #[serde(default = "default_replicas")]
    pub replicas: u32,
    /// Placement constraints.
    #[serde(default)]
    pub placement: PlacementConstraints,
    /// Scheduling [`Priority`] carried onto the stored [`ComputeWorkload`] (NOT the
    /// content-addressed spec). **`None` ⇒ PRESERVE** the stored workload's existing priority: a
    /// spec/replica change (or a manifest `apply`) that OMITS priority must never silently demote
    /// a previously-set `class`/`rank` back to the default. For a brand-NEW workload with no
    /// stored priority, `None` resolves to [`Priority::default`] (`standard`, rank 0). `Some(p)`
    /// sets the priority explicitly — the server still validates the requested `class` against
    /// the project's ceiling fail-closed before storing it. Omitted from the wire when `None`
    /// (back-compat: an older client that never sends the field deserializes to `None` ⇒
    /// preserve/default, and an older server that does not know the field never sees it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,
}

// ---------------------------------------------------------------------------
// Declarative managed-database surface (v0.6.0, #501 Stage B).
// ---------------------------------------------------------------------------

/// The engine a declared managed database runs — the SAFE, typed subset of the
/// node-static `ExternalDatabaseConfig.kind` string. A manifest may only declare an
/// engine boatramp fully manages (provisions + seals the credential for): Postgres
/// or MySQL. `libsql` is deliberately absent — the embedded engine is the per-site
/// default and needs no declaration, and its `path` source is host-fs (excluded).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplyDatabaseKind {
    /// PostgreSQL (lowered to `ExternalDatabaseConfig.kind = "postgres"`).
    Postgres,
    /// MySQL (lowered to `ExternalDatabaseConfig.kind = "mysql"`).
    Mysql,
}

impl ApplyDatabaseKind {
    /// The node-static `ExternalDatabaseConfig.kind` string this lowers to.
    pub fn as_config_kind(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Mysql => "mysql",
        }
    }
}

/// How a declared managed database is physically isolated per tenant — the typed
/// projection of `ExternalDatabaseConfig.tenant` (`TenantIsolation`). `Single` = a
/// dedicated server (container) per tenant; `Shared` = one server hosting a
/// per-tenant database + login role (grant-isolated).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplyDatabaseTenant {
    /// A dedicated database server (its own container) per tenant. The default.
    #[default]
    Single,
    /// One shared server hosting a per-tenant database + role (grant-isolated).
    Shared,
}

/// The grain of a tenant for a declared managed database — the typed projection of
/// `ExternalDatabaseConfig.tenant_scope` (`TenantScope`). `Project` (default) or
/// `Site`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplyDatabaseScope {
    /// A tenant is a **project** (the default).
    #[default]
    Project,
    /// A tenant is a **site** (finer than project).
    Site,
}

/// How "ready" a managed-DB replica must be before a surface treats it as usable — the
/// configurable readiness gate (v0.45.0). The strict default, [`Provisioned`], means the
/// replica has completed its post-launch provisioning (its `CREATE DATABASE` / role DDL).
/// Relaxed to [`ServiceReady`], a surface uses the replica as soon as it answers a real
/// `SELECT 1`, before provisioning has finished. Shared between the manifest
/// [`ApplyDatabase`] and the serving `ExternalDatabaseConfig`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLevel {
    /// Require full post-launch provisioning (the strict default).
    #[default]
    Provisioned,
    /// Require only that the service answers `SELECT 1` (relaxed).
    ServiceReady,
}

/// Per-surface readiness gate for a managed database (v0.45.0). Each surface defaults to
/// [`ReadinessLevel::Provisioned`]; an operator may relax any one independently:
/// - `answerability` — gateway/internal-DNS: whether a replica is an answerable upstream.
/// - `routing` — the handler-runtime SQL connection: whether a request is routed to it.
/// - `migration` — operator `sql exec` / `migrate` / `ensure`-await (container-backed DBs).
///
/// `#[non_exhaustive]`: a new readiness *surface* is an additive field, so downstream crates
/// construct it via [`ReadinessGate::new`] + the `with_*` setters rather than a struct literal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ReadinessGate {
    /// Gate for gateway/internal-DNS answerability. The strict default (`Provisioned`) is
    /// honored across all workloads today; per-DB relaxation to `service_ready` for this
    /// surface is a follow-up (the node-global DNS source must become config-aware first).
    pub answerability: ReadinessLevel,
    /// Gate for request-path handler SQL routing.
    pub routing: ReadinessLevel,
    /// Gate for operator migration/ensure (container-backed DBs).
    pub migration: ReadinessLevel,
}

impl ReadinessGate {
    /// The all-strict gate (every surface [`ReadinessLevel::Provisioned`]) — the default.
    /// The supported constructor now that `ReadinessGate` is `#[non_exhaustive]`; relax a
    /// surface with the chainable `with_*` setters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the gateway/internal-DNS answerability gate.
    #[must_use]
    pub fn with_answerability(mut self, level: ReadinessLevel) -> Self {
        self.answerability = level;
        self
    }

    /// Set the request-path handler SQL routing gate.
    #[must_use]
    pub fn with_routing(mut self, level: ReadinessLevel) -> Self {
        self.routing = level;
        self
    }

    /// Set the operator migration/ensure gate.
    #[must_use]
    pub fn with_migration(mut self, level: ReadinessLevel) -> Self {
        self.migration = level;
        self
    }
}

/// A coarse sizing **preset** for a declared managed database — NOT raw VM knobs.
/// The manifest author picks a t-shirt size; boatramp maps it to concrete
/// vcpus/mem/volume at lowering time (see [`ApplyDatabaseSize::resources`]), so the
/// declarative surface never exposes an unbounded resource request (the errno-28
/// disk-full / DoS guard). Default `Small`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplyDatabaseSize {
    /// 1 vCPU / 512 MiB / 10 GiB volume — the default, matching the stock
    /// `managed_db_spec` sizing.
    #[default]
    Small,
    /// 2 vCPU / 2 GiB / 50 GiB volume.
    Medium,
    /// 4 vCPU / 8 GiB / 200 GiB volume.
    Large,
}

/// How a managed-DB **config change that only takes effect at server start** is applied
/// (e.g. toggling `delta_capture`, which flips `wal_level`/binlog in the launch argv and so
/// remints the content-addressed spec). The change is always STAGED by rolling the workload's
/// active spec; this policy decides whether the DB is also restarted to adopt it NOW.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbRestartPolicy {
    /// Stage the change and mark the DB "restart pending" — the operator restarts it
    /// explicitly (`boatramp db restart`) at a chosen time. The safe default: a managed DB
    /// holds production data, so never cause surprise downtime on a config re-apply.
    #[default]
    Manual,
    /// Apply the change and restart the DB immediately so it takes effect at once (brief
    /// downtime while the container relaunches onto the reattached data volume).
    Auto,
}

impl DbRestartPolicy {
    /// Whether a staged restart-requiring change should restart the DB immediately.
    #[must_use]
    pub fn is_auto(self) -> bool {
        matches!(self, Self::Auto)
    }
}

impl ApplyDatabaseSize {
    /// The `(vcpus, mem_mib, volume_size_mib)` this preset maps to. The single
    /// authority for the preset → resources mapping, so the CLI (rendering) and the
    /// server (lowering) agree. Deliberately bounded: `Large` is the ceiling a
    /// manifest can request — there is no raw-knob escape hatch.
    pub fn resources(self) -> (u32, u32, u32) {
        match self {
            // (vcpus, mem_mib, volume_size_mib)
            Self::Small => (1, 512, 10 * 1024),
            Self::Medium => (2, 2 * 1024, 50 * 1024),
            Self::Large => (4, 8 * 1024, 200 * 1024),
        }
    }
}

/// The operator ceilings a declared database's optional tuning knobs are CAPPED to
/// (a DoS / resource guard — the manifest author can lower a knob, never raise it
/// past the ceiling). Applied at lowering time in `boatramp-node`; centralized here
/// so the cap is one authority.
pub mod apply_db_caps {
    /// Maximum `pool_max` a manifest may request (connections). A too-large pool
    /// exhausts the server's connection slots.
    pub const MAX_POOL: u32 = 64;
    /// Maximum `connect_timeout_secs` a manifest may request.
    pub const MAX_CONNECT_TIMEOUT_SECS: u64 = 60;
    /// Maximum `startup_grace_secs` a manifest may request (bounds how long a
    /// never-healthy replica is left running before the reconcile relaunches it).
    pub const MAX_STARTUP_GRACE_SECS: u32 = 600;

    /// Default operator ceiling on the **number** of declared databases a single
    /// project may hold (#501 Stage B MEDIUM-1 — the disk-exhaustion / errno-28 guard).
    /// Each declared DB eagerly provisions a 10–200 GiB volume, so without a per-project
    /// cap a `Project·Admin` could declare an unbounded number and exhaust the node's
    /// disk. Operator-overridable via `handlers.bindings.sql.max_declared_databases`;
    /// enforced fail-closed at `declare`.
    pub const DEFAULT_MAX_DECLARED_DATABASES_PER_PROJECT: usize = 16;

    /// Default operator ceiling on the **aggregate provisioned volume** (MiB) across all
    /// of a project's declared databases (#501 Stage B MEDIUM-1). 512 GiB — comfortably
    /// above the 16-DB count cap at the Small preset (16 × 10 GiB = 160 GiB) yet a hard
    /// backstop against a handful of Large (200 GiB) declarations. Operator-overridable
    /// via `handlers.bindings.sql.max_declared_volume_mib`; enforced fail-closed at
    /// `declare` by summing the existing declarations' volumes + the incoming one.
    pub const DEFAULT_MAX_DECLARED_VOLUME_MIB: u64 = 512 * 1024;
}

/// A **declared managed database** in an [`ApplyManifest`](crate) `databases:` block
/// (v0.6.0, #501 Stage B). This is a TYPED PROJECTION of the node-static
/// `ExternalDatabaseConfig` restricted to the fields that are SAFE for a project
/// author to declare — the security contract.
///
/// # The security contract (what is DELIBERATELY absent)
///
/// A declared database is DEFINITIONALLY the "boatramp fully manages + seals the
/// credential" path: it carries **no** secret / env-var / URL / host-fs / image
/// field, so a manifest can neither reference a secret nor pick an arbitrary OCI
/// image. The EXCLUDED fields (NOT part of this struct — that exclusion IS the
/// contract):
///
/// - `image` — arbitrary-OCI RCE (no allowlist); boatramp always picks the stock
///   engine image at lowering.
/// - `password_env` — omitting it is what selects the managed-credential path
///   (`ExternalDatabaseConfig::is_managed_credential`); a declared DB can NEVER bring
///   its own password.
/// - `url_env` / `read_url_env` / `migration_url_env` — BYO-secret / SSRF /
///   arbitrary-host reach.
/// - `path` — host-fs traversal.
/// - `compute` — the manifest does NOT let the author name an arbitrary compute
///   workload; boatramp DERIVES the per-project managed DB server workload name at
///   lowering, so a manifest can only ever provision onto its own project's server.
///
/// The struct uses `deny_unknown_fields` so a manifest that tries to smuggle one of
/// the excluded keys fails to parse rather than being silently ignored.
///
/// `#[non_exhaustive]`: the declarative manifest surface grows new SAFE knobs over time, so
/// downstream crates build it via [`ApplyDatabase::new`] + the chainable `with_*` setters
/// rather than a struct literal — a later knob is then an additive, non-breaking field. The
/// two genuinely-required fields (`name`, `kind` — no serde default) are constructor
/// arguments; every optional knob defaults to its serde default, so `new(name, kind)` yields
/// exactly what deserializing a minimal `{name, kind}` manifest would (prior behavior).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ApplyDatabase {
    /// The binding name — how a guest reaches it via `sql.open("<name>")` and the
    /// `{name}` path segment of the `project/{project}/database/{name}` store key.
    pub name: String,
    /// The engine (Postgres or MySQL). Lowered to `ExternalDatabaseConfig.kind`.
    pub kind: ApplyDatabaseKind,
    /// The engine major version (e.g. `16` for Postgres). Advisory metadata carried
    /// on the stored binding; a version CHANGE on re-apply routes through the
    /// owner-gated migrate/repair path (never a silent re-init). `None` ⇒ the engine
    /// default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// Trusted extensions to make available (Postgres). Advisory metadata; enabling
    /// one still routes through the owner-gated migration `Extension` step +
    /// operator allowlist — this does NOT bypass that gate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    /// Coarse sizing preset (`small`/`medium`/`large`). Maps to bounded
    /// vcpus/mem/volume at lowering — NOT raw VM knobs.
    #[serde(default)]
    pub size: ApplyDatabaseSize,
    /// Isolation mechanism (`single` = dedicated container per tenant; `shared` =
    /// one server, per-tenant db + role). Lowered to `ExternalDatabaseConfig.tenant`.
    /// A CHANGE on re-apply is REFUSED (silent data-loss/orphan guard).
    #[serde(default)]
    pub tenant: ApplyDatabaseTenant,
    /// Tenant grain (`project`/`site`). Lowered to
    /// `ExternalDatabaseConfig.tenant_scope`. A CHANGE on re-apply is REFUSED.
    #[serde(default)]
    pub tenant_scope: ApplyDatabaseScope,
    /// Open every transaction `READ ONLY`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read_only: bool,
    /// Opt-in native-RLS session injection (`rls_session`). See
    /// `ExternalDatabaseConfig.rls_session`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rls_session: bool,
    /// The Postgres session GUC for the host-resolved tenant (RLS backstop). Only
    /// honored with `rls_session` on + Postgres.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_guc: Option<String>,
    /// The session GUC for the anonymous session axis (RLS backstop).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_guc: Option<String>,
    /// The reserved sentinel written to `tenant_guc` on an `all`-scoped read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_all_marker: Option<String>,
    /// Maximum pooled connections. CAPPED to [`apply_db_caps::MAX_POOL`] at lowering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_max: Option<u32>,
    /// Connection/acquire timeout in seconds. CAPPED to
    /// [`apply_db_caps::MAX_CONNECT_TIMEOUT_SECS`] at lowering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_secs: Option<u64>,
    /// Startup grace in seconds for the managed server's first `initdb`. CAPPED to
    /// [`apply_db_caps::MAX_STARTUP_GRACE_SECS`] at lowering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_grace_secs: Option<u32>,
    /// The per-surface **readiness gate** (v0.45.0): the readiness level each surface
    /// requires before treating a replica as usable. Default: every surface `provisioned`
    /// (strict). Passes through to the serving config unchanged.
    #[serde(default, skip_serializing_if = "readiness_gate_is_default")]
    pub readiness_gate: ReadinessGate,
    /// **Opt-in** (default `false`): enable row-level change capture on this managed DB so it
    /// can be the source of an incremental/delta export's SQL true-delta (Postgres logical WAL
    /// / MySQL binlog). Flips `wal_level=logical` / `--log-bin` in the launch argv, so turning
    /// it on remints the spec and needs a restart (see `restart_policy`). Off ⇒ no WAL/binlog
    /// cost; a delta export of this DB falls back to a full dump. Ignored for a bring-your-own DB.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub delta_capture: bool,
    /// How a restart-requiring config change (e.g. toggling `delta_capture`) is applied —
    /// `manual` (default: stage + mark pending) or `auto` (apply + restart now).
    #[serde(default, skip_serializing_if = "restart_policy_is_default")]
    pub restart_policy: DbRestartPolicy,
}

impl ApplyDatabase {
    /// A declared database named `name` running engine `kind`, with every optional knob at
    /// its serde default — identical to deserializing a minimal `{ name, kind }` manifest
    /// (no version pin, no extensions, `small`, `single`/`project`, read-write, RLS off, no
    /// pool/timeout/grace overrides, all-`provisioned` readiness, no delta-capture, `manual`
    /// restart). The supported constructor now that `ApplyDatabase` is `#[non_exhaustive]`;
    /// refine with the chainable `with_*` setters.
    #[must_use]
    pub fn new(name: String, kind: ApplyDatabaseKind) -> Self {
        Self {
            name,
            kind,
            version: None,
            extensions: Vec::new(),
            size: ApplyDatabaseSize::default(),
            tenant: ApplyDatabaseTenant::default(),
            tenant_scope: ApplyDatabaseScope::default(),
            read_only: false,
            rls_session: false,
            tenant_guc: None,
            session_guc: None,
            tenant_all_marker: None,
            pool_max: None,
            connect_timeout_secs: None,
            startup_grace_secs: None,
            readiness_gate: ReadinessGate::default(),
            delta_capture: false,
            restart_policy: DbRestartPolicy::default(),
        }
    }

    /// Pin the engine major version (`None` ⇒ the engine default).
    #[must_use]
    pub fn with_version(mut self, version: Option<u32>) -> Self {
        self.version = version;
        self
    }

    /// Request trusted extensions (still owner-gated at the migration step).
    #[must_use]
    pub fn with_extensions(mut self, extensions: Vec<String>) -> Self {
        self.extensions = extensions;
        self
    }

    /// Set the coarse sizing preset (default `small`).
    #[must_use]
    pub fn with_size(mut self, size: ApplyDatabaseSize) -> Self {
        self.size = size;
        self
    }

    /// Set the per-tenant isolation mechanism (default `single`).
    #[must_use]
    pub fn with_tenant(mut self, tenant: ApplyDatabaseTenant) -> Self {
        self.tenant = tenant;
        self
    }

    /// Set the tenant grain (default `project`).
    #[must_use]
    pub fn with_tenant_scope(mut self, tenant_scope: ApplyDatabaseScope) -> Self {
        self.tenant_scope = tenant_scope;
        self
    }

    /// Open every transaction `READ ONLY` (default `false`).
    #[must_use]
    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Opt in to native-RLS session injection (default `false`).
    #[must_use]
    pub fn with_rls_session(mut self, rls_session: bool) -> Self {
        self.rls_session = rls_session;
        self
    }

    /// Set the Postgres session GUC for the host-resolved tenant (`None` ⇒ unset).
    #[must_use]
    pub fn with_tenant_guc(mut self, tenant_guc: Option<String>) -> Self {
        self.tenant_guc = tenant_guc;
        self
    }

    /// Set the session GUC for the anonymous session axis (`None` ⇒ unset).
    #[must_use]
    pub fn with_session_guc(mut self, session_guc: Option<String>) -> Self {
        self.session_guc = session_guc;
        self
    }

    /// Set the reserved sentinel written to `tenant_guc` on an `all`-scoped read.
    #[must_use]
    pub fn with_tenant_all_marker(mut self, tenant_all_marker: Option<String>) -> Self {
        self.tenant_all_marker = tenant_all_marker;
        self
    }

    /// Set the maximum pooled connections (capped at lowering; `None` ⇒ the default).
    #[must_use]
    pub fn with_pool_max(mut self, pool_max: Option<u32>) -> Self {
        self.pool_max = pool_max;
        self
    }

    /// Set the connection/acquire timeout seconds (capped at lowering; `None` ⇒ default).
    #[must_use]
    pub fn with_connect_timeout_secs(mut self, connect_timeout_secs: Option<u64>) -> Self {
        self.connect_timeout_secs = connect_timeout_secs;
        self
    }

    /// Set the first-`initdb` startup grace seconds (capped at lowering; `None` ⇒ default).
    #[must_use]
    pub fn with_startup_grace_secs(mut self, startup_grace_secs: Option<u32>) -> Self {
        self.startup_grace_secs = startup_grace_secs;
        self
    }

    /// Set the per-surface readiness gate (default: every surface `provisioned`).
    #[must_use]
    pub fn with_readiness_gate(mut self, readiness_gate: ReadinessGate) -> Self {
        self.readiness_gate = readiness_gate;
        self
    }

    /// Opt in to row-level change capture for delta exports (default `false`).
    #[must_use]
    pub fn with_delta_capture(mut self, delta_capture: bool) -> Self {
        self.delta_capture = delta_capture;
        self
    }

    /// Set how a restart-requiring config change is applied (default `manual`).
    #[must_use]
    pub fn with_restart_policy(mut self, restart_policy: DbRestartPolicy) -> Self {
        self.restart_policy = restart_policy;
        self
    }
}

/// Omit `restart_policy` from a serialized manifest when it is the `manual` default.
fn restart_policy_is_default(p: &DbRestartPolicy) -> bool {
    *p == DbRestartPolicy::default()
}

/// Omit `readiness_gate` from a serialized manifest when it is the all-`provisioned`
/// default (manifest hygiene — the common case writes nothing).
fn readiness_gate_is_default(g: &ReadinessGate) -> bool {
    *g == ReadinessGate::default()
}

impl ApplyDatabase {
    /// The identity fields a re-apply may NEVER change (silent data-loss / orphan
    /// guard): `kind`, `tenant`, `tenant_scope`. (There is no author-supplied
    /// `compute` to compare — boatramp derives it, so it cannot drift.) Returns the
    /// first differing field name, or `None` if the two declarations agree on all
    /// identity fields. `version`/`extensions`/`size`/rls-knobs are intentionally NOT
    /// compared — those route through migrate/repair or are documented re-tuning.
    pub fn identity_change(&self, prior: &Self) -> Option<&'static str> {
        if self.kind != prior.kind {
            return Some("kind");
        }
        if self.tenant != prior.tenant {
            return Some("tenant");
        }
        if self.tenant_scope != prior.tenant_scope {
            return Some("tenant_scope");
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_without_priority_deserializes_to_default_and_omits_it_on_the_wire() {
        // An existing stored workload (pre-priority) has no `priority` field — it must
        // deserialize to the all-default Priority (class None ⇒ standard, rank 0), so turning
        // the feature on reorders/evicts nothing.
        let json = r#"{"version":1,"name":"w","active":"h","replicas":2}"#;
        let wl: ComputeWorkload = serde_json::from_str(json).expect("back-compat deserialize");
        assert!(wl.priority.is_default());
        assert_eq!(wl.priority.class(), None);
        assert_eq!(wl.priority.rank(), 0);
        // A default-priority workload re-serializes WITHOUT a `priority` field (schema stays v1,
        // byte-identical to the pre-feature record).
        let out = serde_json::to_string(&wl).unwrap();
        assert!(
            !out.contains("priority"),
            "default priority is omitted: {out}"
        );

        // A non-default priority round-trips.
        let mut wl2 = wl.clone();
        wl2.priority = Priority::new()
            .with_class(Some("spot".into()))
            .with_rank(-5)
            .with_min_available(Some(1));
        let s = serde_json::to_string(&wl2).unwrap();
        assert!(s.contains("spot") && s.contains("-5"));
        let back: ComputeWorkload = serde_json::from_str(&s).unwrap();
        assert_eq!(back.priority.class(), Some("spot"));
        assert_eq!(back.priority.rank(), -5);
        assert_eq!(back.priority.min_available(), Some(1));
    }

    #[test]
    fn put_request_priority_is_option_with_preserve_on_omit_back_compat() {
        // FIND #2 wire contract. `PutComputeRequest.priority` is `Option<Priority>`: `None` is the
        // PRESERVE sentinel (the server keeps the stored workload's priority), `Some` an explicit
        // set. The distinction must survive serde.

        // An older client that never sends the field ⇒ `None` (preserve) — not a forced default,
        // so a spec/replica-only put never silently demotes a stored class.
        let old_client = r#"{"spec":{"version":1,"root":{"image":"nginx:1"},"vcpus":1,"mem_mib":256,"port":80},"replicas":3}"#;
        let req: PutComputeRequest =
            serde_json::from_str(old_client).expect("omitted priority ⇒ None");
        assert!(
            req.priority.is_none(),
            "an omitted priority deserializes to None (preserve)"
        );

        // `None` serializes WITHOUT the field (an older server never sees it).
        let omit = PutComputeRequest {
            spec: req.spec.clone(),
            replicas: 3,
            placement: PlacementConstraints::default(),
            priority: None,
        };
        let s_omit = serde_json::to_string(&omit).unwrap();
        assert!(
            !s_omit.contains("priority"),
            "None omits the field: {s_omit}"
        );
        assert!(
            serde_json::from_str::<PutComputeRequest>(&s_omit)
                .unwrap()
                .priority
                .is_none()
        );

        // An explicit priority ⇒ `Some(p)`, round-tripping class + rank.
        let set = PutComputeRequest {
            spec: req.spec.clone(),
            replicas: 1,
            placement: PlacementConstraints::default(),
            priority: Some(
                Priority::new()
                    .with_class(Some("system".into()))
                    .with_rank(3),
            ),
        };
        let s_set = serde_json::to_string(&set).unwrap();
        assert!(s_set.contains("system") && s_set.contains("\"rank\":3"));
        let back: PutComputeRequest = serde_json::from_str(&s_set).unwrap();
        assert_eq!(
            back.priority.as_ref().and_then(|p| p.class()),
            Some("system")
        );
        assert_eq!(back.priority.as_ref().map(Priority::rank), Some(3));

        // `Some(default)` is DISTINCT from `None` on the wire: an explicit "set to standard/0"
        // serializes to an empty object and round-trips to `Some(default)` — not preserve.
        let set_default = PutComputeRequest {
            spec: req.spec,
            replicas: 1,
            placement: PlacementConstraints::default(),
            priority: Some(Priority::default()),
        };
        let s_def = serde_json::to_string(&set_default).unwrap();
        assert!(
            s_def.contains("\"priority\":{}"),
            "an explicit default priority is an empty object (distinct from omitted): {s_def}"
        );
        assert_eq!(
            serde_json::from_str::<PutComputeRequest>(&s_def)
                .unwrap()
                .priority,
            Some(Priority::default())
        );
    }

    fn spec() -> ComputeSpec {
        ComputeSpec {
            version: crate::SCHEMA_VERSION,
            root: RootSource::Rootfs("a".repeat(64)),
            kernel: "b".repeat(64),
            kernel_cmdline: None,
            vcpus: 2,
            mem_mib: 512,
            entrypoint: vec!["/app".into(), "--serve".into()],
            env: BTreeMap::from([("PORT".to_string(), "8080".to_string())]),
            port: 8080,
            restart: RestartPolicy::Always,
            startup_grace_secs: 30,
            scale_to_zero: true,
            volumes: vec![],
            writable_root: false,
            cap_add: Vec::new(),
            user: None,
            isolation: IsolationRequirement::Trusted,
            prefer_backend: None,
            require_backend: None,
            pull_secret: None,
            bindings: vec![],
            post_launch: vec![],
            pull_policy: Default::default(),
        }
    }

    #[test]
    fn empty_post_launch_does_not_change_the_spec_hash() {
        // A spec that declares no post-launch actions serializes without the field, so it
        // hashes identically to a pre-post_launch spec (back-compat / schema stays v1).
        let a = spec();
        let json = serde_json::to_string(&a).unwrap();
        assert!(
            !json.contains("post_launch"),
            "empty post_launch is omitted"
        );

        // Declaring an action is recorded and changes the content hash (it is part of the
        // workload's identity — changing it remints the spec and rolls the container).
        let mut b = spec();
        b.post_launch = vec![PostLaunchAction::Exec {
            argv: vec!["/bin/true".into()],
        }];
        assert_ne!(
            a.id(),
            b.id(),
            "a declared post-launch action changes the id"
        );
    }

    #[test]
    fn absent_require_backend_is_omitted_and_does_not_change_the_spec_hash() {
        // v0.67.0: `require_backend` (like `prefer_backend`) is omitted from the wire when
        // `None`, so an existing spec keeps its content hash (back-compat; an older server
        // never sees the field).
        let a = spec();
        assert_eq!(a.require_backend, None);
        let json = serde_json::to_string(&a).unwrap();
        assert!(
            !json.contains("require_backend"),
            "an absent require_backend is omitted from the wire"
        );
        // Setting it IS recorded, round-trips, and changes the content hash (it is part of
        // the workload's placement identity).
        let mut b = spec();
        b.require_backend = Some("firecracker".into());
        assert_ne!(a.id(), b.id(), "a require_backend changes the id");
        let round: ComputeSpec = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        assert_eq!(round.require_backend.as_deref(), Some("firecracker"));
    }

    #[test]
    fn default_pull_policy_is_omitted_and_does_not_change_the_spec_hash() {
        // The default `Always` pull_policy serializes without the field, so a spec hashes
        // identically to a pre-`pull_policy` spec (back-compat; an older server never sees
        // the field). Mirrors the `isolation`/`pull_secret` omit-from-wire siblings.
        let a = spec();
        assert_eq!(a.pull_policy, PullPolicy::Always, "default is Always");
        let json = serde_json::to_string(&a).unwrap();
        assert!(
            !json.contains("pull_policy"),
            "the default pull_policy is omitted from the wire"
        );

        // A non-default policy IS recorded and changes the content hash (it is part of the
        // workload's identity — it changes how the backend obtains the image).
        let mut b = spec();
        b.pull_policy = PullPolicy::IfNotPresent;
        assert_ne!(a.id(), b.id(), "a non-default pull_policy changes the id");
        assert!(serde_json::to_string(&b).unwrap().contains("pull_policy"));
    }

    #[test]
    fn empty_bindings_do_not_change_the_spec_hash() {
        // A spec that declares no bindings serializes without the field, so it hashes
        // identically to a pre-bindings spec (back-compat).
        let a = spec();
        let json = serde_json::to_string(&a).unwrap();
        assert!(!json.contains("bindings"), "empty bindings are omitted");

        // Declaring a binding is recorded and changes the content hash.
        let mut b = spec();
        b.bindings = vec![ComputeBinding {
            kind: BindingKind::Sql,
            name: String::new(),
            url_env: None,
            migration_url_env: None,
        }];
        assert_ne!(a.id(), b.id(), "a declared binding changes the id");
        assert!(serde_json::to_string(&b).unwrap().contains("bindings"));
    }

    #[test]
    fn binding_kind_parses_lowercase_and_url_env_defaults_per_kind() {
        assert_eq!(
            serde_json::from_str::<BindingKind>("\"sql\"").unwrap(),
            BindingKind::Sql
        );
        let sql = ComputeBinding {
            kind: BindingKind::Sql,
            name: String::new(),
            url_env: None,
            migration_url_env: None,
        };
        assert_eq!(sql.url_env(), "BOATRAMP_SQL_URL");
        let custom = ComputeBinding {
            kind: BindingKind::Sql,
            name: "analytics".into(),
            url_env: Some("ANALYTICS_URL".into()),
            migration_url_env: None,
        };
        assert_eq!(custom.url_env(), "ANALYTICS_URL");
        // The migration/DDL env var defaults to `<url_env>_MIGRATION`, or an explicit override.
        assert_eq!(sql.migration_url_env(), "BOATRAMP_SQL_URL_MIGRATION");
        assert_eq!(custom.migration_url_env(), "ANALYTICS_URL_MIGRATION");
        let explicit = ComputeBinding {
            kind: BindingKind::Sql,
            name: "analytics".into(),
            url_env: Some("ANALYTICS_URL".into()),
            migration_url_env: Some("ANALYTICS_DDL_URL".into()),
        };
        assert_eq!(explicit.migration_url_env(), "ANALYTICS_DDL_URL");
    }

    #[test]
    fn invoke_binding_kind_declares_like_every_other_kind() {
        // `invoke` (Phase 3, compute→function) parses, round-trips, and defaults its env var
        // exactly like the already-resolved kinds — only its SHIM is future work, not its
        // declaration.
        assert_eq!(
            serde_json::from_str::<BindingKind>("\"invoke\"").unwrap(),
            BindingKind::Invoke
        );
        assert_eq!(
            serde_json::to_string(&BindingKind::Invoke).unwrap(),
            "\"invoke\""
        );
        let invoke = ComputeBinding {
            kind: BindingKind::Invoke,
            name: String::new(),
            url_env: None,
            migration_url_env: None,
        };
        assert_eq!(invoke.url_env(), "BOATRAMP_INVOKE_URL");
        // Every kind's stable tag is distinct (the shim token HMAC relies on this).
        let tags: Vec<u8> = [
            BindingKind::Sql,
            BindingKind::Kv,
            BindingKind::Blob,
            BindingKind::Messaging,
            BindingKind::Invoke,
        ]
        .iter()
        .map(|k| k.stable_tag())
        .collect();
        let mut unique = tags.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            tags.len(),
            "every BindingKind has a distinct stable_tag"
        );
    }

    #[test]
    fn declaring_an_invoke_binding_changes_the_spec_hash() {
        let a = spec();
        let mut b = spec();
        b.bindings = vec![ComputeBinding {
            kind: BindingKind::Invoke,
            name: String::new(),
            url_env: None,
            migration_url_env: None,
        }];
        assert_ne!(a.id(), b.id(), "a declared invoke binding changes the id");
        assert!(serde_json::to_string(&b).unwrap().contains("invoke"));
    }

    #[test]
    fn empty_pull_secret_does_not_change_the_spec_hash() {
        // A spec that names no pull secret serializes without the field, so it hashes
        // identically to a pre-pull_secret spec (back-compat / schema stays v1).
        let a = spec();
        let json = serde_json::to_string(&a).unwrap();
        assert!(
            !json.contains("pull_secret"),
            "a `None` pull_secret is omitted from the wire + content hash"
        );
        // Naming a pull secret is recorded and changes the content hash (it is part of
        // the workload's identity — the NAME, never the credential value).
        let mut b = spec();
        b.pull_secret = Some("ghcr-pull".into());
        assert_ne!(a.id(), b.id(), "a named pull_secret changes the id");
        assert!(serde_json::to_string(&b).unwrap().contains("ghcr-pull"));
    }

    #[test]
    fn spec_id_is_stable_and_content_addressed() {
        let a = spec();
        let mut b = spec();
        assert_eq!(a.id(), b.id(), "identical specs share an id");
        b.vcpus = 4;
        assert_ne!(a.id(), b.id(), "a changed field changes the id");
        assert_eq!(a.id().len(), 64);
    }

    #[test]
    fn default_isolation_does_not_change_the_spec_hash() {
        // `Trusted` (default) is omitted from the JSON, so a spec that doesn't
        // touch isolation hashes identically to one explicitly set to Trusted.
        let mut a = spec();
        a.isolation = IsolationRequirement::Trusted;
        let json = serde_json::to_string(&a).unwrap();
        assert!(!json.contains("isolation"), "default isolation is omitted");
        // Untrusted is recorded and changes the hash.
        let mut b = spec();
        b.isolation = IsolationRequirement::Untrusted;
        assert_ne!(a.id(), b.id());
        assert!(serde_json::to_string(&b).unwrap().contains("untrusted"));
    }

    #[test]
    fn spec_round_trips_through_json() {
        let a = spec();
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<ComputeSpec>(&json).unwrap(), a);
    }

    #[test]
    fn old_spec_without_startup_grace_deserializes_with_the_default() {
        // An additive, `#[serde(default)]` field keeps schema at v1: a spec stored
        // before `startup_grace_secs` existed (no such key) still deserializes, taking
        // the generic default (30). `deny_unknown_fields` is on, so this proves the
        // field is genuinely optional on read.
        let old = r#"{
            "version": 1,
            "root": { "rootfs": "aaaa" },
            "vcpus": 1,
            "mem_mib": 256,
            "port": 8080
        }"#;
        let spec: ComputeSpec = serde_json::from_str(old).expect("old spec deserializes");
        assert_eq!(spec.version, 1, "schema stays v1");
        assert_eq!(spec.startup_grace_secs, default_startup_grace_secs());
        assert_eq!(spec.startup_grace_secs, 30);
    }

    #[test]
    fn keyspace_helpers() {
        assert_eq!(
            workload_key("default", "api"),
            "project/default/compute/api"
        );
        assert_eq!(workload_key("acme", "api"), "project/acme/compute/api");
        assert_eq!(workloads_prefix("default"), "project/default/compute/");
        // The spec body is content-addressed and stays global (dedup across projects).
        assert_eq!(spec_key("deadbeef"), "computever/deadbeef");
    }

    #[test]
    fn placement_matches_region_and_labels() {
        let c = PlacementConstraints {
            regions: vec!["eu".into()],
            labels: BTreeMap::from([("gpu".to_string(), "yes".to_string())]),
        };
        let labels = BTreeMap::from([("gpu".to_string(), "yes".to_string())]);
        assert!(c.allows(Some("eu"), &labels));
        assert!(!c.allows(Some("us"), &labels), "wrong region");
        assert!(!c.allows(Some("eu"), &BTreeMap::new()), "missing label");
        // No constraints → any node.
        assert!(PlacementConstraints::default().allows(None, &BTreeMap::new()));
    }

    // ---- U26: constructors/builders for the now-`#[non_exhaustive]` public types ----

    #[test]
    fn spec_builder_matches_the_equivalent_literal() {
        // The builder, with a setter for each field the literal `spec()` helper sets to a
        // non-default, produces a byte-identical spec — so the construction path is complete
        // and downstreams never need a struct literal.
        let built = ComputeSpec::builder(RootSource::Rootfs("a".repeat(64)), 2, 512, 8080)
            .kernel("b".repeat(64))
            .entrypoint(vec!["/app".into(), "--serve".into()])
            .env(BTreeMap::from([("PORT".to_string(), "8080".to_string())]))
            .scale_to_zero(true)
            .build();
        assert_eq!(built, spec());
        assert_eq!(built.id(), spec().id(), "same content hash");
    }

    #[test]
    fn spec_builder_defaults_match_the_documented_defaults() {
        let s = ComputeSpec::builder(RootSource::Tar("c".repeat(64)), 1, 128, 80).build();
        assert_eq!(s.version, crate::schema_version());
        assert!(s.kernel.is_empty() && s.kernel_cmdline.is_none());
        assert!(s.entrypoint.is_empty() && s.env.is_empty());
        assert_eq!(s.restart, RestartPolicy::Always);
        assert_eq!(s.startup_grace_secs, default_startup_grace_secs());
        assert!(!s.scale_to_zero && !s.writable_root);
        assert!(s.volumes.is_empty() && s.cap_add.is_empty());
        assert!(s.user.is_none() && s.prefer_backend.is_none() && s.require_backend.is_none());
        assert_eq!(s.isolation, IsolationRequirement::Trusted);
        assert!(s.pull_secret.is_none());
        assert_eq!(s.pull_policy, PullPolicy::default());
        assert!(s.bindings.is_empty() && s.post_launch.is_empty());
        // A default-built spec omits every optional field from the wire (schema stays v1).
        let json = serde_json::to_string(&s).unwrap();
        for omitted in [
            "kernel",
            "scale_to_zero",
            "require_backend",
            "bindings",
            "pull_policy",
        ] {
            assert!(
                !json.contains(omitted),
                "{omitted} is omitted at its default: {json}"
            );
        }
    }

    #[test]
    fn compute_binding_constructor_and_setters() {
        // `new` defaults to the site default store + the kind's default env + no migration DSN.
        let def = ComputeBinding::new(BindingKind::Sql);
        assert!(def.name.is_empty() && def.url_env.is_none() && def.migration_url_env.is_none());
        assert_eq!(def.url_env(), "BOATRAMP_SQL_URL");

        let b = ComputeBinding::new(BindingKind::Sql)
            .with_name("app")
            .with_url_env(Some("SIMERTEC_DATABASE_URL".into()))
            .with_migration_url_env(Some("APP_MIGRATE".into()));
        assert_eq!(b.name, "app");
        assert_eq!(b.url_env(), "SIMERTEC_DATABASE_URL");
        assert_eq!(b.migration_url_env(), "APP_MIGRATE");
        // Equivalent to a binding set through the spec builder's `.bindings(..)`.
        let spec = ComputeSpec::builder(RootSource::Tar("h".repeat(64)), 1, 64, 80)
            .bindings(vec![b.clone()])
            .build();
        assert_eq!(spec.bindings, vec![b]);
    }

    #[test]
    fn volume_ref_constructor() {
        let v = VolumeRef::new("/data", "db", 128);
        assert_eq!(
            (v.mount.as_str(), v.name.as_str(), v.size_mib),
            ("/data", "db", 128)
        );
    }

    #[test]
    fn placement_constraints_builder_matches_the_literal() {
        // The builder produces the same value a struct literal would (the literal is still
        // legal inside the defining crate; `#[non_exhaustive]` only blocks it downstream).
        let built = PlacementConstraints::new()
            .with_regions(vec!["eu".into(), "us".into()])
            .with_labels(BTreeMap::from([("gpu".to_string(), "yes".to_string())]));
        let literal = PlacementConstraints {
            regions: vec!["eu".into(), "us".into()],
            labels: BTreeMap::from([("gpu".to_string(), "yes".to_string())]),
        };
        assert_eq!(built, literal);
        // An empty builder is the unconstrained default (any node eligible).
        let any = PlacementConstraints::new();
        assert_eq!(any, PlacementConstraints::default());
        assert!(any.allows(None, &BTreeMap::new()));
    }

    #[test]
    fn readiness_gate_builder_and_defaults() {
        // Default: every surface strict (`Provisioned`).
        let def = ReadinessGate::new();
        assert_eq!(def, ReadinessGate::default());
        assert_eq!(def.answerability, ReadinessLevel::Provisioned);
        // Relax only `routing`; the other surfaces keep the strict default.
        let g = ReadinessGate::new().with_routing(ReadinessLevel::ServiceReady);
        assert_eq!(g.routing, ReadinessLevel::ServiceReady);
        assert_eq!(g.answerability, ReadinessLevel::Provisioned);
        assert_eq!(g.migration, ReadinessLevel::Provisioned);
    }

    #[test]
    fn apply_database_new_equals_minimal_manifest_and_builder_is_additive() {
        // `new(name, kind)` yields exactly what deserializing a minimal `{name, kind}`
        // manifest would — every optional knob at its serde default (prior behavior).
        let built = ApplyDatabase::new("app".to_string(), ApplyDatabaseKind::Postgres);
        let deserialized: ApplyDatabase =
            serde_json::from_value(serde_json::json!({ "name": "app", "kind": "postgres" }))
                .expect("minimal ApplyDatabase");
        assert_eq!(built, deserialized);
        // Spot-check the defaults are the documented prior behavior.
        assert_eq!(built.version, None);
        assert!(built.extensions.is_empty());
        assert_eq!(built.size, ApplyDatabaseSize::Small);
        assert_eq!(built.tenant, ApplyDatabaseTenant::Single);
        assert_eq!(built.tenant_scope, ApplyDatabaseScope::Project);
        assert!(!built.read_only);
        assert!(!built.rls_session);
        assert_eq!(built.pool_max, None);
        assert!(!built.delta_capture);
        assert_eq!(built.restart_policy, DbRestartPolicy::Manual);
        // A `with_*` setter refines one knob and nothing else — additive, non-breaking.
        let refined = ApplyDatabase::new("app".to_string(), ApplyDatabaseKind::Mysql)
            .with_tenant(ApplyDatabaseTenant::Shared)
            .with_pool_max(Some(32));
        assert_eq!(refined.kind, ApplyDatabaseKind::Mysql);
        assert_eq!(refined.tenant, ApplyDatabaseTenant::Shared);
        assert_eq!(refined.pool_max, Some(32));
        // Unset knobs keep their defaults.
        assert_eq!(refined.size, ApplyDatabaseSize::Small);
        assert_eq!(refined.tenant_scope, ApplyDatabaseScope::Project);
    }
}
