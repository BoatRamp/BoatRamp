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
}

/// A persistent volume attached to the guest (a host block image, snapshotted
/// to blob storage for durability). Opt-in; the default rootfs is read-only with
/// an ephemeral scratch drive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeRef {
    /// In-guest mount point.
    pub mount: String,
    /// Volume name (the host tracks its backing image).
    pub name: String,
    /// Size in MiB (used when first provisioning).
    pub size_mib: u32,
}

/// An immutable, content-addressed compute workload version (the analogue of a
/// deployment manifest). Stored at `computever/<hash>`; the rootfs + kernel are
/// blob hashes in the shared blob store (deduped, cached forever).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Optional preferred backend id (`vmm`/`container`/`cloudflare`/`docker`);
    /// the scheduler honors it when the backend is eligible, else falls back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefer_backend: Option<String>,
    /// Managed resources this workload depends on — the opaque-process analogue of a
    /// handler's `imports`. boatramp resolves each to a **tenant-scoped** endpoint +
    /// credential at launch and injects the address into the guest env, so a workload
    /// reaches the managed `sql` (and, later, kv/blob/messaging) without a hand-glued
    /// URL. Empty ⇒ omitted from the wire + the content hash (back-compat).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<ComputeBinding>,
}

/// A managed-resource dependency a compute workload declares. It names a *resource*,
/// never a project: the owning project comes from the workload's key
/// (`project/<proj>/compute/<name>`), so a workload cannot request another tenant's
/// data. boatramp resolves it at launch and injects the endpoint into the guest env.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
}

/// The managed-resource kinds a [`ComputeBinding`] may name. Phase 0 implements `Sql`;
/// the others are reserved for the shared resolver mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BindingKind {
    /// The managed `sql` database (per-site libsql, or a named external DB).
    Sql,
    /// Per-site key-value store (Phase 2).
    Kv,
    /// Per-site blob store (Phase 2).
    Blob,
    /// Per-site pub/sub + queues (Phase 2).
    Messaging,
}

impl ComputeBinding {
    /// The env var the endpoint URL is injected as (explicit `url_env`, else the kind
    /// default). The auth token is injected as this name plus `_AUTH_TOKEN`.
    pub fn url_env(&self) -> String {
        self.url_env
            .clone()
            .unwrap_or_else(|| self.kind.default_url_env().to_string())
    }
}

impl BindingKind {
    /// The default env var an endpoint of this kind is injected as.
    pub fn default_url_env(self) -> &'static str {
        match self {
            Self::Sql => "BOATRAMP_SQL_URL",
            Self::Kv => "BOATRAMP_KV_URL",
            Self::Blob => "BOATRAMP_BLOB_URL",
            Self::Messaging => "BOATRAMP_MESSAGING_URL",
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
}

/// Placement constraints: where a workload's replicas may run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlacementConstraints {
    /// If non-empty, only nodes in one of these regions are eligible.
    pub regions: Vec<String>,
    /// Required node labels (all must match a node's advertised labels).
    pub labels: BTreeMap<String, String>,
}

impl PlacementConstraints {
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
            scale_to_zero: true,
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
        };
        assert_eq!(sql.url_env(), "BOATRAMP_SQL_URL");
        let custom = ComputeBinding {
            kind: BindingKind::Sql,
            name: "analytics".into(),
            url_env: Some("ANALYTICS_URL".into()),
        };
        assert_eq!(custom.url_env(), "ANALYTICS_URL");
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
}
