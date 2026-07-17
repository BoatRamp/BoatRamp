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

/// KV key prefix for the mutable per-workload desired state.
pub const WORKLOAD_PREFIX: &str = "compute/";
/// KV key prefix for immutable, content-addressed compute specs.
pub const SPEC_PREFIX: &str = "computever/";

/// The mutable desired-state key for a workload.
pub fn workload_key(name: &str) -> String {
    format!("{WORKLOAD_PREFIX}{name}")
}

/// The immutable spec key for a content hash.
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
    /// Blob hash of the `ext4` rootfs image.
    pub rootfs: String,
    /// Blob hash of the `vmlinux` kernel (shared across workloads).
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
    /// Isolation the workload requires; selects which backends are eligible.
    /// Default `Trusted`; omitted from the serialized
    /// spec when default, so existing specs keep their content hash.
    #[serde(default, skip_serializing_if = "IsolationRequirement::is_trusted")]
    pub isolation: IsolationRequirement,
    /// Optional preferred backend id (`vmm`/`container`/`cloudflare`/`docker`);
    /// the scheduler honors it when the backend is eligible, else falls back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefer_backend: Option<String>,
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
            rootfs: "a".repeat(64),
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
            isolation: IsolationRequirement::Trusted,
            prefer_backend: None,
        }
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
        assert_eq!(workload_key("api"), "compute/api");
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
