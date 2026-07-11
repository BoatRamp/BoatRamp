//! The operator's CustomResourceDefinitions, **single-sourced as Rust types** —
//! `boatramp operator crds` emits their YAML from exactly these definitions, so the
//! shipped CRDs can never drift from what the controller reconciles.
//!
//! Three kinds under `boatramp.dev/v1alpha1`:
//! - [`BoatRampCluster`] — a Raft cluster (StatefulSet) or a stateless frontend
//!   (Deployment); the operator owns its workloads and (in cluster mode) its Raft
//!   **membership** (the reason the operator is mandatory — see `PLAN-kubernetes`).
//! - [`Site`] — a declarative tenant site, reconciled via the control-plane API.
//! - [`Function`] — a declarative function (the k8s surface of `PLAN-faas`).
//!
//! Spec fields are intentionally minimal at K1 (skeleton); the reconcilers that
//! consume them land in K2–K5.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Deploy shape for a [`BoatRampCluster`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ClusterMode {
    /// A Raft cluster: a `StatefulSet` + per-node `PersistentVolumeClaim`, with the
    /// operator managing consensus **membership** (join → learner → voter on
    /// scale-up; demote + remove before pod delete on scale-down).
    #[default]
    Cluster,
    /// A stateless frontend over a shared/replicated KV: a `Deployment` + `HPA`.
    Stateless,
}

/// A boatramp cluster managed by the operator.
#[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "boatramp.dev",
    version = "v1alpha1",
    kind = "BoatRampCluster",
    plural = "boatrampclusters",
    shortname = "brc",
    namespaced,
    status = "BoatRampClusterStatus",
    printcolumn = r#"{"name":"Mode","type":"string","jsonPath":".spec.mode"}"#,
    printcolumn = r#"{"name":"Desired","type":"integer","jsonPath":".spec.replicas"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Quorum","type":"boolean","jsonPath":".status.quorum"}"#
)]
pub struct BoatRampClusterSpec {
    /// Raft cluster (default) or stateless frontend.
    #[serde(default)]
    pub mode: ClusterMode,
    /// Desired node count.
    #[serde(default = "default_replicas")]
    pub replicas: u32,
    /// Container image; empty ⇒ the operator's own image (one artifact, one version).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Per-node persistent-volume size (e.g. `10Gi`), cluster mode only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
    /// Security posture profile (`multi-tenant` / `single-tenant` / `dev` / custom);
    /// the operator enforces this floor and a tenant CRD can never relax it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<String>,
}

/// Observed state of a [`BoatRampCluster`] — surfaced in `kubectl get brc`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BoatRampClusterStatus {
    /// A short lifecycle phase (`Pending` / `Reconciling` / `Ready` / `Degraded`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    /// Per-node Raft membership, as the operator observes it.
    #[serde(default)]
    pub members: Vec<MemberStatus>,
    /// Whether the Raft cluster currently holds quorum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quorum: Option<bool>,
    /// The `.metadata.generation` this status reflects (staleness guard).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// One node's observed Raft membership.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MemberStatus {
    /// The node (pod) name.
    pub node: String,
    /// Its Raft role: `learner`, `voter`, or `leader`.
    pub role: String,
    /// Whether its `/readyz` reports ready.
    pub ready: bool,
}

/// A declarative tenant site, reconciled via the control-plane API.
#[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "boatramp.dev",
    version = "v1alpha1",
    kind = "Site",
    plural = "sites",
    namespaced,
    status = "SiteStatus",
    printcolumn = r#"{"name":"Cluster","type":"string","jsonPath":".spec.cluster"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.phase"}"#
)]
pub struct SiteSpec {
    /// The [`BoatRampCluster`] serving this site; empty ⇒ the sole cluster in the
    /// namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    /// Hostnames routed to this site.
    #[serde(default)]
    pub domains: Vec<String>,
}

/// Observed state of a [`Site`].
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SiteStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
}

/// A declarative function (the Kubernetes surface of `PLAN-faas` FA-1..FA-3).
#[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "boatramp.dev",
    version = "v1alpha1",
    kind = "Function",
    plural = "functions",
    shortname = "fn",
    namespaced,
    status = "FunctionStatus",
    printcolumn = r#"{"name":"Cluster","type":"string","jsonPath":".spec.cluster"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.phase"}"#
)]
pub struct FunctionSpec {
    /// The [`BoatRampCluster`] hosting this function; empty ⇒ the sole cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    /// The wasm component: a blob content-address or an OCI reference.
    pub component: String,
    /// An optional route this function answers (`/api/...` or a host path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
}

/// Observed state of a [`Function`].
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FunctionStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
}

/// The default node count for a new cluster (a minimal Raft quorum).
fn default_replicas() -> u32 {
    3
}
