//! The **Kubernetes** [`ComputeBackend`](boatramp_core::compute::ComputeBackend)
//! (`id = "kubernetes"`).
//!
//! When boatramp runs AS a pod on Kubernetes/k3s — where k8s is already the
//! orchestrator — it delegates its own managed compute to k8s itself, instead of the
//! VM / native-container / remote-docker backends that don't fit inside a pod. Phase 1
//! covers the managed-database (stateful) case: a compute spec for a managed Postgres/
//! MySQL maps to a `StatefulSet` (stable identity + the operand image), a `Service`
//! named after the workload (the `pg-<ident>` in-cluster DNS the sql-shim/bindings
//! resolve), and a `PersistentVolumeClaim` for the data volume on the default (or a
//! configured) `StorageClass`. The pure spec→objects mapping lives in [`plan`]; the
//! client-side apply/delete/health is here.
//!
//! The client uses the SAME in-cluster config the in-binary `boatramp operator` uses
//! ([`kube::Client::try_default`] — a mounted ServiceAccount in-cluster, a kubeconfig
//! locally), so there is no second k8s-auth path. All objects are applied **server-side**
//! (idempotent/reconcilable) in the serve pod's OWN namespace.
//!
//! Default-inert: without the `k8s-backend` cargo feature the crate is a shell exposing
//! only [`BACKEND_ID`] and [`in_cluster`], so a build that never selects it pulls none of
//! the kube-rs / k8s-openapi tree. The node registers this backend only when it is
//! selected (`[compute].backend = "kubernetes"`) or auto-detected in-cluster.

/// The stable backend id (matches [`ComputeBackend::id`](boatramp_core::compute::ComputeBackend::id)).
pub const BACKEND_ID: &str = "kubernetes";

/// The in-cluster ServiceAccount token path (its presence, with
/// `KUBERNETES_SERVICE_HOST`, is the in-cluster signal).
pub const SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
/// The in-cluster ServiceAccount namespace path (the pod's own namespace).
pub const SA_NAMESPACE_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

/// Whether this process is running **inside** a Kubernetes pod with a usable
/// ServiceAccount: the apiserver env var (`KUBERNETES_SERVICE_HOST`) is set AND a
/// ServiceAccount token is mounted. Used for the node's in-cluster auto-detect (default
/// to the k8s backend when both hold). Cheap + side-effect-free, so it is available even
/// without the `k8s-backend` feature.
pub fn in_cluster() -> bool {
    std::env::var_os("KUBERNETES_SERVICE_HOST").is_some_and(|v| !v.is_empty())
        && std::path::Path::new(SA_TOKEN_PATH).exists()
}

#[cfg(feature = "k8s-backend")]
pub mod plan;

#[cfg(feature = "k8s-backend")]
mod backend;

#[cfg(feature = "k8s-backend")]
pub use backend::KubernetesBackend;
