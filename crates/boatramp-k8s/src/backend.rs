//! The client side of the Kubernetes backend: connect with the in-cluster config, and
//! implement [`ComputeBackend`] by server-side-applying / deleting / reading the typed
//! objects the [`plan`](crate::plan) builds. Phase 1 implements `launch`/`stop`/`health`
//! for the managed-database case; the generic-workload, `exec`/logs, volume-management,
//! snapshot/restore and reaper surfaces use the trait's default (unsupported) impls and
//! are Phase 2.

use async_trait::async_trait;
use boatramp_core::compute::ComputeSpec;
use boatramp_core::compute::RootSource;
use boatramp_core::compute::{
    Artifact, BackendError, Capabilities, ComputeBackend, Endpoint, Health, Instance,
    InstanceHandle, IsolationClass, LaunchRequest, Scheme,
};
use boatramp_core::registry_auth::RegistryAuth;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Service};
use kube::api::{DeleteParams, Patch, PatchParams};
use kube::{Api, Client};

use crate::plan::{self, FIELD_MANAGER, PlanContext, ResourcePlan, pvc_name};

/// The in-cluster Kubernetes compute backend: a connected API [`Client`] scoped to the
/// serve pod's own `namespace`, plus the placement policy (the PVC `StorageClass` and the
/// teardown retain flag).
pub struct KubernetesBackend {
    client: Client,
    namespace: String,
    /// `StorageClass` for provisioned PVCs (`None` ⇒ the cluster default).
    storage_class: Option<String>,
    /// Keep a managed database's PVC on `stop` (default) instead of deleting it — a DB's
    /// data must not be reclaimed by a routine teardown. `false` deletes it with the
    /// workload (e.g. an operator tearing a database down for good).
    retain_pvc_on_stop: bool,
}

impl std::fmt::Debug for KubernetesBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubernetesBackend")
            .field("namespace", &self.namespace)
            .field("storage_class", &self.storage_class)
            .field("retain_pvc_on_stop", &self.retain_pvc_on_stop)
            .finish_non_exhaustive()
    }
}

impl KubernetesBackend {
    /// Connect using the same in-cluster config the `boatramp operator` uses
    /// ([`Client::try_default`] — a mounted ServiceAccount in-cluster, a local kubeconfig
    /// otherwise), and resolve the namespace to operate in (the mounted ServiceAccount
    /// namespace, else the client's default). Does NOT re-plumb k8s auth.
    pub async fn connect(
        storage_class: Option<String>,
        retain_pvc_on_stop: bool,
    ) -> Result<Self, BackendError> {
        // kube talks to the apiserver over rustls; the workspace pulls both aws-lc-rs and
        // ring, so rustls can't auto-select a provider — install aws-lc-rs (matching the
        // operator + serve). Idempotent; ignore an already-installed provider.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = Client::try_default()
            .await
            .map_err(|e| BackendError::Other(format!("kube client (in-cluster config): {e}")))?;
        let namespace = detect_namespace(&client);
        tracing::info!(%namespace, ?storage_class, retain_pvc_on_stop, "kubernetes compute backend ready");
        Ok(Self {
            client,
            namespace,
            storage_class,
            retain_pvc_on_stop,
        })
    }

    /// Wrap an already-built client (tests / an embedder that resolved its own config).
    pub fn with_client(
        client: Client,
        namespace: impl Into<String>,
        storage_class: Option<String>,
        retain_pvc_on_stop: bool,
    ) -> Self {
        Self {
            client,
            namespace: namespace.into(),
            storage_class,
            retain_pvc_on_stop,
        }
    }

    fn plan_context(&self, req: &LaunchRequest) -> PlanContext {
        PlanContext {
            project: req.project.clone(),
            workload: req.workload.clone(),
            replica: req.replica,
            namespace: self.namespace.clone(),
            storage_class: self.storage_class.clone(),
        }
    }

    /// Server-side-apply one object under boatramp's field manager (idempotent;
    /// reconcilable — a relaunch re-applies the identical object).
    async fn apply<K>(&self, obj: &K) -> Result<(), BackendError>
    where
        K: kube::Resource<Scope = kube::core::NamespaceResourceScope>
            + Clone
            + std::fmt::Debug
            + serde::Serialize
            + serde::de::DeserializeOwned,
        K::DynamicType: Default,
    {
        let name = obj
            .meta()
            .name
            .clone()
            .ok_or_else(|| BackendError::Launch("object has no name".into()))?;
        let api: Api<K> = Api::namespaced(self.client.clone(), &self.namespace);
        api.patch(
            &name,
            &PatchParams::apply(FIELD_MANAGER).force(),
            &Patch::Apply(obj),
        )
        .await
        .map_err(|e| BackendError::Launch(format!("apply {name}: {e}")))?;
        Ok(())
    }
}

/// Resolve the namespace to operate in: the mounted ServiceAccount namespace file first
/// (the authoritative in-cluster signal), else the client's default namespace (which, for
/// an in-cluster config, kube already derives from that same file; for a local kubeconfig
/// it is the context namespace / `default`).
fn detect_namespace(client: &Client) -> String {
    std::fs::read_to_string(crate::SA_NAMESPACE_PATH)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| client.default_namespace().to_string())
}

/// Treat a `404 Not Found` from the apiserver as success (the object is already gone), so
/// `stop` is idempotent; surface any other error.
fn ignore_not_found(result: Result<(), kube::Error>) -> Result<(), BackendError> {
    match result {
        Ok(()) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(BackendError::Stop(e.to_string())),
    }
}

#[async_trait]
impl ComputeBackend for KubernetesBackend {
    fn id(&self) -> &'static str {
        crate::BACKEND_ID
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // A pod is shared-kernel — classified like native-container / docker. The
            // `require_strong_isolation` posture excludes it exactly as it excludes those.
            isolation: IsolationClass::Container,
            // Scale-to-zero (snapshot/restore) is Phase 2 (CSI VolumeSnapshot).
            scale_to_zero: false,
            // The data volume is a PVC on a CSI/storage class — a real persistent volume.
            persistent_volumes: true,
            max_vcpus: None,
            max_mem_mib: None,
        }
    }

    async fn materialize(
        &self,
        _project: &str,
        _workload: &str,
        spec: &ComputeSpec,
        pull_auth: Option<&RegistryAuth>,
    ) -> Result<Artifact, BackendError> {
        // The kubelet pulls the operand image, so materialize just validates + passes the
        // reference through; k8s stages it. An ext4 rootfs / tar is for the VM / native
        // substrates, not a pod.
        let reference = match &spec.root {
            RootSource::Image(reference) => reference.clone(),
            RootSource::Tar(_) | RootSource::Rootfs(_) => {
                return Err(BackendError::Materialize(
                    "kubernetes backend requires an image reference (RootSource::Image)".into(),
                ));
            }
        };
        // Fail CLOSED on a resolved private-registry credential: Phase 1 does not yet wire
        // a k8s `imagePullSecret`, so a backend that cannot apply the credential must NOT
        // silently pull anonymously (the trait contract). Applying the pull secret is a
        // Phase-2 item.
        if pull_auth.is_some() {
            return Err(BackendError::Materialize(
                "kubernetes backend cannot yet apply a private-registry pull credential \
                 (Phase 2: imagePullSecrets); refusing rather than pulling anonymously"
                    .into(),
            ));
        }
        Ok(Artifact::Image { reference })
    }

    async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
        let ResourcePlan {
            stateful_set,
            service,
            pvc,
        } = plan::managed_db_plan(&self.plan_context(req), &req.spec)
            .map_err(|e| BackendError::Launch(e.to_string()))?;

        // Apply the PVC first (the StatefulSet's pod mounts it), then the workload, then
        // the Service. Server-side apply is idempotent, so a relaunch reconciles in place.
        self.apply(&pvc).await?;
        self.apply(&stateful_set).await?;
        self.apply(&service).await?;

        // The managed-DB DSN host is the bare workload name resolved by in-cluster DNS to
        // this Service's ClusterIP (`pg-<ident>` short name within the namespace), so the
        // routable endpoint host is the workload name itself — not a pod IP.
        Ok(Instance {
            handle: InstanceHandle {
                project: req.project.clone(),
                workload: req.workload.clone(),
                replica: req.replica,
                backend_ref: self.namespace.clone(),
            },
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: req.workload.clone(),
                port: req.spec.port,
            },
        })
    }

    async fn stop(&self, handle: &InstanceHandle) -> Result<(), BackendError> {
        let name = &handle.workload;
        let sts: Api<StatefulSet> = Api::namespaced(self.client.clone(), &self.namespace);
        let svc: Api<Service> = Api::namespaced(self.client.clone(), &self.namespace);

        // Delete the workload + its Service (idempotent: a missing object is success).
        ignore_not_found(svc.delete(name, &DeleteParams::default()).await.map(|_| ()))?;
        ignore_not_found(sts.delete(name, &DeleteParams::default()).await.map(|_| ()))?;

        // The PVC is RETAINED by default (a database's data must survive a teardown); an
        // explicit non-retain teardown deletes it too.
        if !self.retain_pvc_on_stop {
            let pvcs: Api<PersistentVolumeClaim> =
                Api::namespaced(self.client.clone(), &self.namespace);
            // The data volume name in a managed-DB spec is the literal `data`.
            let claim = pvc_name("data", name);
            ignore_not_found(
                pvcs.delete(&claim, &DeleteParams::default())
                    .await
                    .map(|_| ()),
            )?;
        }
        Ok(())
    }

    async fn health(&self, handle: &InstanceHandle) -> Result<Health, BackendError> {
        let sts: Api<StatefulSet> = Api::namespaced(self.client.clone(), &self.namespace);
        match sts.get_opt(&handle.workload).await {
            // Ready once at least one pod passes its readiness probe (the TCP probe on the
            // DB port the plan wires); the managed-DB `SELECT 1` provisioning probe rides
            // the existing reconcile machinery on top of this.
            Ok(Some(s)) => {
                let ready = s.status.and_then(|st| st.ready_replicas).unwrap_or(0);
                Ok(if ready >= 1 {
                    Health::Healthy
                } else {
                    Health::Unhealthy
                })
            }
            Ok(None) => Ok(Health::Unhealthy),
            Err(e) => Err(BackendError::Other(format!(
                "health get statefulset {}: {e}",
                handle.workload
            ))),
        }
    }
}
