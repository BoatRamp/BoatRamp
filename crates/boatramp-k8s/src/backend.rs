//! The client side of the Kubernetes backend: connect with the in-cluster config, and
//! implement [`ComputeBackend`] by server-side-applying / deleting / reading the typed
//! objects the [`plan`](crate::plan) builds.
//!
//! Phase 1 implemented `launch`/`stop`/`health` for the managed-database (stateful) case.
//! Phase 2 adds: generic stateless **Deployments** (a volume-less spec → a `Deployment` +
//! ClusterIP `Service`), **`exec`** into a running pod (the `exec` subresource / kube
//! `AttachedProcess`), **pod logs** ([`KubernetesBackend::logs`]), **PVC volume
//! management** (`list_volumes`/`remove_volume`/`remove_scoped_volume`), the orphan-reaper
//! **`replica_alive`** probe, and **CSI VolumeSnapshot** snapshot/restore
//! ([`KubernetesBackend::snapshot_volume`]/[`KubernetesBackend::restore_volume`], gated on
//! a configured `VolumeSnapshotClass`). The trait's scale-to-zero `snapshot`/`restore`
//! stay the unsupported default (a managed DB is not parked); `run_ephemeral` likewise.

use async_trait::async_trait;
use boatramp_core::compute::ComputeSpec;
use boatramp_core::compute::RootSource;
use boatramp_core::compute::{
    Artifact, BackendError, Capabilities, ComputeBackend, Endpoint, ExecOutput, Health, Instance,
    InstanceHandle, IsolationClass, LaunchRequest, Scheme, VolumeInfo,
};
use boatramp_core::registry_auth::RegistryAuth;
use k8s_openapi::api::apps::v1::{Deployment, StatefulSet};
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Secret, Service};
use kube::api::{DeleteParams, ListParams, Patch, PatchParams};
use kube::core::{ApiResource, DynamicObject};
use kube::{Api, Client};

use crate::plan::{
    self, DeploymentPlan, FIELD_MANAGER, PlanContext, ResourcePlan, pod_container_name, pvc_name,
    workload_object_name,
};

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
    /// The name of a pre-existing `kubernetes.io/dockerconfigjson` `Secret` in this
    /// namespace to attach to every launched pod as an `imagePullSecret` (private
    /// registries). `None` ⇒ anonymous pulls. Operator-configured; never created here.
    image_pull_secret: Option<String>,
    /// The `VolumeSnapshotClass` for CSI snapshot/restore. `None` ⇒ snapshot/restore is a
    /// clean "unsupported" (the cluster's StorageClass has no snapshottable CSI driver, or
    /// the operator did not opt in).
    volume_snapshot_class: Option<String>,
}

impl std::fmt::Debug for KubernetesBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubernetesBackend")
            .field("namespace", &self.namespace)
            .field("storage_class", &self.storage_class)
            .field("retain_pvc_on_stop", &self.retain_pvc_on_stop)
            .field("image_pull_secret", &self.image_pull_secret)
            .field("volume_snapshot_class", &self.volume_snapshot_class)
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
        image_pull_secret: Option<String>,
        volume_snapshot_class: Option<String>,
    ) -> Result<Self, BackendError> {
        // kube talks to the apiserver over rustls; the workspace pulls both aws-lc-rs and
        // ring, so rustls can't auto-select a provider — install aws-lc-rs (matching the
        // operator + serve). Idempotent; ignore an already-installed provider.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = Client::try_default()
            .await
            .map_err(|e| BackendError::Other(format!("kube client (in-cluster config): {e}")))?;
        let namespace = detect_namespace(&client);
        tracing::info!(
            %namespace,
            ?storage_class,
            retain_pvc_on_stop,
            image_pull_secret = ?image_pull_secret,
            volume_snapshot_class = ?volume_snapshot_class,
            "kubernetes compute backend ready"
        );
        Ok(Self {
            client,
            namespace,
            storage_class,
            retain_pvc_on_stop,
            image_pull_secret,
            volume_snapshot_class,
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
            image_pull_secret: None,
            volume_snapshot_class: None,
        }
    }

    /// Set the operator-configured `imagePullSecret` (chainable, for tests/embedders).
    pub fn with_image_pull_secret(mut self, secret: Option<String>) -> Self {
        self.image_pull_secret = secret;
        self
    }

    /// Set the CSI `VolumeSnapshotClass` for snapshot/restore (chainable).
    pub fn with_volume_snapshot_class(mut self, class: Option<String>) -> Self {
        self.volume_snapshot_class = class;
        self
    }

    /// The plan context for a launch, carrying the given `workload` object name (the raw
    /// managed-DB workload for a StatefulSet, or the DNS-safe generic name for a
    /// Deployment) + the backend's placement knobs.
    fn plan_context_named(&self, req: &LaunchRequest, workload: String) -> PlanContext {
        PlanContext {
            project: req.project.clone(),
            workload,
            replica: req.replica,
            namespace: self.namespace.clone(),
            storage_class: self.storage_class.clone(),
            image_pull_secret: self.image_pull_secret.clone(),
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
            // No scale-to-zero parking: a managed DB / stateful pod is not snapshotted +
            // stopped on idle (the trait's `snapshot`/`restore` stay unsupported). The
            // CSI VolumeSnapshot support is a DATA backup/clone primitive
            // (`snapshot_volume`/`restore_volume`), distinct from compute scale-to-zero.
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
        // Fail CLOSED on a resolved PER-PROJECT sealed pull credential: the k8s backend
        // does not mint a Secret from it (that would need a `secrets` create verb its
        // least-privilege Role deliberately omits), so it must NOT silently pull
        // anonymously (the trait contract). The supported private-registry path on k8s is
        // the operator-configured `imagePullSecret` ([compute].k8s_image_pull_secret),
        // threaded onto the pod spec — a per-project sealed credential → auto-minted Secret
        // is a documented follow-up.
        if pull_auth.is_some() {
            return Err(BackendError::Materialize(
                "kubernetes backend cannot apply a per-project sealed pull credential \
                 (its Role grants no `secrets` verb); configure an operator imagePullSecret \
                 via [compute].k8s_image_pull_secret instead of a project pull_secret, or \
                 use a public image — refusing rather than pulling anonymously"
                    .into(),
            ));
        }
        Ok(Artifact::Image { reference })
    }

    async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
        // Stateful (declares a volume) → StatefulSet + Service + PVC, routed to the bare
        // workload name (the in-cluster DNS the sql-shim/bindings resolve). Stateless (no
        // volume) → a one-replica Deployment + a ClusterIP Service, routed to the DNS-safe
        // object name. The branch mirrors the k8s-native stateful/stateless split.
        let host = if req.spec.volumes.is_empty() {
            self.launch_deployment(req).await?
        } else {
            self.launch_stateful(req).await?
        };
        Ok(Instance {
            handle: InstanceHandle {
                project: req.project.clone(),
                workload: req.workload.clone(),
                replica: req.replica,
                backend_ref: self.namespace.clone(),
            },
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host,
                port: req.spec.port,
            },
        })
    }

    async fn stop(&self, handle: &InstanceHandle) -> Result<(), BackendError> {
        // A handle carries no object KIND, so `stop` tears down BOTH naming schemes
        // idempotently (a missing object is success): the stateful objects named by the
        // bare workload, and the generic objects named by the DNS-safe instance id. Only
        // one set actually exists; the other 404s harmlessly. This keeps `stop` robust
        // without threading the kind through the persisted handle.
        let sts_name = &handle.workload;
        let dep_name = workload_object_name(&handle.project, &handle.workload, handle.replica);

        let sts: Api<StatefulSet> = Api::namespaced(self.client.clone(), &self.namespace);
        let dep: Api<Deployment> = Api::namespaced(self.client.clone(), &self.namespace);
        let svc: Api<Service> = Api::namespaced(self.client.clone(), &self.namespace);
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), &self.namespace);

        // Stateful teardown: Service + StatefulSet named by the workload.
        ignore_not_found(
            svc.delete(sts_name, &DeleteParams::default())
                .await
                .map(|_| ()),
        )?;
        ignore_not_found(
            sts.delete(sts_name, &DeleteParams::default())
                .await
                .map(|_| ()),
        )?;
        // Generic teardown: Service + Deployment named by the DNS-safe instance id.
        ignore_not_found(
            svc.delete(&dep_name, &DeleteParams::default())
                .await
                .map(|_| ()),
        )?;
        ignore_not_found(
            dep.delete(&dep_name, &DeleteParams::default())
                .await
                .map(|_| ()),
        )?;
        // The per-workload env Secret (holds the managed-DB credential) under BOTH naming
        // schemes; a missing one 404s harmlessly. Deleting it removes the credential from
        // the namespace on teardown.
        ignore_not_found(
            secrets
                .delete(&plan::env_secret_name(sts_name), &DeleteParams::default())
                .await
                .map(|_| ()),
        )?;
        ignore_not_found(
            secrets
                .delete(&plan::env_secret_name(&dep_name), &DeleteParams::default())
                .await
                .map(|_| ()),
        )?;

        // The stateful PVC is RETAINED by default (a database's data must survive a
        // teardown); an explicit non-retain teardown deletes it too. Generic Deployments
        // back no PVC, so there is nothing to retain there.
        if !self.retain_pvc_on_stop {
            let pvcs: Api<PersistentVolumeClaim> =
                Api::namespaced(self.client.clone(), &self.namespace);
            // The data volume name in a managed-DB spec is the literal `data`.
            let claim = pvc_name("data", sts_name);
            ignore_not_found(
                pvcs.delete(&claim, &DeleteParams::default())
                    .await
                    .map(|_| ()),
            )?;
        }
        Ok(())
    }

    async fn health(&self, handle: &InstanceHandle) -> Result<Health, BackendError> {
        // Try the stateful object (named by the workload), then the generic Deployment
        // (named by the DNS-safe instance id). Ready once at least one pod passes its
        // readiness probe (the TCP probe the plan wires); for a managed DB the `SELECT 1`
        // provisioning probe rides the existing reconcile machinery on top of this.
        let sts: Api<StatefulSet> = Api::namespaced(self.client.clone(), &self.namespace);
        match sts.get_opt(&handle.workload).await {
            Ok(Some(s)) => {
                let ready = s.status.and_then(|st| st.ready_replicas).unwrap_or(0);
                return Ok(health_from_ready(ready));
            }
            Ok(None) => {}
            Err(e) => {
                return Err(BackendError::Other(format!(
                    "health get statefulset {}: {e}",
                    handle.workload
                )));
            }
        }
        let dep_name = workload_object_name(&handle.project, &handle.workload, handle.replica);
        let dep: Api<Deployment> = Api::namespaced(self.client.clone(), &self.namespace);
        match dep.get_opt(&dep_name).await {
            Ok(Some(d)) => {
                let ready = d.status.and_then(|st| st.available_replicas).unwrap_or(0);
                Ok(health_from_ready(ready))
            }
            Ok(None) => Ok(Health::Unhealthy),
            Err(e) => Err(BackendError::Other(format!(
                "health get deployment {dep_name}: {e}"
            ))),
        }
    }

    async fn replica_alive(&self, handle: &InstanceHandle) -> Option<bool> {
        // Affirmative liveness for the orphan reaper: `Some(true)` if the workload object
        // exists AND a pod is up, `Some(false)` if BOTH the stateful + generic objects are
        // cleanly absent (404), `None` on any API error (can't prove gone → never reap).
        let sts: Api<StatefulSet> = Api::namespaced(self.client.clone(), &self.namespace);
        match sts.get_opt(&handle.workload).await {
            Ok(Some(s)) => {
                // Present: live iff a replica (ready or not) is still scheduled.
                let replicas = s.status.map(|st| st.replicas).unwrap_or(0);
                return Some(replicas >= 1);
            }
            Ok(None) => {} // not a StatefulSet — fall through to the Deployment check
            Err(_) => return None, // indeterminate — fail closed (never reap)
        }
        let dep_name = workload_object_name(&handle.project, &handle.workload, handle.replica);
        let dep: Api<Deployment> = Api::namespaced(self.client.clone(), &self.namespace);
        match dep.get_opt(&dep_name).await {
            Ok(Some(d)) => {
                let replicas = d.status.and_then(|st| st.replicas).unwrap_or(0);
                Some(replicas >= 1)
            }
            // Both objects cleanly absent ⇒ affirmatively gone.
            Ok(None) => Some(false),
            Err(_) => None,
        }
    }

    async fn exec(
        &self,
        handle: &InstanceHandle,
        argv: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<ExecOutput, BackendError> {
        if argv.is_empty() {
            return Err(BackendError::Other("exec: empty argv".into()));
        }
        // Resolve the single pod of the workload replica (StatefulSet `-0` pod, else the
        // Deployment's current pod), and the container name within it.
        let (pod, container) = self.resolve_pod(handle).await?;
        self.exec_in_pod(&pod, &container, argv, stdin).await
    }

    async fn list_volumes(&self) -> Result<Vec<VolumeInfo>, BackendError> {
        // Every boatramp-managed PVC in the namespace → a VolumeInfo. The size is the
        // REQUESTED capacity (the core API exposes no per-PVC consumed bytes).
        let pvcs: Api<PersistentVolumeClaim> =
            Api::namespaced(self.client.clone(), &self.namespace);
        let lp = ListParams::default().labels(&plan::managed_label_selector());
        let list = pvcs
            .list(&lp)
            .await
            .map_err(|e| BackendError::Other(format!("list PVCs: {e}")))?;
        let mut out = Vec::with_capacity(list.items.len());
        for pvc in list.items {
            let Some(name) = pvc.metadata.name.clone() else {
                continue;
            };
            let size_bytes = pvc
                .spec
                .as_ref()
                .and_then(|s| s.resources.as_ref())
                .and_then(|r| r.requests.as_ref())
                .and_then(|req| req.get("storage"))
                .and_then(|q| plan::quantity_to_bytes(&q.0))
                .unwrap_or(0);
            out.push(VolumeInfo { name, size_bytes });
        }
        Ok(out)
    }

    async fn remove_volume(&self, name: &str) -> Result<bool, BackendError> {
        // Delete the PVC by name; `404` ⇒ it did not exist (`false`).
        let pvcs: Api<PersistentVolumeClaim> =
            Api::namespaced(self.client.clone(), &self.namespace);
        match pvcs.delete(name, &DeleteParams::default()).await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(false),
            Err(e) => Err(BackendError::Other(format!("delete PVC {name}: {e}"))),
        }
    }

    async fn remove_scoped_volume(&self, scope: &str) -> Result<bool, BackendError> {
        // The reaper's opt-in reclamation of a stranded managed-DB PGDATA. The scope names
        // `(project, workload)`; a managed DB's PVC is `data-<workload>`, so map the scope
        // back to that PVC and delete it (idempotent — a missing PVC is `false`).
        let workload = plan::workload_from_scope(scope);
        let claim = pvc_name("data", workload);
        self.remove_volume(&claim).await
    }
}

/// Map a StatefulSet/Deployment ready/available-replica count to a [`Health`].
fn health_from_ready(ready: i32) -> Health {
    if ready >= 1 {
        Health::Healthy
    } else {
        Health::Unhealthy
    }
}

/// Phase-2 inherent helpers: the stateful / stateless launch split, pod resolution for
/// `exec`/`logs`, the exec drain, the pod-log fetch, and the CSI VolumeSnapshot
/// snapshot/restore plumbing (the operator backup surface calls these).
impl KubernetesBackend {
    /// Launch a STATEFUL workload (declares a volume): StatefulSet + Service + PVC. Returns
    /// the routable endpoint host — the bare workload name the in-cluster DNS resolves.
    async fn launch_stateful(&self, req: &LaunchRequest) -> Result<String, BackendError> {
        let ctx = self.plan_context_named(req, req.workload.clone());
        let ResourcePlan {
            stateful_set,
            service,
            pvc,
            secret,
        } = plan::managed_db_plan(&ctx, &req.spec)
            .map_err(|e| BackendError::Launch(e.to_string()))?;
        // Apply the env Secret first (the pod references its keys), then the PVC (the pod
        // mounts it), then the workload, then the Service. Server-side apply is idempotent,
        // so a relaunch reconciles each in place.
        if let Some(secret) = &secret {
            self.apply(secret).await?;
        }
        self.apply(&pvc).await?;
        self.apply(&stateful_set).await?;
        self.apply(&service).await?;
        Ok(req.workload.clone())
    }

    /// Launch a STATELESS workload (no volume): a one-replica Deployment + ClusterIP
    /// Service named by the DNS-safe instance id. Returns that name — the endpoint host.
    async fn launch_deployment(&self, req: &LaunchRequest) -> Result<String, BackendError> {
        let name = workload_object_name(&req.project, &req.workload, req.replica);
        let ctx = self.plan_context_named(req, name.clone());
        let DeploymentPlan {
            deployment,
            service,
            secret,
        } = plan::deployment_plan(&ctx, &req.spec)
            .map_err(|e| BackendError::Launch(e.to_string()))?;
        // The env Secret first (the pod references its keys), then the Deployment + Service.
        if let Some(secret) = &secret {
            self.apply(secret).await?;
        }
        self.apply(&deployment).await?;
        self.apply(&service).await?;
        Ok(name)
    }

    /// Resolve the single pod of a workload replica + the container to target: a stateful
    /// workload's pod is the StatefulSet's `<workload>-0` (container `db`); a generic
    /// workload's pod is found by the per-workload label on the Deployment's ReplicaSet
    /// (container `app`), preferring a `Running` one.
    async fn resolve_pod(&self, handle: &InstanceHandle) -> Result<(String, String), BackendError> {
        use k8s_openapi::api::core::v1::Pod;
        let sts: Api<StatefulSet> = Api::namespaced(self.client.clone(), &self.namespace);
        let is_stateful = sts.get_opt(&handle.workload).await.map_err(|e| {
            BackendError::Other(format!(
                "resolve pod: get statefulset {}: {e}",
                handle.workload
            ))
        })?;
        if is_stateful.is_some() {
            return Ok((
                format!("{}-0", handle.workload),
                pod_container_name(true).to_string(),
            ));
        }
        let dep_name = workload_object_name(&handle.project, &handle.workload, handle.replica);
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let lp = ListParams::default().labels(&format!("{}={dep_name}", plan::WORKLOAD_LABEL));
        let list = pods
            .list(&lp)
            .await
            .map_err(|e| BackendError::Other(format!("resolve pod: list pods: {e}")))?;
        let pod = list
            .items
            .iter()
            .find(|p| p.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Running"))
            .or_else(|| list.items.first());
        match pod.and_then(|p| p.metadata.name.clone()) {
            Some(name) => Ok((name, pod_container_name(false).to_string())),
            None => Err(BackendError::Other(format!(
                "no pod for workload {} (replica {})",
                handle.workload, handle.replica
            ))),
        }
    }

    /// Run `argv` inside `pod`/`container` via the exec subresource, feeding `stdin` (then
    /// half-closing it) and draining stdout/stderr concurrently so a chatty command cannot
    /// stall, and read the exit code from the remotecommand `Status`.
    async fn exec_in_pod(
        &self,
        pod: &str,
        container: &str,
        argv: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<ExecOutput, BackendError> {
        use k8s_openapi::api::core::v1::Pod;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let ap = plan::exec_attach_params(container, stdin.is_some());
        let mut attached = pods
            .exec(pod, argv.iter().cloned(), &ap)
            .await
            .map_err(|e| BackendError::Other(format!("exec on {pod}: {e}")))?;

        let status_fut = attached.take_status();
        let mut stdin_writer = attached.stdin();
        let mut stdout_reader = attached.stdout();
        let mut stderr_reader = attached.stderr();
        let input = stdin.map(<[u8]>::to_vec);

        let writer = async {
            if let Some(w) = stdin_writer.as_mut() {
                if let Some(bytes) = input.as_ref() {
                    w.write_all(bytes)
                        .await
                        .map_err(|e| BackendError::Other(format!("exec stdin write: {e}")))?;
                    w.flush()
                        .await
                        .map_err(|e| BackendError::Other(format!("exec stdin flush: {e}")))?;
                }
                // Half-close stdin so the command sees EOF.
                w.shutdown()
                    .await
                    .map_err(|e| BackendError::Other(format!("exec stdin close: {e}")))?;
            }
            Ok::<(), BackendError>(())
        };
        let out = async {
            let mut buf = Vec::new();
            if let Some(r) = stdout_reader.as_mut() {
                r.read_to_end(&mut buf)
                    .await
                    .map_err(|e| BackendError::Other(format!("exec stdout read: {e}")))?;
            }
            Ok::<Vec<u8>, BackendError>(buf)
        };
        let err = async {
            let mut buf = Vec::new();
            if let Some(r) = stderr_reader.as_mut() {
                r.read_to_end(&mut buf)
                    .await
                    .map_err(|e| BackendError::Other(format!("exec stderr read: {e}")))?;
            }
            Ok::<Vec<u8>, BackendError>(buf)
        };
        let (w, o, e) = tokio::join!(writer, out, err);
        w?;
        let stdout = o?;
        let stderr = e?;

        let status = match status_fut {
            Some(f) => f.await,
            None => None,
        };
        let exit_code = plan::exec_exit_code(status.as_ref());
        attached
            .join()
            .await
            .map_err(|e| BackendError::Other(format!("exec join on {pod}: {e}")))?;
        Ok(ExecOutput {
            exit_code,
            stdout,
            stderr,
        })
    }

    /// Fetch a workload replica's pod logs (the operator log surface). `tail_lines` bounds
    /// the backlog (`None` ⇒ from the container start). `follow` streams until the pod
    /// ends, so a bounded `tail_lines` + `follow == false` is the snapshot form.
    pub async fn logs(
        &self,
        handle: &InstanceHandle,
        follow: bool,
        tail_lines: Option<i64>,
    ) -> Result<String, BackendError> {
        use k8s_openapi::api::core::v1::Pod;
        let (pod, container) = self.resolve_pod(handle).await?;
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let lp = plan::log_params(&container, follow, tail_lines);
        pods.logs(&pod, &lp)
            .await
            .map_err(|e| BackendError::Other(format!("logs for {pod}: {e}")))
    }

    /// Whether CSI snapshot/restore is enabled (a `VolumeSnapshotClass` is configured).
    pub fn snapshots_supported(&self) -> bool {
        self.volume_snapshot_class.is_some()
    }

    /// Snapshot PVC `pvc` into a CSI `VolumeSnapshot` named `snapshot_name` (the backup /
    /// clone-source primitive). [`BackendError::Unsupported`] when no `VolumeSnapshotClass`
    /// is configured (the StorageClass's CSI driver cannot snapshot, or the operator did
    /// not opt in) — a clean "unsupported".
    pub async fn snapshot_volume(
        &self,
        pvc: &str,
        snapshot_name: &str,
    ) -> Result<(), BackendError> {
        let Some(class) = self.volume_snapshot_class.clone() else {
            return Err(BackendError::Unsupported);
        };
        let ctx = self.snapshot_context(snapshot_name);
        let snap = plan::volume_snapshot(&ctx, snapshot_name, pvc, Some(&class));
        self.apply_volume_snapshot(&snap).await
    }

    /// Restore a CSI `VolumeSnapshot` into a new PVC `pvc` (`size_mib` ≥ the snapshot's
    /// restore size), the shape a `db restore` / clone-from-backup binds.
    /// [`BackendError::Unsupported`] when snapshots are not enabled.
    pub async fn restore_volume(
        &self,
        snapshot_name: &str,
        pvc: &str,
        size_mib: u32,
    ) -> Result<(), BackendError> {
        if self.volume_snapshot_class.is_none() {
            return Err(BackendError::Unsupported);
        }
        let ctx = self.snapshot_context(pvc);
        let restored = plan::restore_pvc_from_snapshot(&ctx, pvc, snapshot_name, size_mib);
        self.apply(&restored).await
    }

    /// A minimal plan context for a snapshot/restore object (namespace + storage class +
    /// the object name as the workload label; no project/replica identity applies).
    fn snapshot_context(&self, name: &str) -> PlanContext {
        PlanContext {
            project: String::new(),
            workload: name.to_string(),
            replica: 0,
            namespace: self.namespace.clone(),
            storage_class: self.storage_class.clone(),
            image_pull_secret: None,
        }
    }

    /// Server-side-apply a CSI `VolumeSnapshot` (a CRD, applied dynamically since it has no
    /// `k8s-openapi` type) under boatramp's field manager.
    async fn apply_volume_snapshot(&self, snap: &plan::VolumeSnapshot) -> Result<(), BackendError> {
        let ar = ApiResource {
            group: plan::SNAPSHOT_API_GROUP.to_string(),
            version: plan::SNAPSHOT_API_VERSION.to_string(),
            api_version: format!(
                "{}/{}",
                plan::SNAPSHOT_API_GROUP,
                plan::SNAPSHOT_API_VERSION
            ),
            kind: "VolumeSnapshot".to_string(),
            plural: "volumesnapshots".to_string(),
        };
        let name = snap
            .metadata
            .name
            .clone()
            .ok_or_else(|| BackendError::Other("VolumeSnapshot has no name".into()))?;
        let body = serde_json::to_value(snap)
            .map_err(|e| BackendError::Other(format!("encode VolumeSnapshot: {e}")))?;
        let api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &self.namespace, &ar);
        api.patch(
            &name,
            &PatchParams::apply(FIELD_MANAGER).force(),
            &Patch::Apply(&body),
        )
        .await
        .map_err(|e| BackendError::Other(format!("apply VolumeSnapshot {name}: {e}")))?;
        Ok(())
    }
}
