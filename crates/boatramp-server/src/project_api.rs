//! The **project** control-plane API (0.2.0): CRUD over the [`Project`] entity — the
//! owning Workspace boundary above sites/functions/compute. `GET`/`POST /api/projects`
//! list + create; `GET`/`DELETE /api/projects/{proj}` read + delete. The per-resource
//! `/api/projects/{proj}/sites/…` surface is served by the existing site/function/…
//! handlers via the [`project_scope`](crate::project_scope) rewrite, not here.
//!
//! Pulls the shared response helpers in via `use super::*`.

use super::*;
use boatramp_core::project::{Project, ProjectConfig, ProjectMeta, DEFAULT_PROJECT};
use boatramp_core::time::now_unix;

/// The `POST /api/projects` request body: a new project's identity + optional metadata.
#[derive(Debug, Deserialize)]
pub(super) struct CreateProjectRequest {
    /// The project slug — its stable identity (unique, immutable, no `/`).
    name: String,
    /// Display name (defaults to the slug).
    #[serde(default)]
    display: String,
    /// Free-text description.
    #[serde(default)]
    description: String,
    /// Default region for the project's compute/replicas.
    #[serde(default)]
    region: Option<String>,
}

/// `GET /api/projects` — list every declared project, sorted by name.
pub(super) async fn list_projects(State(deploy): State<DeployStore>) -> Response {
    match deploy.list_projects().await {
        Ok(projects) => Json(projects).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `POST /api/projects` — create a project. `409` if one already exists (updates go
/// through the project's own resources, not a re-create), `422` on an invalid slug.
pub(super) async fn create_project(
    State(deploy): State<DeployStore>,
    Json(req): Json<CreateProjectRequest>,
) -> Response {
    let name = req.name.trim();
    if let Err(err) = boatramp_core::project::validate_resource_name("project", name) {
        return (StatusCode::UNPROCESSABLE_ENTITY, format!("{err}\n")).into_response();
    }
    // `default` is reserved (the home of pre-project resources); it always exists
    // and can never be (re-)created or deleted.
    if name == boatramp_core::project::DEFAULT_PROJECT {
        return (
            StatusCode::CONFLICT,
            format!("project {name:?} is reserved\n"),
        )
            .into_response();
    }
    match deploy.get_project(name).await {
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                format!("project `{name}` already exists\n"),
            )
                .into_response()
        }
        Ok(None) => {}
        Err(err) => return deploy_error_response(err),
    }
    let project = Project {
        version: boatramp_core::SCHEMA_VERSION,
        name: name.to_string(),
        created_at: now_unix(),
        meta: ProjectMeta {
            display: req.display,
            description: req.description,
            ..Default::default()
        },
        config: ProjectConfig { region: req.region },
        secrets_ref: None,
    };
    match deploy.put_project(&project).await {
        Ok(_) => (StatusCode::CREATED, Json(project)).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `GET /api/projects/{proj}` — read a project, `404` if absent.
pub(super) async fn get_project(
    State(deploy): State<DeployStore>,
    Path(proj): Path<String>,
) -> Response {
    match deploy.get_project(&proj).await {
        Ok(Some(project)) => Json(project).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, format!("no project `{proj}`\n")).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Query parameters for `DELETE /api/projects/{proj}`: the destructive-cascade
/// controls. Both default to `false` (the plain, failsafe delete).
#[derive(Debug, Default, Deserialize)]
pub(super) struct DeleteProjectQuery {
    /// Cascade: tear down everything the project owns, then remove the project.
    #[serde(default)]
    force: bool,
    /// Preview only: report what would be torn down and mutate nothing (`force`
    /// is ignored when this is set).
    #[serde(default)]
    dry_run: bool,
}

/// `DELETE /api/projects/{proj}` — remove a project.
///
/// Behaviour by query:
/// - `?dry_run=true` → `200` + the [`ProjectTeardownPlan`] JSON; **mutates nothing**
///   (`force` is ignored).
/// - neither → the **failsafe** delete: `204` if empty, `409` (with the enumerated
///   list of what remains) while it still owns resources, `404` if it never existed.
/// - `?force=true` → **cascade**: deprovision managed DBs, then delete compute
///   workloads, functions, sites (freeing their global domain claims), secrets, the
///   GraphQL safelist + subgraphs, reclaim the now-orphaned compute volumes, and
///   finally purge any residual state + the project itself; returns `200` + the
///   executed plan JSON. `404` if the project never existed and owns nothing.
///
/// The reserved `default` project is `409` for **every** combination — never deletable.
pub(super) async fn delete_project(
    State(deploy): State<DeployStore>,
    Extension(deprovisioner): Extension<Option<Arc<dyn boatramp_core::sql::TenantDeprovisioner>>>,
    Extension(volumes): Extension<Option<Arc<dyn boatramp_core::compute::ComputeVolumes>>>,
    Path(proj): Path<String>,
    Query(q): Query<DeleteProjectQuery>,
) -> Response {
    // `default` is reserved and can never be deleted — for the failsafe, the dry-run,
    // and the cascade alike.
    if proj == DEFAULT_PROJECT {
        return (
            StatusCode::CONFLICT,
            "the `default` project cannot be deleted\n",
        )
            .into_response();
    }

    // Dry-run: preview the teardown plan and mutate nothing. `force` is ignored.
    if q.dry_run {
        return match deploy.enumerate_project_resources(&proj).await {
            Ok(plan) => (StatusCode::OK, Json(plan)).into_response(),
            Err(err) => deploy_error_response(err),
        };
    }

    if q.force {
        return force_delete_project(&deploy, deprovisioner, volumes, &proj).await;
    }

    // The failsafe path — unchanged: delete only an empty project.
    match deploy.delete_project(&proj).await {
        Ok(true) => {
            // The project is gone from the store. Best-effort: drop its managed
            // databases + roles + sealed credentials (the tenant's, nothing else).
            // A failure is logged inside the deprovisioner and never affects this
            // response — an orphaned DB is a lesser evil than a failed delete.
            if let Some(deprovisioner) = deprovisioner {
                deprovisioner.deprovision_project(&proj).await;
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, format!("no project `{proj}`\n")).into_response(),
        Err(DeployError::Conflict(msg)) => {
            (StatusCode::CONFLICT, format!("{msg}\n")).into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// The `?force=true` cascade. Enumerates the project's resources once (capturing the
/// volume names before teardown drops them), then tears everything down in a fixed,
/// dependency-safe order and returns the executed plan.
async fn force_delete_project(
    deploy: &DeployStore,
    deprovisioner: Option<Arc<dyn boatramp_core::sql::TenantDeprovisioner>>,
    volumes: Option<Arc<dyn boatramp_core::compute::ComputeVolumes>>,
    proj: &str,
) -> Response {
    use boatramp_core::project::ProjectRef;

    // 1. Snapshot the plan up front — volume names must be captured BEFORE the
    //    workloads (and thus their spec pointers) are deleted.
    let plan = match deploy.enumerate_project_resources(proj).await {
        Ok(plan) => plan,
        Err(err) => return deploy_error_response(err),
    };

    // A project that never existed and owns nothing → 404, matching the failsafe.
    let exists = match deploy.get_project(proj).await {
        Ok(p) => p.is_some(),
        Err(err) => return deploy_error_response(err),
    };
    if !exists && plan.is_empty() {
        return (StatusCode::NOT_FOUND, format!("no project `{proj}`\n")).into_response();
    }

    let pref = ProjectRef::new(proj);

    // 2. Deprovision managed DBs/roles/creds FIRST (best-effort, logged; a failure
    //    must not abort the cascade — an orphaned DB is a lesser evil than a
    //    half-deleted project).
    if let Some(deprovisioner) = &deprovisioner {
        deprovisioner.deprovision_project(proj).await;
    }

    // 3. Compute workloads.
    for c in &plan.compute {
        if let Err(err) = deploy.delete_compute_workload(pref, &c.name).await {
            return deploy_error_response(err);
        }
    }
    // 4. Functions (each a complete subtree sweep).
    for name in &plan.functions {
        if let Err(err) = deploy.delete_function(pref, name).await {
            return deploy_error_response(err);
        }
    }
    // 5. Sites (each also frees the global domain/wildcard/httpchallenge claims).
    for site in &plan.sites {
        if let Err(err) = deploy.delete_site(pref, site).await {
            return deploy_error_response(err);
        }
    }
    // 6. Secrets, the GraphQL safelist, and subgraphs are all cleared by
    //    `purge_project` (step 8): secrets live under the project resource prefix, and
    //    the safelist (`hapq/<proj>/…`) + subgraph registry (`graphql/<proj>/…`) are
    //    swept explicitly by their prefixes there. None has an external side effect
    //    beyond its KV keys, so the residual purge is the whole delete — no separate
    //    scoped-delete call is needed (and it avoids depending on the feature-gated
    //    graphql/secret modules from this handler).

    // 7. Reclaim the now-orphaned compute volumes. Force to be race-safe (the
    //    workloads that referenced them are gone). If no volume capability is wired,
    //    log and skip — a missing cap must not fail the cascade.
    let orphaned = plan.all_volumes();
    if !orphaned.is_empty() {
        match &volumes {
            Some(volumes) => {
                for name in &orphaned {
                    if let Err(err) = volumes.remove(name, true).await {
                        tracing::warn!(
                            project = proj,
                            volume = name,
                            error = %err,
                            "force-delete: reclaiming compute volume failed (leaving it orphaned)"
                        );
                    }
                }
            }
            None => tracing::warn!(
                project = proj,
                volumes = ?orphaned,
                "force-delete: no volume-capable backend wired; leaving compute volumes on disk"
            ),
        }
    }

    // 8. Purge any residual KV (incl. the graphql registry/safelist) + the project
    //    pointer/history/reverse-index.
    if let Err(err) = deploy.purge_project(proj).await {
        return deploy_error_response(err);
    }

    (StatusCode::OK, Json(plan)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::compute::{
        ComputeSpec, ComputeVolumes, ComputeWorkload, PlacementConstraints, RestartPolicy,
        RootSource, VolumeError, VolumeRef, VolumeStatus,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::project::{Project, ProjectRef};
    use boatramp_core::sql::TenantDeprovisioner;
    use std::sync::Mutex;

    /// A blob store the project-delete path never touches.
    struct NullStorage;
    #[async_trait::async_trait]
    impl boatramp_core::Storage for NullStorage {
        async fn get(
            &self,
            _: &str,
        ) -> Result<boatramp_core::GetObject, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn get_range(
            &self,
            _: &str,
            _: u64,
            _: Option<u64>,
        ) -> Result<boatramp_core::GetObject, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn put(
            &self,
            _: &str,
            _: boatramp_core::ByteStream,
            _: boatramp_core::PutMeta,
        ) -> Result<boatramp_core::ObjectMeta, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::unsupported("null"))
        }
        async fn head(
            &self,
            _: &str,
        ) -> Result<boatramp_core::ObjectMeta, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn delete(&self, _: &str) -> Result<(), boatramp_core::StorageError> {
            Ok(())
        }
        async fn list(
            &self,
            _: &str,
        ) -> Result<Vec<boatramp_core::ObjectMeta>, boatramp_core::StorageError> {
            Ok(Vec::new())
        }
    }

    /// Records each `deprovision_project` call.
    #[derive(Default)]
    struct RecordingDeprovisioner {
        projects: Mutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl TenantDeprovisioner for RecordingDeprovisioner {
        async fn deprovision_project(&self, project: &str) {
            self.projects.lock().unwrap().push(project.to_string());
        }
        async fn deprovision_site(&self, _project: &str, _site: &str) {}
    }

    /// Records each volume `remove` call.
    #[derive(Default)]
    struct RecordingVolumes {
        removed: Mutex<Vec<(String, bool)>>,
    }
    #[async_trait::async_trait]
    impl ComputeVolumes for RecordingVolumes {
        async fn list(&self) -> Result<Vec<VolumeStatus>, VolumeError> {
            Ok(Vec::new())
        }
        async fn remove(&self, name: &str, force: bool) -> Result<bool, VolumeError> {
            self.removed.lock().unwrap().push((name.to_string(), force));
            Ok(true)
        }
    }

    fn deploy() -> DeployStore {
        DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()))
    }

    // The `keys` module in boatramp-core is `pub(crate)`, so tests here spell out the
    // documented, stable key formats directly (canonical hosts are lowercase; the
    // seeded hosts already are).
    fn domain_key(host: &str) -> String {
        format!("domain/{host}")
    }
    fn secret_key(project: &str, name: &str) -> String {
        format!("project/{project}/secret/{name}")
    }

    async fn body_json(resp: Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, value)
    }

    /// Seed a project owning a site (+ domain claim), a function, a compute workload
    /// (spec with a named volume), and a secret.
    async fn seed_full_project(deploy: &DeployStore, name: &str) {
        let pref = ProjectRef::new(name);
        deploy
            .put_project(&Project {
                version: boatramp_core::SCHEMA_VERSION,
                name: name.into(),
                created_at: 1,
                meta: Default::default(),
                config: Default::default(),
                secrets_ref: None,
            })
            .await
            .unwrap();

        let mut cfg = boatramp_core::config::SiteConfig::default();
        cfg.domains.primary = Some(format!("{name}.example"));
        deploy.set_site_config(pref, "www", &cfg).await.unwrap();
        deploy
            .kv()
            .put(
                &domain_key(&format!("{name}.example")),
                boatramp_core::project::DomainOwner::new(name, "www").to_bytes(),
            )
            .await
            .unwrap();

        deploy
            .put_function(
                pref,
                &boatramp_core::function::Function::new(
                    "worker",
                    boatramp_core::function::Owner::Project(name.into()),
                    "component-hash",
                    Default::default(),
                    Default::default(),
                    0,
                ),
            )
            .await
            .unwrap();

        let spec = ComputeSpec {
            version: boatramp_core::SCHEMA_VERSION,
            root: RootSource::Rootfs("r".repeat(64)),
            kernel: "k".repeat(64),
            kernel_cmdline: None,
            vcpus: 1,
            mem_mib: 256,
            entrypoint: vec!["/app".into()],
            env: Default::default(),
            port: 8080,
            restart: RestartPolicy::Always,
            scale_to_zero: false,
            volumes: vec![VolumeRef {
                mount: "/data".into(),
                name: format!("{name}-data"),
                size_mib: 512,
            }],
            writable_root: false,
            cap_add: Vec::new(),
            user: None,
            isolation: Default::default(),
            prefer_backend: None,
            bindings: vec![],
        };
        let hash = deploy.put_compute_spec(&spec).await.unwrap();
        deploy
            .set_compute_workload(
                pref,
                &ComputeWorkload {
                    version: boatramp_core::SCHEMA_VERSION,
                    name: "pg".into(),
                    active: hash,
                    replicas: 1,
                    placement: PlacementConstraints::default(),
                },
            )
            .await
            .unwrap();

        deploy
            .kv()
            .put(&secret_key(name, "api-key"), b"sealed".to_vec())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn dry_run_previews_and_mutates_nothing() {
        let deploy = deploy();
        seed_full_project(&deploy, "acme").await;
        let before = deploy.kv().list_prefix("").await.unwrap().len();

        let (st, plan) = body_json(
            delete_project(
                State(deploy.clone()),
                Extension(None),
                Extension(None),
                Path("acme".to_string()),
                Query(DeleteProjectQuery {
                    force: false,
                    dry_run: true,
                }),
            )
            .await,
        )
        .await;

        assert_eq!(st, StatusCode::OK);
        assert_eq!(plan["project"], "acme");
        assert_eq!(plan["sites"], serde_json::json!(["www"]));
        assert_eq!(plan["functions"], serde_json::json!(["worker"]));
        assert_eq!(plan["compute"][0]["name"], "pg");
        assert_eq!(
            plan["compute"][0]["volumes"],
            serde_json::json!(["acme-data"])
        );
        assert_eq!(plan["secrets"], serde_json::json!(["api-key"]));

        // Store is byte-unchanged: same key count and the project still present.
        let after = deploy.kv().list_prefix("").await.unwrap().len();
        assert_eq!(before, after, "dry-run mutated the store");
        assert!(deploy.get_project("acme").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn force_cascades_and_leaves_other_projects_untouched() {
        let deploy = deploy();
        seed_full_project(&deploy, "acme").await;
        seed_full_project(&deploy, "keepme").await;

        let deprov = Arc::new(RecordingDeprovisioner::default());
        let vols = Arc::new(RecordingVolumes::default());

        let (st, report) = body_json(
            delete_project(
                State(deploy.clone()),
                Extension(Some(deprov.clone() as Arc<dyn TenantDeprovisioner>)),
                Extension(Some(vols.clone() as Arc<dyn ComputeVolumes>)),
                Path("acme".to_string()),
                Query(DeleteProjectQuery {
                    force: true,
                    dry_run: false,
                }),
            )
            .await,
        )
        .await;

        assert_eq!(st, StatusCode::OK);
        assert_eq!(report["project"], "acme");

        // Project + every family gone.
        assert!(deploy.get_project("acme").await.unwrap().is_none());
        assert!(deploy
            .kv()
            .list_prefix(&boatramp_core::project::resource_prefix("acme"))
            .await
            .unwrap()
            .is_empty());
        assert!(deploy
            .kv()
            .get(&domain_key("acme.example"))
            .await
            .unwrap()
            .is_none());

        // deprovision_project called exactly once, for acme.
        assert_eq!(*deprov.projects.lock().unwrap(), vec!["acme".to_string()]);
        // The workload's volume was removed, forced.
        assert_eq!(
            *vols.removed.lock().unwrap(),
            vec![("acme-data".to_string(), true)]
        );

        // The second project is untouched.
        assert!(deploy.get_project("keepme").await.unwrap().is_some());
        assert!(deploy
            .get_site_config(ProjectRef::new("keepme"), "www")
            .await
            .unwrap()
            .is_some());
        assert!(deploy
            .kv()
            .get(&domain_key("keepme.example"))
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn non_force_nonempty_is_409_with_enumeration() {
        let deploy = deploy();
        seed_full_project(&deploy, "acme").await;

        let resp = delete_project(
            State(deploy.clone()),
            Extension(None),
            Extension(None),
            Path("acme".to_string()),
            Query(DeleteProjectQuery {
                force: false,
                dry_run: false,
            }),
        )
        .await;

        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let msg = String::from_utf8_lossy(&bytes);
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            msg.contains("still owns resources"),
            "409 body should enumerate: {msg}"
        );
        // The failsafe refused — the project is still there.
        assert!(deploy.get_project("acme").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn default_project_with_force_is_409() {
        let deploy = deploy();
        let resp = delete_project(
            State(deploy.clone()),
            Extension(None),
            Extension(None),
            Path(DEFAULT_PROJECT.to_string()),
            Query(DeleteProjectQuery {
                force: true,
                dry_run: false,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }
}
