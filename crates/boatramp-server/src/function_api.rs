//! The function management API (FA-1/FA-2): list function summaries and
//! deploy, version, alias, roll back, and remove function definitions. This is
//! the always-on control surface (no wasm engine required); the runtime that
//! invokes functions lives in `function_runtime`. Pulls the serve-pipeline
//! scope in via `use super::*`.

use super::*;

use boatramp_core::function::FunctionSummary;

/// `?site=` filter for the functions view.
#[derive(serde::Deserialize)]
pub(super) struct FunctionQuery {
    site: Option<String>,
}

/// `GET /api/functions[?site=…]` — the derived, **read-only** site-scoped function
/// view (FA-1): desugar each site's active manifest into functions + triggers and
/// resolve component paths to their blob-hash version ids. A pure projection of the
/// manifests — the serve path is untouched, so a site's handlers are unchanged.
/// `system·read`.
pub(super) async fn list_functions(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    axum::extract::Query(query): axum::extract::Query<FunctionQuery>,
) -> Response {
    use boatramp_core::function;
    let sites = match &query.site {
        Some(s) => vec![s.clone()],
        None => match deploy.all_sites(project.as_ref()).await {
            Ok(s) => s,
            Err(err) => return deploy_error_response(err),
        },
    };
    let mut out: Vec<FunctionSummary> = Vec::new();
    for site in sites {
        let manifest = match deploy.current_manifest(project.as_ref(), &site).await {
            Ok(Some(m)) => m,
            Ok(None) => continue,
            Err(err) => return deploy_error_response(err),
        };
        let (specs, triggers) = function::desugar(&manifest.config);
        for f in function::materialize(&specs, &site, &manifest.files, 0) {
            let trigs = triggers
                .iter()
                .filter(|t| t.target.as_ref().map(|r| r.name.as_str()) == Some(f.name.as_str()))
                .map(std::string::ToString::to_string)
                .collect();
            out.push(FunctionSummary {
                name: format!("{site}/{}", f.name),
                owner: format!("site:{site}"),
                runtime: f.config.runtime.as_str().to_string(),
                version: f.active,
                triggers: trigs,
            });
        }
    }
    // Top-level (independently-stored) functions — FA-2. A `?site=` filter is
    // site-scoped only, so it excludes these.
    if query.site.is_none() {
        match deploy.list_stored_functions(project.as_ref()).await {
            Ok(stored) => {
                for f in stored {
                    out.push(FunctionSummary {
                        name: f.name.clone(),
                        owner: f.owner.to_string(),
                        runtime: f.config.runtime.as_str().to_string(),
                        version: f.active,
                        // A top-level function has a stable invoke URL (FA-3).
                        triggers: vec![format!("invoke {}", f.name)],
                    });
                }
            }
            Err(err) => return deploy_error_response(err),
        }
    }
    Json(out).into_response()
}

/// Body of `PUT /api/functions/:name` — deploy a version of a top-level function.
#[derive(serde::Deserialize)]
pub(super) struct FunctionUpsert {
    /// The component blob hash (uploaded first via `PUT /api/blobs/<hash>`).
    pub(super) component: String,
    /// Binding/capability config.
    #[serde(default)]
    pub(super) config: boatramp_core::function::FunctionConfig,
    /// Version lifecycle (defaults to `deploy-pinned`; top-level functions choose
    /// `independent`).
    #[serde(default)]
    pub(super) lifecycle: boatramp_core::function::Lifecycle,
}

/// Query for `PUT /api/functions/:name`.
#[derive(serde::Deserialize, Default)]
pub(super) struct DeployFunctionQuery {
    /// When this function is an **already-registered** federation subgraph, whether to refresh
    /// its registered SDL from the new version and block the deploy if the new schema no longer
    /// composes (default `true`). Set `false` to deploy without touching the registry — the
    /// escape hatch for a coordinated multi-subgraph migration.
    #[serde(default)]
    register_subgraph: Option<bool>,
}

/// If `name` is an already-registered federation subgraph, refresh its registered SDL from the
/// **pending** component and **block** (return an error response) if the new schema does not
/// compose — so a subgraph redeploy can never leave the project's supergraph invalid or stale.
/// First registration stays an explicit operator action (a not-yet-registered function is left
/// alone; register it with `PUT …/graphql/subgraphs/{name}/function`), and
/// `?register_subgraph=false` skips this entirely. `Ok(())` ⇒ proceed with the deploy.
#[cfg(feature = "handlers")]
async fn refresh_registered_subgraph(
    deploy: &DeployStore,
    handlers: &HandlerRuntime,
    project: boatramp_core::project::ProjectRef<'_>,
    name: &str,
    function: &boatramp_core::function::Function,
    component: &str,
    register: Option<bool>,
) -> Result<(), Response> {
    if register == Some(false) {
        return Ok(()); // explicit opt-out
    }
    let kv = deploy.kv().as_ref();
    if !crate::graphql_registry::is_subgraph(kv, project.as_str(), name).await {
        return Ok(()); // first registration is explicit
    }
    let sdl = match handlers
        .introspect_subgraph_sdl(deploy, project, function, component)
        .await
    {
        Ok(sdl) => sdl,
        // No engine on this node — skip rather than block; the registered SDL isn't refreshed.
        Err(crate::function_runtime::SubgraphSdlError::Unavailable) => return Ok(()),
        Err(crate::function_runtime::SubgraphSdlError::NotASubgraph) => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "the new version of registered subgraph `{name}` no longer answers \
                     `{{ _service {{ sdl }} }}`; deploy with `?register_subgraph=false` to keep \
                     the current SDL, or unregister it first\n"
                ),
            )
                .into_response())
        }
        Err(crate::function_runtime::SubgraphSdlError::InvokeFailed(msg)) => {
            return Err((
                StatusCode::BAD_GATEWAY,
                format!("could not introspect subgraph `{name}`'s new version: {msg}\n"),
            )
                .into_response())
        }
    };
    match crate::graphql_registry::publish(kv, project.as_str(), name, &sdl).await {
        Ok(_) => Ok(()),
        Err(crate::graphql_registry::PublishError::Composition(e)) => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "the new version of subgraph `{name}` does not compose: {e}\n(deploy with \
                 `?register_subgraph=false` to skip, or unregister a conflicting subgraph first)\n"
            ),
        )
            .into_response()),
        Err(crate::graphql_registry::PublishError::Store(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("registry store error: {e}\n"),
        )
            .into_response()),
    }
}

/// No wasm engine in this build → nothing to refresh; the deploy proceeds unchanged.
#[cfg(not(feature = "handlers"))]
async fn refresh_registered_subgraph(
    _deploy: &DeployStore,
    _handlers: &HandlerRuntime,
    _project: boatramp_core::project::ProjectRef<'_>,
    _name: &str,
    _function: &boatramp_core::function::Function,
    _component: &str,
    _register: Option<bool>,
) -> Result<(), Response> {
    Ok(())
}

/// `PUT /api/functions/:name` (FA-2) — deploy a version of a top-level function.
/// The component blob must already be uploaded. Creates the function if new;
/// otherwise appends + activates the version (idempotent per component hash).
/// `system·admin`.
pub(super) async fn deploy_function(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    axum::extract::Query(q): axum::extract::Query<DeployFunctionQuery>,
    Path(name): Path<String>,
    Json(body): Json<FunctionUpsert>,
) -> Response {
    use boatramp_core::function::{Function, Owner};
    if let Some(resp) = reject_invalid_name("function", &name) {
        return resp;
    }
    match deploy.has_blob(&body.component).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("component blob {} not uploaded\n", body.component),
            )
                .into_response()
        }
        Err(err) => return deploy_error_response(err),
    }
    let now = now_unix();
    let f = match deploy.get_function(project.as_ref(), &name).await {
        Ok(Some(mut existing)) => {
            existing.config = body.config;
            existing.upsert_version(&body.component, body.lifecycle, now);
            existing
        }
        // A brand-new top-level function is owned by the (single, for now) default
        // project; per-tenant ownership arrives with FA-4.
        Ok(None) => Function::new(
            name.clone(),
            Owner::Project("default".to_string()),
            &body.component,
            body.config,
            body.lifecycle,
            now,
        ),
        Err(err) => return deploy_error_response(err),
    };
    // Before the new version becomes active: if this function is a registered federation
    // subgraph, refresh its SDL and refuse the deploy if the new schema no longer composes with
    // the project's supergraph (a redeploy must never leave the supergraph invalid or stale).
    if let Err(resp) = refresh_registered_subgraph(
        &deploy,
        &handlers,
        project.as_ref(),
        &name,
        &f,
        &body.component,
        q.register_subgraph,
    )
    .await
    {
        return resp;
    }
    if let Err(err) = deploy.put_function(project.as_ref(), &f).await {
        return deploy_error_response(err);
    }
    Json(f).into_response()
}

/// Body of `POST /api/functions/:name/rollback`.
#[derive(serde::Deserialize)]
pub(super) struct RollbackBody {
    pub(super) to: String,
}

/// `POST /api/functions/:name/rollback` (FA-2) — point active at a prior version.
pub(super) async fn rollback_function(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(name): Path<String>,
    Json(body): Json<RollbackBody>,
) -> Response {
    match deploy.get_function(project.as_ref(), &name).await {
        Ok(Some(mut f)) => match f.rollback(&body.to) {
            Ok(()) => {
                if let Err(err) = deploy.put_function(project.as_ref(), &f).await {
                    return deploy_error_response(err);
                }
                Json(f).into_response()
            }
            Err(msg) => (StatusCode::BAD_REQUEST, format!("{msg}\n")).into_response(),
        },
        Ok(None) => (StatusCode::NOT_FOUND, format!("no function {name:?}\n")).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Body of `PUT /api/functions/:name/aliases/:label`.
#[derive(serde::Deserialize)]
pub(super) struct AliasBody {
    pub(super) version: String,
}

/// `PUT /api/functions/:name/aliases/:label` (FA-2) — point a label at a version.
pub(super) async fn alias_function(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path((name, label)): Path<(String, String)>,
    Json(body): Json<AliasBody>,
) -> Response {
    match deploy.get_function(project.as_ref(), &name).await {
        Ok(Some(mut f)) => match f.set_alias(&label, &body.version) {
            Ok(()) => {
                if let Err(err) = deploy.put_function(project.as_ref(), &f).await {
                    return deploy_error_response(err);
                }
                Json(f).into_response()
            }
            Err(msg) => (StatusCode::BAD_REQUEST, format!("{msg}\n")).into_response(),
        },
        Ok(None) => (StatusCode::NOT_FOUND, format!("no function {name:?}\n")).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `DELETE /api/functions/:name` (FA-2) — remove a top-level function (idempotent).
/// Content-addressed component blobs are shared and left to `prune`.
pub(super) async fn remove_function(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(name): Path<String>,
) -> Response {
    match deploy.delete_function(project.as_ref(), &name).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

#[cfg(all(test, feature = "handlers"))]
mod tests {
    use super::*;
    use boatramp_core::function::{Function, FunctionConfig, Lifecycle, Owner};
    use boatramp_core::kv::MemoryKv;
    use std::sync::Arc;

    /// A blob store the subgraph-refresh guard never reaches (it returns before touching blobs).
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

    fn a_function() -> Function {
        Function::new(
            "accounts",
            Owner::Project("default".to_string()),
            "component-hash",
            FunctionConfig::default(),
            Lifecycle::default(),
            0,
        )
    }

    /// The subgraph-refresh hook must never block or touch the registry for a function that is
    /// not a registered subgraph, on an explicit opt-out, or on a node with no wasm engine — so
    /// an ordinary function deploy (and the coordinated-migration escape hatch) is unaffected.
    #[tokio::test]
    async fn refresh_is_a_noop_unless_the_function_is_a_registered_subgraph() {
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()));
        let handlers = HandlerRuntime::disabled();
        let project = boatramp_core::project::ProjectRef::new("default");
        let f = a_function();

        // Not a registered subgraph → no-op; nothing is published.
        refresh_registered_subgraph(
            &deploy,
            &handlers,
            project,
            "accounts",
            &f,
            "component-hash",
            None,
        )
        .await
        .expect("an unregistered function deploys freely");
        assert!(
            !crate::graphql_registry::is_subgraph(deploy.kv().as_ref(), "default", "accounts")
                .await
        );

        // Now registered: `?register_subgraph=false` opts out (the migration escape hatch).
        crate::graphql_registry::publish(
            deploy.kv().as_ref(),
            "default",
            "accounts",
            "type Query { x: Int }",
        )
        .await
        .unwrap();
        refresh_registered_subgraph(
            &deploy,
            &handlers,
            project,
            "accounts",
            &f,
            "component-hash",
            Some(false),
        )
        .await
        .expect("opt-out never blocks");

        // Registered, no opt-out, but this node has no engine → Unavailable degrades to a skip
        // rather than blocking the deploy.
        refresh_registered_subgraph(
            &deploy,
            &handlers,
            project,
            "accounts",
            &f,
            "component-hash",
            None,
        )
        .await
        .expect("a node with no engine skips the refresh, it does not block");
    }
}
