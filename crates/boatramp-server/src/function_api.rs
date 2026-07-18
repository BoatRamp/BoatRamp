//! The function management API (FA-1/FA-2): list function summaries and
//! deploy, version, alias, roll back, and remove function definitions. This is
//! the always-on control surface (no wasm engine required); the runtime that
//! invokes functions lives in `function_runtime`. Pulls the serve-pipeline
//! scope in via `use super::*`.

use super::*;

/// `?site=` filter for the functions view.
#[derive(serde::Deserialize)]
pub(super) struct FunctionQuery {
    site: Option<String>,
}

/// One entry in the `GET /api/functions` view.
#[derive(serde::Serialize)]
struct FunctionSummary {
    /// Function name (`<site>/<name>` for site-scoped; bare for top-level).
    name: String,
    /// Owner (`site:<site>` or `project:<project>`).
    owner: String,
    /// Execution substrate.
    runtime: String,
    /// Active version id (the component blob hash).
    version: String,
    /// Rendered triggers that reach this function.
    triggers: Vec<String>,
}

/// `GET /api/functions[?site=…]` — the derived, **read-only** site-scoped function
/// view (FA-1): desugar each site's active manifest into functions + triggers and
/// resolve component paths to their blob-hash version ids. A pure projection of the
/// manifests — the serve path is untouched, so a site's handlers are unchanged.
/// `system·read`.
pub(super) async fn list_functions(
    State(deploy): State<DeployStore>,
    axum::extract::Query(query): axum::extract::Query<FunctionQuery>,
) -> Response {
    use boatramp_core::function;
    let sites = match &query.site {
        Some(s) => vec![s.clone()],
        None => match deploy.all_sites().await {
            Ok(s) => s,
            Err(err) => return deploy_error_response(err),
        },
    };
    let mut out: Vec<FunctionSummary> = Vec::new();
    for site in sites {
        let manifest = match deploy.current_manifest(&site).await {
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
        match deploy.list_stored_functions().await {
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

/// `PUT /api/functions/:name` (FA-2) — deploy a version of a top-level function.
/// The component blob must already be uploaded. Creates the function if new;
/// otherwise appends + activates the version (idempotent per component hash).
/// `system·admin`.
pub(super) async fn deploy_function(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
    Json(body): Json<FunctionUpsert>,
) -> Response {
    use boatramp_core::function::{Function, Owner};
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
    let f = match deploy.get_function(&name).await {
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
    if let Err(err) = deploy.put_function(&f).await {
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
    Path(name): Path<String>,
    Json(body): Json<RollbackBody>,
) -> Response {
    match deploy.get_function(&name).await {
        Ok(Some(mut f)) => match f.rollback(&body.to) {
            Ok(()) => {
                if let Err(err) = deploy.put_function(&f).await {
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
    Path((name, label)): Path<(String, String)>,
    Json(body): Json<AliasBody>,
) -> Response {
    match deploy.get_function(&name).await {
        Ok(Some(mut f)) => match f.set_alias(&label, &body.version) {
            Ok(()) => {
                if let Err(err) = deploy.put_function(&f).await {
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
    Path(name): Path<String>,
) -> Response {
    match deploy.delete_function(&name).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}
