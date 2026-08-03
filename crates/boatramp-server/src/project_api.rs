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
    if name.is_empty() || name.contains('/') || name.contains(char::is_whitespace) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid project name: must be a non-empty slug with no `/` or whitespace\n",
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

/// `DELETE /api/projects/{proj}` — delete an **empty** project. `409` while it still
/// owns resources or is the reserved `default`; `404` if it never existed.
pub(super) async fn delete_project(
    State(deploy): State<DeployStore>,
    Path(proj): Path<String>,
) -> Response {
    if proj == DEFAULT_PROJECT {
        return (
            StatusCode::CONFLICT,
            "the `default` project cannot be deleted\n",
        )
            .into_response();
    }
    match deploy.delete_project(&proj).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, format!("no project `{proj}`\n")).into_response(),
        Err(DeployError::Conflict(msg)) => {
            (StatusCode::CONFLICT, format!("{msg}\n")).into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}
