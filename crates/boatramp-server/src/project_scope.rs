//! Project-scoped request routing (0.2.0): the `/api/projects/<proj>/…` per-resource
//! surface reuses the existing site/function/compute/workflow handlers by **rewriting**
//! the path to its unscoped `/api/…` form before routing, while carrying the tenant
//! project in a request extension the handlers thread into the store.
//!
//! ## Security
//!
//! The rewrite is the one place a project-scoped URL becomes a global handler URL, so
//! it is **whitelisted**: only the genuinely project-owned resource families
//! ([`PROJECT_SCOPED_FAMILIES`] — `sites`, `functions`, `compute`, `workflows`,
//! `graphql`, `secrets`, `sql`, `email`) are rewritten. A `/api/projects/<proj>/tokens` (or any non-family
//! sub-path) is **not**
//! rewritten, so it never reaches the global `/api/tokens` handler with mere
//! project authority — it simply 404s. The project-entity paths (`/api/projects` and
//! `/api/projects/<proj>`) are their own routes and are never rewritten.
//!
//! Authorization is unaffected: [`super::auth::require_auth`] reads the **original**
//! (pre-rewrite) path from the [`OriginalPath`] extension, so `Right::required` still
//! sees `/api/projects/<proj>/…` and enforces the project-scoped right — and the DPoP
//! proof still binds the path the client actually signed.

use axum::extract::{Request, State};
use axum::http::{StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use boatramp_core::deploy::DeployStore;
use boatramp_core::project::{ProjectRef, DEFAULT_PROJECT};

/// The resource families a `/api/projects/<proj>/<family>/…` URL may address — the
/// only sub-paths the middleware rewrites onto their global `/api/<family>/…`
/// handlers. Everything else under a project (tokens, authz, daemon, …) is **not**
/// project-owned and must not be reachable via the project path.
pub const PROJECT_SCOPED_FAMILIES: &[&str] = &[
    "sites",
    "functions",
    "compute",
    "workflows",
    "graphql",
    "secrets",
    // The project's SMTP email profiles (`/api/projects/<proj>/email/profiles…`),
    // so `boatramp email set/ls/rm --project <p>` reaches the right tenant.
    "email",
    // Operator SQL to a project's managed database (`/api/projects/<proj>/sql/<db>/…`).
    // Without this, `boatramp sql exec/query --project <p>` could only ever reach the
    // *default* project's DB, so a per-tenant (`tenant_scope = project`) managed database
    // — e.g. `pg-<ident>` under a non-default project — was unreachable by the operator
    // tool (it resolved to the bare `pg`/default workload). The `sql_exec`/`sql_query`
    // handlers already honor the injected `ProjectContext`.
    "sql",
];

/// The tenant project a request targets, injected as a request extension by
/// [`project_scope`]. Handlers read it (defaulting to `default` when absent) and thread
/// it into their store calls. Cloneable so `Extension<ProjectContext>` works.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectContext(pub String);

impl ProjectContext {
    /// The default-project context (the value for every legacy `/api/…` route).
    pub fn default_project() -> Self {
        Self(DEFAULT_PROJECT.to_string())
    }

    /// A borrowing [`ProjectRef`] for threading into `DeployStore` calls.
    pub fn as_ref(&self) -> ProjectRef<'_> {
        ProjectRef::new(&self.0)
    }
}

impl Default for ProjectContext {
    fn default() -> Self {
        Self::default_project()
    }
}

/// The original request path, stashed by [`project_scope`] before a rewrite so the
/// auth layer authorizes (and PoP-binds) the path the client actually sent.
#[derive(Debug, Clone)]
pub struct OriginalPath(pub String);

/// The routing decision for a request path.
struct Scope {
    /// The tenant project (`default` for a legacy/unscoped path).
    project: String,
    /// The rewritten path, when the URL is a project-scoped per-resource path.
    rewrite: Option<String>,
}

/// Classify a request `path`: extract the tenant project and, for a whitelisted
/// project-scoped resource path, the rewritten unscoped path.
fn scope_of(path: &str) -> Scope {
    // Parse the tenant through the same `project_api_path` the authz layer uses, so
    // the middleware and `Right::required` can never disagree on the project.
    let Some((proj, sub)) = boatramp_core::authz::project_api_path(path) else {
        // Not project-scoped (a legacy `/api/…` route, `/api/projects` itself, or a
        // non-api path): the default tenant, no rewrite.
        return Scope {
            project: DEFAULT_PROJECT.to_string(),
            rewrite: None,
        };
    };
    // A malformed empty project segment (`/api/projects//…` or `/api/projects/`) has
    // no tenant to carry, so it falls back to the default project and never rewrites
    // (fail-closed → 404 at routing).
    if proj.is_empty() {
        return Scope {
            project: DEFAULT_PROJECT.to_string(),
            rewrite: None,
        };
    }
    // Bare `/api/projects/<proj>` (the project entity route): carry the tenant, do
    // not rewrite (its own route handles it).
    if sub.is_empty() {
        return Scope {
            project: proj.to_string(),
            rewrite: None,
        };
    }
    // `/api/projects/<proj>/<family>/…`: rewrite to `/api/<family>/…` **iff** the
    // family is project-ownable; otherwise leave it (→ 404, never a global handler).
    let family = sub.split('/').next().unwrap_or("");
    let rewrite = PROJECT_SCOPED_FAMILIES
        .contains(&family)
        .then(|| format!("/api/{sub}"));
    Scope {
        project: proj.to_string(),
        rewrite,
    }
}

/// Middleware (applied outermost on the control-plane API, before routing): derive the
/// [`ProjectContext`] tenant from the path and, for a whitelisted project-scoped
/// resource path, rewrite the URI to its global form (stashing the original path in
/// [`OriginalPath`] for the auth layer). A no-op for every non-project path.
pub async fn project_scope(mut request: Request, next: Next) -> Response {
    let scope = scope_of(request.uri().path());
    request
        .extensions_mut()
        .insert(ProjectContext(scope.project));
    if let Some(new_path) = scope.rewrite {
        let original = request.uri().path().to_string();
        rewrite_path(request.uri_mut(), &new_path);
        request.extensions_mut().insert(OriginalPath(original));
    }
    next.run(request).await
}

/// Reject a project-scoped resource operation on a project that was never created,
/// so a typo'd or hand-crafted `/api/projects/<proj>/…` request cannot manufacture a
/// ghost tenant (live keys under `project/<proj>/…` that `project ls` never shows).
///
/// This runs **after** [`super::auth::require_auth`] (it is layered inside it), so an
/// unauthorized caller is already refused (401/403) and never learns whether the
/// project exists — the guard is not a project-existence oracle. It fires only for a
/// rewritten project-scoped path (an [`OriginalPath`] was stashed) under a non-default
/// project; `default` always exists and every legacy `/api/…` path is untouched.
pub async fn require_project_exists(
    State(deploy): State<DeployStore>,
    request: Request,
    next: Next,
) -> Response {
    let rewritten = request.extensions().get::<OriginalPath>().is_some();
    let project = request
        .extensions()
        .get::<ProjectContext>()
        .map(|p| p.0.clone())
        .unwrap_or_else(|| DEFAULT_PROJECT.to_string());
    if rewritten && project != DEFAULT_PROJECT {
        match deploy.project_exists(&project).await {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::NOT_FOUND,
                    format!("no project `{project}`; create it first (`boatramp project create {project}`)\n"),
                )
                    .into_response();
            }
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("project lookup failed: {err}\n"),
                )
                    .into_response();
            }
        }
    }
    next.run(request).await
}

/// Replace a URI's path (preserving the query + any scheme/authority), for the
/// project→global rewrite. A server-side origin-form URI keeps its `None`
/// scheme/authority; a proxied absolute-form request round-trips them.
fn rewrite_path(uri: &mut Uri, new_path: &str) {
    let mut parts = uri.clone().into_parts();
    let pq = match uri.query() {
        Some(q) => format!("{new_path}?{q}"),
        None => new_path.to_string(),
    };
    if let Ok(path_and_query) = pq.parse() {
        parts.path_and_query = Some(path_and_query);
        if let Ok(rebuilt) = Uri::from_parts(parts) {
            *uri = rebuilt;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_and_non_api_paths_default_and_are_not_rewritten() {
        for p in ["/api/sites/blog/config", "/healthz", "/api/tokens"] {
            let s = scope_of(p);
            assert_eq!(s.project, "default");
            assert!(s.rewrite.is_none());
        }
    }

    #[test]
    fn project_resource_paths_rewrite_to_the_global_handler() {
        let s = scope_of("/api/projects/acme/sites/blog/config");
        assert_eq!(s.project, "acme");
        assert_eq!(s.rewrite.as_deref(), Some("/api/sites/blog/config"));

        let s = scope_of("/api/projects/acme/functions/resize/versions");
        assert_eq!(s.project, "acme");
        assert_eq!(s.rewrite.as_deref(), Some("/api/functions/resize/versions"));

        let s = scope_of("/api/projects/acme/compute/api");
        assert_eq!(s.rewrite.as_deref(), Some("/api/compute/api"));

        // GraphQL admin (subgraph registration, safelist, supergraph) is a
        // project-owned family: a project-scoped path rewrites onto the global handler
        // so multi-project GraphQL administration works.
        let s = scope_of("/api/projects/acme/graphql/safelist");
        assert_eq!(s.project, "acme");
        assert_eq!(s.rewrite.as_deref(), Some("/api/graphql/safelist"));

        let s = scope_of("/api/projects/acme/graphql/subgraphs/catalog");
        assert_eq!(s.rewrite.as_deref(), Some("/api/graphql/subgraphs/catalog"));

        // The internal secret store is a project-owned family: the project-scoped
        // list/set path rewrites onto the global handler, tagged with the tenant so
        // a `boatramp:` ref resolves within its own project's sealed keyspace.
        let s = scope_of("/api/projects/acme/secrets");
        assert_eq!(s.project, "acme");
        assert_eq!(s.rewrite.as_deref(), Some("/api/secrets"));
        let s = scope_of("/api/projects/acme/secrets/db-password");
        assert_eq!(s.project, "acme");
        assert_eq!(s.rewrite.as_deref(), Some("/api/secrets/db-password"));
    }

    #[test]
    fn non_whitelisted_project_subpaths_are_never_rewritten() {
        // A global-only resource under a project path must NOT reach its global
        // handler with mere project authority — no rewrite (→ 404).
        for sub in [
            "tokens",
            "authz/policy",
            "daemon/config",
            "prune",
            "blobs/abc",
        ] {
            let s = scope_of(&format!("/api/projects/acme/{sub}"));
            assert_eq!(s.project, "acme");
            assert!(s.rewrite.is_none(), "{sub} must not rewrite");
        }
    }

    #[test]
    fn project_entity_paths_carry_the_tenant_without_rewrite() {
        let s = scope_of("/api/projects/acme");
        assert_eq!(s.project, "acme");
        assert!(s.rewrite.is_none());
        // `/api/projects` (list/create) is not under the prefix → default, no rewrite.
        let s = scope_of("/api/projects");
        assert_eq!(s.project, "default");
        assert!(s.rewrite.is_none());
    }

    #[test]
    fn a_malformed_empty_project_segment_is_default_and_never_rewrites() {
        // `/api/projects//sites/blog` (empty project) must not carry a bogus tenant
        // or rewrite — it falls back to the default project and fails closed (404).
        let s = scope_of("/api/projects//sites/blog/config");
        assert_eq!(s.project, "default");
        assert!(s.rewrite.is_none());
        let s = scope_of("/api/projects/");
        assert_eq!(s.project, "default");
        assert!(s.rewrite.is_none());
    }

    #[test]
    fn scope_of_and_authz_resolve_the_same_project_segment() {
        // The middleware and `Right::required` MUST agree on which project a path
        // targets (a confused-deputy hazard). Both now parse via the shared
        // `project_api_path`; assert the middleware's tenant matches it (with the
        // middleware's empty → default fail-closed policy) across edge cases.
        use boatramp_core::authz::project_api_path;
        for path in [
            "/api/projects/acme/sites/blog/config",
            "/api/projects/acme",
            "/api/projects/acme/tokens",
            "/api/projects//sites/blog", // malformed empty project
            "/api/projects/",
            "/api/sites/blog", // legacy, not project-scoped
            "/healthz",
        ] {
            let mw = scope_of(path).project;
            match project_api_path(path) {
                Some((proj, _)) if !proj.is_empty() => assert_eq!(mw, proj, "{path}"),
                _ => assert_eq!(mw, "default", "{path}"),
            }
        }
    }
}
