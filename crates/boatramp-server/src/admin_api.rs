//! The control-plane admin REST API: deployment lifecycle (create, upload
//! blobs, activate, list, prune, scrub), per-site config and aliases, the
//! dynamic daemon config, compute-backend management, cache invalidation, cert
//! status, and the OIDC token exchange. These are the `/api/...` endpoints the
//! router mounts behind admin auth. Pulls the shared response helpers in via
//! `use super::*`.

use super::*;

#[derive(Serialize)]
struct CreateDeploymentResponse {
    id: String,
    missing: Vec<String>,
}

/// Optional deploy provenance, supplied as query params on the create call
/// (e.g. `?source=<sha>&branch=main&message=...`). Kept out of the manifest
/// body so it never affects the content-addressed deployment id.
#[derive(Debug, Default, Deserialize)]
pub(super) struct DeployMetaQuery {
    source: Option<String>,
    branch: Option<String>,
    author: Option<String>,
    message: Option<String>,
    /// Release tag (`git describe`).
    tag: Option<String>,
    /// Arbitrary key-value tags, JSON-encoded (`{"env":"prod"}`) — a query
    /// string can't carry a map, so the CLI packs it into one param.
    tags: Option<String>,
}

impl From<DeployMetaQuery> for DeployMetaInput {
    fn from(q: DeployMetaQuery) -> Self {
        Self {
            source: q.source,
            branch: q.branch,
            author: q.author,
            message: q.message,
            tag: q.tag,
            // A malformed tags param drops to empty rather than failing the
            // deploy; the CLI is the only producer and always sends valid JSON.
            tags: q
                .tags
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default(),
        }
    }
}

/// Register a manifest; respond with its deployment id and the blob hashes the
/// client still needs to upload.
pub(super) async fn create_deployment(
    State(deploy): State<DeployStore>,
    Path(_site): Path<String>,
    Query(meta): Query<DeployMetaQuery>,
    Json(manifest): Json<Manifest>,
) -> Response {
    let result = async {
        let id = deploy.put_manifest_with(&manifest, meta.into()).await?;
        let missing = deploy.missing_blobs(&manifest).await?;
        Ok::<_, DeployError>((id, missing))
    }
    .await;

    match result {
        Ok((id, missing)) => {
            srvmetrics::server_metrics().record_deployment();
            (
                StatusCode::OK,
                Json(CreateDeploymentResponse { id, missing }),
            )
                .into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Stream a blob into storage, verifying it hashes to `hash`.
pub(super) async fn put_blob(
    State(deploy): State<DeployStore>,
    Extension(guard): Extension<Arc<UploadGuard>>,
    Path(hash): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // Cheap up-front reject on a declared length over the cap (avoids opening a
    // stream we'd only abort). The streaming guard below is the real backstop.
    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if guard.content_length_rejected(content_length) {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "blob exceeds the upload limit\n",
        )
            .into_response();
    }
    // Admit under the concurrency cap; the permit is held until the upload ends.
    let Some(_permit) = guard.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many concurrent uploads; retry shortly\n",
        )
            .into_response();
    };

    let stream = body
        .into_data_stream()
        .map(|chunk| chunk.map_err(|err| StorageError::backend(err.to_string())))
        .boxed();
    // Wrap so an over-size or stalled upload is aborted mid-stream (streaming
    // preserved — nothing is buffered to measure it).
    let stream = guard.limit_body(stream);

    match deploy.put_blob(&hash, stream).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

pub(super) async fn activate_deployment(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path((site, id)): Path<(String, String)>,
) -> Response {
    if let Some(resp) = reject_invalid_name("site", &site) {
        return resp;
    }
    // Activation compile-gate: a deploy whose handlers the
    // site can't satisfy, or whose components don't compile, must not flip.
    match deploy.get_manifest(&id).await {
        Ok(Some(manifest)) => {
            let site_config = match deploy.get_site_config(project.as_ref(), &site).await {
                Ok(config) => config,
                Err(err) => return deploy_error_response(err),
            };
            if let Err(reason) = handlers
                .precheck_activation(&deploy, &manifest, site_config.as_ref())
                .await
            {
                tracing::warn!(site, id, reason, "activation refused by handler pre-check");
                return (StatusCode::UNPROCESSABLE_ENTITY, format!("{reason}\n")).into_response();
            }
        }
        // A missing manifest falls through; `activate` returns the NotFound error.
        Ok(None) => {}
        Err(err) => return deploy_error_response(err),
    }
    match deploy.activate(project.as_ref(), &site, &id).await {
        Ok(()) => {
            srvmetrics::server_metrics().record_activation();
            StatusCode::NO_CONTENT.into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

#[derive(Serialize)]
struct CurrentResponse {
    site: String,
    deployment: Option<String>,
}

pub(super) async fn current_deployment(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(site): Path<String>,
) -> Response {
    match deploy.current_id(project.as_ref(), &site).await {
        Ok(deployment) => Json(CurrentResponse { site, deployment }).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// List a site's deployment history (most recent first), with the current id.
pub(super) async fn list_deployments(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(site): Path<String>,
) -> Response {
    match deploy.deployments(project.as_ref(), &site).await {
        Ok(list) => Json(list).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Get a site's [`SiteConfig`] (defaults if unset).
/// `GET /api/sites` — every known site name (admin-scoped). Backs the web UI /
/// tooling site navigation.
pub(super) async fn list_sites(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
) -> Response {
    match deploy.all_sites(project.as_ref()).await {
        Ok(sites) => Json(sites).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

pub(super) async fn get_site_config(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(site): Path<String>,
) -> Response {
    match deploy.get_site_config(project.as_ref(), &site).await {
        Ok(config) => Json(config.unwrap_or_default()).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `DELETE /api/sites/:site` — remove a site + its routing/config/aliases/pending
/// verifications (the Kubernetes operator's `Site` finalizer). Admin-scoped
/// (deny-safe `Right::required` default). Content-addressed deploy blobs are
/// shared and left to `prune`. Idempotent.
pub(super) async fn delete_site(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Extension(deprovisioner): Extension<Option<Arc<dyn boatramp_core::sql::TenantDeprovisioner>>>,
    Path(site): Path<String>,
) -> Response {
    match deploy.delete_site(project.as_ref(), &site).await {
        Ok(()) => {
            // The site is gone from the store. Best-effort: drop its managed
            // databases + roles + sealed credentials (this site tenant's, nothing
            // else). A failure is logged inside the deprovisioner and never affects
            // this response — an orphaned DB is a lesser evil than a failed delete.
            if let Some(deprovisioner) = deprovisioner {
                deprovisioner
                    .deprovision_site(project.as_ref().as_str(), &site)
                    .await;
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Canonicalize a site-config domain entry for the verify-gate diff: fold case
/// and any trailing dot, but keep an exact host distinct from a `*.` wildcard
/// (they are different routing entities that must not collapse together).
fn canon_domain_entry(host: &str) -> String {
    boatramp_core::host::Host::new(host).domain_entry()
}

/// Set a site's [`SiteConfig`] (rebuilds its host → site index).
///
/// A domain only enters routing once its ownership is proven. A host **newly
/// added** through this raw config write (rather than the verify→attach flow)
/// must therefore already carry a verified challenge, or a site-writer could
/// squat an unowned host by simply listing it. Hosts already on the site — and
/// any non-domain edit — pass untouched, so the ordinary `access`/`gateway`
/// config edits (which read-modify-write the current config) are unaffected.
pub(super) async fn put_site_config(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(site): Path<String>,
    Json(config): Json<SiteConfig>,
) -> Response {
    if let Some(resp) = reject_invalid_name("site", &site) {
        return resp;
    }
    let current = match deploy.get_site_config(project.as_ref(), &site).await {
        Ok(c) => c.unwrap_or_default(),
        Err(err) => return deploy_error_response(err),
    };
    // Diff on the *canonical* host form (case/trailing-dot folded, wildcard `*.`
    // preserved) so it agrees with the normalizing verification lookup — else a
    // case-variant of an already-attached host reads as "newly added" and a
    // never-verified variant could be laundered in.
    let existing: std::collections::BTreeSet<String> = current
        .domains
        .exact_hosts()
        .map(canon_domain_entry)
        .chain(
            current
                .domains
                .wildcards
                .iter()
                .map(|w| canon_domain_entry(w)),
        )
        .collect();
    let added: Vec<String> = config
        .domains
        .exact_hosts()
        .map(canon_domain_entry)
        .chain(
            config
                .domains
                .wildcards
                .iter()
                .map(|w| canon_domain_entry(w)),
        )
        .filter(|host| !existing.contains(host))
        .collect();
    for host in added {
        let verification = match deploy
            .get_domain_verification(
                project.as_ref(),
                &boatramp_core::site::SiteName::new(site.as_str()),
                &host,
            )
            .await
        {
            Ok(v) => v,
            Err(err) => return deploy_error_response(err),
        };
        if !verification.as_ref().is_some_and(|v| v.verified) {
            return (
                StatusCode::FORBIDDEN,
                format!(
                    "{host} is not verified for {site}; run \
                     `boatramp domain add {host} --site {site}` first\n"
                ),
            )
                .into_response();
        }
        // A wildcard needs DNS proof (parity with `attach_verified_domain`).
        if host.starts_with("*.")
            && verification.as_ref().map(|v| v.method)
                != Some(boatramp_core::domain_verify::VerificationMethod::Dns)
        {
            return (
                StatusCode::FORBIDDEN,
                format!("wildcard {host} must be verified via DNS (an HTTP token proves only the base host)\n"),
            )
                .into_response();
        }
    }
    match deploy
        .set_site_config(project.as_ref(), &site, &config)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `PUT /api/projects/{proj}/graphql/subgraphs/{name}` — publish a subgraph's SDL (the
/// request body). Recomposes + validates the whole supergraph; a composition failure is a
/// `400` and the subgraph is **not** stored. On success, returns the composed supergraph
/// summary.
#[cfg(feature = "handlers")]
pub(super) async fn put_graphql_subgraph(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(name): Path<String>,
    sdl: String,
) -> Response {
    if let Some(resp) = reject_invalid_name("subgraph", &name) {
        return resp;
    }
    let kv = deploy.kv().as_ref();
    match crate::graphql_registry::publish(kv, &project.0, &name, &sdl).await {
        Ok(sg) => {
            let names = crate::graphql_registry::subgraph_names(kv, &project.0).await;
            axum::Json(crate::graphql_registry::summary_json(&sg, &names)).into_response()
        }
        Err(crate::graphql_registry::PublishError::Composition(e)) => {
            (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response()
        }
        Err(crate::graphql_registry::PublishError::Store(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("registry store error: {e}\n"),
        )
            .into_response(),
    }
}

/// The body of a SQL federation-subgraph registration: which site's managed database to
/// expose, and the connector policy (exposed tables/columns) to expose it under.
#[cfg(feature = "handlers")]
#[derive(serde::Deserialize)]
pub(super) struct SqlSubgraphRequest {
    site: String,
    #[serde(default)]
    config: boatramp_core::config::HandlerGraphqlDataConfig,
}

/// `PUT /api/projects/{proj}/graphql/subgraphs/{name}/sql` — register a **SQL-backed**
/// federation subgraph. boatramp introspects the named site's managed database, generates the
/// subgraph's SDL (`@key` entities for the exposed tables — no hand-written SDL), publishes it
/// to the registry (recomposed + validated like any subgraph), and records the SQL backend so
/// the gateway resolves this subgraph's fetches by compiling to SQL.
#[cfg(feature = "handlers")]
pub(super) async fn put_graphql_sql_subgraph(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(name): Path<String>,
    Json(request): Json<SqlSubgraphRequest>,
) -> Response {
    if let Some(resp) = reject_invalid_name("subgraph", &name) {
        return resp;
    }
    if let Some(resp) = reject_invalid_name("site", &request.site) {
        return resp;
    }
    let Some(provider) = handlers.sql_provider() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "this server has no SQL backend configured\n",
        )
            .into_response();
    };
    // Introspect the site's database and generate the subgraph SDL from its exposed shape.
    let sdl = match crate::graphql_data::generate_sql_subgraph_sdl(
        provider.as_ref(),
        &project.0,
        &request.site,
        &request.config,
    )
    .await
    {
        Ok(sdl) => sdl,
        Err(message) => return (StatusCode::BAD_GATEWAY, format!("{message}\n")).into_response(),
    };
    let kv = deploy.kv().as_ref();
    // Publish the SDL (recompose + validate) first — a bad compose never records a backend.
    let sg = match crate::graphql_registry::publish(kv, &project.0, &name, &sdl).await {
        Ok(sg) => sg,
        Err(crate::graphql_registry::PublishError::Composition(e)) => {
            return (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response()
        }
        Err(crate::graphql_registry::PublishError::Store(e)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("registry store error: {e}\n"),
            )
                .into_response()
        }
    };
    // Record the SQL backend so the gateway routes this subgraph's fetches to the connector.
    let spec = crate::graphql_registry::SubgraphBackendSpec::Sql {
        site: request.site,
        config: request.config,
    };
    if let Err(e) =
        crate::graphql_registry::put_subgraph_backend(kv, &project.0, &name, &spec).await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("registry store error: {e}\n"),
        )
            .into_response();
    }
    let names = crate::graphql_registry::subgraph_names(kv, &project.0).await;
    axum::Json(crate::graphql_registry::summary_json(&sg, &names)).into_response()
}

/// Introspect a deployed function subgraph's SDL by invoking its federation `_service { sdl }`
/// field **anonymously** (the SDL is a public field — no caller identity is forwarded for a
/// schema read), with a timeout so a hung guest can't wedge the admin call. The failure surface
/// maps to an HTTP status: the function is not deployed → `409`, the invoke fails or times out →
/// `502`, and a response with no `data._service.sdl` (not a federation subgraph) → `422`.
#[cfg(feature = "handlers")]
async fn introspect_function_sdl(
    invoker: &dyn boatramp_handlers::Invoker,
    name: &str,
) -> Result<String, (StatusCode, String)> {
    let body = serde_json::json!({ "query": "{ _service { sdl } }" })
        .to_string()
        .into_bytes();
    let request = boatramp_handlers::InvokeRequest {
        method: "POST".to_string(),
        path: "/".to_string(),
        headers: vec![("content-type".to_string(), b"application/json".to_vec())],
        body,
    };
    let invoked = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        invoker.invoke(name, request, 0),
    )
    .await;
    let response = match invoked {
        Err(_elapsed) => {
            return Err((
                StatusCode::BAD_GATEWAY,
                format!("subgraph `{name}` timed out answering `_service {{ sdl }}`\n"),
            ))
        }
        Ok(Err(boatramp_handlers::InvokeError::NotFound)) => {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "no function named `{name}` is deployed — deploy it before registering it as a subgraph\n"
                ),
            ))
        }
        Ok(Err(boatramp_handlers::InvokeError::Failed(msg))) => {
            return Err((
                StatusCode::BAD_GATEWAY,
                format!("subgraph `{name}` failed answering `_service {{ sdl }}`: {msg}\n"),
            ))
        }
        Ok(Ok(response)) => response,
    };
    let parsed: serde_json::Value =
        serde_json::from_slice(&response.body).unwrap_or(serde_json::Value::Null);
    match parsed.pointer("/data/_service/sdl").and_then(|v| v.as_str()) {
        Some(sdl) if !sdl.trim().is_empty() => Ok(sdl.to_string()),
        _ => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "function `{name}` did not answer `{{ _service {{ sdl }} }}` — it may not be a federation subgraph\n"
            ),
        )),
    }
}

/// `PUT /api/projects/{proj}/graphql/subgraphs/{name}/function` — register a **function-backed**
/// federation subgraph *by introspection*. boatramp invokes the deployed function's federation
/// `_service { sdl }` field, publishes the returned SDL to the registry (recomposed + validated
/// like any subgraph), and records the function backend — so an operator never hand-writes SDL
/// for a shim-authored subgraph (the parallel of the `/sql` path). Deploy the function first.
#[cfg(feature = "handlers")]
pub(super) async fn put_graphql_function_subgraph(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(name): Path<String>,
) -> Response {
    if let Some(resp) = reject_invalid_name("subgraph", &name) {
        return resp;
    }
    let Some(invoker) = handlers.invoker() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "this server has no function invoker configured\n",
        )
            .into_response();
    };
    // Introspect anonymously, scoped to the project (an invoke never crosses tenants).
    let scoped = invoker.scoped(boatramp_core::project::ProjectRef::new(&project.0));
    let sdl = match introspect_function_sdl(scoped.as_ref(), &name).await {
        Ok(sdl) => sdl,
        Err((status, message)) => return (status, message).into_response(),
    };
    let kv = deploy.kv().as_ref();
    // Publish the SDL (recompose + validate) first — a bad compose never records a backend.
    let sg = match crate::graphql_registry::publish(kv, &project.0, &name, &sdl).await {
        Ok(sg) => sg,
        Err(crate::graphql_registry::PublishError::Composition(e)) => {
            return (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response()
        }
        Err(crate::graphql_registry::PublishError::Store(e)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("registry store error: {e}\n"),
            )
                .into_response()
        }
    };
    // Record the function backend explicitly (it is also the default) for parity with `/sql`.
    let spec = crate::graphql_registry::SubgraphBackendSpec::Function;
    if let Err(e) =
        crate::graphql_registry::put_subgraph_backend(kv, &project.0, &name, &spec).await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("registry store error: {e}\n"),
        )
            .into_response();
    }
    let names = crate::graphql_registry::subgraph_names(kv, &project.0).await;
    axum::Json(crate::graphql_registry::summary_json(&sg, &names)).into_response()
}

/// `DELETE /api/projects/{proj}/graphql/subgraphs/{name}` — unregister a subgraph (remove its
/// SDL + backend record). The escape hatch for a coordinated schema migration: it does **not**
/// recompose the remainder, so an operator can deliberately drop a subgraph as one step of a
/// multi-subgraph change. Idempotent → `204`.
#[cfg(feature = "handlers")]
pub(super) async fn delete_graphql_subgraph(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(name): Path<String>,
) -> Response {
    let kv = deploy.kv().as_ref();
    match crate::graphql_registry::unpublish(kv, &project.0, &name).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("registry store error: {e}\n"),
        )
            .into_response(),
    }
}

/// The body of a safelist registration: the GraphQL operation text. Its sha256-hex is the hash a
/// guest passes to `graphql::run_persisted`.
#[cfg(feature = "handlers")]
#[derive(serde::Deserialize)]
pub(super) struct SafelistEntry {
    query: String,
}

/// `POST /api/projects/{proj}/graphql/safelist` — register a **trusted operation** in the
/// project's GraphQL **safelist** (the guest/agent operation allowlist) and return its hash.
/// Guest runs (`graphql::run` / `run-persisted`) are deny-by-default: only safelisted operations
/// run. The operation is validated (parse + depth/complexity) before it is stored, so a bad op is
/// rejected here rather than at run time. Idempotent (the same operation re-registers to the same
/// hash).
#[cfg(feature = "handlers")]
pub(super) async fn register_graphql_safelist(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Json(entry): Json<SafelistEntry>,
) -> Response {
    let query = entry.query.trim();
    if query.is_empty() {
        return (StatusCode::BAD_REQUEST, "operation is empty\n").into_response();
    }
    let limits =
        crate::graphql_guard::limits_from(&boatramp_core::config::HandlerGraphqlConfig::default());
    if let crate::graphql_guard::GuardVerdict::Reject(reason) =
        crate::graphql_guard::guard_query(query, &limits)
    {
        return (StatusCode::BAD_REQUEST, format!("{reason}\n")).into_response();
    }
    match crate::graphql_apq::register(deploy.kv().as_ref(), &project.0, query).await {
        Ok(hash) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "hash": hash })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("safelist store error: {e}\n"),
        )
            .into_response(),
    }
}

/// `GET /api/projects/{proj}/graphql/safelist` — list the registered operations (`{hash, query}`).
#[cfg(feature = "handlers")]
pub(super) async fn list_graphql_safelist(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
) -> Response {
    let entries: Vec<serde_json::Value> =
        crate::graphql_apq::list(deploy.kv().as_ref(), &project.0)
            .await
            .into_iter()
            .map(|(hash, query)| serde_json::json!({ "hash": hash, "query": query }))
            .collect();
    Json(entries).into_response()
}

/// `DELETE /api/projects/{proj}/graphql/safelist/{hash}` — remove an operation from the safelist.
/// Idempotent → `204`.
#[cfg(feature = "handlers")]
pub(super) async fn delete_graphql_safelist(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(hash): Path<String>,
) -> Response {
    match crate::graphql_apq::unregister(deploy.kv().as_ref(), &project.0, &hash).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("safelist store error: {e}\n"),
        )
            .into_response(),
    }
}

/// `GET /api/projects/{proj}/graphql/supergraph` — the composed supergraph summary
/// (subgraphs, entities, root fields) for the project.
#[cfg(feature = "handlers")]
pub(super) async fn get_graphql_supergraph(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
) -> Response {
    let kv = deploy.kv().as_ref();
    match crate::graphql_registry::supergraph(kv, &project.0).await {
        Ok(sg) => {
            let names = crate::graphql_registry::subgraph_names(kv, &project.0).await;
            axum::Json(crate::graphql_registry::summary_json(&sg, &names)).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response(),
    }
}

/// GET the active dynamic daemon config + its generation hash.
pub(super) async fn get_daemon_config(
    State(deploy): State<DeployStore>,
    Extension(daemon): Extension<Arc<DaemonRuntime>>,
) -> Response {
    match deploy.get_daemon_config().await {
        Ok(cfg) => Json(serde_json::json!({
            "generation": daemon.generation(),
            "config": cfg.unwrap_or_default(),
        }))
        .into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// PUT a new dynamic daemon config: validate against the file baseline (ceilings +
/// tighten-only ratchet), store it, and hot-swap the local runtime. Other nodes
/// converge via Raft replication + their SIGHUP/changelog reload.
pub(super) async fn put_daemon_config(
    State(deploy): State<DeployStore>,
    Extension(daemon): Extension<Arc<DaemonRuntime>>,
    Json(cfg): Json<boatramp_core::daemon_config::DaemonConfig>,
) -> Response {
    if let Err(err) = cfg.validate(daemon.baseline()) {
        return (
            StatusCode::BAD_REQUEST,
            format!("invalid daemon config: {err}\n"),
        )
            .into_response();
    }
    match deploy.set_daemon_config(&cfg).await {
        Ok(generation) => {
            if let Err(err) = daemon.reload(&deploy).await {
                return deploy_error_response(err);
            }
            Json(serde_json::json!({ "generation": generation })).into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Roll the dynamic daemon config back to the previous generation, and hot-swap.
pub(super) async fn rollback_daemon_config(
    State(deploy): State<DeployStore>,
    Extension(daemon): Extension<Arc<DaemonRuntime>>,
) -> Response {
    match deploy.rollback_daemon_config().await {
        Ok(Some(generation)) => {
            if let Err(err) = daemon.reload(&deploy).await {
                return deploy_error_response(err);
            }
            Json(serde_json::json!({ "generation": generation })).into_response()
        }
        Ok(None) => (
            StatusCode::CONFLICT,
            "no prior daemon config to roll back to\n",
        )
            .into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// List all compute workloads.
pub(super) async fn list_compute(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
) -> Response {
    match deploy.list_compute_workloads(project.as_ref()).await {
        Ok(mut workloads) => {
            workloads.sort_by(|a, b| a.name.cmp(&b.name));
            Json(workloads).into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Get one workload's desired state.
pub(super) async fn get_compute(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(name): Path<String>,
) -> Response {
    match deploy.get_compute_workload(project.as_ref(), &name).await {
        Ok(Some(workload)) => Json(workload).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no such workload\n").into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Body of `PUT /api/compute/:name` — the spec plus desired replicas/placement.
#[derive(Deserialize)]
pub(super) struct PutComputeRequest {
    /// The immutable workload spec (rootfs/kernel blob hashes + sizing).
    spec: boatramp_core::compute::ComputeSpec,
    /// Desired replica count (default 1).
    #[serde(default = "one")]
    replicas: u32,
    /// Placement constraints.
    #[serde(default)]
    placement: boatramp_core::compute::PlacementConstraints,
}

fn one() -> u32 {
    1
}

#[derive(Serialize)]
struct PutComputeResponse {
    /// The content hash of the stored spec (`computever/<hash>`).
    spec: String,
}

/// Create/update a workload: content-address its spec, then flip the desired
/// state (replicas/placement) — the atomic activation pointer.
pub(super) async fn put_compute(
    State(deploy): State<DeployStore>,
    Extension(daemon): Extension<Arc<DaemonRuntime>>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(name): Path<String>,
    Json(mut request): Json<PutComputeRequest>,
) -> Response {
    if let Some(resp) = reject_invalid_name("compute", &name) {
        return resp;
    }
    // A kernel applies only to the micro-VM source (`RootSource::Rootfs` boots
    // `vmlinux` + a rootfs image). For an OCI image (docker/cloudflare) or a tar
    // rootfs (native container) the kernel is ignored, so we neither require nor
    // substitute one — leaving it empty keeps the stored spec (and its content hash)
    // honest. A micro-VM workload that omits its kernel uses the node's fleet
    // **default kernel** (from dynamic daemon config), substituted at set time and
    // verified against the posture bar at boot; no kernel and no default ⇒ a clear
    // error rather than a cryptic backend failure.
    if matches!(
        request.spec.root,
        boatramp_core::compute::RootSource::Rootfs(_)
    ) && request.spec.kernel.is_empty()
    {
        match daemon.effective().default_kernel.as_ref() {
            Some(k) => request.spec.kernel = k.source.clone(),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    "micro-VM workload has no kernel and no default kernel is configured; set \
                     one with `boatramp config set compute.default_kernel …`\n",
                )
                    .into_response()
            }
        }
    }
    let spec_hash = match deploy.put_compute_spec(&request.spec).await {
        Ok(hash) => hash,
        Err(err) => return deploy_error_response(err),
    };
    let workload = boatramp_core::compute::ComputeWorkload {
        version: boatramp_core::SCHEMA_VERSION,
        name,
        active: spec_hash.clone(),
        replicas: request.replicas,
        placement: request.placement,
    };
    match deploy
        .set_compute_workload(project.as_ref(), &workload)
        .await
    {
        Ok(()) => (
            StatusCode::CREATED,
            Json(PutComputeResponse { spec: spec_hash }),
        )
            .into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Delete a workload (the scheduler then stops its replicas).
pub(super) async fn delete_compute(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(name): Path<String>,
) -> Response {
    match deploy
        .delete_compute_workload(project.as_ref(), &name)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such workload\n").into_response(),
        Err(err) => deploy_error_response(err),
    }
}

// ---------------------------------------------------------------------------
// Operator SQL to a managed co-located database (`/api/sql/{db}/{exec,query}`)
// ---------------------------------------------------------------------------

/// A managed-DB migration script (multiple statements; simple-query protocol).
#[derive(Deserialize)]
pub(super) struct SqlExecRequest {
    /// The SQL script — `CREATE EXTENSION`, tables, RLS, chained DDL/DML.
    pub sql: String,
}

/// A single row-returning query.
#[derive(Deserialize)]
pub(super) struct SqlQueryRequest {
    /// One `SELECT` (or other row-returning) statement.
    pub sql: String,
}

/// The rows a `sql query` returned, JSON-encoded per cell.
#[derive(Serialize)]
pub(super) struct SqlQueryResponse {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
}

/// Encode one [`SqlValue`](boatramp_core::sql::SqlValue) as a JSON value for the
/// wire. A `Blob` becomes base64 text (JSON has no byte type); `Json` is re-parsed
/// so it nests as structure rather than a string.
fn sql_value_to_json(v: &boatramp_core::sql::SqlValue) -> serde_json::Value {
    use boatramp_core::sql::SqlValue;
    use serde_json::Value;
    match v {
        SqlValue::Null => Value::Null,
        SqlValue::Boolean(b) => Value::Bool(*b),
        SqlValue::Integer(i) => Value::from(*i),
        SqlValue::Real(f) => Value::from(*f),
        SqlValue::Text(s) => Value::String(s.clone()),
        SqlValue::Blob(b) => {
            use base64::Engine;
            Value::String(base64::engine::general_purpose::STANDARD.encode(b))
        }
        SqlValue::Json(s) => serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.clone())),
    }
}

/// Run a migration **script** against managed database `db` using its sealed
/// credential (resolved server-side). Admin-scoped; `501` if no managed SQL is
/// wired on this node.
pub(super) async fn sql_exec(
    Extension(project): Extension<ProjectContext>,
    Extension(op): Extension<Option<Arc<dyn boatramp_core::sql::OperatorSql>>>,
    Path(db): Path<String>,
    Json(req): Json<SqlExecRequest>,
) -> Response {
    let Some(op) = op else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "operator SQL is not available on this node (no managed database configured)\n",
        )
            .into_response();
    };
    match op
        .exec_script(project.as_ref().as_str(), &db, &req.sql)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("sql exec failed: {e}\n")).into_response(),
    }
}

/// Run one row-returning `query` against managed database `db`. Admin-scoped.
pub(super) async fn sql_query(
    Extension(project): Extension<ProjectContext>,
    Extension(op): Extension<Option<Arc<dyn boatramp_core::sql::OperatorSql>>>,
    Path(db): Path<String>,
    Json(req): Json<SqlQueryRequest>,
) -> Response {
    let Some(op) = op else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "operator SQL is not available on this node (no managed database configured)\n",
        )
            .into_response();
    };
    match op.query(project.as_ref().as_str(), &db, &req.sql).await {
        Ok(rows) => {
            let out = SqlQueryResponse {
                columns: rows.columns,
                rows: rows
                    .rows
                    .iter()
                    .map(|r| r.iter().map(sql_value_to_json).collect())
                    .collect(),
            };
            (StatusCode::OK, Json(out)).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("sql query failed: {e}\n")).into_response(),
    }
}

/// One replica's reachability in a `sql ping` response.
#[derive(Serialize)]
pub(super) struct SqlPingReplicaView {
    endpoint: String,
    healthy: bool,
    phase: String,
    tcp_reachable: bool,
}

/// Actively probe every replica of managed database `db` — a TCP reachability check
/// that BYPASSES the stored-health gate `sql query` trips on, so an operator can tell
/// "the DB is actually down" from "the DB is up but the resolver won't serve it" (the
/// `tcp_reachable && !healthy` signature). Admin-scoped; project-owned (the `sql`
/// family). `501` if no managed SQL is wired on this node.
pub(super) async fn sql_ping(
    Extension(project): Extension<ProjectContext>,
    Extension(op): Extension<Option<Arc<dyn boatramp_core::sql::OperatorSql>>>,
    Path(db): Path<String>,
) -> Response {
    let Some(op) = op else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "operator SQL is not available on this node (no managed database configured)\n",
        )
            .into_response();
    };
    match op.ping(project.as_ref().as_str(), &db).await {
        Ok(replicas) => {
            let out: Vec<SqlPingReplicaView> = replicas
                .into_iter()
                .map(|r| SqlPingReplicaView {
                    endpoint: r.endpoint,
                    healthy: r.healthy,
                    phase: r.phase,
                    tcp_reachable: r.tcp_reachable,
                })
                .collect();
            (StatusCode::OK, Json(out)).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("sql ping failed: {e}\n")).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Run a command inside a running workload (`POST /api/compute/{name}/exec`)
// ---------------------------------------------------------------------------

/// A command to run inside a running workload replica.
#[derive(Deserialize)]
pub(super) struct ComputeExecRequest {
    /// The argv (first element is the program; run inside the container).
    pub argv: Vec<String>,
    /// Optional standard input, base64-encoded (binary-safe).
    #[serde(default)]
    pub stdin_b64: Option<String>,
}

/// The buffered result of an exec (stdout/stderr base64-encoded, binary-safe).
#[derive(Serialize)]
pub(super) struct ComputeExecResponse {
    pub exit_code: i32,
    pub stdout_b64: String,
    pub stderr_b64: String,
}

/// Run a command inside a running replica of workload `name` (docker-exec style).
/// Admin-scoped **and** gated by the `allow_compute_exec` posture; `501` if no
/// exec-capable backend is wired, `403` when the posture forbids it.
pub(super) async fn compute_exec(
    Extension(project): Extension<ProjectContext>,
    Extension(posture): Extension<boatramp_core::security::SecurityPosture>,
    Extension(exec): Extension<Option<Arc<dyn boatramp_core::compute::ComputeExec>>>,
    Path(name): Path<String>,
    Json(req): Json<ComputeExecRequest>,
) -> Response {
    if !posture.allow_compute_exec {
        return (
            StatusCode::FORBIDDEN,
            "compute exec is disabled; set the `allow_compute_exec` posture \
             (BOATRAMP_SECURITY_ALLOW_COMPUTE_EXEC=true) to enable it\n",
        )
            .into_response();
    }
    let Some(exec) = exec else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "compute exec is not available on this node\n",
        )
            .into_response();
    };
    if req.argv.is_empty() {
        return (StatusCode::BAD_REQUEST, "argv must not be empty\n").into_response();
    }
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let stdin = match req.stdin_b64.as_deref().map(|s| b64.decode(s)).transpose() {
        Ok(v) => v,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "stdin_b64 is not valid base64\n").into_response()
        }
    };
    match exec
        .exec(
            project.as_ref().as_str(),
            &name,
            &req.argv,
            stdin.as_deref(),
        )
        .await
    {
        Ok(out) => (
            StatusCode::OK,
            Json(ComputeExecResponse {
                exit_code: out.exit_code,
                stdout_b64: b64.encode(&out.stdout),
                stderr_b64: b64.encode(&out.stderr),
            }),
        )
            .into_response(),
        Err(boatramp_core::compute::ExecError::NoReplica(_)) => (
            StatusCode::CONFLICT,
            "workload has no running replica to exec in\n",
        )
            .into_response(),
        Err(boatramp_core::compute::ExecError::Unsupported(b)) => (
            StatusCode::NOT_IMPLEMENTED,
            format!("the {b} backend does not support exec\n"),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("exec failed: {e}\n")).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Persistent-volume management (`GET /api/compute/volumes`,
// `DELETE /api/compute/volumes/{name}`)
// ---------------------------------------------------------------------------

/// Query for `DELETE /api/compute/volumes/{name}`.
#[derive(Deserialize)]
pub(super) struct RemoveVolumeQuery {
    /// Remove even when the volume is still referenced by a registered workload's
    /// spec (the `409` override — for disposable data). Default `false`.
    #[serde(default)]
    force: bool,
}

/// List every persistent volume this node backs, each flagged with whether a
/// registered workload's active spec still references it (`in_use`). Admin-scoped
/// (the deny-safe `/api/compute/*` default). `501` if no volume-capable backend is
/// wired.
pub(super) async fn list_compute_volumes(
    Extension(volumes): Extension<Option<Arc<dyn boatramp_core::compute::ComputeVolumes>>>,
) -> Response {
    let Some(volumes) = volumes else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "compute volume management is not available on this node\n",
        )
            .into_response();
    };
    match volumes.list().await {
        Ok(list) => (StatusCode::OK, Json(list)).into_response(),
        Err(boatramp_core::compute::VolumeError::Unsupported) => (
            StatusCode::NOT_IMPLEMENTED,
            "no volume-capable backend on this node\n",
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            format!("list volumes failed: {e}\n"),
        )
            .into_response(),
    }
}

/// Remove a persistent volume by name. `204` on success, `404` if absent, and
/// `409` when the volume is still referenced by a registered workload's spec —
/// unless `?force=true`. Admin-scoped. `501` if no volume-capable backend is
/// wired.
pub(super) async fn delete_compute_volume(
    Extension(volumes): Extension<Option<Arc<dyn boatramp_core::compute::ComputeVolumes>>>,
    Path(name): Path<String>,
    Query(q): Query<RemoveVolumeQuery>,
) -> Response {
    let Some(volumes) = volumes else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "compute volume management is not available on this node\n",
        )
            .into_response();
    };
    match volumes.remove(&name, q.force).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such volume\n").into_response(),
        Err(boatramp_core::compute::VolumeError::InUse(_)) => (
            StatusCode::CONFLICT,
            "volume in use by a registered workload; `compute rm` it first, or pass --force\n",
        )
            .into_response(),
        Err(boatramp_core::compute::VolumeError::Unsupported) => (
            StatusCode::NOT_IMPLEMENTED,
            "no volume-capable backend on this node\n",
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            format!("remove volume failed: {e}\n"),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Compute maintenance / diagnostics — the operator "maneuvering" surface
// (`GET /api/compute/status`, `POST /api/compute/maintenance/set-health`,
// `GET /api/compute/ipam`). NODE-GLOBAL + `system·admin` (see
// `authz::is_compute_maintenance_path`): these read and override the reconcile
// plane across every tenant, so they must never be reachable by a project token.
// ---------------------------------------------------------------------------

/// The operator-facing view of one observed replica: its stored runtime state as
/// the reconcile loop last persisted it (the same record the endpoint resolver reads
/// to decide "healthy replica" — so `healthy: false` here on a `running`, endpoint-
/// bearing replica is exactly the "reachable but not served" signature).
#[derive(Serialize)]
struct ReplicaStatusView {
    project: String,
    workload: String,
    replica: u32,
    backend: String,
    /// Backend-specific reference (pid / container id / …) for correlating with the host.
    backend_ref: String,
    node: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    scheme: String,
    host: String,
    port: u16,
    /// The stored health flag — what the endpoint resolver gates on.
    healthy: bool,
    /// `running` or `zero` (scaled-to-zero).
    phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at: Option<u64>,
    /// Seconds since launch (`now - started_at`); `None` for older/restored records.
    #[serde(skip_serializing_if = "Option::is_none")]
    age_secs: Option<u64>,
}

impl ReplicaStatusView {
    fn of(o: &boatramp_core::compute::ObservedInstance, now: u64) -> Self {
        Self {
            project: o.handle.project.clone(),
            workload: o.handle.workload.clone(),
            replica: o.handle.replica,
            backend: o.backend.clone(),
            backend_ref: o.handle.backend_ref.clone(),
            node: o.node,
            region: o.region.clone(),
            scheme: o.endpoint.scheme.as_str().to_string(),
            host: o.endpoint.host.clone(),
            port: o.endpoint.port,
            healthy: o.healthy,
            phase: match o.phase {
                boatramp_core::compute::ReplicaPhase::Running => "running",
                boatramp_core::compute::ReplicaPhase::Zero => "zero",
            }
            .to_string(),
            started_at: o.started_at,
            age_secs: o.started_at.map(|s| now.saturating_sub(s)),
        }
    }
}

/// Node-global observed replica state across every tenant — the reconcile plane's
/// X-ray. Read-only; `system·admin`. Sorted by (project, workload, replica) for a
/// stable operator view.
pub(super) async fn compute_status(State(deploy): State<DeployStore>) -> Response {
    match deploy.list_all_replica_states().await {
        Ok(mut states) => {
            states.sort_by(|a, b| {
                (&a.handle.project, &a.handle.workload, a.handle.replica).cmp(&(
                    &b.handle.project,
                    &b.handle.workload,
                    b.handle.replica,
                ))
            });
            let now = boatramp_core::time::now_unix();
            let views: Vec<ReplicaStatusView> = states
                .iter()
                .map(|o| ReplicaStatusView::of(o, now))
                .collect();
            Json(views).into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Body of `POST /api/compute/maintenance/set-health` — override one replica's stored
/// health flag. The escape hatch for a persistence bug like the v0.3.12→v0.3.13 one
/// (a recovered replica stuck `healthy: false`): flip it to `true` and the endpoint
/// resolver serves it again, without waiting for a binary patch.
#[derive(Deserialize)]
pub(super) struct SetHealthRequest {
    project: String,
    workload: String,
    replica: u32,
    healthy: bool,
}

/// Force the stored `healthy` flag of one replica. `200` with the updated view,
/// `404` if no such replica is persisted. `system·admin`.
pub(super) async fn compute_set_health(
    State(deploy): State<DeployStore>,
    Json(req): Json<SetHealthRequest>,
) -> Response {
    let pref = boatramp_core::project::ProjectRef::new(&req.project);
    let states = match deploy.list_replica_states(pref, &req.workload).await {
        Ok(s) => s,
        Err(err) => return deploy_error_response(err),
    };
    let Some(mut target) = states.into_iter().find(|s| s.handle.replica == req.replica) else {
        return (
            StatusCode::NOT_FOUND,
            "no such replica is persisted for that workload\n",
        )
            .into_response();
    };
    target.healthy = req.healthy;
    if let Err(err) = deploy.set_replica_state(pref, &target).await {
        return deploy_error_response(err);
    }
    let now = boatramp_core::time::now_unix();
    (StatusCode::OK, Json(ReplicaStatusView::of(&target, now))).into_response()
}

/// One IP → the replica(s) that claim it, drawn from the persisted observed state.
#[derive(Serialize)]
struct IpAssignmentView {
    ip: String,
    project: String,
    workload: String,
    replica: u32,
    healthy: bool,
    phase: String,
}

/// The node-global IP-assignment view: every replica's persisted endpoint IP, plus
/// the set of IPs claimed by more than one replica (a collision — the v0.3.12 class).
#[derive(Serialize)]
struct IpamView {
    assignments: Vec<IpAssignmentView>,
    /// IPs claimed by two or more replicas — a duplicate-assignment collision.
    duplicates: Vec<String>,
}

/// Node-global IP assignments from the persisted observed state, with duplicate-IP
/// collisions surfaced. Read-only; `system·admin`. (This is the allocation view; a
/// backend live-pool snapshot is a separate, backend-coupled follow-up.)
pub(super) async fn compute_ipam(State(deploy): State<DeployStore>) -> Response {
    let states = match deploy.list_all_replica_states().await {
        Ok(s) => s,
        Err(err) => return deploy_error_response(err),
    };
    let mut assignments: Vec<IpAssignmentView> = states
        .iter()
        .map(|o| IpAssignmentView {
            ip: o.endpoint.host.clone(),
            project: o.handle.project.clone(),
            workload: o.handle.workload.clone(),
            replica: o.handle.replica,
            healthy: o.healthy,
            phase: match o.phase {
                boatramp_core::compute::ReplicaPhase::Running => "running",
                boatramp_core::compute::ReplicaPhase::Zero => "zero",
            }
            .to_string(),
        })
        .collect();
    assignments.sort_by(|a, b| {
        (&a.ip, &a.project, &a.workload, a.replica).cmp(&(
            &b.ip,
            &b.project,
            &b.workload,
            b.replica,
        ))
    });
    // A duplicate is any IP appearing on two or more DISTINCT replicas.
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for a in &assignments {
        *counts.entry(a.ip.as_str()).or_default() += 1;
    }
    let duplicates: Vec<String> = counts
        .into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(ip, _)| ip.to_string())
        .collect();
    Json(IpamView {
        assignments,
        duplicates,
    })
    .into_response()
}

/// Force the compute reconcile loop to run a convergence pass **now** instead of
/// waiting for its next periodic tick — the "kick it" lever for a workload stuck
/// mid-reconcile (a launch that needs re-attempting, a recovered replica the loop
/// should re-probe and persist). Reuses the same coalesced nudge the serving path
/// uses for wake-from-zero, so an extra pass is safe and serialized through the single
/// loop (no concurrent `reconcile_once`). Fire-and-forget: `202` acknowledges the
/// request; the operator reads the outcome with `compute status`. `system·admin`.
pub(super) async fn compute_reconcile() -> Response {
    crate::gateway::wake_reconcile();
    (
        StatusCode::ACCEPTED,
        "reconcile pass requested; check `boatramp compute status` for the result\n",
    )
        .into_response()
}

/// Body of `POST /api/compute/maintenance/restart` — restart one replica.
#[derive(Deserialize)]
pub(super) struct RestartRequest {
    project: String,
    workload: String,
    replica: u32,
}

/// Restart one replica: stop it and drop its observed state, then nudge the reconcile
/// loop to relaunch a fresh one (re-running IPAM) — the live workaround for a wedged
/// replica or a stale IP assignment. `200` on restart, `404` if no such replica,
/// `501` if no control-capable backend is wired. `system·admin`.
pub(super) async fn compute_restart(
    Extension(control): Extension<Option<Arc<dyn boatramp_core::compute::ComputeControl>>>,
    Json(req): Json<RestartRequest>,
) -> Response {
    let Some(control) = control else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "compute control is not available on this node\n",
        )
            .into_response();
    };
    match control
        .restart(&req.project, &req.workload, req.replica)
        .await
    {
        Ok(true) => {
            // Relaunch promptly instead of waiting for the next periodic tick.
            crate::gateway::wake_reconcile();
            (
                StatusCode::OK,
                format!(
                    "restarted {}/{} replica {}; reconcile will relaunch it\n",
                    req.project, req.workload, req.replica
                ),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            "no such replica is persisted for that workload\n",
        )
            .into_response(),
        Err(boatramp_core::compute::ControlError::Unsupported(b)) => (
            StatusCode::NOT_IMPLEMENTED,
            format!("the {b} backend does not support restart\n"),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("restart failed: {e}\n")).into_response(),
    }
}

/// Attempt a TCP connect to `host:port` with a short timeout — an active reachability
/// probe. `ToSocketAddrs` resolves both a literal IP (the co-located container case)
/// and a hostname; a resolve/connect failure or timeout ⇒ `false`.
async fn tcp_reachable(host: &str, port: u16) -> bool {
    matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect((host, port)),
        )
        .await,
        Ok(Ok(_))
    )
}

/// Body of `POST /api/compute/maintenance/netdiag` — probe a workload's replicas.
#[derive(Deserialize)]
pub(super) struct NetdiagRequest {
    project: String,
    workload: String,
}

/// One replica's network diagnosis: its persisted context plus an ACTIVE node→replica
/// TCP reachability probe. `tcp_reachable && !healthy` is the reachable-but-not-served
/// signature; `!tcp_reachable` points at an actual network/launch fault.
#[derive(Serialize)]
struct NetdiagReplicaView {
    replica: u32,
    endpoint: String,
    backend: String,
    healthy: bool,
    phase: String,
    tcp_reachable: bool,
}

/// Actively probe every replica of `workload` from the node — a TCP reachability check
/// against each replica's endpoint, alongside its stored state. The generalized,
/// on-demand counterpart to the launch-time network dump (which stays in the logs):
/// answers "can the node actually reach this replica right now?" for any compute
/// workload. `system·admin`.
pub(super) async fn compute_netdiag(
    State(deploy): State<DeployStore>,
    Json(req): Json<NetdiagRequest>,
) -> Response {
    let pref = boatramp_core::project::ProjectRef::new(&req.project);
    let states = match deploy.list_replica_states(pref, &req.workload).await {
        Ok(s) => s,
        Err(err) => return deploy_error_response(err),
    };
    let mut out = Vec::with_capacity(states.len());
    for st in &states {
        let reachable = tcp_reachable(&st.endpoint.host, st.endpoint.port).await;
        out.push(NetdiagReplicaView {
            replica: st.handle.replica,
            endpoint: format!("{}:{}", st.endpoint.host, st.endpoint.port),
            backend: st.backend.clone(),
            healthy: st.healthy,
            phase: match st.phase {
                boatramp_core::compute::ReplicaPhase::Running => "running",
                boatramp_core::compute::ReplicaPhase::Zero => "zero",
            }
            .to_string(),
            tcp_reachable: reachable,
        });
    }
    Json(out).into_response()
}

/// One internal-DNS forward entry: the name a peer in the same project resolves, and
/// the healthy replica IPs it currently answers with. Derived from the SAME observed
/// state (healthy + running replicas) the live resolver serves from, so this mirrors
/// what a guest's lookup would return.
#[derive(Serialize)]
struct DnsEntryView {
    project: String,
    workload: String,
    /// The unambiguous internal name (`<workload>.<project>`; a same-project peer may
    /// also use the bare `<workload>`). The node's `dns_domain` suffix is appended by
    /// guests on top of this.
    name: String,
    /// Healthy, running replica IPs (primary-first) — the answer set. Empty means the
    /// name currently resolves to nothing (every replica unhealthy/parked) — the
    /// "reachable-but-not-served" case at the DNS layer.
    addrs: Vec<String>,
    /// Total persisted replicas (healthy or not) for context.
    replicas: usize,
}

/// Build the internal-DNS forward map from the observed state: `(project, workload)` →
/// its replicas, with the healthy-running IPs as the answer set.
async fn dns_entries(deploy: &DeployStore) -> Result<Vec<DnsEntryView>, Response> {
    use boatramp_core::compute::ReplicaPhase;
    let states = deploy
        .list_all_replica_states()
        .await
        .map_err(deploy_error_response)?;
    let mut by_key: std::collections::BTreeMap<(String, String), (Vec<String>, usize)> =
        std::collections::BTreeMap::new();
    for st in &states {
        let key = (st.handle.project.clone(), st.handle.workload.clone());
        let entry = by_key.entry(key).or_default();
        entry.1 += 1;
        if st.phase == ReplicaPhase::Running && st.healthy {
            entry.0.push(st.endpoint.host.clone());
        }
    }
    Ok(by_key
        .into_iter()
        .map(|((project, workload), (addrs, replicas))| DnsEntryView {
            name: format!("{workload}.{project}"),
            project,
            workload,
            addrs,
            replicas,
        })
        .collect())
}

/// Node-global internal-DNS forward map (`compute dns ls`): every co-located workload's
/// internal name and the healthy replica IPs it answers with. Read-only; `system·admin`.
pub(super) async fn compute_dns(State(deploy): State<DeployStore>) -> Response {
    match dns_entries(&deploy).await {
        Ok(entries) => Json(entries).into_response(),
        Err(resp) => resp,
    }
}

/// Body of `POST /api/compute/dns/resolve` — resolve one workload's internal name.
#[derive(Deserialize)]
pub(super) struct DnsResolveRequest {
    project: String,
    workload: String,
}

/// Resolve one workload's internal name to its healthy replica IPs (`compute dns
/// resolve`), exactly as a same-project peer's lookup would — the diagnostic for
/// "why can't my guest reach <name>?". `system·admin`.
pub(super) async fn compute_dns_resolve(
    State(deploy): State<DeployStore>,
    Json(req): Json<DnsResolveRequest>,
) -> Response {
    match dns_entries(&deploy).await {
        Ok(entries) => {
            let hit = entries
                .into_iter()
                .find(|e| e.project == req.project && e.workload == req.workload);
            match hit {
                Some(e) => Json(e).into_response(),
                None => Json(DnsEntryView {
                    name: format!("{}.{}", req.workload, req.project),
                    project: req.project,
                    workload: req.workload,
                    addrs: Vec::new(),
                    replicas: 0,
                })
                .into_response(),
            }
        }
        Err(resp) => resp,
    }
}

/// Response for the OIDC→token exchange.
#[cfg(feature = "oidc")]
#[derive(Serialize)]
struct ExchangeResponse {
    /// The minted token (base64url COSE_Sign1 CWT).
    token: String,
    /// Its TTL in seconds.
    expires_in: u64,
}

/// Exchange a validated OIDC JWT (presented as the `Authorization: Bearer`) for
/// a short-TTL token whose roles come from the configured claim.
/// Needs both the OIDC verifier and the issuing key; otherwise `501`.
#[cfg(feature = "oidc")]
pub(super) async fn auth_exchange(
    Extension(issuer): Extension<Issuer>,
    Extension(oidc): Extension<OidcState>,
    headers: HeaderMap,
) -> Response {
    let (Some(signer), Some(verifier)) = (issuer.0, oidc.0) else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "OIDC exchange is not configured on this node\n",
        )
            .into_response();
    };
    let Some(jwt) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return (StatusCode::UNAUTHORIZED, "missing bearer JWT\n").into_response();
    };
    // The configured claim's values are role specs (`"<role>[:<site>]"`).
    let Some(claims) = verifier.verify(jwt) else {
        return (StatusCode::UNAUTHORIZED, "invalid OIDC token\n").into_response();
    };
    let roles: Vec<GrantedRole> = claims.iter().map(|s| GrantedRole::parse(s)).collect();
    if roles.is_empty() {
        return (
            StatusCode::FORBIDDEN,
            "OIDC token carries no boatramp roles\n",
        )
            .into_response();
    }
    let claims = Claims {
        roles,
        kind: cose::KIND_ROLE.to_string(),
        ttl_secs: Some(EXCHANGE_TTL_SECS),
        now_unix: now_unix(),
    };
    match cose::mint(&claims, &*signer).await {
        Ok(token) => Json(ExchangeResponse {
            token,
            expires_in: EXCHANGE_TTL_SECS,
        })
        .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

/// Return the manifest for a specific deployment id.
pub(super) async fn get_deployment(
    State(deploy): State<DeployStore>,
    Path((_site, id)): Path<(String, String)>,
) -> Response {
    match deploy.get_manifest(&id).await {
        Ok(Some(manifest)) => Json(manifest).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "deployment not found\n").into_response(),
        Err(err) => deploy_error_response(err),
    }
}

#[derive(Deserialize)]
pub(super) struct SetAliasRequest {
    /// Deployment id (full content hash) to point the alias at.
    id: String,
}

/// Point a named alias at a deployment id.
pub(super) async fn set_alias(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path((site, name)): Path<(String, String)>,
    Json(request): Json<SetAliasRequest>,
) -> Response {
    match deploy
        .set_alias(project.as_ref(), &site, &name, &request.id)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// List a site's named aliases (`name → deployment id`).
pub(super) async fn list_aliases(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(site): Path<String>,
) -> Response {
    match deploy.list_aliases(project.as_ref(), &site).await {
        Ok(map) => Json(map).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Remove a named alias.
pub(super) async fn remove_alias(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path((site, name)): Path<(String, String)>,
) -> Response {
    match deploy.remove_alias(project.as_ref(), &site, &name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such alias\n").into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Garbage-collection tuning, from query params: `?grace=<secs>` safety window
/// (default 3600), `?keep_last=<n>` and `?keep_age=<secs>` retention.
#[derive(Debug, Default, Deserialize)]
pub(super) struct PruneQuery {
    grace: Option<u64>,
    keep_last: Option<usize>,
    keep_age: Option<u64>,
}

impl PruneQuery {
    fn options(&self) -> GcOptions {
        GcOptions {
            // Default to a 1h grace window so a routine prune never races an
            // in-flight deploy. Callers can override (e.g. `?grace=0`).
            grace_secs: self.grace.unwrap_or(3600),
            keep_last: self.keep_last,
            keep_age_secs: self.keep_age,
        }
    }
}

/// Report reclaimable garbage without deleting anything (safe, read-only).
pub(super) async fn prune_report(
    State(deploy): State<DeployStore>,
    Query(q): Query<PruneQuery>,
) -> Response {
    prune_response(deploy.collect_garbage_with(false, q.options()).await)
}

/// Delete orphan manifests and unreferenced blobs.
pub(super) async fn prune_delete(
    State(deploy): State<DeployStore>,
    Query(q): Query<PruneQuery>,
) -> Response {
    prune_response(deploy.collect_garbage_with(true, q.options()).await)
}

fn prune_response(result: Result<GcReport, DeployError>) -> Response {
    match result {
        Ok(report) => Json(report).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Verify every stored blob still hashes to its key (integrity scrub).
/// Read-only; the JSON report lists any corrupted or unreadable blobs.
pub(super) async fn scrub_blobs(State(deploy): State<DeployStore>) -> Response {
    match deploy.scrub_blobs().await {
        Ok(report) => Json(report).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Cluster-managed cert status (domain + expiry; never key material).
pub(super) async fn cert_status(State(deploy): State<DeployStore>) -> Response {
    match deploy.cert_status().await {
        Ok(status) => Json(status).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Push cache-invalidation (shared-mode coherence):
/// a Cloudflare DO / Queue (or any pusher) POSTs the keys a peer changed for
/// real-time invalidation without waiting on the poll. Empty `keys` flushes the
/// whole cache (the coarse fallback). Admin-scoped (under `/api`, "*" required).
pub(super) async fn invalidate_cache(
    State(deploy): State<DeployStore>,
    Json(body): Json<InvalidateRequest>,
) -> Response {
    if body.keys.is_empty() {
        deploy.invalidate_cache();
    } else {
        deploy.invalidate_cache_keys(&body.keys);
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
pub(super) struct InvalidateRequest {
    #[serde(default)]
    keys: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_meta_query_parses_tag_and_tags_json() {
        let q = DeployMetaQuery {
            source: Some("abc".into()),
            branch: None,
            author: None,
            message: None,
            tag: Some("v1.2.3".into()),
            tags: Some(r#"{"env":"prod","ticket":"ABC-123"}"#.into()),
        };
        let input: DeployMetaInput = q.into();
        assert_eq!(input.tag.as_deref(), Some("v1.2.3"));
        assert_eq!(input.tags.get("env").map(String::as_str), Some("prod"));
        assert_eq!(
            input.tags.get("ticket").map(String::as_str),
            Some("ABC-123")
        );
    }

    #[test]
    fn deploy_meta_query_malformed_tags_drop_to_empty() {
        let q = DeployMetaQuery {
            tags: Some("not json".into()),
            ..Default::default()
        };
        let input: DeployMetaInput = q.into();
        assert!(input.tags.is_empty());
    }

    /// A mock invoker with a canned `_service { sdl }` answer, for testing subgraph SDL
    /// introspection without a deployed component.
    #[cfg(feature = "handlers")]
    struct SdlInvoker(&'static str);

    #[cfg(feature = "handlers")]
    #[async_trait::async_trait]
    impl boatramp_handlers::Invoker for SdlInvoker {
        async fn invoke(
            &self,
            _target: &str,
            _request: boatramp_handlers::InvokeRequest,
            _depth: u32,
        ) -> Result<boatramp_handlers::InvokeResponse, boatramp_handlers::InvokeError> {
            let body = serde_json::json!({ "data": { "_service": { "sdl": self.0 } } });
            Ok(boatramp_handlers::InvokeResponse {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&body).unwrap(),
            })
        }
    }

    /// A mock invoker that answers with a body carrying no `_service` — i.e. a deployed
    /// function that is not a federation subgraph.
    #[cfg(feature = "handlers")]
    struct NonSubgraphInvoker;

    #[cfg(feature = "handlers")]
    #[async_trait::async_trait]
    impl boatramp_handlers::Invoker for NonSubgraphInvoker {
        async fn invoke(
            &self,
            _target: &str,
            _request: boatramp_handlers::InvokeRequest,
            _depth: u32,
        ) -> Result<boatramp_handlers::InvokeResponse, boatramp_handlers::InvokeError> {
            let body = serde_json::json!({ "data": { "hello": "world" } });
            Ok(boatramp_handlers::InvokeResponse {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&body).unwrap(),
            })
        }
    }

    /// A mock invoker with nothing deployed — every target is `NotFound`.
    #[cfg(feature = "handlers")]
    struct UndeployedInvoker;

    #[cfg(feature = "handlers")]
    #[async_trait::async_trait]
    impl boatramp_handlers::Invoker for UndeployedInvoker {
        async fn invoke(
            &self,
            _target: &str,
            _request: boatramp_handlers::InvokeRequest,
            _depth: u32,
        ) -> Result<boatramp_handlers::InvokeResponse, boatramp_handlers::InvokeError> {
            Err(boatramp_handlers::InvokeError::NotFound)
        }
    }

    #[cfg(feature = "handlers")]
    #[tokio::test]
    async fn introspecting_a_subgraph_returns_its_sdl() {
        let inv = SdlInvoker("type Query { me: String }");
        let sdl = introspect_function_sdl(&inv, "accounts").await.unwrap();
        assert!(sdl.contains("type Query"));
    }

    #[cfg(feature = "handlers")]
    #[tokio::test]
    async fn introspecting_an_undeployed_function_is_409() {
        let (status, _msg) = introspect_function_sdl(&UndeployedInvoker, "ghost")
            .await
            .unwrap_err();
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[cfg(feature = "handlers")]
    #[tokio::test]
    async fn introspecting_a_non_subgraph_function_is_422() {
        let (status, _msg) = introspect_function_sdl(&NonSubgraphInvoker, "plain")
            .await
            .unwrap_err();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // ---- compute maintenance / diagnostics (operator "maneuvering" surface) --------

    /// A storage backend that holds nothing — the compute maintenance handlers read
    /// only the KV-backed observed state, never blob storage.
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

    /// A fresh in-memory `DeployStore` (KV-backed observed state; no blob storage).
    fn store() -> DeployStore {
        DeployStore::new(
            Arc::new(NullStorage),
            Arc::new(boatramp_core::kv::MemoryKv::new()),
        )
    }

    /// Build a persisted-replica record.
    fn obs(
        project: &str,
        workload: &str,
        replica: u32,
        ip: &str,
        healthy: bool,
        started_at: Option<u64>,
    ) -> boatramp_core::compute::ObservedInstance {
        use boatramp_core::compute::{
            Endpoint, InstanceHandle, ObservedInstance, ReplicaPhase, Scheme,
        };
        ObservedInstance {
            handle: InstanceHandle {
                project: project.to_string(),
                workload: workload.to_string(),
                replica,
                backend_ref: format!("pid-{replica}"),
            },
            node: 1,
            backend: "container".to_string(),
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: ip.to_string(),
                port: 5432,
            },
            region: None,
            healthy,
            started_at,
            phase: ReplicaPhase::Running,
            snapshot: None,
        }
    }

    /// Consume a `Response` into its parsed JSON body.
    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("body is json")
    }

    #[tokio::test]
    async fn compute_status_surfaces_the_stored_health_of_every_tenant() {
        let deploy = store();
        // A reachable-but-not-served replica (`healthy: false` while `Running`) — the
        // v0.3.13 signature — plus a healthy one, in two different tenants.
        deploy
            .set_replica_state(
                boatramp_core::project::ProjectRef::new("acme"),
                &obs(
                    "acme",
                    "pg",
                    0,
                    "10.0.0.2",
                    false,
                    Some(boatramp_core::time::now_unix() - 30),
                ),
            )
            .await
            .unwrap();
        deploy
            .set_replica_state(
                boatramp_core::project::ProjectRef::new("globex"),
                &obs(
                    "globex",
                    "pg",
                    0,
                    "10.0.0.3",
                    true,
                    Some(boatramp_core::time::now_unix()),
                ),
            )
            .await
            .unwrap();

        let resp = compute_status(State(deploy)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let arr = body.as_array().expect("array");
        assert_eq!(arr.len(), 2, "both tenants' replicas are visible");
        let acme = arr
            .iter()
            .find(|r| r["project"] == "acme")
            .expect("acme present");
        assert_eq!(
            acme["healthy"], false,
            "the stuck replica shows healthy=false"
        );
        assert_eq!(acme["phase"], "running");
        assert_eq!(acme["host"], "10.0.0.2");
        assert_eq!(acme["port"], 5432);
        assert!(
            acme["age_secs"].as_u64().unwrap() >= 30,
            "age derived from started_at"
        );
        let globex = arr
            .iter()
            .find(|r| r["project"] == "globex")
            .expect("globex present");
        assert_eq!(globex["healthy"], true);
    }

    #[tokio::test]
    async fn set_health_flips_and_persists_the_stored_flag() {
        let deploy = store();
        let pref = boatramp_core::project::ProjectRef::new("acme");
        deploy
            .set_replica_state(pref, &obs("acme", "pg", 0, "10.0.0.2", false, None))
            .await
            .unwrap();

        // Force it healthy — the escape hatch for a persistence bug.
        let req = SetHealthRequest {
            project: "acme".into(),
            workload: "pg".into(),
            replica: 0,
            healthy: true,
        };
        let resp = compute_set_health(State(deploy.clone()), Json(req)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["healthy"], true);

        // The store now reflects it — the endpoint resolver would serve it again.
        let states = deploy.list_replica_states(pref, "pg").await.unwrap();
        assert_eq!(states.len(), 1);
        assert!(states[0].healthy, "the flip is persisted");

        // A missing replica is a 404, not a silent no-op.
        let miss = compute_set_health(
            State(deploy),
            Json(SetHealthRequest {
                project: "acme".into(),
                workload: "pg".into(),
                replica: 9,
                healthy: true,
            }),
        )
        .await;
        assert_eq!(miss.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn ipam_flags_a_duplicate_ip_collision() {
        let deploy = store();
        // Two DIFFERENT workloads both claiming 10.0.0.2 — the v0.3.12 collision class.
        deploy
            .set_replica_state(
                boatramp_core::project::ProjectRef::new("acme"),
                &obs("acme", "pg", 0, "10.0.0.2", true, None),
            )
            .await
            .unwrap();
        deploy
            .set_replica_state(
                boatramp_core::project::ProjectRef::new("globex"),
                &obs("globex", "pg", 0, "10.0.0.2", true, None),
            )
            .await
            .unwrap();
        // A third, non-colliding assignment.
        deploy
            .set_replica_state(
                boatramp_core::project::ProjectRef::new("acme"),
                &obs("acme", "web", 0, "10.0.0.4", true, None),
            )
            .await
            .unwrap();

        let resp = compute_ipam(State(deploy)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["assignments"].as_array().unwrap().len(), 3);
        let dups = body["duplicates"].as_array().unwrap();
        assert_eq!(dups.len(), 1, "exactly one colliding IP");
        assert_eq!(dups[0], "10.0.0.2");
    }

    /// A `ComputeControl` that records the restart it was asked for and answers with a
    /// canned found/not-found result — so the handler's status mapping is testable
    /// without a live backend.
    struct FakeControl {
        found: bool,
        seen: std::sync::Mutex<Vec<(String, String, u32)>>,
    }

    #[async_trait::async_trait]
    impl boatramp_core::compute::ComputeControl for FakeControl {
        async fn restart(
            &self,
            project: &str,
            workload: &str,
            replica: u32,
        ) -> Result<bool, boatramp_core::compute::ControlError> {
            self.seen
                .lock()
                .unwrap()
                .push((project.to_string(), workload.to_string(), replica));
            Ok(self.found)
        }
    }

    #[tokio::test]
    async fn restart_maps_found_and_missing_replicas() {
        // A found replica → 200, and the capability was called with the exact target.
        let ctrl = Arc::new(FakeControl {
            found: true,
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let resp = compute_restart(
            Extension(Some(
                ctrl.clone() as Arc<dyn boatramp_core::compute::ComputeControl>
            )),
            Json(RestartRequest {
                project: "acme".into(),
                workload: "pg".into(),
                replica: 0,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            ctrl.seen.lock().unwrap().as_slice(),
            &[("acme".to_string(), "pg".to_string(), 0)]
        );

        // A missing replica → 404.
        let miss = Arc::new(FakeControl {
            found: false,
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let resp = compute_restart(
            Extension(Some(
                miss as Arc<dyn boatramp_core::compute::ComputeControl>,
            )),
            Json(RestartRequest {
                project: "acme".into(),
                workload: "pg".into(),
                replica: 9,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // No capability wired → 501.
        let resp = compute_restart(
            Extension(None),
            Json(RestartRequest {
                project: "acme".into(),
                workload: "pg".into(),
                replica: 0,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    /// An `OperatorSql` whose `ping` returns a canned fleet — so the handler's shape
    /// and status mapping are testable without a live database.
    struct FakePingSql(Vec<boatramp_core::sql::SqlPingReplica>);

    #[async_trait::async_trait]
    impl boatramp_core::sql::OperatorSql for FakePingSql {
        async fn exec_script(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<(), boatramp_core::sql::SqlError> {
            Ok(())
        }
        async fn query(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<boatramp_core::sql::SqlRows, boatramp_core::sql::SqlError> {
            Ok(boatramp_core::sql::SqlRows {
                columns: vec![],
                rows: vec![],
            })
        }
        async fn ping(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Vec<boatramp_core::sql::SqlPingReplica>, boatramp_core::sql::SqlError> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn sql_ping_surfaces_reachable_but_unhealthy_replicas() {
        use boatramp_core::sql::SqlPingReplica;
        // The v0.3.13 signature: TCP-reachable yet stored `healthy: false`.
        let op: Arc<dyn boatramp_core::sql::OperatorSql> =
            Arc::new(FakePingSql(vec![SqlPingReplica {
                endpoint: "10.0.0.3:5432".into(),
                healthy: false,
                phase: "running".into(),
                tcp_reachable: true,
            }]));
        let resp = sql_ping(
            Extension(ProjectContext("construens".into())),
            Extension(Some(op)),
            Path("default".into()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let arr = body.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["tcp_reachable"], true);
        assert_eq!(
            arr[0]["healthy"], false,
            "reachable-but-not-served signature"
        );
        assert_eq!(arr[0]["endpoint"], "10.0.0.3:5432");

        // No managed SQL wired → 501.
        let resp = sql_ping(
            Extension(ProjectContext("construens".into())),
            Extension(None),
            Path("default".into()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn netdiag_actively_probes_each_replica_endpoint() {
        let deploy = store();
        // Bind a real listener so one replica is genuinely reachable; point a second
        // replica at a port nothing listens on so it is genuinely unreachable.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up = listener.local_addr().unwrap();
        deploy
            .set_replica_state(
                boatramp_core::project::ProjectRef::new("acme"),
                &obs("acme", "pg", 0, "127.0.0.1", true, None),
            )
            .await
            .unwrap();
        // Overwrite replica 0's port to the live listener's; add replica 1 on a dead port.
        {
            let mut r0 = obs("acme", "pg", 0, "127.0.0.1", true, None);
            r0.endpoint.port = up.port();
            deploy
                .set_replica_state(boatramp_core::project::ProjectRef::new("acme"), &r0)
                .await
                .unwrap();
            let mut r1 = obs("acme", "pg", 1, "127.0.0.1", false, None);
            r1.endpoint.port = 1; // nothing listens on TCP/1 in the test sandbox
            deploy
                .set_replica_state(boatramp_core::project::ProjectRef::new("acme"), &r1)
                .await
                .unwrap();
        }

        let resp = compute_netdiag(
            State(deploy),
            Json(NetdiagRequest {
                project: "acme".into(),
                workload: "pg".into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let arr = body.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        let r0 = arr.iter().find(|r| r["replica"] == 0).unwrap();
        assert_eq!(r0["tcp_reachable"], true, "the live listener is reachable");
        let r1 = arr.iter().find(|r| r["replica"] == 1).unwrap();
        assert_eq!(r1["tcp_reachable"], false, "the dead port is unreachable");
    }

    #[tokio::test]
    async fn dns_forward_map_answers_only_healthy_running_replicas() {
        let deploy = store();
        // acme/web: two replicas, only #0 healthy → the name answers just #0's IP.
        deploy
            .set_replica_state(
                boatramp_core::project::ProjectRef::new("acme"),
                &obs("acme", "web", 0, "10.0.0.5", true, None),
            )
            .await
            .unwrap();
        deploy
            .set_replica_state(
                boatramp_core::project::ProjectRef::new("acme"),
                &obs("acme", "web", 1, "10.0.0.6", false, None),
            )
            .await
            .unwrap();

        // Resolve acme/web → only the healthy IP, and the name matches the convention.
        let resp = compute_dns_resolve(
            State(deploy.clone()),
            Json(DnsResolveRequest {
                project: "acme".into(),
                workload: "web".into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["name"], "web.acme");
        assert_eq!(body["addrs"].as_array().unwrap().len(), 1);
        assert_eq!(body["addrs"][0], "10.0.0.5");
        assert_eq!(body["replicas"], 2);

        // An unknown workload resolves to nothing (not an error).
        let resp = compute_dns_resolve(
            State(deploy),
            Json(DnsResolveRequest {
                project: "acme".into(),
                workload: "ghost".into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert!(body["addrs"].as_array().unwrap().is_empty());
    }
}
