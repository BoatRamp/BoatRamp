//! The control-plane admin REST API: deployment lifecycle (create, upload
//! blobs, activate, list, prune, scrub), per-site config and aliases, the
//! dynamic daemon config, compute-backend management, cache invalidation, cert
//! status, and the OIDC token exchange. These are the `/api/...` endpoints the
//! router mounts behind admin auth. Pulls the shared response helpers in via
//! `use super::*`.

use super::*;

use boatramp_core::compute::PutComputeRequest;

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
    // PLAN-system-principal P2: deployer-class capture happens at ACTIVATION (per (project, site)),
    // NOT here — registering content carries no per-site authority. See `activate_deployment`.
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
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
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
        Ok(()) => {
            // #1a (deploy-resilience): warm the compiled-module cache off the critical path, so a
            // later deploy-time introspection / first request is a cache hit instead of a cold
            // compile that can blow the client/proxy timeout. Best-effort + concurrency-gated (#2):
            // acquire a compile permit FIRST, then read the just-stored blob back — so under an
            // upload burst at most `compile_concurrency` full blobs are resident at once, not one
            // per concurrent upload (bounds peak RSS on the small hosts this release targets). Only
            // if it's a wasm **component** (magic bytes) is it precompiled (no guest code runs). A
            // non-component asset, a compile failure, or a node without an engine is silently
            // skipped — the deploy remains the activation authority. Spawned so the upload responds
            // immediately.
            #[cfg(feature = "handlers")]
            {
                let handlers = handlers.clone();
                let deploy = deploy.clone();
                let hash = hash.clone();
                tokio::spawn(async move {
                    // No engine on this node ⇒ nothing to warm; don't even read the blob back.
                    let Some(_permit) = handlers.acquire_compile_permit().await else {
                        return;
                    };
                    match crate::handler_dispatch::read_blob_bytes(&deploy, &hash).await {
                        Ok(wasm) if is_wasm_component(&wasm) => {
                            // Already holding the permit — use the non-re-gating precompile.
                            if let Err(e) = handlers
                                .precompile_component_holding_permit(&hash, &wasm)
                                .await
                            {
                                tracing::debug!(hash = %hash, "precompile-at-upload skipped: {e}");
                            }
                        }
                        _ => {} // not a component (or unreadable) — nothing to warm
                    }
                });
            }
            #[cfg(not(feature = "handlers"))]
            let _ = &handlers;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Whether `bytes` begins with the wasm **component** preamble (`\0asm` + layer byte `0x01`) — a
/// core module has layer `0x00`, so this precompiles only components (what handlers deploy), never
/// an uploaded static asset. (deploy-resilience #1a)
#[cfg(feature = "handlers")]
fn is_wasm_component(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && bytes[0..4] == [0x00, 0x61, 0x73, 0x6d] && bytes[6] == 0x01
}

pub(super) async fn activate_deployment(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    // PLAN-system-principal P2: the SERVER-DERIVED class of the actor performing THIS activation
    // (stashed by `require_auth`; absent when auth is disabled). This — bound to the (project, site)
    // being made live — is the sole authority a `run_as: deployer` cron consults. The client cannot
    // supply it. A non-body extractor, so it precedes `Path`.
    deploy_class: Option<Extension<crate::auth::VerifiedDeployClass>>,
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
                .precheck_activation(&deploy, &manifest, site_config.as_ref(), &project.0)
                .await
            {
                tracing::warn!(site, id, reason, "activation refused by handler pre-check");
                return (StatusCode::UNPROCESSABLE_ENTITY, format!("{reason}\n")).into_response();
            }
            // Two-tier gateway (0.37.0): a project manifest may only DECLARE gateway reach bounded by
            // the site's grants + ceilings. This is the authoritative with-site declare point — count
            // caps, the shared/collision rules, the route→upstream existence check, and the
            // raw-target egress-host allowlist all fire here with the SiteConfig in hand (atop the
            // posture-independent IP bright line re-checked on every resolved address at serve). A
            // deploy with no project gateway has empty `upstreams`/`routes`, so this is a no-op for it.
            if let Err(err) = boatramp_core::gateway::validate_project_gateway(
                &manifest.config.gateway,
                site_config.as_ref().and_then(|c| c.gateway.as_ref()),
                site_config.as_ref().map(|c| &c.gateway_caps),
            ) {
                tracing::warn!(site, id, %err, "activation refused: project gateway over site bounds");
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("gateway: {err}\n"),
                )
                    .into_response();
            }
        }
        // A missing manifest falls through; `activate` returns the NotFound error.
        Ok(None) => {}
        Err(err) => return deploy_error_response(err),
    }
    let activator = deploy_class.map(|Extension(c)| c.0);
    match deploy
        .activate_with_principal(project.as_ref(), &site, &id, activator)
        .await
    {
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
/// Outcome of the added-domain verification guard: either every newly-added domain is
/// ownership-verified, or one isn't (with a human reason).
pub(super) enum DomainGuard {
    Ok,
    Unverified(String),
}

/// For a site-config write, ensure every **newly-added** domain is already ownership-verified
/// (and a wildcard via DNS). Shared by the HTTP [`put_site_config`] and the guest `admin`
/// site-config path so **neither** can attach an unverified domain — the routing-hijack guard.
/// Diffs on the *canonical* host form (case/trailing-dot folded, wildcard `*.` preserved) so it
/// agrees with the normalizing verification lookup and a case-variant can't launder a host in.
pub(super) async fn check_added_domains_verified(
    deploy: &DeployStore,
    project: boatramp_core::project::ProjectRef<'_>,
    site: &str,
    next: &SiteConfig,
) -> Result<DomainGuard, boatramp_core::error::DeployError> {
    let current = deploy
        .get_site_config(project, site)
        .await?
        .unwrap_or_default();
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
    let added: Vec<String> = next
        .domains
        .exact_hosts()
        .map(canon_domain_entry)
        .chain(next.domains.wildcards.iter().map(|w| canon_domain_entry(w)))
        .filter(|host| !existing.contains(host))
        .collect();
    for host in added {
        let verification = deploy
            .get_domain_verification(project, &boatramp_core::site::SiteName::new(site), &host)
            .await?;
        if !verification.as_ref().is_some_and(|v| v.verified) {
            return Ok(DomainGuard::Unverified(format!(
                "{host} is not verified for {site}; verify it (`boatramp domain add {host} --site {site}`, or the admin `domain-verify`) first"
            )));
        }
        // A wildcard needs DNS proof (parity with `attach_verified_domain`).
        if host.starts_with("*.")
            && verification.as_ref().map(|v| v.method)
                != Some(boatramp_core::domain_verify::VerificationMethod::Dns)
        {
            return Ok(DomainGuard::Unverified(format!(
                "wildcard {host} must be verified via DNS (an HTTP token proves only the base host)"
            )));
        }
    }
    Ok(DomainGuard::Ok)
}

pub(super) async fn put_site_config(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(site): Path<String>,
    Json(config): Json<SiteConfig>,
) -> Response {
    if let Some(resp) = reject_invalid_name("site", &site) {
        return resp;
    }
    match check_added_domains_verified(&deploy, project.as_ref(), &site, &config).await {
        Ok(DomainGuard::Ok) => {}
        Ok(DomainGuard::Unverified(reason)) => {
            return (StatusCode::FORBIDDEN, format!("{reason}\n")).into_response();
        }
        Err(err) => return deploy_error_response(err),
    }
    // Per-site subgraph composition (S2b): a site's `graphql.subgraphs` include list is validated
    // fail-closed HERE, at the config-write chokepoint, against the live registry — an empty set, an
    // unregistered include, or an invalid Federation subset is a `400` and the config is NOT stored.
    // Absent ⇒ full-project (nothing to validate, byte-identical to before).
    #[cfg(feature = "handlers")]
    if let Some(gql) = config.handlers.as_ref().and_then(|h| h.graphql.as_ref())
        && let Some(subset) = gql.subgraphs.as_ref()
    {
        if !gql.federated {
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "site \"{site}\": graphql.subgraphs is set but the graphql edge is not \
                     `federated` — per-site subset composition applies only to a federated \
                     supergraph gateway (set `federated = true`, or remove `subgraphs`)\n"
                ),
            )
                .into_response();
        }
        if let Err(reason) =
            crate::graphql_registry::validate_site_subset(deploy.kv().as_ref(), &project.0, subset)
                .await
        {
            return (
                StatusCode::BAD_REQUEST,
                format!("site \"{site}\": {reason}\n"),
            )
                .into_response();
        }
    }
    // Cooperative (apply-merge-contexts): a whole-config PUT preserves imperatively-written
    // `domains.contexts`/`aliases` the incoming config doesn't mention — so a declarative `apply`
    // (which calls this) can't wipe a tenant's runtime host routing. Removal stays via `domain rm`.
    match deploy
        .set_site_config_cooperative(project.as_ref(), &site, &config)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `GET /api/projects/{proj}/tenancy` — the project's [`TenancySchema`], the per-table
/// tenant-key map the scope injector consults (deny-by-default on undeclared tables).
/// A project that declared none returns the default schema (`tenant_id`, no tables),
/// i.e. legacy single-column `Uniform` scoping. Read-scoped (`Project·Read`).
pub(super) async fn get_project_tenancy(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
) -> Response {
    match deploy.get_project_tenancy(project.as_ref()).await {
        Ok(schema) => Json(schema.unwrap_or_default()).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `PUT /api/projects/{proj}/tenancy` — replace the project's [`TenancySchema`].
///
/// This redraws the tenant-isolation boundary for **every** guest query in the
/// project, so it is gated at `Project·Admin` in [`authz::Right::required`] — never the
/// deploy-grade publisher right. Storage is plain; deny-by-default is enforced
/// downstream at scope injection, so a malformed/over-broad schema cannot silently
/// widen access without a subsequent query still resolving each table's key.
pub(super) async fn put_project_tenancy(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Json(schema): Json<boatramp_core::tenancy::TenancySchema>,
) -> Response {
    match deploy.set_project_tenancy(project.as_ref(), &schema).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `DELETE /api/projects/{proj}/tenancy` — clear the project's schema (revert to legacy
/// `Uniform` single-column scoping). Idempotent; `Project·Admin` like the PUT.
pub(super) async fn delete_project_tenancy(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
) -> Response {
    match deploy.clear_project_tenancy(project.as_ref()).await {
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

/// `POST /api/projects/{proj}/graphql/compose` — validate + promote the **staged** subgraphs
/// (deploy-resilience #3) in one composition. An apply that deployed many subgraphs with
/// `?compose=defer` calls this once at the end: the whole set is composed together, and on success
/// every staged SDL is promoted to live with a single version bump; on a composition failure
/// nothing is promoted and the live supergraph is untouched. `System·Admin`.
#[cfg(feature = "handlers")]
pub(super) async fn post_graphql_compose(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
) -> Response {
    let kv = deploy.kv().as_ref();
    match crate::graphql_registry::compose_batch(kv, &project.0).await {
        Ok(sg) => {
            let names = crate::graphql_registry::subgraph_names(kv, &project.0).await;
            axum::Json(crate::graphql_registry::summary_json(&sg, &names)).into_response()
        }
        Err(crate::graphql_registry::PublishError::Composition(e)) => (
            StatusCode::BAD_REQUEST,
            format!("staged supergraph does not compose: {e}\n"),
        )
            .into_response(),
        Err(crate::graphql_registry::PublishError::Store(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("registry store error: {e}\n"),
        )
            .into_response(),
    }
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
            return (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response();
        }
        Err(crate::graphql_registry::PublishError::Store(e)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("registry store error: {e}\n"),
            )
                .into_response();
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
            ));
        }
        Ok(Err(boatramp_handlers::InvokeError::NotFound)) => {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "no function named `{name}` is deployed — deploy it before registering it as a subgraph\n"
                ),
            ));
        }
        Ok(Err(boatramp_handlers::InvokeError::Failed(msg))) => {
            return Err((
                StatusCode::BAD_GATEWAY,
                format!("subgraph `{name}` failed answering `_service {{ sdl }}`: {msg}\n"),
            ));
        }
        Ok(Ok(response)) => response,
    };
    let parsed: serde_json::Value =
        serde_json::from_slice(&response.body).unwrap_or(serde_json::Value::Null);
    match parsed
        .pointer("/data/_service/sdl")
        .and_then(|v| v.as_str())
    {
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
    // Introspect anonymously, scoped to the project (an invoke never crosses tenants); no in-site
    // tenant and no sealed principal to propagate for an anonymous SDL fetch (PLAN-async-persona).
    let scoped = invoker.scoped(
        boatramp_core::project::ProjectRef::new(&project.0),
        Vec::new(),
        None,
    );
    let sdl = match introspect_function_sdl(scoped.as_ref(), &name).await {
        Ok(sdl) => sdl,
        Err((status, message)) => return (status, message).into_response(),
    };
    let kv = deploy.kv().as_ref();
    // Publish the SDL (recompose + validate) first — a bad compose never records a backend.
    let sg = match crate::graphql_registry::publish(kv, &project.0, &name, &sdl).await {
        Ok(sg) => sg,
        Err(crate::graphql_registry::PublishError::Composition(e)) => {
            return (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response();
        }
        Err(crate::graphql_registry::PublishError::Store(e)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("registry store error: {e}\n"),
            )
                .into_response();
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

/// Query params for safelist registration. `site` (optional) names the site this operation is being
/// safelisted *for* — when that site composes a per-site subgraph subset (`graphql.subgraphs`), the
/// operation is validated fail-closed against THAT site's composed schema (S2b): an op selecting a
/// root the subset doesn't contain is rejected. Absent ⇒ project-level registration with no per-site
/// subset check (the direct `graphql safelist add` path).
#[cfg(feature = "handlers")]
#[derive(serde::Deserialize, Default)]
pub(super) struct SafelistParams {
    #[serde(default)]
    site: Option<String>,
}

/// Fail-closed (S2b): if `site` composes a per-site subgraph subset, reject a safelisted operation
/// that selects a root `Query`/`Mutation` field absent from that site's composed subset — the op
/// could never run on this site's schema, so declaring it there is almost certainly a mistake
/// (same spirit as the include-validation). Best-effort on a config/registry read blip (never blocks
/// registration on an unrelated transient); the site-config PUT is the authoritative subset gate.
/// A full-project site (no `subgraphs`) imposes no restriction. Introspection meta + `__typename`
/// (`__`-prefixed) roots are never subset-scoped.
#[cfg(feature = "handlers")]
async fn check_op_in_site_subset(
    deploy: &DeployStore,
    project: &ProjectContext,
    site: &str,
    query: &str,
) -> Result<(), Response> {
    let cfg = match deploy.get_site_config(project.as_ref(), site).await {
        Ok(Some(cfg)) => cfg,
        // No such site yet, or a transient read error: the config PUT validates the subset itself —
        // don't block a register-only call on it.
        Ok(None) | Err(_) => return Ok(()),
    };
    let Some(subset) = cfg
        .handlers
        .as_ref()
        .and_then(|h| h.graphql.as_ref())
        .filter(|g| g.federated)
        .and_then(|g| g.subgraphs.clone())
    else {
        return Ok(());
    };
    let sg =
        match crate::graphql_registry::supergraph_subset(deploy.kv().as_ref(), &project.0, &subset)
            .await
        {
            Ok(sg) => sg,
            // The subset doesn't compose — that's the site-config PUT's error to report, not this one.
            Err(_) => return Ok(()),
        };
    let Ok(doc) = async_graphql_parser::parse_query(query) else {
        // Unparsable — `guard_query` already rejected it upstream; nothing to subset-check.
        return Ok(());
    };
    let fragments = crate::graphql_root_fields::document_fragments(&doc);
    let ops: Vec<&async_graphql_parser::types::OperationDefinition> = match &doc.operations {
        async_graphql_parser::types::DocumentOperations::Single(op) => vec![&op.node],
        async_graphql_parser::types::DocumentOperations::Multiple(m) => {
            m.values().map(|o| &o.node).collect()
        }
    };
    let mut missing: Vec<String> = Vec::new();
    for op in ops {
        for (root_ty, field) in crate::graphql_root_fields::expanded_root_fields(op, &fragments) {
            if field.starts_with("__") {
                continue; // introspection meta / __typename — never subset-scoped
            }
            let present = match root_ty {
                crate::graphql_root_fields::RootType::Query => sg.root_query.contains_key(&field),
                crate::graphql_root_fields::RootType::Mutation => {
                    sg.root_mutation.contains_key(&field)
                }
                // Federated subscriptions aren't subset-tracked (the composed supergraph carries
                // only Query/Mutation roots); don't over-restrict apply by rejecting a safelisted
                // subscription op here (sec-review LOW-3). Skip it rather than mark it absent.
                crate::graphql_root_fields::RootType::Subscription => continue,
            };
            if !present {
                missing.push(format!("{}.{}", root_ty.type_name(), field));
            }
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    missing.sort_unstable();
    missing.dedup();
    Err((
        StatusCode::BAD_REQUEST,
        format!(
            "site \"{site}\": safelisted operation selects root field(s) absent from this site's \
             graphql.subgraphs subset: {} — the operation cannot run on this site's composed schema \
             (adjust the subset or the operation)\n",
            missing.join(", ")
        ),
    )
        .into_response())
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
    Query(params): Query<SafelistParams>,
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
    // S2b: when registered FOR a site that composes a per-site subset, fail closed on an op whose
    // roots the subset doesn't contain.
    if let Some(site) = params.site.as_deref()
        && let Err(resp) = check_op_in_site_subset(&deploy, &project, site, query).await
    {
        return resp;
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

/// The body of `PUT /api/compute/:name` — the spec plus desired replicas/placement —
/// is the shared [`boatramp_core::compute::PutComputeRequest`] (re-exported from
/// `boatramp-types`), so the `apply` manifest client parses the SAME type: no
/// duplicated schema between the server and the CLI.
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
    // A `pull_secret` authenticates an OCI **image** pull; it is meaningless on a tar/rootfs
    // source (which never pulls from a registry). Reject it fail-closed at this single choke
    // point so the CLI, the apply manifest, and a direct API call all get the same rule — a
    // misplaced secret ref is a clear 400, never silently ignored (parity with
    // `compute set --pull-secret`).
    if request.spec.pull_secret.is_some()
        && !matches!(
            request.spec.root,
            boatramp_core::compute::RootSource::Image(_)
        )
    {
        return (
            StatusCode::BAD_REQUEST,
            "pull_secret applies only to an image() workload (a tar/rootfs source never \
             pulls from a registry)\n",
        )
            .into_response();
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
                    .into_response();
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

/// Reject a `{db}` path param that is not a safe URL path segment, short-circuiting the
/// handler before any lookup. The name arrives already percent-decoded by axum's `Path`
/// extractor, so a smuggled `%2F` is caught as a literal `/`. Routes through the one
/// canonical [`validate_resource_name`](boatramp_core::project::validate_resource_name)
/// (`kind = "database"`) so the accept/reject rule matches config load, the CLI `--db`,
/// and the handler lookup. `None` = the name is fine. Returns **`422`** — a well-formed
/// request carrying a semantically-invalid resource identifier — to match the other
/// resource-name path-param rejections (`reject_invalid_name`), so the "one spec" surfaces
/// as one status code across every resource-identifier ingress.
fn reject_invalid_db(db: &str) -> Option<Response> {
    boatramp_core::project::validate_resource_name("database", db)
        .err()
        .map(|err| {
            // The empty name is the common v0.5.0 upgrade snag (the legacy default was
            // keyed by `""`), so its 422 body carries a one-line cure pointing at the
            // new `default` name; any other invalid name carries the v0.7.0 slug cure
            // pointing at `project doctor`.
            let body = if db.is_empty() {
                format!("{err}; {}\n", boatramp_core::project::EMPTY_DB_NAME_CURE)
            } else {
                format!("{err}; {}\n", boatramp_core::project::INVALID_NAME_CURE)
            };
            (StatusCode::UNPROCESSABLE_ENTITY, body).into_response()
        })
}

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
    if let Some(bad) = reject_invalid_db(&db) {
        return bad;
    }
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
    if let Some(bad) = reject_invalid_db(&db) {
        return bad;
    }
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
    if let Some(bad) = reject_invalid_db(&db) {
        return bad;
    }
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
// Owner-gated schema migrations (`/api/migrate/{db}/{apply,dry-run,baseline,status}`)
// ---------------------------------------------------------------------------
//
// Input is **upload-then-trigger** (content-addressed): the ordered step set is a JSON bundle
// uploaded via the existing `PUT /api/blobs/{hash}`, then apply/dry-run/baseline reference it by
// hash. The host reads the blob, parses the manifest, and drives the server-side orchestrator
// (`crate::migrate`). A step is a `function` (the base — a project function doing arbitrary work,
// DDL via the owner-role `migrate-ddl` capability), `sql` sugar (a DDL script run as the owner
// role), or `extension` sugar (an allowlisted `CREATE EXTENSION`).

/// One migration step in the uploaded JSON bundle. Exactly one of `function` / `sql` / `extension`
/// must be set. `function` names a project function (+ optional pinned `version` and opaque `args`
/// string passed as the invoke body); `sql` is a DDL/DML script (rejected if it contains
/// `CREATE EXTENSION`), `no_transaction` applying it outside the wrapping transaction (for
/// `CREATE INDEX CONCURRENTLY`-class DDL); `extension` enables an allowlisted extension by name.
#[derive(Deserialize)]
pub(super) struct MigrateStepInput {
    pub id: String,
    #[serde(default)]
    pub function: Option<FunctionStepInput>,
    #[serde(default)]
    pub sql: Option<String>,
    #[serde(default)]
    pub no_transaction: bool,
    #[serde(default)]
    pub extension: Option<String>,
}

/// A `function` step's reference: the project function name, an optional pinned component `version`
/// (defaults to the function's active version), and an opaque `args` string handed to the function
/// as the invoke request body.
#[derive(Deserialize)]
pub(super) struct FunctionStepInput {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub args: Option<String>,
}

/// The uploaded bundle manifest (the blob body): the ordered step set. A hand-authored and a
/// CLI-generated bundle serialize identically (JSON, stable field set), so they hash-agree (U1).
#[derive(Deserialize)]
pub(super) struct BundleManifest {
    pub steps: Vec<MigrateStepInput>,
}

/// The body of `POST /api/migrate/{db}/{apply,dry-run,baseline}` — a reference to the uploaded,
/// content-addressed bundle by hash, plus (baseline only) the inclusive boundary id `up_to`.
#[derive(Deserialize)]
pub(super) struct MigrateTriggerRequest {
    /// The content hash of the uploaded step-set bundle (`PUT /api/blobs/{hash}`).
    pub bundle: String,
    /// Baseline only: record the prefix through (and including) this id. Unset ⇒ the whole set.
    #[serde(default)]
    pub up_to: Option<String>,
}

/// Which migrate verb to run (ungated so the axum handlers stay uniform across feature sets).
enum MigrateModeArg {
    Apply,
    DryRun,
    Baseline { up_to: Option<String> },
}

/// Convert a wire step to the core [`MigrationStep`](boatramp_core::sql::MigrationStep), or a
/// per-step error string (malformed step — not exactly one of function/sql/extension).
fn to_migration_step(
    s: MigrateStepInput,
) -> Result<boatramp_core::sql::MigrationStep, (String, String)> {
    use boatramp_core::sql::{MigrationAction, MigrationStep};
    let action = match (s.function, s.sql, s.extension) {
        (Some(f), None, None) => MigrationAction::Function {
            name: f.name,
            version: f.version,
            args: f.args,
        },
        (None, Some(script), None) => MigrationAction::Sql {
            script,
            no_transaction: s.no_transaction,
        },
        (None, None, Some(name)) => MigrationAction::Extension { name },
        (None, None, None) => {
            return Err((
                s.id,
                "step has none of `function` / `sql` / `extension`".to_string(),
            ));
        }
        _ => {
            return Err((
                s.id,
                "step sets more than one of `function` / `sql` / `extension` (set exactly one)"
                    .to_string(),
            ));
        }
    };
    Ok(MigrationStep { id: s.id, action })
}

/// Parse an uploaded bundle blob into the ordered step set.
fn parse_bundle(bytes: &[u8]) -> Result<Vec<boatramp_core::sql::MigrationStep>, String> {
    let manifest: BundleManifest =
        serde_json::from_slice(bytes).map_err(|e| format!("bundle is not valid JSON: {e}"))?;
    if manifest.steps.is_empty() {
        return Err("bundle has no steps".to_string());
    }
    let mut out = Vec::with_capacity(manifest.steps.len());
    for s in manifest.steps {
        out.push(to_migration_step(s).map_err(|(id, e)| format!("step {id:?}: {e}"))?);
    }
    Ok(out)
}

/// The `501` a migrate route returns when no managed database is configured (no substrate).
fn migrate_unavailable() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "schema migrations are not available on this node (no managed database configured)\n",
    )
        .into_response()
}

/// Read + parse the bundle, then drive the server-side orchestrator (needs the handler runtime for
/// `function` steps). `handlers`-gated; a lean build returns `501`.
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
async fn run_migrate_bundle(
    handlers: &HandlerRuntime,
    substrate: Option<Arc<dyn boatramp_core::sql::MigrationSubstrate>>,
    deploy: &DeployStore,
    project: &str,
    db: &str,
    bundle_hash: &str,
    mode: MigrateModeArg,
) -> Response {
    let Some(substrate) = substrate else {
        return migrate_unavailable();
    };
    let bytes = match crate::handler_dispatch::read_blob_fully(deploy, bundle_hash).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let steps = match parse_bundle(&bytes) {
        Ok(s) => s,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid migration bundle: {msg}\n"),
            )
                .into_response();
        }
    };
    let core_mode = match mode {
        MigrateModeArg::Apply => crate::migrate::MigrateMode::Apply,
        MigrateModeArg::DryRun => crate::migrate::MigrateMode::DryRun,
        MigrateModeArg::Baseline { up_to } => crate::migrate::MigrateMode::Baseline { up_to },
    };
    let inner = handlers.inner.as_ref().map(std::convert::AsRef::as_ref);
    match crate::migrate::orchestrate(inner, deploy, &substrate, project, db, &steps, core_mode)
        .await
    {
        Ok(report) => migration_report_response(report),
        Err(e) => migration_error_response(e),
    }
}

#[cfg(not(feature = "handlers"))]
#[allow(clippy::too_many_arguments)]
async fn run_migrate_bundle(
    _handlers: &HandlerRuntime,
    _substrate: Option<Arc<dyn boatramp_core::sql::MigrationSubstrate>>,
    _deploy: &DeployStore,
    _project: &str,
    _db: &str,
    _bundle_hash: &str,
    _mode: MigrateModeArg,
) -> Response {
    migrate_unavailable()
}

/// Map a [`MigrationError`](boatramp_core::sql::MigrationError) to an HTTP response — reserving
/// non-2xx status codes for "couldn't attempt correctly" (a step that RAN but failed comes back
/// as a `200`/`422` report body instead, via [`migration_report_response`]).
fn migration_error_response(e: boatramp_core::sql::MigrationError) -> Response {
    use boatramp_core::sql::MigrationError as E;
    match e {
        E::NotConfigured => (
            StatusCode::NOT_IMPLEMENTED,
            "schema migrations are not available on this node (no managed database configured)\n"
                .to_string(),
        )
            .into_response(),
        // A managed DB still starting — retryable, mirrors the v0.4.19 readiness gate.
        E::Unavailable(m) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(axum::http::header::RETRY_AFTER, "1")],
            format!("managed database not ready: {m}\n"),
        )
            .into_response(),
        // The requested set is inconsistent with the recorded ledger — a conflict.
        E::PrefixDivergence(m) => (
            StatusCode::CONFLICT,
            format!("migration set diverged from the ledger: {m}\n"),
        )
            .into_response(),
        E::ContentChanged(id) => (
            StatusCode::CONFLICT,
            format!("migration {id:?} was modified after it was applied\n"),
        )
            .into_response(),
        E::RawCreateExtension => (
            StatusCode::BAD_REQUEST,
            "a sql migration step may not CREATE EXTENSION — use an extension step\n".to_string(),
        )
            .into_response(),
        E::ExtensionNotAllowed(name) => (
            StatusCode::BAD_REQUEST,
            format!("extension {name:?} is not on the operator trusted-extension allowlist\n"),
        )
            .into_response(),
        E::Sql(inner) => {
            let inner = inner.to_string();
            (
                StatusCode::BAD_REQUEST,
                format!("migration failed: {inner}{}\n", repair_cure_hint(&inner)),
            )
                .into_response()
        }
        E::Other(m) => (
            StatusCode::BAD_REQUEST,
            format!("migration error: {m}{}\n", repair_cure_hint(&m)),
        )
            .into_response(),
    }
}

/// A "the error carries its cure" hint (house style, per `EMPTY_DB_NAME_CURE`): a permission-denied
/// migration failure on a Shared managed tenant is the classic pre-v0.4.25 owner-model drift — the
/// db is owned by the runtime role, there is no owner role, so the owner-role migrate connection is
/// denied. Point the operator straight at the fix (`boatramp project repair --db <name> --dry-run`).
/// Returns a leading `; try: …` fragment when the message looks like a permission/ownership refusal,
/// else empty (so a plain syntax error isn't cluttered).
fn repair_cure_hint(msg: &str) -> String {
    let lower = msg.to_ascii_lowercase();
    let looks_like_permission = lower.contains("permission denied")
        || lower.contains("must be owner")
        || lower.contains("must be member")
        || (lower.contains("owner") && lower.contains("denied"));
    if looks_like_permission {
        "; try: boatramp project repair --db <name> --dry-run \
         (fixes provisioning so migrate can run; never touches schema or data)"
            .to_string()
    } else {
        String::new()
    }
}

/// Turn a [`MigrationReport`](boatramp_core::sql::MigrationReport) into a response: `200` when no
/// step failed, `422` when one did (the body carries the structured report either way, so a thin
/// client can always parse `failed{id,error}` AND branch on the status).
fn migration_report_response(report: boatramp_core::sql::MigrationReport) -> Response {
    let status = if report.failed.is_some() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    (status, Json(report)).into_response()
}

/// Apply the pending suffix of the uploaded bundle to managed database `db`, running each step
/// as the project's non-superuser OWNER role (a `function` step via the invoke kernel + owner-role
/// `migrate-ddl`), tracked in the host-owned ledger. `Project·Admin`.
pub(super) async fn migrate_apply(
    State(deploy): State<DeployStore>,
    Extension(project): Extension<ProjectContext>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(substrate): Extension<Option<Arc<dyn boatramp_core::sql::MigrationSubstrate>>>,
    Path(db): Path<String>,
    Json(req): Json<MigrateTriggerRequest>,
) -> Response {
    if let Some(bad) = reject_invalid_db(&db) {
        return bad;
    }
    run_migrate_bundle(
        &handlers,
        substrate,
        &deploy,
        project.as_ref().as_str(),
        &db,
        &req.bundle,
        MigrateModeArg::Apply,
    )
    .await
}

/// Compute the migration plan (which ids WOULD apply) without applying anything. `Project·Admin`.
pub(super) async fn migrate_dry_run(
    State(deploy): State<DeployStore>,
    Extension(project): Extension<ProjectContext>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(substrate): Extension<Option<Arc<dyn boatramp_core::sql::MigrationSubstrate>>>,
    Path(db): Path<String>,
    Json(req): Json<MigrateTriggerRequest>,
) -> Response {
    if let Some(bad) = reject_invalid_db(&db) {
        return bad;
    }
    run_migrate_bundle(
        &handlers,
        substrate,
        &deploy,
        project.as_ref().as_str(),
        &db,
        &req.bundle,
        MigrateModeArg::DryRun,
    )
    .await
}

/// Record the bundle prefix through `up_to` as already-applied WITHOUT running any step — the
/// owner-assertion adoption op for a pre-existing/populated DB (#480). `Project·Admin`, audited,
/// prefix-consistent (an empty ledger or a strict consistent extension; divergence → `409`).
pub(super) async fn migrate_baseline(
    State(deploy): State<DeployStore>,
    Extension(project): Extension<ProjectContext>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(substrate): Extension<Option<Arc<dyn boatramp_core::sql::MigrationSubstrate>>>,
    Path(db): Path<String>,
    Json(req): Json<MigrateTriggerRequest>,
) -> Response {
    if let Some(bad) = reject_invalid_db(&db) {
        return bad;
    }
    run_migrate_bundle(
        &handlers,
        substrate,
        &deploy,
        project.as_ref().as_str(),
        &db,
        &req.bundle,
        MigrateModeArg::Baseline { up_to: req.up_to },
    )
    .await
}

/// Read the applied-migration ledger for managed database `db`. `Project·Read`. Needs only the
/// substrate (no invoke kernel), so it is uniform across feature sets.
pub(super) async fn migrate_status(
    Extension(project): Extension<ProjectContext>,
    Extension(substrate): Extension<Option<Arc<dyn boatramp_core::sql::MigrationSubstrate>>>,
    Path(db): Path<String>,
) -> Response {
    if let Some(bad) = reject_invalid_db(&db) {
        return bad;
    }
    let Some(substrate) = substrate else {
        return migrate_unavailable();
    };
    match substrate.preflight(project.as_ref().as_str(), &db).await {
        Ok(applied) => (
            StatusCode::OK,
            Json(boatramp_core::sql::MigrationStatus { applied }),
        )
            .into_response(),
        Err(e) => migration_error_response(e),
    }
}

// ---------------------------------------------------------------------------
// Owner-gated provisioning drift-repair (`/api/repair/{db}` + `/api/repair/{db}/dry-run`)
// ---------------------------------------------------------------------------
//
// Repair converges a shared managed tenant's provisioning against spec (the owner-model retrofit:
// create/seal the owner role, re-own the db + objects + ledger to it) — idempotent, data-preserving.
// `POST /api/repair/{db}` applies; `POST /api/repair/{db}/dry-run` reports only (the default posture
// the CLI uses). BOTH are `Project·Admin`-gated (see `authz::Right::required`; NOT under `/api/sql/`,
// whose catch-all a publisher satisfies), audited, and carry the `{db}` path through the same
// `reject_invalid_db` 422 screen the sql/migrate routes use.

/// The `501` a repair route returns when no managed database is configured (no repair capability).
fn repair_unavailable() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "provisioning drift-repair is not available on this node (no managed database configured)\n",
    )
        .into_response()
}

/// Map a [`RepairError`](boatramp_core::sql::RepairError) to an HTTP response — reserving non-2xx for
/// "couldn't produce a report at all"; a run that produced a report (even with errored checks) comes
/// back `200`/`422` via [`repair_report_response`].
fn repair_error_response(e: boatramp_core::sql::RepairError) -> Response {
    use boatramp_core::sql::RepairError as E;
    match e {
        E::NotConfigured => repair_unavailable(),
        E::Unavailable(m) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(axum::http::header::RETRY_AFTER, "1")],
            format!("managed database not ready: {m}\n"),
        )
            .into_response(),
        E::Other(m) => (StatusCode::BAD_REQUEST, format!("repair error: {m}\n")).into_response(),
    }
}

/// Turn a [`RepairReport`](boatramp_core::sql::RepairReport) into a response: `200` when no check
/// errored, `422` when one did (the structured report rides in the body either way, so a thin client
/// can always parse the per-check verdicts AND branch on the status — mirrors
/// [`migration_report_response`]).
fn repair_report_response(report: boatramp_core::sql::RepairReport) -> Response {
    let status = if report.any_error() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    (status, Json(report)).into_response()
}

/// Defense-in-depth (Backend §4 / Security HIGH-1): re-derive the right the authoritative table
/// requires for THIS repair request and assert it is `Project·Admin` before running any privileged
/// DDL. The auth middleware already enforced it; this is a second, independent check inside the
/// handler so a future routing/table regression can't silently downgrade the gate. Reconstructs the
/// canonical repair path from the resolved `ProjectContext` (default → the global form, else the
/// project-scoped form), so it holds for both request shapes. Returns `Some(403)` if — against
/// expectation — the required right is not Admin.
fn assert_repair_is_admin(project: &str) -> Option<Response> {
    use boatramp_core::authz::{Action, Right};
    // A representative repair path for this project (the `{db}` segment is irrelevant to the arm).
    let path = if project == boatramp_core::project::DEFAULT_PROJECT {
        "/api/repair/_/dry-run".to_string()
    } else {
        format!("/api/projects/{project}/repair/_/dry-run")
    };
    match Right::required("POST", &path) {
        Some(right) if right.action == Action::Admin => None,
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                "provisioning repair requires Project·Admin\n",
            )
                .into_response(),
        ),
    }
}

/// Drive a repair `mode` over managed database `db` (shared body of the apply + dry-run handlers).
async fn run_repair(
    repair: Option<Arc<dyn boatramp_core::sql::TenantRepair>>,
    project: &str,
    db: &str,
    mode: boatramp_core::sql::RepairMode,
) -> Response {
    if let Some(bad) = reject_invalid_db(db) {
        return bad;
    }
    if let Some(forbidden) = assert_repair_is_admin(project) {
        return forbidden;
    }
    let Some(repair) = repair else {
        return repair_unavailable();
    };
    match repair.repair(project, db, mode).await {
        Ok(report) => repair_report_response(report),
        Err(e) => repair_error_response(e),
    }
}

/// Converge managed database `db`'s provisioning against spec (`POST /api/repair/{db}`). The
/// mutating verb — creates/seals the owner role, re-owns the db + objects + ledger. `Project·Admin`,
/// audited. Never touches schema or data (only roles/ownership/grants/credentials/scaffolding).
pub(super) async fn repair_apply(
    Extension(project): Extension<ProjectContext>,
    Extension(repair): Extension<Option<Arc<dyn boatramp_core::sql::TenantRepair>>>,
    Path(db): Path<String>,
) -> Response {
    run_repair(
        repair,
        project.as_ref().as_str(),
        &db,
        boatramp_core::sql::RepairMode::Apply,
    )
    .await
}

/// Report the provisioning drift of managed database `db` WITHOUT converging anything
/// (`POST /api/repair/{db}/dry-run`) — the default posture. Provably side-effect-free (read-only
/// probes; no DDL, no KV write). `Project·Admin`.
pub(super) async fn repair_dry_run(
    Extension(project): Extension<ProjectContext>,
    Extension(repair): Extension<Option<Arc<dyn boatramp_core::sql::TenantRepair>>>,
    Path(db): Path<String>,
) -> Response {
    run_repair(
        repair,
        project.as_ref().as_str(),
        &db,
        boatramp_core::sql::RepairMode::DryRun,
    )
    .await
}

// ---------------------------------------------------------------------------
// Declarative managed-database front door (`PUT /api/projects/{proj}/databases/{name}`
// + `POST …/ensure`, GET reads) — v0.6.0, #501 Stage B.
// ---------------------------------------------------------------------------

/// Map a [`DeclareError`](boatramp_core::sql::DeclareError) to an HTTP response. The
/// structured reason rides in the body; the status distinguishes the security refusals
/// (`409` daemon-conflict / identity-change / not-yet-provisioned) from a per-project
/// quota refusal (`422`), a missing declaration (`404`), an unavailable capability
/// (`501`), and a generic bad request (`400`).
fn declare_error_response(err: boatramp_core::sql::DeclareError) -> Response {
    use boatramp_core::sql::DeclareError as E;
    let status = match &err {
        E::NotConfigured => StatusCode::NOT_IMPLEMENTED,
        E::DaemonConflict(_) | E::IdentityChange { .. } | E::NotProvisioned(_) => {
            StatusCode::CONFLICT
        }
        E::QuotaExceeded { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        E::NotDeclared(_) => StatusCode::NOT_FOUND,
        E::Other(_) => StatusCode::BAD_REQUEST,
    };
    (status, format!("{err}\n")).into_response()
}

/// The `501` when the node wired no [`ManagedDbDeclare`] capability (no managed SQL engine
/// / no `[secrets]` envelope), mirroring [`repair_unavailable`].
fn declare_unavailable() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "managed database declaration is not available on this node (no managed SQL engine \
         / no [secrets] envelope configured)\n",
    )
        .into_response()
}

/// Defense-in-depth (the `/api/repair` escalation lesson, Security HIGH-1): re-derive the
/// right the authoritative table requires for a `databases` DECLARE (a `PUT`) on THIS
/// project and assert it is `Project·Admin` before touching the privileged
/// declare/provision path. The auth middleware already enforced it; this is a second,
/// independent check inside the handler so a future routing/table regression can't
/// silently downgrade the gate below the migrate/repair-grade owner right. Reconstructs
/// the canonical path from the resolved `ProjectContext` (default → the global form, else
/// the project-scoped form). Returns `Some(403)` if — against expectation — the required
/// right is not Admin.
fn assert_databases_is_admin(project: &str) -> Option<Response> {
    use boatramp_core::authz::{Action, Right};
    let path = if project == boatramp_core::project::DEFAULT_PROJECT {
        "/api/databases/_".to_string()
    } else {
        format!("/api/projects/{project}/databases/_")
    };
    match Right::required("PUT", &path) {
        Some(right) if right.action == Action::Admin => None,
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                "declaring a managed database requires Project·Admin\n",
            )
                .into_response(),
        ),
    }
}

/// `PUT /api/projects/{proj}/databases/{name}` — declare (persist + eagerly provision) a
/// managed database from a manifest `databases:` entry (the typed
/// [`ApplyDatabase`](boatramp_core::compute::ApplyDatabase) body). `Project·Admin`
/// (it mints owner-role identities — the migrate/repair-grade gate). Enforces
/// daemon-config-wins, identity-change refusal, and caller's-project binding server-side.
pub(super) async fn declare_database(
    Extension(project): Extension<ProjectContext>,
    Extension(declare): Extension<Option<Arc<dyn boatramp_core::sql::ManagedDbDeclare>>>,
    Path(name): Path<String>,
    Json(db): Json<boatramp_core::compute::ApplyDatabase>,
) -> Response {
    if let Some(bad) = reject_invalid_db(&name) {
        return bad;
    }
    if let Some(forbidden) = assert_databases_is_admin(project.as_ref().as_str()) {
        return forbidden;
    }
    let Some(declare) = declare else {
        return declare_unavailable();
    };
    match declare.declare(project.as_ref().as_str(), &name, &db).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => declare_error_response(e),
    }
}

/// `POST /api/projects/{proj}/databases/{name}/ensure` — re-provision an ALREADY-declared
/// managed database idempotently (the eager-provision hook). `Project·Admin`.
pub(super) async fn ensure_database(
    Extension(project): Extension<ProjectContext>,
    Extension(declare): Extension<Option<Arc<dyn boatramp_core::sql::ManagedDbDeclare>>>,
    Path(name): Path<String>,
) -> Response {
    if let Some(bad) = reject_invalid_db(&name) {
        return bad;
    }
    if let Some(forbidden) = assert_databases_is_admin(project.as_ref().as_str()) {
        return forbidden;
    }
    let Some(declare) = declare else {
        return declare_unavailable();
    };
    match declare.ensure(project.as_ref().as_str(), &name).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => declare_error_response(e),
    }
}

/// `POST /api/projects/{proj}/databases/{name}/restart` — restart a managed database:
/// stop its workload's currently-running replica(s) so the reconcile loop relaunches it,
/// applying any restart-requiring config change staged on the declaration in the
/// process (e.g. a flipped `delta_capture`). `Project·Admin` (the same owner-grade gate
/// as declare/ensure — it drives the same privileged provisioning plane). Backs
/// `boatramp db restart`.
pub(super) async fn restart_database(
    Extension(project): Extension<ProjectContext>,
    Extension(declare): Extension<Option<Arc<dyn boatramp_core::sql::ManagedDbDeclare>>>,
    Path(name): Path<String>,
) -> Response {
    if let Some(bad) = reject_invalid_db(&name) {
        return bad;
    }
    if let Some(forbidden) = assert_databases_is_admin(project.as_ref().as_str()) {
        return forbidden;
    }
    let Some(declare) = declare else {
        return declare_unavailable();
    };
    match declare.restart(project.as_ref().as_str(), &name).await {
        Ok(outcome) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "workload": outcome.workload,
                "config_applied": outcome.config_applied,
                "replicas_restarted": outcome.replicas_restarted,
            })),
        )
            .into_response(),
        Err(e) => declare_error_response(e),
    }
}

/// The optional body of the ensure-user verb.
#[derive(Debug, Default, Deserialize)]
pub(super) struct EnsureUserBody {
    /// An operator-supplied secret ref for the role's password (BYO). Omit to mint + seal
    /// a managed credential (returned once). (BYO is a scoped follow-up today.)
    #[serde(default)]
    pub password_secret: Option<String>,
}

/// `POST /api/projects/{proj}/databases/{db}/users/{user}/ensure` — ensure a locked-down
/// login role on an already-declared managed database, idempotently. `Project·Admin`
/// (same owner-grade gate as declare/ensure, enforced by the middleware AND re-checked
/// here). On the call that MINTS the role's credential the response carries `password`
/// once; a re-ensure returns `created:false` and no password (the sealed secret is never
/// re-surfaced).
pub(super) async fn ensure_user(
    Extension(project): Extension<ProjectContext>,
    Extension(declare): Extension<Option<Arc<dyn boatramp_core::sql::ManagedDbDeclare>>>,
    Path((db, user)): Path<(String, String)>,
    body: Option<Json<EnsureUserBody>>,
) -> Response {
    if let Some(bad) = reject_invalid_db(&db) {
        return bad;
    }
    if let Some(bad) = reject_invalid_db(&user) {
        return bad;
    }
    if let Some(forbidden) = assert_databases_is_admin(project.as_ref().as_str()) {
        return forbidden;
    }
    let Some(declare) = declare else {
        return declare_unavailable();
    };
    let secret = body.and_then(|b| b.0.password_secret);
    match declare
        .ensure_user(project.as_ref().as_str(), &db, &user, secret.as_deref())
        .await
    {
        Ok(outcome) => {
            let mut resp = serde_json::json!({
                "user": user,
                "database": db,
                "created": outcome.created,
                // The actual cluster principal to connect as (per-tenant-qualified on Shared).
                "role_name": outcome.role_name,
            });
            // Return-once: the minted password appears ONLY on the creating call.
            if let Some(pw) = outcome.password {
                resp["password"] = serde_json::Value::String(pw);
            }
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => declare_error_response(e),
    }
}

/// `DELETE /api/projects/{proj}/databases/{db}/users/{user}` — drop a login role from an
/// already-declared managed database, idempotently. `Project·Admin`. Drops the DERIVED
/// per-tenant role (never an operator-supplied raw name), reassigns/drops what it owns,
/// and deletes its sealed credential. Dropping an absent role is a clean no-op.
pub(super) async fn drop_user(
    Extension(project): Extension<ProjectContext>,
    Extension(declare): Extension<Option<Arc<dyn boatramp_core::sql::ManagedDbDeclare>>>,
    Path((db, user)): Path<(String, String)>,
) -> Response {
    if let Some(bad) = reject_invalid_db(&db) {
        return bad;
    }
    if let Some(bad) = reject_invalid_db(&user) {
        return bad;
    }
    if let Some(forbidden) = assert_databases_is_admin(project.as_ref().as_str()) {
        return forbidden;
    }
    let Some(declare) = declare else {
        return declare_unavailable();
    };
    match declare
        .drop_user(project.as_ref().as_str(), &db, &user)
        .await
    {
        Ok(outcome) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "user": user,
                "database": db,
                "existed": outcome.existed,
                "role_name": outcome.role_name,
            })),
        )
            .into_response(),
        Err(e) => declare_error_response(e),
    }
}

/// `GET /api/projects/{proj}/databases` — list the project's declared managed databases
/// (read-only; `Project·Read`). Each is the stored typed
/// [`ApplyDatabase`](boatramp_core::compute::ApplyDatabase).
pub(super) async fn list_databases(
    State(deploy): State<DeployStore>,
    Extension(project): Extension<ProjectContext>,
) -> Response {
    match deploy.list_project_databases(project.as_ref()).await {
        Ok(dbs) => Json(dbs).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `GET /api/projects/{proj}/databases/{name}` — the one declared managed database, or
/// `404` if the project declared none by that name (read-only; `Project·Read`).
pub(super) async fn get_database(
    State(deploy): State<DeployStore>,
    Extension(project): Extension<ProjectContext>,
    Path(name): Path<String>,
) -> Response {
    if let Some(bad) = reject_invalid_db(&name) {
        return bad;
    }
    match deploy.get_project_database(project.as_ref(), &name).await {
        Ok(Some(db)) => Json(db).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            format!("no declared managed database {name:?} in this project\n"),
        )
            .into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `GET /api/projects/{proj}/databases/{name}/status` — a read-only status view of a
/// declared managed database: the stored declaration plus whether it is registered as a
/// compute workload yet (a coarse "provisioned" signal for `boatramp db status`), and
/// whether a restart-requiring config change is staged but not yet applied
/// (`pending_restart`, PLAN-sql-true-delta Stage 1b — e.g. a flipped `delta_capture`
/// under `restart_policy: manual`). `Project·Read`. Never returns a secret.
pub(super) async fn database_status(
    State(deploy): State<DeployStore>,
    Extension(project): Extension<ProjectContext>,
    Extension(declare): Extension<Option<Arc<dyn boatramp_core::sql::ManagedDbDeclare>>>,
    Path(name): Path<String>,
) -> Response {
    if let Some(bad) = reject_invalid_db(&name) {
        return bad;
    }
    let db = match deploy.get_project_database(project.as_ref(), &name).await {
        Ok(Some(db)) => db,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                format!("no declared managed database {name:?} in this project\n"),
            )
                .into_response();
        }
        Err(err) => return deploy_error_response(err),
    };
    // The derived per-project server workload name (same derivation as the declare path,
    // `bramp-db-<project>-<name>`) — the operator-visible handle for the managed server.
    // A read-only view: it reports the DECLARATION only, never a secret. Where the
    // workload is registered (default project for `Shared`, the caller's project for a
    // `Single` tenant) varies by isolation, so the coarse "declared" fact is what a status
    // view honestly asserts.
    let workload = format!("bramp-db-{}-{}", project.as_ref().as_str(), name);
    // Surface the workload's live readiness (distinct from the bare declaration): read its
    // replica states and reduce them to a single honest signal. This is what lets an
    // operator see "declared but not yet ready to migrate" vs "ready", and turns a
    // can't-serve-but-looks-running container (e.g. a data-dir-ownership failure) into a
    // visible `provision_failed` instead of a silent healthy. A workload registered under
    // a different scope (a `Shared` server lives in the default project) or not yet
    // launched has no replicas here → `pending` (honest: this view doesn't track it).
    let states = deploy
        .list_replica_states(project.as_ref(), &workload)
        .await
        .unwrap_or_default();
    let readiness = summarize_readiness(&states);
    // `pending_restart`: whether the current declaration would re-mint a different
    // content-addressed spec than what is actually active (PLAN-sql-true-delta Stage
    // 1b) — `false` (never an error) if no restart capability is wired, the database
    // isn't provisioned yet, or its tenancy is out of the restart primitive's scope.
    let pending_restart = match &declare {
        Some(cap) => cap
            .restart_pending(project.as_ref().as_str(), &name)
            .await
            .unwrap_or(false),
        None => false,
    };
    let mut body = serde_json::json!({
        "database": db,
        "workload": workload,
        "declared": true,
        "readiness": readiness,
        "pending_restart": pending_restart,
    });
    // Surface the data-dir-ownership health signal when a replica recorded one: a
    // filesystem-level fault (foreign-owned files the rootless DB can't read) that leaves a
    // replica stuck `starting`, which `/api/repair` does NOT cover (it reconciles only
    // in-pg drift). Omitted entirely when nothing was observed, so a healthy status view
    // stays unchanged.
    if let Some(data_dir) = summarize_data_dir(&states) {
        body["data_dir"] = data_dir;
    }
    Json(body).into_response()
}

/// Reduce a managed workload's replica states to one readiness signal for `db status`.
/// Most-informative-wins so an operator sees the actionable state: a `provision_failed`
/// (with its reason) is surfaced over a sibling that is merely `starting`; `provisioned`
/// means at least one replica is usable. No replicas ⇒ `pending` (not launched, or
/// registered under another scope this view does not track).
fn summarize_readiness(states: &[boatramp_core::compute::ObservedInstance]) -> serde_json::Value {
    use boatramp_core::compute::{Readiness, ReplicaPhase};
    let running: Vec<&Readiness> = states
        .iter()
        .filter(|s| s.phase == ReplicaPhase::Running)
        .map(|s| &s.readiness)
        .collect();
    if running.is_empty() {
        return serde_json::json!({ "state": "pending" });
    }
    if let Some(reason) = running.iter().find_map(|r| match r {
        Readiness::ProvisionFailed { reason } => Some(reason.clone()),
        _ => None,
    }) {
        return serde_json::json!({ "state": "provision_failed", "reason": reason });
    }
    if running.iter().any(|r| r.is_provisioned()) {
        return serde_json::json!({ "state": "provisioned" });
    }
    if running.iter().any(|r| r.is_service_ready()) {
        return serde_json::json!({ "state": "service_ready" });
    }
    serde_json::json!({ "state": "starting" })
}

/// Surface the most actionable data-dir-ownership observation across a managed workload's
/// running replicas for `db status`: a detected **fault** (`ok == false`, naming the
/// volume + a sample foreign entry) wins over a clean check, which wins over no
/// observation at all. This is the signal `/api/repair` can't give — it reconciles in-pg
/// drift (roles/ownership/grants), never filesystem permissions. `None` when no running
/// replica recorded one (not in the diagnostic window, or a backend with no on-node data
/// directory) — so the field is simply absent from a status view with nothing to report.
fn summarize_data_dir(
    states: &[boatramp_core::compute::ObservedInstance],
) -> Option<serde_json::Value> {
    use boatramp_core::compute::ReplicaPhase;
    let mut clean: Option<&boatramp_core::compute::DataDirOwnership> = None;
    for s in states.iter().filter(|s| s.phase == ReplicaPhase::Running) {
        if let Some(dd) = &s.data_dir {
            if !dd.ok {
                return serde_json::to_value(dd).ok();
            }
            clean.get_or_insert(dd);
        }
    }
    clean.and_then(|dd| serde_json::to_value(dd).ok())
}

// ---------------------------------------------------------------------------
// Operator S3 upload-credential minting (`POST /api/blob-mint-upload`) — M3
// ---------------------------------------------------------------------------

/// The body of `POST /api/blob-mint-upload` (PLAN-blob-s3-ingress §6). Project is HOST-forced from the
/// token's project context (never in the body); the operator names the site + container + the target
/// (exactly one of key/prefix) + perms + constraints + ttl. The TTL + max-bytes are clamped to the
/// operator ceilings server-side (the operator can only request a shorter/smaller bound).
#[cfg(feature = "blob-upload")]
#[derive(Debug, Deserialize)]
pub(super) struct MintUploadRequest {
    /// The site the container belongs to (host-forced project + this site scope the credential).
    pub site: String,
    /// The blob container to mint an upload credential for.
    pub container: String,
    /// The single object key the credential is bound to (mutually exclusive with `prefix`).
    #[serde(default)]
    pub key: Option<String>,
    /// The key prefix the credential is bound to (mutually exclusive with `key`).
    #[serde(default)]
    pub prefix: Option<String>,
    /// The permitted operations (`put` / `multipart`). Empty ⇒ write-only (single-shot).
    #[serde(default)]
    pub perms: Vec<String>,
    /// Requested max object size in bytes (clamped down to the operator ceiling).
    #[serde(default)]
    pub max_bytes: Option<u64>,
    /// Required Content-Type (exact or a `type/*` family).
    #[serde(default)]
    pub content_type: Option<String>,
    /// Require the object key to equal `sha256(bytes)` (content-addressing).
    #[serde(default)]
    pub require_sha256: bool,
    /// Refuse to overwrite an existing key (create-only).
    #[serde(default)]
    pub create_only: bool,
    /// Requested lifetime in seconds (clamped to the operator ceiling).
    pub ttl_seconds: u64,
}

/// The JSON response of `POST /api/blob-mint-upload`: a self-describing credential, `kind` selecting
/// the shape. `presigned_put` carries `url`/`method`/`required_headers`; `temp_credentials` carries
/// the STS-style fields + the enforced/advisory contract. Unset fields for the other shape are omitted.
#[cfg(feature = "blob-upload")]
#[derive(Debug, Serialize)]
pub(super) struct MintUploadResponse {
    /// `"presigned_put"` or `"temp_credentials"`.
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required_headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_path_style: Option<bool>,
    pub expires_at: u64,
    pub expires_in_secs: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub enforced: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub advisory: Vec<String>,
}

/// Mint a scoped, short-lived S3 upload credential for a project+site's blob container
/// (`POST /api/blob-mint-upload`, gated `BlobUpload·Write`). Project is HOST-forced from the token
/// context; site + container + shape come from the body. TTL + max-bytes are clamped to the operator
/// ceilings. `501` when the local S3 face / minting is not wired on this node.
#[cfg(feature = "blob-upload")]
pub(super) async fn blob_mint_upload(
    Extension(project): Extension<ProjectContext>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Json(req): Json<MintUploadRequest>,
) -> Response {
    use boatramp_handlers::{
        MintScope, MintedCredentials, UploadConstraints, UploadPerm, UploadTarget,
    };

    // The minter is wired only when the local S3 face + fleet signer are up.
    let Some((minter, max_ttl, max_bytes_ceiling)) = handlers.blob_upload_minter() else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "S3 upload-credential minting is not enabled on this node (no local S3 face wired)\n",
        )
            .into_response();
    };
    // Validate the target: exactly one of key/prefix.
    let target = match (req.key.as_deref(), req.prefix.as_deref()) {
        (Some(k), None) => UploadTarget::Key(k.to_string()),
        (None, Some(p)) => UploadTarget::Prefix(p.to_string()),
        _ => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                "specify exactly one of --key / --prefix\n",
            )
                .into_response();
        }
    };
    if req.site.trim().is_empty() || req.container.trim().is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "both --site and --container are required\n",
        )
            .into_response();
    }
    // SCREEN the container + key|prefix BEFORE any signing / policy build (Security HIGH-1), mirroring
    // the guest binding's mint choke point: reject a traversal, a reserved `.boatramp*` segment, a
    // `*`/`\`/control byte, or a policy metacharacter (`"`/`'`) that could restructure a cloud policy
    // document — the operator route flows into the SAME hand-built policy strings the guest path does.
    if let Err(e) = boatramp_handlers::screen_upload_target(req.container.trim(), &target) {
        let reason = match e {
            boatramp_handlers::MintRefused::InvalidRequest(m) => m,
            other => format!("{other:?}"),
        };
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("invalid mint target: {reason}\n"),
        )
            .into_response();
    }
    if req.ttl_seconds == 0 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "--ttl must be greater than zero\n",
        )
            .into_response();
    }
    // Parse perms (empty ⇒ write-only).
    let mut perms = Vec::new();
    for p in &req.perms {
        match p.as_str() {
            "put" | "write" => perms.push(UploadPerm::Put),
            "multipart" => perms.push(UploadPerm::Multipart),
            other => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("unknown perm `{other}` (expected put|multipart)\n"),
                )
                    .into_response();
            }
        }
    }
    if perms.is_empty() {
        perms.push(UploadPerm::Put);
    }
    // Clamp the TTL + max_bytes to the operator ceilings (the operator can only narrow) — the same
    // clamp the guest binding applies, mirrored here for the operator surface.
    let ttl = req.ttl_seconds.min(max_ttl);
    let clamped_max_bytes = match (req.max_bytes, max_bytes_ceiling) {
        (Some(g), Some(c)) => Some(g.min(c)),
        (Some(g), None) => Some(g),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    };
    let scope = MintScope {
        // Project HOST-forced from the token context; site from the body. The container is validated
        // as a single safe segment at the S3-face key choke point (M2-review MEDIUM-2).
        project: project.as_ref().as_str().to_string(),
        site: req.site.trim().to_string(),
        container: req.container.trim().to_string(),
        target,
        perms,
        constraints: UploadConstraints {
            max_bytes: clamped_max_bytes,
            content_type: req.content_type.clone(),
            require_sha256: req.require_sha256,
            create_only: req.create_only,
        },
        ttl_secs: ttl,
    };
    match minter.mint(&scope).await {
        Ok(MintedCredentials::PresignedPut(p)) => Json(MintUploadResponse {
            kind: "presigned_put",
            url: Some(p.url),
            method: Some(p.method),
            required_headers: p.required_headers,
            access_key_id: None,
            secret: None,
            session_token: None,
            endpoint: None,
            region: None,
            bucket: None,
            force_path_style: None,
            expires_at: p.expires_at,
            expires_in_secs: p.expires_in_secs,
            enforced: Vec::new(),
            advisory: Vec::new(),
        })
        .into_response(),
        Ok(MintedCredentials::TempCredentials(t)) => Json(MintUploadResponse {
            kind: "temp_credentials",
            url: None,
            method: None,
            required_headers: Vec::new(),
            access_key_id: Some(t.access_key_id),
            secret: Some(t.secret),
            session_token: Some(t.session_token),
            endpoint: Some(t.endpoint),
            region: Some(t.region),
            bucket: Some(t.bucket),
            force_path_style: Some(t.force_path_style),
            expires_at: t.expires_at,
            expires_in_secs: t.expires_in_secs,
            enforced: t.enforced,
            advisory: t.advisory,
        })
        .into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("mint failed: {e}\n"),
        )
            .into_response(),
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
            return (StatusCode::BAD_REQUEST, "stdin_b64 is not valid base64\n").into_response();
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
// Dev/CI blob-shim affordance (`POST /api/compute/dev-bind-blob`)
// ---------------------------------------------------------------------------

/// `POST /api/compute/dev-bind-blob` body: bind a NON-managed local process to the
/// blob-shim for one site (a dev/CI test-harness affordance). `site` is the workload/site
/// identity (a managed workload's name stands in for its site); `container` optionally
/// confines the credential to one `--bind blob:<container>`; `project` selects the blob
/// namespace's project (default `"default"`).
#[derive(Debug, Deserialize)]
pub(super) struct DevBindBlobRequest {
    site: String,
    #[serde(default)]
    container: Option<String>,
    #[serde(default)]
    project: Option<String>,
}

/// `POST /api/compute/dev-bind-blob` response: the env the caller exports into the local
/// process — `BOATRAMP_BLOB_URL` + `BOATRAMP_BLOB_URL_AUTH_TOKEN` (the blob analogue of
/// `DATABASE_URL`).
#[derive(Debug, Serialize)]
pub(super) struct DevBindBlobResponse {
    env: Vec<(String, String)>,
}

/// The synthetic replica index a dev bind derives its token under — `u32::MAX`, OUTSIDE
/// the managed-replica index space, so a dev token never collides with a live workload
/// replica's token (even one whose workload name equals `site`).
const DEV_BIND_REPLICA: u32 = u32::MAX;

/// Mint + register a blob-shim credential for a NON-managed local process (dev/CI). Gated
/// `System·Admin` (node-global, `is_compute_maintenance_path`) AND the `allow_dev_blob_bind`
/// posture (off outside `dev`). Reuses the EXACT managed `resolve()` path — the same token
/// derivation + scope resolution + registry insert a `--bind blob` workload gets — so the
/// dev credential is identical in strength + confinement (site-scoped, container-bound when
/// named) to a managed one, just handed to an external process. `501` when the blob-shim is
/// not wired on this node.
pub(super) async fn compute_dev_bind_blob(
    Extension(posture): Extension<boatramp_core::security::SecurityPosture>,
    Extension(resolver): Extension<Option<Arc<dyn boatramp_core::compute::ComputeBindingResolver>>>,
    Json(req): Json<DevBindBlobRequest>,
) -> Response {
    // Defense-in-depth: re-derive that this path is `System·Admin` (node-global), so a
    // routing/table regression cannot silently downgrade a credential-minting endpoint.
    if let Some(forbidden) = assert_project_export_is_system_admin(
        "POST",
        "/api/compute/dev-bind-blob",
        "compute dev-bind-blob",
    ) {
        return forbidden;
    }
    if !posture.allow_dev_blob_bind {
        return (
            StatusCode::FORBIDDEN,
            "compute dev-bind-blob is disabled; set the `allow_dev_blob_bind` posture \
             (BOATRAMP_SECURITY_ALLOW_DEV_BLOB_BIND=true — on by default only in the `dev` \
             profile) to enable it\n",
        )
            .into_response();
    }
    let Some(resolver) = resolver else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "the compute blob-shim is not active on this node (no blob provider or \
             `compute.blob_shim_url` configured)\n",
        )
            .into_response();
    };
    if req.site.is_empty() {
        return (StatusCode::BAD_REQUEST, "site is required\n").into_response();
    }
    let project = req.project.as_deref().unwrap_or("default");
    // Slug-validate everything that flows into the token scope + `hblob/…` storage prefix
    // (mirrors the managed path's `validate_key_segment`/`reject_invalid_name` choke points
    // — a `..`/`/` would traverse). The container, when named, is additionally re-validated
    // inside the resolver's `scope` (fail-closed → empty env → 400 below).
    if let Some(resp) = reject_invalid_name("project", project) {
        return resp;
    }
    if let Some(resp) = reject_invalid_name("site", &req.site) {
        return resp;
    }
    if let Some(c) = req.container.as_deref()
        && let Some(resp) = reject_invalid_name("container", c)
    {
        return resp;
    }
    let binding = boatramp_core::compute::ComputeBinding {
        kind: boatramp_core::compute::BindingKind::Blob,
        name: req.container.unwrap_or_default(),
        url_env: None,
    };
    let env = resolver
        .resolve(
            project,
            &req.site,
            DEV_BIND_REPLICA,
            std::slice::from_ref(&binding),
        )
        .await;
    if env.is_empty() {
        // The resolver produced nothing — the blob binding's scope failed to resolve (an
        // invalid container the resolver rejects). Fail closed, never a silent empty 200.
        return (
            StatusCode::BAD_REQUEST,
            "the blob binding did not resolve (check the container name)\n",
        )
            .into_response();
    }
    (StatusCode::OK, Json(DevBindBlobResponse { env })).into_response()
}

// ---------------------------------------------------------------------------
// Dev/CI messaging-shim affordance (`POST /api/compute/dev-bind-messaging`)
// ---------------------------------------------------------------------------

/// A distinct Extension newtype for the messaging dev-bind resolver, so axum's TYPE-keyed
/// `Extension` layer does not collide with the blob dev-bind's
/// `Extension<Option<Arc<dyn ComputeBindingResolver>>>` (both resolvers are the same trait
/// object type). `None` ⇒ the messaging-shim is inactive on this node.
#[derive(Clone)]
pub(super) struct DevMessagingBind(
    pub(super) Option<Arc<dyn boatramp_core::compute::ComputeBindingResolver>>,
);

/// `POST /api/compute/dev-bind-messaging` body: bind a NON-managed local process to the
/// messaging-shim for one project bus (a dev/CI test-harness affordance). `topic` optionally
/// confines the credential to one `--bind messaging:<topic>`; `project` selects the bus's
/// project (default `"default"`). Unlike the blob bind there is NO `site`: the project bus is
/// project-scoped (`{project}/bus/…`), shared across every site in the project.
#[derive(Debug, Deserialize)]
pub(super) struct DevBindMessagingRequest {
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    project: Option<String>,
}

/// `POST /api/compute/dev-bind-messaging` response: the env the caller exports into the local
/// process — `BOATRAMP_MESSAGING_URL` + `BOATRAMP_MESSAGING_URL_AUTH_TOKEN` (the messaging
/// analogue of `DATABASE_URL`).
#[derive(Debug, Serialize)]
pub(super) struct DevBindMessagingResponse {
    env: Vec<(String, String)>,
}

/// A synthetic workload name a dev messaging bind derives its token under. The project bus is
/// project-scoped, so the workload does not enter the resolved keyspace (unlike the blob bind,
/// where `site` IS the keyspace); this is only a stable, distinct token-derivation input. Paired
/// with [`DEV_BIND_REPLICA`] (`u32::MAX`), it never collides with a managed replica's token.
const DEV_MESSAGING_WORKLOAD: &str = "_dev-bind-messaging";

/// Mint + register a messaging-shim credential for a NON-managed local process (dev/CI). Gated
/// `System·Admin` (node-global, `is_compute_maintenance_path`) AND the `allow_dev_messaging_bind`
/// posture (off outside `dev`). Reuses the EXACT managed `resolve()` path — the same token
/// derivation + scope resolution + registry insert a `--bind messaging` workload gets — so the
/// dev credential is identical in strength + confinement (project-bus-scoped, topic-bound when
/// named) to a managed one, just handed to an external process. `501` when the messaging-shim is
/// not wired on this node.
pub(super) async fn compute_dev_bind_messaging(
    Extension(posture): Extension<boatramp_core::security::SecurityPosture>,
    Extension(DevMessagingBind(resolver)): Extension<DevMessagingBind>,
    Json(req): Json<DevBindMessagingRequest>,
) -> Response {
    // Defense-in-depth: re-derive that this path is `System·Admin` (node-global), so a
    // routing/table regression cannot silently downgrade a credential-minting endpoint.
    if let Some(forbidden) = assert_project_export_is_system_admin(
        "POST",
        "/api/compute/dev-bind-messaging",
        "compute dev-bind-messaging",
    ) {
        return forbidden;
    }
    if !posture.allow_dev_messaging_bind {
        return (
            StatusCode::FORBIDDEN,
            "compute dev-bind-messaging is disabled; set the `allow_dev_messaging_bind` posture \
             (BOATRAMP_SECURITY_ALLOW_DEV_MESSAGING_BIND=true — on by default only in the `dev` \
             profile) to enable it\n",
        )
            .into_response();
    }
    let Some(resolver) = resolver else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "the compute messaging-shim is not active on this node (no messaging substrate or \
             `compute.messaging_shim_url` configured)\n",
        )
            .into_response();
    };
    let project = req.project.as_deref().unwrap_or("default");
    // Slug-validate the project (it flows into the token scope + the `{project}/bus/` key
    // prefix). The topic, when named, is re-validated inside the resolver's `scope`
    // (`validate_object_key` — a bus topic legitimately has `/`/`.`); a reject there yields an
    // empty env → `400` below (fail-closed, never a silent empty 200).
    if let Some(resp) = reject_invalid_name("project", project) {
        return resp;
    }
    let binding = boatramp_core::compute::ComputeBinding {
        kind: boatramp_core::compute::BindingKind::Messaging,
        name: req.topic.unwrap_or_default(),
        url_env: None,
    };
    let env = resolver
        .resolve(
            project,
            DEV_MESSAGING_WORKLOAD,
            DEV_BIND_REPLICA,
            std::slice::from_ref(&binding),
        )
        .await;
    if env.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "the messaging binding did not resolve (check the topic name)\n",
        )
            .into_response();
    }
    (StatusCode::OK, Json(DevBindMessagingResponse { env })).into_response()
}

// ---------------------------------------------------------------------------
// Operator node-wide registry pull credentials
// (`/api/compute/registry-auth{,/{name}}`, System·Admin — PLAN-compute-registry-auth)
// ---------------------------------------------------------------------------

/// The clear `501` every operator registry-auth endpoint returns when no `[secrets]` key
/// envelope is configured (there is then no sealed store) — never a panic or a `500`.
const NO_REGISTRY_SECRET_STORE: &str = "no [secrets] key envelope configured; registry credentials require sealing at rest \
     (set [secrets] envelope = \"local\" or \"vault\" in boatramp.cfg)\n";

/// Body of `POST /api/compute/registry-auth` — seal an operator node-wide registry
/// credential `{username,password}` under `name` in the reserved, tenant-unreachable
/// operator keyspace. The password is sealed server-side and is NEVER logged or returned.
/// `Debug` is deliberately NOT derived so a stray `{:?}` cannot echo the password.
#[derive(serde::Deserialize)]
pub(super) struct OperatorRegistryAuthRequest {
    /// The credential ref name (as used in `[compute].registry_auth`'s value). Validated
    /// fail-closed inside the store.
    name: String,
    /// The registry username.
    username: String,
    /// The registry password / token — sealed, never echoed.
    password: String,
}

/// Map a secret-store error to a client-safe response. A backend (KV/envelope) error's
/// detail is NOT client-safe (it can name KV shapes / a KMS status), so it is logged and
/// returned generically — and it never carries a plaintext credential.
fn registry_auth_store_response(err: boatramp_core::secret_store::SecretError) -> Response {
    if err.is_conflict() {
        (StatusCode::CONFLICT, format!("{err}\n")).into_response()
    } else if err.is_client_error() {
        (StatusCode::BAD_REQUEST, format!("{err}\n")).into_response()
    } else {
        tracing::warn!(%err, "operator registry-auth store error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "registry-auth store error\n",
        )
            .into_response()
    }
}

/// The reserved operator project `ProjectRef`.
fn operator_registry_project() -> boatramp_core::project::ProjectRef<'static> {
    boatramp_core::project::ProjectRef::new(boatramp_core::registry_auth::OPERATOR_REGISTRY_PROJECT)
}

/// `POST /api/compute/registry-auth` — seal an operator node-wide registry credential.
/// `System·Admin` (node-global). Returns the value-free [`SecretMeta`] as `201`; never
/// echoes the credential. `501` when no envelope is configured; `400` on an invalid name.
pub(super) async fn set_operator_registry_auth(
    Extension(store): Extension<Option<Arc<boatramp_core::secret_store::SecretStore>>>,
    Json(req): Json<OperatorRegistryAuthRequest>,
) -> Response {
    if let Some(forbidden) = assert_project_export_is_system_admin(
        "POST",
        "/api/compute/registry-auth",
        "operator registry-auth",
    ) {
        return forbidden;
    }
    let Some(store) = store else {
        return (StatusCode::NOT_IMPLEMENTED, NO_REGISTRY_SECRET_STORE).into_response();
    };
    // Seal the full `{username,password}` credential as JSON — the SAME shape the resolver
    // expects (project + operator scopes share one plaintext shape).
    let cred = boatramp_core::registry_auth::RegistryCredential {
        username: req.username,
        password: req.password,
    };
    let Ok(bytes) = serde_json::to_vec(&cred) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not encode credential\n",
        )
            .into_response();
    };
    match store
        .set(operator_registry_project(), &req.name, &bytes)
        .await
    {
        Ok(meta) => (StatusCode::CREATED, Json(meta)).into_response(),
        Err(e) => registry_auth_store_response(e),
    }
}

/// `GET /api/compute/registry-auth` — list operator registry credential names + metadata
/// (never a value). `System·Admin`. `501` when no envelope is configured.
pub(super) async fn list_operator_registry_auth(
    Extension(store): Extension<Option<Arc<boatramp_core::secret_store::SecretStore>>>,
) -> Response {
    if let Some(forbidden) = assert_project_export_is_system_admin(
        "GET",
        "/api/compute/registry-auth",
        "operator registry-auth",
    ) {
        return forbidden;
    }
    let Some(store) = store else {
        return (StatusCode::NOT_IMPLEMENTED, NO_REGISTRY_SECRET_STORE).into_response();
    };
    match store.list(operator_registry_project()).await {
        Ok(metas) => Json(metas).into_response(),
        Err(e) => registry_auth_store_response(e),
    }
}

/// `DELETE /api/compute/registry-auth/{name}` — remove an operator registry credential.
/// `System·Admin`. `204` if it existed, `404` if not; `501` when no envelope is configured.
pub(super) async fn delete_operator_registry_auth(
    Extension(store): Extension<Option<Arc<boatramp_core::secret_store::SecretStore>>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    if let Some(forbidden) = assert_project_export_is_system_admin(
        "DELETE",
        "/api/compute/registry-auth/_",
        "operator registry-auth",
    ) {
        return forbidden;
    }
    let Some(store) = store else {
        return (StatusCode::NOT_IMPLEMENTED, NO_REGISTRY_SECRET_STORE).into_response();
    };
    match store.delete(operator_registry_project(), &name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            "no matching operator registry credential\n",
        )
            .into_response(),
        Err(e) => registry_auth_store_response(e),
    }
}

// ---------------------------------------------------------------------------
// Native project export / import (`POST /api/project-export` / `/api/project-import`)
// ---------------------------------------------------------------------------

/// Defense-in-depth (mirrors `control_api::assert_kv_dump_is_system_admin`): re-derive that
/// `path` is gated `System·Admin` inside the handler, so a routing/table regression cannot
/// silently downgrade a node-global endpoint to a project right. Generic — reused by the
/// node-global credential-minting dev-bind handlers (NOT the project export/import, which are now
/// Project·Admin — see `assert_project_export_is_project_admin`).
fn assert_project_export_is_system_admin(method: &str, path: &str, what: &str) -> Option<Response> {
    use boatramp_core::authz::{Action, Resource, Right};
    match Right::required(method, path) {
        Some(right)
            if right.resource == Resource::System
                && right.target.is_none()
                && right.action == Action::Admin =>
        {
            None
        }
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                format!("{what} requires System·Admin\n"),
            )
                .into_response(),
        ),
    }
}

/// Defense-in-depth re-check (mirrors the `clone` family + `control_api::assert_kv_dump_is_system_admin`
/// pattern): re-derive that `path` with its `?project=<target>` is gated **`Project·Admin` on that
/// exact target project**, so a routing/table regression cannot silently downgrade the data-moving
/// export/import below Project·Admin or to a WRONG/target-less scope (which would open a cross-tenant
/// data-move hole). Binds to the SAME target the request names — the authoritative token check happens
/// in `require_auth` via `authorize_with_query`; this guards the mapping, fail-closed.
fn assert_project_export_is_project_admin(
    method: &str,
    path: &str,
    target: &str,
    what: &str,
) -> Option<Response> {
    use boatramp_core::authz::{Action, Resource, Right};
    // Re-derive through the same query-scoped table entry the authorizer used, with a query that
    // names this request's target project.
    let query = format!("project={target}");
    let expected = Right::new(Resource::Project, Some(target.to_string()), Action::Admin);
    match Right::required_for(method, path, Some(&query)) {
        Some(right) if right == expected => None,
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                format!("{what} requires Project·Admin on {target:?}\n"),
            )
                .into_response(),
        ),
    }
}

/// `POST /api/project-export` query: the project + whether to produce a `--data-only`
/// bundle (app data only; the Phase-1 default) vs a full schema+data bundle.
#[derive(Debug, Deserialize)]
pub(super) struct ProjectExportQuery {
    project: String,
    #[serde(default = "default_data_only")]
    data_only: bool,
    /// Also include the identity transport container (requires the transport-key header).
    /// Default off — the safe, identity-free bundle.
    #[serde(default)]
    include_identity: bool,
    /// RESUMABLE mode (T3): a relative directory NAME under the node's configured
    /// `[serve] resumable_export_dir` base. When set, the export writes a resumable
    /// member-object directory on the NODE (resuming an interrupted run) instead of
    /// streaming the bundle in the response body. The host confines the name under the base
    /// and refuses any escape / when no base is configured.
    #[serde(default)]
    resumable: Option<String>,
    /// DELTA mode: `differential` or `incremental` (see [`DeltaMode`]). Only valid alongside
    /// `resumable` + `base` — a delta is written as a node-local member-object directory that
    /// chains onto `base`. Absent ⇒ a full (non-delta) bundle.
    #[serde(default)]
    mode: Option<String>,
    /// The base (differential) / parent (incremental) resumable-dir NAME to chain the delta
    /// onto. Required with `mode`; the host confines it under the configured base like
    /// `resumable`.
    #[serde(default)]
    base: Option<String>,
}

fn default_data_only() -> bool {
    true
}

/// Build the optional [`DeltaRequest`] from the export query's `mode`/`base`, enforcing that a
/// delta (a) names both `mode` and `base`, (b) runs only in `resumable` mode (the base is a
/// node-local member-object dir, so a streamed delta is meaningless), and (c) uses a known mode.
/// Returns `Ok(None)` for a plain full/resumable export. Errors are caller-facing `400` text.
fn parse_export_delta(
    mode: Option<&str>,
    base: Option<&str>,
    resumable: Option<&str>,
) -> Result<Option<boatramp_core::project_delta::DeltaRequest>, String> {
    use boatramp_core::project_delta::{DeltaMode, DeltaRequest};
    match (mode, base) {
        (None, None) => Ok(None),
        (Some(_), None) => {
            Err("delta export: `mode` requires `base` (the resumable dir to chain onto)".into())
        }
        (None, Some(_)) => {
            Err("delta export: `base` requires `mode` (differential|incremental)".into())
        }
        (Some(m), Some(b)) => {
            if resumable.is_none() {
                return Err(
                    "delta export requires `resumable` — a delta is written as a \
                            node-local member-object directory, not a streamed bundle"
                        .into(),
                );
            }
            let mode = DeltaMode::parse_flag(m).ok_or_else(|| {
                format!("delta export: unknown `mode` {m:?} (expected differential|incremental)")
            })?;
            Ok(Some(DeltaRequest {
                mode,
                base_reference: b.to_string(),
            }))
        }
    }
}

/// The HTTP header carrying the operator transport passphrase for `--include-identity`
/// export / `--identity adopt` import. A header (not a query param) so the secret never
/// lands in a URL / access log; sent over TLS. The value is the raw passphrase bytes.
const TRANSPORT_KEY_HEADER: &str = "x-boatramp-transport-key";

fn transport_key_from_headers(headers: &HeaderMap) -> Option<Vec<u8>> {
    headers
        .get(TRANSPORT_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.as_bytes().to_vec())
        .filter(|b| !b.is_empty())
}

/// Map a resumable export/import failure to an HTTP response. The resumable path's errors
/// are predominantly caller-facing (the feature isn't enabled on this node, the directory
/// name is refused by the host's confinement, or the directory doesn't exist), so an
/// `Other` maps to `400` with its (already-redacted) message rather than a `500`; the typed
/// import variants keep their existing codes.
fn resumable_error_response(e: boatramp_core::project_export::ProjectExportError) -> Response {
    use boatramp_core::project_export::ProjectExportError as E;
    match e {
        E::Unavailable(m) => (StatusCode::NOT_IMPLEMENTED, format!("{m}\n")).into_response(),
        E::SchemaSkew(dbs) => (
            StatusCode::CONFLICT,
            format!("schema skew on: {}\n", dbs.join(", ")),
        )
            .into_response(),
        E::Commingle(m) => (StatusCode::CONFLICT, format!("{m}\n")).into_response(),
        E::Other(m) => (StatusCode::BAD_REQUEST, format!("{m}\n")).into_response(),
    }
}

/// Export a project to a `BRPROJ` bundle, STREAMED as the response body (`Project·Admin` on the
/// `?project=` target — re-checked defense-in-depth in-handler, mirroring the clone family).
/// The driver writes the bundle straight into an in-memory pipe whose read half is the
/// response body — the node never stages the whole bundle to a temp file (peak staging is
/// bounded to the largest single member). `501` when no export driver is wired. Because bytes
/// start flowing immediately, a driver failure after the first bytes cannot change the
/// already-sent `200`; the bundle's per-member SHA-256 makes a truncated bundle fail loud on
/// import.
pub(super) async fn project_export(
    Extension(cap): Extension<Option<Arc<dyn boatramp_core::project_export::ProjectExport>>>,
    headers: HeaderMap,
    Query(q): Query<ProjectExportQuery>,
) -> Response {
    let Some(cap) = cap else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "project export is not available on this node\n",
        )
            .into_response();
    };
    if q.project.is_empty() {
        return (StatusCode::BAD_REQUEST, "project is required\n").into_response();
    }
    // Slug-validate before the name flows into temp paths, `local_path`, the blob prefix
    // and `ProjectRef::qualified` — a `..`/`/` would traverse (mirrors every sibling).
    if let Some(resp) = reject_invalid_name("project", &q.project) {
        return resp;
    }
    // Defense-in-depth: re-derive that this request is gated Project·Admin on THIS target project
    // (bound to `?project=`), so a table regression can't downgrade it below Project·Admin or to a
    // wrong/target-less scope. The authoritative token check already ran in `require_auth`.
    if let Some(forbidden) = assert_project_export_is_project_admin(
        "POST",
        "/api/project-export",
        &q.project,
        "project export",
    ) {
        return forbidden;
    }
    let transport_key = transport_key_from_headers(&headers);
    if q.include_identity && transport_key.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            "include_identity requires the X-Boatramp-Transport-Key header\n",
        )
            .into_response();
    }
    // The delta (`mode` + `base`) surface: present ⇒ write a delta member-object dir chaining
    // onto `base`; absent ⇒ a full/resumable export. Bad combinations are caller-facing 400s.
    let delta =
        match parse_export_delta(q.mode.as_deref(), q.base.as_deref(), q.resumable.as_deref()) {
            Ok(d) => d,
            Err(m) => return (StatusCode::BAD_REQUEST, format!("{m}\n")).into_response(),
        };
    let export_opts = boatramp_core::project_export::ExportOptions {
        data_only: q.data_only,
        include_identity: q.include_identity,
        transport_key,
        delta,
    };
    // RESUMABLE mode (T3): write a node-local member-object directory (resuming an
    // interrupted run) and return a status, instead of streaming the bundle. The host
    // confines the operator-named dir under the configured base (refusing an escape or when
    // no base is set), so the capability resolves the path — the handler just passes the name.
    if let Some(dir_name) = q.resumable.as_deref() {
        return match cap
            .export_resumable(&q.project, &export_opts, dir_name)
            .await
        {
            Ok(()) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "project": q.project,
                    "resumable_dir": dir_name,
                    "status": "complete",
                })),
            )
                .into_response(),
            Err(e) => resumable_error_response(e),
        };
    }
    // Stream the bundle straight to the response body: the driver writes the `BRPROJ` tar
    // into the write half of an in-memory pipe (bounded) as it produces each member, and the
    // response body drains the read half — so the node's transient on-disk staging stays
    // bounded to the LARGEST SINGLE MEMBER and the whole bundle is never buffered to a temp
    // file (the env-clone disk-fill fix). Because the bytes start flowing immediately, a
    // driver failure AFTER the first bytes cannot change the already-sent 200; the bundle's
    // per-member SHA-256 + size make a truncated/partial bundle fail LOUD on import instead.
    use tokio_util::compat::TokioAsyncWriteCompatExt;
    let (dup_w, dup_r) = tokio::io::duplex(128 * 1024);
    let project_for_task = q.project.clone();
    // FOLLOW-UP (LOW-2, release hardening): this export task is detached. If the client
    // disconnects, the duplex read half drops and the driver's sink write errors out, which
    // unwinds the stream; an explicit abort-on-disconnect handle would make that tidier.
    tokio::spawn(async move {
        let mut sink = dup_w.compat_write();
        if let Err(e) = cap.export(&project_for_task, &export_opts, &mut sink).await {
            tracing::warn!(error = %e, project = %project_for_task, "project export stream failed");
        }
        // Dropping `sink` closes the pipe's write half ⇒ the response body sees EOF.
    });
    let stream = futures::stream::try_unfold(
        (dup_r, vec![0u8; 64 * 1024]),
        |(mut rd, mut buf)| async move {
            use tokio::io::AsyncReadExt;
            let n = rd.read(&mut buf).await?;
            if n == 0 {
                Ok::<_, std::io::Error>(None)
            } else {
                Ok(Some((bytes::Bytes::copy_from_slice(&buf[..n]), (rd, buf))))
            }
        },
    );
    let mut resp = Body::from_stream(stream).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(cd) = HeaderValue::from_str(&format!(
        "attachment; filename=\"boatramp-project-{}.brproj\"",
        q.project
    )) {
        resp.headers_mut().insert(header::CONTENT_DISPOSITION, cd);
    }
    resp
}

/// `POST /api/project-import` query: the project + import flags (`apply` executes vs a
/// dry-run plan; `force` overlays a non-empty control-plane KV store-wide; `overwrite` allows
/// replacing a target PROJECT that already holds its own data; `allow_schema_skew` proceeds
/// past a Postgres schema-ledger fingerprint mismatch).
#[derive(Debug, Default, Deserialize)]
pub(super) struct ProjectImportQuery {
    project: String,
    #[serde(default)]
    apply: bool,
    #[serde(default)]
    force: bool,
    #[serde(default)]
    allow_schema_skew: bool,
    /// Replace an existing target project (one that already has owned KV/blob data). Default
    /// `false` ⇒ refuse a populated target, so a clone into a fresh target is the safe default.
    #[serde(default)]
    overwrite: bool,
    /// `fresh` (default — mint own identity, drop source-sealed secrets) or `adopt`
    /// (install the bundle's KEK for a same-environment recovery; requires the
    /// transport-key header).
    #[serde(default = "default_identity")]
    identity: String,
    /// RESUMABLE mode (T3): a relative directory NAME under the node's configured
    /// `[serve] resumable_export_dir` base to import from (the output of a resumable
    /// export), instead of a streamed request body. Host-confined under the base.
    #[serde(default)]
    resumable: Option<String>,
    /// Clone-robustness (PLAN-clone-robustness #1): scan ALL members, report EVERY declared≠streamed
    /// integrity mismatch in one pass, and fail at the end (assessment — applies nothing that
    /// mismatches). Default `false`.
    #[serde(default)]
    enumerate_mismatches: bool,
    /// Clone-robustness (PLAN-clone-robustness #2): warn + continue past a mismatched member (not
    /// applied — the target re-derives it), DEFAULT-scoped to re-generable `der/` derivatives.
    /// Default `false`.
    #[serde(default)]
    skip_member_mismatch: bool,
    /// Clone-robustness: broaden `skip_member_mismatch` to ANY blob member (never a non-blob one) —
    /// the louder opt-in. Default `false`.
    #[serde(default)]
    skip_any_blob_mismatch: bool,
}

fn default_identity() -> String {
    "fresh".to_string()
}

/// Import a `BRPROJ` bundle (the request body) into a project (`Project·Admin` on the `?project=`
/// target — re-checked defense-in-depth in-handler, mirroring the clone family). The body is
/// STREAMED straight into the driver (never staged whole to a node temp file; peak staging is
/// bounded to the largest single member) and restored in a single forward pass; dry-run unless
/// `?apply=true`. Returns the import report JSON. `501` when no driver is wired, `409` on a
/// schema skew / KV commingle refusal.
///
/// Atomicity (inc2): each FULL managed, dedicated/Single DB member (pg/mysql/libsql) is applied
/// into a SHADOW and swapped in only after its trailing SHA verifies, so a corrupt/truncated/
/// aborted DB member applies NOTHING to live (PER-MEMBER all-or-nothing, default #2). The bundle is
/// NOT whole-bundle atomic: a cross-member window remains (a known residual). Overwriting a
/// populated DB peaks at ~2× its size during the shadow swap.
///
/// Privilege confinement (HIGH-1): a bundle's pg/mysql dump is attacker-crafted, so the chunked
/// shadow apply runs it as a freshly-minted EPHEMERAL non-superuser role (a fail-closed probe
/// refuses a superuser), never the binding's configured user (the bootstrap superuser on a managed
/// co-located server). Consequently a MANAGED `--data-only` or Shared sidecar restore — which would
/// apply as that superuser — is REFUSED fail-closed (a least-privilege sidecar apply is a
/// follow-up); an EXTERNAL bring-your-own-URL binding applies with the operator's own credential
/// against their own database; and chunked shadow-restore is dedicated/Single only (Shared deferred).
pub(super) async fn project_import(
    Extension(cap): Extension<Option<Arc<dyn boatramp_core::project_export::ProjectExport>>>,
    Query(q): Query<ProjectImportQuery>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(cap) = cap else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "project import is not available on this node\n",
        )
            .into_response();
    };
    if q.project.is_empty() {
        return (StatusCode::BAD_REQUEST, "project is required\n").into_response();
    }
    // Slug-validate before the name reaches any path / `ProjectRef::qualified`.
    if let Some(resp) = reject_invalid_name("project", &q.project) {
        return resp;
    }
    // Defense-in-depth: re-derive that this request is gated Project·Admin on THIS target project
    // (the import TARGET, bound to `?project=`), so a table regression can't downgrade it below
    // Project·Admin or to a wrong/target-less scope. The token check already ran in `require_auth`.
    if let Some(forbidden) = assert_project_export_is_project_admin(
        "POST",
        "/api/project-import",
        &q.project,
        "project import",
    ) {
        return forbidden;
    }
    let identity = match q.identity.as_str() {
        "fresh" => boatramp_core::project_export::IdentityChoice::Fresh,
        "adopt" => match transport_key_from_headers(&headers) {
            Some(transport_key) => {
                boatramp_core::project_export::IdentityChoice::Adopt { transport_key }
            }
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    "identity=adopt requires the X-Boatramp-Transport-Key header\n",
                )
                    .into_response();
            }
        },
        other => {
            return (
                StatusCode::BAD_REQUEST,
                format!("identity must be 'fresh' or 'adopt', got {other:?}\n"),
            )
                .into_response();
        }
    };
    let opts = boatramp_core::project_export::ImportOptions {
        apply: q.apply,
        force: q.force,
        allow_schema_skew: q.allow_schema_skew,
        overwrite: q.overwrite,
        identity,
        enumerate_mismatches: q.enumerate_mismatches,
        skip_member_mismatch: q.skip_member_mismatch,
        skip_any_blob_mismatch: q.skip_any_blob_mismatch,
    };
    // RESUMABLE mode (T3): import from a node-local member-object directory (the output of a
    // resumable export) named relative to the configured base — no request body. The host
    // confines the operator-named dir under the base (refusing an escape / when unset).
    if let Some(dir_name) = q.resumable.as_deref() {
        return match cap.import_resumable(&q.project, dir_name, opts).await {
            Ok(report) => (StatusCode::OK, Json(report)).into_response(),
            Err(e) => resumable_error_response(e),
        };
    }
    // Stream the request body straight into the driver — no stage-to-temp: the node never
    // holds the whole bundle (peak staging is bounded to the largest single member), and the
    // bundle is restored in a single forward pass. `into_async_read` adapts axum's body
    // byte-stream to the `futures::io::AsyncRead` the capability takes.
    use futures::TryStreamExt;
    let mut reader = body
        .into_data_stream()
        .map_err(std::io::Error::other)
        .into_async_read();
    let res = cap.import(&q.project, &mut reader, opts).await;
    match res {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(boatramp_core::project_export::ProjectExportError::SchemaSkew(dbs)) => (
            StatusCode::CONFLICT,
            format!(
                "project import: schema SKEW for {dbs:?} — the target's migrated schema differs \
                 from the source bundle; re-send with `?allow_schema_skew=true` only if you \
                 intend to load the data anyway\n"
            ),
        )
            .into_response(),
        Err(boatramp_core::project_export::ProjectExportError::Commingle(m)) => {
            (StatusCode::CONFLICT, format!("{m}\n")).into_response()
        }
        Err(boatramp_core::project_export::ProjectExportError::Unavailable(m)) => {
            (StatusCode::NOT_IMPLEMENTED, format!("{m}\n")).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("project import failed: {e}\n"),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Streaming project CLONE (PLAN-project-clone, increment 1)
//
// Three project-scoped, `Project·Admin`-gated surfaces (NOT the node-global `System·Admin`
// export/import above). The SOURCE side serves a cheap manifest + a filtered member stream;
// the TARGET side is the orchestrator that pulls from the source and restores through the
// EXISTING inc2 import path. All three live under the `clone` project family, so authz sees
// the original `/api/projects/<proj>/clone/…` path and gates it `Project·Admin` (see
// `authz::Right::required`), and `project_scope` injects the tenant as `ProjectContext`.
// ---------------------------------------------------------------------------

/// The HTTP header carrying the operator's SOURCE-node Project-Admin bearer for a clone pull
/// (the operator-redeems-Project-Admin model, increment 1). A header (not a query param) so
/// the token never lands in a URL / access log; sent over TLS. The target forwards it as the
/// `Authorization: Bearer` to the source's clone endpoints.
const SOURCE_TOKEN_HEADER: &str = "x-boatramp-source-token";

/// The hard cap on the clone MANIFEST body the target will read from a source (`diff` OOM guard):
/// a manifest is a blob LIST, so it is modest even for a large project, but the source is
/// attacker-influenceable — bound it like `clone_stream` bounds its skip body. Transitively bounds
/// `manifest.blobs.len()`; the driver also caps the count explicitly before the HEAD fan-out.
const CLONE_MANIFEST_CAP: usize = 64 * 1024 * 1024;

/// Query for the SOURCE clone surfaces (`/api/clone/manifest`, `/api/clone/stream`): whether the
/// clone stream is `--data-only` (no control-plane KV / identity). Default `false` ⇒ a FULL clone
/// (carries the project's control-plane KV slice); the target mints a FRESH identity on restore.
#[derive(Debug, Default, Deserialize)]
pub(super) struct CloneSourceQuery {
    #[serde(default)]
    data_only: bool,
}

/// SOURCE — produce the cheap clone MANIFEST (`GET /api/projects/<proj>/clone/manifest`,
/// `Project·Admin`): a LIST of the project's blob objects (for the target's per-SHA diff) plus
/// the non-blob member paths the stream will carry. No full materialization. `501` when no clone
/// driver is wired on this node.
pub(super) async fn clone_manifest(
    Extension(cap): Extension<Option<Arc<dyn boatramp_core::project_export::ProjectExport>>>,
    Extension(project): Extension<ProjectContext>,
    Query(q): Query<CloneSourceQuery>,
) -> Response {
    let Some(cap) = cap else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "project clone is not available on this node\n",
        )
            .into_response();
    };
    let project = project.0;
    if let Some(resp) = reject_invalid_name("project", &project) {
        return resp;
    }
    let opts = boatramp_core::project_export::ExportOptions {
        data_only: q.data_only,
        ..Default::default()
    };
    match cap.clone_manifest(&project, &opts).await {
        Ok(manifest) => (StatusCode::OK, Json(manifest)).into_response(),
        Err(e) => resumable_error_response(e),
    }
}

/// SOURCE — stream the filtered clone bundle (`POST /api/projects/<proj>/clone/stream`,
/// `Project·Admin`): the request body is a [`CloneSkip`](boatramp_core::project_export::CloneSkip)
/// JSON (the blob member paths the target already holds); the driver streams a format-v2/v3
/// bundle OMITTING those members, straight into the response body (bounded in-memory pipe — never
/// staged whole, exactly like `project_export`). The target restores it through the existing inc2
/// atomic reader.
pub(super) async fn clone_stream(
    Extension(cap): Extension<Option<Arc<dyn boatramp_core::project_export::ProjectExport>>>,
    Extension(project): Extension<ProjectContext>,
    Query(q): Query<CloneSourceQuery>,
    body: Body,
) -> Response {
    let Some(cap) = cap else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "project clone is not available on this node\n",
        )
            .into_response();
    };
    let project = project.0;
    if let Some(resp) = reject_invalid_name("project", &project) {
        return resp;
    }
    // The skip set is a small JSON body (member paths); read it bounded before streaming.
    let skip_bytes = match axum::body::to_bytes(body, 64 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("clone stream: cannot read skip set body: {e}\n"),
            )
                .into_response();
        }
    };
    let skip: boatramp_core::project_export::CloneSkip = if skip_bytes.is_empty() {
        boatramp_core::project_export::CloneSkip::default()
    } else {
        match serde_json::from_slice(&skip_bytes) {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("clone stream: malformed skip set JSON: {e}\n"),
                )
                    .into_response();
            }
        }
    };
    let opts = boatramp_core::project_export::ExportOptions {
        data_only: q.data_only,
        ..Default::default()
    };
    // Same bounded-pipe streaming as `project_export`: the driver writes the filtered bundle into
    // the duplex write half (a detached task), the response body drains the read half.
    use tokio_util::compat::TokioAsyncWriteCompatExt;
    let (dup_w, dup_r) = tokio::io::duplex(128 * 1024);
    tokio::spawn(async move {
        let mut sink = dup_w.compat_write();
        if let Err(e) = cap.export_clone(&project, &opts, &skip, &mut sink).await {
            tracing::warn!(error = %e, project = %project, "project clone stream failed");
        }
    });
    let stream = futures::stream::try_unfold(
        (dup_r, vec![0u8; 64 * 1024]),
        |(mut rd, mut buf)| async move {
            use tokio::io::AsyncReadExt;
            let n = rd.read(&mut buf).await?;
            if n == 0 {
                Ok::<_, std::io::Error>(None)
            } else {
                Ok(Some((bytes::Bytes::copy_from_slice(&buf[..n]), (rd, buf))))
            }
        },
    );
    let mut resp = Body::from_stream(stream).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    resp
}

/// The `POST /api/projects/<target>/clone/from` body: where to pull from + the import knobs.
#[derive(Debug, Deserialize)]
pub(super) struct CloneFromRequest {
    /// The SOURCE node's base URL (e.g. `https://src.example.com`). Operator-supplied.
    source_url: String,
    /// The SOURCE project to clone. Defaults to the target project name (the common same-name
    /// env-clone) when absent.
    #[serde(default)]
    source_project: Option<String>,
    /// Execute the restore (default `false` ⇒ a dry-run plan on the target).
    #[serde(default)]
    apply: bool,
    /// Stream-level VERIFY: with `apply=false`, open the source stream and validate the whole
    /// bundle end-to-end WITHOUT mutating the target (the pre-v0.49 `apply=false` behavior). The
    /// DEFAULT dry-run (`apply=false`, `verify=false`) is instead the CHEAP PLAN — manifest + diff
    /// only, no stream. Ignored when `apply=true` (an apply already restores for real).
    #[serde(default)]
    verify: bool,
    /// Replace an existing (populated) target project.
    #[serde(default)]
    overwrite: bool,
    /// Overlay a non-empty control-plane KV destination on the target.
    #[serde(default)]
    force: bool,
    /// Pull a `--data-only` clone (no control-plane KV / identity).
    #[serde(default)]
    data_only: bool,
    /// Clone-robustness (PLAN-clone-robustness #1): with `verify` (or `apply`), scan ALL members
    /// and report EVERY declared≠streamed integrity mismatch in one pass, failing at the end — the
    /// assess-scope pass (applies nothing that mismatches). Default `false`.
    #[serde(default)]
    enumerate_mismatches: bool,
    /// Clone-robustness (PLAN-clone-robustness #2): warn + continue past a mismatched member
    /// instead of aborting the clone — the target re-derives a skipped derivative on access.
    /// DEFAULT-scoped to re-generable `der/` derivatives. Default `false`.
    #[serde(default)]
    skip_member_mismatch: bool,
    /// Clone-robustness: broaden `skip_member_mismatch` to ANY blob member (never a non-blob one) —
    /// the louder opt-in. Default `false`.
    #[serde(default)]
    skip_any_blob_mismatch: bool,
}

/// TARGET — the clone ORCHESTRATOR (`POST /api/projects/<target>/clone/from`, `Project·Admin`):
/// authenticate to the SOURCE as Project Admin (the operator's forwarded source bearer), fetch the
/// cheap manifest, and diff it against THIS node's own content-addressed store. The DEFAULT dry-run
/// (`apply=false`, `verify=false`) STOPS there and returns a cheap [`ClonePlan`] JSON (blob
/// total/present/to-transfer, approx bytes, the non-blob members) — it does NOT open the stream or
/// import. `apply=true` (or `verify=true`, the old stream-level validate) pulls ONLY the missing
/// members over the live stream and restores each through the EXISTING inc2 shadow-restore path
/// (reusing [`import`](ProjectExport::import), so the target enforces its OWN project scope on
/// every restored member — a source-declared scope is never trusted), returning an **NDJSON
/// progress stream** (`application/x-ndjson`): the plan, periodic transfer heartbeats, then one
/// terminal report/error. The plan/apply control flow lives in [`orchestrate_clone`] over a
/// transport seam so it is unit-testable (the dry-run provably never opens the stream).
pub(super) async fn clone_from(
    Extension(cap): Extension<Option<Arc<dyn boatramp_core::project_export::ProjectExport>>>,
    Extension(project): Extension<ProjectContext>,
    headers: HeaderMap,
    Json(req): Json<CloneFromRequest>,
) -> Response {
    let Some(cap) = cap else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "project clone is not available on this node\n",
        )
            .into_response();
    };
    let target = project.0;
    if let Some(resp) = reject_invalid_name("project", &target) {
        return resp;
    }
    let source_project = req.source_project.clone().unwrap_or_else(|| target.clone());
    if let Some(resp) = reject_invalid_name("source_project", &source_project) {
        return resp;
    }
    // The operator's SOURCE Project-Admin bearer (forwarded to the source). Required: a clone is
    // TWO Project-Admin authorizations — this node already gated the target side (`Project·Admin`
    // on `/api/projects/<target>/clone/from`); this token is the SOURCE side.
    let source_token = match headers
        .get(SOURCE_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .filter(|t| !t.is_empty())
    {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "clone requires the X-Boatramp-Source-Token header (the operator's Project-Admin \
                 bearer on the SOURCE node)\n",
            )
                .into_response();
        }
    };
    // SSRF guard [HIGH]: `source_url` is attacker-influenceable (a tenant-level Project·Admin picks
    // it), so the target must not be tricked into fetching internal services / cloud metadata
    // (169.254.169.254) / another tenant. RESOLVE + PIN the address and REFUSE any non-global target
    // (loopback / private / link-local / ULA — via `is_global_ip`), require HTTPS (so the forwarded
    // bearer never rides cleartext), and NEVER follow a redirect off the pinned host. Reuses the
    // shared SSRF decision + pinned-client policy (`graphql_data::token`). The manifest + stream
    // share the SAME host, so one pin covers both requests (no rebind window between them).
    let source_base = req.source_url.trim_end_matches('/').to_string();
    let manifest_url = format!("{source_base}/api/projects/{source_project}/clone/manifest");
    let stream_url = format!("{source_base}/api/projects/{source_project}/clone/stream");
    let Some((host, addr)) = crate::ssrf::resolve_pin(&manifest_url, false, false).await else {
        tracing::warn!(
            source_url = %source_base,
            target = %target,
            "clone refused: source_url is not an allowed https target resolving to a public address (SSRF guard)"
        );
        return (
            StatusCode::BAD_REQUEST,
            "clone source_url must be an absolute https URL resolving to a public address\n",
        )
            .into_response();
    };
    let Some(client) = crate::ssrf::pinned_client(&host, addr, true) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "clone: could not build the SSRF-pinned HTTP client\n",
        )
            .into_response();
    };
    // The SSRF-pinned transport to the source's `clone/manifest` + `clone/stream` surfaces. The
    // orchestration (manifest → diff → PLAN → optional stream+restore) is driven by
    // `orchestrate_clone` over this transport seam, so the plan/apply control flow is unit-testable
    // (a mock transport proves the dry-run NEVER opens the stream) and the SSRF/pin policy stays here.
    let transport = Arc::new(HttpCloneSource {
        client,
        manifest_url,
        stream_url,
        source_token,
        source_base,
        data_only: req.data_only,
    }) as Arc<dyn CloneSourceTransport>;

    orchestrate_clone(
        cap,
        target,
        source_project,
        transport,
        req.apply,
        req.verify,
        req.overwrite,
        req.force,
        CloneMismatchPolicy {
            enumerate: req.enumerate_mismatches,
            skip: req.skip_member_mismatch,
            skip_any_blob: req.skip_any_blob_mismatch,
        },
    )
    .await
}

/// The clone-robustness member-mismatch knobs (PLAN-clone-robustness #1 + #2) carried from the
/// clone request into [`orchestrate_clone`] → the target's [`ImportOptions`]. Grouped so a future
/// knob does not widen the already-long orchestrator signature.
#[derive(Debug, Clone, Copy, Default)]
struct CloneMismatchPolicy {
    /// Enumerate every mismatch + fail at the end (assess scope).
    enumerate: bool,
    /// Warn + skip a `der/` mismatch (broadened by `skip_any_blob`).
    skip: bool,
    /// Broaden the skip to any blob member (never a non-blob one).
    skip_any_blob: bool,
}

/// How often the `--apply` / `--verify` progress stream emits a transfer heartbeat (bytes pulled +
/// elapsed) so a long clone is never zero-output. A heartbeat, not a cost — the import keeps pulling
/// between ticks; a tick just samples the running byte counter.
const CLONE_PROGRESS_INTERVAL_SECS: u64 = 5;

/// A transport-level failure reaching the SOURCE (manifest fetch / stream open): carries the HTTP
/// status + the generic, non-reflective message to return to the caller (the source's own error
/// body is NEVER echoed — that would amplify a semi-blind SSRF; the detail is logged server-side).
struct CloneTransportError {
    status: StatusCode,
    message: &'static str,
}

impl CloneTransportError {
    fn into_response(self) -> Response {
        (self.status, format!("{}\n", self.message)).into_response()
    }
}

/// The SOURCE clone transport the orchestrator drives: fetch the cheap manifest, then (only on an
/// apply/verify) open the filtered member stream. A trait so the orchestration control flow is
/// testable with a mock that records whether the stream was ever opened — the DEFAULT dry-run must
/// not open it.
#[async_trait::async_trait]
trait CloneSourceTransport: Send + Sync {
    /// Fetch + parse the cheap `clone/manifest` (bounded read; a bad/oversized/wrong-scheme response
    /// is a [`CloneTransportError`]).
    async fn fetch_manifest(
        &self,
    ) -> Result<boatramp_core::project_export::CloneManifest, CloneTransportError>;
    /// Open the `clone/stream` filtered bundle for the given skip set, returning the response body
    /// as an async reader. Called ONLY on an apply/verify — never on the cheap plan.
    async fn open_stream(
        &self,
        skip: &boatramp_core::project_export::CloneSkip,
    ) -> Result<Box<dyn futures::io::AsyncRead + Send + Unpin>, CloneTransportError>;
}

/// The real HTTP transport over the SSRF-pinned, no-redirect reqwest client (both the manifest and
/// the stream share the one pinned host, so a single pin covers both — no rebind window between).
struct HttpCloneSource {
    client: reqwest::Client,
    manifest_url: String,
    stream_url: String,
    source_token: String,
    source_base: String,
    data_only: bool,
}

#[async_trait::async_trait]
impl CloneSourceTransport for HttpCloneSource {
    async fn fetch_manifest(
        &self,
    ) -> Result<boatramp_core::project_export::CloneManifest, CloneTransportError> {
        let data_only = if self.data_only { "true" } else { "false" };
        // Fetch the SOURCE manifest (cheap LIST), BOUNDED to `CLONE_MANIFEST_CAP` (OOM guard) with a
        // short per-request total timeout. A 3xx is a failure (the no-redirect client refuses to
        // follow off the pinned host). The source's error body is NEVER reflected to the caller.
        let manifest_resp = match self
            .client
            .get(&self.manifest_url)
            .query(&[("data_only", data_only)])
            .bearer_auth(&self.source_token)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, source_url = %self.source_base, "clone: source manifest fetch failed");
                return Err(CloneTransportError {
                    status: StatusCode::BAD_GATEWAY,
                    message: "clone: could not fetch the source manifest",
                });
            }
        };
        if !manifest_resp.status().is_success() {
            tracing::warn!(status = %manifest_resp.status(), source_url = %self.source_base, "clone: source refused the manifest");
            return Err(CloneTransportError {
                status: StatusCode::BAD_GATEWAY,
                message: "clone: the source refused the manifest request",
            });
        }
        let manifest_bytes = {
            use futures::StreamExt;
            let mut stream = manifest_resp.bytes_stream();
            let mut buf: Vec<u8> = Vec::new();
            loop {
                match stream.next().await {
                    Some(Ok(chunk)) => {
                        if buf.len().saturating_add(chunk.len()) > CLONE_MANIFEST_CAP {
                            tracing::warn!(source_url = %self.source_base, cap = CLONE_MANIFEST_CAP, "clone: source manifest exceeds the size cap");
                            return Err(CloneTransportError {
                                status: StatusCode::BAD_GATEWAY,
                                message: "clone: the source manifest is too large",
                            });
                        }
                        buf.extend_from_slice(&chunk);
                    }
                    Some(Err(e)) => {
                        tracing::warn!(error = %e, source_url = %self.source_base, "clone: error reading the source manifest");
                        return Err(CloneTransportError {
                            status: StatusCode::BAD_GATEWAY,
                            message: "clone: error reading the source manifest",
                        });
                    }
                    None => break,
                }
            }
            buf
        };
        match serde_json::from_slice(&manifest_bytes) {
            Ok(m) => Ok(m),
            Err(e) => {
                tracing::warn!(error = %e, source_url = %self.source_base, "clone: source manifest was not valid JSON");
                Err(CloneTransportError {
                    status: StatusCode::BAD_GATEWAY,
                    message: "clone: the source manifest was not valid",
                })
            }
        }
    }

    async fn open_stream(
        &self,
        skip: &boatramp_core::project_export::CloneSkip,
    ) -> Result<Box<dyn futures::io::AsyncRead + Send + Unpin>, CloneTransportError> {
        let data_only = if self.data_only { "true" } else { "false" };
        // Pull ONLY the missing members over the live stream. No total timeout (a legitimate large
        // clone is long) — the pinned client's idle `read_timeout` bounds a stalled peer and the
        // import driver caps the total bytes. 3xx ⇒ failure; the source body is NEVER reflected.
        let stream_resp = match self
            .client
            .post(&self.stream_url)
            .query(&[("data_only", data_only)])
            .bearer_auth(&self.source_token)
            .json(skip)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, source_url = %self.source_base, "clone: source stream open failed");
                return Err(CloneTransportError {
                    status: StatusCode::BAD_GATEWAY,
                    message: "clone: could not open the source stream",
                });
            }
        };
        if !stream_resp.status().is_success() {
            tracing::warn!(status = %stream_resp.status(), source_url = %self.source_base, "clone: source refused the stream");
            return Err(CloneTransportError {
                status: StatusCode::BAD_GATEWAY,
                message: "clone: the source refused the stream request",
            });
        }
        use futures::TryStreamExt;
        let reader = stream_resp
            .bytes_stream()
            .map_err(std::io::Error::other)
            .into_async_read();
        Ok(Box::new(reader))
    }
}

/// The clone ORCHESTRATION core, over the [`CloneSourceTransport`] seam (so the plan/apply control
/// flow is unit-testable): fetch the manifest, cross-check it, run the SAME scope-enforcing diff
/// (`clone_blobs_present`) the real clone always has, and build the [`ClonePlan`]. On the DEFAULT
/// dry-run (`!apply && !verify`) it short-circuits and returns the CHEAP PLAN — it NEVER opens the
/// source stream and NEVER imports. On `apply`/`verify` it opens the stream and restores through the
/// EXISTING inc2 reader (the target enforces its OWN scope on every member — a source-declared scope
/// is never trusted; a clone is always a FRESH identity), streaming progress as it goes.
#[allow(clippy::too_many_arguments)]
async fn orchestrate_clone(
    cap: Arc<dyn boatramp_core::project_export::ProjectExport>,
    target: String,
    source_project: String,
    transport: Arc<dyn CloneSourceTransport>,
    apply: bool,
    verify: bool,
    overwrite: bool,
    force: bool,
    mismatch: CloneMismatchPolicy,
) -> Response {
    // 1. Manifest (cheap LIST).
    let manifest = match transport.fetch_manifest().await {
        Ok(m) => m,
        Err(e) => return e.into_response(),
    };
    // Defense: the manifest MUST describe the project the operator asked to clone (never trust a
    // source that answers for a different project).
    if manifest.source_project != source_project {
        tracing::warn!(got = %manifest.source_project, expected = %source_project, "clone: source manifest names a different project");
        return (
            StatusCode::BAD_GATEWAY,
            "clone: the source manifest names a different project\n",
        )
            .into_response();
    }

    // 2. Diff the source's blobs against THIS node's own store (re-keyed to the target scope,
    //    fail-closed on any foreign path; the driver also caps the blob COUNT before the HEAD
    //    fan-out) → the per-SHA skip set. SAME call on the plan path and the apply path — the
    //    plan short-circuit skips NO check that gates what would be transferred/restored.
    let skip = match cap
        .clone_blobs_present(&target, &source_project, &manifest.blobs)
        .await
    {
        Ok(s) => s,
        Err(e) => return resumable_error_response(e),
    };

    // 3. The plan — a pure projection of (manifest, diff): what WOULD transfer/restore.
    let plan =
        boatramp_core::project_export::ClonePlan::from_manifest_and_skip(&manifest, &skip, &target);

    // 4. DEFAULT dry-run: return the CHEAP PLAN. No stream opened, nothing imported.
    if !apply && !verify {
        return (StatusCode::OK, Json(plan)).into_response();
    }

    // 5. apply/verify: open the filtered stream and restore (or validate-only, `apply=false`)
    //    through the EXISTING inc2 reader, streaming progress. `verify` ⇒ `apply=false` ⇒ the
    //    import validates the whole bundle but mutates nothing.
    let reader = match transport.open_stream(&skip).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let opts = boatramp_core::project_export::ImportOptions {
        apply,
        force,
        allow_schema_skew: false,
        overwrite,
        identity: boatramp_core::project_export::IdentityChoice::Fresh,
        enumerate_mismatches: mismatch.enumerate,
        skip_member_mismatch: mismatch.skip,
        skip_any_blob_mismatch: mismatch.skip_any_blob,
    };
    clone_progress_response(cap, target, plan, reader, opts)
}

/// Build the NDJSON progress response for an apply/verify clone: a detached task emits the plan
/// first, then a periodic transfer heartbeat sampled from a byte counter wrapping the source
/// reader, and finally exactly one terminal report/error — so a 39-minute clone is never
/// zero-output. The import drives the reader; the counter is sampled, never a throttle. A failure
/// AFTER the first byte rides in-band (the `200` can no longer change), mirroring the streamed
/// export's own after-first-byte failure mode.
fn clone_progress_response(
    cap: Arc<dyn boatramp_core::project_export::ProjectExport>,
    target: String,
    plan: boatramp_core::project_export::ClonePlan,
    reader: Box<dyn futures::io::AsyncRead + Send + Unpin>,
    opts: boatramp_core::project_export::ImportOptions,
) -> Response {
    use boatramp_core::project_export::CloneEvent;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(8);
    tokio::spawn(async move {
        if !send_clone_event(&tx, CloneEvent::Plan(plan)).await {
            return; // client already gone — nothing to restore for
        }
        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut counting = CloneCountingReader {
            inner: reader,
            counter: counter.clone(),
        };
        let started = std::time::Instant::now();
        let import_fut = cap.import(&target, &mut counting, opts);
        tokio::pin!(import_fut);
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(CLONE_PROGRESS_INTERVAL_SECS));
        ticker.tick().await; // the first tick fires immediately — consume it
        let outcome = loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let ev = CloneEvent::Progress {
                        bytes_transferred: counter.load(std::sync::atomic::Ordering::Relaxed),
                        elapsed_secs: started.elapsed().as_secs(),
                    };
                    // A progress send failure (operator disconnected) is NON-fatal: keep restoring
                    // so the target is not left half-applied just because the stream reader went away.
                    let _sent = send_clone_event(&tx, ev).await;
                }
                res = &mut import_fut => break res,
            }
        };
        let final_ev = match outcome {
            Ok(report) => CloneEvent::Report(report),
            Err(e) => CloneEvent::Error {
                message: format!("{e}"),
            },
        };
        let _sent = send_clone_event(&tx, final_ev).await;
    });
    let body = Body::from_stream(futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    }));
    let mut resp = body.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    resp
}

/// Serialize one [`CloneEvent`](boatramp_core::project_export::CloneEvent) as an NDJSON line and
/// push it to the response channel. Returns `false` when the receiver is gone (client
/// disconnected). A serialize failure drops the one line (returns `true`) rather than the whole
/// stream.
async fn send_clone_event(
    tx: &tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    ev: boatramp_core::project_export::CloneEvent,
) -> bool {
    let mut line = match serde_json::to_vec(&ev) {
        Ok(v) => v,
        Err(_) => return true,
    };
    line.push(b'\n');
    tx.send(Ok(bytes::Bytes::from(line))).await.is_ok()
}

/// An [`AsyncRead`](futures::io::AsyncRead) wrapper that counts bytes read through it, so the
/// progress stream can report transfer bytes without the import driver knowing anything about it.
struct CloneCountingReader {
    inner: Box<dyn futures::io::AsyncRead + Send + Unpin>,
    counter: Arc<std::sync::atomic::AtomicU64>,
}

impl futures::io::AsyncRead for CloneCountingReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let r = std::pin::Pin::new(&mut *this.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &r {
            this.counter
                .fetch_add(*n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        r
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
    // Slug-validate the request `project` before composing a `ProjectRef` (consistency with the
    // other compute surfaces; System·Admin + read-mostly, so not a landing vector, but no reason
    // to skip the check).
    if let Some(resp) = reject_invalid_name("project", &req.project) {
        return resp;
    }
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

/// Defense-in-depth (mirrors [`assert_store_migrate_is_system_admin`](crate::store_migrate)):
/// re-derive the right the authoritative table requires for the reap path and assert it is
/// node-global `System·Admin` before the DESTRUCTIVE reap. The auth middleware already enforced
/// it (`is_compute_maintenance_path` → `System·Admin`); this catches a future routing/table
/// regression that might silently downgrade this node-global destructive op to a project right.
fn assert_compute_reap_is_system_admin() -> Option<Response> {
    use boatramp_core::authz::{Action, Resource, Right};
    match Right::required("POST", "/api/compute/maintenance/reap") {
        Some(right)
            if right.resource == Resource::System
                && right.target.is_none()
                && right.action == Action::Admin =>
        {
            None
        }
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                "the orphan-replica reaper requires System·Admin\n",
            )
                .into_response(),
        ),
    }
}

/// Body of `POST /api/compute/maintenance/reap` — the DESTRUCTIVE orphaned-replica reaper
/// lever (node-health-alerting Stage 2). With `project`+`workload`+`replica` it targets one
/// replica (still fail-closed re-checked); otherwise it scans every project. `dry_run`
/// DEFAULTS TO TRUE (report-only) — the caller must send `dry_run: false` to actually reap.
#[derive(Deserialize)]
pub(super) struct ReapRequest {
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    workload: Option<String>,
    #[serde(default)]
    replica: Option<u32>,
    /// Report-only unless explicitly `false`. Absent ⇒ `true` (dry-run), the safe default.
    #[serde(default)]
    dry_run: Option<bool>,
    /// Minimum orphan age (seconds) required before acting. Absent ⇒ `0` for an explicitly
    /// targeted replica (conditions "no desired workload" + "container gone" are the real
    /// guarantee), i.e. the operator named it deliberately.
    #[serde(default)]
    grace_secs: Option<u64>,
    /// Also free the orphan's scoped volume staging (PGDATA). Default `false`.
    #[serde(default)]
    reclaim_volumes: bool,
}

/// `POST /api/compute/maintenance/reap` — reap (or, dry-run, report) orphaned compute
/// replicas: a replica with NO desired workload AND no live container, past the grace.
/// DESTRUCTIVE → `System·Admin` (node-global, `is_compute_maintenance_path`), re-asserted
/// here defense-in-depth. Dry-run by default. `None` capability ⇒ `501`.
pub(super) async fn compute_reap(
    Extension(reaper): Extension<Option<Arc<dyn boatramp_core::compute::ComputeReaper>>>,
    Json(req): Json<ReapRequest>,
) -> Response {
    if let Some(forbidden) = assert_compute_reap_is_system_admin() {
        return forbidden;
    }
    let Some(reaper) = reaper else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "the orphan-replica reaper is not available on this node\n",
        )
            .into_response();
    };
    let target = match (req.project, req.workload, req.replica) {
        (Some(project), Some(workload), Some(replica)) => boatramp_core::compute::ReapTarget::One {
            project,
            workload,
            replica,
        },
        // A partial target is ambiguous — refuse rather than silently scanning all.
        (p, w, r) if p.is_some() || w.is_some() || r.is_some() => {
            return (
                StatusCode::BAD_REQUEST,
                "a targeted reap needs all of project + workload + replica (or none, to \
                 scan every project)\n",
            )
                .into_response();
        }
        _ => boatramp_core::compute::ReapTarget::All,
    };
    let opts = boatramp_core::compute::ReapOptions {
        target,
        grace_secs: req.grace_secs.unwrap_or(0),
        dry_run: req.dry_run.unwrap_or(true),
        reclaim_volumes: req.reclaim_volumes,
    };
    match reaper.reap(opts).await {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("reap failed: {e}\n")).into_response(),
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
    // Slug-validate the request `project` before composing a `ProjectRef` (consistency with the
    // other compute surfaces).
    if let Some(resp) = reject_invalid_name("project", &req.project) {
        return resp;
    }
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
    // A8: a claim-mapped role must not carry a non-conforming target. Fail closed on
    // the whole exchange (403) rather than silently dropping the role — a wrongly-mapped
    // `publisher:${PROJECT}` claim is a configuration error the operator must see, and
    // dropping it could quietly mint a lesser (or empty) token.
    for role in &roles {
        if let Some(target) = &role.target
            && boatramp_core::project::validate_role_target(target).is_err()
        {
            return (
                StatusCode::FORBIDDEN,
                "OIDC token maps a role with a non-conforming target (v0.7.0 name rules)\n",
            )
                .into_response();
        }
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

/// The body of a `POST /api/sql-move`: relocate the libsql database
/// `(project, site, from)` to `to` (same project + site), data intact.
#[derive(Deserialize)]
pub(super) struct SqlMoveRequest {
    /// The owning project (`default` for the reserved / pre-project project).
    pub project: String,
    /// The site whose database is being relocated.
    pub site: String,
    /// The source binding name (`default` = the site's default database).
    pub from: String,
    /// The destination binding name.
    pub to: String,
}

/// Relocate a libsql database, data-preserving — a destructive, node-level
/// maintenance op like prune/scrub (`system·admin`-gated in
/// [`authz::Right::required`](boatramp_types::authz::Right::required)). Backs
/// `boatramp sql move`. Local single-node only; a remote/sqld backend is refused
/// with a typed error (surfaced as `422`). `501` if this node has no guest SQL
/// data plane (no handlers runtime). Both names are validated through the canonical
/// [`validate_resource_name`](boatramp_core::project::validate_resource_name); an
/// invalid name is `422`. Reports the resolved `{status, from, to, integrity}` JSON.
pub(super) async fn sql_move(
    Extension(sql): Extension<Option<Arc<dyn boatramp_core::sql::SqlBackends>>>,
    Json(req): Json<SqlMoveRequest>,
) -> Response {
    // Screen both endpoint names at the ingress with the ONE canonical validator so a
    // malformed/`//`-collapsing/traversal name is rejected `422` before any lookup —
    // the reserved default (`default`) is explicitly allowed as either endpoint.
    for name in [&req.from, &req.to] {
        if name != boatramp_core::project::DEFAULT_DB_NAME
            && let Some(bad) = reject_invalid_db(name)
        {
            return bad;
        }
    }
    let Some(sql) = sql else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "SQL database relocation is not available on this node (no guest SQL data plane \
             configured)\n",
        )
            .into_response();
    };
    match sql
        .move_database(&req.project, &req.site, &req.from, &req.to)
        .await
    {
        Ok(report) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "moved",
                "project": report.project,
                "site": report.site,
                "from": report.from,
                "to": report.to,
                "integrity": report.integrity,
            })),
        )
            .into_response(),
        // A refusal (remote-unsupported, absent source, existing destination, name
        // validation, no-op) is a well-formed request the backend declined — surface it
        // as `422`, distinct from a `500` transport/IO fault.
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("sql move failed: {e}\n"),
        )
            .into_response(),
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
    fn export_delta_query_parses_and_refuses_bad_combos() {
        use boatramp_core::project_delta::DeltaMode;

        // No mode/base ⇒ a plain full/resumable export (None).
        assert!(
            parse_export_delta(None, None, Some("snap1"))
                .unwrap()
                .is_none()
        );
        assert!(parse_export_delta(None, None, None).unwrap().is_none());

        // A well-formed delta: mode + base + resumable.
        let d = parse_export_delta(Some("incremental"), Some("snap1"), Some("snap2"))
            .unwrap()
            .expect("a delta request");
        assert_eq!(d.mode, DeltaMode::Incremental);
        assert_eq!(d.base_reference, "snap1");
        assert_eq!(
            parse_export_delta(Some("differential"), Some("base"), Some("d1"))
                .unwrap()
                .unwrap()
                .mode,
            DeltaMode::Differential
        );

        // mode without base, base without mode, and an unknown mode all refuse.
        assert!(parse_export_delta(Some("incremental"), None, Some("d")).is_err());
        assert!(parse_export_delta(None, Some("base"), Some("d")).is_err());
        assert!(parse_export_delta(Some("sideways"), Some("base"), Some("d")).is_err());

        // A delta REQUIRES resumable (the base is a node-local member-object dir).
        assert!(parse_export_delta(Some("incremental"), Some("base"), None).is_err());
    }

    #[test]
    fn bundle_parses_function_sql_extension_and_rejects_ambiguity() {
        use boatramp_core::sql::MigrationAction;
        // A well-formed bundle with all three step kinds (U1 JSON format).
        let json = br#"{
            "steps": [
                { "id": "0001_fn", "function": { "name": "backfill", "version": "v3", "args": "{}" } },
                { "id": "0002_sql", "sql": "CREATE TABLE t (id int)", "no_transaction": true },
                { "id": "0003_ext", "extension": "citext" }
            ]
        }"#;
        let steps = parse_bundle(json).expect("valid bundle parses");
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].kind(), "function");
        assert_eq!(steps[1].kind(), "sql");
        assert_eq!(steps[2].kind(), "extension");
        assert!(
            matches!(&steps[0].action, MigrationAction::Function { name, version, .. }
            if name == "backfill" && version.as_deref() == Some("v3"))
        );
        assert!(matches!(
            &steps[1].action,
            MigrationAction::Sql {
                no_transaction: true,
                ..
            }
        ));

        // A step that sets more than one of function/sql/extension is refused (U1 exactly-one).
        let ambiguous = br#"{"steps":[{"id":"x","sql":"SELECT 1","extension":"citext"}]}"#;
        assert!(
            parse_bundle(ambiguous).is_err(),
            "a multi-kind step is refused"
        );
        // A step with none is refused.
        let empty = br#"{"steps":[{"id":"x"}]}"#;
        assert!(parse_bundle(empty).is_err(), "a kindless step is refused");
        // An empty bundle is refused.
        assert!(
            parse_bundle(br#"{"steps":[]}"#).is_err(),
            "an empty bundle is refused"
        );
        // Non-JSON is refused (not silently accepted).
        assert!(parse_bundle(b"not json").is_err());
    }

    #[cfg(feature = "handlers")]
    #[test]
    fn is_wasm_component_matches_component_not_module_or_asset() {
        // A component (layer byte 0x01) is precompiled; a core module (layer 0x00) and a non-wasm
        // asset are skipped, so precompile-at-upload (#1a) never wastes a compile on a static asset.
        let component = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
        let core_module = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        assert!(is_wasm_component(&component));
        assert!(!is_wasm_component(&core_module));
        assert!(!is_wasm_component(b"<!DOCTYPE html>")); // an SPA asset
        assert!(!is_wasm_component(&[0x00, 0x61, 0x73])); // too short
        assert!(!is_wasm_component(&[])); // empty
    }

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
            readiness: if healthy {
                boatramp_core::compute::Readiness::Provisioned
            } else {
                boatramp_core::compute::Readiness::Starting
            },
            data_dir: None,
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

    #[test]
    fn summarize_data_dir_surfaces_a_fault_over_a_clean_check_and_omits_when_absent() {
        use boatramp_core::compute::{DataDirOwnership, ForeignOwnedEntry};

        // No observation on any replica → absent (the field is simply not surfaced).
        let mut clean = obs("p", "pg", 0, "10.0.0.2", true, None);
        assert!(
            summarize_data_dir(std::slice::from_ref(&clean)).is_none(),
            "nothing recorded → no data_dir in the status view"
        );

        // A clean check present → surfaced as ok (rules data-dir out as the cause).
        clean.data_dir = Some(DataDirOwnership {
            volume: "data".into(),
            ok: true,
            expected_uid: 100_999,
            expected_gid: 100_999,
            foreign_count: 0,
            sample: None,
        });
        let v = summarize_data_dir(std::slice::from_ref(&clean)).expect("clean surfaced");
        assert_eq!(v["ok"], true);

        // A fault on another replica WINS over the clean one — the actionable signal.
        let mut faulty = obs("p", "pg", 1, "10.0.0.3", true, None);
        faulty.data_dir = Some(DataDirOwnership {
            volume: "data".into(),
            ok: false,
            expected_uid: 100_999,
            expected_gid: 100_999,
            foreign_count: 7,
            sample: Some(ForeignOwnedEntry {
                path: "global/pg_filenode.map".into(),
                uid: 0,
                gid: 0,
            }),
        });
        let v = summarize_data_dir(&[clean, faulty]).expect("fault surfaced");
        assert_eq!(v["ok"], false, "the fault wins over the clean sibling");
        assert_eq!(v["foreign_count"], 7);
        assert_eq!(v["volume"], "data");
        assert_eq!(v["sample"]["path"], "global/pg_filenode.map");
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

    /// A `ComputeBindingResolver` that returns a canned env for a `blob` binding — so the
    /// dev-bind handler's GATE matrix (posture / 501 / validation / empty-resolve) is
    /// testable without the live shim. `env` empty ⇒ simulate a binding the resolver
    /// rejected (e.g. a bad container).
    struct FakeBlobResolver {
        env: Vec<(String, String)>,
    }

    #[async_trait::async_trait]
    impl boatramp_core::compute::ComputeBindingResolver for FakeBlobResolver {
        async fn resolve(
            &self,
            _project: &str,
            _workload: &str,
            _replica: u32,
            bindings: &[boatramp_core::compute::ComputeBinding],
        ) -> Vec<(String, String)> {
            if bindings
                .iter()
                .any(|b| b.kind == boatramp_core::compute::BindingKind::Blob)
            {
                self.env.clone()
            } else {
                Vec::new()
            }
        }
        async fn release(
            &self,
            _project: &str,
            _workload: &str,
            _replica: u32,
            _bindings: &[boatramp_core::compute::ComputeBinding],
        ) {
        }
    }

    fn posture_with_dev_bind(on: bool) -> boatramp_core::security::SecurityPosture {
        boatramp_core::security::SecurityPosture {
            allow_dev_blob_bind: on,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn dev_bind_blob_gate_matrix() {
        let env = vec![
            (
                "BOATRAMP_BLOB_URL".to_string(),
                "http://10.0.0.1:8082".to_string(),
            ),
            (
                "BOATRAMP_BLOB_URL_AUTH_TOKEN".to_string(),
                "tok-abc".to_string(),
            ),
        ];
        let resolver: Arc<dyn boatramp_core::compute::ComputeBindingResolver> =
            Arc::new(FakeBlobResolver { env: env.clone() });
        let req = || DevBindBlobRequest {
            site: "mailroom".into(),
            container: None,
            project: None,
        };

        // Posture OFF ⇒ 403 even with a resolver wired (the gate, not availability).
        let resp = compute_dev_bind_blob(
            Extension(posture_with_dev_bind(false)),
            Extension(Some(resolver.clone())),
            Json(req()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Posture ON but no resolver (blob-shim inactive) ⇒ 501.
        let resp = compute_dev_bind_blob(
            Extension(posture_with_dev_bind(true)),
            Extension(None),
            Json(req()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);

        // Posture ON + resolver ⇒ 200 with the BLOB_URL + token env.
        let resp = compute_dev_bind_blob(
            Extension(posture_with_dev_bind(true)),
            Extension(Some(resolver.clone())),
            Json(req()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let pairs = body["env"].as_array().expect("env array");
        assert!(
            pairs.iter().any(|p| p[0] == "BOATRAMP_BLOB_URL"),
            "env carries BOATRAMP_BLOB_URL"
        );
        assert!(
            pairs.iter().any(|p| p[0] == "BOATRAMP_BLOB_URL_AUTH_TOKEN"),
            "env carries the auth token"
        );

        // Empty site ⇒ 400 (fail closed, before touching the resolver).
        let resp = compute_dev_bind_blob(
            Extension(posture_with_dev_bind(true)),
            Extension(Some(resolver.clone())),
            Json(DevBindBlobRequest {
                site: String::new(),
                container: None,
                project: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Resolver returns EMPTY (a rejected container) ⇒ 400, never a silent empty 200.
        let empty: Arc<dyn boatramp_core::compute::ComputeBindingResolver> =
            Arc::new(FakeBlobResolver { env: Vec::new() });
        let resp = compute_dev_bind_blob(
            Extension(posture_with_dev_bind(true)),
            Extension(Some(empty)),
            Json(req()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// A `ComputeBindingResolver` that returns a canned env for a `messaging` binding — the
    /// messaging analogue of [`FakeBlobResolver`], so the `dev-bind-messaging` handler's GATE
    /// matrix (posture / 501 / empty-resolve) is testable without the live shim. `env` empty ⇒
    /// simulate a binding the resolver rejected (e.g. a bad topic).
    struct FakeMessagingResolver {
        env: Vec<(String, String)>,
    }

    #[async_trait::async_trait]
    impl boatramp_core::compute::ComputeBindingResolver for FakeMessagingResolver {
        async fn resolve(
            &self,
            _project: &str,
            _workload: &str,
            _replica: u32,
            bindings: &[boatramp_core::compute::ComputeBinding],
        ) -> Vec<(String, String)> {
            if bindings
                .iter()
                .any(|b| b.kind == boatramp_core::compute::BindingKind::Messaging)
            {
                self.env.clone()
            } else {
                Vec::new()
            }
        }
        async fn release(
            &self,
            _project: &str,
            _workload: &str,
            _replica: u32,
            _bindings: &[boatramp_core::compute::ComputeBinding],
        ) {
        }
    }

    fn posture_with_dev_messaging_bind(on: bool) -> boatramp_core::security::SecurityPosture {
        boatramp_core::security::SecurityPosture {
            allow_dev_messaging_bind: on,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn dev_bind_messaging_gate_matrix() {
        let env = vec![
            (
                "BOATRAMP_MESSAGING_URL".to_string(),
                "http://10.0.0.1:8083".to_string(),
            ),
            (
                "BOATRAMP_MESSAGING_URL_AUTH_TOKEN".to_string(),
                "tok-msg".to_string(),
            ),
        ];
        let resolver: Arc<dyn boatramp_core::compute::ComputeBindingResolver> =
            Arc::new(FakeMessagingResolver { env: env.clone() });
        let req = || DevBindMessagingRequest {
            topic: Some("deliver".into()),
            project: None,
        };

        // Posture OFF ⇒ 403 even with a resolver wired (the gate, not availability).
        let resp = compute_dev_bind_messaging(
            Extension(posture_with_dev_messaging_bind(false)),
            Extension(DevMessagingBind(Some(resolver.clone()))),
            Json(req()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Posture ON but no resolver (messaging-shim inactive) ⇒ 501.
        let resp = compute_dev_bind_messaging(
            Extension(posture_with_dev_messaging_bind(true)),
            Extension(DevMessagingBind(None)),
            Json(req()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);

        // Posture ON + resolver ⇒ 200 with the MESSAGING_URL + token env.
        let resp = compute_dev_bind_messaging(
            Extension(posture_with_dev_messaging_bind(true)),
            Extension(DevMessagingBind(Some(resolver.clone()))),
            Json(req()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let pairs = body["env"].as_array().expect("env array");
        assert!(
            pairs.iter().any(|p| p[0] == "BOATRAMP_MESSAGING_URL"),
            "env carries BOATRAMP_MESSAGING_URL"
        );
        assert!(
            pairs
                .iter()
                .any(|p| p[0] == "BOATRAMP_MESSAGING_URL_AUTH_TOKEN"),
            "env carries the auth token"
        );

        // Resolver returns EMPTY (a rejected topic) ⇒ 400, never a silent empty 200.
        let empty: Arc<dyn boatramp_core::compute::ComputeBindingResolver> =
            Arc::new(FakeMessagingResolver { env: Vec::new() });
        let resp = compute_dev_bind_messaging(
            Extension(posture_with_dev_messaging_bind(true)),
            Extension(DevMessagingBind(Some(empty))),
            Json(req()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
            Extension(ProjectContext("exampleorg".into())),
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
            Extension(ProjectContext("exampleorg".into())),
            Extension(None),
            Path("default".into()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn sql_handlers_reject_an_invalid_db_path_param_with_422() {
        // Every `{db}` ingress fails closed on a name that is not a safe URL path
        // segment — BEFORE any lookup — with `422` (a well-formed request bearing a
        // semantically-invalid resource identifier, matching the other resource-name
        // path-param rejections) and the canonical validator's reason. The empty-string
        // `{db}` (a `/api/sql//exec` collapse) and a separator-bearing `{db}` (a smuggled
        // `%2F`, arriving decoded as `/`) are the headline cases. The `op`/`substrate`
        // extension is present (so a `501`/`503` can't mask the rejection).
        let op: Arc<dyn boatramp_core::sql::OperatorSql> = Arc::new(FakePingSql(vec![]));
        for bad in ["", "a/b", "..", "proj*"] {
            let resp = sql_ping(
                Extension(ProjectContext("exampleorg".into())),
                Extension(Some(op.clone())),
                Path(bad.into()),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "db {bad:?} should be rejected with 422"
            );
        }
        // A valid `{db}` passes the screen (reaches the handler; here `default` pings
        // the fake op and returns 200 with no replicas).
        let resp = sql_ping(
            Extension(ProjectContext("exampleorg".into())),
            Extension(Some(op)),
            Path(boatramp_core::project::DEFAULT_DB_NAME.into()),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a valid db passes the screen"
        );
    }

    #[tokio::test]
    async fn empty_db_name_422_body_carries_the_cure() {
        // The empty `{db}` (the common v0.5.0 upgrade snag — the legacy default was keyed
        // by `""`) is rejected `422` with the canonical reason PLUS a one-line cure
        // pointing at the new `default` name, so an operator is told the fix in the body.
        let resp = reject_invalid_db("").expect("empty db is rejected");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let body = String::from_utf8(bytes.to_vec()).expect("utf8 body");
        assert!(
            body.contains(boatramp_core::project::EMPTY_DB_NAME_CURE),
            "empty-name 422 body must carry the cure, got: {body}"
        );

        // A different invalid name is still `422`, but WITHOUT the empty-name cure — it
        // keeps the plain canonical reason.
        let resp = reject_invalid_db("a/b").expect("`a/b` is rejected");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let body = String::from_utf8(bytes.to_vec()).expect("utf8 body");
        assert!(
            !body.contains(boatramp_core::project::EMPTY_DB_NAME_CURE),
            "a non-empty invalid name must not carry the empty-name cure, got: {body}"
        );
        // …it carries the v0.7.0 slug cure instead (pointing at `project doctor`).
        assert!(
            body.contains(boatramp_core::project::INVALID_NAME_CURE),
            "a non-empty invalid name must carry the v0.7.0 slug cure, got: {body}"
        );
    }

    /// `POST /api/sql-move` end-to-end at the handler: a real local libsql backend, a
    /// successful move (200 + `{status, from, to, integrity}`), an invalid name (422
    /// before any lookup), and no backend wired (501).
    #[tokio::test]
    async fn sql_move_relocates_locally_and_reports_json() {
        use boatramp_core::sql::{SqlBackends, SqlValue};
        let dir = std::env::temp_dir().join(format!("boatramp-sqlmove-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let backends = Arc::new(boatramp_storage::LibsqlSqlBackends::local(&dir));
        // Seed the default database via the empty spelling.
        let db = backends.database("default", "blog", "").await.unwrap();
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute("CREATE TABLE t (v TEXT)", &[]).await.unwrap();
            tx.execute("INSERT INTO t VALUES ('x')", &[]).await.unwrap();
            tx.commit().await.unwrap();
        }
        let sql: Arc<dyn SqlBackends> = backends.clone();

        // Invalid destination name → 422, before any move.
        let resp = sql_move(
            Extension(Some(sql.clone())),
            Json(SqlMoveRequest {
                project: "default".into(),
                site: "blog".into(),
                from: "default".into(),
                to: "a/b".into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // Valid move (default → analytics) → 200 with the JSON report.
        let resp = sql_move(
            Extension(Some(sql.clone())),
            Json(SqlMoveRequest {
                project: "default".into(),
                site: "blog".into(),
                from: "default".into(),
                to: "analytics".into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["status"], "moved");
        assert_eq!(body["integrity"], "ok");
        // The report echoes the resolved (project, site) so an operator sees which
        // site's default was relocated, not only the filesystem paths.
        assert_eq!(body["project"], "default");
        assert_eq!(body["site"], "blog");
        assert!(body["to"].as_str().unwrap().ends_with("blog/analytics.db"));

        // The data landed at the destination, and the source is gone.
        let moved = backends
            .database("default", "blog", "analytics")
            .await
            .unwrap();
        let mut tx = moved.begin().await.unwrap();
        let rows = tx.query("SELECT v FROM t", &[]).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(rows.rows[0][0], SqlValue::Text("x".into()));
        assert!(!dir.join("blog.db").exists());

        // No SQL data plane wired → 501.
        let resp = sql_move(
            Extension(None),
            Json(SqlMoveRequest {
                project: "default".into(),
                site: "blog".into(),
                from: "default".into(),
                to: "analytics".into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);

        let _ = std::fs::remove_dir_all(&dir);
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

    // ---- Streaming-clone orchestration (plan-only dry-run + apply progress) ----

    /// A fake clone capability: records whether `import` ran, and reports exactly the member paths
    /// in `present` from `clone_blobs_present` (standing in for the real scope-enforcing diff).
    struct FakeCloneCap {
        present: std::collections::BTreeSet<String>,
        imported: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl boatramp_core::project_export::ProjectExport for FakeCloneCap {
        async fn export(
            &self,
            _project: &str,
            _opts: &boatramp_core::project_export::ExportOptions,
            _sink: &mut (dyn futures::io::AsyncWrite + Send + Unpin),
        ) -> Result<(), boatramp_core::project_export::ProjectExportError> {
            Err(boatramp_core::project_export::ProjectExportError::Other(
                "export not used in this test".into(),
            ))
        }

        async fn import(
            &self,
            _project: &str,
            src: &mut (dyn futures::io::AsyncRead + Send + Unpin),
            _opts: boatramp_core::project_export::ImportOptions,
        ) -> Result<
            boatramp_core::project_export::ImportReport,
            boatramp_core::project_export::ProjectExportError,
        > {
            use futures::io::AsyncReadExt;
            let mut buf = Vec::new();
            let _ = src.read_to_end(&mut buf).await; // drain the stream the orchestrator opened
            self.imported
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(boatramp_core::project_export::ImportReport {
                blobs: 2,
                kv_records: 5,
                ..Default::default()
            })
        }

        async fn clone_blobs_present(
            &self,
            _project: &str,
            _source_project: &str,
            blobs: &[boatramp_core::project_export::CloneBlobRef],
        ) -> Result<
            boatramp_core::project_export::CloneSkip,
            boatramp_core::project_export::ProjectExportError,
        > {
            let mut skip = boatramp_core::project_export::CloneSkip::default();
            for b in blobs {
                if self.present.contains(&b.member_path) {
                    skip.skip_member_paths.insert(b.member_path.clone());
                }
            }
            Ok(skip)
        }
    }

    /// A mock clone transport that records whether `open_stream` was ever called — the proof the
    /// dry-run never opens the source stream.
    struct MockCloneSource {
        manifest: boatramp_core::project_export::CloneManifest,
        opened: Arc<std::sync::atomic::AtomicBool>,
        bundle: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl CloneSourceTransport for MockCloneSource {
        async fn fetch_manifest(
            &self,
        ) -> Result<boatramp_core::project_export::CloneManifest, CloneTransportError> {
            Ok(self.manifest.clone())
        }
        async fn open_stream(
            &self,
            _skip: &boatramp_core::project_export::CloneSkip,
        ) -> Result<Box<dyn futures::io::AsyncRead + Send + Unpin>, CloneTransportError> {
            self.opened.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(Box::new(futures::io::Cursor::new(self.bundle.clone())))
        }
    }

    fn clone_test_manifest() -> boatramp_core::project_export::CloneManifest {
        use boatramp_core::project_export::{CloneBlobRef, CloneManifest};
        CloneManifest {
            source_project: "acme".into(),
            data_only: false,
            blobs: vec![
                CloneBlobRef {
                    member_path: "blobs/hblob/acme/web/c/a".into(),
                    size: Some(100),
                    etag: None,
                },
                CloneBlobRef {
                    member_path: "blobs/hblob/acme/web/c/b".into(),
                    size: Some(200),
                    etag: None,
                },
            ],
            non_blob_members: vec!["sql/app.pgc".into()],
        }
    }

    /// FIX 1 gate: the DEFAULT dry-run (`apply=false`, `verify=false`) returns the cheap PLAN and
    /// NEVER opens the source stream or imports — the plan is a projection of the SAME diff the
    /// apply path runs (`clone_blobs_present`), not a cheaper shortcut that skips a scope check.
    #[tokio::test]
    async fn clone_dry_run_returns_plan_without_opening_stream_or_importing() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let imported = Arc::new(AtomicBool::new(false));
        let opened = Arc::new(AtomicBool::new(false));
        let cap: Arc<dyn boatramp_core::project_export::ProjectExport> = Arc::new(FakeCloneCap {
            present: ["blobs/hblob/acme/web/c/a".to_string()]
                .into_iter()
                .collect(),
            imported: imported.clone(),
        });
        let transport: Arc<dyn CloneSourceTransport> = Arc::new(MockCloneSource {
            manifest: clone_test_manifest(),
            opened: opened.clone(),
            bundle: b"UNUSED on a dry-run".to_vec(),
        });

        let resp = orchestrate_clone(
            cap,
            "acme".into(),
            "acme".into(),
            transport,
            false, // apply
            false, // verify
            false, // overwrite
            false, // force
            CloneMismatchPolicy::default(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let plan: boatramp_core::project_export::ClonePlan =
            serde_json::from_value(body_json(resp).await).expect("body is a ClonePlan");
        assert_eq!(plan.source_project, "acme");
        assert_eq!(plan.target_project, "acme");
        assert_eq!(plan.blobs_total, 2);
        assert_eq!(plan.blobs_present, 1);
        assert_eq!(plan.blobs_to_transfer, 1);
        assert_eq!(plan.bytes_to_transfer, 200); // `b` only; the present `a`'s 100 is not counted
        assert!(plan.bytes_exact);
        assert_eq!(plan.non_blob_members, vec!["sql/app.pgc".to_string()]);

        assert!(
            !opened.load(Ordering::SeqCst),
            "a dry-run must NOT open the source stream"
        );
        assert!(
            !imported.load(Ordering::SeqCst),
            "a dry-run must NOT import/restore"
        );
    }

    /// FIX 3 gate: `apply` opens the stream, imports, and returns the NDJSON progress channel — a
    /// `plan` event first, then a terminal `report` event — so a long clone is never zero-output.
    #[tokio::test]
    async fn clone_apply_streams_plan_then_report_and_imports() {
        use boatramp_core::project_export::CloneEvent;
        use std::sync::atomic::{AtomicBool, Ordering};
        let imported = Arc::new(AtomicBool::new(false));
        let opened = Arc::new(AtomicBool::new(false));
        let cap: Arc<dyn boatramp_core::project_export::ProjectExport> = Arc::new(FakeCloneCap {
            present: std::collections::BTreeSet::new(),
            imported: imported.clone(),
        });
        let transport: Arc<dyn CloneSourceTransport> = Arc::new(MockCloneSource {
            manifest: clone_test_manifest(),
            opened: opened.clone(),
            bundle: b"a small fake bundle body".to_vec(),
        });

        let resp = orchestrate_clone(
            cap,
            "acme".into(),
            "acme".into(),
            transport,
            true,  // apply
            false, // verify
            false, // overwrite
            false, // force
            CloneMismatchPolicy::default(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/x-ndjson"),
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read ndjson body");
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        let events: Vec<CloneEvent> = text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("each line is a CloneEvent"))
            .collect();
        assert!(
            matches!(events.first(), Some(CloneEvent::Plan(_))),
            "the first NDJSON event is the plan: {events:?}"
        );
        assert!(
            matches!(events.last(), Some(CloneEvent::Report(_))),
            "the last NDJSON event is the terminal report: {events:?}"
        );
        assert!(
            opened.load(Ordering::SeqCst),
            "apply opens the source stream"
        );
        assert!(imported.load(Ordering::SeqCst), "apply imports/restores");
    }

    /// A manifest naming a DIFFERENT project than the operator asked to clone is refused
    /// fail-closed BEFORE any diff/stream (the source is never trusted to answer for another
    /// project).
    #[tokio::test]
    async fn clone_refuses_a_manifest_for_a_different_project() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let imported = Arc::new(AtomicBool::new(false));
        let opened = Arc::new(AtomicBool::new(false));
        let cap: Arc<dyn boatramp_core::project_export::ProjectExport> = Arc::new(FakeCloneCap {
            present: std::collections::BTreeSet::new(),
            imported: imported.clone(),
        });
        let mut manifest = clone_test_manifest();
        manifest.source_project = "evil".into(); // the source answers for a different project
        let transport: Arc<dyn CloneSourceTransport> = Arc::new(MockCloneSource {
            manifest,
            opened: opened.clone(),
            bundle: Vec::new(),
        });

        let resp = orchestrate_clone(
            cap,
            "acme".into(),
            "acme".into(),
            transport,
            true,
            false,
            false,
            false,
            CloneMismatchPolicy::default(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert!(
            !opened.load(Ordering::SeqCst),
            "a wrong-project manifest never opens the stream"
        );
        assert!(
            !imported.load(Ordering::SeqCst),
            "a wrong-project manifest never imports"
        );
    }
}
