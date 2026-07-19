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
    Path((site, id)): Path<(String, String)>,
) -> Response {
    // Activation compile-gate: a deploy whose handlers the
    // site can't satisfy, or whose components don't compile, must not flip.
    match deploy.get_manifest(&id).await {
        Ok(Some(manifest)) => {
            let site_config = match deploy.get_site_config(&site).await {
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
    match deploy.activate(&site, &id).await {
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
    Path(site): Path<String>,
) -> Response {
    match deploy.current_id(&site).await {
        Ok(deployment) => Json(CurrentResponse { site, deployment }).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// List a site's deployment history (most recent first), with the current id.
pub(super) async fn list_deployments(
    State(deploy): State<DeployStore>,
    Path(site): Path<String>,
) -> Response {
    match deploy.deployments(&site).await {
        Ok(list) => Json(list).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Get a site's [`SiteConfig`] (defaults if unset).
/// `GET /api/sites` — every known site name (admin-scoped). Backs the web UI /
/// tooling site navigation.
pub(super) async fn list_sites(State(deploy): State<DeployStore>) -> Response {
    match deploy.all_sites().await {
        Ok(sites) => Json(sites).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

pub(super) async fn get_site_config(
    State(deploy): State<DeployStore>,
    Path(site): Path<String>,
) -> Response {
    match deploy.get_site_config(&site).await {
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
    Path(site): Path<String>,
) -> Response {
    match deploy.delete_site(&site).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Canonicalize a site-config domain entry for the verify-gate diff: fold case
/// and any trailing dot, but keep an exact host distinct from a `*.` wildcard
/// (they are different routing entities that must not collapse together).
fn canon_domain_entry(host: &str) -> String {
    match host.strip_prefix("*.") {
        Some(base) => format!(
            "*.{}",
            base.trim().trim_end_matches('.').to_ascii_lowercase()
        ),
        None => host.trim().trim_end_matches('.').to_ascii_lowercase(),
    }
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
    Path(site): Path<String>,
    Json(config): Json<SiteConfig>,
) -> Response {
    let current = match deploy.get_site_config(&site).await {
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
        let verification = match deploy.get_domain_verification(&site, &host).await {
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
    match deploy.set_site_config(&site, &config).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
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
pub(super) async fn list_compute(State(deploy): State<DeployStore>) -> Response {
    match deploy.list_compute_workloads().await {
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
    Path(name): Path<String>,
) -> Response {
    match deploy.get_compute_workload(&name).await {
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
    Path(name): Path<String>,
    Json(mut request): Json<PutComputeRequest>,
) -> Response {
    // A workload that omits its kernel uses the node's fleet **default kernel**
    // (from dynamic daemon config). Substituted at set time; the kernel is
    // verified against the posture bar at boot. No kernel and no default ⇒ a clear
    // error rather than a cryptic backend failure.
    if request.spec.kernel.is_empty() {
        match daemon.effective().default_kernel.as_ref() {
            Some(k) => request.spec.kernel = k.source.clone(),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    "workload has no kernel and no default kernel is configured; set one \
                     with `boatramp config set compute.default_kernel …`\n",
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
    match deploy.set_compute_workload(&workload).await {
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
    Path(name): Path<String>,
) -> Response {
    match deploy.delete_compute_workload(&name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such workload\n").into_response(),
        Err(err) => deploy_error_response(err),
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
    Path((site, name)): Path<(String, String)>,
    Json(request): Json<SetAliasRequest>,
) -> Response {
    match deploy.set_alias(&site, &name, &request.id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// List a site's named aliases (`name → deployment id`).
pub(super) async fn list_aliases(
    State(deploy): State<DeployStore>,
    Path(site): Path<String>,
) -> Response {
    match deploy.list_aliases(&site).await {
        Ok(map) => Json(map).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Remove a named alias.
pub(super) async fn remove_alias(
    State(deploy): State<DeployStore>,
    Path((site, name)): Path<(String, String)>,
) -> Response {
    match deploy.remove_alias(&site, &name).await {
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
}
