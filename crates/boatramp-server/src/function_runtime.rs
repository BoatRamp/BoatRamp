//! The function runtime surface (FA-3..FA-5): synchronous and asynchronous
//! invocation, the durable async-queue drain, per-function metering and quota
//! admission, trigger configuration, and the webhook/queue/blob event dispatch
//! that fans incoming events into invocations. `handlers`-gated; pulls the
//! serve-pipeline scope in via `use super::*`.

use super::*;

use boatramp_core::project::ProjectRef;

/// How the in-site tenant is sourced for one function invocation (Stage 0). Chosen by the entry
/// point: an HTTP invoke trusts its inbound request; an in-project invoke inherits the caller's
/// host-resolved tenant (never the guest's invoke request); background triggers have no trusted
/// source (an `own` op then fails closed).
#[cfg(feature = "handlers")]
pub(super) enum FnTenant {
    /// A trusted inbound HTTP request — resolve from its verified bearer + routed domain tag.
    Request,
    /// Inherit the caller's host-resolved **principal** (the axis-tagged fact set) down an
    /// in-project invoke chain — so an inherited `Session`/`TargetTenant` fact keeps its axis, not
    /// just the `Tenant` value. Empty ⇒ no inherited principal. In-process only; never serialized.
    Inherited(Vec<boatramp_handlers::ScopeFact>),
    /// The **durable async lane** (Stage 4): a queue/bus drain carrying an optional host-minted
    /// [signed-context envelope](boatramp_core::cose::mint_context) stamped at publish from the
    /// producer's own-tenant. A consumer declaring `sources: [signed_context]` resolves that tenant
    /// (verified against the fleet anchor); `None` (or a forged/expired envelope) ⇒ no own tenant,
    /// so an "own" op fails closed. The value crosses the durability boundary **only** as this
    /// signed, host-issued envelope — never a guest-named tenant.
    Durable(Option<String>),
    /// A **host-forced target-tenant** binding (R4/D8 wasm-plane, Gap 1): the federation gateway
    /// resolved another tenant `B`'s public-subset confinement for a `Target`-class fetch and forces
    /// it onto this (wasm subgraph) invocation. The provided [`HostTenancy`] already has the project
    /// schema baked into its `PerTableTarget` keys, so it is used verbatim (no `with_schema`) — the
    /// callee's own declared tenancy is bypassed (the SDL field's class is the authority). `B` is
    /// host-derived (domain / verified capability / handle), NEVER guest input. In-process only.
    ForcedTarget(boatramp_handlers::HostTenancy),
    /// No trusted source (cron / webhook / SDL introspection) and no durable context.
    Background,
}

/// SECURITY (S1/S2): the capability context for a **migration step** invocation. Its presence is the
/// HARD structural gate that (a) attaches the owner-role `migrate-ddl` capability and (b) applies the
/// tenant-`sql` binding-split — a migration invocation gets a KNOWN-MINIMAL binding set
/// (kv/blob/logging/env + migrate-ddl), never the tenant `sql`/`orm`/messaging/admin/… grants, so a
/// function that disables RLS via owner-DDL has no tenant binding to then read cross-tenant through.
///
/// It is a SEPARATE context flag, not a [`FnTenant`] variant (Backend A2): the migration function's
/// tenant is irrelevant — all its DB work runs at owner altitude via `migrate-ddl`. It is
/// constructible ONLY on the `Project·Admin` migration orchestrator path ([`crate::migrate`]) — never
/// from a request/consumer/cron trigger — so owner-DDL is unreachable outside an owner-authenticated
/// migration run. Carries the owner-DDL seam the host runs each `migrate::exec` on.
#[cfg(feature = "handlers")]
pub(crate) struct MigrationContext {
    /// The orchestrator-owned owner-role DDL seam for this `(project, db)`.
    pub ddl: std::sync::Arc<dyn boatramp_core::sql::MigrateDdl>,
}

/// The authority the engine sees for an invoked function. `wasi:http` needs a
/// scheme + authority; the public control-plane path is the host's concern, so
/// every function is invoked at `http://function.invoke/`.
#[cfg(feature = "handlers")]
const INVOKE_AUTHORITY: &str = "function.invoke";

/// Attempts a durable (async) invocation gets before it is dead-lettered
/// (left terminal-`failed` in its keyspace for inspection).
#[cfg(feature = "handlers")]
const MAX_INVOKE_ATTEMPTS: u32 = 5;

/// Grace added to the async ceiling when stamping a claimed invocation's lease.
/// The lease elapses only after the whole ceiling *plus* this margin, so it can
/// never expire under a legitimately long run — only after a real crash — while
/// keeping the crash-recovery window bounded (ceiling + margin).
#[cfg(feature = "handlers")]
const LEASE_MARGIN_SECS: u64 = 60;

/// Max request body buffered when **enqueuing** an async invocation. The sync
/// path streams into the guest and never buffers; async must persist the body,
/// so it is bounded here (mirrors the engine's default body cap).
#[cfg(feature = "handlers")]
const MAX_ASYNC_BODY_BYTES: usize = 16 * 1024 * 1024;

/// TTL for a durable signed-context envelope (R1). It must outlive a message's *automatic*
/// residency — publish, lease, up to `MAX_INVOKE_ATTEMPTS` redeliveries, and a backlog drain — but
/// no longer, because it also bounds how long a captured envelope can be replayed and how stale a
/// resolved tenant may be after off-boarding (a de-provisioned tenant's in-flight envelope stops
/// resolving at expiry). 48 hours comfortably covers automatic residency plus a multi-day backlog
/// while keeping that replay/staleness window tight (a deliberate ~15× cut from a naive 30-day
/// horizon). Past expiry the consumer resolves no own tenant and fails an "own" op closed; an
/// operator redrive after expiry likewise fails closed (never a cross-tenant widening).
#[cfg(feature = "handlers")]
const DURABLE_CONTEXT_TTL_SECS: u64 = 48 * 3600;

/// Mint a durable signed-context envelope (R1) from the producer's resolved **own-tenant**, so a
/// message it publishes carries that tenant across the durability boundary for a consumer that
/// declares `sources: [signed_context]`. The guest never names a tenant — the host stamps its
/// already-resolved principal. `None` (⇒ the message carries no context, and the consumer fails an
/// "own" op closed) when there is no fleet signer, no own-tenant fact, or a non-stampable value.
///
/// TRUST MODEL (same-project bus): the envelope binds the producer's **tenant**, not the topic or
/// the producing component. A project is one trust domain (its owner deploys all its components),
/// so on the shared `{project}/bus/` a consumer declaring `signed_context` acts as **whatever
/// tenant published the message it drains** — correct within a project, and cross-*project* is
/// structurally impossible (the bus keyspace is `{project}/bus/`, project names are `/`-free). A
/// consumer author therefore opts into "act as the producer's tenant"; a project that deploys
/// mutually-distrusting components onto one bus topic should not use `signed_context` there.
#[cfg(feature = "handlers")]
pub(super) async fn mint_producer_context(
    inner: &HandlerRuntimeInner,
    principal: &[boatramp_handlers::ScopeFact],
) -> Option<String> {
    let signer = inner.session_signer.get()?;
    let tenant = principal
        .iter()
        .find(|f| f.axis == boatramp_core::tenancy::ScopeAxis::Tenant)
        .and_then(|f| ctx_stamp(&f.value))?;
    boatramp_core::cose::mint_context(
        &tenant,
        DURABLE_CONTEXT_TTL_SECS,
        now_unix(),
        signer.as_ref(),
    )
    .await
    .ok()
}

/// Render an own-tenant [`SqlValue`](boatramp_core::sql::SqlValue) to the string a durable context
/// envelope carries. A tenant id is always a scalar; only a scalar is stampable (the consumer
/// resolves it back as text). A non-scalar tenant value is not stamped ⇒ the async lane fails
/// closed rather than carrying an ambiguous key.
#[cfg(feature = "handlers")]
fn ctx_stamp(value: &boatramp_core::sql::SqlValue) -> Option<String> {
    use boatramp_core::sql::SqlValue;
    match value {
        SqlValue::Text(s) => Some(s.clone()),
        SqlValue::Integer(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The PLAIN resolved own-tenant value of a principal, as a string — the literal tenant segment an
/// app uses (NOT the COSE-signed durable envelope [`mint_producer_context`] mints). Used to fill the
/// `{tenant}` placeholder in a `messaging-stats` bus-topic template with the SAME tenant the SQL scope
/// injector resolved. `None` for an unscoped/anonymous invocation or a non-scalar tenant value — a
/// `{tenant}` template is then refused (the stats binding fails closed). The guest never supplies it.
#[cfg(feature = "handlers")]
pub(super) fn resolved_tenant_string(principal: &[boatramp_handlers::ScopeFact]) -> Option<String> {
    principal
        .iter()
        .find(|f| f.axis == boatramp_core::tenancy::ScopeAxis::Tenant)
        .and_then(|f| ctx_stamp(&f.value))
}

/// The tenant claim a component's `token` source names (Gap 3) — the first `TenantSource::Token`
/// in a `Scoped` tenancy decision. `None` when the component declares no token source (so
/// `present-token` has nothing to verify against → deny-by-default).
#[cfg(feature = "handlers")]
pub(crate) fn token_source_claim(
    decision: Option<&boatramp_core::tenancy::Tenancy>,
) -> Option<String> {
    match decision {
        Some(boatramp_core::tenancy::Tenancy::Scoped { sources, .. }) => {
            sources.iter().find_map(|s| match s {
                boatramp_core::tenancy::TenantSource::Token { claim } => Some(claim.clone()),
                _ => None,
            })
        }
        _ => None,
    }
}

/// The server's [`ProducerContextSource`](boatramp_handlers::ProducerContextSource) (Gap 3): the
/// verify-and-seal seam behind the guest `tenancy::present-token`. The guest presents a credential
/// it verified in-guest; the HOST re-verifies it against the component's operator-declared
/// `token_claims` (JWKS / issuer / audience / expiry) — never trusting the guest — extracts the
/// tenant claim (the `claim` named by the component's `token` source), and mints the SAME
/// host-sealed durable context [`mint_producer_context`] produces from a host-resolved principal. So
/// a guest can only cause a stamp for a tenant it holds a validly-signed token for from the
/// configured issuer; it can never NAME an arbitrary tenant.
#[cfg(feature = "handlers")]
pub(crate) struct ServerProducerContextSource {
    /// The JWKS/issuer/audience config verifying the presented credential (the component's own).
    pub(crate) token_cfg: boatramp_core::config::HandlerGraphqlTokenClaims,
    /// The claim carrying the tenant id (from the component's `TenantSource::Token { claim }`).
    pub(crate) claim: String,
    /// The fleet signer that seals the durable context (the same key session cookies use).
    pub(crate) signer: Arc<dyn boatramp_core::cose::Signer>,
}

#[cfg(feature = "handlers")]
#[async_trait::async_trait]
impl boatramp_handlers::ProducerContextSource for ServerProducerContextSource {
    async fn seal_presented(&self, token: &str) -> Result<String, String> {
        // Verification pulls the JWKS verifier (behind `oidc`). Without it the async-lane stamp
        // can't verify a presented token, so it fails closed (mirrors the request-path `token`
        // source), never trusting the guest.
        #[cfg(feature = "oidc")]
        {
            let claims = crate::graphql_data::token::verified_claims(&self.token_cfg, token)
                .await
                .ok_or_else(|| "presented token did not verify".to_string())?;
            let value = claims
                .get(&self.claim)
                .and_then(crate::tenant_resolve::scalar_to_sql)
                .ok_or_else(|| {
                    format!("presented token carries no `{}` tenant claim", self.claim)
                })?;
            let tenant =
                ctx_stamp(&value).ok_or_else(|| "tenant claim is not a scalar".to_string())?;
            boatramp_core::cose::mint_context(
                &tenant,
                DURABLE_CONTEXT_TTL_SECS,
                now_unix(),
                self.signer.as_ref(),
            )
            .await
            .map_err(|e| e.to_string())
        }
        #[cfg(not(feature = "oidc"))]
        {
            // Without `oidc` there is no JWKS verifier, so a presented token can't be verified —
            // fail closed. Reference the fields so a handlers-without-oidc build doesn't flag them
            // dead (they're only read on the `oidc` verify path above).
            let _ = (token, &self.token_cfg, &self.claim, &self.signer);
            Err("token verification is unavailable in this build (no `oidc`)".to_string())
        }
    }
}

/// Query of `POST /api/functions/:name/invoke`.
#[cfg(feature = "handlers")]
#[derive(serde::Deserialize)]
pub(super) struct InvokeQuery {
    /// Delivery mode: `sync` (default) or `async`.
    #[serde(default)]
    mode: Option<String>,
    /// Which version/alias to invoke (defaults to the active version).
    #[serde(default)]
    version: Option<String>,
}

/// A random 16-byte invocation id, hex, from the OS CSPRNG (the same source the
/// token layer draws its `cti` from). A CSPRNG failure implies a broken platform
/// and is logged; it is not expected on our targets.
#[cfg(feature = "handlers")]
pub(super) fn new_invocation_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        tracing::error!("getrandom failed generating an invocation id");
    }
    hex::encode(bytes)
}

/// `POST /api/functions/:name/invoke` (FA-3) — invoke a function.
///
/// `?mode=sync` (default) runs inline and returns the function's response.
/// `?mode=async` durably enqueues the call and returns `202 Accepted` with an
/// invocation id to poll at `/invocations/:id`; a drain worker runs it (retried,
/// then dead-lettered). An `Idempotency-Key` header dedups: a repeat with the
/// same key replays the first call's outcome instead of running again.
/// `system·admin` (a finer per-function invoke right lands in FA-4).
#[cfg(feature = "handlers")]
pub(super) async fn invoke_function(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(name): Path<String>,
    axum::extract::Query(query): axum::extract::Query<InvokeQuery>,
    request: Request,
) -> Response {
    let Some(inner) = handlers.inner.as_ref() else {
        return handler_unavailable();
    };
    let function = match deploy.get_function(project.as_ref(), &name).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, format!("no function {name:?}\n")).into_response()
        }
        Err(err) => return deploy_error_response(err),
    };
    let reference = query.version.as_deref().unwrap_or(&function.active);
    let Some(component) = function.resolve(reference).map(str::to_owned) else {
        return (
            StatusCode::NOT_FOUND,
            format!("no version {reference:?} in function {name:?}\n"),
        )
            .into_response();
    };
    let is_async = query.mode.as_deref() == Some("async");
    let idem_key = request
        .headers()
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // Idempotency replay: a recorded key returns the first call's outcome (its
    // captured result, or `202` + id while the async call is still in flight).
    // Checked *before* the quota so a replay never spends the rate budget.
    if let Some(key) = &idem_key {
        match deploy.get_idempotency(project.as_ref(), &name, key).await {
            Ok(Some(id)) => {
                if let Ok(Some(inv)) = deploy.get_invocation(project.as_ref(), &name, &id).await {
                    return replay_invocation(&inv);
                }
            }
            Ok(None) => {}
            Err(err) => return deploy_error_response(err),
        }
    }

    // Rate-limit quota (FA-4), fail-closed → 429, charged once at entry for both
    // sync and async (a drain retry does not re-charge).
    if let Err(response) = admit_by_quota(inner, &deploy, project.as_ref(), &function).await {
        return response;
    }

    if is_async {
        enqueue_invocation(
            &deploy,
            project.as_ref(),
            &function,
            &component,
            request,
            idem_key,
        )
        .await
    } else {
        execute_sync(
            inner,
            &deploy,
            project.as_ref(),
            &function,
            &component,
            request,
            idem_key,
        )
        .await
    }
}

/// Run a function inline and return its response. With an idempotency key the
/// response is captured + persisted (as a `succeeded` [`Invocation`]) so a repeat
/// replays it; without one it streams straight back.
#[cfg(feature = "handlers")]
async fn execute_sync(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    project: ProjectRef<'_>,
    function: &boatramp_core::function::Function,
    component: &str,
    request: Request,
    idem_key: Option<String>,
) -> Response {
    let (response, duration_ms) = execute_function(
        inner,
        deploy,
        project,
        function,
        component,
        request,
        0,
        boatramp_handlers::Lane::Sync,
        // Top-level HTTP invoke (depth 0): trust the inbound request's verified bearer + routed
        // domain tag as the tenant source. Sibling invokes go through FunctionInvoker (inherited).
        FnTenant::Request,
    )
    .await;
    let Some(key) = idem_key else {
        // No capture on the plain streaming path: meter counts + duration + a
        // head-status success signal (byte totals are metered on the buffered
        // async / idempotent paths).
        let sample = boatramp_core::function::MeteringSample {
            success: response.status().as_u16() < 500,
            duration_ms,
            bytes_in: 0,
            bytes_out: 0,
        };
        record_metering(inner, deploy, project, &function.name, &sample).await;
        return response;
    };
    // Capture so the outcome can be replayed under the idempotency key.
    let (status, content_type, body) = capture_response(response).await;
    let sample = boatramp_core::function::MeteringSample {
        success: status.as_u16() < 500,
        duration_ms,
        bytes_in: 0,
        bytes_out: body.len() as u64,
    };
    record_metering(inner, deploy, project, &function.name, &sample).await;
    let now = now_unix();
    let id = new_invocation_id();
    let inv = boatramp_core::function::Invocation {
        id: id.clone(),
        function: function.name.clone(),
        version: component.to_string(),
        mode: boatramp_core::function::InvokeMode::Sync,
        status: boatramp_core::function::InvocationStatus::Succeeded,
        idempotency_key: Some(key.clone()),
        attempts: 1,
        lease_expires: None,
        request_b64: None,
        request_content_type: None,
        result: Some(boatramp_core::function::InvocationResult {
            status: status.as_u16(),
            content_type: content_type.clone(),
            body_b64: b64_encode(&body),
        }),
        created: now,
        updated: now,
    };
    if let Err(err) = deploy.put_invocation(project, &inv).await {
        return deploy_error_response(err);
    }
    if let Err(err) = deploy
        .put_idempotency(project, &function.name, &key, &id)
        .await
    {
        return deploy_error_response(err);
    }
    rebuild_response(status, content_type.as_deref(), body)
}

/// Durably enqueue an async invocation: buffer the request body, persist a
/// `queued` [`Invocation`], bind the idempotency key, and return `202` + id.
#[cfg(feature = "handlers")]
async fn enqueue_invocation(
    deploy: &DeployStore,
    project: ProjectRef<'_>,
    function: &boatramp_core::function::Function,
    component: &str,
    request: Request,
    idem_key: Option<String>,
) -> Response {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = match axum::body::to_bytes(request.into_body(), MAX_ASYNC_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "async invoke body exceeds the buffer cap\n",
            )
                .into_response()
        }
    };
    let now = now_unix();
    let id = new_invocation_id();
    let inv = boatramp_core::function::Invocation {
        id: id.clone(),
        function: function.name.clone(),
        version: component.to_string(),
        mode: boatramp_core::function::InvokeMode::Async,
        status: boatramp_core::function::InvocationStatus::Queued,
        idempotency_key: idem_key.clone(),
        attempts: 0,
        lease_expires: None,
        request_b64: (!body.is_empty()).then(|| b64_encode(&body)),
        request_content_type: content_type,
        result: None,
        created: now,
        updated: now,
    };
    if let Err(err) = deploy.put_invocation(project, &inv).await {
        return deploy_error_response(err);
    }
    if let Some(key) = &idem_key {
        if let Err(err) = deploy
            .put_idempotency(project, &function.name, key, &id)
            .await
        {
            return deploy_error_response(err);
        }
    }
    (StatusCode::ACCEPTED, Json(inv)).into_response()
}

/// `GET /api/functions/:name/invocations/:id` (FA-3) — poll a durable
/// invocation's status/result. `system·read`.
#[cfg(feature = "handlers")]
pub(super) async fn get_invocation_record(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path((name, id)): Path<(String, String)>,
) -> Response {
    match deploy.get_invocation(project.as_ref(), &name, &id).await {
        Ok(Some(inv)) => Json(inv).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            format!("no invocation {id:?} for function {name:?}\n"),
        )
            .into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Reconstruct a `Response` for an idempotency replay / async poll shortcut: a
/// completed invocation replays its captured result; one still in flight returns
/// `202` + the record.
#[cfg(feature = "handlers")]
fn replay_invocation(inv: &boatramp_core::function::Invocation) -> Response {
    match &inv.result {
        Some(result) => {
            let body = b64_decode(&result.body_b64);
            rebuild_response(
                StatusCode::from_u16(result.status).unwrap_or(StatusCode::OK),
                result.content_type.as_deref(),
                body,
            )
        }
        None => (StatusCode::ACCEPTED, Json(inv.clone())).into_response(),
    }
}

/// The core engine run: enforce the per-function concurrency quota, load the
/// component blob, build the function's bindings under its own `fn/<name>` scope,
/// and serve the request. Returns the response and its time-to-head in ms (for
/// metering). Errors map to the same statuses as a handler dispatch; a
/// `max_concurrent`-full function yields `503` (a retryable delivery failure for
/// the async drain).
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
pub(super) async fn execute_function(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    project: ProjectRef<'_>,
    function: &boatramp_core::function::Function,
    component: &str,
    request: Request,
    depth: u32,
    // Which engine lane to run in: `Sync` for a connection-bearing invoke
    // (tight ceiling, shared pool), `Async` for the durable drain / workflow
    // step (large ceiling, isolated pool). See [`boatramp_handlers::Lane`].
    lane: boatramp_handlers::Lane,
    // How the in-site tenant is sourced for this invocation (Stage 0).
    tenant: FnTenant,
) -> (Response, u64) {
    // Concurrency quota (held through the head, mirroring the site permit).
    // Keyed by the **project-qualified** function identity so a same-named
    // function in another tenant can't starve this one's semaphore.
    let permit_key = project.qualified(&function.name);
    let _permit = match acquire_function_permit(inner, &permit_key, &function.config.quota) {
        Ok(permit) => permit,
        Err(()) => {
            return (
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "function concurrency limit reached\n",
                )
                    .into_response(),
                0,
            )
        }
    };
    let wasm = match read_blob_fully(deploy, component).await {
        Ok(bytes) => bytes,
        Err(response) => return (response, 0),
    };
    // Project-qualify the guest binding scope (BR-TEN-1): a same-named function
    // in two tenants must not share one kv/blob/messaging/logs namespace.
    // `default` → bare `fn/<name>` (byte-identical, back-compat).
    let fn_ident = format!("fn/{}", function.name);
    let scope = project.qualified(&fn_ident);
    // The SQL provider qualifies + validates `project` + `site` itself, so it
    // takes the *raw* `fn/<name>` identity (it composes the same `default →
    // fn/<name>`, `non-default → {project}/fn/<name>` the `scope` above carries)
    // — never the already-qualified `scope`, to avoid double-qualifying.
    // Stage 0 tenant source: a trusted HTTP request contributes its verified bearer + routed
    // domain tag; an in-project invoke carries the caller's resolved value; background has none.
    let (bearer, domain_context) = match tenant {
        FnTenant::Request => (
            request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| {
                    s.strip_prefix("Bearer ")
                        .or_else(|| s.strip_prefix("bearer "))
                })
                .map(str::to_string),
            request
                .extensions()
                .get::<crate::DomainContext>()
                .map(|c| c.0.clone()),
        ),
        _ => (None, None),
    };
    let bindings = match build_function_bindings(
        inner,
        project,
        &scope,
        &fn_ident,
        &function.config,
        depth,
        &tenant,
        bearer.as_deref(),
        domain_context.as_deref(),
        // Not a migration step — the normal (full, tenancy-resolved) binding path.
        None,
    )
    .await
    {
        Ok(bindings) => bindings,
        // A required managed database is still starting — gate with a retryable 503 + Retry-After
        // so a caller / migration probe waits, instead of running the function into a confusing
        // "not granted" (the managed-dependency readiness gate). Fail-closed.
        Err(super::handler_dispatch::BindingsError::NotReady {
            detail,
            retry_after_secs,
        }) => {
            tracing::info!(function = %function.name, %detail, "function not ready: managed database starting");
            return (sql_starting_response(retry_after_secs), 0);
        }
        // A refused secret ref (a host-env ref under the multi-tenant posture, or
        // an unsupported scheme) / a tenancy misconfiguration fails the invocation closed — the
        // function never runs with a leaked or missing value.
        Err(super::handler_dispatch::BindingsError::Refused(err)) => {
            tracing::warn!(function = %function.name, %err, "function bindings refused");
            return (handler_unavailable(), 0);
        }
    };
    let limits = function_limits(function.config.limits.as_ref());
    let request = prepare_invoke_request(request);
    let start = std::time::Instant::now();
    let result = match lane {
        boatramp_handlers::Lane::Sync => {
            inner
                .engine
                .serve_with_limits(component, &wasm, request, bindings, limits)
                .await
        }
        boatramp_handlers::Lane::Async => {
            inner
                .engine
                .serve_with_limits_async(component, &wasm, request, bindings, limits)
                .await
        }
        // Function invokes are Sync (synchronous call) or Async (durable); the streaming lane
        // is HTTP-handler-only. Handle it for exhaustiveness — it runs there correctly if a
        // streaming invoke path is ever added.
        boatramp_handlers::Lane::Streaming => {
            inner
                .engine
                .serve_with_limits_streaming(component, &wasm, request, bindings, limits)
                .await
        }
    };
    let elapsed = start.elapsed();
    inner.metrics.observe(
        &function.name,
        metrics::Trigger::Invoke,
        "invoke",
        component,
        metrics::Outcome::from_result(&result),
        elapsed,
    );
    let response = match result {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            axum::http::Response::from_parts(parts, axum::body::Body::new(body))
        }
        Err(err) => {
            tracing::warn!(function = %function.name, %err, "function invocation failed");
            handler_error_response(&err)
        }
    };
    (response, elapsed.as_millis() as u64)
}

/// Invoke a function as a **migration step** (Security S1/S2, Backend A4). A dedicated path — not
/// [`execute_function`] — because the migration invocation has distinct, security-load-bearing
/// semantics that must not leak into the normal invoke path:
///
/// - **Quota-exempt (A4):** it acquires NO per-function concurrency permit, so an admin migration
///   never `503`s under serving load (a migration is a control-plane op, not request traffic).
/// - **Migration bindings (S1/S2):** it passes a [`MigrationContext`] to `build_function_bindings`,
///   which force the owner-role `migrate-ddl` grant + the tenant-`sql` binding-split.
/// - **No request tenant:** the tenant source is `Background` — the function does all DB work at
///   owner altitude via `migrate-ddl`, never a request-derived tenant binding.
/// - **Async lane:** a migration can run long (external-source sync, big DDL); it uses the isolated
///   async pool with the large ceiling, like the durable drain.
///
/// `component` is the orchestrator-pinned blob hash (Backend A3), so a replay runs identical bytes.
/// Returns the guest's `Response` (its status distinguishes success from an author-returned / trap
/// failure) plus the elapsed ms.
#[cfg(all(feature = "handlers", feature = "migrate"))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_migration_function(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    project: ProjectRef<'_>,
    function: &boatramp_core::function::Function,
    component: &str,
    request: Request,
    ddl: std::sync::Arc<dyn boatramp_core::sql::MigrateDdl>,
) -> (Response, u64) {
    let wasm = match read_blob_fully(deploy, component).await {
        Ok(bytes) => bytes,
        Err(response) => return (response, 0),
    };
    let fn_ident = format!("fn/{}", function.name);
    let scope = project.qualified(&fn_ident);
    let ctx = MigrationContext { ddl };
    let bindings = match build_function_bindings(
        inner,
        project,
        &scope,
        &fn_ident,
        &function.config,
        0,
        &FnTenant::Background,
        None,
        None,
        Some(&ctx),
    )
    .await
    {
        Ok(bindings) => bindings,
        Err(super::handler_dispatch::BindingsError::NotReady {
            detail,
            retry_after_secs,
        }) => {
            tracing::info!(function = %function.name, %detail, "migration function not ready: managed database starting");
            return (sql_starting_response(retry_after_secs), 0);
        }
        Err(super::handler_dispatch::BindingsError::Refused(err)) => {
            tracing::warn!(function = %function.name, %err, "migration function bindings refused");
            return (handler_unavailable(), 0);
        }
    };
    let limits = function_limits(function.config.limits.as_ref());
    let request = prepare_invoke_request(request);
    let start = std::time::Instant::now();
    let result = inner
        .engine
        .serve_with_limits_async(component, &wasm, request, bindings, limits)
        .await;
    let elapsed = start.elapsed();
    inner.metrics.observe(
        &function.name,
        metrics::Trigger::Invoke,
        "migrate",
        component,
        metrics::Outcome::from_result(&result),
        elapsed,
    );
    let response = match result {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            axum::http::Response::from_parts(parts, axum::body::Body::new(body))
        }
        Err(err) => {
            tracing::warn!(function = %function.name, %err, "migration function invocation failed");
            handler_error_response(&err)
        }
    };
    (response, elapsed.as_millis() as u64)
}

/// Build a top-level function's bindings. Unlike a site handler (whose grants are
/// the site allowlist ∩ its imports), a top-level function is admin-deployed, so
/// its declared `imports` **are** its grants — served under its own `fn/<name>`
/// scope so kv/blob/messaging/sql land in an isolated namespace.
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
pub(super) async fn build_function_bindings(
    inner: &HandlerRuntimeInner,
    project: ProjectRef<'_>,
    scope: &str,
    sql_site: &str,
    config: &boatramp_core::function::FunctionConfig,
    depth: u32,
    tenant: &FnTenant,
    bearer: Option<&str>,
    domain_context: Option<&str>,
    // SECURITY (S1/S2): `Some` iff this is a `Project·Admin` migration-step invocation. It forces a
    // KNOWN-MINIMAL binding set (kv/blob/logging/env + owner-role `migrate-ddl`) and DROPS the tenant
    // `sql`/`orm` + every other grant — see [`MigrationContext`]. Constructible only on the
    // orchestrator path, so a normal request can never reach this branch.
    migration: Option<&MigrationContext>,
) -> Result<boatramp_handlers::Bindings, super::handler_dispatch::BindingsError> {
    use super::handler_dispatch::BindingsError;
    let granted = |name: &str| config.imports.iter().any(|i| i == name);
    let mut bindings = boatramp_handlers::Bindings::new(scope);

    // Migration-step early return (Security S1 binding-split): a migration invocation gets ONLY the
    // owner-role `migrate-ddl` capability plus the non-DB conveniences (kv/blob for staging an
    // external-source sync, logging, env). It is NOT given the tenant `sql`/`orm` binding — nor
    // messaging/email/admin/capability/invoke/graphql/session — so even if the function's owner-DDL
    // disables RLS on a table, it holds no tenant-scoped connection to read another tenant through.
    // `wasi:http` remains engine-level (for external-source sync). This explicit allowlist is the
    // auditable proof of S1 (gate MIGRATE-DDL RLS-INVARIANT OK).
    if let Some(_ctx) = migration {
        if granted("wasi:keyvalue") {
            bindings = bindings.with_keyvalue(scope, inner.kv.clone());
        }
        if granted("wasi:blobstore") {
            let max_blob = inner.max_blob_bytes.get().copied().unwrap_or(0);
            bindings = bindings.with_blobstore(scope, inner.storage.clone(), max_blob);
        }
        #[cfg(feature = "migrate")]
        {
            bindings = bindings.with_migrate(_ctx.ddl.clone());
        }
        inner.logs.configure(scope, None);
        bindings = bindings.with_logging(scope.to_string(), None, inner.logs.clone());
        let allow_env_secret_refs = inner.allow_env_secret_refs.get().copied().unwrap_or(false);
        let env = resolve_secret_env(
            scope,
            project,
            &config.env,
            &config.secrets,
            allow_env_secret_refs,
            inner.secret_store.get().map(std::convert::AsRef::as_ref),
        )
        .await?;
        return Ok(bindings.with_env(env));
    }

    if granted("wasi:keyvalue") {
        bindings = bindings.with_keyvalue(scope, inner.kv.clone());
    }
    if granted("wasi:blobstore") {
        let max_blob = inner.max_blob_bytes.get().copied().unwrap_or(0);
        bindings = bindings.with_blobstore(scope, inner.storage.clone(), max_blob);
    }
    if let Some(provider) = &inner.sql {
        // A top-level function is admin-deployed, so its declared `imports` **are** its grants
        // (no site allowlist ceiling). The bare `sql` grants the default (`""`) database;
        // `sql:<name>` grants a named database — same least-privilege isolation as a site handler
        // (a normal `product` role vs a `privileged` role, each its own connection). A `sql:*` on
        // a function has no site universe to enumerate, so it grants no named database.
        //
        // `sql_site` is the *raw* `fn/<name>` identity; the provider qualifies it by `project`
        // internally (default → `fn/<name>`, else `{project}/fn/<name>` — matching `scope`) and
        // validates it segment-wise, so we pass the raw identity, never the project-qualified
        // `scope`.
        let mut names: Vec<&str> = Vec::new();
        if granted("sql") {
            names.push(""); // the default database
        }
        for imp in &config.imports {
            if let Some(name) = imp.strip_prefix("sql:") {
                if !name.is_empty() && name != "*" {
                    names.push(name);
                }
            }
        }
        for name in names {
            // Same managed-dependency readiness handling as the site-handler path
            // (`build_bindings`): a MANAGED database still starting (`Unavailable`, after a short
            // readiness retry) gates the whole invocation with a retryable 503; any other error
            // (external/local DB down) is logged + skipped (per-DB resilience).
            match super::handler_dispatch::open_bindings_sql(
                provider.as_ref(),
                project.as_str(),
                sql_site,
                name,
                None,
            )
            .await
            {
                Ok(backend) => bindings = bindings.with_sql(name, backend),
                Err(err) if err.is_unavailable() => {
                    tracing::info!(
                        scope, database = name, %err,
                        "required managed database not ready — gating the function with a retryable 503"
                    );
                    return Err(BindingsError::NotReady {
                        detail: format!("database `{name}`: {err}"),
                        retry_after_secs: super::handler_dispatch::SQL_NOT_READY_RETRY_AFTER_SECS,
                    });
                }
                Err(err) => {
                    tracing::warn!(scope, database = name, %err, "opening function SQL database failed");
                }
            }
        }
    }
    // Stage 0: resolve the in-site tenant scope (applied to both sql + orm), by source: a trusted
    // HTTP request (bearer/domain), an inherited invoke-chain value, or none. An undeclared
    // sql/orm importer is refused under the strict posture (Dimension 0); an `all` grant is capped
    // to `own` unless the posture opens cross-tenant. The resolved value is also carried into the
    // `invoke` binding below so a sibling this function calls inherits the same tenant.
    let host_tenancy = {
        let imports_db = granted("sql") || config.imports.iter().any(|i| i.starts_with("sql:"));
        // Gap 4a: per-project tenancy posture (operator override for this project, else node base).
        let project_knobs = inner.project_tenancy_knobs(project.as_str());
        let posture = crate::tenant_resolve::TenantPosture {
            require_declaration: project_knobs.require_tenancy_declaration,
            allow_cross_tenant: project_knobs.allow_cross_tenant_db,
        };
        // The fleet anchor that verifies a durable signed-context envelope (the session signer's
        // public half — the same key that mints/verifies session cookies). Bound outside the match
        // so it outlives the borrow in the `Durable` arm's inputs.
        let context_anchor = inner
            .session_signer
            .get()
            .map(|s| boatramp_core::cose::Signer::public_key(s.as_ref()));
        // Resolve the invocation's principal + whether it is a host-forced target (Gap 1). A forced
        // target is used verbatim (its schema is baked into `PerTableTarget` keys), bypassing the
        // config/posture resolution AND the `with_schema` below.
        let (resolved, is_forced_target) = match tenant {
            // The match borrows `tenant` (it's read earlier), so clone the forced binding out.
            FnTenant::ForcedTarget(host_tenancy) => (Some(host_tenancy.clone()), true),
            FnTenant::Request => (
                crate::tenant_resolve::resolve_host_tenancy(
                    config.tenancy.as_ref(),
                    imports_db,
                    posture,
                    crate::tenant_resolve::TenantSourceInputs {
                        bearer,
                        domain_context,
                        token_cfg: config.token_claims.as_ref(),
                        session_cookie: None,
                        session_anchor: None,
                        signed_context: None,
                        context_anchor: None,
                    },
                )
                .await
                .map_err(|e| BindingsError::Refused(e.to_string()))?,
                false,
            ),
            FnTenant::Inherited(value) => (
                crate::tenant_resolve::resolve_inherited_tenancy(
                    config.tenancy.as_ref(),
                    imports_db,
                    posture,
                    value.clone(),
                )
                .map_err(|e| BindingsError::Refused(e.to_string()))?,
                false,
            ),
            // The durable async lane: a `signed_context` source resolves the producer's stamped
            // tenant from the envelope carried on the drained message, verified against the fleet
            // anchor. No envelope / no anchor ⇒ no own tenant (fail closed).
            FnTenant::Durable(signed_context) => (
                crate::tenant_resolve::resolve_host_tenancy(
                    config.tenancy.as_ref(),
                    imports_db,
                    posture,
                    crate::tenant_resolve::TenantSourceInputs {
                        signed_context: signed_context.as_deref(),
                        context_anchor: context_anchor.as_ref(),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|e| BindingsError::Refused(e.to_string()))?,
                false,
            ),
            FnTenant::Background => (
                crate::tenant_resolve::resolve_host_tenancy(
                    config.tenancy.as_ref(),
                    imports_db,
                    posture,
                    crate::tenant_resolve::TenantSourceInputs::default(),
                )
                .await
                .map_err(|e| BindingsError::Refused(e.to_string()))?,
                false,
            ),
        };
        // Attach the project per-table tenancy schema (R2/D2) from the KV. Absent ⇒ Uniform;
        // present-but-unreadable ⇒ **fail closed** with a deny-all schema (never a silent downgrade
        // to Uniform). Applies on every trigger (request/inherited/background) so a frame- or
        // job-triggered query scopes each table on its own key identically to a request.
        let schema =
            match boatramp_core::deploy::load_project_tenancy(inner.kv.as_ref(), project).await {
                Ok(s) => s,
                Err(_) => Some(boatramp_core::tenancy::TenancySchema::deny_all()),
            };
        // A forced target binding already carries the schema (in its `PerTableTarget` keys) — never
        // re-attach it (`with_schema` would clobber the target keys with own `PerTable` keys).
        let resolved = if is_forced_target {
            resolved
        } else {
            resolved.map(|h| h.with_schema(schema.as_ref()))
        };
        bindings = bindings.with_tenancy(resolved.clone());
        resolved
    };
    // The resolved principal (axis-tagged fact set) to propagate down an in-project invoke chain
    // (host-carried, never guest-supplied). Empty when there's no in-site tenancy.
    let caller_tenant = host_tenancy
        .as_ref()
        .map(|h| h.facts().to_vec())
        .unwrap_or_default();
    if granted("wasi:messaging") {
        if let Some(messaging) = &inner.messaging {
            // Stamp the producer's own-tenant onto every message it publishes (R1, guest-blind), so
            // a consumer declaring `sources: [signed_context]` resolves it on the async lane. Fixed
            // here from this invocation's resolved principal; `None` for an unscoped producer.
            let signed_context = mint_producer_context(inner, &caller_tenant).await;
            // Private topics namespace under the function's own scope; `bus:<topic>`
            // publishes route to the shared, project-scoped bus.
            bindings = bindings.with_messaging(
                format!("{scope}/"),
                format!("{}/", project.qualified("bus")),
                messaging.clone(),
                signed_context,
            );
        }
    }
    // The read-only `messaging-stats` capability: surface the already-computed per-topic bus gauges
    // to a granted function. Plain topics resolve under the function's own `scope` prefix; a
    // `bus:<template>` topic must be one of the function's declared `stats_topics`, and the host
    // substitutes THIS invocation's resolved tenant for the template's `{tenant}` placeholder — the
    // guest never names a tenant, so no cross-tenant oracle. Deny-by-default.
    if granted("messaging-stats") {
        if let Some(messaging) = &inner.messaging {
            let resolved_tenant = resolved_tenant_string(&caller_tenant);
            bindings = bindings.with_messaging_stats(
                format!("{scope}/"),
                format!("{}/", project.qualified("bus")),
                messaging.clone(),
                config.stats_topics.clone(),
                resolved_tenant,
            );
        }
    }
    // Gap 3: `tenancy::present-token` — an emitter that verified a tenant credential IN-GUEST hands
    // it to the host, which RE-verifies it against this function's declared `token_claims` + `token`
    // source and seals the tenant onto the producer-context cell (so a subsequent `emit::message`
    // stamps it). Deny-by-default: needs the `tenancy` import, a messaging cell to stamp, a declared
    // `token` source (for the claim name) + `token_claims` (the JWKS), and a fleet signer — absent
    // any, `present-token` is `access-denied` and nothing is stamped. The guest never names a tenant.
    if granted("tenancy") {
        if let (Some(cell), Some(token_cfg), Some(signer), Some(claim)) = (
            bindings.producer_context_cell(),
            config.token_claims.clone(),
            inner.session_signer.get().cloned(),
            token_source_claim(config.tenancy.as_ref()),
        ) {
            bindings = bindings.with_present_token(
                Arc::new(ServerProducerContextSource {
                    token_cfg,
                    claim,
                    signer,
                }),
                cell,
            );
        }
    }
    // Function-to-function invoke (FI): granted only when the function imports
    // `invoke`, names at least one allowed target, and the runtime has an invoker
    // (set at serve startup). `depth` is this function's position in the call
    // chain; the host caps the next hop.
    if granted("invoke") && !config.invoke_targets.is_empty() {
        if let Some(invoker) = inner.invoker.get() {
            bindings = bindings.with_invoke(
                invoker.scoped(project, caller_tenant.clone()),
                config.invoke_targets.clone(),
                depth,
            );
        }
    }
    // GraphQL supergraph capability: run an operation against the project's composed supergraph
    // in-process, at this function's call depth (so a subgraph function reached from a guest run
    // that itself runs an op counts against the shared cap).
    if granted("graphql") {
        if let Some(runner) = inner.federation_runner.get() {
            // Propagate the caller's resolved principal so a `graphql::run` sub-fetch inherits the
            // caller's tenancy (symmetric to `with_invoke` above) — the async lane's own-scoped
            // supergraph writes then resolve instead of failing closed.
            bindings = bindings.with_graphql(runner.scoped(project, caller_tenant.clone()), depth);
        }
    }
    // Per-project SMTP email gateway: a function may submit a finished message to
    // one of the project's SMTP profiles. Granted when it imports `email` and the
    // runtime offers email — a spool + profile store are set, which the operator's
    // `allow_guest_email` posture gates at startup (spool unset ⇒ not granted ⇒
    // `access-denied`). The SMTP credentials are resolved host-side and never
    // exposed to the guest.
    #[cfg(feature = "email")]
    if granted("email") {
        if let (Some(store), Some(spool)) =
            (inner.email_profile_store.get(), inner.email_spool.get())
        {
            match store.resolve_all(project).await {
                Ok(profiles) => {
                    bindings = bindings.with_email(
                        project.as_str(),
                        std::sync::Arc::new(profiles),
                        spool.clone(),
                    );
                }
                Err(err) => {
                    tracing::warn!(scope, %err, "resolving email profiles failed; email not granted");
                }
            }
        }
    }
    // Guest project self-config (`boatramp:handlers/admin`): grant the surfaces this function
    // imports AND the operator posture enables, project-scoped host-side. Deny-by-default — an
    // unenabled/ungranted surface is simply absent (its verbs return `access-denied`).
    #[cfg(feature = "admin")]
    if let (Some(controller), Some(enabled)) =
        (inner.admin_controller.get(), inner.admin_surfaces.get())
    {
        use boatramp_handlers::AdminSurface;
        let mut surfaces = std::collections::BTreeSet::new();
        for (imp, surface) in [
            ("admin:domains", AdminSurface::Domains),
            ("admin:email", AdminSurface::Email),
            ("admin:site", AdminSurface::Site),
            ("admin:secrets", AdminSurface::Secrets),
        ] {
            if enabled.contains(&surface) && granted(imp) {
                surfaces.insert(surface);
            }
        }
        if !surfaces.is_empty() {
            bindings = bindings.with_admin(controller.scoped(project), surfaces);
        }
    }
    inner.logs.configure(scope, None);
    // A function invocation (API or in-process subgraph fetch) does not thread a request id
    // through the invoke path yet; its logs are scope-tagged but not request-correlated.
    bindings = bindings.with_logging(scope.to_string(), None, inner.logs.clone());
    // Environment for the function: its static `env` strings, then its `secrets`
    // — each a *reference* to a secret value, resolved here at instantiation and
    // never stored in the manifest/config (same indirection as a site handler; a
    // resolved secret overrides a static `env` of the same name, a missing
    // referent is logged and skipped). Under the multi-tenant posture a bare /
    // `env:` ref into the operator's environment is refused (fail-closed).
    let allow_env_secret_refs = inner.allow_env_secret_refs.get().copied().unwrap_or(false);
    let env = resolve_secret_env(
        scope,
        project,
        &config.env,
        &config.secrets,
        allow_env_secret_refs,
        inner.secret_store.get().map(std::convert::AsRef::as_ref),
    )
    .await?;
    Ok(bindings.with_env(env))
}

/// Per-invocation limits for a function: its own `limits` (memory/timeout/fuel),
/// left at the engine default where unset. The engine clamps to its ceiling. Also reused by the
/// session re-entry path ([`crate::session_serve`]), whose config carries the same `HandlerLimits`.
#[cfg(feature = "handlers")]
pub(super) fn function_limits(
    limits: Option<&boatramp_core::config::HandlerLimits>,
) -> boatramp_handlers::Limits {
    let mut l = boatramp_handlers::Limits::default();
    if let Some(hl) = limits {
        if let Some(mb) = hl.memory_mb {
            l.memory_bytes = (mb as usize).saturating_mul(1024 * 1024);
        }
        if let Some(ms) = hl.timeout_ms {
            l.timeout_ms = ms as u64;
        }
        if let Some(fuel) = hl.fuel {
            l.fuel = Some(fuel);
        }
    }
    l
}

/// Point a request at the synthetic invoke authority so `wasi:http` sees a
/// well-formed absolute URI (`http://function.invoke/`), preserving method +
/// headers + body. The public `/api/functions/<name>/invoke` path is dropped —
/// the function sees a clean request, not the control-plane envelope.
#[cfg(feature = "handlers")]
fn prepare_invoke_request(mut request: Request) -> Request {
    // An internal function-to-function call has already built an absolute
    // `http://function.invoke/<path>` URI and wants its path preserved; only the
    // external control-plane path (a relative `/api/functions/.../invoke` URI)
    // is collapsed to the clean root the function sees.
    let already_internal = request
        .uri()
        .authority()
        .is_some_and(|a| a.host() == INVOKE_AUTHORITY);
    if !already_internal {
        if let Ok(uri) = format!("http://{INVOKE_AUTHORITY}/").parse() {
            *request.uri_mut() = uri;
        }
    }
    request
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static(INVOKE_AUTHORITY));
    request
}

/// The function-to-function invoke resolver (FI): backs the `invoke` capability
/// the engine grants a function. It holds the deploy store (to resolve + read the
/// target) and a `Weak` back to the handler runtime (to execute on the same
/// engine), so the engine can call *up* into the full invoke machinery — resolve
/// the target, admit it against its own quota, run it at the next call depth, and
/// meter it — exactly as the external `POST /invoke` path does.
#[cfg(feature = "handlers")]
pub(crate) struct FunctionInvoker {
    deploy: DeployStore,
    runtime: std::sync::Weak<HandlerRuntimeInner>,
    /// The tenant project the caller runs in. Function-to-function invoke is
    /// **in-project**: a target is resolved, admitted, and metered within this
    /// project, never across the tenant boundary. The startup template carries
    /// `default`; [`scoped`](Self::scoped) rebinds it per caller.
    project: String,
    /// The caller's host-resolved **principal** — the axis-tagged fact set (`PLAN-tenancy-principal`
    /// D1) — carried so an invoked sibling inherits the caller's tenant identity (and, later, its
    /// `Session`/`TargetTenant` facts with their axes intact) — host-propagated, never read from the
    /// guest's invoke request. Empty when the caller has no resolved tenancy (plain / anonymous).
    /// Set per binding by [`scoped`](Self::scoped).
    caller_tenant: Vec<boatramp_handlers::ScopeFact>,
}

#[cfg(feature = "handlers")]
impl FunctionInvoker {
    pub(crate) fn new(deploy: DeployStore, runtime: std::sync::Weak<HandlerRuntimeInner>) -> Self {
        Self {
            deploy,
            runtime,
            project: ProjectRef::DEFAULT.as_str().to_string(),
            caller_tenant: Vec::new(),
        }
    }

    /// Derive a project-scoped invoker: the same store + runtime, but resolving the caller's
    /// siblings within `project`, carrying the caller's host-resolved `caller_tenant` so an invoked
    /// sibling inherits it (Stage 0). Built per binding (a site handler or a top-level function) so
    /// the `invoke` capability never crosses tenants.
    pub(crate) fn scoped(
        &self,
        project: ProjectRef<'_>,
        caller_tenant: Vec<boatramp_handlers::ScopeFact>,
    ) -> Arc<dyn boatramp_handlers::Invoker> {
        Arc::new(Self {
            deploy: self.deploy.clone(),
            runtime: self.runtime.clone(),
            project: project.as_str().to_string(),
            caller_tenant,
        })
    }
}

#[cfg(feature = "handlers")]
#[async_trait::async_trait]
impl boatramp_handlers::Invoker for FunctionInvoker {
    async fn invoke(
        &self,
        target: &str,
        request: boatramp_handlers::InvokeRequest,
        depth: u32,
    ) -> Result<boatramp_handlers::InvokeResponse, boatramp_handlers::InvokeError> {
        use boatramp_handlers::InvokeError;
        let Some(inner) = self.runtime.upgrade() else {
            return Err(InvokeError::Failed(
                "handler runtime is shutting down".into(),
            ));
        };
        // In-project invoke: resolve, admit, and meter the callee within the
        // caller's own tenant project (never `default`, never a sibling tenant).
        let project = ProjectRef::new(&self.project);
        // Resolve the target by name to its active version's component.
        let function = match self.deploy.get_function(project, target).await {
            Ok(Some(f)) => f,
            Ok(None) => return Err(InvokeError::NotFound),
            Err(err) => return Err(InvokeError::Failed(err.to_string())),
        };
        let Some(component) = function.resolve(&function.active).map(str::to_owned) else {
            return Err(InvokeError::NotFound);
        };
        let bytes_in = request.body.len() as u64;
        let axum_request = match build_internal_request(request) {
            Ok(req) => req,
            Err(err) => return Err(InvokeError::Failed(err)),
        };
        // Rate-limit the callee against its own quota, as an external call would.
        // A rejection is the callee's response (429), surfaced to the caller.
        if let Err(response) = admit_by_quota(&inner, &self.deploy, project, &function).await {
            return Ok(buffer_invoke_response(response).await);
        }
        let (response, duration_ms) = execute_function(
            &inner,
            &self.deploy,
            project,
            &function,
            &component,
            axum_request,
            depth,
            boatramp_handlers::Lane::Sync,
            // In-project invoke: the sibling inherits the caller's host-resolved tenant (never the
            // guest's invoke request), applying its own declared grant.
            FnTenant::Inherited(self.caller_tenant.clone()),
        )
        .await;
        let invoke_response = buffer_invoke_response(response).await;
        let sample = boatramp_core::function::MeteringSample {
            success: invoke_response.status < 500,
            duration_ms,
            bytes_in,
            bytes_out: invoke_response.body.len() as u64,
        };
        record_metering(&inner, &self.deploy, project, &function.name, &sample).await;
        Ok(invoke_response)
    }

    async fn invoke_target(
        &self,
        target: &str,
        request: boatramp_handlers::InvokeRequest,
        depth: u32,
        tenancy: boatramp_handlers::HostTenancy,
    ) -> Result<boatramp_handlers::InvokeResponse, boatramp_handlers::InvokeError> {
        use boatramp_handlers::InvokeError;
        let Some(inner) = self.runtime.upgrade() else {
            return Err(InvokeError::Failed(
                "handler runtime is shutting down".into(),
            ));
        };
        // A target fetch is served in the SAME project as the caller (the gateway resolved `B`'s
        // public-subset confinement for a field of THIS project's supergraph); the callee is a
        // subgraph FUNCTION of this project.
        let project = ProjectRef::new(&self.project);
        let function = match self.deploy.get_function(project, target).await {
            Ok(Some(f)) => f,
            Ok(None) => return Err(InvokeError::NotFound),
            Err(err) => return Err(InvokeError::Failed(err.to_string())),
        };
        let Some(component) = function.resolve(&function.active).map(str::to_owned) else {
            return Err(InvokeError::NotFound);
        };
        let bytes_in = request.body.len() as u64;
        let axum_request = match build_internal_request(request) {
            Ok(req) => req,
            Err(err) => return Err(InvokeError::Failed(err)),
        };
        if let Err(response) = admit_by_quota(&inner, &self.deploy, project, &function).await {
            return Ok(buffer_invoke_response(response).await);
        }
        let (response, duration_ms) = execute_function(
            &inner,
            &self.deploy,
            project,
            &function,
            &component,
            axum_request,
            depth,
            boatramp_handlers::Lane::Sync,
            // The subgraph runs under the host-FORCED target confinement (its own declared tenancy
            // is bypassed — the composed SDL field's target class is the authority). `B` + the
            // public-subset confinement were host-resolved at the gateway (never guest input).
            FnTenant::ForcedTarget(tenancy),
        )
        .await;
        let invoke_response = buffer_invoke_response(response).await;
        let sample = boatramp_core::function::MeteringSample {
            success: invoke_response.status < 500,
            duration_ms,
            bytes_in,
            bytes_out: invoke_response.body.len() as u64,
        };
        record_metering(&inner, &self.deploy, project, &function.name, &sample).await;
        Ok(invoke_response)
    }

    async fn invoke_streaming(
        &self,
        target: &str,
        request: boatramp_handlers::InvokeRequest,
        depth: u32,
    ) -> Result<boatramp_handlers::InvokeStreamResponse, boatramp_handlers::InvokeError> {
        use boatramp_handlers::InvokeError;
        let Some(inner) = self.runtime.upgrade() else {
            return Err(InvokeError::Failed(
                "handler runtime is shutting down".into(),
            ));
        };
        let project = ProjectRef::new(&self.project);
        let function = match self.deploy.get_function(project, target).await {
            Ok(Some(f)) => f,
            Ok(None) => return Err(InvokeError::NotFound),
            Err(err) => return Err(InvokeError::Failed(err.to_string())),
        };
        let Some(component) = function.resolve(&function.active).map(str::to_owned) else {
            return Err(InvokeError::NotFound);
        };
        let bytes_in = request.body.len() as u64;
        let axum_request = match build_internal_request(request) {
            Ok(req) => req,
            Err(err) => return Err(InvokeError::Failed(err)),
        };
        // A quota rejection is the callee's (429) response, streamed like any other.
        if let Err(response) = admit_by_quota(&inner, &self.deploy, project, &function).await {
            return Ok(stream_invoke_response(response));
        }
        let (response, duration_ms) = execute_function(
            &inner,
            &self.deploy,
            project,
            &function,
            &component,
            axum_request,
            depth,
            boatramp_handlers::Lane::Sync,
            FnTenant::Inherited(self.caller_tenant.clone()),
        )
        .await;
        let stream_response = stream_invoke_response(response);
        // Streamed responses are metered at hand-off: `bytes_out` is taken from a
        // declared `Content-Length` when present (the common case), else 0 — the body is
        // not buffered to count it. `success`/`duration`/`bytes_in` are exact.
        let bytes_out = stream_response
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| std::str::from_utf8(v).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let sample = boatramp_core::function::MeteringSample {
            success: stream_response.status < 500,
            duration_ms,
            bytes_in,
            bytes_out,
        };
        record_metering(&inner, &self.deploy, project, &function.name, &sample).await;
        Ok(stream_response)
    }
}

/// Turn an internal [`InvokeRequest`](boatramp_handlers::InvokeRequest) into the
/// HTTP request the callee runs against, at `http://function.invoke/<path>` so
/// [`prepare_invoke_request`] preserves the guest-chosen path. `Err` carries a
/// human reason for a malformed method/header.
#[cfg(feature = "handlers")]
fn build_internal_request(request: boatramp_handlers::InvokeRequest) -> Result<Request, String> {
    let path = if request.path.starts_with('/') {
        request.path.clone()
    } else {
        format!("/{}", request.path)
    };
    let mut builder = axum::http::Request::builder()
        .method(request.method.as_str())
        .uri(format!("http://{INVOKE_AUTHORITY}{path}"));
    for (name, value) in &request.headers {
        // The host is set by `prepare_invoke_request`; a guest-supplied one is
        // dropped so it can't spoof the authority.
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_slice());
    }
    builder
        .body(axum::body::Body::from(request.body))
        .map_err(|err| err.to_string())
}

/// Buffer a [`Response`] into an [`InvokeResponse`](boatramp_handlers::InvokeResponse):
/// status + all headers + body. A body over the internal cap (or a stream error)
/// yields an empty body but keeps the status/headers, so the caller still sees
/// the outcome.
#[cfg(feature = "handlers")]
async fn buffer_invoke_response(response: Response) -> boatramp_handlers::InvokeResponse {
    let status = response.status().as_u16();
    let headers: Vec<(String, Vec<u8>)> = response
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect();
    let body = axum::body::to_bytes(response.into_body(), MAX_ASYNC_BODY_BYTES)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();
    boatramp_handlers::InvokeResponse {
        status,
        headers,
        body,
    }
}

/// Why introspecting a function subgraph's SDL failed.
#[cfg(feature = "handlers")]
#[derive(Debug)]
pub(super) enum SubgraphSdlError {
    /// The handler runtime has no wasm engine, so the component cannot be run to introspect it.
    Unavailable,
    /// The component could not be run (trap, timeout, overload) or produced no usable response.
    InvokeFailed(String),
    /// The component ran but did not answer `{ _service { sdl } }` — it is not a federation
    /// subgraph.
    NotASubgraph,
}

/// Run `{ _service { sdl } }` against a **specific component blob** (by hash) and return its
/// federation SDL. Unlike the [`Invoker`] path — which resolves the function's *active* version
/// — this targets an arbitrary component, so a **pending** (about-to-be-activated) subgraph
/// version can be composed-checked *before* its activation flips. Anonymous (a schema read needs
/// no caller identity), with a timeout so a hung guest can't wedge the deploy.
#[cfg(feature = "handlers")]
pub(super) async fn introspect_service_sdl(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    project: ProjectRef<'_>,
    function: &boatramp_core::function::Function,
    component: &str,
) -> Result<String, SubgraphSdlError> {
    let body = serde_json::json!({ "query": "{ _service { sdl } }" })
        .to_string()
        .into_bytes();
    let invoke = boatramp_handlers::InvokeRequest {
        method: "POST".to_string(),
        path: "/".to_string(),
        headers: vec![("content-type".to_string(), b"application/json".to_vec())],
        body,
    };
    let request = build_internal_request(invoke).map_err(SubgraphSdlError::InvokeFailed)?;
    let run = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        execute_function(
            inner,
            deploy,
            project,
            function,
            component,
            request,
            0,
            boatramp_handlers::Lane::Sync,
            // Host-initiated subgraph SDL fetch — no tenant source (introspection).
            FnTenant::Background,
        ),
    )
    .await;
    let (response, _ms) = match run {
        Ok(pair) => pair,
        Err(_elapsed) => {
            return Err(SubgraphSdlError::InvokeFailed(
                "timed out answering `_service { sdl }`".to_string(),
            ))
        }
    };
    let buffered = buffer_invoke_response(response).await;
    if buffered.status >= 500 {
        return Err(SubgraphSdlError::InvokeFailed(format!(
            "status {}",
            buffered.status
        )));
    }
    let parsed: serde_json::Value =
        serde_json::from_slice(&buffered.body).unwrap_or(serde_json::Value::Null);
    match parsed
        .pointer("/data/_service/sdl")
        .and_then(|v| v.as_str())
    {
        Some(sdl) if !sdl.trim().is_empty() => Ok(sdl.to_string()),
        _ => Err(SubgraphSdlError::NotASubgraph),
    }
}

/// Adapt a [`Response`] into a streaming [`InvokeStreamResponse`](boatramp_handlers::InvokeStreamResponse):
/// status + headers eagerly, the body as a chunk stream the caller pulls on demand
/// (never buffered whole in host memory). A body-stream error surfaces as a chunk error.
#[cfg(feature = "handlers")]
fn stream_invoke_response(response: Response) -> boatramp_handlers::InvokeStreamResponse {
    use futures::StreamExt as _;
    let status = response.status().as_u16();
    let headers: Vec<(String, Vec<u8>)> = response
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect();
    let body = response
        .into_body()
        .into_data_stream()
        .map(|chunk| chunk.map_err(|e| e.to_string()))
        .boxed();
    boatramp_handlers::InvokeStreamResponse {
        status,
        headers,
        body,
    }
}

/// Buffer a response into `(status, content-type, body)` — for idempotency
/// capture and async result persistence.
#[cfg(feature = "handlers")]
pub(super) async fn capture_response(response: Response) -> (StatusCode, Option<String>, Vec<u8>) {
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();
    (status, content_type, body)
}

/// Rebuild a `Response` from captured parts.
#[cfg(feature = "handlers")]
fn rebuild_response(status: StatusCode, content_type: Option<&str>, body: Vec<u8>) -> Response {
    let mut builder = axum::http::Response::builder().status(status);
    if let Some(ct) = content_type {
        if let Ok(value) = HeaderValue::from_str(ct) {
            builder = builder.header(header::CONTENT_TYPE, value);
        }
    }
    builder
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| handler_unavailable())
}

/// Standard base64 of bytes (invocation records are plain JSON).
#[cfg(feature = "handlers")]
pub(super) fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode standard base64 back to bytes (empty on malformed input — a persisted
/// record we wrote is always valid).
#[cfg(feature = "handlers")]
pub(super) fn b64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}

/// Drain a function's queued async invocations: claim each within the async
/// lane's budget and run it **off the tick**, so a long background job never
/// stalls crons, other drains, or workflow progress. A crash mid-run leaves a
/// `Running` record whose **lease** eventually elapses; a later drain (this node
/// after restart, or a new leader) reclaims it. A failed run is retried until
/// [`MAX_INVOKE_ATTEMPTS`], then dead-lettered (left `failed` for inspection).
#[cfg(feature = "handlers")]
pub(super) async fn drain_function_invocations(
    inner: &Arc<HandlerRuntimeInner>,
    deploy: &DeployStore,
    project: ProjectRef<'_>,
    function: &boatramp_core::function::Function,
    // Whether this drain is the unsharded safety-net backstop (B10) rather than the sharded/owner
    // fast path. When a claim wins on the safety net, bump the `safetynet_only_drains` observability
    // counter (B14) — a rising count flags a shard/ownership gap that the backstop is covering.
    is_safety_net: bool,
) {
    use boatramp_core::function::InvocationStatus;
    let queued = match deploy.list_invocations(project, &function.name).await {
        Ok(list) => list,
        Err(err) => {
            tracing::warn!(function = %function.name, %err, "listing invocations failed");
            return;
        }
    };
    let now = now_unix();
    for inv in queued {
        // Claimable = freshly queued, or a `Running` whose lease has elapsed (the
        // node holding it died mid-run — reclaim it, counting the attempt).
        let claimable = match inv.status {
            InvocationStatus::Queued => true,
            InvocationStatus::Running => inv.lease_expires.is_none_or(|exp| exp <= now),
            InvocationStatus::Succeeded | InvocationStatus::Failed => false,
        };
        if !claimable {
            continue;
        }
        // Bound fan-out to the async lane's capacity by holding an owned permit
        // for the whole run. When the gate is full, leave the rest queued for a
        // later tick — no unbounded spawn, and backpressure never burns an attempt.
        let Ok(permit) = inner.async_drain_gate.clone().try_acquire_owned() else {
            break;
        };
        // Claim: pin `Running` + a lease sized to the async ceiling, count the attempt, and persist
        // — but via a **compare-and-set** on the exact record we observed (B10), NOT a blind write.
        // Sharding removed the leader-gate that made a plain read-then-write safe: in a membership
        // transition the old and new owner may briefly both drain this function (the double-owner
        // window), so the Queued→Running (or expired-lease reclaim) transition MUST succeed for at
        // most ONE node. The CAS admits exactly one: a racing node observed the SAME record, computes
        // its own claim, and its CAS fails because our swap already changed the bytes — it re-scans
        // instead of double-executing (Invariant 1). Counting the attempt *before* running means a
        // run that crashes the node still advances toward the dead-letter cap (a poison job can't
        // loop forever). The lease is the cluster-wide hold: a crashed owner's expired `Running` is
        // reclaimable by any node via this same CAS (Invariant 2, lease-expiry reclaim).
        let observed = inv.clone();
        let mut claimed = inv;
        claimed.status = InvocationStatus::Running;
        claimed.attempts = claimed.attempts.saturating_add(1);
        claimed.lease_expires = Some(now.saturating_add(lease_ttl_secs(inner)));
        claimed.updated = now;
        match deploy.claim_invocation(project, &observed, &claimed).await {
            Ok(true) => {
                // Won the claim — run it. If the safety-net (not the owner's fast path) won it, this
                // was a shard/ownership gap the backstop covered (B14): meter it for the operator.
                if is_safety_net {
                    inner
                        .safetynet_only_drains
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            Ok(false) => {
                // Lost the race (another node claimed it first) or the record moved on since the
                // scan — skip it, don't double-execute. Redundant scans (the unsharded safety-net)
                // are idempotent precisely because of this CAS.
                drop(permit);
                continue;
            }
            Err(err) => {
                tracing::warn!(function = %function.name, %err, "claiming invocation failed");
                drop(permit);
                continue;
            }
        }
        let inner = inner.clone();
        let deploy = deploy.clone();
        let project = project.as_str().to_string();
        let function = function.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when the run settles
            run_claimed_invocation(
                &inner,
                &deploy,
                ProjectRef::new(&project),
                &function,
                claimed,
            )
            .await;
        });
    }
}

/// The lease TTL (seconds) stamped on a claimed invocation: the async ceiling
/// (the longest a run can take) plus a margin, so the lease only elapses after a
/// genuine crash, never under a legitimately long-running job.
#[cfg(feature = "handlers")]
fn lease_ttl_secs(inner: &HandlerRuntimeInner) -> u64 {
    inner
        .engine
        .async_timeout_ms()
        .div_ceil(1000)
        .saturating_add(LEASE_MARGIN_SECS)
}

/// Run an already-**claimed** (`Running`) invocation against its pinned version
/// and persist the settled outcome — terminal (`succeeded`/`failed`) or requeued
/// for retry. The claim (status / attempt / lease) was written by the drain;
/// this clears the lease once the invocation settles.
#[cfg(feature = "handlers")]
async fn run_claimed_invocation(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    project: ProjectRef<'_>,
    function: &boatramp_core::function::Function,
    mut inv: boatramp_core::function::Invocation,
) {
    use boatramp_core::function::InvocationStatus;
    // The version was pinned at enqueue; a later deploy can't silently change it.
    let Some(component) = function.resolve(&inv.version).map(str::to_owned) else {
        // The pinned version is gone (rolled off / pruned) — unrunnable, so fail.
        inv.status = InvocationStatus::Failed;
        inv.lease_expires = None;
        inv.updated = now_unix();
        let _ = deploy.put_invocation(project, &inv).await;
        return;
    };
    let bytes_in = inv
        .request_b64
        .as_deref()
        .map(|b| b64_decode(b).len() as u64)
        .unwrap_or(0);
    let request = build_stored_request(&inv);
    // The durable drain runs in the async lane: no client is connected, so it
    // gets the larger async ceiling on the isolated async pool.
    let (response, duration_ms) = execute_function(
        inner,
        deploy,
        project,
        function,
        &component,
        request,
        0,
        boatramp_handlers::Lane::Async,
        // Durable drain (stored-request replay): no live request; the original tenant isn't
        // persisted, so an `own` op fails closed (safe).
        FnTenant::Background,
    )
    .await;
    let (status, content_type, body) = capture_response(response).await;
    // A function that returns a 5xx from the engine wrapper (timeout/trap/etc.)
    // is a delivery failure worth retrying; any response the guest itself
    // produced (including its own 4xx/5xx) is a successful delivery.
    let delivered = status != StatusCode::INTERNAL_SERVER_ERROR
        && status != StatusCode::GATEWAY_TIMEOUT
        && status != StatusCode::SERVICE_UNAVAILABLE;
    if delivered {
        inv.status = InvocationStatus::Succeeded;
        inv.result = Some(boatramp_core::function::InvocationResult {
            status: status.as_u16(),
            content_type,
            body_b64: b64_encode(&body),
        });
    } else if inv.attempts >= MAX_INVOKE_ATTEMPTS {
        inv.status = InvocationStatus::Failed;
    } else {
        inv.status = InvocationStatus::Queued;
    }
    // The lease only guards an in-flight `Running` claim; drop it now the
    // invocation has settled (terminal or requeued for a later tick).
    inv.lease_expires = None;
    inv.updated = now_unix();
    let _ = deploy.put_invocation(project, &inv).await;
    // Meter a settled attempt (a requeue-for-retry is not yet a completed
    // invocation, so only the terminal transition is metered).
    if matches!(
        inv.status,
        InvocationStatus::Succeeded | InvocationStatus::Failed
    ) {
        let sample = boatramp_core::function::MeteringSample {
            success: matches!(inv.status, InvocationStatus::Succeeded),
            duration_ms,
            bytes_in,
            bytes_out: body.len() as u64,
        };
        record_metering(inner, deploy, project, &function.name, &sample).await;
    }
}

/// Rebuild the engine request for a stored async invocation from its buffered
/// body + content type (method is always `POST` for an enqueued call).
#[cfg(feature = "handlers")]
fn build_stored_request(inv: &boatramp_core::function::Invocation) -> Request {
    let body = inv
        .request_b64
        .as_deref()
        .map(b64_decode)
        .unwrap_or_default();
    let mut builder = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri(format!("http://{INVOKE_AUTHORITY}/"))
        .header(header::HOST, INVOKE_AUTHORITY);
    if let Some(ct) = &inv.request_content_type {
        if let Ok(value) = HeaderValue::from_str(ct) {
            builder = builder.header(header::CONTENT_TYPE, value);
        }
    }
    builder
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| Request::new(axum::body::Body::empty()))
}

// ---- function metering + quotas (FA-4) ---------------------------------------

/// The per-function lock serializing its metering + rate-limit read-modify-write,
/// created on first use so concurrent invocations of one function can't lose an
/// update (the KV is get/put, not atomic-increment). `name` is the
/// **project-qualified** function identity (the callers pass
/// `project.qualified(&function.name)`), so a same-named function in two tenants
/// gets two independent locks.
#[cfg(feature = "handlers")]
fn function_meter_lock(inner: &HandlerRuntimeInner, name: &str) -> Arc<tokio::sync::Mutex<()>> {
    inner
        .function_meter_locks
        .lock()
        .unwrap()
        .entry(name.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Acquire a permit from the function's concurrency semaphore (created on first
/// use) when it sets a `max_concurrent` quota; `Ok(None)` if uncapped, `Err(())`
/// when at the limit (the caller turns that into a `503`). `name` is the
/// **project-qualified** function identity (`project.qualified(&function.name)`),
/// so a same-named function in another tenant can't starve this one's budget.
#[cfg(feature = "handlers")]
fn acquire_function_permit(
    inner: &HandlerRuntimeInner,
    name: &str,
    quota: &boatramp_core::function::FunctionQuota,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, ()> {
    let Some(max) = quota.max_concurrent else {
        return Ok(None);
    };
    let semaphore = {
        let mut map = inner.function_semaphores.lock().unwrap();
        map.entry(name.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(max as usize)))
            .clone()
    };
    semaphore.try_acquire_owned().map(Some).map_err(|_| ())
}

/// Charge one invocation against the function's rate-limit quota (fixed window).
/// `Ok(())` admits; `Err(429)` means the window is full (fail-closed). A function
/// with no `max_invocations` cap always admits without touching the store.
#[cfg(feature = "handlers")]
async fn admit_by_quota(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    project: ProjectRef<'_>,
    function: &boatramp_core::function::Function,
) -> Result<(), Response> {
    let quota = &function.config.quota;
    if quota.max_invocations.is_none() {
        return Ok(());
    }
    // Serialize on the **project-qualified** function identity so a same-named
    // function in another tenant can't share (and contend on) this lock. The
    // metering *store* keys are already project-scoped; this only fixes the
    // in-memory lock key.
    let lock = function_meter_lock(inner, &project.qualified(&function.name));
    let _guard = lock.lock().await;
    let now = now_unix();
    let mut metering = match deploy.get_metering(project, &function.name).await {
        Ok(Some(m)) => m,
        Ok(None) => boatramp_core::function::Metering::new(&function.name),
        Err(err) => return Err(deploy_error_response(err)),
    };
    if !metering.admit(quota, now) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "function invocation quota exceeded\n",
        )
            .into_response());
    }
    if let Err(err) = deploy.put_metering(project, &metering).await {
        return Err(deploy_error_response(err));
    }
    Ok(())
}

/// Fold one invocation's measured cost into the function's usage aggregate
/// (best-effort: a metering write failure is logged, never surfaced to the
/// caller). Serialized per function so concurrent updates don't race.
#[cfg(feature = "handlers")]
async fn record_metering(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    project: ProjectRef<'_>,
    function: &str,
    sample: &boatramp_core::function::MeteringSample,
) {
    // Project-qualified lock key (see `admit_by_quota`) — the metering store
    // itself is already project-scoped, this just isolates the in-memory lock.
    let lock = function_meter_lock(inner, &project.qualified(function));
    let _guard = lock.lock().await;
    let now = now_unix();
    let mut metering = match deploy.get_metering(project, function).await {
        Ok(Some(m)) => m,
        Ok(None) => boatramp_core::function::Metering::new(function),
        Err(err) => {
            tracing::warn!(function, %err, "reading metering failed");
            return;
        }
    };
    metering.record(sample, now);
    if let Err(err) = deploy.put_metering(project, &metering).await {
        tracing::warn!(function, %err, "writing metering failed");
    }
}

/// `GET /api/functions/:name/usage` (FA-4) — the function's usage aggregate.
/// `system·read`.
#[cfg(feature = "handlers")]
pub(super) async fn get_function_usage(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(name): Path<String>,
) -> Response {
    match deploy.get_metering(project.as_ref(), &name).await {
        Ok(Some(m)) => Json(m).into_response(),
        // No invocations yet ⇒ a zeroed aggregate, so the CLI always has a shape.
        Ok(None) => Json(boatramp_core::function::Metering::new(name)).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

// ---- function triggers: scheduled + event sources ----------------------------

/// `PUT /api/functions/:name/triggers/:id` — add/replace a stored trigger on a
/// function (the body is a [`TriggerKind`], e.g. `{"type":"cron","schedule":…}`).
/// The scheduler dispatches `cron` (→ a scheduled async invocation) and `queue`
/// (→ claim + invoke) triggers. `system·admin`.
#[cfg(feature = "handlers")]
pub(super) async fn put_trigger_handler(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path((name, id)): Path<(String, String)>,
    Json(kind): Json<boatramp_core::function::TriggerKind>,
) -> Response {
    match deploy.get_function(project.as_ref(), &name).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (StatusCode::NOT_FOUND, format!("no function {name:?}\n")).into_response()
        }
        Err(err) => return deploy_error_response(err),
    }
    // Fail closed: a blob-change trigger is only meaningful on a backend that can
    // natively watch — refuse (never silently no-op) so the semantics stay uniform.
    if let boatramp_core::function::TriggerKind::Blob { prefix } = &kind {
        let Some(inner) = handlers.inner.as_ref() else {
            return (
                StatusCode::BAD_REQUEST,
                "this storage backend does not support blob-change triggers\n",
            )
                .into_response();
        };
        if !inner.storage.supports_watch() {
            return (
                StatusCode::BAD_REQUEST,
                "this storage backend does not support blob-change triggers\n",
            )
                .into_response();
        }
        // On a cloud object store a native pipeline (S3→SQS, …) must be
        // provisioned per the operator tier before the watch can fire. A
        // self-watching backend (fs) has no provider and needs nothing.
        if let Some(provider) = inner.watch_provider.get() {
            let storage_prefix = blob_storage_prefix(project.as_ref(), &name, prefix);
            let tier = inner.provision_tier.get().copied().unwrap_or_default();
            match boatramp_core::blob_provision::ensure_watch(
                provider.as_ref(),
                tier,
                &name,
                &storage_prefix,
                &deploy,
                now_unix(),
            )
            .await
            {
                Ok(boatramp_core::blob_provision::ProvisionOutcome::Ready) => {}
                // Dry-run: print the exact pipeline to apply; don't activate.
                Ok(boatramp_core::blob_provision::ProvisionOutcome::Recipe(recipe)) => {
                    return (StatusCode::BAD_REQUEST, format!("{recipe}\n")).into_response();
                }
                // Fail-closed refuse (no creds / nothing configured).
                Ok(boatramp_core::blob_provision::ProvisionOutcome::Refused(msg)) => {
                    return (StatusCode::BAD_REQUEST, format!("{msg}\n")).into_response();
                }
                Err(err) => {
                    return (StatusCode::BAD_GATEWAY, format!("{err}\n")).into_response();
                }
            }
        }
    }
    let trigger = boatramp_core::function::FunctionTrigger {
        id: id.clone(),
        kind,
        last_fired_minute: None,
    };
    if let Err(err) = deploy.put_trigger(project.as_ref(), &name, &trigger).await {
        return deploy_error_response(err);
    }
    Json(trigger).into_response()
}

/// `GET /api/functions/:name/triggers` — list a function's stored triggers.
/// `system·read`.
#[cfg(feature = "handlers")]
pub(super) async fn list_triggers_handler(
    State(deploy): State<DeployStore>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(name): Path<String>,
) -> Response {
    match deploy.list_triggers(project.as_ref(), &name).await {
        Ok(mut list) => {
            list.sort_by(|a, b| a.id.cmp(&b.id));
            Json(list).into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// `DELETE /api/functions/:name/triggers/:id` — remove a stored trigger.
/// `system·admin`. Idempotent. Removing a `Blob` trigger also **retracts** any
/// cloud notification pipeline provisioned for it (so no leaked queues), mirroring
/// auto-DNS retraction.
#[cfg(feature = "handlers")]
pub(super) async fn delete_trigger_handler(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path((name, id)): Path<(String, String)>,
) -> Response {
    // Look the trigger up first: a `Blob` trigger may own a provisioned pipeline
    // to retract before the trigger record is gone.
    if let (Some(inner), Ok(Some(trigger))) = (
        handlers.inner.as_ref(),
        deploy.get_trigger(project.as_ref(), &name, &id).await,
    ) {
        if let (boatramp_core::function::TriggerKind::Blob { prefix }, Some(provider)) =
            (&trigger.kind, inner.watch_provider.get())
        {
            let storage_prefix = blob_storage_prefix(project.as_ref(), &name, prefix);
            if let Ok(Some(record)) = deploy
                .get_managed_notification(project.as_ref(), &name, &storage_prefix)
                .await
            {
                if let Err(err) = boatramp_core::blob_provision::retract_watch(
                    provider.as_ref(),
                    &record,
                    &deploy,
                )
                .await
                {
                    tracing::warn!(function = %name, %err, "retracting blob notification failed");
                }
            }
        }
    }
    match deploy.delete_trigger(project.as_ref(), &name, &id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// The full storage key prefix a function's `Blob { prefix }` trigger watches:
/// the function's **project-qualified** blobstore namespace
/// (`hblob/{qualified(project, fn/<name>)}/` — `hblob/fn/<name>/` for the
/// `default` project, `hblob/{project}/fn/<name>/` otherwise, matching the
/// function's blob binding) joined with the trigger-relative prefix. The
/// provisioner (bucket-notification filter), the notification ledger, and the
/// `spawn_blob_watcher` consumer all key off this, so they must agree.
#[cfg(feature = "handlers")]
pub(super) fn blob_storage_prefix(
    project: ProjectRef<'_>,
    function: &str,
    trigger_prefix: &str,
) -> String {
    format!(
        "hblob/{}/{trigger_prefix}",
        project.qualified(&format!("fn/{function}"))
    )
}

/// Dispatch a function's stored triggers on a scheduler tick: fire due **cron**
/// triggers (enqueue a durable async invocation, minute-deduped) and drain
/// **queue** triggers (claim a batch + invoke per message). Route/webhook/invoke
/// triggers are request-driven and not dispatched here.
#[cfg(feature = "handlers")]
pub(super) async fn dispatch_function_triggers(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    project: ProjectRef<'_>,
    function: &boatramp_core::function::Function,
    now: &CronNow,
) {
    use boatramp_core::function::TriggerKind;
    let triggers = match deploy.list_triggers(project, &function.name).await {
        Ok(t) => t,
        Err(err) => {
            tracing::warn!(function = %function.name, %err, "listing triggers failed");
            return;
        }
    };
    for mut trigger in triggers {
        match &trigger.kind {
            TriggerKind::Cron { schedule, .. } => {
                let Ok(parsed) = boatramp_core::cron::CronSchedule::parse(schedule) else {
                    continue;
                };
                if !parsed.fires_at(now.minute, now.hour, now.dom, now.month, now.dow) {
                    continue;
                }
                if trigger.last_fired_minute == Some(now.minute_stamp) {
                    continue; // already fired this minute
                }
                enqueue_scheduled_invocation(deploy, project, function, now.minute_stamp).await;
                trigger.last_fired_minute = Some(now.minute_stamp);
                let _ = deploy.put_trigger(project, &function.name, &trigger).await;
            }
            TriggerKind::Queue {
                topic,
                group,
                start,
            } => {
                dispatch_function_queue(inner, deploy, project, function, topic, group, *start)
                    .await;
            }
            // Route / Invoke / Webhook are request-driven; Blob / Stream are not
            // dispatched from the scheduler in this pass.
            _ => {}
        }
    }
}

/// The **deterministic** id for a scheduled (function-cron) fire: a SHA-256 over `(project, function,
/// version, minute_stamp)`, so two owners firing the same cron in the same minute (the double-owner
/// window) collapse to one invocation record (B10 Invariant 5).
#[cfg(feature = "handlers")]
fn scheduled_invocation_id(
    project: &str,
    function: &str,
    version: &str,
    minute_stamp: i64,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for field in [project, function, version] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.update(minute_stamp.to_le_bytes());
    format!("cron-{}", hex::encode(hasher.finalize()))
}

/// Enqueue a durable async invocation of a function's active version with no body
/// — the scheduled (cron) fire. The existing invoke drain runs it.
///
/// The id is **deterministic** per `(project, function, version, minute_stamp)` (B10 Invariant 5): a
/// function cron fires owner-only, but in the double-owner window of a membership transition the old
/// and new owner could both fire it in the same minute — a deterministic id means both enqueue the
/// IDENTICAL record key, so the second write overwrites an identical `Queued` record instead of
/// creating a duplicate. One logical scheduled invocation per minute, cluster-wide.
#[cfg(feature = "handlers")]
pub(super) async fn enqueue_scheduled_invocation(
    deploy: &DeployStore,
    project: ProjectRef<'_>,
    function: &boatramp_core::function::Function,
    minute_stamp: i64,
) {
    let now = now_unix();
    let id = scheduled_invocation_id(
        project.as_str(),
        &function.name,
        &function.active,
        minute_stamp,
    );
    let inv = boatramp_core::function::Invocation {
        id,
        function: function.name.clone(),
        version: function.active.clone(),
        mode: boatramp_core::function::InvokeMode::Async,
        status: boatramp_core::function::InvocationStatus::Queued,
        idempotency_key: None,
        attempts: 0,
        lease_expires: None,
        request_b64: None,
        request_content_type: None,
        result: None,
        created: now,
        updated: now,
    };
    // Create-if-absent (B10): the minute-stamped id means one record per minute; a second fire in the
    // same minute (the double-owner window) is a no-op and can never resurrect a claimed/settled
    // record back to `Queued`. The next minute is a fresh id. (Replaces a blind `put_invocation` that
    // reset an in-flight record to `Queued`, re-arming a second execution.)
    if let Err(err) = deploy.enqueue_invocation_if_absent(project, &inv).await {
        tracing::warn!(function = %function.name, %err, "enqueuing scheduled invocation failed");
    }
}

/// Claim a batch from a function's queue-trigger topic and invoke the function per
/// message (ack on a delivered response, nack — for redelivery / eventual
/// dead-letter — otherwise). The topic is namespaced under the function's own
/// `fn/<name>/` scope, so it is a per-function work queue (fan-out to many
/// functions is future work).
#[cfg(feature = "handlers")]
async fn dispatch_function_queue(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    project: ProjectRef<'_>,
    function: &boatramp_core::function::Function,
    topic: &str,
    group: &str,
    start: boatramp_core::messaging::StartPosition,
) {
    let Some(messaging) = inner.messaging.clone() else {
        return;
    };
    // A `bus:<topic>` trigger drains the shared project bus (so a worker consumes
    // events a *different* component published); a plain topic drains the
    // function's own queue. Project-qualifying keeps a same-named function's
    // private queue distinct across tenants (matches the function's messaging
    // binding namespace); `default` → bare `fn/<name>/<topic>` (back-compat).
    let namespaced = match topic.strip_prefix(boatramp_handlers::BUS_TOPIC_SELECTOR) {
        Some(bus_topic) => format!("{}/{bus_topic}", project.qualified("bus")),
        None => project.qualified(&format!("fn/{}/{topic}", function.name)),
    };
    // An empty `group` is the default work-queue (`claim_grouped` delegates to
    // `claim`); a non-empty group is a durable fan-out subscriber with its own
    // cursor, so several functions can each consume every event on one bus topic.
    let batch = match messaging
        .claim_grouped(
            &namespaced,
            group,
            start,
            CONSUMER_LEASE,
            CONSUMER_BATCH,
            CONSUMER_MAX_ATTEMPTS,
        )
        .await
    {
        Ok(batch) => batch,
        Err(err) => {
            tracing::warn!(function = %function.name, topic, %err, "claiming queue messages failed");
            return;
        }
    };
    if batch.is_empty() {
        return;
    }
    let Some(component) = function.resolve(&function.active).map(str::to_owned) else {
        return;
    };
    for msg in batch {
        let bytes_in = msg.payload.len() as u64;
        let request = build_webhook_request(None, msg.payload.clone());
        // Queue-drained messages are durable background work → async lane. The producer's own-tenant
        // rides on the message as a host-minted signed-context envelope (R1); the consumer resolves
        // it iff it declares `sources: [signed_context]`, else an "own" op fails closed.
        let (response, duration_ms) = execute_function(
            inner,
            deploy,
            project,
            function,
            &component,
            request,
            0,
            boatramp_handlers::Lane::Async,
            FnTenant::Durable(msg.signed_context.clone()),
        )
        .await;
        let (status, _content_type, body) = capture_response(response).await;
        let delivered = status != StatusCode::INTERNAL_SERVER_ERROR
            && status != StatusCode::GATEWAY_TIMEOUT
            && status != StatusCode::SERVICE_UNAVAILABLE;
        let sample = boatramp_core::function::MeteringSample {
            success: delivered,
            duration_ms,
            bytes_in,
            bytes_out: body.len() as u64,
        };
        record_metering(inner, deploy, project, &function.name, &sample).await;
        if delivered {
            let _ = messaging.ack(&msg).await;
        } else {
            // Record a host-classified failure reason (P1/SEC6: never guest body bytes) so it
            // survives into the dead-letter for `dlq ls/show` + `--match`. ONLY on the final attempt
            // (the one whose failure dead-letters the message on the next claim): last_error means
            // "why it dead-lettered", not a transient retry that may yet succeed — and this keeps the
            // hot redelivery path a single write (nack), not two.
            if msg.attempts >= CONSUMER_MAX_ATTEMPTS {
                let reason = match status {
                    StatusCode::GATEWAY_TIMEOUT => "timeout",
                    StatusCode::SERVICE_UNAVAILABLE => "unavailable",
                    _ => "error",
                };
                let _ = messaging.set_last_error(&msg, reason).await;
            }
            let _ = messaging.nack(&msg).await;
        }
    }
}

// ---- signed webhook ingress (FA-5) -------------------------------------------

/// `POST /_webhooks/:name` — signed inbound-webhook ingress. **Public** but
/// signature-gated: the request signature is verified over the raw body,
/// constant-time, **before** anything runs (the SSRF/abuse guard). Requires the
/// function to declare a `webhook` config whose `secret_env` names a set host env
/// var. On a valid signature: if the webhook declares a `publish` topic, the body
/// is dropped onto the project bus and `202` returned (the fabric ingress — no
/// component runs); otherwise the function is invoked (sync, active version) and
/// its response returned. A missing/invalid signature is `401`, an oversize body
/// `413`, a missing secret `503`.
#[cfg(feature = "handlers")]
pub(super) async fn webhook_ingress(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): axum::extract::Extension<ProjectContext>,
    Path(name): Path<String>,
    request: Request,
) -> Response {
    let Some(inner) = handlers.inner.as_ref() else {
        return handler_unavailable();
    };
    let function = match deploy.get_function(project.as_ref(), &name).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, format!("no function {name:?}\n")).into_response()
        }
        Err(err) => return deploy_error_response(err),
    };
    let Some(webhook) = function.config.webhook.clone() else {
        return (
            StatusCode::NOT_FOUND,
            format!("function {name:?} has no webhook\n"),
        )
            .into_response();
    };
    // The verifying secret is a host env-var *reference*, never stored plaintext.
    let Ok(secret) = std::env::var(&webhook.secret_env) else {
        tracing::warn!(
            function = %name,
            env = %webhook.secret_env,
            "webhook secret env var is not set; refusing",
        );
        return (StatusCode::SERVICE_UNAVAILABLE, "webhook not configured\n").into_response();
    };
    // Capture the signature + content type *before* consuming the body.
    let provided = request
        .headers()
        .get(webhook.header())
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = match axum::body::to_bytes(request.into_body(), webhook.body_cap() as usize).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "webhook body exceeds the cap\n",
            )
                .into_response()
        }
    };
    let Some(provided) = provided else {
        return (StatusCode::UNAUTHORIZED, "missing webhook signature\n").into_response();
    };
    if !verify_webhook_signature(webhook.algorithm, secret.as_bytes(), &body, &provided) {
        return (StatusCode::UNAUTHORIZED, "invalid webhook signature\n").into_response();
    }
    // Rate-limit quota (fail-closed) applies to a verified webhook like any invoke.
    if let Err(response) = admit_by_quota(inner, &deploy, project.as_ref(), &function).await {
        return response;
    }
    // Ingress mode: a verified webhook with a `publish` topic drops the raw body
    // onto the **project bus** (a consumer subscribes with `bus:<topic>`) and
    // returns 202 — external input into the fabric with no component to run. The
    // whole path stayed default-deny (secret required, signature verified, body
    // capped, quota-admitted) before we got here; a spoofed post never reaches it.
    if let Some(topic) = &webhook.publish {
        let Some(messaging) = inner.messaging.as_ref() else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "messaging backend not configured\n",
            )
                .into_response();
        };
        let bus_topic = format!("{}/{topic}", project.as_ref().qualified("bus"));
        if let Err(err) = messaging.publish(&bus_topic, &body).await {
            tracing::warn!(function = %name, topic, %err, "webhook ingress publish failed");
            return (StatusCode::BAD_GATEWAY, "webhook publish failed\n").into_response();
        }
        return (StatusCode::ACCEPTED, "published\n").into_response();
    }
    let Some(component) = function.resolve(&function.active).map(str::to_owned) else {
        return handler_unavailable();
    };
    let bytes_in = body.len() as u64;
    let request = build_webhook_request(content_type, body.to_vec());
    // An inbound webhook is connection-bearing (the sender awaits the response)
    // → sync lane.
    let (response, duration_ms) = execute_function(
        inner,
        &deploy,
        project.as_ref(),
        &function,
        &component,
        request,
        0,
        boatramp_handlers::Lane::Sync,
        // Inbound webhook: the signed-context tenant source is reserved (unwired), so no source
        // yet — an `own` op fails closed.
        FnTenant::Background,
    )
    .await;
    let sample = boatramp_core::function::MeteringSample {
        success: response.status().as_u16() < 500,
        duration_ms,
        bytes_in,
        bytes_out: 0,
    };
    record_metering(inner, &deploy, project.as_ref(), &function.name, &sample).await;
    response
}

/// Verify a webhook signature over `body`, constant-time. HMAC-SHA256 accepts the
/// raw hex or a `sha256=`-prefixed hex (GitHub style).
#[cfg(feature = "handlers")]
fn verify_webhook_signature(
    algorithm: boatramp_core::function::WebhookAlgorithm,
    secret: &[u8],
    body: &[u8],
    provided: &str,
) -> bool {
    use boatramp_core::function::WebhookAlgorithm;
    use hmac::{Hmac, Mac};
    use subtle::ConstantTimeEq;
    match algorithm {
        WebhookAlgorithm::HmacSha256 => {
            let provided = provided.strip_prefix("sha256=").unwrap_or(provided);
            let Ok(provided_bytes) = hex::decode(provided) else {
                return false;
            };
            // HMAC accepts a key of any length, so this construction never fails.
            let Ok(mut mac) = <Hmac<sha2::Sha256> as Mac>::new_from_slice(secret) else {
                return false;
            };
            mac.update(body);
            let expected = mac.finalize().into_bytes();
            provided_bytes.ct_eq(&expected).into()
        }
    }
}

/// Build the engine request for a verified webhook: a `POST` carrying the raw body
/// (+ content type). `execute_function` rewrites the URI to the invoke authority.
#[cfg(feature = "handlers")]
fn build_webhook_request(content_type: Option<String>, body: Vec<u8>) -> Request {
    let mut builder = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/");
    if let Some(ct) = &content_type {
        if let Ok(value) = HeaderValue::from_str(ct) {
            builder = builder.header(header::CONTENT_TYPE, value);
        }
    }
    builder
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| Request::new(axum::body::Body::empty()))
}

/// Gap 3 live gate (v0.4.7): the host-verified guest-presented producer stamp, end to end. Proves
/// [`ServerProducerContextSource`] RE-verifies a guest-presented token against the component's
/// declared `token_claims`, extracts the tenant, and host-seals a durable context that resolves
/// (via [`verify_context`](boatramp_core::cose::verify_context)) back to that tenant — and that a
/// forged / wrong-issuer token seals NOTHING (fail-closed). Also asserts the per-message batch
/// isolation of the shared producer-context cell (the Finding-1 fix). Needs `oidc` (the JWKS
/// verifier); runs in-process (no compiled guest, no libsql).
#[cfg(all(test, feature = "handlers", feature = "oidc"))]
mod gap3_tests {
    use super::*;
    use boatramp_core::cose::{verify_context, LocalSigner, Signer};
    use boatramp_handlers::ProducerContextSource as _;
    use ed25519_dalek::{Signer as _, SigningKey};

    const ISS: &str = "https://idp.example";

    fn b64url(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Sign an Ed25519 JWT by hand (the host verifies it via the JWKS in `jwks_env`).
    fn ed25519_token(key: &SigningKey, kid: &str, claims: serde_json::Value) -> String {
        let header = b64url(
            serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid })
                .to_string()
                .as_bytes(),
        );
        let payload = b64url(claims.to_string().as_bytes());
        let signing_input = format!("{header}.{payload}");
        let sig = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64url(&sig.to_bytes()))
    }

    #[tokio::test]
    async fn present_token_verify_seal_resolve_chain_and_fail_closed() {
        // The app's Ed25519 signing key + its JWKS (public half), published to a host env var the
        // component's `token_claims` names — the SAME verifier path a request-lane `token` source uses.
        let app_key = SigningKey::from_bytes(&[7u8; 32]);
        let jwks = serde_json::json!({ "keys": [ {
            "kty": "OKP", "crv": "Ed25519", "kid": "app-1",
            "x": b64url(app_key.verifying_key().as_bytes()),
        } ] })
        .to_string();
        let env_name = format!("BR_TEST_GAP3_JWKS_{}", std::process::id());
        std::env::set_var(&env_name, &jwks);
        let token_cfg = boatramp_core::config::HandlerGraphqlTokenClaims {
            issuer: ISS.to_string(),
            jwks_env: Some(env_name.clone()),
            jwks_url: None,
            audience: None,
        };

        // The fleet signer that seals + verifies the durable context (deterministic test key).
        let fleet: Arc<dyn Signer> = Arc::new(
            LocalSigner::from_private_hex(&format!("ed25519:{}", hex::encode([9u8; 32]))).unwrap(),
        );
        let source = ServerProducerContextSource {
            token_cfg: token_cfg.clone(),
            claim: "tid".to_string(),
            signer: fleet.clone(),
        };

        let exp = boatramp_core::time::now_unix() + 3600;

        // (1) A valid token → the host seals a context that resolves back to the token's tenant.
        let good = ed25519_token(
            &app_key,
            "app-1",
            serde_json::json!({ "iss": ISS, "exp": exp, "tid": "tenant_B" }),
        );
        let sealed = source
            .seal_presented(&good)
            .await
            .expect("a valid presented token seals a producer context");
        let resolved = verify_context(
            &sealed,
            &fleet.public_key(),
            boatramp_core::time::now_unix(),
        )
        .expect("the sealed context verifies against the fleet anchor");
        assert_eq!(
            resolved, "tenant_B",
            "the host-sealed context resolves back to the tenant the presented token carried"
        );

        // (2) A token forged with a DIFFERENT key (same kid) → the host does not verify it → seals
        // nothing (the guest cannot name a tenant it holds no valid token for).
        let forged = ed25519_token(
            &SigningKey::from_bytes(&[42u8; 32]),
            "app-1",
            serde_json::json!({ "iss": ISS, "exp": exp, "tid": "tenant_B" }),
        );
        assert!(
            source.seal_presented(&forged).await.is_err(),
            "a forged token must not seal a producer context (fail-closed)"
        );

        // (3) A validly-signed token whose issuer is wrong → rejected.
        let wrong_iss = ed25519_token(
            &app_key,
            "app-1",
            serde_json::json!({ "iss": "https://evil.example", "exp": exp, "tid": "tenant_B" }),
        );
        assert!(
            source.seal_presented(&wrong_iss).await.is_err(),
            "a wrong-issuer token must not seal (fail-closed)"
        );

        std::env::remove_var(&env_name);
        println!(
            "PRESENT-TOKEN CHAIN OK: a guest-presented app JWT was host-verified against the \
             component's token_claims, its tenant extracted + host-sealed, and the sealed durable \
             context resolved back to tenant_B via the fleet anchor; a forged and a wrong-issuer \
             token both sealed nothing (fail-closed)"
        );
    }

    #[test]
    fn producer_context_cell_is_reset_per_message_in_a_batch() {
        // The Finding-1 fix: a consumer batch reuses one shared cell. Snapshot the bind-time value,
        // then before each message restore it — so a `present-token` on message 1 cannot leak onto
        // message 2's publishes. This mirrors the reset loop in `dispatch_consumer_batch`.
        let cell: boatramp_handlers::ProducerContext =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let bind_time = cell.lock().unwrap().clone(); // None (a consumer resolves no own tenant)

        // Message 1 presents tenant A (host-seals it into the shared cell) and would publish under A.
        *cell.lock().unwrap() = Some("sealed:tenant_A".to_string());
        assert_eq!(
            cell.lock().unwrap().clone(),
            Some("sealed:tenant_A".to_string())
        );

        // Before message 2 the batch loop restores the bind-time value.
        *cell.lock().unwrap() = bind_time.clone();
        // Message 2 does NOT present → the cell is back to bind-time (None), NOT tenant A.
        assert_eq!(
            cell.lock().unwrap().clone(),
            None,
            "message 2 must not inherit message 1's presented tenant (no cross-message leak)"
        );
    }
}
