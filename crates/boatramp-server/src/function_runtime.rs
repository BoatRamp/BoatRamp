//! The function runtime surface (FA-3..FA-5): synchronous and asynchronous
//! invocation, the durable async-queue drain, per-function metering and quota
//! admission, trigger configuration, and the webhook/queue/blob event dispatch
//! that fans incoming events into invocations. `handlers`-gated; pulls the
//! serve-pipeline scope in via `use super::*`.

use super::*;

/// The authority the engine sees for an invoked function. `wasi:http` needs a
/// scheme + authority; the public control-plane path is the host's concern, so
/// every function is invoked at `http://function.invoke/`.
#[cfg(feature = "handlers")]
const INVOKE_AUTHORITY: &str = "function.invoke";

/// Attempts a durable (async) invocation gets before it is dead-lettered
/// (left terminal-`failed` in its keyspace for inspection).
#[cfg(feature = "handlers")]
const MAX_INVOKE_ATTEMPTS: u32 = 5;

/// Max request body buffered when **enqueuing** an async invocation. The sync
/// path streams into the guest and never buffers; async must persist the body,
/// so it is bounded here (mirrors the engine's default body cap).
#[cfg(feature = "handlers")]
const MAX_ASYNC_BODY_BYTES: usize = 16 * 1024 * 1024;

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
    Path(name): Path<String>,
    axum::extract::Query(query): axum::extract::Query<InvokeQuery>,
    request: Request,
) -> Response {
    let Some(inner) = handlers.inner.as_ref() else {
        return handler_unavailable();
    };
    let function = match deploy.get_function(&name).await {
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
        match deploy.get_idempotency(&name, key).await {
            Ok(Some(id)) => {
                if let Ok(Some(inv)) = deploy.get_invocation(&name, &id).await {
                    return replay_invocation(&inv);
                }
            }
            Ok(None) => {}
            Err(err) => return deploy_error_response(err),
        }
    }

    // Rate-limit quota (FA-4), fail-closed → 429, charged once at entry for both
    // sync and async (a drain retry does not re-charge).
    if let Err(response) = admit_by_quota(inner, &deploy, &function).await {
        return response;
    }

    if is_async {
        enqueue_invocation(&deploy, &function, &component, request, idem_key).await
    } else {
        execute_sync(inner, &deploy, &function, &component, request, idem_key).await
    }
}

/// Run a function inline and return its response. With an idempotency key the
/// response is captured + persisted (as a `succeeded` [`Invocation`]) so a repeat
/// replays it; without one it streams straight back.
#[cfg(feature = "handlers")]
async fn execute_sync(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
    component: &str,
    request: Request,
    idem_key: Option<String>,
) -> Response {
    let (response, duration_ms) =
        execute_function(inner, deploy, function, component, request).await;
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
        record_metering(inner, deploy, &function.name, &sample).await;
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
    record_metering(inner, deploy, &function.name, &sample).await;
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
    if let Err(err) = deploy.put_invocation(&inv).await {
        return deploy_error_response(err);
    }
    if let Err(err) = deploy.put_idempotency(&function.name, &key, &id).await {
        return deploy_error_response(err);
    }
    rebuild_response(status, content_type.as_deref(), body)
}

/// Durably enqueue an async invocation: buffer the request body, persist a
/// `queued` [`Invocation`], bind the idempotency key, and return `202` + id.
#[cfg(feature = "handlers")]
async fn enqueue_invocation(
    deploy: &DeployStore,
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
        request_b64: (!body.is_empty()).then(|| b64_encode(&body)),
        request_content_type: content_type,
        result: None,
        created: now,
        updated: now,
    };
    if let Err(err) = deploy.put_invocation(&inv).await {
        return deploy_error_response(err);
    }
    if let Some(key) = &idem_key {
        if let Err(err) = deploy.put_idempotency(&function.name, key, &id).await {
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
    Path((name, id)): Path<(String, String)>,
) -> Response {
    match deploy.get_invocation(&name, &id).await {
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
pub(super) async fn execute_function(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
    component: &str,
    request: Request,
) -> (Response, u64) {
    // Concurrency quota (held through the head, mirroring the site permit).
    let _permit = match acquire_function_permit(inner, &function.name, &function.config.quota) {
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
    let scope = format!("fn/{}", function.name);
    let bindings = build_function_bindings(inner, &scope, &function.config).await;
    let limits = function_limits(function.config.limits.as_ref());
    let request = prepare_invoke_request(request);
    let start = std::time::Instant::now();
    let result = inner
        .engine
        .serve_with_limits(component, &wasm, request, bindings, limits)
        .await;
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

/// Build a top-level function's bindings. Unlike a site handler (whose grants are
/// the site allowlist ∩ its imports), a top-level function is admin-deployed, so
/// its declared `imports` **are** its grants — served under its own `fn/<name>`
/// scope so kv/blob/messaging/sql land in an isolated namespace.
#[cfg(feature = "handlers")]
async fn build_function_bindings(
    inner: &HandlerRuntimeInner,
    scope: &str,
    config: &boatramp_core::function::FunctionConfig,
) -> boatramp_handlers::Bindings {
    let granted = |name: &str| config.imports.iter().any(|i| i == name);
    let mut bindings = boatramp_handlers::Bindings::new(scope);
    if granted("wasi:keyvalue") {
        bindings = bindings.with_keyvalue(scope, inner.kv.clone());
    }
    if granted("wasi:blobstore") {
        let max_blob = inner.max_blob_bytes.get().copied().unwrap_or(0);
        bindings = bindings.with_blobstore(scope, inner.storage.clone(), max_blob);
    }
    if granted("sql") {
        if let Some(provider) = &inner.sql {
            match provider.database(scope, "").await {
                Ok(backend) => bindings = bindings.with_sql("", backend),
                Err(err) => tracing::warn!(scope, %err, "opening function SQL database failed"),
            }
        }
    }
    if granted("wasi:messaging") {
        if let Some(messaging) = &inner.messaging {
            bindings = bindings.with_messaging(format!("{scope}/"), messaging.clone());
        }
    }
    inner.logs.configure(scope, None);
    bindings = bindings.with_logging(scope.to_string(), inner.logs.clone());
    let env: Vec<(String, String)> = config
        .env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    bindings.with_env(env)
}

/// Per-invocation limits for a function: its own `limits` (memory/timeout/fuel),
/// left at the engine default where unset. The engine clamps to its ceiling.
#[cfg(feature = "handlers")]
fn function_limits(
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
    if let Ok(uri) = format!("http://{INVOKE_AUTHORITY}/").parse() {
        *request.uri_mut() = uri;
    }
    request
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static(INVOKE_AUTHORITY));
    request
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

/// Drain a function's queued async invocations: run each once, capturing its
/// result. A failed run is retried next tick until [`MAX_INVOKE_ATTEMPTS`], then
/// dead-lettered (left `failed` for inspection). Driven from the scheduler tick.
#[cfg(feature = "handlers")]
pub(super) async fn drain_function_invocations(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
) {
    let queued = match deploy.list_invocations(&function.name).await {
        Ok(list) => list,
        Err(err) => {
            tracing::warn!(function = %function.name, %err, "listing invocations failed");
            return;
        }
    };
    for inv in queued {
        if !matches!(
            inv.status,
            boatramp_core::function::InvocationStatus::Queued
        ) {
            continue;
        }
        run_queued_invocation(inner, deploy, function, inv).await;
    }
}

/// Execute one queued invocation against its pinned version, persisting the
/// terminal outcome (or re-queuing for retry / dead-lettering on failure).
#[cfg(feature = "handlers")]
async fn run_queued_invocation(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
    mut inv: boatramp_core::function::Invocation,
) {
    use boatramp_core::function::InvocationStatus;
    // The version was pinned at enqueue; a later deploy can't silently change it.
    let Some(component) = function.resolve(&inv.version).map(str::to_owned) else {
        // The pinned version is gone (rolled off / pruned) — unrunnable, so fail.
        inv.status = InvocationStatus::Failed;
        inv.updated = now_unix();
        let _ = deploy.put_invocation(&inv).await;
        return;
    };
    inv.status = InvocationStatus::Running;
    inv.attempts = inv.attempts.saturating_add(1);
    inv.updated = now_unix();
    if let Err(err) = deploy.put_invocation(&inv).await {
        tracing::warn!(function = %function.name, %err, "marking invocation running failed");
        return;
    }
    let bytes_in = inv
        .request_b64
        .as_deref()
        .map(|b| b64_decode(b).len() as u64)
        .unwrap_or(0);
    let request = build_stored_request(&inv);
    let (response, duration_ms) =
        execute_function(inner, deploy, function, &component, request).await;
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
    inv.updated = now_unix();
    let _ = deploy.put_invocation(&inv).await;
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
        record_metering(inner, deploy, &function.name, &sample).await;
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
/// update (the KV is get/put, not atomic-increment).
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
/// when at the limit (the caller turns that into a `503`).
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
    function: &boatramp_core::function::Function,
) -> Result<(), Response> {
    let quota = &function.config.quota;
    if quota.max_invocations.is_none() {
        return Ok(());
    }
    let lock = function_meter_lock(inner, &function.name);
    let _guard = lock.lock().await;
    let now = now_unix();
    let mut metering = match deploy.get_metering(&function.name).await {
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
    if let Err(err) = deploy.put_metering(&metering).await {
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
    function: &str,
    sample: &boatramp_core::function::MeteringSample,
) {
    let lock = function_meter_lock(inner, function);
    let _guard = lock.lock().await;
    let now = now_unix();
    let mut metering = match deploy.get_metering(function).await {
        Ok(Some(m)) => m,
        Ok(None) => boatramp_core::function::Metering::new(function),
        Err(err) => {
            tracing::warn!(function, %err, "reading metering failed");
            return;
        }
    };
    metering.record(sample, now);
    if let Err(err) = deploy.put_metering(&metering).await {
        tracing::warn!(function, %err, "writing metering failed");
    }
}

/// `GET /api/functions/:name/usage` (FA-4) — the function's usage aggregate.
/// `system·read`.
#[cfg(feature = "handlers")]
pub(super) async fn get_function_usage(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
) -> Response {
    match deploy.get_metering(&name).await {
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
    Path((name, id)): Path<(String, String)>,
    Json(kind): Json<boatramp_core::function::TriggerKind>,
) -> Response {
    match deploy.get_function(&name).await {
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
            let storage_prefix = blob_storage_prefix(&name, prefix);
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
    if let Err(err) = deploy.put_trigger(&name, &trigger).await {
        return deploy_error_response(err);
    }
    Json(trigger).into_response()
}

/// `GET /api/functions/:name/triggers` — list a function's stored triggers.
/// `system·read`.
#[cfg(feature = "handlers")]
pub(super) async fn list_triggers_handler(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
) -> Response {
    match deploy.list_triggers(&name).await {
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
    Path((name, id)): Path<(String, String)>,
) -> Response {
    // Look the trigger up first: a `Blob` trigger may own a provisioned pipeline
    // to retract before the trigger record is gone.
    if let (Some(inner), Ok(Some(trigger))) = (
        handlers.inner.as_ref(),
        deploy.get_trigger(&name, &id).await,
    ) {
        if let (boatramp_core::function::TriggerKind::Blob { prefix }, Some(provider)) =
            (&trigger.kind, inner.watch_provider.get())
        {
            let storage_prefix = blob_storage_prefix(&name, prefix);
            if let Ok(Some(record)) = deploy
                .get_managed_notification(&name, &storage_prefix)
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
    match deploy.delete_trigger(&name, &id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// The full storage key prefix a function's `Blob { prefix }` trigger watches:
/// the function's blobstore namespace (`hblob/fn/<name>/`) joined with the
/// trigger-relative prefix. The provisioner (bucket-notification filter), the
/// notification ledger, and the `spawn_blob_watcher` consumer all key off this,
/// so they must agree.
#[cfg(feature = "handlers")]
pub(super) fn blob_storage_prefix(function: &str, trigger_prefix: &str) -> String {
    format!("hblob/fn/{function}/{trigger_prefix}")
}

/// Dispatch a function's stored triggers on a scheduler tick: fire due **cron**
/// triggers (enqueue a durable async invocation, minute-deduped) and drain
/// **queue** triggers (claim a batch + invoke per message). Route/webhook/invoke
/// triggers are request-driven and not dispatched here.
#[cfg(feature = "handlers")]
pub(super) async fn dispatch_function_triggers(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
    now: &CronNow,
) {
    use boatramp_core::function::TriggerKind;
    let triggers = match deploy.list_triggers(&function.name).await {
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
                enqueue_scheduled_invocation(deploy, function).await;
                trigger.last_fired_minute = Some(now.minute_stamp);
                let _ = deploy.put_trigger(&function.name, &trigger).await;
            }
            TriggerKind::Queue { topic } => {
                dispatch_function_queue(inner, deploy, function, topic).await;
            }
            // Route / Invoke / Webhook are request-driven; Blob / Stream are not
            // dispatched from the scheduler in this pass.
            _ => {}
        }
    }
}

/// Enqueue a durable async invocation of a function's active version with no body
/// — the scheduled (cron) fire. The existing invoke drain runs it.
#[cfg(feature = "handlers")]
async fn enqueue_scheduled_invocation(
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
) {
    let now = now_unix();
    let inv = boatramp_core::function::Invocation {
        id: new_invocation_id(),
        function: function.name.clone(),
        version: function.active.clone(),
        mode: boatramp_core::function::InvokeMode::Async,
        status: boatramp_core::function::InvocationStatus::Queued,
        idempotency_key: None,
        attempts: 0,
        request_b64: None,
        request_content_type: None,
        result: None,
        created: now,
        updated: now,
    };
    if let Err(err) = deploy.put_invocation(&inv).await {
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
    function: &boatramp_core::function::Function,
    topic: &str,
) {
    let Some(messaging) = inner.messaging.clone() else {
        return;
    };
    let namespaced = format!("fn/{}/{topic}", function.name);
    let batch = match messaging
        .claim(
            &namespaced,
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
        let (response, duration_ms) =
            execute_function(inner, deploy, function, &component, request).await;
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
        record_metering(inner, deploy, &function.name, &sample).await;
        if delivered {
            let _ = messaging.ack(&msg).await;
        } else {
            let _ = messaging.nack(&msg).await;
        }
    }
}

// ---- signed webhook ingress (FA-5) -------------------------------------------

/// `POST /_webhooks/:name` (FA-5) — signed inbound-webhook ingress. **Public** but
/// signature-gated: the request signature is verified over the raw body,
/// constant-time, **before** the guest runs (the SSRF/abuse guard). Requires the
/// function to declare a `webhook` config whose `secret_env` names a set host env
/// var. A valid signature invokes the function (sync, active version) and returns
/// its response; a missing/invalid signature is `401`, an oversize body `413`.
#[cfg(feature = "handlers")]
pub(super) async fn webhook_ingress(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(name): Path<String>,
    request: Request,
) -> Response {
    let Some(inner) = handlers.inner.as_ref() else {
        return handler_unavailable();
    };
    let function = match deploy.get_function(&name).await {
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
    if let Err(response) = admit_by_quota(inner, &deploy, &function).await {
        return response;
    }
    let Some(component) = function.resolve(&function.active).map(str::to_owned) else {
        return handler_unavailable();
    };
    let bytes_in = body.len() as u64;
    let request = build_webhook_request(content_type, body.to_vec());
    let (response, duration_ms) =
        execute_function(inner, &deploy, &function, &component, request).await;
    let sample = boatramp_core::function::MeteringSample {
        success: response.status().as_u16() < 500,
        duration_ms,
        bytes_in,
        bytes_out: 0,
    };
    record_metering(inner, &deploy, &function.name, &sample).await;
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
