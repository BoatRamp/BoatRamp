//! The background scheduler: the per-tick loop that drives each active
//! deployment's consumers, crons, and blob-change watchers, plus the shared
//! per-site limit/permit/error helpers the request path also uses.
//! `handlers`-gated; pulls the serve-pipeline scope in via `use super::*`.

use super::*;

/// How often the scheduler polls each active consumer for messages.
#[cfg(feature = "handlers")]
const SCHEDULER_TICK: Duration = Duration::from_millis(500);
/// Visibility-timeout lease per consumer delivery.
#[cfg(feature = "handlers")]
pub(super) const CONSUMER_LEASE: Duration = Duration::from_secs(30);
/// Deliveries before a message is dead-lettered.
#[cfg(feature = "handlers")]
pub(super) const CONSUMER_MAX_ATTEMPTS: u32 = 5;
/// Messages claimed per consumer per tick.
#[cfg(feature = "handlers")]
pub(super) const CONSUMER_BATCH: usize = 16;

/// Per-invocation limits from the site's caps only (consumers have no
/// per-component limit config), clamped to the engine ceiling downstream.
#[cfg(feature = "handlers")]
fn site_limits(
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
) -> boatramp_handlers::Limits {
    let mut limits = boatramp_handlers::Limits::default();
    if let Some(mb) = site_handlers.max_memory_mb {
        limits.memory_bytes = (mb as usize).saturating_mul(1024 * 1024);
    }
    if let Some(ms) = site_handlers.max_timeout_ms {
        limits.timeout_ms = ms as u64;
    }
    limits
}

/// Current wall-clock decomposed into cron fields (+ a monotonic minute stamp
/// for once-per-minute dedup).
#[cfg(feature = "handlers")]
#[derive(Clone, Copy)]
pub(super) struct CronNow {
    pub(super) minute: u32,
    pub(super) hour: u32,
    pub(super) dom: u32,
    pub(super) month: u32,
    pub(super) dow: u32,
    pub(super) minute_stamp: i64,
}

#[cfg(feature = "handlers")]
impl CronNow {
    fn now() -> Self {
        use chrono::{Datelike, Timelike, Utc};
        let t = Utc::now();
        Self {
            minute: t.minute(),
            hour: t.hour(),
            dom: t.day(),
            month: t.month(),
            dow: t.weekday().num_days_from_sunday(),
            minute_stamp: t.timestamp().div_euclid(60),
        }
    }
}

/// Per-cron scheduler state: the minute we last fired in (dedup across the
/// sub-minute ticks) and whether a fire is still running (for `overlap: Skip`).
#[cfg(feature = "handlers")]
pub(super) struct CronEntry {
    last_minute: i64,
    pub(super) running: Arc<std::sync::atomic::AtomicBool>,
}

impl HandlerRuntime {
    /// Spawn the **background scheduler**: a loop that drives each *active*
    /// deployment's consumers and crons. "Active" = a site's
    /// current (production) deployment plus any site-configured background
    /// aliases; previews are never enumerated, so a preview deployment runs
    /// request handlers but **no background work**. Returns `None` when handlers
    /// are disabled (or no runtime). The caller aborts the handle on shutdown.
    #[cfg(feature = "handlers")]
    pub fn spawn_scheduler(&self, deploy: DeployStore) -> Option<tokio::task::JoinHandle<()>> {
        let inner = self.inner.clone()?;
        Some(tokio::spawn(async move {
            // Content-addressed component bytes never change, so cache them
            // across ticks (avoids re-reading the blob when a consumer is idle).
            let mut wasm_cache: std::collections::HashMap<String, Vec<u8>> =
                std::collections::HashMap::new();
            let mut cron_state: std::collections::HashMap<String, CronEntry> =
                std::collections::HashMap::new();
            // Live blob-change watchers, keyed by `<function>|<trigger id>`; each
            // owns a native watch stream + its drain task (FA-5).
            let mut blob_watchers: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
                std::collections::HashMap::new();
            let mut interval = tokio::time::interval(SCHEDULER_TICK);
            loop {
                interval.tick().await;
                // Spawned cron fires are detached (bounded by the invocation
                // timeout); their handles are dropped here.
                if let Err(err) = run_scheduler_tick(
                    &inner,
                    &deploy,
                    &mut wasm_cache,
                    &mut cron_state,
                    CronNow::now(),
                )
                .await
                {
                    tracing::warn!(%err, "scheduler tick failed");
                }
                // Reconcile blob-change watchers (FA-5): spawn one per live
                // `Blob` trigger, drop those whose trigger is gone.
                reconcile_blob_watchers(&inner, &deploy, &mut blob_watchers).await;
            }
        }))
    }
}

/// Reconcile the live blob-change watchers against the stored `Blob` triggers:
/// spawn a watcher for each new trigger, abort + drop watchers whose trigger was
/// removed. Leader-gated (shared-FS clusters would otherwise fire per-node).
#[cfg(feature = "handlers")]
async fn reconcile_blob_watchers(
    inner: &Arc<HandlerRuntimeInner>,
    deploy: &DeployStore,
    watchers: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
) {
    use boatramp_core::function::TriggerKind;
    // Only the leader (or a single node) dispatches, matching cron/invoke.
    if inner.cron_leader_gate.get().is_some_and(|gate| !gate()) {
        for (_, handle) in watchers.drain() {
            handle.abort();
        }
        return;
    }
    let functions = match deploy.list_stored_functions().await {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut desired = std::collections::HashSet::new();
    for function in functions {
        let triggers = deploy
            .list_triggers(&function.name)
            .await
            .unwrap_or_default();
        for trigger in triggers {
            let TriggerKind::Blob { prefix } = &trigger.kind else {
                continue;
            };
            let watch_id = format!("{}|{}", function.name, trigger.id);
            desired.insert(watch_id.clone());
            if let std::collections::hash_map::Entry::Vacant(slot) = watchers.entry(watch_id) {
                if let Some(handle) =
                    spawn_blob_watcher(inner.clone(), deploy.clone(), function.clone(), prefix)
                        .await
                {
                    slot.insert(handle);
                }
            }
        }
    }
    // Drop watchers whose trigger no longer exists.
    watchers.retain(|id, handle| {
        if desired.contains(id) {
            true
        } else {
            handle.abort();
            false
        }
    });
}

/// Spawn a task that watches the function's blob prefix and enqueues an async
/// invocation on each change. Returns `None` if the backend can't watch (the
/// activation gate should already have refused, so this is defensive).
#[cfg(feature = "handlers")]
pub(super) async fn spawn_blob_watcher(
    inner: Arc<HandlerRuntimeInner>,
    deploy: DeployStore,
    function: boatramp_core::function::Function,
    prefix: &str,
) -> Option<tokio::task::JoinHandle<()>> {
    // The function's blobstore lives under `hblob/fn/<name>/`; the trigger prefix
    // is relative to that namespace (same key the provisioner + ledger use).
    let storage_prefix = blob_storage_prefix(&function.name, prefix);
    let mut stream = match inner.storage.watch(&storage_prefix).await {
        Ok(Some(stream)) => stream,
        Ok(None) => return None,
        Err(err) => {
            tracing::warn!(function = %function.name, %err, "starting blob watch failed");
            return None;
        }
    };
    let namespace = format!("hblob/fn/{}/", function.name);
    Some(tokio::spawn(async move {
        use futures::StreamExt;
        while let Some(change) = stream.next().await {
            enqueue_blob_invocation(&deploy, &function, &change, &namespace).await;
        }
    }))
}

/// Enqueue a durable async invocation for a blob change, with the changed key +
/// kind as the JSON request body (the function-relative key, `hblob/fn/<name>/`
/// stripped).
#[cfg(feature = "handlers")]
async fn enqueue_blob_invocation(
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
    change: &boatramp_core::BlobChange,
    namespace: &str,
) {
    use boatramp_core::BlobChangeKind;
    let key = change.key.strip_prefix(namespace).unwrap_or(&change.key);
    let kind = match change.kind {
        BlobChangeKind::Created => "created",
        BlobChangeKind::Modified => "modified",
        BlobChangeKind::Removed => "removed",
    };
    let body = serde_json::json!({ "key": key, "kind": kind });
    let payload = serde_json::to_vec(&body).unwrap_or_default();
    let now = now_unix();
    let inv = boatramp_core::function::Invocation {
        id: new_invocation_id(),
        function: function.name.clone(),
        version: function.active.clone(),
        mode: boatramp_core::function::InvokeMode::Async,
        status: boatramp_core::function::InvocationStatus::Queued,
        idempotency_key: None,
        attempts: 0,
        request_b64: (!payload.is_empty()).then(|| b64_encode(&payload)),
        request_content_type: Some("application/json".to_string()),
        result: None,
        created: now,
        updated: now,
    };
    if let Err(err) = deploy.put_invocation(&inv).await {
        tracing::warn!(function = %function.name, %err, "enqueuing blob invocation failed");
    }
}

/// One scheduler pass: for every site, drive the consumers and crons of its
/// active deployments. Consumers are processed inline (claim+dispatch); crons
/// that are due are fired as detached tasks (loopback dispatch). Returns the
/// number of messages acked and the spawned cron-fire handles (for tests).
#[cfg(feature = "handlers")]
pub(super) async fn run_scheduler_tick(
    inner: &Arc<HandlerRuntimeInner>,
    deploy: &DeployStore,
    wasm_cache: &mut std::collections::HashMap<String, Vec<u8>>,
    cron_state: &mut std::collections::HashMap<String, CronEntry>,
    now: CronNow,
) -> Result<(usize, Vec<tokio::task::JoinHandle<()>>), DeployError> {
    use std::sync::atomic::Ordering;
    let mut acked = 0;
    let mut cron_handles = Vec::new();
    for site in deploy.list_sites().await? {
        let Some(site_config) = deploy.get_site_config(&site).await? else {
            continue;
        };
        let Some(site_handlers) = site_config.handlers.as_ref().filter(|h| h.enabled) else {
            continue;
        };
        // Active deployments: the current one (production, namespace `{site}`)
        // plus each background alias (namespace `{site}/{alias}`). Never previews.
        let mut active: Vec<(String, String)> = Vec::new();
        if let Some(id) = deploy.current_id(&site).await? {
            active.push((id, site.clone()));
        }
        for alias in &site_handlers.background_aliases {
            if let Some(id) = deploy.get_alias(&site, alias).await? {
                active.push((id, format!("{site}/{alias}")));
            }
        }
        for (deploy_id, scope) in active {
            let Some(manifest) = deploy.get_manifest(&deploy_id).await? else {
                continue;
            };
            // --- consumers (only with a messaging backend) ---
            if let Some(messaging) = inner.messaging.clone() {
                for consumer in &manifest.config.consumers {
                    let Some(entry) = manifest.files.get(&consumer.component) else {
                        tracing::warn!(site, component = %consumer.component, "consumer component missing");
                        continue;
                    };
                    // Cache the (content-addressed) component bytes by hash.
                    if !wasm_cache.contains_key(&entry.hash) {
                        match read_blob_bytes(deploy, &entry.hash).await {
                            Ok(bytes) => {
                                wasm_cache.insert(entry.hash.clone(), bytes);
                            }
                            Err(err) => {
                                tracing::warn!(site, %err, "reading consumer component failed");
                                continue;
                            }
                        }
                    }
                    let wasm = &wasm_cache[&entry.hash];
                    let bindings = build_bindings(
                        inner,
                        &site,
                        &scope,
                        None,
                        &consumer.imports,
                        site_handlers,
                        // Consumers have no deploy `env`; site secrets still apply.
                        &std::collections::BTreeMap::new(),
                    )
                    .await;
                    acked += dispatch_consumer_batch(
                        &inner.engine,
                        messaging.as_ref(),
                        &inner.metrics,
                        &site,
                        &format!("{scope}/{}", consumer.topic),
                        &format!("{scope}/"),
                        &entry.hash,
                        wasm,
                        &bindings,
                        site_limits(site_handlers),
                        CONSUMER_LEASE,
                        CONSUMER_MAX_ATTEMPTS,
                        CONSUMER_BATCH,
                    )
                    .await;
                }
            }
            // --- crons (leader-only in cluster mode) ---
            // The gate fires crons on exactly one node; consumers above run on
            // every node (leased dispatch distributes them). `None` = single
            // node, always fires.
            let cron_enabled = inner.cron_leader_gate.get().is_none_or(|gate| gate());
            for (idx, cron) in manifest.config.crons.iter().enumerate() {
                if !cron_enabled {
                    break;
                }
                let Ok(schedule) = boatramp_core::cron::CronSchedule::parse(&cron.schedule) else {
                    continue;
                };
                if !schedule.fires_at(now.minute, now.hour, now.dom, now.month, now.dow) {
                    continue;
                }
                let key = format!("{scope}|cron|{idx}");
                let entry = cron_state.entry(key).or_insert_with(|| CronEntry {
                    last_minute: -1,
                    running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                });
                if entry.last_minute == now.minute_stamp {
                    continue; // already fired this minute
                }
                if matches!(cron.overlap, boatramp_core::config::Overlap::Skip)
                    && entry.running.load(Ordering::Acquire)
                {
                    tracing::info!(site, route = %cron.route, "cron skipped (previous run still in flight)");
                    continue;
                }
                entry.last_minute = now.minute_stamp;
                let running = entry.running.clone();
                running.store(true, Ordering::Release);
                let (inner, deploy, manifest, site, scope, site_handlers, cron) = (
                    inner.clone(),
                    deploy.clone(),
                    manifest.clone(),
                    site.clone(),
                    scope.clone(),
                    site_handlers.clone(),
                    cron.clone(),
                );
                cron_handles.push(tokio::spawn(async move {
                    fire_cron(
                        &inner,
                        &deploy,
                        &manifest,
                        &site,
                        &scope,
                        &site_handlers,
                        &cron,
                    )
                    .await;
                    running.store(false, Ordering::Release);
                }));
            }
        }
    }
    // --- async function invocations (FA-3) ---
    // Drain each top-level function's queued invocations. Leader-gated like crons
    // (`None` = single node) so a durable async call runs exactly once
    // cluster-wide; the drain runs inline so the outcome is settled this tick.
    let invoke_enabled = inner.cron_leader_gate.get().is_none_or(|gate| gate());
    if invoke_enabled {
        for function in deploy.list_stored_functions().await? {
            // Fire due triggers first (a cron enqueues an invocation this tick),
            // then drain the queue so a just-enqueued call runs without waiting.
            dispatch_function_triggers(inner, deploy, &function, &now).await;
            drain_function_invocations(inner, deploy, &function).await;
        }
        // --- workflow runs (FA-6), same leader gate ---
        for workflow in deploy.list_workflows().await? {
            drain_workflow_runs(inner, deploy, &workflow).await;
        }
    }
    Ok((acked, cron_handles))
}

/// Fire one cron: dispatch the declared handler route in-process (loopback,
/// never a network hop) with a synthetic `GET`, scoped to the deployment's
/// namespace. The response is drained and discarded — a cron has no caller.
#[cfg(feature = "handlers")]
async fn fire_cron(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    manifest: &Manifest,
    site: &str,
    scope: &str,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    cron: &boatramp_core::config::CronConfig,
) {
    let Some(handler) = route::match_handler(&manifest.config.handlers, "GET", &cron.route) else {
        tracing::warn!(site, route = %cron.route, "cron route matches no GET handler");
        return;
    };
    let Some(entry) = manifest.files.get(&handler.component) else {
        return;
    };
    let wasm = match read_blob_bytes(deploy, &entry.hash).await {
        Ok(wasm) => wasm,
        Err(err) => {
            tracing::warn!(site, %err, "reading cron handler component failed");
            return;
        }
    };
    let bindings = build_bindings(
        inner,
        site,
        scope,
        None,
        &handler.imports,
        site_handlers,
        &handler.env,
    )
    .await;
    let limits = effective_limits(site_handlers, handler);
    let request = match axum::http::Request::builder()
        .method("GET")
        .uri(format!("http://localhost{}", cron.route))
        .header("x-boatramp-trigger", "cron")
        .body(boatramp_handlers::empty_body())
    {
        Ok(request) => request,
        Err(_) => return,
    };
    let start = std::time::Instant::now();
    let result = inner
        .engine
        .serve_with_limits(&entry.hash, &wasm, request, bindings, limits)
        .await;
    inner.metrics.observe(
        site,
        metrics::Trigger::Cron,
        &cron.route,
        &entry.hash,
        metrics::Outcome::from_result(&result),
        start.elapsed(),
    );
    match result {
        Ok(response) => {
            // Drive the (possibly streamed) body to completion so the guest's
            // side effects finish, then discard it.
            let _ = http_body_util::BodyExt::collect(response.into_body()).await;
            tracing::info!(site, route = %cron.route, "cron fired");
        }
        Err(err) => tracing::warn!(site, route = %cron.route, %err, "cron invocation failed"),
    }
}

/// `503` for a handler that cannot run (e.g. its component is missing).
#[cfg(feature = "handlers")]
pub(super) fn handler_unavailable() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, "handler unavailable\n").into_response()
}

/// The per-invocation limits for a handler: the site's caps and any per-handler
/// caps (the lower of the two for each dimension). Left at the engine default
/// where neither is set; the engine then clamps to its own ceiling.
#[cfg(feature = "handlers")]
pub(super) fn effective_limits(
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    handler: &boatramp_core::config::HandlerConfig,
) -> boatramp_handlers::Limits {
    let mut limits = boatramp_handlers::Limits::default();
    let handler_limits = handler.limits.as_ref();
    if let Some(mb) = [
        site_handlers.max_memory_mb,
        handler_limits.and_then(|l| l.memory_mb),
    ]
    .into_iter()
    .flatten()
    .min()
    {
        limits.memory_bytes = (mb as usize).saturating_mul(1024 * 1024);
    }
    if let Some(ms) = [
        site_handlers.max_timeout_ms,
        handler_limits.and_then(|l| l.timeout_ms),
    ]
    .into_iter()
    .flatten()
    .min()
    {
        limits.timeout_ms = ms as u64;
    }
    // CPU fuel cap: the smaller of the site ceiling and any per-handler budget
    // (a handler may only lower it). Absent on both → unmetered.
    limits.fuel = [site_handlers.max_fuel, handler_limits.and_then(|l| l.fuel)]
        .into_iter()
        .flatten()
        .min();
    limits
}

/// Acquire a permit from the site's concurrency semaphore (created on first use)
/// when the site sets `maxConcurrency`; `Ok(None)` if uncapped, `Err(())` when
/// the site is at its limit (the caller turns that into a 503).
#[cfg(feature = "handlers")]
pub(super) fn acquire_site_permit(
    inner: &HandlerRuntimeInner,
    site: &str,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, ()> {
    let Some(max) = site_handlers.max_concurrency else {
        return Ok(None);
    };
    let semaphore = {
        let mut map = inner.site_semaphores.lock().unwrap();
        map.entry(site.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(max as usize)))
            .clone()
    };
    semaphore.try_acquire_owned().map(Some).map_err(|_| ())
}

/// Map a handler engine error to an HTTP status.
#[cfg(feature = "handlers")]
pub(super) fn handler_error_response(err: &boatramp_handlers::HandlerError) -> Response {
    use boatramp_handlers::HandlerError;
    let (status, body) = match err {
        HandlerError::Timeout => (StatusCode::GATEWAY_TIMEOUT, "handler timed out\n"),
        HandlerError::OutOfFuel => (
            StatusCode::GATEWAY_TIMEOUT,
            "handler exhausted its CPU budget\n",
        ),
        HandlerError::Overloaded => (
            StatusCode::SERVICE_UNAVAILABLE,
            "handler engine at capacity\n",
        ),
        HandlerError::Compile(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "handler failed to compile\n",
        ),
        HandlerError::Trap(_) | HandlerError::NoResponse | HandlerError::Internal(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "handler error\n")
        }
    };
    (status, body).into_response()
}
