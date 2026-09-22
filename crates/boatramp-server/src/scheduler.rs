//! The background scheduler: the per-tick loop that drives each active
//! deployment's consumers, crons, and blob-change watchers, plus the shared
//! per-site limit/permit/error helpers the request path also uses.
//! `handlers`-gated; pulls the serve-pipeline scope in via `use super::*`.

use super::*;
use boatramp_core::project::ProjectRef;

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

/// Which consumers a scheduler pass drives (event-driven delivery). Selects the topic set only — the
/// binding-build + claim + dispatch body is identical whichever is chosen.
#[cfg(feature = "handlers")]
#[derive(Clone, Copy)]
pub(super) enum ConsumerFilter<'a> {
    /// Drive EVERY active consumer (the fallback full poll for a backend without a ready-set, and the
    /// legacy path every existing caller/test uses). Also runs crons + the async lane + retention.
    All,
    /// Drive NO consumers this pass — the event-driven drainer owns delivery — but still run the
    /// maintenance work (crons, async lane, retention sweep, session reap). The maintenance-loop pass
    /// when the ready-set drainer is active.
    Skip,
    /// Drive exactly the consumers whose namespaced topic is in this set (the ready topics). Skips
    /// crons/async/retention (those are the maintenance loop's job) — a pure delivery drain.
    Topics(&'a std::collections::HashSet<String>),
}

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
        // Event-driven delivery: is a durable ready-set available? If the messaging backend supports
        // it (an atomic `write_batch` — B2), delivery is driven by the ready-set DRAINER and the
        // maintenance tick skips the per-consumer poll. Otherwise (no messaging, or a non-atomic
        // backend) the maintenance tick keeps the legacy full poll — never losing a message, just
        // paying the old O(#topics) cost. Decided once at spawn (the backend doesn't change).
        let ready_set = inner
            .messaging
            .as_ref()
            .is_some_and(|m| m.supports_ready_set());

        Some(tokio::spawn(async move {
            // --- the delivery drainer (event-driven), spawned only when the ready-set is available.
            // It reacts to the durable ready-set (∪ the due-heap) instead of polling every topic. On a
            // non-ready-set backend this is not spawned and the maintenance tick below does the full
            // poll (fallback), so delivery is never lost — only the idle-scaling win is forgone.
            let drainer = ready_set.then(|| {
                let inner = inner.clone();
                let deploy = deploy.clone();
                tokio::spawn(async move { run_delivery_drainer(inner, deploy).await })
            });

            // --- the maintenance tick (crons, async lane, workflows, retention sweep, session reap,
            // blob watchers) on the coarse periodic timer. When the drainer owns delivery it passes
            // `ConsumerFilter::Skip` (no per-consumer poll); on the fallback it passes `All`.
            let mut wasm_cache: std::collections::HashMap<String, Vec<u8>> =
                std::collections::HashMap::new();
            let mut cron_state: std::collections::HashMap<String, CronEntry> =
                std::collections::HashMap::new();
            let mut sweep_state: std::collections::HashMap<String, i64> =
                std::collections::HashMap::new();
            let mut blob_watchers: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
                std::collections::HashMap::new();
            let mut interval = tokio::time::interval(SCHEDULER_TICK);
            let consumers = if ready_set {
                ConsumerFilter::Skip // the drainer delivers; the tick only does maintenance
            } else {
                ConsumerFilter::All // no ready-set: the tick keeps the legacy full poll (fallback)
            };
            loop {
                interval.tick().await;
                if let Err(err) = run_scheduler_tick(
                    &inner,
                    &deploy,
                    &mut wasm_cache,
                    &mut cron_state,
                    &mut sweep_state,
                    CronNow::now(),
                    consumers,
                )
                .await
                {
                    tracing::warn!(%err, "scheduler tick failed");
                }
                reconcile_blob_watchers(&inner, &deploy, &mut blob_watchers).await;
                // If the drainer task ever exits (it shouldn't — it loops forever), the maintenance
                // loop keeps running; delivery would then rely on the drainer being respawned by a
                // restart. Abort it with us on shutdown (the caller aborts this outer handle).
                let _ = &drainer;
            }
        }))
    }
}

/// The **event-driven delivery drainer** (Phase A): react to the durable ready-set + due-heap instead
/// of polling every topic. It (1) waits on the fast-path wake OR the safety-net timer (whichever
/// first), (2) drains the ready-set — mapping each ready topic to its consumer(s) and dispatching —
/// (3) fires lease-expiry redelivery from a per-message-deadline due-heap, and (4) periodically
/// rebuilds the ready-set from the authoritative index (the lost-marker / fresh-node self-heal). An
/// idle topic costs nothing: it is absent from the ready-set, so 10 000 idle topics cost the same as
/// 10 (the headline win). The durable ready-set is the AUTHORITY for *where* to look; the wake is a
/// pure latency optimization (a dropped wake ⇒ the safety-net still delivers, B12).
#[cfg(feature = "handlers")]
async fn run_delivery_drainer(inner: Arc<HandlerRuntimeInner>, deploy: DeployStore) {
    let Some(messaging) = inner.messaging.clone() else {
        return; // no messaging backend — nothing to drain (defensive; spawn already checked)
    };
    let cfg = inner.delivery_config();
    // The fast-path wake, if the backend offers one (a publish/nack fires it post-commit). Absent ⇒
    // the drainer relies on the safety-net timer alone (still correct, just higher latency).
    let wake = messaging.wake_handle();
    // Component-byte cache, shared across drains (content-addressed, never changes).
    let mut wasm_cache: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    // A throwaway cron/sweep state — the drainer never fires crons/sweeps (it passes `Topics`), so
    // these are never touched; they satisfy `run_scheduler_tick`'s signature only.
    let mut cron_state: std::collections::HashMap<String, CronEntry> =
        std::collections::HashMap::new();
    let mut sweep_state: std::collections::HashMap<String, i64> = std::collections::HashMap::new();

    // The redelivery **due-heap** (B6): a pure rebuild-from-durable-state cache of per-topic next
    // lease-expiry deadlines. NEVER the authority — rebuilt from the index on start (below) and on a
    // periodic cadence, so a lost heap costs bounded latency, never a lost redelivery.
    let mut due_heap: std::collections::BinaryHeap<std::cmp::Reverse<(u64, String)>> =
        std::collections::BinaryHeap::new();

    // Startup safety-net (B6): before trusting the wake/heap, do a full ready-set rebuild AND a full
    // due-heap rebuild once, so a marker/heap lost across a restart is recovered before we rely on
    // the fast path. A fresh/upgraded node self-populates its ready-set here (B18).
    let leader = || inner.cron_leader_gate.get().is_none_or(|gate| gate());
    if leader() {
        if let Err(err) = messaging.rebuild_ready_set().await {
            tracing::warn!(%err, "initial ready-set rebuild failed");
        }
    }
    rebuild_due_heap(messaging.as_ref(), &mut due_heap).await;
    let mut last_rebuild = tokio::time::Instant::now();
    let mut last_heap_rebuild = tokio::time::Instant::now();
    // Phase D: when this node last did an UNSHARDED safety-net drain (B7 no-owner backstop). Start in
    // the past so the FIRST drain after spawn is unsharded — a node joining/restarting immediately
    // picks up any orphaned topic rather than waiting a full interval.
    let mut last_unsharded =
        tokio::time::Instant::now() - cfg.safetynet_interval.min(Duration::from_secs(60));

    loop {
        // (1) Drain everything ready right now: the durable ready-set ∪ the topics whose lease-expiry
        // deadline has passed (popped from the due-heap). Both map to the same dispatch.
        let now_ms = boatramp_core::time::now_unix_ms();
        let ready = match messaging.ready_topics().await {
            Ok(t) => t,
            Err(err) => {
                // A backend that lost ready-set support at runtime (shouldn't happen) — fall back to
                // a full rebuild next cycle rather than silently delivering nothing.
                tracing::warn!(%err, "ready_topics failed; will rely on rebuild");
                Vec::new()
            }
        };
        // Phase D topic sharding (B8/B9): the per-wake fast path drives only the topics THIS node
        // OWNS under the applied-membership HRW assignment — so each node scans its ~1/N share and the
        // leader is no longer the single funnel. Single-node / LogMessaging owns everything
        // (`shard_owns` defaults true), so the filter is a no-op there.
        //
        // BUT the periodic safety-net pass is UNSHARDED (B7): every `safetynet_interval` this node
        // drains the WHOLE ready-set regardless of ownership. This closes the sharding **no-owner
        // window** — when a node dies, its owned topics have no surviving owner until the membership
        // change applies; the unsharded pass means SOME node still drains them within one safety-net
        // interval. Redundant claims across the old+new owner during a rebalance are SAFE (the
        // leader-serialized atomic claim delivers each message exactly once, C4/B9), so the worst case
        // is a cheap redundant empty claim — never a double-delivery, never a stranding.
        let unsharded_pass = last_unsharded.elapsed() >= cfg.safetynet_interval;
        // Candidate topics = the ready-set ∪ the topics whose lease-expiry deadline has passed (popped
        // off the due-heap — a leased message whose lease expired is claimable again, even if its
        // marker was pruned). The whole set is shard-filtered together against ONE membership snapshot.
        let mut candidates: Vec<String> = ready;
        while let Some(std::cmp::Reverse((deadline, topic))) = due_heap.peek().cloned() {
            if deadline > now_ms {
                break; // the heap is min-ordered — nothing else is due yet
            }
            due_heap.pop();
            candidates.push(topic);
        }
        let topics: std::collections::HashSet<String> = if unsharded_pass {
            // Unsharded backstop (B7): drain the WHOLE candidate set regardless of ownership, closing
            // the sharding no-owner window (a dead node's orphaned topics get picked up here). Also
            // the single-node/degenerate path (`shard_owned` would return everything anyway).
            last_unsharded = tokio::time::Instant::now();
            candidates.into_iter().collect()
        } else {
            // Sharded per-wake fast path: only the topics this node OWNS under the applied-membership
            // HRW assignment — filtered as one batch against a single snapshot (B8: recompute once per
            // drain cycle). Single-node / LogMessaging owns all, so this is a no-op there.
            messaging
                .shard_owned(candidates)
                .await
                .into_iter()
                .collect()
        };

        if !topics.is_empty() {
            // Dispatch exactly the ready/due topics (the drainer's `Topics` filter): no cron/async/
            // sweep, no full walk — just the consumers whose topic is ready. Re-add the just-drained
            // topics' new deadlines to the due-heap afterward (below).
            if let Err(err) = run_scheduler_tick(
                &inner,
                &deploy,
                &mut wasm_cache,
                &mut cron_state,
                &mut sweep_state,
                CronNow::now(),
                ConsumerFilter::Topics(&topics),
            )
            .await
            {
                tracing::warn!(%err, "delivery drain failed");
            }
        }

        // (2) Periodic ready-set rebuild (B6/B18) — the lost-marker / stale-marker / fresh-node
        // self-heal, on a LONG cadence (the one full-ish scan). Leader-gated in Phase A (it proposes
        // reconciling writes; a follower rebuild would be redundant, though safe — B7).
        if last_rebuild.elapsed() >= cfg.rebuild_interval {
            if leader() {
                if let Err(err) = messaging.rebuild_ready_set().await {
                    tracing::warn!(%err, "ready-set rebuild failed");
                }
            }
            last_rebuild = tokio::time::Instant::now();
        }
        // (3) Periodic due-heap rebuild from durable lease state (B6) — cheaper than the ready-set
        // rebuild (bounded by leased records), on the safety-net cadence, so a lease taken on another
        // node (cluster) or a heap gap is reflected.
        if last_heap_rebuild.elapsed() >= cfg.safetynet_interval {
            rebuild_due_heap(messaging.as_ref(), &mut due_heap).await;
            last_heap_rebuild = tokio::time::Instant::now();
        }

        // (4) Sleep until the NEXT of: a fast-path wake, the safety-net timer, or the next due
        // deadline. The safety-net timer is the backstop for a dropped wake and for time-based
        // visibility; it never scans idle topics (an absent ready-set entry costs nothing).
        let until_due = due_heap
            .peek()
            .map(|std::cmp::Reverse((deadline, _))| {
                Duration::from_millis(deadline.saturating_sub(now_ms))
            })
            .unwrap_or(cfg.safetynet_interval);
        let sleep_for = until_due.min(cfg.safetynet_interval);
        match &wake {
            Some(w) => {
                // Wake OR timer, whichever first. A wake resolves immediately if one is pending
                // (coalesced), so a burst of publishes drains in one pass.
                tokio::select! {
                    _ = w.notified() => {}
                    _ = tokio::time::sleep(sleep_for) => {}
                }
            }
            None => tokio::time::sleep(sleep_for).await,
        }
    }
}

/// Rebuild the redelivery due-heap from the messaging backend's durable lease state (B6): replace the
/// heap with one entry per topic that has a future lease deadline, min-ordered by deadline. A pure
/// cache refresh — the durable records are the authority. A backend without `due_topics` support
/// yields an empty heap (redelivery then rides the safety-net's ready-set drain + lease-expiry claim).
#[cfg(feature = "handlers")]
async fn rebuild_due_heap(
    messaging: &dyn boatramp_core::messaging::Messaging,
    heap: &mut std::collections::BinaryHeap<std::cmp::Reverse<(u64, String)>>,
) {
    heap.clear();
    match messaging.due_topics().await {
        Ok(due) => {
            for (topic, deadline) in due {
                heap.push(std::cmp::Reverse((deadline, topic)));
            }
        }
        Err(err) => tracing::warn!(%err, "due-heap rebuild failed"),
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
    // Reconcile every project's blob triggers; a same-named function in two
    // projects gets two independent watchers (the watch id is project-qualified).
    let projects = deploy.discover_projects().await.unwrap_or_default();
    let mut desired = std::collections::HashSet::new();
    for project_name in projects {
        let project = ProjectRef::new(&project_name);
        let functions = match deploy.list_stored_functions(project).await {
            Ok(f) => f,
            Err(_) => continue,
        };
        for function in functions {
            let triggers = deploy
                .list_triggers(project, &function.name)
                .await
                .unwrap_or_default();
            for trigger in triggers {
                let TriggerKind::Blob { prefix } = &trigger.kind else {
                    continue;
                };
                let watch_id = format!("{project_name}|{}|{}", function.name, trigger.id);
                desired.insert(watch_id.clone());
                if let std::collections::hash_map::Entry::Vacant(slot) = watchers.entry(watch_id) {
                    if let Some(handle) = spawn_blob_watcher(
                        inner.clone(),
                        deploy.clone(),
                        project_name.clone(),
                        function.clone(),
                        prefix,
                    )
                    .await
                    {
                        slot.insert(handle);
                    }
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
    project: String,
    function: boatramp_core::function::Function,
    prefix: &str,
) -> Option<tokio::task::JoinHandle<()>> {
    // The function's blobstore lives under its **project-qualified** namespace
    // (`hblob/fn/<name>/` for `default`, `hblob/{project}/fn/<name>/` otherwise);
    // the trigger prefix is relative to it (same key the provisioner + ledger
    // use, so a watcher and the ledger/provisioner agree).
    let project_ref = ProjectRef::new(&project);
    let storage_prefix = blob_storage_prefix(project_ref, &function.name, prefix);
    let mut stream = match inner.storage.watch(&storage_prefix).await {
        Ok(Some(stream)) => stream,
        Ok(None) => return None,
        Err(err) => {
            tracing::warn!(function = %function.name, %err, "starting blob watch failed");
            return None;
        }
    };
    let namespace = format!(
        "hblob/{}/",
        project_ref.qualified(&format!("fn/{}", function.name))
    );
    Some(tokio::spawn(async move {
        use futures::StreamExt;
        while let Some(change) = stream.next().await {
            enqueue_blob_invocation(
                &deploy,
                ProjectRef::new(&project),
                &function,
                &change,
                &namespace,
            )
            .await;
        }
    }))
}

/// Enqueue a durable async invocation for a blob change, with the changed key +
/// kind as the JSON request body (the function-relative key, `hblob/fn/<name>/`
/// stripped).
#[cfg(feature = "handlers")]
async fn enqueue_blob_invocation(
    deploy: &DeployStore,
    project: ProjectRef<'_>,
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
        lease_expires: None,
        request_b64: (!payload.is_empty()).then(|| b64_encode(&payload)),
        request_content_type: Some("application/json".to_string()),
        result: None,
        created: now,
        updated: now,
    };
    if let Err(err) = deploy.put_invocation(project, &inv).await {
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
    sweep_state: &mut std::collections::HashMap<String, i64>,
    now: CronNow,
    // Event-driven delivery: which consumers this pass drives (see [`ConsumerFilter`]). The legacy
    // full poll is `All`; the maintenance loop passes `Skip` (drainer owns delivery); the drainer
    // passes `Topics(ready)`. Crons + the async lane run only on a maintenance pass (`All`/`Skip`),
    // never on a per-ready-topic drain (`Topics`).
    consumers: ConsumerFilter<'_>,
) -> Result<(usize, Vec<tokio::task::JoinHandle<()>>), DeployError> {
    use std::sync::atomic::Ordering;
    let mut acked = 0;
    let mut cron_handles = Vec::new();
    // Crons, the async lane, workflows, blob watchers, and the session reap are MAINTENANCE work,
    // never part of a per-ready-topic delivery drain — so they run only when this is a maintenance
    // pass (`All` or `Skip`), not the drainer's `Topics(..)` pass. `All` keeps every existing
    // caller/test byte-identical (it is a maintenance pass that also drives all consumers).
    let maintenance = !matches!(consumers, ConsumerFilter::Topics(_));
    // Fan out over every project: a same-named site/function/workflow in two
    // projects is scheduled independently (its background jobs run under its own
    // tenant, never `default`). For a single default-only store this is one pass.
    let projects = deploy.discover_projects().await?;
    for project_name in &projects {
        let project = ProjectRef::new(project_name);
        // Session GC: reap this project's idle/closed session records, at most once per minute — the
        // enforcement side of the idle-TTL (paired with the per-project open cap), so the KV can't
        // accumulate dead session records. Throttled via `sweep_state` like the retention sweep.
        // Maintenance-only (never on a per-ready-topic drain pass — B13).
        #[cfg(feature = "session")]
        if maintenance {
            let reap_key = format!("__session_reap/{project_name}");
            if sweep_state
                .get(&reap_key)
                .is_none_or(|stamp| *stamp != now.minute_stamp)
            {
                sweep_state.insert(reap_key, now.minute_stamp);
                match crate::session_serve::session_store(inner)
                    .reap_expired(project.as_str(), boatramp_core::time::now_unix_ms())
                    .await
                {
                    Ok(n) if n > 0 => {
                        tracing::debug!(project = %project_name, reaped = n, "session reap");
                    }
                    Ok(_) => {}
                    Err(err) => {
                        tracing::warn!(project = %project_name, %err, "session reap failed");
                    }
                }
            }
        }
        for site in deploy.list_sites(project).await? {
            let Some(site_config) = deploy.get_site_config(project, &site).await? else {
                continue;
            };
            let Some(site_handlers) = site_config.handlers.as_ref().filter(|h| h.enabled) else {
                continue;
            };
            // Active deployments: the current one (production, namespace `{site}`)
            // plus each background alias (namespace `{site}/{alias}`). Never previews.
            let mut active: Vec<(String, String)> = Vec::new();
            if let Some(id) = deploy.current_id(project, &site).await? {
                active.push((id, site.clone()));
            }
            for alias in &site_handlers.background_aliases {
                if let Some(id) = deploy.get_alias(project, &site, alias).await? {
                    active.push((id, format!("{site}/{alias}")));
                }
            }
            for (deploy_id, scope) in active {
                let Some(manifest) = deploy.get_manifest(&deploy_id).await? else {
                    continue;
                };
                // --- consumers (only with a messaging backend) ---
                // Event-driven delivery: `consumers` selects WHICH topics to drive this pass.
                // `ConsumerFilter::All` = the full walk (the fallback poll for a non-ready-set backend,
                // and every existing caller/test); `Skip` = the ready-set drainer owns delivery, so this
                // maintenance pass only does the retention sweep; `Topics(set)` = drive exactly the
                // ready topics (the drainer). The retention sweep + binding-build + dispatch body are
                // unchanged — only the topic selection is new.
                if let Some(messaging) = inner.messaging.clone() {
                    for consumer in &manifest.config.consumers {
                        // `bus:<topic>` consumes the shared project bus; a plain topic its site scope.
                        let (consumer_topic, consumer_prefix) = match consumer
                            .topic
                            .strip_prefix(boatramp_handlers::BUS_TOPIC_SELECTOR)
                        {
                            Some(bus_topic) => {
                                let bus = project.qualified("bus");
                                (format!("{bus}/{bus_topic}"), format!("{bus}/"))
                            }
                            None => (format!("{scope}/{}", consumer.topic), format!("{scope}/")),
                        };
                        // Should this pass DISPATCH this consumer (claim + run)? `All` yes; `Skip` no
                        // (the drainer owns it); `Topics` only if this consumer's topic is ready.
                        let dispatch = match consumers {
                            ConsumerFilter::All => true,
                            ConsumerFilter::Skip => false,
                            ConsumerFilter::Topics(set) => set.contains(&consumer_topic),
                        };
                        if dispatch {
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
                            let bindings = match build_bindings(
                                inner,
                                project,
                                &site,
                                &scope,
                                None,
                                &consumer.imports,
                                site_handlers,
                                // Consumers have no deploy `env`; site secrets still apply.
                                &std::collections::BTreeMap::new(),
                                // Consumers do not get the invoke capability (no allowlist field).
                                &[],
                                // The consumer's declared `bus:` stats-topic templates (messaging-stats).
                                &consumer.stats_topics,
                                0,
                                // Background consumers have no request context to correlate with.
                                None,
                                // No HTTP request ⇒ no token/domain tenant source; an `own` scope
                                // fails closed (a consumer uses `null`/`all`, or signed-context once
                                // wired).
                                None,
                                None,
                                // No request cookie ⇒ no R3 session fact on a background trigger.
                                None,
                                // No HTTP request ⇒ no `?handle=` slug (a background trigger is never a
                                // handle-sourced target route).
                                None,
                                // Per-consumer tenancy (Gap 2). This once-per-tick build has no message,
                                // so `signed_context` is `None` here; a consumer declaring that source is
                                // rebuilt PER MESSAGE in `dispatch_consumer_batch` with the drained
                                // envelope (below), and this prebuilt binding is used only for
                                // non-signed-context consumers.
                                consumer.tenancy.as_ref(),
                                consumer.token_claims.as_ref(),
                                None,
                            )
                            .await
                            {
                                Ok(bindings) => bindings,
                                // A refused secret ref (host-env ref under the multi-tenant
                                // posture, or an unsupported scheme) fails the consumer
                                // closed — skip dispatch rather than run with a leaked value.
                                Err(err) => {
                                    tracing::warn!(site, topic = %consumer.topic, %err, "consumer bindings refused");
                                    continue;
                                }
                            };
                            // R1 async lane: a consumer declaring `sources: [signed_context]` must resolve
                            // EACH message's sealed originator tenant, so its bindings are rebuilt per
                            // message from that message's envelope (the built-once `bindings` above can't
                            // carry a per-message context). A consumer that does not declare it reuses the
                            // built-once binding (`rebuild = None`), unchanged.
                            let rebuild = consumer
                                .tenancy
                                .as_ref()
                                .filter(|t| t.declares_signed_context())
                                .map(|_| crate::handler_dispatch::ConsumerRebuild {
                                    inner,
                                    project,
                                    site: &site,
                                    scope: &scope,
                                    imports: &consumer.imports,
                                    site_handlers,
                                    tenancy: consumer.tenancy.as_ref(),
                                    token_claims: consumer.token_claims.as_ref(),
                                    stats_topics: &consumer.stats_topics,
                                });
                            acked += dispatch_consumer_batch(
                                &inner.engine,
                                messaging.as_ref(),
                                &inner.metrics,
                                &site,
                                &consumer_topic,
                                &consumer_prefix,
                                &consumer.group,
                                consumer.start,
                                &entry.hash,
                                wasm,
                                &bindings,
                                rebuild.as_ref(),
                                site_limits(site_handlers),
                                // Per-consumer overrides (≈ JetStream AckWait/MaxDeliver/batch), each
                                // falling back to the server default when unset (back-compat).
                                consumer
                                    .lease_ms
                                    .map(Duration::from_millis)
                                    .unwrap_or(CONSUMER_LEASE),
                                consumer.max_attempts.unwrap_or(CONSUMER_MAX_ATTEMPTS),
                                consumer.max_batch.unwrap_or(CONSUMER_BATCH),
                                consumer.max_ack_pending,
                                consumer.backoff_ms.unwrap_or(0),
                            )
                            .await;
                        }
                        // A grouped (fan-out) topic keeps a retained log; reclaim fully-consumed
                        // messages once a minute per topic, off the hot claim path, on the leader only
                        // (single node = always). Runs on the FULL/maintenance pass regardless of the
                        // dispatch filter (B13: an idle grouped topic must still be swept), but never on
                        // a per-ready-topic drain pass (`Topics`) — that would re-introduce per-tick
                        // sweep work. `All` and `Skip` are the maintenance passes; `Topics` is the drainer.
                        let sweep_this_pass = !matches!(consumers, ConsumerFilter::Topics(_));
                        if sweep_this_pass
                            && !consumer.group.is_empty()
                            && inner.cron_leader_gate.get().is_none_or(|gate| gate())
                            && sweep_state
                                .get(&consumer_topic)
                                .is_none_or(|stamp| *stamp != now.minute_stamp)
                        {
                            sweep_state.insert(consumer_topic.clone(), now.minute_stamp);
                            match messaging
                                .retention_sweep(
                                    &consumer_topic,
                                    consumer
                                        .retention_ms
                                        .unwrap_or(boatramp_core::messaging::GROUP_RETENTION_MS),
                                )
                                .await
                            {
                                Ok(n) if n > 0 => tracing::debug!(
                                    topic = %consumer_topic,
                                    reclaimed = n,
                                    "consumer-group retention sweep"
                                ),
                                Ok(_) => {}
                                Err(err) => tracing::warn!(
                                    topic = %consumer_topic, %err,
                                    "consumer-group retention sweep failed"
                                ),
                            }
                        }
                    }
                }
                // --- crons (leader-only in cluster mode) ---
                // The gate fires crons on exactly one node; consumers above run on
                // every node (leased dispatch distributes them). `None` = single
                // node, always fires. Crons run only on a maintenance pass (never on the
                // drainer's per-ready-topic pass).
                let cron_enabled =
                    maintenance && inner.cron_leader_gate.get().is_none_or(|gate| gate());
                for (idx, cron) in manifest.config.crons.iter().enumerate() {
                    if !cron_enabled {
                        break;
                    }
                    let Ok(schedule) = boatramp_core::cron::CronSchedule::parse(&cron.schedule)
                    else {
                        continue;
                    };
                    if !schedule.fires_at(now.minute, now.hour, now.dom, now.month, now.dow) {
                        continue;
                    }
                    let key = format!("{project_name}|{scope}|cron|{idx}");
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
                    let (inner, deploy, manifest, project_owned, site, scope, site_handlers, cron) = (
                        inner.clone(),
                        deploy.clone(),
                        manifest.clone(),
                        project_name.clone(),
                        site.clone(),
                        scope.clone(),
                        site_handlers.clone(),
                        cron.clone(),
                    );
                    cron_handles.push(tokio::spawn(async move {
                        fire_cron(
                            &inner,
                            &deploy,
                            ProjectRef::new(&project_owned),
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
    }
    // --- async function invocations (FA-3) ---
    // Drain each top-level function's queued invocations. Leader-gated like crons
    // (`None` = single node) so a durable async call is claimed exactly once
    // cluster-wide; the claim is persisted with a lease and the run is spawned off
    // the tick, so a long background job never stalls this loop (crons, other
    // drains, workflow progress) and a crash mid-run is reclaimed when the lease
    // elapses.
    let invoke_enabled = maintenance && inner.cron_leader_gate.get().is_none_or(|gate| gate());
    if invoke_enabled {
        // Same per-project fan-out as the site loop: each project's functions +
        // workflows drain under their own tenant.
        for project_name in &projects {
            let project = ProjectRef::new(project_name);
            for function in deploy.list_stored_functions(project).await? {
                // Fire due triggers first (a cron enqueues an invocation this
                // tick), then drain the queue so a just-enqueued call runs without
                // waiting.
                dispatch_function_triggers(inner, deploy, project, &function, &now).await;
                drain_function_invocations(inner, deploy, project, &function).await;
            }
            // --- workflow runs (FA-6), same leader gate ---
            for workflow in deploy.list_workflows(project).await? {
                drain_workflow_runs(inner, deploy, project, &workflow).await;
            }
        }
    }
    Ok((acked, cron_handles))
}

/// Fire one cron: dispatch the declared handler route in-process (loopback,
/// never a network hop) with a synthetic `GET`, scoped to the deployment's
/// namespace. The response is drained and discarded — a cron has no caller.
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
async fn fire_cron(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    project: ProjectRef<'_>,
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
    let bindings = match build_bindings(
        inner,
        project,
        site,
        scope,
        None,
        &handler.imports,
        site_handlers,
        &handler.env,
        // A cron-triggered handler is also the root of a call chain (depth 0); its
        // invoke allowlist applies the same as on the HTTP path.
        &handler.invoke_targets,
        &handler.stats_topics,
        0,
        // A cron trigger has no inbound request to correlate with.
        None,
        // No HTTP request ⇒ no token/domain tenant source (an `own` scope fails closed).
        None,
        None,
        // No request cookie ⇒ no R3 session fact on a cron trigger.
        None,
        // No HTTP request ⇒ no `?handle=` slug on a cron trigger.
        None,
        // Per-handler tenancy (Gap 2) for a cron-triggered handler, narrowing within the site.
        handler.tenancy.as_ref(),
        handler.token_claims.as_ref(),
        // A cron trigger is not a messaging drain — no signed-context envelope.
        None,
    )
    .await
    {
        Ok(bindings) => bindings,
        // A refused secret ref fails the cron closed — skip firing rather than run
        // with a leaked (multi-tenant host-env) or unsupported value.
        Err(err) => {
            tracing::warn!(site, route = %cron.route, %err, "cron bindings refused");
            return;
        }
    };
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

/// A **retryable** `503` for a component whose required host-managed database is still starting —
/// the managed-dependency readiness gate. Carries `Retry-After` so a client / a migration or health
/// probe re-polls instead of the guest running into a confusing "not granted"; the guest never runs.
#[cfg(feature = "handlers")]
pub(super) fn sql_starting_response(retry_after_secs: u32) -> Response {
    let mut headers = axum::http::HeaderMap::new();
    let secs = retry_after_secs.clamp(1, 3600);
    if let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string()) {
        headers.insert(axum::http::header::RETRY_AFTER, v);
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        headers,
        "database starting; retry shortly\n",
    )
        .into_response()
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
