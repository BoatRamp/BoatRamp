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

/// How a maintenance pass treats the async lane / crons / blob watchers under Phase-D sharding (B10).
/// Orthogonal to [`ConsumerFilter`] (which selects the *delivery* topics): this selects the *async*
/// work. Only meaningful on a maintenance pass (`All`/`Skip`); a `Topics` delivery drain ignores it.
#[cfg(feature = "handlers")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AsyncPass {
    /// The legacy leader-gate (pre-B10, and every existing caller/test): crons, the async drain, and
    /// blob watchers run iff this node passes `cron_leader_gate` (single node ⇒ always). Byte-for-byte
    /// the pre-sharding behavior — no shard gate is consulted. Used where sharding isn't wired.
    Legacy,
    /// The **sharded fast path** (B10 common case): drain/fire/watch only the function/cron identities
    /// this node HRW-OWNS (`async_shard_owns`). Each node does its ~1/N share; the leader is no longer
    /// the single async funnel. Crons + blob watchers fire ONLY here (owner-only single-fire).
    Sharded,
    /// The **unsharded safety-net** (B10 backstop, B7 no-owner window): drain EVERY function's async
    /// invocations regardless of ownership, so a function orphaned during a membership transition still
    /// gets drained by some node within one safety-net interval. Safe because the claim is a CAS
    /// (redundant scans are idempotent — Invariant 2). Crons + blob watchers are NOT run on this pass
    /// (they have no cross-node dedup for *firing/watching*, so a non-owner must not fire/watch them).
    UnshardedSafetyNet,
}

/// The dispatch scope for a consumer / cron on `(project, base)` where `base` is the site (or
/// `{site}/{alias}`). PROJECT-QUALIFIED, identical to the handler path (`project_ref.qualified`) and
/// the function path, so a consumer/cron's `wasi:blobstore` (`hblob/{scope}/…`) and its plain-topic
/// namespace resolve to the SAME namespace this project's handlers use, isolated across projects that
/// share a site name. `qualified` is a no-op for the default project (byte-identical to the pre-fix
/// bare scope), so only non-default projects change — closing the bug where a non-default project's
/// consumer addressed an empty, cross-project-colliding `hblob/{site}/…`.
#[cfg(feature = "handlers")]
fn consumer_dispatch_scope(project: ProjectRef<'_>, base: &str) -> String {
    // MUTATION SEAM (gate `bare_scope`): drop the project qualification, reproducing the bug (the
    // consumer scope diverges from the handler's). Compiled out of shipped builds; the gate then goes
    // RED because the consumer scope no longer equals the handler's `qualified` scope.
    if consumerscope_mutation().as_deref() == Some("bare_scope") {
        return base.to_string();
    }
    project.qualified(base)
}

/// The active consumer-scope mutation (anti-hollow gate), or `None`. Present ONLY under `cfg(test)`
/// or the `consumer-scope-gate-mutation` feature; a shipped build has neither, so
/// [`consumer_dispatch_scope`] always project-qualifies and this is a dead `None`.
#[cfg(all(
    feature = "handlers",
    any(test, feature = "consumer-scope-gate-mutation")
))]
fn consumerscope_mutation() -> Option<String> {
    std::env::var("BOATRAMP_CONSUMERSCOPE_MUTATION").ok()
}
#[cfg(all(
    feature = "handlers",
    not(any(test, feature = "consumer-scope-gate-mutation"))
))]
#[inline]
fn consumerscope_mutation() -> Option<String> {
    None
}

/// Per-invocation limits from the site's caps only (consumers have no
/// per-component limit config), clamped to the engine ceiling downstream.
#[cfg(feature = "handlers")]
fn site_limits(
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
) -> boatramp_handlers::Limits {
    // Unset memory ⇒ inherit the lane ceiling (sentinel `usize::MAX`; the engine clamps down). This
    // is how a consumer on a lane with a raised `async_max_memory_mb` gets the headroom — a
    // `max_memory_mb` on the site only ever clamps the consumer DOWN from the ceiling. In the struct
    // initializer (not a post-`default()` reassignment) to satisfy `field_reassign_with_default`.
    let mut limits = boatramp_handlers::Limits {
        memory_bytes: site_handlers
            .max_memory_mb
            .map(|mb| (mb as usize).saturating_mul(1024 * 1024))
            .unwrap_or(usize::MAX),
        ..boatramp_handlers::Limits::default()
    };
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

/// A handle to the background scheduler that can **fully quiesce** it on shutdown — not just
/// abort the outer loop, but stop it spawning new work and abort+await its DETACHED children
/// (the delivery drainer, the per-site blob watchers) so NONE of them can issue a KV write after
/// the store is closed. This is the Part-A prerequisite for a lossless quiesce-then-`close()`:
/// aborting a tokio task then AWAITING it is the only way to be sure it issues no further write.
///
/// The old contract (a bare [`abort`](tokio::task::JoinHandle::abort) on the outer handle) left
/// the drainer + blob watchers running detached — they kept writing right up to (and past) the
/// store close, which is exactly what produced a fresh WAL segment on shutdown.
#[cfg(feature = "handlers")]
pub struct SchedulerHandle {
    /// The outer scheduler task. On [`quiesce`](Self::quiesce) it observes the cancel signal,
    /// aborts+awaits its children, then returns — so awaiting it means the whole scheduler tree
    /// has stopped writing.
    handle: tokio::task::JoinHandle<()>,
    /// Signals the scheduler loop to stop: flips to `true` on [`quiesce`](Self::quiesce).
    cancel: tokio::sync::watch::Sender<bool>,
}

#[cfg(feature = "handlers")]
impl SchedulerHandle {
    /// Signal the scheduler to stop and **await** its full quiescence — the outer loop breaks,
    /// aborts+awaits the drainer + every blob watcher + any in-flight cron fire, then returns.
    /// After this resolves NO scheduler task can issue another KV write, so the caller may safely
    /// `close()` the store. Bounded by the caller's `close` timeout (a slow child is abandoned by
    /// the outer timeout, fail-safe).
    pub async fn quiesce(self) {
        // Ask the loop to stop; a send error just means the task already exited (fine).
        let _ = self.cancel.send(true);
        // Await the outer task: it runs the child abort+await on the cancel path before returning.
        // A JoinError (the task panicked/was cancelled) is not actionable at shutdown — log-free.
        let _ = self.handle.await;
    }

    /// Abort the scheduler without awaiting quiescence (the legacy best-effort stop). Used only
    /// where the caller cannot await (a non-async drop path); prefer [`quiesce`](Self::quiesce).
    pub fn abort(&self) {
        let _ = self.cancel.send(true);
        self.handle.abort();
    }
}

impl HandlerRuntime {
    /// Spawn the **background scheduler**: a loop that drives each *active*
    /// deployment's consumers and crons. "Active" = a site's
    /// current (production) deployment plus any site-configured background
    /// aliases; previews are never enumerated, so a preview deployment runs
    /// request handlers but **no background work**. Returns `None` when handlers
    /// are disabled (or no runtime). The caller calls
    /// [`SchedulerHandle::quiesce`] on shutdown to fully stop it (drainer + blob
    /// watchers + in-flight crons) BEFORE closing the KV store.
    #[cfg(feature = "handlers")]
    pub fn spawn_scheduler(&self, deploy: DeployStore) -> Option<SchedulerHandle> {
        let inner = self.inner.clone()?;
        // The shutdown cancel signal: the loop selects on this and stops on `true`, then aborts+
        // awaits its detached children so none can write after the store closes (Part A).
        let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
        // Event-driven delivery: is a durable ready-set available? If the messaging backend supports
        // it (an atomic `write_batch` — B2), delivery is driven by the ready-set DRAINER and the
        // maintenance tick skips the per-consumer poll. Otherwise (no messaging, or a non-atomic
        // backend) the maintenance tick keeps the legacy full poll — never losing a message, just
        // paying the old O(#topics) cost. Decided once at spawn (the backend doesn't change).
        let ready_set = inner
            .messaging
            .as_ref()
            .is_some_and(|m| m.supports_ready_set());

        let handle = tokio::spawn(async move {
            // --- the delivery drainer (event-driven), spawned only when the ready-set is available.
            // It reacts to the durable ready-set (∪ the due-heap) instead of polling every topic. On a
            // non-ready-set backend this is not spawned and the maintenance tick below does the full
            // poll (fallback), so delivery is never lost — only the idle-scaling win is forgone.
            let drainer = ready_set.then(|| {
                let inner = inner.clone();
                let deploy = deploy.clone();
                tokio::spawn(async move { run_delivery_drainer(inner, deploy).await })
            });
            // In-flight cron fires spawned by the maintenance tick. Held so shutdown can await them
            // (a cron fire can enqueue an async invocation — a KV write). Pruned of finished handles
            // each tick so it stays bounded on a long-running node.
            let mut cron_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

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
            // Phase-D async sharding (B10) is ACTIVE only when the async claim can be made race-safe:
            // a linearizable-CAS KV backend AND a messaging substrate to derive the HRW assignment
            // from. Otherwise the async lane stays on the legacy leader-gate (owns-all), byte-for-byte
            // unchanged — the fail-closed default (single node, a non-CAS remote KV, an old node
            // during version skew — B18). Decided once at spawn (the backend/topology is fixed).
            let shard_active = deploy.supports_invocation_cas() && inner.messaging.is_some();
            // The async pass this node runs every fast tick: the sharded fast path when sharding is
            // active (owner-only crons/watchers + owner + safety-net invocation drains), else the
            // legacy leader-gate. On single node both resolve to "own all" identically.
            let fast_pass = if shard_active {
                AsyncPass::Sharded
            } else {
                AsyncPass::Legacy
            };
            // The unsharded safety-net cadence (B7 no-owner backstop) reuses the delivery safety-net
            // interval (B17: no new knob) — a coarse periodic full drain that re-derives every
            // function's queue so a function orphaned by a membership transition drains within one
            // interval. Only meaningful on a live shard; skipped entirely when sharding is inactive.
            let safetynet_interval = inner.delivery_config().safetynet_interval;
            let mut last_safetynet = tokio::time::Instant::now();
            loop {
                // Wait for the next tick OR the shutdown cancel. On cancel we break to the quiesce
                // tail below — stop spawning new work and abort+await the detached children so none
                // can write after the store is closed (Part A).
                tokio::select! {
                    biased;
                    _ = cancel_rx.changed() => {
                        if *cancel_rx.borrow_and_update() {
                            break;
                        }
                    }
                    _ = interval.tick() => {}
                }
                // Prune finished cron fires so the held set stays bounded on a long-running node.
                cron_handles.retain(|h| !h.is_finished());
                // (1) The fast pass: sharded owner-only work (or the legacy leader-gate).
                match run_scheduler_tick(
                    &inner,
                    &deploy,
                    &mut wasm_cache,
                    &mut cron_state,
                    &mut sweep_state,
                    CronNow::now(),
                    consumers,
                    fast_pass,
                )
                .await
                {
                    Ok((_, fired)) => cron_handles.extend(fired),
                    Err(err) => tracing::warn!(%err, "scheduler tick failed"),
                }
                reconcile_blob_watchers(&inner, &deploy, &mut blob_watchers, fast_pass).await;
                // (2) The unsharded safety-net pass (B7): every `safetynet_interval`, on a live shard,
                // drain EVERY function's queue regardless of ownership so a no-owner window can't
                // strand work. Safe by the CAS claim (redundant scans are no-ops — Invariant 2). Crons
                // + blob watchers are NOT touched here (`UnshardedSafetyNet` skips them — no cross-node
                // firing dedup). Never runs on single node / a non-CAS backend (nothing to back up).
                if shard_active && last_safetynet.elapsed() >= safetynet_interval {
                    last_safetynet = tokio::time::Instant::now();
                    match run_scheduler_tick(
                        &inner,
                        &deploy,
                        &mut wasm_cache,
                        &mut cron_state,
                        &mut sweep_state,
                        CronNow::now(),
                        // The safety net is an async-only backstop; it drives no consumer delivery
                        // (the drainer / the fast pass own that) — `Skip` keeps it maintenance-only.
                        ConsumerFilter::Skip,
                        AsyncPass::UnshardedSafetyNet,
                    )
                    .await
                    {
                        Ok((_, fired)) => cron_handles.extend(fired),
                        Err(err) => tracing::warn!(%err, "async safety-net pass failed"),
                    }
                }
            }

            // --- Shutdown quiescence (Part A): the loop broke on the cancel signal. Stop the
            // detached children so NONE can issue a KV write after the store is closed. Abort THEN
            // await each — an abort alone only *requests* cancellation; awaiting is what guarantees
            // the task has stopped at its next await point and will run no further code.
            if let Some(drainer) = drainer {
                drainer.abort();
                let _ = drainer.await;
            }
            for (_, watcher) in blob_watchers.drain() {
                watcher.abort();
                let _ = watcher.await;
            }
            // In-flight cron fires: await the ones already running (bounded — the loop stopped
            // spawning new ones). A fire that has not finished is aborted+awaited so it cannot land
            // a late enqueue write. The outer `close` timeout bounds a wedged fire (fail-safe).
            for fire in cron_handles.drain(..) {
                fire.abort();
                let _ = fire.await;
            }
        });
        Some(SchedulerHandle {
            handle,
            cancel: cancel_tx,
        })
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
    if leader()
        && let Err(err) = messaging.rebuild_ready_set().await
    {
        tracing::warn!(%err, "initial ready-set rebuild failed");
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
                // A `Topics` delivery drain never touches the async lane / crons / watchers (it's a
                // pure per-ready-topic dispatch — `maintenance` is false), so the async pass is
                // irrelevant here; `Legacy` is the inert choice.
                AsyncPass::Legacy,
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
            if leader()
                && let Err(err) = messaging.rebuild_ready_set().await
            {
                tracing::warn!(%err, "ready-set rebuild failed");
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
/// removed. Single-fire cluster-wide (shared-FS clusters would otherwise fire per-node).
///
/// Pre-B10 this was strictly leader-gated (only the leader watched). Under Phase-D sharding
/// (`AsyncPass::Sharded`) a function's watchers run on the ONE node that HRW-OWNS the function
/// identity — so exactly one node watches ⇒ exactly one enqueue per change (Invariant 4), and the
/// watch load spreads off the leader. Ownership is folded into the `desired` set, so the `retain`
/// step below AUTOMATICALLY aborts a watcher this node no longer owns after a membership change
/// (rebuild-on-change, mirroring B11's rebuild-on-deploy-change) — re-covering the no-owner window.
/// A change that slips through during a transition is caught by the content-hash-idempotent enqueue
/// (the blob change body is deterministic) + the periodic re-reconcile.
#[cfg(feature = "handlers")]
async fn reconcile_blob_watchers(
    inner: &Arc<HandlerRuntimeInner>,
    deploy: &DeployStore,
    watchers: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    async_pass: AsyncPass,
) {
    use boatramp_core::function::TriggerKind;
    // The unsharded safety-net pass never (re)spawns watchers — a non-owner watching would double-
    // enqueue every change. Watchers are owner-only, reconciled on the sharded/legacy pass; the
    // safety net's job is the CAS-idempotent invocation drain, not watching.
    if async_pass == AsyncPass::UnshardedSafetyNet {
        return;
    }
    // Legacy leader-gate (single node ⇒ always): the pre-B10 behavior for the `Legacy` pass.
    let legacy_gated =
        async_pass == AsyncPass::Legacy && inner.cron_leader_gate.get().is_some_and(|gate| !gate());
    if legacy_gated {
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
            // Sharded (B10): only the node that owns this function's identity watches its blobs, so
            // exactly one node enqueues per change. Owns-all on single node / non-CAS backend (no-op).
            // A function this node doesn't own is simply left OUT of `desired`, so any watcher it had
            // is aborted by the `retain` below on the next reconcile after a membership change.
            if async_pass == AsyncPass::Sharded {
                let key = crate::async_shard_key_function(&project_name, &function.name);
                if !inner.async_shard_owns(deploy, &key).await {
                    continue;
                }
            }
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
                if let std::collections::hash_map::Entry::Vacant(slot) = watchers.entry(watch_id)
                    && let Some(handle) = spawn_blob_watcher(
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

/// The **deterministic** invocation id for a blob change (B10 Invariant 4): a SHA-256 over the
/// change's identity — project, function, pinned version, changed key, and change kind — so two
/// watchers that both observe the same change (the double-owner window of a membership transition)
/// mint the IDENTICAL id and thus enqueue exactly one logical invocation (the second write overwrites
/// an identical `Queued` record). Folding the version in means a genuinely new deploy re-fires.
#[cfg(feature = "handlers")]
fn blob_change_invocation_id(
    project: &str,
    function: &str,
    version: &str,
    key: &str,
    kind: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Length-prefix each field so distinct tuples can never collide by concatenation.
    for field in [project, function, version, key, kind] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    format!("blob-{}", hex::encode(hasher.finalize()))
}

/// Enqueue a durable async invocation for a blob change, with the changed key +
/// kind as the JSON request body (the function-relative key, `hblob/fn/<name>/`
/// stripped).
#[cfg(feature = "handlers")]
pub(super) async fn enqueue_blob_invocation(
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
    // Content-hash-idempotent id (B10 Invariant 4): derive the invocation id from the CHANGE itself
    // (project + function + version + changed key + kind), NOT a random nonce. During the double-owner
    // window of a membership transition the old and new owner may both observe the same change; a
    // deterministic id means both enqueue the SAME record key, so the second write overwrites an
    // identical `Queued` record instead of creating a duplicate invocation — exactly one logical
    // enqueue per change, cluster-wide. (A settled record with this id is not resurrected: the drain
    // only claims `Queued`/expired-`Running`, and a re-observed change after settlement is a genuinely
    // new event only if the version advanced, which the id folds in.)
    let id = blob_change_invocation_id(
        project.as_str(),
        &function.name,
        &function.active,
        key,
        kind,
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
        request_b64: (!payload.is_empty()).then(|| b64_encode(&payload)),
        request_content_type: Some("application/json".to_string()),
        result: None,
        created: now,
        updated: now,
    };
    // Create-if-absent-or-terminal (B10): never overwrite a `Queued`/`Running` record, so a second
    // observation of this change (the double-owner window, or a duplicate watcher event) coalesces
    // into the in-flight invocation instead of resurrecting it into a second run; a change after the
    // previous run settled re-fires. (The blind `put_invocation` here reset an in-flight record to
    // `Queued`, re-arming a second execution.)
    if let Err(err) = deploy.refire_invocation(project, &inv).await {
        tracing::warn!(function = %function.name, %err, "enqueuing blob invocation failed");
    }
}

/// One scheduler pass: for every site, drive the consumers and crons of its
/// active deployments. Consumers are processed inline (claim+dispatch); crons
/// that are due are fired as detached tasks (loopback dispatch). Returns the
/// number of messages acked and the spawned cron-fire handles (for tests).
// The tick threads the delivery topic-selection (`consumers`) AND the async-lane pass mode
// (`async_pass`, B10) alongside its four mutable state maps — over the 7-arg clippy soft cap, but
// each is load-bearing and grouping them into a struct would only move the noise. Same allow as the
// other wide scheduler/binding builders in this crate.
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
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
    // Phase-D async-lane sharding (B10): how this maintenance pass treats the async drain / crons /
    // blob watchers (see [`AsyncPass`]). `Legacy` = the pre-B10 leader-gate (every existing caller).
    async_pass: AsyncPass,
) -> Result<(usize, Vec<tokio::task::JoinHandle<()>>), DeployError> {
    use std::sync::atomic::Ordering;
    let mut acked = 0;
    let mut cron_handles = Vec::new();
    // Crons, the async lane, workflows, blob watchers, and the session reap are MAINTENANCE work,
    // never part of a per-ready-topic delivery drain — so they run only when this is a maintenance
    // pass (`All` or `Skip`), not the drainer's `Topics(..)` pass. `All` keeps every existing
    // caller/test byte-identical (it is a maintenance pass that also drives all consumers).
    let maintenance = !matches!(consumers, ConsumerFilter::Topics(_));
    // v0.7.1 orphaned-work signal (Item 7): accumulate every ACTIVE consumer's namespaced
    // subscription (exact OR `{tenant}` template) seen this maintenance pass, so after the walk we
    // can set-difference the backend's concrete indexed topics against these matchers and flag a
    // topic with claimable work that NO consumer covers. Only collected on a maintenance pass (`All`/
    // `Skip`); a per-ready-topic drain (`Topics`) does not touch it (the maintenance loop owns this
    // signal). Cheap: one string per active consumer.
    let mut active_subscriptions: Vec<String> = Vec::new();
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
            // The binding scope is PROJECT-QUALIFIED (`consumer_dispatch_scope`), exactly like the
            // handler path (`handler_dispatch.rs` `project_ref.qualified(&base)`) and the function
            // path (`project_ref.qualified("fn/…")`) — so a consumer/cron's `wasi:blobstore`
            // (`hblob/{scope}/…`) and its plain-topic namespace resolve to the SAME namespace this
            // project's handlers use, and are isolated across projects that share a site name. A BARE
            // scope (the pre-fix bug) pointed a non-default project's consumer at an empty,
            // cross-project-colliding `hblob/{site}/…`.
            // The third tuple element (PLAN-system-principal P2): whether the VERIFIED actor who
            // ACTIVATED this active deployment was a System·Admin — the per-(project, site) activation
            // authority a `run_as: deployer` cron consults. Production reads the activation record;
            // a background ALIAS has no such per-alias capture, so it is `false` (fail closed — an
            // alias cron never inherits the production activation's class).
            let mut active: Vec<(String, String, bool)> = Vec::new();
            if let Some(id) = deploy.current_id(project, &site).await? {
                let activator_is_system =
                    deploy.current_activator_is_system(project, &site).await?;
                active.push((
                    id,
                    consumer_dispatch_scope(project, &site),
                    activator_is_system,
                ));
            }
            for alias in &site_handlers.background_aliases {
                if let Some(id) = deploy.get_alias(project, &site, alias).await? {
                    active.push((
                        id,
                        consumer_dispatch_scope(project, &format!("{site}/{alias}")),
                        false,
                    ));
                }
            }
            for (deploy_id, scope, activator_is_system) in active {
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
                        // Orphaned-work signal (Item 7): record this active consumer's namespaced
                        // subscription (exact OR `{tenant}` template) on a maintenance pass, so the
                        // post-walk set-difference knows this topic/template IS covered.
                        if maintenance {
                            active_subscriptions.push(consumer_topic.clone());
                        }
                        // Which CONCRETE topics should this pass DISPATCH for this consumer (v0.7.1)?
                        // A non-templated `consumer_topic` (no `{tenant}` segment) degenerates to at
                        // most one exact target (today's behavior, unchanged); a `{tenant}`-templated
                        // subscription fans in over every matching concrete ready/indexed topic — once
                        // per concrete (preserving per-tenant group/DLQ). Each target carries its
                        // `TenantMatch`, so the dispatch can bind+verify the concrete `{tenant}` segment
                        // against the drained message's sealed context (the security crux).
                        //
                        // * `All`   — enumerate the backend's concrete indexed topics and match each
                        //   (the fallback poll for a non-ready-set backend + every existing caller/test).
                        // * `Skip`  — none (the ready-set drainer owns delivery).
                        // * `Topics(set)` — filter the ready set (the drainer already narrowed to due
                        //   topics; a template segment never appears there, so match each concrete).
                        use boatramp_core::messaging::{TenantMatch, tenant_tmpl_matches};
                        let targets: Vec<(String, TenantMatch)> = match consumers {
                            ConsumerFilter::Skip => Vec::new(),
                            ConsumerFilter::Topics(set) => set
                                .iter()
                                .filter_map(|t| {
                                    tenant_tmpl_matches(&consumer_topic, t).map(|m| (t.clone(), m))
                                })
                                .collect(),
                            ConsumerFilter::All => {
                                // Non-templated: keep the exact single fast path (no enumeration) —
                                // byte-identical to the pre-v0.7.1 `All`-pass dispatch of the literal
                                // topic. Templated: enumerate concrete indexed topics + match each.
                                if !consumer_topic
                                    .contains(boatramp_core::messaging::TENANT_TEMPLATE)
                                {
                                    vec![(consumer_topic.clone(), TenantMatch::Exact)]
                                } else {
                                    match messaging.indexed_topics().await {
                                        Ok(all) => all
                                            .into_iter()
                                            .filter_map(|t| {
                                                tenant_tmpl_matches(&consumer_topic, &t)
                                                    .map(|m| (t, m))
                                            })
                                            .collect(),
                                        Err(err) => {
                                            tracing::warn!(site, topic = %consumer.topic, %err, "enumerating concrete topics for a templated consumer failed");
                                            Vec::new()
                                        }
                                    }
                                }
                            }
                        };
                        if !targets.is_empty() {
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
                                // The consumer's tenant-secret name allowlist (task #493): empty ⇒ deny-all.
                                &consumer.tenant_secret_names,
                                // The consumer's blob-upload container allowlist (S3 ingress): empty ⇒ deny-all.
                                &consumer.upload_containers,
                                // The consumer's plain-`wasi:blobstore` allowlist (host-enforced tenant confinement).
                                &consumer.blobstore_containers,
                                // Per-guest secret allowlist (task #492): empty ⇒ the whole site pool.
                                &consumer.secrets,
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
                                // A consumer resolves any system class from the drained seal, not here.
                                false,
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
                                    tenant_secret_names: &consumer.tenant_secret_names,
                                    upload_containers: &consumer.upload_containers,
                                    blobstore_containers: &consumer.blobstore_containers,
                                    secret_allowlist: &consumer.secrets,
                                });
                            // Dispatch ONCE per matching concrete topic (v0.7.1 fan-in). For a
                            // non-templated consumer this loops exactly once over the exact topic
                            // (`TenantMatch::Exact`, `expected_tenant = None` ⇒ no bind-verify —
                            // unchanged). For a `{tenant}` template each concrete match carries its
                            // captured tenant as `expected_tenant`, so a per-message sealed-context
                            // mismatch is quarantined (bind-verify). `claim_grouped(concrete, group)`
                            // keys the group cursor + DLQ + lag per concrete topic, so per-tenant
                            // operability is preserved for free (Item 4).
                            // The fleet anchor (the signer's public half) the durable signed-context
                            // envelope is verified against — resolved once per consumer for the
                            // bind-verify. Absent (no signer wired) ⇒ a templated topic can verify no
                            // envelope, so every message on it quarantines (fail-closed).
                            let context_anchor = inner.session_signer.get().map(|s| s.public_key());
                            for (concrete, matched) in &targets {
                                let expected_tenant = match matched {
                                    TenantMatch::Exact => None,
                                    TenantMatch::Tenant(t) => Some(t.as_str()),
                                };
                                acked += dispatch_consumer_batch(
                                    &inner.engine,
                                    messaging.as_ref(),
                                    &inner.metrics,
                                    &site,
                                    concrete,
                                    &consumer_prefix,
                                    &consumer.group,
                                    consumer.start,
                                    &entry.hash,
                                    wasm,
                                    &bindings,
                                    rebuild.as_ref(),
                                    // The concrete topic's bound `{tenant}` segment (templated), or
                                    // `None` (non-templated ⇒ no check). SECURITY CRUX (Item 3).
                                    expected_tenant,
                                    context_anchor.as_ref(),
                                    site_limits(site_handlers),
                                    // Per-consumer overrides (≈ JetStream AckWait/MaxDeliver/batch),
                                    // each falling back to the server default when unset (back-compat).
                                    consumer
                                        .lease_ms
                                        .map(Duration::from_millis)
                                        .unwrap_or(CONSUMER_LEASE),
                                    consumer.max_attempts.unwrap_or(CONSUMER_MAX_ATTEMPTS),
                                    consumer.max_batch.unwrap_or(CONSUMER_BATCH),
                                    consumer.max_ack_pending,
                                    consumer.backoff_ms.unwrap_or(0),
                                    // P2 resource isolation: cap THIS consumer's node-wide
                                    // concurrency (clamped to the async lane); unset ⇒ shares the lane.
                                    consumer.max_concurrency,
                                )
                                .await;
                            }
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
                        {
                            // v0.7.1: a `{tenant}`-templated grouped consumer must sweep EACH matching
                            // concrete topic (sweeping the literal template is a no-op — no group state
                            // is keyed under the template string). A non-templated consumer sweeps its
                            // one literal topic (unchanged). The maintenance pass's `targets` above is
                            // empty on the `Skip` pass (the drainer owns delivery), so enumerate the
                            // concrete sweep set here independently of `targets`.
                            let sweep_topics: Vec<String> = if !consumer_topic
                                .contains(boatramp_core::messaging::TENANT_TEMPLATE)
                            {
                                vec![consumer_topic.clone()]
                            } else {
                                match messaging.indexed_topics().await {
                                    Ok(all) => all
                                        .into_iter()
                                        .filter(|t| {
                                            boatramp_core::messaging::tenant_tmpl_matches(
                                                &consumer_topic,
                                                t,
                                            )
                                            .is_some()
                                        })
                                        .collect(),
                                    Err(err) => {
                                        tracing::warn!(site, topic = %consumer.topic, %err, "enumerating concrete topics for a templated retention sweep failed");
                                        Vec::new()
                                    }
                                }
                            };
                            let retention_ms = consumer
                                .retention_ms
                                .unwrap_or(boatramp_core::messaging::GROUP_RETENTION_MS);
                            for sweep_topic in sweep_topics {
                                // Per-concrete once-a-minute throttle (each concrete topic has its own
                                // group cursor, so it sweeps independently).
                                if sweep_state
                                    .get(&sweep_topic)
                                    .is_some_and(|stamp| *stamp == now.minute_stamp)
                                {
                                    continue;
                                }
                                sweep_state.insert(sweep_topic.clone(), now.minute_stamp);
                                match messaging.retention_sweep(&sweep_topic, retention_ms).await {
                                    Ok(n) if n > 0 => tracing::debug!(
                                        topic = %sweep_topic,
                                        reclaimed = n,
                                        "consumer-group retention sweep"
                                    ),
                                    Ok(_) => {}
                                    Err(err) => tracing::warn!(
                                        topic = %sweep_topic, %err,
                                        "consumer-group retention sweep failed"
                                    ),
                                }
                            }
                        }
                    }
                }
                // --- crons (single-fire cluster-wide) ---
                // A cron fires on exactly ONE node so a scheduled job runs once cluster-wide.
                // Pre-B10 that node was the Raft leader (`cron_leader_gate`); under Phase-D sharding
                // (B10, `AsyncPass::Sharded`) it is the node that HRW-OWNS the cron's identity, so
                // crons spread across the fleet instead of all landing on the leader. Crons NEVER fire
                // on the unsharded safety-net pass (Invariant 5: a cron has no cross-node dedup for
                // *firing* — only the per-node `cron_state` within-minute guard — so a non-owner firing
                // would double-fire; a tick missed during a rare membership transition is bounded/
                // acceptable). Consumers above run on every node (leased dispatch distributes them).
                let cron_maintenance = match async_pass {
                    // Legacy leader-gate (single node ⇒ always) — byte-for-byte the pre-B10 behavior.
                    AsyncPass::Legacy => {
                        maintenance && inner.cron_leader_gate.get().is_none_or(|gate| gate())
                    }
                    // Sharded: owner-only, checked per-cron on its identity below.
                    AsyncPass::Sharded => maintenance,
                    // Safety-net: crons never fire here (would double-fire on a non-owner).
                    AsyncPass::UnshardedSafetyNet => false,
                };
                for (idx, cron) in manifest.config.crons.iter().enumerate() {
                    if !cron_maintenance {
                        break;
                    }
                    // Sharded pass: fire only if THIS node owns the cron's identity
                    // (`{project}/{site}#cron:{idx}`). Owns-all on single node / non-CAS backend, so
                    // this is a no-op there. Skip a cron this node doesn't own (its owner fires it).
                    if async_pass == AsyncPass::Sharded {
                        let cron_key = crate::async_shard_key_site_cron(project_name, &scope, idx);
                        if !inner.async_shard_owns(deploy, &cron_key).await {
                            continue;
                        }
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
                            activator_is_system,
                        )
                        .await;
                        running.store(false, Ordering::Release);
                    }));
                }
            }
        }
    }
    // --- async function invocations (FA-3) + function triggers + workflow runs ---
    // Phase-D sharding (B10) partitions this the same way as crons above:
    //   * `Legacy`  — leader-gated (single node ⇒ always), byte-for-byte the pre-B10 behavior.
    //   * `Sharded` — this node handles only the FUNCTIONS it HRW-OWNS (`{project}/{function}`), so
    //                 each node does its ~1/N share and the leader is no longer the async funnel.
    //   * `UnshardedSafetyNet` — DRAIN every function's queue regardless of ownership (the B7 no-owner
    //                 backstop): a function orphaned during a membership transition still drains within
    //                 one safety-net interval. Safe because `drain_function_invocations` now claims via
    //                 a CAS (Invariant 1), so a redundant scan on the owner + a safety-net node can
    //                 never double-execute — the loser's CAS is a no-op (Invariant 2).
    //
    // Split by race-safety:
    //   * `drain_function_invocations` — CAS-claimed ⇒ runs on the owner (Sharded) AND on the safety
    //     net (idempotent). This is the guarantee that no invocation is ever stranded.
    //   * `dispatch_function_triggers` — fires FUNCTION-level crons (each enqueues an invocation) and
    //     queue triggers; the cron enqueue has NO cross-node dedup, so it runs ONLY on the owner /
    //     leader, NEVER on the safety-net pass (else a non-owner double-enqueues the cron). A queue
    //     trigger skipped on the safety-net pass is fine (owner ticks drive it; the messaging claim is
    //     idempotent regardless).
    //   * `drain_workflow_runs` — OUT OF B10 SCOPE (its run record has no CAS-safe claim), so it stays
    //     strictly leader-gated and is never sharded — a documented residual for the review panel.
    if maintenance {
        let leader = inner.cron_leader_gate.get().is_none_or(|gate| gate());
        for project_name in &projects {
            let project = ProjectRef::new(project_name);
            for function in deploy.list_stored_functions(project).await? {
                let owns = match async_pass {
                    AsyncPass::Legacy => leader,
                    AsyncPass::Sharded => {
                        let key = crate::async_shard_key_function(project_name, &function.name);
                        inner.async_shard_owns(deploy, &key).await
                    }
                    // The safety net drains everyone's queues (owner or not); the CAS makes it safe.
                    AsyncPass::UnshardedSafetyNet => true,
                };
                if !owns {
                    continue;
                }
                // Fire due triggers first (a function cron enqueues an invocation this tick), then
                // drain the queue so a just-enqueued call runs without waiting. Triggers fire only on
                // the OWNER/LEADER (single-fire, no CAS dedup for the enqueue) — never on the safety
                // net; the queue drain runs everywhere it's reached (CAS-idempotent).
                if async_pass != AsyncPass::UnshardedSafetyNet {
                    dispatch_function_triggers(inner, deploy, project, &function, &now).await;
                }
                drain_function_invocations(
                    inner,
                    deploy,
                    project,
                    &function,
                    async_pass == AsyncPass::UnshardedSafetyNet,
                )
                .await;
            }
            // --- workflow runs (FA-6): strictly leader-gated, NOT sharded (B10 residual) ---
            if leader && async_pass != AsyncPass::UnshardedSafetyNet {
                for workflow in deploy.list_workflows(project).await? {
                    drain_workflow_runs(inner, deploy, project, &workflow).await;
                }
            }
        }
    }
    // v0.7.1 orphaned-work signal (Item 7): on a maintenance pass, set-difference the backend's
    // concrete indexed topics against the active consumer subscriptions collected above — a concrete
    // topic with claimable work that NO consumer covers (exact OR `{tenant}`-match) is ORPHANED
    // (a declared-but-un-routable consumer, or a producer with no consumer). Emit a `warn` + record
    // it into the metrics registry (`orphaned_ready_topic{topic}` gauge + the operator `stats`
    // block), so the silent stuck-backlog defect surfaces in minutes. Leader-gated (single node =
    // always) so a cluster raises it once, not per-node. Cheap: one `indexed_topics` scan + a
    // per-orphan `backlog` count (only for the — normally empty — uncovered set).
    let is_leader = inner.cron_leader_gate.get().is_none_or(|gate| gate());
    if maintenance
        && is_leader
        && let Some(messaging) = inner.messaging.clone()
    {
        match messaging.indexed_topics().await {
            Ok(indexed) => {
                let mut orphaned = std::collections::BTreeMap::new();
                for topic in indexed {
                    // Covered if ANY active subscription matches this concrete topic (an exact
                    // literal or a `{tenant}` template) — reuse the SAME matcher the dispatch uses,
                    // so the orphaned signal and the delivery path agree exactly.
                    let covered = active_subscriptions.iter().any(|sub| {
                        boatramp_core::messaging::tenant_tmpl_matches(sub, &topic).is_some()
                    });
                    if covered {
                        continue;
                    }
                    // Uncovered: count its claimable backlog (an uncovered topic is never claimed,
                    // so its whole backlog is never-attempted `attempts=0` work). A topic with zero
                    // backlog is not orphaned work — skip it (idle/drained).
                    let backlog = messaging.backlog(&topic).await.unwrap_or(0);
                    if backlog > 0 {
                        tracing::warn!(
                            topic = %topic,
                            claimable = backlog,
                            "orphaned ready topic: claimable work with NO active consumer \
                             subscription covering it (a declared-but-un-routable consumer, or a \
                             producer with no consumer) — messages will never be delivered"
                        );
                        orphaned.insert(topic, backlog as u64);
                    }
                }
                inner.metrics.set_orphaned_topics(orphaned);
            }
            // A backend without `indexed_topics` (poll-only) can't enumerate — clear the signal
            // (no false positives) rather than erroring the tick.
            Err(_) => inner
                .metrics
                .set_orphaned_topics(std::collections::BTreeMap::new()),
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
    // PLAN-system-principal P2: whether the VERIFIED actor who ACTIVATED the deployment serving THIS
    // (project, scope) was a System·Admin — resolved by the caller from the per-(project, site)
    // activation record (NOT the global, content-addressed `DeployMeta`), and `false` for a background
    // alias (fail closed). The sole input that can let a `run_as: deployer` cron fire as system.
    activator_is_system: bool,
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
    // PLAN-system-principal P2: a `run_as: deployer` cron fires as the system principal ONLY when the
    // VERIFIED actor who ACTIVATED this (project, site) was a System·Admin (`activator_is_system`,
    // bound per-site by `activate_with_principal` — never the global content meta). A deploy identity
    // carries no in-site tenant, so a non-system (or unknown / alias) activator's deployer-cron is
    // REFUSED (fail closed), never faked. A system fire coerces the handler to the system class + seals
    // a system `signed_context` on `emit` (so the downstream `signed_context` consumer resolves system).
    let run_as_system = match cron.run_as {
        boatramp_core::config::CronRunAs::Unauthenticated => false,
        boatramp_core::config::CronRunAs::Deployer => {
            if !activator_is_system {
                tracing::warn!(
                    site,
                    route = %cron.route,
                    "cron run_as:deployer refused — this site's current deployment was not activated by a System·Admin (fail closed); a deploy identity has no tenant to run as"
                );
                return;
            }
            true
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
        // A cron-triggered handler inherits the matched handler's tenant-secret allowlist (#493).
        &handler.tenant_secret_names,
        // A cron-triggered handler inherits the matched handler's blob-upload allowlist (S3 ingress).
        &handler.upload_containers,
        // A cron-triggered handler inherits the matched handler's plain-`wasi:blobstore` allowlist.
        &handler.blobstore_containers,
        // A cron-triggered handler inherits the matched handler's per-guest secret allowlist (#492).
        &handler.secrets,
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
        // PLAN-system-principal P2: fire as system iff this cron's deployer was a System·Admin.
        run_as_system,
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
/// caps (the lower of the two for each dimension). Memory, when neither cap is
/// set, inherits the lane ceiling (so raising `*_max_memory_mb` lifts every
/// component on that lane); the other dimensions are left at the engine default.
/// The engine then clamps everything to its own lane ceiling.
#[cfg(feature = "handlers")]
pub(super) fn effective_limits(
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    handler: &boatramp_core::config::HandlerConfig,
) -> boatramp_handlers::Limits {
    let mut limits = boatramp_handlers::Limits::default();
    let handler_limits = handler.limits.as_ref();
    // Memory: the lower of the site/handler caps. With NEITHER set, inherit the lane ceiling via the
    // `usize::MAX` sentinel — the engine's `min(requested, ceiling)` then yields the ceiling, so a
    // component on a lane whose `*_max_memory_mb` was raised gets that headroom without having to
    // restate it per component. A set cap only ever clamps DOWN from the ceiling (never raises it).
    limits.memory_bytes = [
        site_handlers.max_memory_mb,
        handler_limits.and_then(|l| l.memory_mb),
    ]
    .into_iter()
    .flatten()
    .min()
    .map(|mb| (mb as usize).saturating_mul(1024 * 1024))
    .unwrap_or(usize::MAX);
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
        // A deterministic per-invocation fault (the guest asked for more linear memory than its
        // ceiling), so a retry would fail identically — a 500-class crash, not transient capacity.
        HandlerError::OutOfMemory => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "handler exhausted its memory budget\n",
        ),
        HandlerError::Overloaded => (
            StatusCode::SERVICE_UNAVAILABLE,
            "handler engine at capacity\n",
        ),
        HandlerError::Compile(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "handler failed to compile\n",
        ),
        // `ConsumerError` is produced only on the consumer/async lane (never here on the sync HTTP
        // path), but the match must be exhaustive: a clean guest error is still a 500-class outcome.
        HandlerError::Trap(_)
        | HandlerError::ConsumerError(_)
        | HandlerError::NoResponse
        | HandlerError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "handler error\n"),
    };
    (status, body).into_response()
}

#[cfg(all(test, feature = "handlers"))]
mod consumer_scope_gate {
    use super::consumer_dispatch_scope;
    use boatramp_core::project::ProjectRef;

    /// GATE (boatramp-consumer-blob-scope-bug) — a consumer/cron dispatch scope is PROJECT-QUALIFIED,
    /// identical to the handler path, so its `wasi:blobstore` (`hblob/{scope}/…`) and plain-topic
    /// namespace resolve to the SAME namespace this project's handlers use, isolated across projects.
    /// Mutation-verified: `BOATRAMP_CONSUMERSCOPE_MUTATION=bare_scope` drops the qualification (the
    /// pre-fix bug) → the "equals the handler's qualified scope" assertion goes RED. Marker
    /// `CONSUMER BLOB SCOPE OK`.
    #[test]
    fn consumer_scope_is_project_qualified_and_isolated() {
        let p = ProjectRef::new("construens-preview");
        // The invariant: a consumer's scope EQUALS what the handler path computes for the same
        // (project, site) — `project_ref.qualified(site)`. This is the exact bug: they must match.
        assert_eq!(
            consumer_dispatch_scope(p, "console"),
            p.qualified("console"),
            "consumer scope must equal the handler's project-qualified scope"
        );
        assert_eq!(
            consumer_dispatch_scope(p, "console"),
            "construens-preview/console"
        );
        // Background alias is qualified too.
        assert_eq!(
            consumer_dispatch_scope(p, "console/thumbs"),
            "construens-preview/console/thumbs"
        );
        // Default project: byte-identical to the bare site (no regression on the pre-project layout).
        assert_eq!(
            consumer_dispatch_scope(ProjectRef::DEFAULT, "console"),
            "console"
        );
        // Cross-project isolation: two projects' `console` consumers get DISTINCT scopes, so one can
        // never address the other's `hblob/.../console/...` namespace.
        assert_ne!(
            consumer_dispatch_scope(ProjectRef::new("alpha"), "console"),
            consumer_dispatch_scope(ProjectRef::new("beta"), "console"),
        );
        println!("CONSUMER BLOB SCOPE OK");
    }
}
