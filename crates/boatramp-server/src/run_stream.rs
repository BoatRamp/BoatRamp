//! The **run engine** (PLAN-run-streaming P1): the durable driver behind a correlation-scoped,
//! resumable run event stream. It EXTENDS the v0.74 consumer-delivery core — it does not duplicate it.
//! Every durability property (the retained append-only log, leases, at-least-once, redelivery) is
//! inherited from the unchanged [`Messaging::claim_grouped`](boatramp_core::messaging::Messaging)
//! core and the shared [`pump_until_batch`](crate::bus_consumer::pump_until_batch) claim pump; this
//! module adds only the per-run correlation scope, the typed envelope, the `seq` allocator, and
//! cancellation.
//!
//! # How a run rides the durable grouped log
//! A run is its OWN durable grouped topic, keyed by [`run_topic`] under the reserved, tenancy-fenced
//! `{project}/.boatramp-run/{scope}/{run_id}` namespace (unreachable by any guest producer — see
//! [`boatramp_core::run`]). At [`create`](RunEngine::create) the engine registers a RETENTION consumer
//! group ([`RUN_RETENTION_GROUP`]) on the topic: that makes every emit land in the RETAINED grouped
//! log (not the delete-on-ack work-queue), and because the retention group is never advanced its
//! retention low-water pins the whole log for the run's life — so any (re)attach replays from the
//! start with no loss.
//!
//! - **emit** reserves the next `seq` (an atomic CAS on the per-run [`RunState`]), builds the typed
//!   [`RunEnvelope`], and publishes it to the run topic (retained). A terminal kind then flips the
//!   run's status so a further emit is refused — the stop signal a long-lived emitter observes.
//! - **attach** opens a FRESH ephemeral consumer group on the run topic (so every attacher sees every
//!   event — fan-out for free), drives the durable pump, auto-acks each frame, and skips any envelope
//!   whose `seq <= after_seq` (lossless resume by the caller-carried cursor). It ends when it delivers
//!   a terminal envelope.
//! - **cancel** (explicit, or drop-cancel when an attacher goes away before a terminal) emits the
//!   terminal `cancelled` envelope and flips the status — idempotent.
//!
//! # Tenancy
//! The engine is BAKED with the invocation's resolved `(project, scope)` — the guest never names
//! either. A `run_id` from tenant A composes a different key under tenant B's scope, which does not
//! exist, so cross-tenant reach is structurally impossible (and the id is unguessable on top).

#![cfg(feature = "run-streaming")]

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use boatramp_core::config::{StartPosition, SubscriptionParams};
use boatramp_core::kv::KvStore;
use boatramp_core::messaging::{ClaimedMessage, Messaging, Wake};
use boatramp_core::run::{
    RUN_PAYLOAD_MAX, RUN_RETENTION_GROUP, RunEnvelope, RunError, RunEventKind, RunState, RunStatus,
    decode_envelope, encode_envelope, mint_run_id, run_state_key, run_topic, validate_run_id,
};
use boatramp_core::time::now_unix_ms;
use futures::StreamExt;
use futures::stream::BoxStream;

use crate::bus_consumer::pump_until_batch;

/// Visibility lease on a claimed run frame. The attach pump auto-acks each frame immediately, so the
/// lease only matters if an attacher process dies mid-frame — the frame then redelivers (at-least-once
/// via the durable core), and a fresh attach replays the retained log anyway.
const RUN_LEASE: Duration = Duration::from_secs(30);

/// Dead-letter threshold for a run frame. Set high: a run event must not be dead-lettered out of the
/// retained log during normal replay (the attach pump acks promptly, so attempts never climb in
/// practice); this is only the backstop for a pathologically wedged attacher.
const RUN_MAX_ATTEMPTS: u32 = 1000;

/// The engine's output of [`attach`](RunEngine::attach): the envelope stream plus whether DROP-CANCEL
/// is armed for this run (so the caller can wire the drop hook).
pub struct EngineAttach {
    /// Envelopes in `seq` order (resumed past `after_seq`); ends (`None`) after a terminal envelope.
    pub stream: BoxStream<'static, Result<RunEnvelope, RunError>>,
    /// Whether this run has drop-cancel armed — the caller cancels the run if the attacher drops
    /// before a terminal event.
    pub drop_cancel_armed: bool,
}

/// The durable run engine, baked to one invocation's resolved `(project, scope)`. Cheap to clone
/// (two `Arc`s + two small strings), so the drop-cancel hook can own a clone.
#[derive(Clone)]
pub struct RunEngine {
    messaging: Arc<dyn Messaging>,
    kv: Arc<dyn KvStore>,
    /// The project-qualified root (`ProjectRef::qualified` of the bare project) — the run topic's
    /// first segment, so a run is confined to its project exactly like the project bus.
    project_qualified: String,
    /// The tenancy scope segment (`boatramp_core::run::run_scope_segment`) — host-composed from the
    /// invocation's resolved own-tenant, never guest input.
    scope: String,
}

impl RunEngine {
    /// Build an engine baked to `project_qualified` + `scope` over the node's durable messaging + KV.
    #[must_use]
    pub fn new(
        messaging: Arc<dyn Messaging>,
        kv: Arc<dyn KvStore>,
        project_qualified: impl Into<String>,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            messaging,
            kv,
            project_qualified: project_qualified.into(),
            scope: scope.into(),
        }
    }

    /// The durable topic for `run_id` under THIS engine's baked `(project, scope)`.
    fn topic(&self, run_id: &str) -> String {
        run_topic(&self.project_qualified, &self.scope, run_id)
    }

    /// Load a run's state record + its raw bytes (for a subsequent CAS), or `None` if the run does
    /// not exist under this scope (the fail-closed cross-tenant / fabricated-id case).
    async fn load_state(&self, state_key: &str) -> Result<Option<(RunState, Vec<u8>)>, RunError> {
        match self
            .kv
            .get(state_key)
            .await
            .map_err(|e| RunError::Backend(e.to_string()))?
        {
            Some(bytes) => {
                let state = serde_json::from_slice::<RunState>(&bytes)
                    .map_err(|e| RunError::Backend(format!("run state decode: {e}")))?;
                Ok(Some((state, bytes)))
            }
            None => Ok(None),
        }
    }

    /// CREATE a new run fenced to this engine's `(project, scope)`. Registers the retention group so
    /// every emit is retained from the first event, then writes the durable state record. Returns the
    /// server-minted run id.
    pub async fn create(&self, drop_cancel: bool) -> Result<String, RunError> {
        let run_id = mint_run_id();
        let topic = self.topic(&run_id);
        // Register the retention group FIRST (an empty claim on a fresh group just creates its state),
        // so an emit — which requires the state record below, written after — always lands in the
        // retained grouped log rather than the delete-on-ack work-queue.
        self.messaging
            .claim_grouped(
                &topic,
                RUN_RETENTION_GROUP,
                StartPosition::Earliest,
                RUN_LEASE,
                1,
                RUN_MAX_ATTEMPTS,
            )
            .await
            .map_err(|e| RunError::Backend(e.to_string()))?;
        let state = RunState::new(drop_cancel);
        let bytes = serde_json::to_vec(&state)
            .map_err(|e| RunError::Backend(format!("run state encode: {e}")))?;
        let key = run_state_key(&topic);
        // Create-if-absent: a minted id collision (128-bit random) is effectively impossible, so a
        // lost CAS here is a hard backend anomaly rather than a retry case.
        let created = self
            .kv
            .compare_and_swap(&key, None, bytes)
            .await
            .map_err(|e| RunError::Backend(e.to_string()))?;
        if !created {
            return Err(RunError::Backend("run id collision on create".into()));
        }
        Ok(run_id)
    }

    /// Reserve the next `seq` for a run via an atomic CAS on its state, refusing a non-active run
    /// (the stop signal). Returns the reserved `seq`. The status is NOT changed here — a terminal
    /// transition is finalized AFTER the terminal envelope is durably published (so an attacher always
    /// finds the terminal envelope, and emit-after-terminal is refused).
    async fn reserve_seq(&self, state_key: &str) -> Result<u64, RunError> {
        loop {
            let Some((state, raw)) = self.load_state(state_key).await? else {
                return Err(RunError::NotFound);
            };
            match state.status {
                RunStatus::Active => {}
                RunStatus::Cancelled => return Err(RunError::Cancelled),
                RunStatus::Ended | RunStatus::Errored => return Err(RunError::Terminal),
            }
            let seq = state.next_seq;
            let next = RunState {
                next_seq: seq + 1,
                ..state.clone()
            };
            let bytes = serde_json::to_vec(&next)
                .map_err(|e| RunError::Backend(format!("run state encode: {e}")))?;
            if self
                .kv
                .compare_and_swap(state_key, Some(&raw), bytes)
                .await
                .map_err(|e| RunError::Backend(e.to_string()))?
            {
                return Ok(seq);
            }
            // Lost the race with a concurrent emit — reload and retry (another emit reserved a seq).
        }
    }

    /// Finalize a terminal run: CAS the status to the terminal kind's status + record `terminal_seq`.
    /// Called AFTER the terminal envelope is durably published. Idempotent-ish: a run already terminal
    /// is left as-is (the first terminal wins).
    async fn finalize_terminal(
        &self,
        state_key: &str,
        status: RunStatus,
        seq: u64,
    ) -> Result<(), RunError> {
        loop {
            let Some((state, raw)) = self.load_state(state_key).await? else {
                return Err(RunError::NotFound);
            };
            if state.status != RunStatus::Active {
                // Already terminal (a racing terminal emit won) — leave the first terminal in place.
                return Ok(());
            }
            let next = RunState {
                status,
                terminal_seq: Some(seq),
                ..state.clone()
            };
            let bytes = serde_json::to_vec(&next)
                .map_err(|e| RunError::Backend(format!("run state encode: {e}")))?;
            if self
                .kv
                .compare_and_swap(state_key, Some(&raw), bytes)
                .await
                .map_err(|e| RunError::Backend(e.to_string()))?
            {
                return Ok(());
            }
        }
    }

    /// EMIT one event to `run_id`. Reserves the monotonic `seq`, publishes the typed envelope to the
    /// retained run log, and (for a terminal kind) flips the run's status. Returns the allocated `seq`.
    /// Refuses a non-existent run (`NotFound`), or a terminal/cancelled run (`Terminal`/`Cancelled` —
    /// the stop signal).
    pub async fn emit(
        &self,
        run_id: &str,
        kind: RunEventKind,
        payload: Vec<u8>,
    ) -> Result<u64, RunError> {
        validate_run_id(run_id)?;
        if payload.len() > RUN_PAYLOAD_MAX {
            return Err(RunError::Invalid(format!(
                "payload exceeds the {RUN_PAYLOAD_MAX}-byte cap ({} given)",
                payload.len()
            )));
        }
        let topic = self.topic(run_id);
        let state_key = run_state_key(&topic);
        let seq = self.reserve_seq(&state_key).await?;
        let env = RunEnvelope {
            run_id: run_id.to_string(),
            seq,
            kind,
            timestamp_ms: now_unix_ms(),
            payload,
        };
        let bytes = encode_envelope(&env)?;
        // Publish to the run topic — retained in the grouped log (the retention group is registered),
        // so a (re)attach replays it. The run's tenancy is the KEY, so no signed-context is needed.
        self.messaging
            .publish(&topic, &bytes)
            .await
            .map_err(|e| RunError::Backend(e.to_string()))?;
        if let Some(status) = kind.terminal_status() {
            self.finalize_terminal(&state_key, status, seq).await?;
        }
        Ok(seq)
    }

    /// The current [`RunStatus`] of `run_id` — a cheap poll a long-lived emitter uses to observe a
    /// cancel between work steps and stop early.
    pub async fn status(&self, run_id: &str) -> Result<RunStatus, RunError> {
        validate_run_id(run_id)?;
        let topic = self.topic(run_id);
        let state_key = run_state_key(&topic);
        let Some((state, _)) = self.load_state(&state_key).await? else {
            return Err(RunError::NotFound);
        };
        Ok(state.status)
    }

    /// CANCEL `run_id` (explicit or drop-cancel): emit the terminal `cancelled` envelope + flip the
    /// status. Idempotent — cancelling an already-terminal run is a no-op success (but a non-existent
    /// run is `NotFound`).
    pub async fn cancel(&self, run_id: &str) -> Result<(), RunError> {
        match self.emit(run_id, RunEventKind::Cancelled, Vec::new()).await {
            Ok(_) => Ok(()),
            // Already concluded (someone emitted a terminal / cancelled first) — cancel is a no-op.
            Err(RunError::Terminal | RunError::Cancelled) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// ATTACH to `run_id`, resuming strictly AFTER `after_seq` (`None` = from the first event),
    /// lossless and in `seq` order. The returned stream replays the retained log (skipping
    /// `seq <= after_seq`) then tails live emits, ending after it delivers a terminal envelope.
    pub async fn attach(
        &self,
        run_id: &str,
        after_seq: Option<u64>,
    ) -> Result<EngineAttach, RunError> {
        validate_run_id(run_id)?;
        let topic = self.topic(run_id);
        let state_key = run_state_key(&topic);
        let Some((state, _)) = self.load_state(&state_key).await? else {
            return Err(RunError::NotFound);
        };
        // If the run is already terminal and the caller's cursor already covers the terminal event,
        // there is nothing left to deliver — return an empty stream rather than park forever.
        if state.status != RunStatus::Active
            && let (Some(term), Some(after)) = (state.terminal_seq, after_seq)
            && after >= term
        {
            let empty = futures::stream::empty::<Result<RunEnvelope, RunError>>().boxed();
            return Ok(EngineAttach {
                stream: empty,
                drop_cancel_armed: false, // already terminal — nothing to drop-cancel
            });
        }

        // A FRESH ephemeral consumer group per attach (so every attacher sees every event — fan-out);
        // `earliest` so it replays the whole retained log, filtered by `after_seq`. The retention
        // group keeps the log retained regardless of this group's acks.
        let group = format!("a{}", mint_run_id().replace('-', ""));
        let sub = SubscriptionParams {
            group,
            start: StartPosition::Earliest,
            lease_ms: Some(RUN_LEASE.as_millis() as u64),
            max_attempts: Some(RUN_MAX_ATTEMPTS),
            max_batch: None,
            max_ack_pending: None,
            backoff_ms: None,
            retention_ms: None,
        }
        .resolve();

        struct AttachState {
            messaging: Arc<dyn Messaging>,
            key: String,
            sub: boatramp_core::config::ResolvedSubscription,
            wake: Option<Wake>,
            buffer: VecDeque<ClaimedMessage>,
            after_seq: Option<u64>,
            done: bool,
        }
        let st = AttachState {
            wake: self.messaging.wake_handle(),
            messaging: self.messaging.clone(),
            key: topic,
            sub,
            buffer: VecDeque::new(),
            after_seq,
            done: false,
        };

        let stream = futures::stream::unfold(st, |mut st| async move {
            loop {
                if st.done {
                    return None;
                }
                if let Some(m) = st.buffer.pop_front() {
                    // Auto-ack the frame to advance THIS ephemeral group (the retention group still
                    // pins the retained log, so a later attach can replay the whole run).
                    let _ = st.messaging.ack(&m).await;
                    let env = match decode_envelope(&m.payload) {
                        Ok(e) => e,
                        Err(e) => {
                            st.done = true;
                            return Some((Err(e), st));
                        }
                    };
                    // Lossless resume: skip anything the caller already has.
                    if let Some(after) = st.after_seq
                        && env.seq <= after
                    {
                        continue;
                    }
                    if env.kind.is_terminal() {
                        st.done = true;
                    }
                    return Some((Ok(env), st));
                }
                // Refill: the durable pump parks on the wake (zero busy-poll) until a batch appears.
                match pump_until_batch(st.messaging.as_ref(), &st.key, &st.sub, &st.wake).await {
                    Ok(batch) => st.buffer.extend(batch),
                    Err(e) => {
                        st.done = true;
                        return Some((Err(RunError::Backend(e.to_string())), st));
                    }
                }
            }
        })
        // Fuse so polling past end-of-stream is a safe `None` (a raw `unfold` panics on re-poll); the
        // binding seam never re-polls, but a direct consumer (or P2's HTTP door) may.
        .fuse()
        .boxed();

        Ok(EngineAttach {
            stream,
            drop_cancel_armed: state.drop_cancel,
        })
    }
}

// ---- the guest-binding seam adapter -----------------------------------------------------------
// `RunEngine` above is transport-agnostic (it will also back the P2 external HTTP front door). This
// adapter implements the handlers `RunStore` seam so the `boatramp:handlers/run` binding can delegate
// to it, mapping the host-internal `RunError` onto the seam's `RunStoreError` and wiring the
// drop-cancel hook from the engine's armed flag.

use boatramp_handlers::{RunAttachStream, RunStore, RunStoreError};

/// Map the engine's host-internal error onto the binding seam's error (both are host-side; the WIT
/// `access-denied` is decided by the posture/grant gate in the binding, never reached here).
fn to_store_err(e: RunError) -> RunStoreError {
    match e {
        RunError::NotFound => RunStoreError::NotFound,
        RunError::Terminal => RunStoreError::Terminal,
        RunError::Cancelled => RunStoreError::Cancelled,
        RunError::Invalid(m) => RunStoreError::Invalid(m),
        RunError::Backend(m) => RunStoreError::Backend(m),
    }
}

/// The `RunStore` seam over a baked [`RunEngine`], handed to `Bindings::with_run` by the server's
/// `build_bindings`. The engine is already fenced to the invocation's `(project, scope)`.
pub struct RunStoreImpl {
    engine: Arc<RunEngine>,
}

impl RunStoreImpl {
    /// Wrap a baked engine as the guest-binding seam.
    #[must_use]
    pub fn new(engine: RunEngine) -> Self {
        Self {
            engine: Arc::new(engine),
        }
    }
}

#[async_trait::async_trait]
impl RunStore for RunStoreImpl {
    async fn create(&self) -> Result<String, RunStoreError> {
        // Guest-created runs default to DROP-CANCEL ON (the plan's default): a dropped watcher must
        // not leave a long-lived emitter burning compute.
        self.engine.create(true).await.map_err(to_store_err)
    }

    async fn emit(
        &self,
        run_id: &str,
        kind: RunEventKind,
        payload: Vec<u8>,
    ) -> Result<u64, RunStoreError> {
        self.engine
            .emit(run_id, kind, payload)
            .await
            .map_err(to_store_err)
    }

    async fn attach(
        &self,
        run_id: &str,
        after_seq: Option<u64>,
    ) -> Result<RunAttachStream, RunStoreError> {
        let EngineAttach {
            stream,
            drop_cancel_armed,
        } = self
            .engine
            .attach(run_id, after_seq)
            .await
            .map_err(to_store_err)?;
        let mapped = stream.map(|r| r.map_err(to_store_err)).boxed();
        let drop_cancel = if drop_cancel_armed {
            let engine = self.engine.clone();
            let rid = run_id.to_string();
            let hook: Box<dyn FnOnce() -> futures::future::BoxFuture<'static, ()> + Send> =
                Box::new(move || {
                    Box::pin(async move {
                        // Drop-cancel: the attacher went away before a terminal event, so stop the run
                        // (idempotent — a no-op if it already concluded).
                        let _ = engine.cancel(&rid).await;
                    })
                });
            Some(hook)
        } else {
            None
        };
        Ok(RunAttachStream::new(mapped, drop_cancel))
    }

    async fn cancel(&self, run_id: &str) -> Result<(), RunStoreError> {
        self.engine.cancel(run_id).await.map_err(to_store_err)
    }

    async fn status(&self, run_id: &str) -> Result<RunStatus, RunStoreError> {
        self.engine.status(run_id).await.map_err(to_store_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::messaging::LogMessaging;
    use boatramp_core::run::run_scope_segment;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use boatramp_core::{
        ByteStream, GetObject, ListPage, ObjectMeta, PutMeta, Storage, StorageError,
    };
    use bytes::Bytes as RawBytes;

    /// Minimal in-memory [`Storage`] so the REAL [`LogMessaging`] durable substrate can be built
    /// (it persists non-inlined payloads as objects) — mirrors the bus-consumer test's `MemStorage`.
    #[derive(Default, Clone)]
    struct MemStorage {
        map: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    }
    fn meta(key: &str, len: usize) -> ObjectMeta {
        ObjectMeta {
            key: key.to_string(),
            size: Some(len as u64),
            content_type: None,
            etag: None,
        }
    }
    fn once_stream(bytes: RawBytes) -> ByteStream {
        futures::stream::once(async move { Ok::<_, StorageError>(bytes) }).boxed()
    }
    #[async_trait]
    impl Storage for MemStorage {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            let data = self
                .map
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(GetObject {
                meta: meta(key, data.len()),
                body: once_stream(RawBytes::from(data)),
            })
        }
        async fn get_range(
            &self,
            key: &str,
            offset: u64,
            len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            let data = self
                .map
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            let start = (offset as usize).min(data.len());
            let end = match len {
                Some(l) => (start + l as usize).min(data.len()),
                None => data.len(),
            };
            Ok(GetObject {
                meta: meta(key, end - start),
                body: once_stream(RawBytes::from(data[start..end].to_vec())),
            })
        }
        async fn put(
            &self,
            key: &str,
            mut body: ByteStream,
            _meta: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            let mut buf = Vec::new();
            while let Some(chunk) = body.next().await {
                buf.extend_from_slice(&chunk?);
            }
            let m = meta(key, buf.len());
            self.map.lock().unwrap().insert(key.to_string(), buf);
            Ok(m)
        }
        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            let map = self.map.lock().unwrap();
            let data = map
                .get(key)
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(meta(key, data.len()))
        }
        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.map.lock().unwrap().remove(key);
            Ok(())
        }
        async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(self
                .map
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| meta(k, v.len()))
                .collect())
        }
        async fn list_page(
            &self,
            prefix: &str,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<ListPage, StorageError> {
            Ok(ListPage {
                metas: self.list(prefix).await?,
                cursor: None,
            })
        }
    }

    /// Build an engine over the REAL `LogMessaging` + `MemoryKv` durable core, fenced to one tenant.
    fn engine_for(tenant: Option<&str>) -> RunEngine {
        let messaging = Arc::new(LogMessaging::new(
            Arc::new(MemStorage::default()),
            Arc::new(MemoryKv::new()),
        ));
        // The engine's seq-allocator CAS + state live in a SEPARATE KV from the messaging substrate's
        // KV (as in production: the control-plane KV vs the messaging substrate). A shared one works
        // too; separate is the honest topology.
        let kv = Arc::new(MemoryKv::new());
        RunEngine::new(messaging, kv, "acme", run_scope_segment(tenant))
    }

    /// Share ONE messaging+kv substrate across several engines (to model two tenants on one node).
    fn shared_substrate() -> (Arc<LogMessaging>, Arc<MemoryKv>) {
        (
            Arc::new(LogMessaging::new(
                Arc::new(MemStorage::default()),
                Arc::new(MemoryKv::new()),
            )),
            Arc::new(MemoryKv::new()),
        )
    }

    async fn collect_n(attach: &mut EngineAttach, n: usize) -> Vec<RunEnvelope> {
        let mut out = Vec::new();
        for _ in 0..n {
            match attach.stream.next().await {
                Some(Ok(env)) => out.push(env),
                Some(Err(e)) => panic!("attach error: {e}"),
                None => break,
            }
        }
        out
    }

    /// P1 (1) emit progress*→result; (3) a guest attacher receives the envelopes in `seq` order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn emit_then_attach_receives_in_seq_order() {
        let engine = engine_for(Some("firm-a"));
        let run = engine.create(true).await.unwrap();
        for i in 0..3u8 {
            engine
                .emit(&run, RunEventKind::Progress, vec![i])
                .await
                .unwrap();
        }
        engine
            .emit(&run, RunEventKind::Result, b"done".to_vec())
            .await
            .unwrap();

        let mut attach = engine.attach(&run, None).await.unwrap();
        let got = collect_n(&mut attach, 10).await;
        let seqs: Vec<u64> = got.iter().map(|e| e.seq).collect();
        assert_eq!(
            seqs,
            vec![0, 1, 2, 3],
            "envelopes arrive in strict seq order"
        );
        assert_eq!(got[3].kind, RunEventKind::Result);
        assert_eq!(got[3].payload, b"done");
        // The stream ENDS after the terminal envelope.
        assert!(attach.stream.next().await.is_none());
    }

    /// P1 (3) the durable guarantee: a reconnecting attacher resuming after its last `seq` sees NO gap
    /// and NO loss. Drop-cancel OFF (this exercises resume, not cancel).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconnect_resumes_after_seq_with_no_gap_or_loss() {
        let engine = engine_for(Some("firm-a"));
        let run = engine.create(false).await.unwrap();
        for i in 0..6u8 {
            engine
                .emit(&run, RunEventKind::Progress, vec![i])
                .await
                .unwrap();
        }
        // Attacher #1 reads the first three, then "disconnects" (drops the stream).
        let mut a1 = engine.attach(&run, None).await.unwrap();
        let first = collect_n(&mut a1, 3).await;
        assert_eq!(
            first.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        drop(a1);

        // Attacher #2 resumes strictly AFTER seq 2 — it must see 3,4,5 with no gap and no loss (the
        // retained log replays from the start, skipping what the caller already has).
        let mut a2 = engine.attach(&run, Some(2)).await.unwrap();
        let resumed = collect_n(&mut a2, 3).await;
        assert_eq!(
            resumed.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![3, 4, 5],
            "resume sees exactly the un-consumed suffix — no gap, no loss"
        );
        // Tail: a late terminal arrives on the live connection and ends the stream.
        engine
            .emit(&run, RunEventKind::End, Vec::new())
            .await
            .unwrap();
        let tail = collect_n(&mut a2, 2).await;
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].kind, RunEventKind::End);
        assert!(a2.stream.next().await.is_none());
    }

    /// P1 (4b) explicit cancel: a `cancelled` terminal is emitted, the attacher sees it, and a
    /// subsequent emit is REFUSED with `Cancelled` (the stop signal a long-lived emitter observes).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn explicit_cancel_emits_cancelled_and_stops_the_emitter() {
        let engine = engine_for(Some("firm-a"));
        let run = engine.create(true).await.unwrap();
        engine
            .emit(&run, RunEventKind::Progress, b"p".to_vec())
            .await
            .unwrap();
        engine.cancel(&run).await.unwrap();

        assert_eq!(engine.status(&run).await.unwrap(), RunStatus::Cancelled);
        // The emitting agent's next emit learns the run is cancelled and stops.
        assert_eq!(
            engine
                .emit(&run, RunEventKind::Progress, b"more".to_vec())
                .await,
            Err(RunError::Cancelled)
        );

        let mut attach = engine.attach(&run, None).await.unwrap();
        let got = collect_n(&mut attach, 5).await;
        assert_eq!(got.last().unwrap().kind, RunEventKind::Cancelled);
        assert!(attach.stream.next().await.is_none());
    }

    /// P1 (4a) drop-cancel: when the attacher drops before a terminal event, the run is cancelled and
    /// the emitter is signalled to stop. Driven through the `RunStore` seam (whose `attach` wires the
    /// drop hook), since drop-cancel is a seam-level behavior.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_cancel_stops_the_emitter() {
        let store = RunStoreImpl::new(engine_for(Some("firm-a")));
        let run = store.create().await.unwrap(); // drop-cancel ON by default
        store
            .emit(&run, RunEventKind::Progress, b"p".to_vec())
            .await
            .unwrap();

        // Attach, read the one progress event (NOT a terminal), then drop before any terminal.
        let mut attach = store.attach(&run, None).await.unwrap();
        let first = attach.next().await.expect("one event").expect("ok");
        assert_eq!(first.kind, RunEventKind::Progress);
        // Dropping the attacher (simulating the resource drop) must drop-cancel the run.
        attach.on_drop().await;

        assert_eq!(store.status(&run).await.unwrap(), RunStatus::Cancelled);
        // The long-lived emitter's next emit is refused — it genuinely stops.
        assert_eq!(
            store
                .emit(&run, RunEventKind::Progress, b"x".to_vec())
                .await,
            Err(RunStoreError::Cancelled)
        );
    }

    /// P1 (5) tenancy fence: a `run_id` created by tenant A is UNREACHABLE from tenant B on the SAME
    /// node — every op (emit / attach / cancel / status) fails `NotFound`, never a cross-tenant touch.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cross_tenant_access_is_refused() {
        let (messaging, kv) = shared_substrate();
        let a = RunEngine::new(
            messaging.clone(),
            kv.clone(),
            "acme",
            run_scope_segment(Some("firm-a")),
        );
        let b = RunEngine::new(messaging, kv, "acme", run_scope_segment(Some("firm-b")));

        let run = a.create(true).await.unwrap();
        a.emit(&run, RunEventKind::Progress, b"secret".to_vec())
            .await
            .unwrap();

        // Tenant B presents A's run id — the host composes a DIFFERENT (B-scoped) key, so the run is
        // simply not found. No bytes of A's run are ever reachable.
        assert_eq!(
            b.emit(&run, RunEventKind::Progress, b"x".to_vec()).await,
            Err(RunError::NotFound)
        );
        assert_eq!(b.status(&run).await, Err(RunError::NotFound));
        assert_eq!(b.cancel(&run).await, Err(RunError::NotFound));
        assert!(matches!(
            b.attach(&run, None).await,
            Err(RunError::NotFound)
        ));

        // A's own run is unaffected and still active (no byte of it was touched by B).
        assert_eq!(a.status(&run).await.unwrap(), RunStatus::Active);
    }

    /// Resume whose cursor already covers the terminal event ends immediately (no park) rather than
    /// hanging on a run that has already concluded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resume_past_terminal_ends_immediately() {
        let engine = engine_for(Some("firm-a"));
        let run = engine.create(false).await.unwrap();
        engine
            .emit(&run, RunEventKind::Progress, vec![0])
            .await
            .unwrap();
        let term = engine
            .emit(&run, RunEventKind::End, Vec::new())
            .await
            .unwrap();
        // A reconnect whose cursor is at/after the terminal seq has nothing left — the stream ends.
        let mut attach = engine.attach(&run, Some(term)).await.unwrap();
        assert!(attach.stream.next().await.is_none());
    }

    /// Emit/attach/cancel on a fabricated (never-created) run id fail closed with `NotFound`.
    #[tokio::test]
    async fn fabricated_run_id_is_not_found() {
        let engine = engine_for(Some("firm-a"));
        let fake = mint_run_id();
        assert_eq!(
            engine.emit(&fake, RunEventKind::Progress, vec![]).await,
            Err(RunError::NotFound)
        );
        assert_eq!(engine.status(&fake).await, Err(RunError::NotFound));
    }
}
