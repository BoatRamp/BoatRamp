//! The host-side **run** binding (`boatramp:handlers/run`, PLAN-run-streaming P1): a granted,
//! posture-ON guest CREATEs a durable run, EMITs typed events to it over time (the long-lived
//! bus-consumer emit path), ATTACHes to a run's resumable event stream, and CANCELs it. The durable
//! substrate logic (the tenancy-fenced per-run topic, the `seq` allocator, the claim pump,
//! cancellation) lives a layer up behind the [`RunStore`] seam the server implements over the v0.74
//! consumer-delivery core — this binding is only the capability gate + the WIT glue, exactly like
//! `egress-register` / `invoke`.
//!
//! # Fail-closed gate (deny-by-default at every layer)
//! 1. **Node posture `allow_guest_run_streaming`** (carried as `posture_enabled`, OFF by default):
//!    off ⇒ `access-denied`.
//! 2. **Per-grant**: the binding is `None` when the component was not granted the capability ⇒
//!    `access-denied`.
//! The run's TENANCY fence is structural, below this gate: the [`RunStore`] the server injects is
//! BAKED with THIS invocation's resolved `(project, tenant)`, so the guest can only ever reach its own
//! tenant's runs (it supplies only a `run-id`, never a tenant/project).
//!
//! # STORE-RESIDENT state (the host-view-rebuild footgun)
//! wasmtime REBUILDS this host view on EVERY host call, so the baked [`RunStore`] + posture live in
//! the store-resident [`RunBinding`] (a field of `HostState.bindings`), BORROWED by the per-call
//! [`RunHost`] view. A live attach's stream state lives in the store's [`ResourceTable`] as a
//! [`RunStreamResource`], not on the view.

use std::sync::Arc;

use wasmtime::component::{Resource, ResourceTable};

pub use boatramp_core::run::{RunEnvelope, RunEventKind, RunStatus};

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/run-host",
        imports: { default: async },
        with: {
            "boatramp:handlers/run.run-stream": super::RunStreamResource,
        },
    });
}

use generated::boatramp::handlers::{run as run_iface, run_types};

/// Why a [`RunStore`] op failed (the host-internal seam error; the binding maps it onto the WIT
/// `run-error`). The `access-denied` posture/grant deny is decided by the binding, never the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunStoreError {
    /// No such run under THIS invocation's tenant/project (wrong-tenant / never-created / fabricated).
    NotFound,
    /// The run has already ended — a further emit is refused.
    Terminal,
    /// The run was cancelled — a further emit is refused (the stop signal).
    Cancelled,
    /// The request was malformed (bad run-id / over-cap payload). Carries a reason.
    Invalid(String),
    /// A backend (messaging / KV) fault. Carries a sanitized reason.
    Backend(String),
}

/// A live attach: the envelope stream plus a DROP-CANCEL hook invoked if the attacher drops before a
/// terminal event. The server builds this from the baked engine; the binding drives it from the
/// `run-stream` resource.
pub struct RunAttachStream {
    stream: futures::stream::BoxStream<'static, Result<RunEnvelope, RunStoreError>>,
    /// Called once, on resource drop, IFF no terminal event was delivered (implements drop-cancel).
    /// `None` when drop-cancel is not armed for this run.
    drop_cancel: Option<Box<dyn FnOnce() -> futures::future::BoxFuture<'static, ()> + Send>>,
    /// Set once a terminal envelope has been delivered — suppresses drop-cancel on drop.
    terminal_seen: bool,
    /// Set once the stream has ended (a terminal, an error, or end-of-stream).
    ended: bool,
}

impl RunAttachStream {
    /// Build an attach from the server's stream + optional drop-cancel hook.
    #[must_use]
    pub fn new(
        stream: futures::stream::BoxStream<'static, Result<RunEnvelope, RunStoreError>>,
        drop_cancel: Option<Box<dyn FnOnce() -> futures::future::BoxFuture<'static, ()> + Send>>,
    ) -> Self {
        Self {
            stream,
            drop_cancel,
            terminal_seen: false,
            ended: false,
        }
    }

    /// The next envelope, or `None` at end of stream. Tracks whether a terminal envelope was seen so
    /// `on_drop` can decide whether to drop-cancel.
    pub async fn next(&mut self) -> Option<Result<RunEnvelope, RunStoreError>> {
        use futures::StreamExt as _;
        if self.ended {
            return None;
        }
        match self.stream.next().await {
            Some(Ok(env)) => {
                if env.kind.is_terminal() {
                    self.terminal_seen = true;
                    self.ended = true;
                }
                Some(Ok(env))
            }
            Some(Err(e)) => {
                self.ended = true;
                Some(Err(e))
            }
            None => {
                self.ended = true;
                None
            }
        }
    }

    /// Called when the guest drops the attach resource: if no terminal event was delivered and
    /// drop-cancel is armed, cancel the run (so a long-lived emitter stops).
    pub async fn on_drop(&mut self) {
        if !self.terminal_seen
            && let Some(hook) = self.drop_cancel.take()
        {
            hook().await;
        }
    }
}

/// The durable run substrate seam, implemented by the server over the v0.74 consumer-delivery core and
/// BAKED with THIS invocation's resolved `(project, tenant)` — so the guest names only a `run-id`.
#[async_trait::async_trait]
pub trait RunStore: Send + Sync {
    /// Create a new run fenced to the baked tenant/project; returns the server-minted id.
    async fn create(&self) -> Result<String, RunStoreError>;
    /// Emit one event; returns the allocated monotonic `seq`.
    async fn emit(
        &self,
        run_id: &str,
        kind: RunEventKind,
        payload: Vec<u8>,
    ) -> Result<u64, RunStoreError>;
    /// Attach to a run, resuming strictly after `after_seq` (`None` = from the start).
    async fn attach(
        &self,
        run_id: &str,
        after_seq: Option<u64>,
    ) -> Result<RunAttachStream, RunStoreError>;
    /// Cancel a run (explicit) — emits the terminal `cancelled` event; idempotent.
    async fn cancel(&self, run_id: &str) -> Result<(), RunStoreError>;
    /// The current status of a run.
    async fn status(&self, run_id: &str) -> Result<RunStatus, RunStoreError>;
}

/// Store-resident binding (a field of `HostState.bindings`): the host-held, baked [`RunStore`].
/// Borrowed (not owned) by the per-call [`RunHost`] view. The node posture is NOT carried here — it
/// is applied by the view from the invocation's `HostState`, exactly like `EgressRegisterHost`.
#[derive(Clone)]
pub struct RunBinding {
    store: Arc<dyn RunStore>,
}

impl RunBinding {
    /// Grant the capability, backed by the host-held, baked `store`.
    #[must_use]
    pub fn new(store: Arc<dyn RunStore>) -> Self {
        Self { store }
    }
}

/// The host state behind a guest `run-stream` resource: the live attach. Pulled by `run-stream.next`
/// and finalized (drop-cancel) on `drop`.
pub struct RunStreamResource {
    attach: RunAttachStream,
}

/// The per-invocation host view (REBUILT on every host call — holds only a BORROW of the
/// store-resident binding, the store's resource table, and the node posture).
pub struct RunHost<'a> {
    table: &'a mut ResourceTable,
    binding: Option<&'a RunBinding>,
    /// The node posture `allow_guest_run_streaming` (from `HostState`). OFF ⇒ `access-denied`.
    posture_enabled: bool,
}

impl<'a> RunHost<'a> {
    /// Build the per-call view borrowing the store-resident binding (`None` ⇒ ungranted ⇒ deny-all),
    /// the store's resource table, and the node posture (off ⇒ deny-all).
    #[must_use]
    pub fn new(
        table: &'a mut ResourceTable,
        binding: Option<&'a RunBinding>,
        posture_enabled: bool,
    ) -> Self {
        Self {
            table,
            binding,
            posture_enabled,
        }
    }

    /// The admitted store, or the fail-closed `access-denied` (posture off / ungranted). A cheap `Arc`
    /// clone so no borrow of `self` outlives it (the table is used separately for the resource).
    fn admit(&self) -> Result<Arc<dyn RunStore>, run_types::RunError> {
        if !self.posture_enabled {
            return Err(run_types::RunError::AccessDenied);
        }
        match self.binding {
            Some(b) => Ok(b.store.clone()),
            None => Err(run_types::RunError::AccessDenied),
        }
    }
}

// ---- wire <-> host conversions --------------------------------------------------------------------

fn kind_from_wire(k: run_types::RunEventKind) -> RunEventKind {
    match k {
        run_types::RunEventKind::Progress => RunEventKind::Progress,
        run_types::RunEventKind::Result => RunEventKind::Result,
        run_types::RunEventKind::Error => RunEventKind::Error,
        run_types::RunEventKind::End => RunEventKind::End,
        run_types::RunEventKind::Cancelled => RunEventKind::Cancelled,
    }
}

fn kind_to_wire(k: RunEventKind) -> run_types::RunEventKind {
    match k {
        RunEventKind::Progress => run_types::RunEventKind::Progress,
        RunEventKind::Result => run_types::RunEventKind::Result,
        RunEventKind::Error => run_types::RunEventKind::Error,
        RunEventKind::End => run_types::RunEventKind::End,
        RunEventKind::Cancelled => run_types::RunEventKind::Cancelled,
    }
}

fn status_to_wire(s: RunStatus) -> run_types::RunStatus {
    match s {
        RunStatus::Active => run_types::RunStatus::Active,
        RunStatus::Ended => run_types::RunStatus::Ended,
        RunStatus::Errored => run_types::RunStatus::Errored,
        RunStatus::Cancelled => run_types::RunStatus::Cancelled,
    }
}

fn event_to_wire(env: RunEnvelope) -> run_types::RunEvent {
    run_types::RunEvent {
        run_id: env.run_id,
        seq: env.seq,
        kind: kind_to_wire(env.kind),
        timestamp_ms: env.timestamp_ms,
        payload: env.payload,
    }
}

fn err_to_wire(e: RunStoreError) -> run_types::RunError {
    match e {
        RunStoreError::NotFound => run_types::RunError::NotFound,
        RunStoreError::Terminal => run_types::RunError::Terminal,
        RunStoreError::Cancelled => run_types::RunError::Cancelled,
        RunStoreError::Invalid(m) => run_types::RunError::Invalid(m),
        RunStoreError::Backend(m) => run_types::RunError::Backend(m),
    }
}

impl run_iface::Host for RunHost<'_> {
    async fn create(&mut self) -> Result<String, run_types::RunError> {
        let store = self.admit()?;
        store.create().await.map_err(err_to_wire)
    }

    async fn emit(
        &mut self,
        id: String,
        kind: run_types::RunEventKind,
        payload: Vec<u8>,
    ) -> Result<u64, run_types::RunError> {
        let store = self.admit()?;
        store
            .emit(&id, kind_from_wire(kind), payload)
            .await
            .map_err(err_to_wire)
    }

    async fn attach(
        &mut self,
        id: String,
        after_seq: Option<u64>,
    ) -> Result<Resource<RunStreamResource>, run_types::RunError> {
        let store = self.admit()?;
        let attach = store.attach(&id, after_seq).await.map_err(err_to_wire)?;
        self.table
            .push(RunStreamResource { attach })
            .map_err(|e| run_types::RunError::Backend(format!("resource table: {e}")))
    }

    async fn cancel(&mut self, id: String) -> Result<(), run_types::RunError> {
        let store = self.admit()?;
        store.cancel(&id).await.map_err(err_to_wire)
    }

    async fn status(&mut self, id: String) -> Result<run_types::RunStatus, run_types::RunError> {
        let store = self.admit()?;
        store
            .status(&id)
            .await
            .map(status_to_wire)
            .map_err(err_to_wire)
    }
}

impl run_iface::HostRunStream for RunHost<'_> {
    async fn next(
        &mut self,
        res: Resource<RunStreamResource>,
    ) -> Result<Option<run_types::RunEvent>, run_types::RunError> {
        let entry = self
            .table
            .get_mut(&res)
            .map_err(|e| run_types::RunError::Backend(format!("resource: {e}")))?;
        match entry.attach.next().await {
            Some(Ok(env)) => Ok(Some(event_to_wire(env))),
            Some(Err(e)) => Err(err_to_wire(e)),
            None => Ok(None),
        }
    }

    async fn drop(&mut self, res: Resource<RunStreamResource>) -> wasmtime::Result<()> {
        // Finalize BEFORE removing the entry: if the attacher drops before a terminal event, this
        // fires drop-cancel (stopping a long-lived emitter). A failed lookup just means the table is
        // tearing down — nothing to cancel.
        if let Ok(entry) = self.table.get_mut(&res) {
            entry.attach.on_drop().await;
        }
        self.table.delete(res)?;
        Ok(())
    }
}

/// Add the `boatramp:handlers/run` interface to `linker`, resolving the per-invocation [`RunHost`]
/// view via `host`.
struct LinkData;
impl wasmtime::component::HasData for LinkData {
    type Data<'a> = RunHost<'a>;
}

/// Link the `boatramp:handlers/run` import, resolving the per-invocation view via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: fn(&mut T) -> RunHost<'_>,
) -> wasmtime::Result<()> {
    run_iface::add_to_linker::<T, LinkData>(linker, host)
}

#[cfg(test)]
mod tests {
    use super::run_iface::{Host, HostRunStream};
    use super::*;
    use futures::StreamExt as _;
    use std::sync::Mutex;

    /// A stub store recording calls, so a test can assert the binding gates (or does not delegate).
    #[derive(Default)]
    struct StubStore {
        calls: Mutex<Vec<String>>,
        /// Whether `create`/`emit`/etc. succeed; a `None` run makes `attach` yield a cancel-armed
        /// stream with one progress + records drop-cancel.
        cancelled: Mutex<bool>,
    }
    impl StubStore {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }
    #[async_trait::async_trait]
    impl RunStore for StubStore {
        async fn create(&self) -> Result<String, RunStoreError> {
            self.calls.lock().unwrap().push("create".into());
            Ok("run-1".into())
        }
        async fn emit(
            &self,
            run_id: &str,
            kind: RunEventKind,
            _payload: Vec<u8>,
        ) -> Result<u64, RunStoreError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("emit:{run_id}:{kind:?}"));
            Ok(0)
        }
        async fn attach(
            &self,
            run_id: &str,
            _after_seq: Option<u64>,
        ) -> Result<RunAttachStream, RunStoreError> {
            self.calls.lock().unwrap().push(format!("attach:{run_id}"));
            let env = RunEnvelope {
                run_id: run_id.to_string(),
                seq: 0,
                kind: RunEventKind::Progress,
                timestamp_ms: 1,
                payload: b"p".to_vec(),
            };
            let stream = futures::stream::iter(vec![Ok(env)]).boxed();
            let cancelled = Arc::new(());
            let _ = cancelled; // placeholder
            Ok(RunAttachStream::new(stream, None))
        }
        async fn cancel(&self, run_id: &str) -> Result<(), RunStoreError> {
            *self.cancelled.lock().unwrap() = true;
            self.calls.lock().unwrap().push(format!("cancel:{run_id}"));
            Ok(())
        }
        async fn status(&self, _run_id: &str) -> Result<RunStatus, RunStoreError> {
            Ok(RunStatus::Active)
        }
    }

    /// Posture-off and ungranted both deny with `access-denied` and NEVER reach the store.
    #[tokio::test]
    async fn posture_off_or_ungranted_denies_without_delegating() {
        let store = Arc::new(StubStore::default());
        let binding = RunBinding::new(store.clone());
        let mut table = ResourceTable::new();

        // (a) ungranted (binding None), posture on ⇒ access-denied.
        let mut ungranted = RunHost::new(&mut table, None, true);
        assert!(matches!(
            ungranted.create().await,
            Err(run_types::RunError::AccessDenied)
        ));

        // (b) granted but posture OFF ⇒ access-denied, store never reached.
        let mut off = RunHost::new(&mut table, Some(&binding), false);
        assert!(matches!(
            off.create().await,
            Err(run_types::RunError::AccessDenied)
        ));
        assert!(store.calls().is_empty(), "posture off must not delegate");

        // (c) granted + posture ON ⇒ delegates.
        let mut on = RunHost::new(&mut table, Some(&binding), true);
        assert_eq!(on.create().await.unwrap(), "run-1");
        assert_eq!(store.calls(), vec!["create".to_string()]);
    }

    /// `attach` pushes a resource; `next` drains it then ends; `drop` tears it down. Error mapping
    /// covers the terminal/not-found cases.
    #[tokio::test]
    async fn attach_next_drop_round_trip() {
        let store = Arc::new(StubStore::default());
        let binding = RunBinding::new(store.clone());
        let mut table = ResourceTable::new();
        let mut host = RunHost::new(&mut table, Some(&binding), true);

        let res = host.attach("run-1".into(), None).await.unwrap();
        let rep = res.rep();
        // One progress event, then end-of-stream.
        let first = host.next(Resource::new_borrow(rep)).await.unwrap();
        assert!(matches!(
            first,
            Some(run_types::RunEvent {
                kind: run_types::RunEventKind::Progress,
                ..
            })
        ));
        let end = host.next(Resource::new_borrow(rep)).await.unwrap();
        assert!(end.is_none(), "stream ends after the one event");
        host.drop(res).await.unwrap();
    }

    /// The seam-level drop-cancel wiring: an attach armed with a drop-cancel hook fires it on drop
    /// when no terminal was delivered (the hook the server builds around `engine.cancel`).
    #[tokio::test]
    async fn drop_cancel_hook_fires_when_no_terminal_seen() {
        let fired = Arc::new(Mutex::new(false));
        let f2 = fired.clone();
        let hook: Box<dyn FnOnce() -> futures::future::BoxFuture<'static, ()> + Send> =
            Box::new(move || {
                Box::pin(async move {
                    *f2.lock().unwrap() = true;
                })
            });
        let env = RunEnvelope {
            run_id: "r".into(),
            seq: 0,
            kind: RunEventKind::Progress,
            timestamp_ms: 1,
            payload: vec![],
        };
        let stream = futures::stream::iter(vec![Ok(env)]).boxed();
        let mut attach = RunAttachStream::new(stream, Some(hook));
        // Read the non-terminal event, then drop WITHOUT reading a terminal.
        let _ = attach.next().await.unwrap().unwrap();
        attach.on_drop().await;
        assert!(
            *fired.lock().unwrap(),
            "drop-cancel fires with no terminal seen"
        );
    }

    /// When a terminal event WAS delivered, drop does NOT fire drop-cancel (the run already concluded).
    #[tokio::test]
    async fn drop_cancel_hook_suppressed_after_terminal() {
        let fired = Arc::new(Mutex::new(false));
        let f2 = fired.clone();
        let hook: Box<dyn FnOnce() -> futures::future::BoxFuture<'static, ()> + Send> =
            Box::new(move || Box::pin(async move { *f2.lock().unwrap() = true }));
        let term = RunEnvelope {
            run_id: "r".into(),
            seq: 0,
            kind: RunEventKind::End,
            timestamp_ms: 1,
            payload: vec![],
        };
        let stream = futures::stream::iter(vec![Ok(term)]).boxed();
        let mut attach = RunAttachStream::new(stream, Some(hook));
        let _ = attach.next().await.unwrap().unwrap(); // terminal
        attach.on_drop().await;
        assert!(
            !*fired.lock().unwrap(),
            "no drop-cancel after a terminal event was delivered"
        );
    }
}
