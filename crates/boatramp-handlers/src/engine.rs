//! The wasmtime component engine: compile (cached by blob hash), instantiate
//! per request, drive `wasi:http/incoming-handler`, and enforce limits.

use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body as HttpBody, Frame};
use lru::LruCache;
use tokio::sync::Semaphore;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{IoView, WasiCtx, WasiCtxBuilder, WasiView};
use wasmtime_wasi_http::bindings::http::types::{ErrorCode, Scheme};
use wasmtime_wasi_http::bindings::ProxyPre;
use wasmtime_wasi_http::body::{HostIncomingBody, HyperIncomingBody, HyperOutgoingBody};
use wasmtime_wasi_http::types::HostIncomingRequest;
use wasmtime_wasi_http::{WasiHttpCtx, WasiHttpView};

use crate::bindings::{self, Bindings};

/// Generated bindings for the **consumer** world (`wasi:messaging` incoming
/// handler): imports the producer (host-provided) and exports `handle`, which
/// the dispatcher calls once per delivered message.
#[cfg(feature = "messaging")]
mod consumer_world {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/consumer",
        async: true,
    });
}

/// The shared wasmtime [`Config`] for handler execution: component model, async,
/// epoch interruption (the per-invocation wall-clock timeout), fuel consumption
/// (the per-handler **CPU** bound — an instruction-count
/// budget deterministic regardless of host load, unlike the wall-clock epoch),
/// and a **persisted compile cache** so a component's compiled artifact
/// survives a restart and the first request after a cold start skips
/// recompilation. The cache is best-effort: a missing config file or an
/// unwritable cache dir degrades to no caching rather than failing.
fn base_config() -> Result<Config, HandlerError> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.async_support(true);
    config.epoch_interruption(true);
    config.consume_fuel(true);
    // Enable the on-disk compilation cache at wasmtime's default location.
    // `cache_config_load_default` treats a missing config file as "use the
    // default enabled cache", and cache writes are themselves best-effort.
    config.cache_config_load_default()?;
    Ok(config)
}

/// Build the shared engine with the default **on-demand** instance allocator.
pub fn build_engine() -> Result<Engine, HandlerError> {
    Ok(Engine::new(&base_config()?)?)
}

/// Build the engine with the **pooling** instance allocator (H8, opt-in): it
/// pre-reserves instance slots so instantiation avoids per-call mmap/setup.
/// Sized generously against `limits` (the engine ceiling) — the pool's per-memory
/// max matches the memory ceiling and the slot counts scale with the concurrency
/// cap, so a clamped invocation always fits. Pooling reserves a large block of
/// virtual address space up front (≈ `memory_bytes × total_memories`), so it is
/// a tuning choice an operator opts into and benchmarks for their workload.
pub fn build_engine_pooling(limits: &Limits) -> Result<Engine, HandlerError> {
    use wasmtime::{InstanceAllocationStrategy, PoolingAllocationConfig};
    let mut config = base_config()?;
    // Headroom over the concurrency cap: a single component instantiates several
    // core instances + memories (WASI + the capability worlds).
    let concurrency = limits.max_concurrency.max(1) as u32;
    let mut pool = PoolingAllocationConfig::default();
    pool.max_memory_size(limits.memory_bytes.max(1));
    pool.total_memories(concurrency.saturating_mul(8).max(16));
    pool.total_tables(concurrency.saturating_mul(8).max(16));
    pool.total_core_instances(concurrency.saturating_mul(8).max(16));
    pool.total_stacks(concurrency.max(1));
    pool.max_memories_per_component(8);
    pool.max_core_instances_per_component(32);
    config.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));
    Ok(Engine::new(&config)?)
}

/// Per-invocation resource limits (capped by site config upstream).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Max linear memory per instance, bytes.
    pub memory_bytes: usize,
    /// Wall-clock timeout per invocation, milliseconds.
    pub timeout_ms: u64,
    /// Max concurrent in-flight invocations across the engine.
    pub max_concurrency: usize,
    /// CPU budget per invocation in wasmtime **fuel** units (`None` = unmetered).
    /// Fuel is an instruction-count proxy: when it runs out the guest traps
    /// ([`HandlerError::OutOfFuel`]), giving a deterministic CPU bound on top of
    /// the wall-clock timeout.
    pub fuel: Option<u64>,
    /// Max request body bytes streamed into the guest (`None` = unbounded). The
    /// body is **streamed** (not buffered); this caps the running total and
    /// errors the body if exceeded, so a large upload never has to be buffered
    /// to be bounded.
    pub max_body_bytes: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            memory_bytes: 64 * 1024 * 1024,
            timeout_ms: 10_000,
            max_concurrency: 64,
            fuel: None,
            // Preserve the historical 16 MiB request-body cap (now enforced
            // streaming, not by pre-buffering).
            max_body_bytes: Some(16 * 1024 * 1024),
        }
    }
}

/// Epoch ticks happen every this many milliseconds; the store deadline is
/// `timeout_ms / EPOCH_TICK_MS` ticks.
const EPOCH_TICK_MS: u64 = 10;

/// Outcome of a failed invocation.
#[derive(Debug)]
pub enum HandlerError {
    /// The component could not be compiled/instantiated.
    Compile(String),
    /// The guest trapped (panic, unreachable, bad host call).
    Trap(String),
    /// The guest exceeded its wall-clock budget.
    Timeout,
    /// The guest exhausted its CPU **fuel** budget.
    OutOfFuel,
    /// The engine is at its concurrency limit.
    Overloaded,
    /// The guest returned without producing a response.
    NoResponse,
    /// An internal engine error.
    Internal(String),
}

impl From<wasmtime::Error> for HandlerError {
    /// wasmtime setup errors (engine/linker/config) are engine-internal.
    /// Component-compile failures are mapped to [`HandlerError::Compile`]
    /// explicitly at the call site instead.
    fn from(err: wasmtime::Error) -> Self {
        HandlerError::Internal(err.to_string())
    }
}

impl std::fmt::Display for HandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandlerError::Compile(m) => write!(f, "component compile error: {m}"),
            HandlerError::Trap(m) => write!(f, "handler trapped: {m}"),
            HandlerError::Timeout => write!(f, "handler timed out"),
            HandlerError::OutOfFuel => write!(f, "handler exhausted its CPU fuel budget"),
            HandlerError::Overloaded => write!(f, "handler engine at capacity"),
            HandlerError::NoResponse => write!(f, "handler produced no response"),
            HandlerError::Internal(m) => write!(f, "handler engine error: {m}"),
        }
    }
}

impl std::error::Error for HandlerError {}

/// Per-store host state: the WASI + WASI-HTTP contexts, the resource table, the
/// memory limiter, and the per-site capability bindings (kv/blob/sql) this
/// invocation was granted.
struct HostState {
    table: ResourceTable,
    wasi: WasiCtx,
    http: WasiHttpCtx,
    limits: StoreLimits,
    bindings: Bindings,
    /// The invocation's SQL transaction state (begun lazily on first query).
    #[cfg(feature = "sql")]
    sql: bindings::sql::SqlSession,
}

impl IoView for HostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
}
impl WasiView for HostState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
}
impl WasiHttpView for HostState {
    fn ctx(&mut self) -> &mut WasiHttpCtx {
        &mut self.http
    }

    /// SSRF egress guard for **guest** outbound HTTP: before
    /// sending, resolve the destination and refuse it if any resolved address is
    /// not globally routable (loopback / private / link-local / CGNAT / the
    /// cloud-metadata IP). An adversarial guest therefore cannot reach internal
    /// infrastructure via `wasi:http`; public destinations pass through to the
    /// default sender. (The operator-config `proxy` rewrite has its own,
    /// IP-pinning guard in the server.)
    fn send_request(
        &mut self,
        request: http::Request<wasmtime_wasi_http::body::HyperOutgoingBody>,
        config: wasmtime_wasi_http::types::OutgoingRequestConfig,
    ) -> wasmtime_wasi_http::HttpResult<wasmtime_wasi_http::types::HostFutureIncomingResponse> {
        let use_tls = config.use_tls;
        let handle = wasmtime_wasi::runtime::spawn(async move {
            let result = match egress_target_allowed(request.uri(), use_tls).await {
                Ok(()) => {
                    wasmtime_wasi_http::types::default_send_request_handler(request, config).await
                }
                Err(code) => Err(code),
            };
            Ok(result)
        });
        Ok(wasmtime_wasi_http::types::HostFutureIncomingResponse::pending(handle))
    }
}

/// Resolve `uri`'s host and require every address be globally routable, so a
/// guest's `wasi:http` request can't target internal infrastructure (SSRF).
async fn egress_target_allowed(
    uri: &http::Uri,
    use_tls: bool,
) -> Result<(), wasmtime_wasi_http::bindings::http::types::ErrorCode> {
    use wasmtime_wasi_http::bindings::http::types::ErrorCode;
    let authority = uri.authority().ok_or(ErrorCode::HttpRequestUriInvalid)?;
    let port = authority
        .port_u16()
        .unwrap_or(if use_tls { 443 } else { 80 });
    // `Authority::host` keeps the brackets on an IPv6 literal (`[::1]`), which
    // `lookup_host` won't parse — strip them.
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| ErrorCode::DestinationNotFound)?;
    let mut saw_any = false;
    for addr in addrs.by_ref() {
        saw_any = true;
        if !boatramp_core::access::is_global_ip(addr.ip()) {
            return Err(ErrorCode::DestinationIpProhibited);
        }
    }
    if saw_any {
        Ok(())
    } else {
        Err(ErrorCode::DestinationNotFound)
    }
}

/// The handler engine: a wasmtime [`Engine`], a blob-hash-keyed cache of
/// compiled+pre-instantiated components, the limit policy, and a concurrency
/// gate. A background task ticks the engine epoch for timeouts.
pub struct HandlerEngine {
    engine: Engine,
    cache: Mutex<LruCache<String, ProxyPre<HostState>>>,
    /// Separate compile cache for consumer (`wasi:messaging`) components — a
    /// different world (`handle` export) than the request `ProxyPre`.
    #[cfg(feature = "messaging")]
    consumer_cache: Mutex<LruCache<String, consumer_world::ConsumerPre<HostState>>>,
    limits: Limits,
    semaphore: Semaphore,
    epoch_ticker: tokio::task::JoinHandle<()>,
}

impl Drop for HandlerEngine {
    fn drop(&mut self) {
        self.epoch_ticker.abort();
    }
}

impl HandlerEngine {
    /// Build the engine with `limits`, caching up to `cache_size` compiled
    /// components. Uses the default on-demand instance allocator.
    pub fn new(limits: Limits, cache_size: usize) -> Result<Self, HandlerError> {
        Self::from_engine(build_engine()?, limits, cache_size)
    }

    /// Like [`new`](Self::new) but with the **pooling** instance allocator (H8,
    /// opt-in): instances come from a pre-reserved pool, so instantiation skips
    /// per-call allocation. The pool is sized against `limits`; reserves a large
    /// block of virtual memory up front (see [`build_engine_pooling`]).
    pub fn with_pooling(limits: Limits, cache_size: usize) -> Result<Self, HandlerError> {
        Self::from_engine(build_engine_pooling(&limits)?, limits, cache_size)
    }

    /// Assemble the engine around an already-built wasmtime [`Engine`] (shared by
    /// [`new`](Self::new) and [`with_pooling`](Self::with_pooling)).
    fn from_engine(
        engine: Engine,
        limits: Limits,
        cache_size: usize,
    ) -> Result<Self, HandlerError> {
        let capacity = NonZeroUsize::new(cache_size.max(1)).expect("cache size >= 1");
        let cache = Mutex::new(LruCache::new(capacity));
        // Tick the epoch so store deadlines fire (timeouts).
        let ticker_engine = engine.clone();
        let epoch_ticker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(EPOCH_TICK_MS));
            loop {
                interval.tick().await;
                ticker_engine.increment_epoch();
            }
        });
        Ok(Self {
            engine,
            cache,
            #[cfg(feature = "messaging")]
            consumer_cache: Mutex::new(LruCache::new(capacity)),
            semaphore: Semaphore::new(limits.max_concurrency.max(1)),
            limits,
            epoch_ticker,
        })
    }

    /// Compile (and cache) a component without serving it — the activation
    /// pre-warm + compile gate. The server calls this for
    /// every component of a deployment before flipping the `current` pointer, so
    /// a deploy with a component that fails to compile never goes live. Also
    /// warms the compilation cache so the first real request is fast.
    pub fn precompile(&self, hash: &str, wasm: &[u8]) -> Result<(), HandlerError> {
        self.proxy_pre(hash, wasm).map(|_| ())
    }

    /// Compile a component (cached by `hash`) into a reusable [`ProxyPre`].
    fn proxy_pre(&self, hash: &str, wasm: &[u8]) -> Result<ProxyPre<HostState>, HandlerError> {
        if let Some(pre) = self.cache.lock().unwrap().get(hash) {
            return Ok(pre.clone());
        }
        let pre = self.compile(wasm)?;
        self.cache
            .lock()
            .unwrap()
            .put(hash.to_string(), pre.clone());
        Ok(pre)
    }

    /// Compile a consumer component (cached by `hash`) into a reusable
    /// [`ConsumerPre`](consumer_world::ConsumerPre).
    #[cfg(feature = "messaging")]
    fn consumer_pre(
        &self,
        hash: &str,
        wasm: &[u8],
    ) -> Result<consumer_world::ConsumerPre<HostState>, HandlerError> {
        if let Some(pre) = self.consumer_cache.lock().unwrap().get(hash) {
            return Ok(pre.clone());
        }
        let component = Component::from_binary(&self.engine, wasm)
            .map_err(|err| HandlerError::Compile(err.to_string()))?;
        let instance_pre = self
            .build_linker()?
            .instantiate_pre(&component)
            .map_err(|err| HandlerError::Compile(err.to_string()))?;
        let pre = consumer_world::ConsumerPre::new(instance_pre).map_err(|_| {
            HandlerError::Compile("component is not a wasi:messaging consumer".into())
        })?;
        self.consumer_cache
            .lock()
            .unwrap()
            .put(hash.to_string(), pre.clone());
        Ok(pre)
    }

    /// Deliver one message to a **consumer** component (`hash`): instantiate the
    /// consumer world and call its exported `handle` once, under the same limits
    /// regime as a request (epoch timeout, memory limiter, concurrency gate).
    ///
    /// `Ok(())` means the guest handled it (the dispatcher acks). An `Err` —
    /// the guest returned an error, trapped, or timed out — means the message
    /// should be retried (and eventually dead-lettered).
    #[cfg(feature = "messaging")]
    pub async fn dispatch_message(
        &self,
        hash: &str,
        wasm: &[u8],
        topic: &str,
        data: &[u8],
        bindings: Bindings,
        limits: Limits,
    ) -> Result<(), HandlerError> {
        let _permit = self
            .semaphore
            .try_acquire()
            .map_err(|_| HandlerError::Overloaded)?;
        let consumer_pre = self.consumer_pre(hash, wasm)?;
        let mut store = self.new_store(bindings, self.effective_limits(limits));
        let consumer = consumer_pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| classify(&e))?;
        let message = consumer_world::boatramp::handlers::messaging_types::Message {
            topic: topic.to_string(),
            data: data.to_vec(),
        };
        let result = consumer
            .boatramp_handlers_messaging_handler()
            .call_handle(&mut store, &message)
            .await;
        // Close any per-invocation SQL transaction: commit only if the consumer
        // handled the message cleanly.
        #[cfg(feature = "sql")]
        store
            .data_mut()
            .sql
            .finalize(matches!(result, Ok(Ok(()))))
            .await;
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(HandlerError::Trap(format!(
                "consumer returned error: {err:?}"
            ))),
            Err(trap) => Err(classify(&trap)),
        }
    }

    fn compile(&self, wasm: &[u8]) -> Result<ProxyPre<HostState>, HandlerError> {
        let component = Component::from_binary(&self.engine, wasm)
            .map_err(|err| HandlerError::Compile(err.to_string()))?;
        let instance_pre = self
            .build_linker()?
            .instantiate_pre(&component)
            .map_err(|err| HandlerError::Compile(err.to_string()))?;
        ProxyPre::new(instance_pre)
            .map_err(|_| HandlerError::Compile("component is not a wasi:http/proxy handler".into()))
    }

    /// A linker with WASI + the capability interfaces. They are always linked;
    /// whether a handler can actually use one is decided per invocation by the
    /// bindings it was granted (an ungranted capability fails `access-denied`).
    /// Shared by the request (`wasi:http`) and consumer (`wasi:messaging`) paths.
    fn build_linker(&self) -> Result<Linker<HostState>, HandlerError> {
        let mut linker = Linker::<HostState>::new(&self.engine);
        wasmtime_wasi::add_to_linker_async(&mut linker)?;
        wasmtime_wasi_http::add_only_http_to_linker_async(&mut linker)?;
        bindings::keyvalue::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::keyvalue::KvHost::new(&mut state.table, state.bindings.keyvalue())
        })?;
        bindings::blobstore::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::blobstore::BlobHost::new(&mut state.table, state.bindings.blobstore())
        })?;
        #[cfg(feature = "sql")]
        bindings::sql::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::sql::SqlHost::new(&mut state.table, &mut state.sql)
        })?;
        #[cfg(feature = "messaging")]
        bindings::messaging::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::messaging::MessagingHost::new(state.bindings.messaging())
        })?;
        Ok(linker)
    }

    /// Clamp `requested` to the engine's configured ceiling — a per-invocation
    /// (per-site) override may only *lower* the limits, never raise them.
    fn effective_limits(&self, requested: Limits) -> Limits {
        Limits {
            memory_bytes: requested.memory_bytes.min(self.limits.memory_bytes),
            timeout_ms: requested.timeout_ms.min(self.limits.timeout_ms),
            max_concurrency: requested.max_concurrency.min(self.limits.max_concurrency),
            // A `None` (unmetered) on either side is the larger bound, so the
            // effective fuel is the smaller of any present budgets.
            fuel: min_opt(requested.fuel, self.limits.fuel),
            max_body_bytes: min_opt(requested.max_body_bytes, self.limits.max_body_bytes),
        }
    }

    fn new_store(&self, bindings: Bindings, limits: Limits) -> Store<HostState> {
        // Capture stdout/stderr into the host log sink when granted; otherwise
        // the guest's stdio is inherited (host stdio).
        let mut wasi_builder = WasiCtxBuilder::new();
        if let Some(logging) = bindings.logging() {
            use crate::logging::{LogStream, SinkStdout};
            wasi_builder.stdout(SinkStdout::new(logging, LogStream::Stdout));
            wasi_builder.stderr(SinkStdout::new(logging, LogStream::Stderr));
        }
        // Inject only the granted env (deploy `env` + resolved secrets); the
        // host's own environment is never inherited.
        for (key, value) in bindings.env() {
            wasi_builder.env(key, value);
        }
        let wasi = wasi_builder.build();
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(limits.memory_bytes)
            .build();
        #[cfg(feature = "sql")]
        let sql = bindings::sql::SqlSession::for_backends(bindings.sql());
        let state = HostState {
            table: ResourceTable::new(),
            wasi,
            http: WasiHttpCtx::new(),
            limits: store_limits,
            bindings,
            #[cfg(feature = "sql")]
            sql,
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        // Deadline in epoch ticks; trap when exceeded.
        let ticks = (limits.timeout_ms / EPOCH_TICK_MS).max(1);
        store.set_epoch_deadline(ticks);
        // CPU fuel budget (`None` = unmetered → the maximum, so the guest never
        // traps on fuel). The engine has `consume_fuel` on, so a budget must be
        // set or the guest would trap immediately.
        store
            .set_fuel(limits.fuel.unwrap_or(u64::MAX))
            .expect("fuel is enabled on the engine");
        store
    }

    /// Serve one request through the handler identified by `hash`, granting it
    /// the capabilities in `bindings` (kv/blob/sql, per-site), under the engine's
    /// configured limits. The request body may be any hyper body (the server
    /// passes the live request body through; `empty_body` covers bodyless
    /// requests).
    pub async fn serve<B>(
        &self,
        hash: &str,
        wasm: &[u8],
        request: http::Request<B>,
        bindings: Bindings,
    ) -> Result<http::Response<HyperOutgoingBody>, HandlerError>
    where
        B: HttpBody<Data = Bytes> + Send + 'static,
        B::Error: std::fmt::Display + Send,
    {
        self.serve_with_limits(hash, wasm, request, bindings, self.limits)
            .await
    }

    /// Like [`serve`](Self::serve) but with per-invocation `limits` (e.g. a
    /// site's caps). They are clamped to the engine's configured ceiling — a
    /// site may only lower the memory/timeout, never raise them.
    pub async fn serve_with_limits<B>(
        &self,
        hash: &str,
        wasm: &[u8],
        request: http::Request<B>,
        bindings: Bindings,
        limits: Limits,
    ) -> Result<http::Response<HyperOutgoingBody>, HandlerError>
    where
        B: HttpBody<Data = Bytes> + Send + 'static,
        B::Error: std::fmt::Display + Send,
    {
        let _permit = self
            .semaphore
            .try_acquire()
            .map_err(|_| HandlerError::Overloaded)?;
        let proxy_pre = self.proxy_pre(hash, wasm)?;

        let effective = self.effective_limits(limits);
        let mut store = self.new_store(bindings, effective);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let out = store
            .data_mut()
            .new_response_outparam(sender)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        // Build the incoming request with a **streamed** body:
        // bypass `new_incoming_request`'s `Error = hyper::Error` bound by using the
        // public lower-level pieces directly, feeding our own bridged body whose
        // errors map to `ErrorCode` — so the live request body flows into the
        // guest frame-by-frame instead of being buffered up front.
        let (parts, body) = request.into_parts();
        let incoming = HostIncomingBody::new(
            stream_incoming_body(body, effective.max_body_bytes),
            BODY_FRAME_TIMEOUT,
        );
        let req = {
            let state = store.data_mut();
            let request = HostIncomingRequest::new(state, parts, Scheme::Http, Some(incoming))
                .map_err(|e| HandlerError::Internal(e.to_string()))?;
            state
                .table()
                .push(request)
                .map_err(|e| HandlerError::Internal(e.to_string()))?
        };
        let proxy = proxy_pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| classify(&e))?;

        // Drive the guest on its own task: it may stream the body after setting
        // the response outparam, so the task must outlive the head response.
        let task = tokio::spawn(async move {
            let result = proxy
                .wasi_http_incoming_handler()
                .call_handle(&mut store, req, out)
                .await;
            // Close the per-invocation SQL transaction once the guest is done
            // (after any streamed body): commit on success, roll back otherwise.
            #[cfg(feature = "sql")]
            store.data_mut().sql.finalize(result.is_ok()).await;
            result
        });

        match receiver.await {
            // Guest produced a response head; let `task` keep streaming the body.
            Ok(Ok(response)) => Ok(response),
            // Guest explicitly produced an error response.
            Ok(Err(code)) => Err(HandlerError::Trap(format!("{code:?}"))),
            // Sender dropped before a response — the guest trapped/returned first.
            Err(_) => match task.await {
                Ok(Ok(())) => Err(HandlerError::NoResponse),
                Ok(Err(trap)) => Err(classify(&trap)),
                Err(join) => Err(HandlerError::Internal(join.to_string())),
            },
        }
    }
}

/// An empty request body (for synthetic requests / requests without a body).
pub fn empty_body() -> http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error> {
    Empty::<bytes::Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Per-frame read timeout for an incoming body (wasi-http's own default).
const BODY_FRAME_TIMEOUT: Duration = Duration::from_secs(600);

/// A `Send + Sync` [`HttpBody`] backed by an mpsc receiver — the bridge target
/// for [`stream_incoming_body`]. Holding only the receiver keeps it `Sync` (an
/// arbitrary streaming body, e.g. axum's, may not be), so it boxes into the
/// `Send + Sync` [`HyperIncomingBody`] the wasi-http layer requires.
struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, ErrorCode>>,
}

impl HttpBody for ChannelBody {
    type Data = Bytes;
    type Error = ErrorCode;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, ErrorCode>>> {
        self.rx.poll_recv(cx)
    }
}

/// Bridge an arbitrary request body into a [`HyperIncomingBody`] for the guest,
/// **streaming** frame-by-frame (no up-front buffering) while enforcing a running
/// byte cap. A forwarder task reads `body` (it only needs `Send`, not `Sync`),
/// enforces `max_bytes`, maps any read error or cap breach to an `ErrorCode`, and
/// pushes frames through a channel the `Send + Sync` [`ChannelBody`] drains.
fn stream_incoming_body<B>(body: B, max_bytes: Option<u64>) -> HyperIncomingBody
where
    B: HttpBody<Data = Bytes> + Send + 'static,
    B::Error: std::fmt::Display + Send,
{
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, ErrorCode>>(8);
    tokio::spawn(async move {
        let mut body = std::pin::pin!(body);
        let mut total: u64 = 0;
        while let Some(frame) = body.as_mut().frame().await {
            match frame {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        total = total.saturating_add(data.len() as u64);
                        if max_bytes.is_some_and(|cap| total > cap) {
                            let _ = tx
                                .send(Err(ErrorCode::InternalError(Some(
                                    "request body exceeds the handler limit".to_string(),
                                ))))
                                .await;
                            return;
                        }
                    }
                    if tx.send(Ok(frame)).await.is_err() {
                        return; // guest dropped the body
                    }
                }
                Err(err) => {
                    let _ = tx
                        .send(Err(ErrorCode::InternalError(Some(format!(
                            "request body read error: {err}"
                        )))))
                        .await;
                    return;
                }
            }
        }
    });
    ChannelBody { rx }.boxed()
}

/// Classify a wasmtime execution error: an epoch interrupt is a wall-clock
/// timeout, an out-of-fuel trap is the CPU budget exhausted, anything else is a
/// generic guest trap.
fn classify(err: &wasmtime::Error) -> HandlerError {
    match err.downcast_ref::<wasmtime::Trap>() {
        Some(wasmtime::Trap::Interrupt) => HandlerError::Timeout,
        Some(wasmtime::Trap::OutOfFuel) => HandlerError::OutOfFuel,
        _ => HandlerError::Trap(err.to_string()),
    }
}

/// The smaller of two optional bounds, treating `None` as "no bound" (i.e. the
/// larger). Used to clamp a per-invocation limit to an engine ceiling.
fn min_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) | (None, x) => x,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmtime_wasi_http::bindings::http::types::ErrorCode;

    #[test]
    fn engine_builds() {
        build_engine().expect("engine builds");
    }

    #[tokio::test]
    async fn streams_body_frames_into_an_incoming_body() {
        use http_body_util::StreamBody;
        // A multi-frame source body bridges through to the guest-facing incoming
        // body frame-by-frame (no buffering), preserving the bytes.
        let frames = vec![
            Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from_static(b"hello "))),
            Ok(Frame::data(Bytes::from_static(b"world"))),
        ];
        let body = StreamBody::new(futures::stream::iter(frames));
        let incoming = stream_incoming_body(body, Some(1024));
        let bytes = incoming.collect().await.expect("collect").to_bytes();
        assert_eq!(&bytes[..], b"hello world");
    }

    #[tokio::test]
    async fn streaming_body_errors_when_it_exceeds_the_cap() {
        use http_body_util::StreamBody;
        // Two 100-byte frames against a 150-byte cap: the running total trips the
        // cap on the second frame and the body errors (no full buffering needed).
        let frames = vec![
            Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from(vec![0u8; 100]))),
            Ok(Frame::data(Bytes::from(vec![0u8; 100]))),
        ];
        let body = StreamBody::new(futures::stream::iter(frames));
        let incoming = stream_incoming_body(body, Some(150));
        assert!(
            incoming.collect().await.is_err(),
            "a body over the cap must error rather than deliver truncated data"
        );
    }

    async fn egress(uri: &str, tls: bool) -> Result<(), ErrorCode> {
        egress_target_allowed(&uri.parse().unwrap(), tls).await
    }

    /// The SSRF egress guard refuses guest outbound HTTP to
    /// non-global addresses and allows public ones. IP literals resolve offline,
    /// so this needs no network.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn egress_guard_blocks_internal_allows_public() {
        for blocked in [
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data", // cloud metadata
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "https://[::1]:8443/",
        ] {
            assert!(
                matches!(
                    egress(blocked, blocked.starts_with("https")).await,
                    Err(ErrorCode::DestinationIpProhibited)
                ),
                "{blocked} should be prohibited"
            );
        }
        // A public IP literal is allowed.
        assert!(egress("http://1.1.1.1/", false).await.is_ok());
        // A request with no authority is rejected as an invalid URI.
        assert!(matches!(
            egress("/relative-only", false).await,
            Err(ErrorCode::HttpRequestUriInvalid)
        ));
    }
}
