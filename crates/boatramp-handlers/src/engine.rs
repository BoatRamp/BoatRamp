//! The wasmtime component engine: compile (cached by blob hash), instantiate
//! per request, drive `wasi:http/incoming-handler`, and enforce limits.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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
use wasmtime_wasi_http::bindings::ProxyPre;
use wasmtime_wasi_http::bindings::http::types::{ErrorCode, Scheme};
use wasmtime_wasi_http::body::{HostIncomingBody, HyperIncomingBody, HyperOutgoingBody};
use wasmtime_wasi_http::types::HostIncomingRequest;
use wasmtime_wasi_http::{WasiHttpCtx, WasiHttpView};

use crate::bindings::{self, Bindings};
use crate::concurrency::KeyedSemaphores;

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

// The session-host world: the export caller for `session-handler.handle` (the host re-enters the
// guest per inbound batch, mechanism B). The `session` import it declares is satisfied on the
// linker by `bindings::session::add_to_linker` (a separate bindgen), exactly as the consumer world
// gets `messaging-producer` from `bindings::messaging` — the WIT interface identity matches.
#[cfg(feature = "session")]
mod session_world {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/session-host",
        async: true,
    });
}

/// One re-entry's input for [`HandlerEngine::dispatch_session`]: the session id, the checkpoint to
/// resume from (if any), and the pending inbound frames in order. Frames are opaque bytes.
#[cfg(feature = "session")]
pub struct SessionBatch {
    pub id: String,
    pub resumed: Option<Vec<u8>>,
    pub frames: Vec<Vec<u8>>,
}

/// The shared wasmtime [`Config`] for handler execution: component model, async,
/// epoch interruption (the per-invocation wall-clock timeout), fuel consumption
/// (the per-handler **CPU** bound — an instruction-count
/// budget deterministic regardless of host load, unlike the wall-clock epoch),
/// and a **persisted compile cache** so a component's compiled artifact
/// survives a restart and the first request after a cold start skips
/// recompilation. The cache is best-effort: a missing config file or an
/// unwritable cache dir degrades to no caching rather than failing.
fn base_config(cache_dir: Option<&Path>) -> Result<Config, HandlerError> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.async_support(true);
    config.epoch_interruption(true);
    config.consume_fuel(true);
    configure_compile_cache(&mut config, cache_dir);
    Ok(config)
}

/// Enable wasmtime's on-disk compile cache so a component's compiled artifact survives a restart —
/// the first request after a cold start **deserializes in ms** instead of paying a multi-second
/// cranelift compile. Best-effort throughout: any failure logs a warning and degrades to no caching
/// rather than failing engine construction.
///
/// When `cache_dir` is `Some`, the cache is pinned to `<cache_dir>/wasmtime-cache` on the operator's
/// **persistent data volume**. This matters because wasmtime's default location
/// (`cache_config_load_default`) resolves to `~/.cache/wasmtime` — the *ephemeral container rootfs* on
/// a distroless node — so it is WIPED on every restart/roll, and the first visitor after each deploy
/// then eats the full compile (and, on a small node, a concurrent burst stampedes behind it). `None`
/// (tests, or a caller without a data dir) falls back to that ephemeral default, still best-effort.
fn configure_compile_cache(config: &mut Config, cache_dir: Option<&Path>) {
    // `#[cfg(test)]` severance seam: when forced, ignore the data dir and take the `None` (default,
    // ephemeral) branch even though a dir was threaded — so the durability gate can prove its
    // "cache files land under the data volume" assertion actually depends on this pinning (the
    // mutation makes it land at the default location instead → the gate's data-dir check goes empty).
    #[cfg(test)]
    let cache_dir = if compile_cache_mutation_forces_default() {
        None
    } else {
        cache_dir
    };
    match cache_dir {
        Some(dir) => {
            if let Err(e) = enable_persistent_compile_cache(config, dir) {
                tracing::warn!(
                    target: "boatramp::handler",
                    data_dir = %dir.display(),
                    error = %e,
                    "wasm compile cache could not be pinned to the data volume; serving continues \
                     WITHOUT a persisted cache (components recompile on the first request after each restart)"
                );
            }
        }
        None => {
            // `cache_config_load_default()` itself returns an error when it cannot resolve a default
            // directory (e.g. no `$HOME` on a container) — swallow that rather than failing engine
            // construction, honoring the best-effort contract (the prior code's `?` could hard-fail boot).
            if let Err(e) = config.cache_config_load_default() {
                tracing::debug!(
                    target: "boatramp::handler",
                    error = %e,
                    "wasm compile cache not enabled (no default cache dir resolvable); serving continues uncached"
                );
            }
        }
    }
}

/// Pin the compile cache to `<data_dir>/wasmtime-cache` by generating a wasmtime cache-config TOML at
/// `<data_dir>/wasmtime-cache.toml` and loading it. wasmtime 30's only programmatic cache knob is
/// `cache_config_load(path)` (a TOML file); there is no in-memory `Cache` type until a later release.
/// Returns an error (for the caller to log + degrade) if the dir can't be created or the config can't
/// be written/loaded.
fn enable_persistent_compile_cache(
    config: &mut Config,
    data_dir: &Path,
) -> Result<(), HandlerError> {
    let cache_root = data_dir.join("wasmtime-cache");
    std::fs::create_dir_all(&cache_root)
        .map_err(|e| HandlerError::Internal(format!("create {}: {e}", cache_root.display())))?;
    // Security (defense-in-depth): the cache holds EXECUTABLE native artifacts — a wasmtime cache hit
    // loads compiled host code — so a group/other-writable `/data` must not let another local principal
    // plant a forged artifact (it is not content-MAC'd). Restrict to owner-only, best-effort.
    restrict_perms(&cache_root, 0o700);
    // TOML-basic-string escape the directory (backslash + quote) so a Windows-style or quote-bearing
    // data dir can never produce invalid TOML.
    let escaped = cache_root
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let toml = format!("[cache]\nenabled = true\ndirectory = \"{escaped}\"\n");
    let toml_path = data_dir.join("wasmtime-cache.toml");
    std::fs::write(&toml_path, toml)
        .map_err(|e| HandlerError::Internal(format!("write {}: {e}", toml_path.display())))?;
    restrict_perms(&toml_path, 0o600);
    config
        .cache_config_load(&toml_path)
        .map_err(|e| HandlerError::Internal(format!("load {}: {e}", toml_path.display())))?;
    tracing::info!(
        target: "boatramp::handler",
        cache_dir = %cache_root.display(),
        "wasm compile cache pinned to the persistent data volume (survives restarts)"
    );
    Ok(())
}

/// Best-effort restrict a path to owner-only (`0o700` for the cache dir, `0o600` for its config) on
/// unix. The compile cache holds executable native artifacts, so a loosely-permissioned `/data` must
/// not let another local principal plant one. Best-effort: a failure (unsupported FS, race) is ignored
/// — the worst case is the inherited umask, exactly as before this pinning existed. No-op off unix.
#[cfg(unix)]
fn restrict_perms(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}
#[cfg(not(unix))]
fn restrict_perms(_path: &Path, _mode: u32) {}

/// Build the shared engine with the default **on-demand** instance allocator. `cache_dir` pins the
/// persisted compile cache to the data volume (see [`configure_compile_cache`]); `None` uses the
/// ephemeral default.
pub fn build_engine(cache_dir: Option<&Path>) -> Result<Engine, HandlerError> {
    Ok(Engine::new(&base_config(cache_dir)?)?)
}

#[cfg(test)]
thread_local! {
    /// `#[cfg(test)]`-only severance seam for the compile-cache durability gate: when set, forces
    /// [`configure_compile_cache`] to take the `None` (default, ephemeral) branch even though a data
    /// dir was threaded. The gate's mutation arm flips this to prove that its "cache files land under
    /// the data volume" assertion genuinely depends on the pinning — with the mutation, the files land
    /// at the default location and the data-dir check goes empty. Compiled out of every shipped build.
    static COMPILE_CACHE_FORCE_DEFAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn compile_cache_mutation_forces_default() -> bool {
    COMPILE_CACHE_FORCE_DEFAULT.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn force_compile_cache_default(on: bool) {
    COMPILE_CACHE_FORCE_DEFAULT.with(|c| c.set(on));
}

/// Build the engine with the **pooling** instance allocator (H8, opt-in): it
/// pre-reserves instance slots so instantiation avoids per-call mmap/setup.
/// Sized generously against `limits` (the engine ceiling) — the pool's per-memory
/// max matches the memory ceiling and the slot counts scale with the concurrency
/// cap, so a clamped invocation always fits. Pooling reserves a large block of
/// virtual address space up front (≈ `memory_bytes × total_memories`), so it is
/// a tuning choice an operator opts into and benchmarks for their workload.
pub fn build_engine_pooling(
    limits: &Limits,
    cache_dir: Option<&Path>,
) -> Result<Engine, HandlerError> {
    use wasmtime::{InstanceAllocationStrategy, PoolingAllocationConfig};
    let mut config = base_config(cache_dir)?;
    // Headroom over the concurrency cap: a single component instantiates several
    // core instances + memories (WASI + the capability worlds). `with_pooling_lanes` feeds the
    // SUMMED lane concurrency here (a `usize`), so SATURATE the u32 cast rather than silently
    // truncating an absurd operator value into a smaller-than-estimated pool.
    let concurrency = u32::try_from(limits.max_concurrency.max(1)).unwrap_or(u32::MAX);
    let mut pool = PoolingAllocationConfig::default();
    pool.max_memory_size(limits.memory_bytes.max(1));
    pool.total_memories(concurrency.saturating_mul(8).max(16));
    pool.total_tables(concurrency.saturating_mul(8).max(16));
    pool.total_core_instances(concurrency.saturating_mul(8).max(16));
    // Headroom for the separate async lane's concurrent instances on top of the
    // sync pool, so both lanes at capacity never run out of async stacks.
    pool.total_stacks(concurrency.saturating_mul(2).max(16));
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

/// Which resource lane an invocation runs in. The engine keeps a **separate
/// ceiling and concurrency budget** per lane so the two cannot starve each
/// other:
/// - [`Lane::Sync`] — a connection-bearing request (a site handler or a
///   synchronous function/webhook invoke). A client, proxy, and the shared
///   request pool are all blocked while it runs, so its ceiling stays tight.
/// - [`Lane::Async`] — the durable drain / workflow-step path. No client is
///   connected, the work is retried and dead-lettered, so it can carry a much
///   larger ceiling on its own concurrency budget without touching live traffic.
/// - [`Lane::Streaming`] — a **long-lived, connection-bearing** response (SSE,
///   chunked, agent token streaming). A client *is* connected, but the response
///   is written incrementally over seconds-to-minutes, so it has the resource
///   profile of background work, not a fast request: its own concurrency budget
///   (so a burst of streams can't exhaust the sync request pool, nor starve the
///   durable async drain) and a much larger wall-clock ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// Connection-bearing; tight ceiling; the shared request concurrency pool.
    Sync,
    /// Durable background; large ceiling; an isolated concurrency budget.
    Async,
    /// Connection-bearing but long-lived (streaming responses); its own large
    /// ceiling + concurrency budget, isolated from both `Sync` and `Async`.
    Streaming,
}

/// Per-serve cost returned by [`Engine::serve_lane`], so the server can attribute per-invocation
/// latency (construens ask #3): `cold` is whether this serve paid a cranelift (re)compile vs reused a
/// warm component; `instantiate_us` is the per-invocation `instantiate_async` cost (distinct from the
/// cold compile and from the handler body). The `serve_with_limits*` wrappers discard it; the metered
/// HTTP + function-invoke paths read it onto the `handler invocation` signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeTiming {
    /// This serve paid a cold (re)compile (a warm-cache miss).
    pub cold: bool,
    /// Per-invocation instantiate cost in microseconds.
    pub instantiate_us: u64,
}

/// Epoch ticks happen every this many milliseconds; the store deadline is
/// `timeout_ms / EPOCH_TICK_MS` ticks.
const EPOCH_TICK_MS: u64 = 10;

/// Upper bound (chars) on the guest-returned error text carried by
/// [`HandlerError::ConsumerError`]. The guest controls this string, so it is bounded here before it
/// is stored (and the DLQ layer sanitizes control chars before an operator sees it).
pub const MAX_CONSUMER_ERROR_LEN: usize = 512;

/// Outcome of a failed invocation.
#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    /// The component could not be compiled/instantiated.
    #[error("component compile error: {0}")]
    Compile(String),
    /// The guest trapped (panic, unreachable, bad host call).
    #[error("handler trapped: {0}")]
    Trap(String),
    /// A **consumer returned a clean `Err`** (not a trap): the guest's `handle` completed and
    /// returned an error value — a downstream denial/validation failure, NOT a crash. Distinguished
    /// from [`Trap`](Self::Trap) so a dead-letter reads `consumer-error`, not the opaque `trap` a real
    /// panic yields (PLAN-async-persona legible-terminal-outcome taxonomy). The carried string is the
    /// guest's returned error text — treated as UNTRUSTED (bounded, never structured-log-interpolated
    /// by the host; the DLQ layer sanitizes it before it reaches an operator).
    #[error("consumer returned an error")]
    ConsumerError(String),
    /// The guest exceeded its wall-clock budget.
    #[error("handler timed out")]
    Timeout,
    /// The guest exhausted its CPU **fuel** budget.
    #[error("handler exhausted its CPU fuel budget")]
    OutOfFuel,
    /// The guest exhausted its **linear-memory** budget: a `memory.grow` was denied by the
    /// (lane ∧ component) ceiling and the guest then trapped. Distinguished from the opaque
    /// [`Trap`](Self::Trap) so the async-lane DLQ reads `out-of-memory` — an operator who raised (or
    /// could raise) a lane's `*_max_memory_mb` sees memory exhaustion as a distinct terminal outcome
    /// rather than a generic crash (construens async-lane-memory-budget request #4).
    #[error("handler exhausted its linear-memory budget")]
    OutOfMemory,
    /// The engine is at its concurrency limit.
    #[error("handler engine at capacity")]
    Overloaded,
    /// The guest returned without producing a response.
    #[error("handler produced no response")]
    NoResponse,
    /// An internal engine error.
    #[error("handler engine error: {0}")]
    Internal(String),
}

impl From<wasmtime::Error> for HandlerError {
    /// wasmtime setup errors (engine/linker/config) are engine-internal.
    /// Component-compile failures are mapped to [`HandlerError::Compile`]
    /// explicitly at the call site instead. (This deliberately stringifies rather
    /// than carrying the source, so `Internal` stays a plain `String`.)
    fn from(err: wasmtime::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

/// Per-store host state: the WASI + WASI-HTTP contexts, the resource table, the
/// memory limiter, and the per-site capability bindings (kv/blob/sql) this
/// invocation was granted.
/// Wraps [`StoreLimits`] to *observe* a denied linear-memory growth, so a guest that traps after
/// exhausting its (lane ∧ component) memory budget is classified as [`HandlerError::OutOfMemory`]
/// rather than an opaque `trap`. It changes NO policy: every decision is forwarded to the inner
/// `StoreLimits` (so the ceiling `effective_limits` computed still binds identically) and the
/// `Ok(false)` deny is merely recorded in `oom`. `trap_on_grow_failure` stays off upstream, so
/// `memory.grow` still returns -1 to a guest that handles allocation failure gracefully — the flag
/// only changes how a *subsequent* trap is labelled, never whether the grow is allowed.
struct MemLimiter {
    inner: StoreLimits,
    oom: Arc<AtomicBool>,
}

impl wasmtime::ResourceLimiter for MemLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let allow = self.inner.memory_growing(current, desired, maximum)?;
        if !allow {
            // The guest asked for more linear memory than its ceiling. wasmtime returns -1 to the
            // `memory.grow`; a guest allocator typically then traps. Record it so `classify` can tag
            // that trap as `out-of-memory`.
            self.oom.store(true, Ordering::Relaxed);
        }
        Ok(allow)
    }

    fn memory_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        self.inner.memory_grow_failed(error)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.inner.table_growing(current, desired, maximum)
    }

    fn table_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        self.inner.table_grow_failed(error)
    }

    fn instances(&self) -> usize {
        self.inner.instances()
    }

    fn tables(&self) -> usize {
        self.inner.tables()
    }

    fn memories(&self) -> usize {
        self.inner.memories()
    }
}

struct HostState {
    table: ResourceTable,
    wasi: WasiCtx,
    http: WasiHttpCtx,
    limits: MemLimiter,
    bindings: Bindings,
    /// Ceiling on this invocation's outbound `wasi:http` connect + first-byte
    /// wait (from the engine), independent of the invocation's own timeout.
    outbound_timeout: Option<Duration>,
    /// Whether this invocation's guest outbound `wasi:http` may reach a private/loopback
    /// address (from the engine's `allow_private_egress`). `false` is the SSRF default.
    allow_private_egress: bool,
    /// The instance's own serve socket(s) a guest self-call may reach (empty ⇒ self-egress
    /// off). Copied from the engine.
    self_egress_addrs: Arc<[SocketAddr]>,
    /// Operator-supplied EXTRA trust anchors for this invocation's guest egress TLS client (copied
    /// from the engine's `guest_egress_extra_roots`). Empty ⇒ the stock webpki-only sender.
    guest_egress_extra_roots: Arc<[rustls::pki_types::CertificateDer<'static>]>,
    /// This invocation's inbound self-egress recursion depth: 0 for an external request, or
    /// the value a parent self-call stamped (validated against [`egress_nonce`](Self::egress_nonce)).
    egress_depth: u32,
    /// The per-process nonce that authenticates a self-egress depth marker.
    egress_nonce: u64,
    /// The invocation's SQL transaction state (begun lazily on first query).
    #[cfg(feature = "sql")]
    sql: bindings::sql::SqlSession,
}

impl HostState {
    /// Whether this invocation hit its linear-memory ceiling (a denied `memory.grow`). Read at the
    /// trap-classification sites so an OOM-induced trap is labelled `out-of-memory`.
    fn oom(&self) -> bool {
        self.limits.oom.load(Ordering::Relaxed)
    }

    /// A clone of the OOM flag, for the sync serve path where the `Store` is moved into the guest's
    /// drive task and so cannot be read back directly after the trap.
    fn oom_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.limits.oom)
    }
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
        mut config: wasmtime_wasi_http::types::OutgoingRequestConfig,
    ) -> wasmtime_wasi_http::HttpResult<wasmtime_wasi_http::types::HostFutureIncomingResponse> {
        // Bound a hung upstream on its own terms (connect + first byte), so it
        // can't silently ride the whole invocation budget. `None` keeps the
        // wasmtime default. The between-bytes timeout is left alone so a slow
        // streaming body (e.g. an LLM token stream) is not cut mid-flight.
        if let Some(timeout) = self.outbound_timeout {
            config.connect_timeout = timeout;
            config.first_byte_timeout = timeout;
        }
        let use_tls = config.use_tls;
        let allow_private = self.allow_private_egress;
        let self_addrs = self.self_egress_addrs.clone();
        let egress_depth = self.egress_depth;
        let egress_nonce = self.egress_nonce;
        let extra_roots = self.guest_egress_extra_roots.clone();
        let handle = wasmtime_wasi::runtime::spawn(async move {
            let mut request = request;
            let result = match egress_target_allowed(
                request.uri(),
                use_tls,
                allow_private,
                &self_addrs,
                egress_depth,
            )
            .await
            {
                Ok(plan) => {
                    // A self-call carries its (nonce-stamped) recursion depth so the
                    // re-entering invocation sees it and the gate can cap the chain.
                    if let Some(next) = plan.self_depth
                        && let Ok(v) = format!("{egress_nonce:x}:{next}").parse()
                    {
                        request.headers_mut().insert(SELF_EGRESS_DEPTH_HEADER, v);
                    }
                    // Dev-posture extra-CA: when an operator supplied extra roots AND this is a TLS
                    // request, send through our own handler that trusts webpki ⊕ those roots.
                    // Otherwise (the default, and every plaintext request) use the stock sender
                    // verbatim — production trust is byte-identical.
                    if use_tls && !extra_roots.is_empty() {
                        send_with_extra_roots(request, config, &extra_roots).await
                    } else {
                        wasmtime_wasi_http::types::default_send_request_handler(request, config)
                            .await
                    }
                }
                Err(code) => Err(code),
            };
            Ok(result)
        });
        Ok(wasmtime_wasi_http::types::HostFutureIncomingResponse::pending(handle))
    }
}

/// Replicates wasmtime-wasi-http's crate-private `dns_error` (a `DnsError` with the given rcode).
fn egress_dns_error(
    rcode: String,
    info_code: u16,
) -> wasmtime_wasi_http::bindings::http::types::ErrorCode {
    wasmtime_wasi_http::bindings::http::types::ErrorCode::DnsError(
        wasmtime_wasi_http::bindings::http::types::DnsErrorPayload {
            rcode: Some(rcode),
            info_code: Some(info_code),
        },
    )
}

/// Build the guest-egress TLS client config trusting the webpki roots **⊕** the operator's `extra_roots`.
///
/// This is the security-critical core of the dev-posture extra-CA option, factored out so it can be
/// exercised by a real loopback-TLS handshake test. It **adds** trust anchors — server-certificate
/// verification is still fully performed by rustls against the (widened) root set; it never disables
/// verification or accepts an unpinned cert. With `extra_roots` empty this is exactly the stock trust
/// set (webpki only). An explicit aws-lc-rs provider is used so the config does not depend on a
/// process-default `CryptoProvider` having been installed.
fn guest_egress_client_config(
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<rustls::ClientConfig, wasmtime_wasi_http::bindings::http::types::ErrorCode> {
    use wasmtime_wasi_http::bindings::http::types::ErrorCode;
    let mut root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    // Append the operator CA(s). A malformed entry is ignored (the webpki roots remain, so public
    // hosts still verify); a valid one becomes an additional trust anchor.
    let (_added, _ignored) = root_store.add_parsable_certificates(extra_roots.iter().cloned());
    rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| {
        tracing::warn!("guest egress TLS config error: {e:?}");
        ErrorCode::InternalError(Some("guest egress TLS config".into()))
    })
    .map(|b| b.with_root_certificates(root_store).with_no_client_auth())
}

/// Send a guest outbound **TLS** request trusting webpki ⊕ the operator's `extra_roots`. A faithful
/// copy of wasmtime-wasi-http 30.0.2's `default_send_request_handler` TLS branch, differing ONLY in
/// the root store (via [`guest_egress_client_config`]) — reached only when an operator supplied
/// extra roots (the dev-posture option), otherwise the stock sender runs. Version-coupled: on a
/// wasmtime-wasi-http bump, re-diff this against `default_send_request_handler`.
async fn send_with_extra_roots(
    mut request: http::Request<wasmtime_wasi_http::body::HyperOutgoingBody>,
    config: wasmtime_wasi_http::types::OutgoingRequestConfig,
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<
    wasmtime_wasi_http::types::IncomingResponse,
    wasmtime_wasi_http::bindings::http::types::ErrorCode,
> {
    use http_body_util::BodyExt;
    use rustls::pki_types::ServerName;
    use wasmtime_wasi_http::bindings::http::types::ErrorCode;

    let authority = match request.uri().authority() {
        Some(a) if a.port().is_some() => a.to_string(),
        // This path is TLS-only (the caller gates on `use_tls`), so default to 443.
        Some(a) => format!("{a}:443"),
        None => return Err(ErrorCode::HttpRequestUriInvalid),
    };
    let tcp_stream = tokio::time::timeout(
        config.connect_timeout,
        tokio::net::TcpStream::connect(&authority),
    )
    .await
    .map_err(|_| ErrorCode::ConnectionTimeout)?
    .map_err(|e| match e.kind() {
        std::io::ErrorKind::AddrNotAvailable => {
            egress_dns_error("address not available".to_string(), 0)
        }
        _ if e
            .to_string()
            .starts_with("failed to lookup address information") =>
        {
            egress_dns_error("address not available".to_string(), 0)
        }
        _ => ErrorCode::ConnectionRefused,
    })?;

    let tls_config = guest_egress_client_config(extra_roots)?;
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
    let host = authority.split(':').next().unwrap_or(&authority);
    let domain = ServerName::try_from(host)
        .map_err(|e| {
            tracing::warn!("guest egress dns name error: {e:?}");
            egress_dns_error("invalid dns name".to_string(), 0)
        })?
        .to_owned();
    let stream = connector.connect(domain, tcp_stream).await.map_err(|e| {
        tracing::warn!("guest egress tls protocol error: {e:?}");
        ErrorCode::TlsProtocolError
    })?;
    let stream = hyper_util::rt::TokioIo::new(stream);

    let (mut sender, conn) = tokio::time::timeout(
        config.connect_timeout,
        hyper::client::conn::http1::handshake(stream),
    )
    .await
    .map_err(|_| ErrorCode::ConnectionTimeout)?
    .map_err(wasmtime_wasi_http::hyper_request_error)?;
    let worker = wasmtime_wasi::runtime::spawn(async move {
        if let Err(e) = conn.await {
            tracing::warn!("guest egress connection dropped: {e}");
        }
    });

    // Origin-form: strip scheme+authority (SendRequest::send_request does not).
    *request.uri_mut() = http::Uri::builder()
        .path_and_query(
            request
                .uri()
                .path_and_query()
                .map(http::uri::PathAndQuery::as_str)
                .unwrap_or("/"),
        )
        .build()
        .expect("comes from a valid request");

    let resp = tokio::time::timeout(config.first_byte_timeout, sender.send_request(request))
        .await
        .map_err(|_| ErrorCode::ConnectionReadTimeout)?
        .map_err(wasmtime_wasi_http::hyper_request_error)?
        .map(|body| {
            body.map_err(wasmtime_wasi_http::hyper_request_error)
                .boxed()
        });

    Ok(wasmtime_wasi_http::types::IncomingResponse {
        resp,
        worker: Some(worker),
        between_bytes_timeout: config.between_bytes_timeout,
    })
}

/// The request header carrying a guest self-egress call's recursion depth, stamped with the
/// per-process [`HandlerEngine::egress_nonce`] as `<nonce>:<depth>` so an external client
/// cannot forge it (a mismatched nonce is read as depth 0). Set on an outgoing self-call and
/// read back when that call re-enters the serve pipeline.
const SELF_EGRESS_DEPTH_HEADER: &str = "x-boatramp-egress-depth";

/// Max guest→own-instance self-call depth before the egress gate refuses, so a guest can't
/// self-recurse over loopback to exhaust the handler pool. Mirrors `MAX_INVOKE_DEPTH`.
const MAX_SELF_EGRESS_DEPTH: u32 = 8;

/// What the egress gate decided for a permitted request.
struct EgressPlan {
    /// `Some(next_depth)` when the target is this instance's own serve socket: the caller
    /// stamps [`SELF_EGRESS_DEPTH_HEADER`] with `next_depth` on the outgoing request.
    self_depth: Option<u32>,
}

/// Resolve `uri`'s host and (unless `allow_private`) require every address be globally
/// routable, so a guest's `wasi:http` request can't target internal infrastructure (SSRF).
/// `allow_private` is the operator posture's `allow_guest_private_egress` — on a trusted
/// single-tenant/dev fleet a guest may reach loopback/private hosts; the multi-tenant
/// default keeps the gate closed. Even with `allow_private`, the destination must still
/// resolve (an empty/unresolvable host is refused).
///
/// `allow_private` is the posture's `allow_guest_private_egress` — on a trusted fleet a
/// guest may reach any loopback/private host. `self_addrs` is the instance's own serve
/// socket(s) (from `allow_guest_self_egress`): a target that resolves there is permitted
/// **even when** `allow_private` is off — it is only boatramp's own auth-gated front door —
/// but is capped at [`MAX_SELF_EGRESS_DEPTH`] against `egress_depth` so a guest can't
/// self-recurse over loopback to exhaust the pool. Even when permitted, the destination
/// must still resolve.
async fn egress_target_allowed(
    uri: &http::Uri,
    use_tls: bool,
    allow_private: bool,
    self_addrs: &[SocketAddr],
    egress_depth: u32,
) -> Result<EgressPlan, wasmtime_wasi_http::bindings::http::types::ErrorCode> {
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
    let mut hit_self = false;
    for addr in addrs.by_ref() {
        saw_any = true;
        // The instance's own serve socket is always permitted (it re-enters the pipeline);
        // depth-capped below. Otherwise apply the SSRF gate unless the posture trusts egress.
        if self_addrs.contains(&addr) {
            hit_self = true;
        } else if !allow_private && !boatramp_core::access::is_global_ip(addr.ip()) {
            return Err(ErrorCode::DestinationIpProhibited);
        }
    }
    if !saw_any {
        return Err(ErrorCode::DestinationNotFound);
    }
    if hit_self {
        let next = egress_depth.saturating_add(1);
        if next > MAX_SELF_EGRESS_DEPTH {
            // Too deep a self-recursion — refuse rather than nest further.
            return Err(ErrorCode::DestinationIpProhibited);
        }
        return Ok(EgressPlan {
            self_depth: Some(next),
        });
    }
    Ok(EgressPlan { self_depth: None })
}

/// The active async-lane mutation (anti-hollow gates), or `None`. Present ONLY under `cfg(test)`
/// (this crate's own unit gates) or the `async-lane-gate-mutation` feature; a shipped build has
/// neither, so both lane clamps below — the per-invocation memory down-clamp in
/// [`HandlerEngine::effective_limits`] and the per-consumer `min(cap, lane_ceiling)` in
/// [`ConsumerGates::gate`] — are unconditional and this is a dead `None`.
#[cfg(any(test, feature = "async-lane-gate-mutation"))]
fn lane_gate_mutation() -> Option<String> {
    std::env::var("BOATRAMP_ASYNCLANE_MUTATION").ok()
}
#[cfg(not(any(test, feature = "async-lane-gate-mutation")))]
#[inline]
fn lane_gate_mutation() -> Option<String> {
    None
}

/// Per-consumer concurrency gates (P2 resource isolation): a lazily-created [`Semaphore`] per
/// consumer identity, so one consumer's burst (e.g. a thumbnail backfill) can't occupy the shared
/// async lane and starve other consumers.
///
/// A dedicated type with a **single** lock site ([`permit`](Self::permit)) so the one discipline —
/// *the `std` mutex guard is cloned-out and DROPPED before the `.await`, never held across it* —
/// lives in exactly one audited place rather than being an inline footgun at the call site. Keyed by
/// the consumer's stable identity (site∥topic∥group); each entry remembers its effective cap, so a
/// changed cap (on the next `apply`) rebuilds the semaphore instead of honoring a stale one. The map
/// holds one small entry per declared consumer (bounded, not per-message).
#[cfg(feature = "messaging")]
#[derive(Default)]
struct ConsumerGates(KeyedSemaphores);

#[cfg(feature = "messaging")]
impl ConsumerGates {
    /// Resolve the `Arc<Semaphore>` for consumer `key`, sized `min(cap, lane_ceiling)` (floored at 1)
    /// — the per-consumer value can never exceed the operator lane budget. Rebuilt if the effective
    /// cap changed (next `apply`). The map + the lock-vs-await discipline live in
    /// [`KeyedSemaphores`](boatramp_core::concurrency::KeyedSemaphores) now (the one audited home for
    /// this pattern); this wrapper only applies the lane-ceiling clamp (and its mutation seam). The
    /// caller resolves the gate ONCE per batch and `.acquire_owned()`s a permit per message off the
    /// returned `Arc`, so no guard is ever held across an await.
    fn gate(&self, key: &str, cap: usize, lane_ceiling: usize) -> Arc<Semaphore> {
        // MUTATION SEAM (G-conc): the per-consumer cap is floored by the lane budget so a declared
        // `max_concurrency` can never raise a consumer above the operator's `async_max_concurrency`.
        // Dropping the `.min(lane_ceiling)` lets `cap` exceed the lane → the gate goes RED.
        let eff = if lane_gate_mutation().as_deref() == Some("skip_consumer_clamp") {
            cap.max(1)
        } else {
            cap.min(lane_ceiling).max(1)
        };
        self.0.gate(key, eff)
    }
}

/// Insert a freshly-compiled component into a lane's LRU cache, returning `1` if the insert EVICTED
/// a resident component (the cache was at capacity and the key was new), else `0` — the per-lane
/// eviction signal for the instance-lifecycle stats (construens memory-instance-observability). A
/// warm component dropped here pays a cold recompile on its next request; the REASON is the LRU
/// capacity cap (reported as `warm_capacity`). Version-agnostic over the `lru` API (len-vs-cap, not
/// a return-value contract).
fn cache_insert_evicted<V>(cache: &Mutex<LruCache<String, V>>, key: &str, value: V) -> u64 {
    let mut c = cache.lock().unwrap();
    let at_capacity = c.len() >= c.cap().get();
    let replaced = c.put(key.to_string(), value).is_some();
    u64::from(at_capacity && !replaced)
}

/// The handler engine: a wasmtime [`Engine`], a blob-hash-keyed cache of
/// compiled+pre-instantiated components, the limit policy, and a concurrency
/// gate. A background task ticks the engine epoch for timeouts.
pub struct HandlerEngine {
    engine: Engine,
    /// Host-side instance-lifecycle counters (warm-hit / cold-miss / eviction / instantiation +
    /// durations), incremented on the serve path and snapshotted read-only for the admin stats
    /// surface (construens memory-instance-observability). `Arc` so the server can hold a handle.
    stats: Arc<crate::instance_stats::InstanceStats>,
    cache: Mutex<LruCache<String, ProxyPre<HostState>>>,
    /// Separate compile cache for consumer (`wasi:messaging`) components — a
    /// different world (`handle` export) than the request `ProxyPre`.
    #[cfg(feature = "messaging")]
    consumer_cache: Mutex<LruCache<String, consumer_world::ConsumerPre<HostState>>>,
    /// Separate compile cache for session (`session-handler` export) components.
    #[cfg(feature = "session")]
    session_cache: Mutex<LruCache<String, session_world::SessionHostPre<HostState>>>,
    /// The [`Lane::Sync`] ceiling — connection-bearing requests are clamped to
    /// this (default 10s). Named `limits` for back-compat with existing callers.
    limits: Limits,
    /// The [`Lane::Async`] ceiling — the durable drain / workflow-step path is
    /// clamped to this instead. Defaults to `limits` (identical behavior) until a
    /// caller opts into a larger one via [`with_async_limits`](Self::with_async_limits).
    async_limits: Limits,
    /// The [`Lane::Streaming`] ceiling — a long-lived streaming response is
    /// clamped to this (a much larger wall-clock than the sync default).
    /// Defaults to `limits` until a caller opts into a larger one via
    /// [`with_streaming_limits`](Self::with_streaming_limits).
    streaming_limits: Limits,
    /// Concurrency gate for the sync lane (the shared request pool).
    semaphore: Semaphore,
    /// A **separate** concurrency gate for the async lane, so a long background
    /// job can never exhaust the pool live site traffic draws from.
    async_semaphore: Semaphore,
    /// A **separate** concurrency gate for the streaming lane, so a burst of
    /// long-lived streams can't exhaust the sync request pool or the async drain.
    streaming_semaphore: Semaphore,
    /// Per-consumer concurrency gates (P2 resource isolation) — see [`ConsumerGates`]. A consumer
    /// with no `max_concurrency` never enters it and shares the async lane budget exactly as before.
    #[cfg(feature = "messaging")]
    consumer_gates: ConsumerGates,
    /// Per-component serve-path ADMISSION gates (image-serve-latency Ask B), keyed by component blob
    /// hash. Resolved by [`serve_admission`](Self::serve_admission) and acquired by the request
    /// dispatch BEFORE `build_bindings`, so a burst to one component (a gallery firing ~48 `/img`
    /// thumbnails) admits only a bounded number into the expensive build+serve region and queues the
    /// rest cheaply — the fix for the measured `bindgap` scheduling park. The same audited
    /// [`KeyedSemaphores`] the consumer gates use; keyed by a deploy-derived hash (bounded set).
    request_gates: KeyedSemaphores,
    /// Concurrency cap on **compilation** (deploy-resilience #2): bounds how many cranelift
    /// compiles run at once, so a bulk precompile (e.g. an apply uploading many components, each
    /// warming the cache via [`precompile_gated`](Self::precompile_gated)) can't spike RSS on a
    /// small host. Acquired only on the gated precompile path; the on-demand serve-path
    /// [`proxy_pre`](Self::proxy_pre) is unchanged (traffic-serialized + cached). Default 1
    /// (fully serialize); raise via [`with_compile_concurrency`](Self::with_compile_concurrency).
    /// `Arc` so a caller can hold an OWNED permit across an expensive blob read + compile (the
    /// precompile-at-upload path bounds resident blobs to this concurrency, #1a).
    compile_gate: Arc<Semaphore>,
    /// Optional ceiling on a guest's **outbound** `wasi:http` call (connect +
    /// time-to-first-byte), independent of the invocation's own timeout, so a
    /// hung upstream is bounded on its own terms. `None` keeps wasmtime's default.
    outbound_timeout: Option<Duration>,
    /// Whether a guest's outbound `wasi:http` may reach a private/loopback/link-local
    /// address (the operator posture's `allow_guest_private_egress`). `false` is the SSRF
    /// default: guests reach only globally-routable hosts. Does not affect a guest calling
    /// its own site (served in-process, never network egress).
    allow_private_egress: bool,
    /// The instance's own serve socket(s) a guest self-call may reach (`allow_guest_self_egress`).
    /// Empty ⇒ self-egress off. Loopback normalization (`0.0.0.0` ⇒ `127.0.0.1`/`::1`) is done
    /// by the caller (`build_handler_runtime`).
    self_egress_addrs: Arc<[SocketAddr]>,
    /// Operator-supplied EXTRA trust anchors for a guest's outbound `wasi:http` TLS client — the
    /// dev-posture `allow_guest_egress_extra_ca` option (default OFF; refused under `multi-tenant`).
    /// Empty ⇒ the stock wasmtime-wasi-http sender (webpki roots only) is used verbatim, so
    /// production trust is byte-identical. Non-empty ⇒ the guest egress TLS client trusts webpki
    /// roots **⊕** these certs (see [`guest_egress_client_config`]); still fully verified, just
    /// against an additional operator CA (e.g. a hermetic HTTPS test double).
    guest_egress_extra_roots: Arc<[rustls::pki_types::CertificateDer<'static>]>,
    /// A per-process random nonce stamped on the self-egress depth header so an external
    /// client can't forge it. Generated once at engine build.
    egress_nonce: u64,
    epoch_ticker: tokio::task::JoinHandle<()>,
}

impl Drop for HandlerEngine {
    fn drop(&mut self) {
        self.epoch_ticker.abort();
    }
}

impl HandlerEngine {
    /// Build the engine with `limits`, caching up to `cache_size` compiled
    /// components. Uses the default on-demand instance allocator. The persisted compile cache falls
    /// back to wasmtime's ephemeral default location; a production node that wants the cache to
    /// survive restarts uses [`new_with_cache_dir`](Self::new_with_cache_dir) instead.
    pub fn new(limits: Limits, cache_size: usize) -> Result<Self, HandlerError> {
        Self::new_with_cache_dir(limits, cache_size, None)
    }

    /// Like [`new`](Self::new) but pins the persisted compile cache to `cache_dir` (the operator's
    /// durable data volume) so a component's compiled artifact survives a restart — the first request
    /// after a roll deserializes in ms instead of paying a cranelift compile. `None` ⇒ the ephemeral
    /// default (identical to [`new`](Self::new)).
    pub fn new_with_cache_dir(
        limits: Limits,
        cache_size: usize,
        cache_dir: Option<&Path>,
    ) -> Result<Self, HandlerError> {
        Self::from_engine(build_engine(cache_dir)?, limits, cache_size)
    }

    /// Like [`new`](Self::new) but with the **pooling** instance allocator (H8,
    /// opt-in): instances come from a pre-reserved pool, so instantiation skips
    /// per-call allocation. The pool is sized against `limits`; reserves a large
    /// block of virtual memory up front (see [`build_engine_pooling`]). `cache_dir` pins the
    /// persisted compile cache to the data volume (`None` ⇒ ephemeral default).
    pub fn with_pooling(
        limits: Limits,
        cache_size: usize,
        cache_dir: Option<&Path>,
    ) -> Result<Self, HandlerError> {
        Self::from_engine(
            build_engine_pooling(&limits, cache_dir)?,
            limits,
            cache_size,
        )
    }

    /// Like [`with_pooling`](Self::with_pooling) but for the full three-lane model:
    /// the single shared pool is sized off the **largest** lane (the max memory
    /// ceiling + the max concurrency across lanes), so an instance dispatched on ANY
    /// lane fits a pool slot — while each lane keeps its own ceiling and the
    /// per-invocation [`StoreLimits`] still clamps every instance down to its
    /// effective (lane ∧ component) memory. This is how a raised `async` memory
    /// ceiling works under pooling without a separate engine per lane.
    ///
    /// The pooling allocator reserves ≈ `max_lane_memory × total_memories` of VIRTUAL
    /// address space up front; this logs that estimate and warns loudly when it is
    /// large, so an operator who raised a lane ceiling sees the cost (and a failure to
    /// reserve surfaces as a clear build error rather than a silent first-invocation
    /// OOM).
    pub fn with_pooling_lanes(
        sync: Limits,
        async_: Limits,
        streaming: Limits,
        cache_size: usize,
        cache_dir: Option<&Path>,
    ) -> Result<Self, HandlerError> {
        // Per-slot memory is the LARGEST lane ceiling (any lane's instance must fit a slot). Slot
        // COUNT, however, must cover the lanes running at once: the three lane semaphores are
        // independent, so up to `sync + async + streaming` instances can be live simultaneously, all
        // drawing from this one pool. Sizing the count off `max(lanes)` (not the sum) would
        // under-provision exactly when an operator raises `async_max_concurrency` — the feature's
        // whole point — so use the SUM (review finding C4).
        let pool_memory = sync
            .memory_bytes
            .max(async_.memory_bytes)
            .max(streaming.memory_bytes);
        let pool_concurrency = sync
            .max_concurrency
            .saturating_add(async_.max_concurrency)
            .saturating_add(streaming.max_concurrency);
        // Mirror `build_engine_pooling`'s slot math (`concurrency*8`, min 16) to estimate
        // the up-front virtual reservation so it is visible / loud before it bites.
        let total_memories = (pool_concurrency.saturating_mul(8)).max(16);
        let reservation = (pool_memory as u128).saturating_mul(total_memories as u128);
        let reservation_gib = reservation / (1024 * 1024 * 1024);
        tracing::info!(
            target: "boatramp::handler",
            pool_memory_mib = pool_memory / (1024 * 1024),
            total_memories,
            reservation_gib,
            "pooling allocator: per-slot memory = largest lane ceiling, slot count = summed lane concurrency"
        );
        // Soft guard: a very large VIRTUAL reservation is viable on a 64-bit host with
        // overcommit, but an implausible one usually indicates a ceiling set far too high. Warn loudly
        // (don't refuse a config that may be valid on this host); a real reservation
        // failure still fails the build below with context.
        if reservation_gib >= 128 {
            tracing::warn!(
                target: "boatramp::handler",
                reservation_gib,
                pool_memory_mib = pool_memory / (1024 * 1024),
                total_memories,
                "pooling allocator will reserve a very large block of virtual address space; \
                 if the node cannot start, lower a `*_max_memory_mb` / `*_max_concurrency` knob \
                 or disable `[handlers] pooling`"
            );
        }
        let pool_limits = Limits {
            memory_bytes: pool_memory,
            max_concurrency: pool_concurrency,
            ..sync
        };
        let engine = build_engine_pooling(&pool_limits, cache_dir).map_err(|e| {
            HandlerError::Internal(format!(
                "pooling allocator could not reserve ~{reservation_gib} GiB of virtual address \
                 space for the raised memory ceiling ({} MiB × {total_memories} slots): {e}. \
                 Lower a `*_max_memory_mb`/`*_max_concurrency` knob, or disable `[handlers] pooling`.",
                pool_memory / (1024 * 1024)
            ))
        })?;
        Ok(Self::from_engine(engine, sync, cache_size)?
            .with_async_limits(async_)
            .with_streaming_limits(streaming))
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
            stats: Arc::new(crate::instance_stats::InstanceStats::default()),
            cache,
            #[cfg(feature = "messaging")]
            consumer_cache: Mutex::new(LruCache::new(capacity)),
            #[cfg(feature = "messaging")]
            consumer_gates: ConsumerGates::default(),
            request_gates: KeyedSemaphores::default(),
            #[cfg(feature = "session")]
            session_cache: Mutex::new(LruCache::new(capacity)),
            semaphore: Semaphore::new(limits.max_concurrency.max(1)),
            // The async + streaming lanes default to the sync ceiling + an equally-sized,
            // *independent* pool each, so an engine built without opting in behaves
            // exactly as before (back-compat for tests and existing callers).
            async_semaphore: Semaphore::new(limits.max_concurrency.max(1)),
            async_limits: limits,
            streaming_semaphore: Semaphore::new(limits.max_concurrency.max(1)),
            streaming_limits: limits,
            // Serialize bulk precompiles by default (safest for a memory-bound host); operators with
            // headroom raise it via `with_compile_concurrency`.
            compile_gate: Arc::new(Semaphore::new(1)),
            outbound_timeout: None,
            allow_private_egress: false,
            self_egress_addrs: Arc::from([] as [SocketAddr; 0]),
            // Default: no extra roots ⇒ the stock webpki-only egress sender (prod-identical).
            guest_egress_extra_roots: Arc::from(
                [] as [rustls::pki_types::CertificateDer<'static>; 0]
            ),
            egress_nonce: {
                let mut b = [0u8; 8];
                // A failure here would only weaken the anti-forgery nonce, never break
                // serving — fall back to a fixed value rather than refuse to build.
                getrandom::getrandom(&mut b).ok();
                u64::from_le_bytes(b)
            },
            limits,
            epoch_ticker,
        })
    }

    /// Set the [`Lane::Async`] ceiling — the drain / workflow-step path is
    /// clamped to this instead of the sync ceiling, on its own concurrency
    /// budget (`async_limits.max_concurrency`). This is what lets a durable
    /// background job declare (and actually get) a timeout well beyond the tight
    /// sync default, without a long job ever holding a slot live traffic needs.
    #[must_use]
    pub fn with_async_limits(mut self, async_limits: Limits) -> Self {
        self.async_semaphore = Semaphore::new(async_limits.max_concurrency.max(1));
        self.async_limits = async_limits;
        self
    }

    /// Set the [`Lane::Streaming`] ceiling — a long-lived streaming response
    /// (SSE, chunked, agent token streaming) runs here instead of the sync lane,
    /// on its own concurrency budget (`streaming_limits.max_concurrency`) with a
    /// much larger wall-clock (`streaming_limits.timeout_ms`), so a stream that
    /// runs for minutes never holds a slot the fast-request pool needs and can't
    /// starve the durable async drain either.
    #[must_use]
    pub fn with_streaming_limits(mut self, streaming_limits: Limits) -> Self {
        self.streaming_semaphore = Semaphore::new(streaming_limits.max_concurrency.max(1));
        self.streaming_limits = streaming_limits;
        self
    }

    /// Resolve the **per-consumer** concurrency gate (P2 resource isolation): the `Arc<Semaphore>`
    /// sized `min(cap, async-lane)` for consumer `key` (its stable identity site∥topic∥group), so a
    /// per-consumer cap can only narrow, never exceed the operator lane budget. Created on first use,
    /// rebuilt if the cap changed (a manifest edit). Resolve this **once per batch**, then
    /// `.acquire_owned()` a permit per message off the returned `Arc` — so the map is locked once per
    /// batch, not once per message (the lookup is synchronous; the await is the caller's per-message
    /// `acquire_owned`). Call only when a consumer declares `max_concurrency`; an unset consumer
    /// shares the lane budget as before (never enters the map).
    #[cfg(feature = "messaging")]
    pub fn consumer_gate(&self, key: &str, cap: usize) -> Arc<Semaphore> {
        self.consumer_gates
            .gate(key, cap, self.async_limits.max_concurrency)
    }

    /// Resolve the **per-component serve-admission** gate (image-serve-latency Ask B): the
    /// `Arc<Semaphore>` sized `cap` for component blob `hash`, created on first use and rebuilt if the
    /// cap changed. The request dispatch resolves this BEFORE `build_bindings` and `.acquire_owned()`s
    /// a permit off the returned `Arc` (held through serve-to-head), so at most `cap` requests are
    /// ever inside the expensive build+instantiate+serve region per component — the rest queue cheaply
    /// on the semaphore instead of oversubscribing the tokio workers (the measured `bindgap` park).
    /// The lookup is synchronous (the lock is never held across the caller's await). Call only with
    /// `cap >= 1`; the caller treats `cap == 0` as "gate disabled" and skips this entirely.
    pub fn serve_admission(&self, hash: &str, cap: usize) -> Arc<Semaphore> {
        self.request_gates.gate(hash, cap)
    }

    /// The NONCE-VERIFIED inbound self-egress recursion depth from [`SELF_EGRESS_DEPTH_HEADER`]:
    /// trust the marker only when it carries THIS process's [`egress_nonce`](Self::egress_nonce) (an
    /// external client cannot forge it), else `0` (a fresh external request, or a forged/absent/
    /// malformed marker). The request dispatch calls this BEFORE the serve-admission gate to SKIP the
    /// gate for a re-entrant self-call (depth > 0): the outer request in the self-call chain already
    /// holds this component's permit, so making the inner re-entrant call also take one would be a
    /// reentrant deadlock under load (the outer holds a permit while awaiting the inner's → circular
    /// wait until the outer's wall-clock timeout). Because a bogus header verifies to `0`, the gate
    /// still bounds EVERY real external burst — the skip cannot be used to bypass it.
    pub fn verified_self_egress_depth(&self, headers: &http::HeaderMap) -> u32 {
        headers
            .get(SELF_EGRESS_DEPTH_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split_once(':'))
            .and_then(|(n, d)| {
                (u64::from_str_radix(n, 16).ok()? == self.egress_nonce)
                    .then(|| d.parse::<u32>().ok())
                    .flatten()
            })
            .unwrap_or(0)
    }

    /// The sync-lane wall-clock ceiling (ms): connection-bearing requests (site
    /// handlers, synchronous invokes) are clamped to this. A deploy that declares a
    /// larger per-handler/site timeout can inspect this to warn that sync calls will
    /// be capped (see the activation pre-check).
    pub fn sync_timeout_ms(&self) -> u64 {
        self.limits.timeout_ms
    }

    /// Set the ceiling on a guest's **outbound** `wasi:http` request (applied to
    /// the connect + first-byte timeouts), independent of the invocation budget.
    #[must_use]
    pub fn with_outbound_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.outbound_timeout = timeout;
        self
    }

    /// Permit (or refuse) a guest's outbound `wasi:http` reaching a private/loopback IP —
    /// the operator posture's `allow_guest_private_egress`. Default (`false`) is the strict
    /// SSRF gate; an operator on a trusted single-tenant/dev posture opts in.
    #[must_use]
    pub fn with_private_egress(mut self, allow: bool) -> Self {
        self.allow_private_egress = allow;
        self
    }

    /// Add operator-supplied EXTRA trust anchors (DER certs) to a guest's outbound `wasi:http` TLS
    /// client — the dev-posture `allow_guest_egress_extra_ca` option. The guest egress client then
    /// trusts webpki roots **⊕** these certs; server verification is still fully performed (this
    /// only widens the accepted CA set, never disables verification). Empty (the default) keeps the
    /// stock webpki-only sender, so production trust is unchanged unless an operator opts in. The
    /// caller (`boatramp-node`) parses the PEM and passes the certs only when the posture permits.
    #[must_use]
    pub fn with_guest_egress_extra_roots(
        mut self,
        roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Self {
        self.guest_egress_extra_roots = Arc::from(roots);
        self
    }

    /// The instance's own serve socket(s) a guest self-call may reach (the posture's
    /// `allow_guest_self_egress`). Empty ⇒ self-egress off. Pass the loopback-normalized
    /// addresses (`0.0.0.0`/`[::]` ⇒ `127.0.0.1` + `::1` on the serve port).
    #[must_use]
    pub fn with_self_egress(mut self, addrs: Vec<SocketAddr>) -> Self {
        self.self_egress_addrs = Arc::from(addrs);
        self
    }

    /// The [`Lane::Async`] wall-clock ceiling, milliseconds — the drain reads
    /// this to size an invocation's lease (it can run for at most this long).
    #[must_use]
    pub fn async_timeout_ms(&self) -> u64 {
        self.async_limits.timeout_ms
    }

    /// The [`Lane::Async`] concurrency budget — the drain sizes its own claim
    /// gate to this so it never spawns more background jobs than the lane can run.
    #[must_use]
    pub fn async_max_concurrency(&self) -> usize {
        self.async_limits.max_concurrency
    }

    /// The [`Lane::Streaming`] wall-clock ceiling, milliseconds — a streaming
    /// route's response may run for at most this long. A deploy can inspect it to
    /// warn that a longer per-handler timeout will still be capped here.
    #[must_use]
    pub fn streaming_timeout_ms(&self) -> u64 {
        self.streaming_limits.timeout_ms
    }

    /// The [`Lane::Streaming`] concurrency budget — the maximum number of
    /// concurrent streaming responses the lane will admit.
    #[must_use]
    pub fn streaming_max_concurrency(&self) -> usize {
        self.streaming_limits.max_concurrency
    }

    /// Compile (and cache) a component without serving it — the activation
    /// pre-warm + compile gate. The server calls this for
    /// every component of a deployment before flipping the `current` pointer, so
    /// a deploy with a component that fails to compile never goes live. Also
    /// warms the compilation cache so the first real request is fast.
    pub fn precompile(&self, hash: &str, wasm: &[u8]) -> Result<(), HandlerError> {
        self.proxy_pre(hash, wasm).map(|_| ())
    }

    /// Raise the compilation-concurrency cap (deploy-resilience #2). Default 1 (fully serialize);
    /// an operator with memory headroom can allow more parallel compiles. Called once at build.
    #[must_use]
    pub fn with_compile_concurrency(mut self, n: usize) -> Self {
        self.compile_gate = Arc::new(Semaphore::new(n.max(1)));
        self
    }

    /// Acquire an OWNED permit on the compile-concurrency gate (#2), to be held across an expensive
    /// blob read **and** the subsequent [`precompile_off_runtime`](Self::precompile_off_runtime) —
    /// so the precompile-at-upload path reads a blob back into RAM only when it is this component's
    /// turn to compile, bounding simultaneously-resident upload blobs to the compile-concurrency
    /// (not the upload-concurrency). The gate is never closed, so acquisition always succeeds.
    pub async fn acquire_compile_permit(&self) -> tokio::sync::OwnedSemaphorePermit {
        Arc::clone(&self.compile_gate)
            .acquire_owned()
            .await
            .expect("compile gate is never closed")
    }

    /// [`precompile`](Self::precompile) off the async runtime but WITHOUT acquiring the compile gate
    /// — for a caller that already holds a permit from
    /// [`acquire_compile_permit`](Self::acquire_compile_permit). (Re-acquiring the gate here would
    /// deadlock at concurrency 1, since the same task already holds the only permit.)
    pub async fn precompile_off_runtime(
        &self,
        hash: &str,
        wasm: &[u8],
    ) -> Result<(), HandlerError> {
        Self::run_compile_off_runtime(|| self.precompile(hash, wasm))
    }

    /// Run a synchronous cranelift compile without starving the async runtime. On the multi-thread
    /// runtime (the server's) `block_in_place` moves the OTHER tasks off this worker for the
    /// compile's duration, so a several-hundred-ms compile can't stall unrelated futures sharing the
    /// worker. On a current-thread runtime (some unit tests) `block_in_place` would panic, so we run
    /// the closure inline there — harmless, as those callers serve no live traffic.
    fn run_compile_off_runtime<T>(f: impl FnOnce() -> T) -> T {
        match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
            Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
            _ => f(),
        }
    }

    /// [`precompile`](Self::precompile) behind the compile-concurrency gate (#2): `await`s a permit
    /// (yielding the worker while others hold it), then runs the cranelift compile via
    /// [`block_in_place`](tokio::task::block_in_place) so the sync compile doesn't block the async
    /// worker it runs on. Used by the bulk-precompile paths (blob upload, activation precheck) so a
    /// many-component apply warms the cache without a simultaneous compile spike. Best-effort at the
    /// call site — a compile failure here is surfaced by the eventual deploy, never silently served.
    pub async fn precompile_gated(&self, hash: &str, wasm: &[u8]) -> Result<(), HandlerError> {
        let _permit = self
            .compile_gate
            .acquire()
            .await
            .expect("compile gate is never closed");
        Self::run_compile_off_runtime(|| self.precompile(hash, wasm))
    }

    /// [`precompile_consumer`](Self::precompile_consumer) behind the same compile gate (#2), with the
    /// same off-runtime compile as [`precompile_gated`](Self::precompile_gated).
    #[cfg(feature = "messaging")]
    pub async fn precompile_consumer_gated(
        &self,
        hash: &str,
        wasm: &[u8],
    ) -> Result<(), HandlerError> {
        let _permit = self
            .compile_gate
            .acquire()
            .await
            .expect("compile gate is never closed");
        Self::run_compile_off_runtime(|| self.precompile_consumer(hash, wasm))
    }

    /// Precompile + validate a component as a **`wasi:messaging` consumer** (it
    /// must export `messaging-handler`) — the activation gate for a `consumers`
    /// entry, mirroring [`precompile`](Self::precompile) for request handlers. A
    /// component that is not a consumer world fails here, at deploy, instead of
    /// silently at drain time.
    #[cfg(feature = "messaging")]
    pub fn precompile_consumer(&self, hash: &str, wasm: &[u8]) -> Result<(), HandlerError> {
        self.consumer_pre(hash, wasm).map(|_| ())
    }

    /// Read-only snapshot of the instance-lifecycle + memory stats (construens
    /// memory-instance-observability): each lane's live warm set / capacity / in-flight, the lifetime
    /// warm-hit / cold-miss / eviction / instantiation counters + durations, and process RSS vs the
    /// configured per-instance ceiling. A pure read (the serving surface admin-gates it); the warm set
    /// + in-flight are read live under the lane locks, the counters are lock-free atomics.
    pub fn instance_stats(&self) -> crate::instance_stats::InstanceStatsSnapshot {
        use crate::instance_stats::{LaneLive, ProcessMemory, process_rss_bytes};
        fn lane_live<V>(
            cache: &Mutex<LruCache<String, V>>,
            ceiling: usize,
            available: usize,
        ) -> LaneLive {
            let c = cache.lock().unwrap();
            let ceiling = ceiling.max(1);
            LaneLive {
                warm_now: c.len() as u64,
                warm_capacity: c.cap().get() as u64,
                warm_components: c.iter().map(|(k, _)| k.clone()).collect(),
                in_flight: ceiling.saturating_sub(available) as u64,
                lane_ceiling: ceiling as u64,
            }
        }
        let request = lane_live(
            &self.cache,
            self.limits.max_concurrency,
            self.semaphore.available_permits(),
        );
        #[cfg(feature = "messaging")]
        let consumer = lane_live(
            &self.consumer_cache,
            self.async_limits.max_concurrency,
            self.async_semaphore.available_permits(),
        );
        #[cfg(not(feature = "messaging"))]
        let consumer = LaneLive {
            warm_now: 0,
            warm_capacity: 0,
            warm_components: Vec::new(),
            in_flight: 0,
            lane_ceiling: 0,
        };
        #[cfg(feature = "session")]
        let session = lane_live(
            &self.session_cache,
            self.streaming_limits.max_concurrency,
            self.streaming_semaphore.available_permits(),
        );
        #[cfg(not(feature = "session"))]
        let session = LaneLive {
            warm_now: 0,
            warm_capacity: 0,
            warm_components: Vec::new(),
            in_flight: 0,
            lane_ceiling: 0,
        };
        self.stats.snapshot(
            request,
            consumer,
            session,
            ProcessMemory {
                rss_bytes: process_rss_bytes(),
                per_instance_limit_bytes: self.limits.memory_bytes as u64,
            },
        )
    }

    /// Compile a component (cached by `hash`) into a reusable [`ProxyPre`].
    /// Whether a REQUEST-lane component (`hash`) is already compiled + resident in the warm cache —
    /// so the serve path can SKIP re-reading (and, on a remote blob backend, re-FETCHING over the
    /// network) the component bytes it would only discard on a warm hit. A non-promoting peek
    /// (`contains`, no LRU touch): a `true` means [`serve_with_limits`] will hit the cache and never
    /// look at the `wasm` argument, so the caller may pass an empty slice. (A component evicted in the
    /// window between this check and the serve — only possible once the node holds MORE than
    /// `instance_cache_size` distinct components — degrades to a clear, transient compile error on that
    /// one request, not a wrong result; size the cache ≥ your component count to preclude it.)
    pub fn request_component_warm(&self, hash: &str) -> bool {
        self.cache.lock().unwrap().contains(hash)
    }

    /// The CONSUMER-lane analog of [`request_component_warm`](Self::request_component_warm): a
    /// non-promoting peek of the SEPARATE `consumer_cache` (the messaging consumer serves via
    /// `dispatch_message` → `consumer_pre`, not the request `cache`). `true` ⇒ `dispatch_message` will
    /// hit the warm `ConsumerPre` and never look at the bytes, so the caller may pass an empty slice
    /// and skip the per-message component-blob re-read (a remote GET it would only discard). A stale
    /// warm-skip (evicted in the window) degrades to a clear, transient compile error on that one
    /// message (`consumer_pre`'s empty-bytes guard), never a wrong result.
    #[cfg(feature = "messaging")]
    pub fn request_consumer_warm(&self, hash: &str) -> bool {
        self.consumer_cache.lock().unwrap().contains(hash)
    }

    /// Returns the pre-instantiated component and whether this call paid a COLD compile (`true`) vs a
    /// warm-cache hit (`false`) — the per-serve `cold` signal [`serve_lane`] surfaces as `ServeTiming`.
    fn proxy_pre(
        &self,
        hash: &str,
        wasm: &[u8],
    ) -> Result<(ProxyPre<HostState>, bool), HandlerError> {
        if let Some(pre) = self.cache.lock().unwrap().get(hash) {
            self.stats.request.record_warm_hit();
            return Ok((pre.clone(), false));
        }
        // A cold miss needs the bytes. If the caller skipped the read on a stale warm-check (the
        // component was evicted in the window), fail this one request with a clear, retryable message
        // rather than feeding empty bytes into the compiler.
        if wasm.is_empty() {
            return Err(HandlerError::Compile(
                "component not resident and no bytes supplied (evicted between the warm-check and \
                 serve; retry — or raise [handlers] instance_cache_size so it stays warm)"
                    .into(),
            ));
        }
        // Cold miss: compile (the dominant cold-start cost) + insert, noting a capacity eviction.
        let compiled_at = std::time::Instant::now();
        let pre = self.compile(wasm)?;
        let compile = compiled_at.elapsed();
        self.stats
            .request
            .record_cold_miss(compile.as_nanos() as u64);
        // Operator-visible at the default `boatramp=info`: a warm-cache MISS paid a cranelift compile,
        // the term a warm hit avoids — the signal construens needs to tell a cold start from execution.
        // Rare when healthy (once per deploy); frequent only when eviction is churning the cache (the
        // very problem to surface). Level-by-op, mirroring the blob-read-404 lesson.
        tracing::info!(
            component = %hash,
            lane = "request",
            compile_ms = compile.as_millis() as u64,
            "wasm component cold-compiled (warm-cache miss)"
        );
        self.stats
            .request
            .record_evictions(cache_insert_evicted(&self.cache, hash, pre.clone()));
        // Per-component resident-footprint proxy (source wasm length), recorded at compile.
        self.stats.record_resident_bytes(hash, wasm.len() as u64);
        Ok((pre, true))
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
            self.stats.consumer.record_warm_hit();
            return Ok(pre.clone());
        }
        // A cold miss needs the bytes. If the caller skipped the per-message read on a stale
        // warm-check (evicted in the window), fail this one message with a clear, retryable message
        // rather than feeding empty bytes into the compiler. Mirrors `proxy_pre`'s guard.
        if wasm.is_empty() {
            return Err(HandlerError::Compile(
                "consumer component not resident and no bytes supplied (evicted between the \
                 warm-check and dispatch; retry — or raise [handlers] instance_cache_size)"
                    .into(),
            ));
        }
        let compiled_at = std::time::Instant::now();
        let component = Component::from_binary(&self.engine, wasm)
            .map_err(|err| HandlerError::Compile(err.to_string()))?;
        let instance_pre = self
            .build_linker()?
            .instantiate_pre(&component)
            .map_err(|err| HandlerError::Compile(err.to_string()))?;
        let pre = consumer_world::ConsumerPre::new(instance_pre).map_err(|_| {
            HandlerError::Compile("component is not a wasi:messaging consumer".into())
        })?;
        let compile = compiled_at.elapsed();
        self.stats
            .consumer
            .record_cold_miss(compile.as_nanos() as u64);
        tracing::info!(
            component = %hash,
            lane = "consumer",
            compile_ms = compile.as_millis() as u64,
            "wasm component cold-compiled (warm-cache miss)"
        );
        self.stats.consumer.record_evictions(cache_insert_evicted(
            &self.consumer_cache,
            hash,
            pre.clone(),
        ));
        self.stats.record_resident_bytes(hash, wasm.len() as u64);
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
        // A `wasi:messaging` consumer is durable background work (no connected
        // client), so it runs in the async lane — its own concurrency budget and
        // the larger async ceiling, never competing with live requests.
        let _permit = self
            .lane_semaphore(Lane::Async)
            .try_acquire()
            .map_err(|_| {
                self.stats.record_overloaded(hash);
                HandlerError::Overloaded
            })?;
        // Count this component's in-flight invocation for the per-component stats (RAII: decremented
        // on drop, so a trap/early-return can't leak the count).
        let _cguard = self.stats.enter_component(hash);
        let consumer_pre = self.consumer_pre(hash, wasm)?;
        let mut store = self.new_store(bindings, self.effective_limits(Lane::Async, limits));
        let instantiated_at = std::time::Instant::now();
        let consumer = consumer_pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| classify(&e, store.data().oom()))?;
        self.stats
            .consumer
            .record_instantiation(instantiated_at.elapsed().as_nanos() as u64);
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
            // A CLEAN guest `Err` (the consumer's `handle` returned an error value) — distinct from a
            // wasm trap. Carry the guest's error string so the dead-letter is legible as a downstream
            // denial (`consumer-error`), not the opaque `trap` a real panic yields. The string is
            // untrusted guest text; bound it HERE (the guest controls its length) and the DLQ layer
            // sanitizes it (control chars stripped) before an operator sees it.
            Ok(Err(err)) => Err(HandlerError::ConsumerError(
                format!("{err:?}")
                    .chars()
                    .take(MAX_CONSUMER_ERROR_LEN)
                    .collect(),
            )),
            Err(trap) => Err(classify(&trap, store.data().oom())),
        }
    }

    /// Compile + pre-instantiate a **session** component (`session-handler` export), cached by hash.
    #[cfg(feature = "session")]
    fn session_pre(
        &self,
        hash: &str,
        wasm: &[u8],
    ) -> Result<session_world::SessionHostPre<HostState>, HandlerError> {
        if let Some(pre) = self.session_cache.lock().unwrap().get(hash) {
            self.stats.session.record_warm_hit();
            return Ok(pre.clone());
        }
        let compiled_at = std::time::Instant::now();
        let component = Component::from_binary(&self.engine, wasm)
            .map_err(|err| HandlerError::Compile(err.to_string()))?;
        let instance_pre = self
            .build_linker()?
            .instantiate_pre(&component)
            .map_err(|err| HandlerError::Compile(err.to_string()))?;
        let pre = session_world::SessionHostPre::new(instance_pre)
            .map_err(|_| HandlerError::Compile("component is not a session handler".into()))?;
        let compile = compiled_at.elapsed();
        self.stats
            .session
            .record_cold_miss(compile.as_nanos() as u64);
        tracing::info!(
            component = %hash,
            lane = "session",
            compile_ms = compile.as_millis() as u64,
            "wasm component cold-compiled (warm-cache miss)"
        );
        self.stats.session.record_evictions(cache_insert_evicted(
            &self.session_cache,
            hash,
            pre.clone(),
        ));
        Ok(pre)
    }

    /// Drive one **re-entry** of a session handler (`hash`): instantiate the component and call its
    /// `session-handler.handle(input)` with the pending inbound batch + resume checkpoint. The
    /// `bindings` carry the [`SessionController`](crate::SessionController) scoped to this session
    /// (its `send`/`checkpoint`/`close` reach the store) plus the verified principal's tenancy, so
    /// frame-triggered `sql`/`orm` is host-scoped identically to a normal handler. Runs on the async
    /// lane (no connected client on the re-entry itself). `Ok` commits the invocation's sends +
    /// checkpoint; `Err`/trap fails it (the inbound frames redeliver).
    #[cfg(feature = "session")]
    pub async fn dispatch_session(
        &self,
        hash: &str,
        wasm: &[u8],
        batch: SessionBatch,
        bindings: Bindings,
        limits: Limits,
    ) -> Result<(), HandlerError> {
        let _permit = self
            .lane_semaphore(Lane::Async)
            .try_acquire()
            .map_err(|_| HandlerError::Overloaded)?;
        let session_pre = self.session_pre(hash, wasm)?;
        let mut store = self.new_store(bindings, self.effective_limits(Lane::Async, limits));
        let instantiated_at = std::time::Instant::now();
        let session = session_pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| classify(&e, store.data().oom()))?;
        self.stats
            .session
            .record_instantiation(instantiated_at.elapsed().as_nanos() as u64);
        let input = session_world::boatramp::handlers::session_types::SessionInput {
            id: batch.id,
            resumed: batch.resumed,
            frames: batch.frames,
        };
        let result = session
            .boatramp_handlers_session_handler()
            .call_handle(&mut store, &input)
            .await;
        // Close any per-invocation SQL transaction: commit only on a clean re-entry.
        #[cfg(feature = "sql")]
        store
            .data_mut()
            .sql
            .finalize(matches!(result, Ok(Ok(()))))
            .await;
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(HandlerError::Trap(format!(
                "session handler returned error: {err:?}"
            ))),
            Err(trap) => Err(classify(&trap, store.data().oom())),
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
        // `wasi:logging` is host-side observability (captured like stdout/stderr), always linked
        // — not a grantable capability. A guest that imports it emits into the same log sink.
        bindings::wasi_logging::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::wasi_logging::WasiLoggingHost::new(state.bindings.logging())
        })?;
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
        // The typed `orm` binding shares the same per-invocation SQL session (backends +
        // transactions) as the raw `sql` binding above.
        #[cfg(feature = "sql")]
        bindings::orm::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::orm::OrmHost::new(&mut state.table, &mut state.sql)
        })?;
        #[cfg(feature = "messaging")]
        bindings::messaging::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::messaging::MessagingHost::new(state.bindings.messaging())
        })?;
        #[cfg(feature = "messaging")]
        bindings::tenancy::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::tenancy::TenancyHost::new(
                state.bindings.tenancy_present(),
                state.bindings.sealed_principal(),
            )
        })?;
        #[cfg(feature = "messaging")]
        bindings::messaging_stats::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::messaging_stats::StatsHost::new(state.bindings.messaging_stats())
        })?;
        #[cfg(feature = "tenant-secrets")]
        bindings::tenant_secrets::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::tenant_secrets::TenantSecretsHost::new(state.bindings.tenant_secrets())
        })?;
        #[cfg(feature = "invoke")]
        bindings::invoke::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::invoke::InvokeHost::new(&mut state.table, state.bindings.invoke())
        })?;
        #[cfg(feature = "graphql")]
        bindings::graphql::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::graphql::GraphqlHost::new(state.bindings.graphql())
        })?;
        #[cfg(feature = "email")]
        bindings::email::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::email::EmailHost::new(state.bindings.email())
        })?;
        #[cfg(feature = "admin")]
        bindings::admin::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::admin::AdminHost::new(state.bindings.admin())
        })?;
        #[cfg(feature = "migrate")]
        bindings::migrate::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::migrate::MigrateHost::new(state.bindings.migrate())
        })?;
        #[cfg(feature = "capability")]
        bindings::capability::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::capability::CapabilityHost::new(state.bindings.capability())
        })?;
        #[cfg(feature = "blob-upload")]
        bindings::blob_upload::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::blob_upload::BlobUploadHost::new(state.bindings.blob_upload())
        })?;
        #[cfg(feature = "sql")]
        bindings::target_context::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::target_context::TargetContextHost::new(
                state.bindings.tenancy_target_context(),
            )
        })?;
        #[cfg(feature = "session")]
        bindings::session::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::session::SessionHost::new(state.bindings.session())
        })?;
        Ok(linker)
    }

    /// The configured ceiling for `lane`.
    fn lane_ceiling(&self, lane: Lane) -> Limits {
        match lane {
            Lane::Sync => self.limits,
            Lane::Async => self.async_limits,
            Lane::Streaming => self.streaming_limits,
        }
    }

    /// The concurrency gate for `lane` — the sync lane shares the request pool;
    /// the async and streaming lanes each have their own, so no lane can starve
    /// another.
    fn lane_semaphore(&self, lane: Lane) -> &Semaphore {
        match lane {
            Lane::Sync => &self.semaphore,
            Lane::Async => &self.async_semaphore,
            Lane::Streaming => &self.streaming_semaphore,
        }
    }

    /// Clamp `requested` to `lane`'s configured ceiling — a per-invocation
    /// (per-site) override may only *lower* the limits, never raise them.
    fn effective_limits(&self, lane: Lane, requested: Limits) -> Limits {
        let ceiling = self.lane_ceiling(lane);
        // MUTATION SEAM (G-mem): a per-invocation (per-site) `memory_mb` override may only *lower* the
        // lane memory ceiling, never raise it — so a guest can't claim more linear memory than the
        // operator's `*_max_memory_mb` budget. Dropping the `.min(ceiling)` lets the request exceed the
        // ceiling → the gate goes RED.
        let memory_bytes = if lane_gate_mutation().as_deref() == Some("skip_mem_clamp") {
            requested.memory_bytes
        } else {
            requested.memory_bytes.min(ceiling.memory_bytes)
        };
        Limits {
            memory_bytes,
            timeout_ms: requested.timeout_ms.min(ceiling.timeout_ms),
            max_concurrency: requested.max_concurrency.min(ceiling.max_concurrency),
            // A `None` (unmetered) on either side is the larger bound, so the
            // effective fuel is the smaller of any present budgets.
            fuel: min_opt(requested.fuel, ceiling.fuel),
            max_body_bytes: min_opt(requested.max_body_bytes, ceiling.max_body_bytes),
        }
    }

    fn new_store(&self, bindings: Bindings, limits: Limits) -> Store<HostState> {
        // Capture stdout/stderr into the host log sink. The server wires a sink for
        // *every* dispatched invocation (host-side observability, not a guest-requested
        // capability), so this branch is the normal case. Without a sink the guest's
        // stdio is **discarded** — `WasiCtxBuilder` defaults to a null stream; it is never
        // wired to the host's stdout — so guest output reaches an operator only via a sink.
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
        // The memory ceiling is the already-clamped (lane ∧ component) `effective_limits` value; the
        // `MemLimiter` only *observes* a denied grow (for `out-of-memory` classification) without
        // changing the decision.
        let store_limits = MemLimiter {
            inner: StoreLimitsBuilder::new()
                .memory_size(limits.memory_bytes)
                .build(),
            oom: Arc::new(AtomicBool::new(false)),
        };
        #[cfg(feature = "sql")]
        let sql = bindings::sql::SqlSession::for_backends(bindings.sql())
            .with_tenancy(bindings.tenancy());
        let state = HostState {
            table: ResourceTable::new(),
            wasi,
            http: WasiHttpCtx::new(),
            limits: store_limits,
            bindings,
            outbound_timeout: self.outbound_timeout,
            allow_private_egress: self.allow_private_egress,
            self_egress_addrs: self.self_egress_addrs.clone(),
            guest_egress_extra_roots: self.guest_egress_extra_roots.clone(),
            egress_depth: 0,
            egress_nonce: self.egress_nonce,
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
    /// site's caps), on the **sync** lane: a connection-bearing request clamped
    /// to the tight sync ceiling. A site may only lower the memory/timeout,
    /// never raise them.
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
        self.serve_lane(hash, wasm, request, bindings, limits, Lane::Sync)
            .await
            .map(|(response, _timing)| response)
    }

    /// Like [`serve_with_limits`](Self::serve_with_limits) but on the **async**
    /// lane: the durable drain / workflow-step path, clamped to the larger async
    /// ceiling on its own concurrency budget. No client is connected, so a long
    /// background job here never blocks live traffic.
    pub async fn serve_with_limits_async<B>(
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
        self.serve_lane(hash, wasm, request, bindings, limits, Lane::Async)
            .await
            .map(|(response, _timing)| response)
    }

    /// Like [`serve_with_limits`](Self::serve_with_limits) but on the
    /// **streaming** lane: a long-lived, connection-bearing streaming response
    /// (SSE, chunked, agent token streaming), clamped to the larger streaming
    /// ceiling on its own concurrency budget — isolated from both the fast sync
    /// request pool and the durable async drain.
    pub async fn serve_with_limits_streaming<B>(
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
        self.serve_lane(hash, wasm, request, bindings, limits, Lane::Streaming)
            .await
            .map(|(response, _timing)| response)
    }

    /// The shared serve core: acquire `lane`'s concurrency permit, clamp to `lane`'s ceiling, and
    /// drive the guest. Returns the response plus a [`ServeTiming`] (`cold` = this serve paid a
    /// compile; `instantiate_us` = the per-invocation instantiate cost) so the server can attribute
    /// per-invocation latency. The thin `serve_with_limits*` wrappers drop the timing for the many
    /// callers that don't need it; the metered HTTP + function-invoke paths call this directly.
    pub async fn serve_lane<B>(
        &self,
        hash: &str,
        wasm: &[u8],
        request: http::Request<B>,
        bindings: Bindings,
        limits: Limits,
        lane: Lane,
    ) -> Result<(http::Response<HyperOutgoingBody>, ServeTiming), HandlerError>
    where
        B: HttpBody<Data = Bytes> + Send + 'static,
        B::Error: std::fmt::Display + Send,
    {
        let _permit = self.lane_semaphore(lane).try_acquire().map_err(|_| {
            self.stats.record_overloaded(hash);
            HandlerError::Overloaded
        })?;
        // Count this component's in-flight invocation (RAII: decremented on drop — same scope as the
        // lane permit, so a trap/early-return can't leak the count).
        let _cguard = self.stats.enter_component(hash);
        let (proxy_pre, cold) = self.proxy_pre(hash, wasm)?;

        let effective = self.effective_limits(lane, limits);
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
        // Inbound self-egress recursion depth (nonce-verified — an external client can't forge it;
        // a fresh external request is depth 0, a guest self-call continues the chain at depth+1). The
        // SAME verification the request dispatch uses to skip the serve-admission gate for a
        // re-entrant self-call, so the two can never drift.
        let egress_depth = self.verified_self_egress_depth(&parts.headers);
        store.data_mut().egress_depth = egress_depth;
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
        let instantiated_at = std::time::Instant::now();
        let proxy = proxy_pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| classify(&e, store.data().oom()))?;
        let instantiate_elapsed = instantiated_at.elapsed();
        self.stats
            .request
            .record_instantiation(instantiate_elapsed.as_nanos() as u64);
        // Per-serve timing surfaced to the server for the per-invocation `cold`/`instantiate_ms`
        // signal (construens ask #3): distinguishes a cold (re)compile + the instantiate cost from
        // the handler body and from queueing.
        let timing = ServeTiming {
            cold,
            instantiate_us: instantiate_elapsed.as_micros() as u64,
        };

        // The `Store` moves into the drive task below, so grab a clone of the OOM flag now to read
        // back after a trap (the moved store is otherwise unreachable from here).
        let oom_flag = store.data().oom_flag();

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
            Ok(Ok(response)) => Ok((response, timing)),
            // Guest explicitly produced an error response.
            Ok(Err(code)) => Err(HandlerError::Trap(format!("{code:?}"))),
            // Sender dropped before a response — the guest trapped/returned first.
            Err(_) => match task.await {
                Ok(Ok(())) => Err(HandlerError::NoResponse),
                Ok(Err(trap)) => Err(classify(&trap, oom_flag.load(Ordering::Relaxed))),
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

/// Classify a wasmtime execution error: an epoch interrupt is a wall-clock timeout, an out-of-fuel
/// trap is the CPU budget exhausted, a trap that follows a denied linear-memory growth (`oom`) is
/// memory exhaustion, and anything else is a generic guest trap. The explicit interrupt/fuel trap
/// kinds take precedence over the inferred `oom` flag — a timeout is a timeout even if the guest also
/// brushed its memory ceiling earlier in the run.
fn classify(err: &wasmtime::Error, oom: bool) -> HandlerError {
    match err.downcast_ref::<wasmtime::Trap>() {
        Some(wasmtime::Trap::Interrupt) => HandlerError::Timeout,
        Some(wasmtime::Trap::OutOfFuel) => HandlerError::OutOfFuel,
        _ if oom => HandlerError::OutOfMemory,
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
        build_engine(None).expect("engine builds");
    }

    /// The reentrant-deadlock guard (image-serve-latency Ask B, security review HIGH): the request
    /// dispatch skips the per-component serve-admission gate for a re-entrant self-egress call, keyed
    /// on `verified_self_egress_depth > 0`. That skip MUST be forge-proof — an external client passing
    /// a bogus `x-boatramp-egress-depth` must verify to depth 0 (still gated), or the gate could be
    /// bypassed and the park re-created. Only the marker carrying THIS process's nonce is trusted.
    #[tokio::test]
    async fn verified_self_egress_depth_trusts_only_the_process_nonce() {
        let engine = HandlerEngine::new(Limits::default(), 4).expect("engine");
        let nonce = engine.egress_nonce;
        let hdr = |val: String| {
            let mut h = http::HeaderMap::new();
            h.insert(SELF_EGRESS_DEPTH_HEADER, val.parse().unwrap());
            h
        };
        // Correct process nonce ⇒ the depth is trusted (a genuine self-call chain).
        assert_eq!(
            engine.verified_self_egress_depth(&hdr(format!("{nonce:x}:3"))),
            3
        );
        // Wrong nonce ⇒ forged ⇒ depth 0 (cannot be used to skip/bypass the gate).
        assert_eq!(
            engine.verified_self_egress_depth(&hdr(format!("{:x}:3", nonce.wrapping_add(1)))),
            0
        );
        // Absent / malformed marker ⇒ fresh external request at depth 0.
        assert_eq!(
            engine.verified_self_egress_depth(&http::HeaderMap::new()),
            0
        );
        assert_eq!(engine.verified_self_egress_depth(&hdr("garbage".into())), 0);
    }

    /// Anti-hollow gate (image-serve-latency Ask A): the wasm compile cache MUST be pinned to the
    /// operator's persistent data volume so a component's compiled artifact survives a restart — the
    /// first request after a roll then deserializes (ms) instead of paying a cranelift compile (and,
    /// on a small node, a concurrent burst stampeding behind that one compile → the measured 13–16 s
    /// first reload). Proven by compiling a real component under a threaded data dir and asserting the
    /// artifact lands THERE. The `#[cfg(test)]` severance seam then forces the ephemeral default even
    /// though a data dir was threaded, and the SAME assertion goes empty — so a hollow "pinning" that
    /// didn't actually pin (or a reversion to `cache_config_load_default`) fails the gate.
    #[test]
    fn compile_cache_durable_gate() {
        const HTTP_200: &[u8] = include_bytes!("../tests/fixtures/http-200.wasm");

        let unique = |tag: &str| {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            std::env::temp_dir().join(format!(
                "boatramp-cachegate-{}-{nanos}-{tag}",
                std::process::id()
            ))
        };
        let wait_nonempty = |dir: &Path| -> bool {
            for _ in 0..50 {
                if std::fs::read_dir(dir)
                    .map(|mut e| e.next().is_some())
                    .unwrap_or(false)
                {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            false
        };
        let is_empty = |dir: &Path| -> bool {
            std::fs::read_dir(dir)
                .map(|mut e| e.next().is_none())
                .unwrap_or(true)
        };

        // --- Real path: the cache is pinned to the data volume ---
        let data_dir = unique("real");
        std::fs::create_dir_all(&data_dir).expect("mk data dir");
        let cache_root = data_dir.join("wasmtime-cache");
        force_compile_cache_default(false);
        {
            let engine = build_engine(Some(&data_dir)).expect("engine with pinned cache");
            Component::new(&engine, HTTP_200).expect("component compiles");
        }
        // The cache worker may flush just after `Component::new` returns, so poll.
        let durable = wait_nonempty(&cache_root);

        // --- Mutation: force the ephemeral default even though a data dir was threaded ---
        let data_dir2 = unique("mutated");
        std::fs::create_dir_all(&data_dir2).expect("mk data dir 2");
        let cache_root2 = data_dir2.join("wasmtime-cache");
        force_compile_cache_default(true);
        {
            let engine = build_engine(Some(&data_dir2)).expect("engine (mutated)");
            Component::new(&engine, HTTP_200).expect("component compiles (mutated)");
        }
        force_compile_cache_default(false);
        // Give an async cache worker the same grace, then assert the data volume stayed empty (the
        // mutated compile went to the default location, never `<data_dir2>/wasmtime-cache`).
        std::thread::sleep(Duration::from_millis(500));
        let mutated_empty = !cache_root2.exists() || is_empty(&cache_root2);

        // Best-effort cleanup before asserting, so a failure never leaks temp dirs.
        let _ = std::fs::remove_dir_all(&data_dir);
        let _ = std::fs::remove_dir_all(&data_dir2);

        assert!(
            durable,
            "compile cache must be populated under the data volume ({})",
            cache_root.display()
        );
        assert!(
            mutated_empty,
            "MUTATION must defeat durability: nothing should land under the data volume, but {} is populated",
            cache_root2.display()
        );
        println!("COMPILE-CACHE DURABLE OK");
    }

    #[test]
    fn classify_maps_oom_flag_but_explicit_trap_kinds_win() {
        // A denied linear-memory growth (the `oom` flag) turns a generic trap into `OutOfMemory`…
        let generic = wasmtime::Error::from(wasmtime::Trap::UnreachableCodeReached);
        assert!(matches!(
            classify(&generic, true),
            HandlerError::OutOfMemory
        ));
        // …but without the flag the same trap stays a plain `Trap`.
        assert!(matches!(classify(&generic, false), HandlerError::Trap(_)));
        // The explicit interrupt/fuel trap kinds take precedence over the inferred flag: a run that
        // both brushed its memory ceiling and then timed out (or ran out of fuel) is reported as the
        // timeout / fuel outcome, not OOM.
        let interrupt = wasmtime::Error::from(wasmtime::Trap::Interrupt);
        assert!(matches!(classify(&interrupt, true), HandlerError::Timeout));
        let fuel = wasmtime::Error::from(wasmtime::Trap::OutOfFuel);
        assert!(matches!(classify(&fuel, true), HandlerError::OutOfFuel));
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
    async fn instance_stats_fresh_engine_reports_empty_warm_set_and_live_capacity() {
        // A freshly-built engine has nothing warm: zero lifetime counters, an empty warm set, and the
        // LRU capacity + lane ceiling read LIVE from the engine (the wiring the counter unit tests
        // can't cover). Also the per-instance memory limit for headroom context.
        let engine = HandlerEngine::new(Limits::default(), 8).expect("engine builds");
        let snap = engine.instance_stats();
        assert_eq!(snap.request.warm_now, 0);
        assert_eq!(
            snap.request.warm_capacity, 8,
            "the LRU capacity is read live"
        );
        assert!(snap.request.warm_components.is_empty());
        assert_eq!(
            snap.request.in_flight, 0,
            "nothing in flight on a fresh engine"
        );
        assert_eq!(
            snap.request.lane_ceiling,
            Limits::default().max_concurrency as u64
        );
        assert_eq!(snap.request.warm_hits, 0);
        assert_eq!(snap.request.cold_misses, 0);
        assert_eq!(snap.request.evictions, 0);
        assert_eq!(snap.request.instantiations, 0);
        assert_eq!(
            snap.memory.per_instance_limit_bytes,
            Limits::default().memory_bytes as u64
        );
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

    /// Anti-hollow gates for the two async-lane security clamps: the raisable per-lane memory
    /// ceiling (G-mem — a per-invocation override may only *lower* it) and the per-consumer
    /// concurrency floor (G-conc — a declared `max_concurrency` may only *narrow* the lane budget).
    /// Each clamp has a clean gate (seam UNARMED → the SECURE behavior holds) paired with a `mutation_`
    /// gate that arms `BOATRAMP_ASYNCLANE_MUTATION` and asserts the clamp is gone (RED under mutation).
    /// The four share a serial lock because they toggle a process-global env var; the mutation only
    /// diverges from the clean path when a request EXCEEDS a ceiling (which only these gates
    /// construct), so a concurrent reader elsewhere is behaviorally unaffected.
    #[cfg(feature = "messaging")]
    mod lane_clamp_gates {
        use super::*;
        use std::sync::Mutex;

        static ENV_LOCK: Mutex<()> = Mutex::new(());

        fn engine_with_async(mem_mb: usize, max_conc: usize) -> HandlerEngine {
            let async_ = Limits {
                memory_bytes: mem_mb * 1024 * 1024,
                max_concurrency: max_conc,
                ..Limits::default()
            };
            HandlerEngine::new(Limits::default(), 4)
                .expect("engine builds")
                .with_async_limits(async_)
        }

        /// G-mem (clean): a per-invocation `memory_mb` override ABOVE the async lane ceiling clamps
        /// DOWN to the ceiling — a guest can never claim more linear memory than `async_max_memory_mb`.
        #[tokio::test]
        async fn mem_override_clamps_to_the_lane_ceiling() {
            let _g = ENV_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            unsafe { std::env::remove_var("BOATRAMP_ASYNCLANE_MUTATION") };
            let engine = engine_with_async(128, 8);
            let requested = Limits {
                memory_bytes: 512 * 1024 * 1024,
                ..Limits::default()
            };
            let eff = engine.effective_limits(Lane::Async, requested);
            assert_eq!(
                eff.memory_bytes,
                128 * 1024 * 1024,
                "a 512 MiB request must clamp to the 128 MiB async lane ceiling"
            );
        }

        /// A component with NO memory cap — the scheduler passes `usize::MAX` — inherits the lane
        /// ceiling (the whole point of raising `*_max_memory_mb`: an uncapped component on the lane
        /// gets the headroom without restating it). `min(MAX, ceiling) == ceiling`.
        #[tokio::test]
        async fn uncapped_memory_request_inherits_the_lane_ceiling() {
            let _g = ENV_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            unsafe { std::env::remove_var("BOATRAMP_ASYNCLANE_MUTATION") };
            let engine = engine_with_async(384, 8);
            let requested = Limits {
                memory_bytes: usize::MAX,
                ..Limits::default()
            };
            let eff = engine.effective_limits(Lane::Async, requested);
            assert_eq!(
                eff.memory_bytes,
                384 * 1024 * 1024,
                "an uncapped component must inherit the raised 384 MiB async lane ceiling"
            );
        }

        /// G-mem (mutation): with `skip_mem_clamp` armed the oversized request escapes the ceiling.
        #[tokio::test]
        async fn mutation_mem_override_escapes_the_ceiling() {
            let _g = ENV_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let engine = engine_with_async(128, 8);
            let requested = Limits {
                memory_bytes: 512 * 1024 * 1024,
                ..Limits::default()
            };
            unsafe { std::env::set_var("BOATRAMP_ASYNCLANE_MUTATION", "skip_mem_clamp") };
            let eff = engine.effective_limits(Lane::Async, requested);
            unsafe { std::env::remove_var("BOATRAMP_ASYNCLANE_MUTATION") };
            assert_eq!(
                eff.memory_bytes,
                512 * 1024 * 1024,
                "with the clamp removed the oversized request escapes the ceiling (gate RED)"
            );
        }

        /// G-conc (clean): a per-consumer cap ABOVE the async lane budget floors to the lane budget —
        /// a consumer can never run more concurrent handlers than `async_max_concurrency`.
        #[tokio::test]
        async fn consumer_cap_floors_to_the_lane_budget() {
            let _g = ENV_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            unsafe { std::env::remove_var("BOATRAMP_ASYNCLANE_MUTATION") };
            let engine = engine_with_async(64, 4);
            let gate = engine.consumer_gate("site\u{1}topic\u{1}group", 100);
            assert_eq!(
                gate.available_permits(),
                4,
                "a consumer cap of 100 must floor to the async lane budget of 4"
            );
        }

        /// G-conc (mutation): with `skip_consumer_clamp` armed the consumer semaphore is sized to the
        /// full requested 100, exceeding the lane budget.
        #[tokio::test]
        async fn mutation_consumer_cap_escapes_the_lane_budget() {
            let _g = ENV_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let engine = engine_with_async(64, 4);
            unsafe { std::env::set_var("BOATRAMP_ASYNCLANE_MUTATION", "skip_consumer_clamp") };
            let gate = engine.consumer_gate("site\u{1}topic\u{1}group", 100);
            unsafe { std::env::remove_var("BOATRAMP_ASYNCLANE_MUTATION") };
            assert_eq!(
                gate.available_permits(),
                100,
                "with the floor removed the consumer cap escapes the lane budget (gate RED)"
            );
        }
    }

    async fn egress(uri: &str, tls: bool) -> Result<(), ErrorCode> {
        egress_target_allowed(&uri.parse().unwrap(), tls, false, &[], 0)
            .await
            .map(|_| ())
    }

    async fn egress_priv(uri: &str, tls: bool) -> Result<(), ErrorCode> {
        egress_target_allowed(&uri.parse().unwrap(), tls, true, &[], 0)
            .await
            .map(|_| ())
    }

    /// Self-egress: with the instance's own serve socket in the allow-set, a guest may reach
    /// it even under the strict (private-blocked) posture — capped against recursion depth —
    /// while other loopback/private targets stay blocked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn egress_guard_allows_self_socket_capped_by_depth() {
        let self_sock: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let plan = |uri: &'static str, depth: u32| async move {
            egress_target_allowed(&uri.parse().unwrap(), false, false, &[self_sock], depth).await
        };
        // The instance's own socket is permitted (private blocked otherwise) and marks the
        // outgoing call as self at depth+1.
        let ok = plan("http://127.0.0.1:8080/api", 0).await.unwrap();
        assert_eq!(ok.self_depth, Some(1));
        // A *different* loopback port is not the self socket → still blocked.
        assert!(matches!(
            plan("http://127.0.0.1:9999/", 0).await,
            Err(ErrorCode::DestinationIpProhibited)
        ));
        // The self chain is depth-capped: at the max, one more hop is refused.
        assert_eq!(
            plan("http://127.0.0.1:8080/", MAX_SELF_EGRESS_DEPTH - 1)
                .await
                .unwrap()
                .self_depth,
            Some(MAX_SELF_EGRESS_DEPTH)
        );
        assert!(matches!(
            plan("http://127.0.0.1:8080/", MAX_SELF_EGRESS_DEPTH).await,
            Err(ErrorCode::DestinationIpProhibited)
        ));
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

    /// With `allow_guest_private_egress` on (trusted single-tenant/dev posture), the SSRF
    /// gate opens for private/loopback addresses — but the URI still has to be valid.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn egress_guard_allows_private_when_posture_permits() {
        for allowed in [
            "http://127.0.0.1/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "https://[::1]:8443/",
        ] {
            assert!(
                egress_priv(allowed, allowed.starts_with("https"))
                    .await
                    .is_ok(),
                "{allowed} should be permitted under allow_guest_private_egress"
            );
        }
        // Structural refusals still hold regardless of the knob.
        assert!(matches!(
            egress_priv("/relative-only", false).await,
            Err(ErrorCode::HttpRequestUriInvalid)
        ));
    }
}

/// The dev-posture guest-egress extra-CA gate: a REAL loopback TLS handshake proving
/// [`guest_egress_client_config`] trusts an operator-supplied CA **only when supplied**, and never
/// bypasses verification. This is the boatramp-side hard gate for the extra-CA feature (construens'
/// compiled-guest OIDC back-channel test is the end-to-end companion).
#[cfg(test)]
mod egress_tls_tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

    /// Mint a throwaway CA + a `localhost` leaf signed by it. Returns (ca_der, server_chain, key).
    fn ca_and_leaf() -> (
        CertificateDer<'static>,
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
    ) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        let ca_der = ca_cert.der().clone();
        let chain = vec![leaf_cert.der().clone(), ca_cert.der().clone()];
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        (ca_der, chain, key)
    }

    /// A one-shot loopback rustls server presenting `chain`/`key`; returns its bound addr.
    async fn spawn_tls_server(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> std::net::SocketAddr {
        let cfg = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                let _ = acceptor.accept(tcp).await; // drive the handshake; result unused
            }
        });
        addr
    }

    /// Does a guest-egress client trusting `extra` complete a TLS handshake to `addr`?
    async fn handshakes(addr: std::net::SocketAddr, extra: &[CertificateDer<'static>]) -> bool {
        let Ok(cfg) = guest_egress_client_config(extra) else {
            return false;
        };
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg));
        let Ok(tcp) = tokio::net::TcpStream::connect(addr).await else {
            return false;
        };
        let name = ServerName::try_from("localhost").unwrap();
        connector.connect(name, tcp).await.is_ok()
    }

    #[tokio::test]
    async fn guest_egress_extra_ca_is_trusted_only_when_supplied() {
        let (ca, chain, key) = ca_and_leaf();
        // WITH the operator CA in the extra set → the handshake to the test-CA server succeeds
        // (the CA is a new trust anchor, so the leaf verifies — real HTTPS, just an added root).
        let addr = spawn_tls_server(chain.clone(), key.clone_key()).await;
        assert!(
            handshakes(addr, std::slice::from_ref(&ca)).await,
            "an operator-supplied extra CA is trusted ⇒ the handshake succeeds"
        );
        // WITHOUT it (the default, webpki-only trust) → the SAME server is rejected: verification is
        // still fully performed, so an unknown-CA cert fails the handshake (never a bypass).
        let addr2 = spawn_tls_server(chain, key).await;
        assert!(
            !handshakes(addr2, &[]).await,
            "no extra CA ⇒ the test-CA server is rejected (verification is not bypassed)"
        );
        println!(
            "GUEST-EGRESS EXTRA-CA OK: the guest outbound TLS client trusts an operator-supplied \
             extra CA ONLY when supplied (a real loopback handshake to a test-CA server succeeds \
             with it, is rejected without it); trust is WIDENED, never bypassed — the webpki roots \
             still apply and full certificate verification is always performed."
        );
    }
}
