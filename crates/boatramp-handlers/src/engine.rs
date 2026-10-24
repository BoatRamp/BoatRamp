//! The wasmtime component engine: compile (cached by blob hash), instantiate
//! per request, drive `wasi:http/incoming-handler`, and enforce limits.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
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
use wasmtime_wasi::sockets::SocketAddrUse;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::p2::bindings::ProxyPre;
use wasmtime_wasi_http::p2::bindings::http::types::Scheme;
use wasmtime_wasi_http::p2::body::{HyperIncomingBody, HyperOutgoingBody};
use wasmtime_wasi_http::{WasiHttpCtx, WasiHttpCtxView, WasiHttpHooks, WasiHttpView};

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
        imports: { default: async },
        exports: { default: async },
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
        imports: { default: async },
        exports: { default: async },
    });
}

// The tcp-connection-host world: the export caller for `tcp-connection-handler.handle`, which the host
// re-enters ONCE per already-accepted inbound connection (PLAN-handler-tcp-inbound). The world EXPORTS
// the handler and imports only `wasi:io` — mapped here to the SAME `wasmtime_wasi::p2::bindings::io` host
// types the engine linker already serves (`add_to_linker_async`), so the `input-stream`/`output-stream`
// the host pushes into the store table (`AsyncReadStream`/`AsyncWriteStream`) are the resource type the
// generated `call_handle` expects. The guest receives NO `wasi:sockets` (the socket host's deny-all
// default stands; no permissive `socket_addr_check`, no `allow_tcp` for this lane).
#[cfg(feature = "tcp-listener")]
mod tcp_connection_world {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/tcp-connection-host",
        imports: { default: async },
        exports: { default: async },
        with: {
            "wasi:io": wasmtime_wasi::p2::bindings::io,
        },
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
/// Domain-separation tag for the AOT engine fingerprint (cold-start cap-req 09). Bump the
/// suffix if the fingerprint derivation ever changes, to partition old artifacts out.
const AOT_FINGERPRINT_DOMAIN: &[u8] = b"boatramp-aot-fingerprint-v2";

/// A `std::hash::Hasher` that feeds the hashed bytes into SHA-256, so a value implementing
/// `Hash` (here wasmtime's `precompile_compatibility_hash()`, which is only exposed as
/// `impl Hash`) can be reduced to a full 32-byte digest rather than a lossy 64-bit `finish`.
/// Used only by [`HandlerEngine::artifact_fingerprint`]; `finish` returns a valid (hash-derived)
/// u64 so the impl is well-behaved if ever reused, but the fingerprint path finalizes `.0` directly.
struct Sha256Hasher(sha2::Sha256);

impl std::hash::Hasher for Sha256Hasher {
    fn write(&mut self, bytes: &[u8]) {
        sha2::Digest::update(&mut self.0, bytes);
    }
    fn finish(&self) -> u64 {
        let out = sha2::Digest::finalize(self.0.clone());
        u64::from_le_bytes(out[..8].try_into().expect("sha256 ≥ 8 bytes"))
    }
}

fn base_config(cache_dir: Option<&Path>) -> Result<Config, HandlerError> {
    let mut config = Config::new();
    config.wasm_component_model(true);
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
/// `cache_dir` is the operator's **persistent data volume**; the cache is pinned to
/// `<cache_dir>/wasmtime-cache` via wasmtime's programmatic [`wasmtime::Cache`] API (wasmtime 49+ —
/// no config file on disk). This matters because wasmtime's default location resolves to
/// `~/.cache/wasmtime` — the *ephemeral container rootfs* on a distroless node — so it would be WIPED
/// on every restart/roll, and the first visitor after each deploy would eat the full compile (and, on
/// a small node, a concurrent burst stampedes behind it). `None` (tests, or a caller without a data
/// dir) leaves caching disabled.
fn configure_compile_cache(config: &mut Config, cache_dir: Option<&Path>) {
    // `#[cfg(test)]` severance seam: when forced, ignore the data dir and take the `None` (no-cache)
    // branch even though a dir was threaded — so the durability gate can prove its "cache files land
    // under the data volume" assertion actually depends on this pinning (the mutation makes nothing
    // land there → the gate's data-dir check goes empty).
    #[cfg(test)]
    let cache_dir = if compile_cache_mutation_forces_default() {
        None
    } else {
        cache_dir
    };
    let Some(dir) = cache_dir else {
        // No data dir (tests, or a caller without one): leave caching disabled.
        return;
    };
    match build_persistent_cache(dir) {
        Ok(cache) => {
            config.cache(Some(cache));
        }
        Err(e) => tracing::warn!(
            target: "boatramp::handler",
            data_dir = %dir.display(),
            error = %e,
            "wasm compile cache could not be pinned to the data volume; serving continues WITHOUT a \
             persisted cache (components recompile on the first request after each restart)"
        ),
    }
}

/// Build a persistent [`wasmtime::Cache`] pinned to `<data_dir>/wasmtime-cache` on the operator's data
/// volume. Returns an error (for the caller to log + degrade) if the dir can't be created or the cache
/// can't be built. The directory is created `0700` (defense-in-depth: the cache holds EXECUTABLE
/// native artifacts a cache hit loads as host code, so a group/other-writable `/data` must not let
/// another local principal plant a forged one; it is not content-MAC'd).
fn build_persistent_cache(data_dir: &Path) -> Result<wasmtime::Cache, HandlerError> {
    let cache_root = data_dir.join("wasmtime-cache");
    std::fs::create_dir_all(&cache_root)
        .map_err(|e| HandlerError::Internal(format!("create {}: {e}", cache_root.display())))?;
    restrict_perms(&cache_root, 0o700);
    let mut cache_config = wasmtime::CacheConfig::new();
    cache_config.with_directory(&cache_root);
    let cache = wasmtime::Cache::new(cache_config)
        .map_err(|e| HandlerError::Internal(format!("build wasm compile cache: {e}")))?;
    tracing::info!(
        target: "boatramp::handler",
        cache_dir = %cache_root.display(),
        "wasm compile cache pinned to the persistent data volume (survives restarts)"
    );
    Ok(cache)
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
/// latency (a latency-observability ask): `cold` is whether this serve paid a cranelift (re)compile vs reused a
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

/// Default streaming-lane idle cap (ms) — a streaming response that emits no body frame for this
/// long is torn down and its slot reclaimed (PLAN-handler-stream-lifecycle GAP2). 600 s matches the
/// `[stream]` SSE fan-out's idle window, so a well-behaved heartbeat-sending stream is never killed
/// while a silent (slowloris) one is. Overridable per node via `with_streaming_idle_ms`.
const DEFAULT_STREAMING_IDLE_MS: u64 = 600_000;

/// Default per-dial CONNECT timeout for the `tcp-egress` capability (`PLAN-handler-tcp-egress`
/// Build A, mailroom #15): bounds the TCP connect AND the TLS handshake together. Overridable via
/// [`HandlerEngine::with_tcp_egress_timeouts`].
#[cfg(feature = "tcp-egress")]
const DEFAULT_TCP_EGRESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default per-dial READ/IDLE timeout for `tcp-egress`: how long the peer may go silent after the
/// handshake before the connection's streams surface a timeout. Overridable via
/// [`HandlerEngine::with_tcp_egress_timeouts`].
#[cfg(feature = "tcp-egress")]
const DEFAULT_TCP_EGRESS_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// rather than a generic crash (an async-lane-memory-budget request).
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
    /// This invocation's guest-egress policy, carried as the `wasi:http` [`WasiHttpHooks`] so the
    /// SSRF guard + self-egress-depth cap + dev-posture extra-CA send run on every guest outbound
    /// request. (wasmtime 49 moved the outbound-send override off `WasiHttpView::send_request` onto
    /// this hooks type; [`GuestEgressHooks`] carries the per-invocation config.)
    http_hooks: GuestEgressHooks,
    /// Whether this invocation's guest may dial out through the `tcp-egress` capability (copied
    /// from the engine's `allow_tcp_egress` posture — the EXACT SAME flag that gates the raw
    /// `wasi:sockets` outbound-TCP capability, `PLAN-handler-tcp-egress` Build A / mailroom #15). No
    /// new posture knob; `false` is the deny-by-default.
    #[cfg(feature = "tcp-egress")]
    tcp_egress_enabled: bool,
    /// Per-dial CONNECT timeout for `tcp-egress` (copied from the engine).
    #[cfg(feature = "tcp-egress")]
    tcp_egress_connect_timeout: Duration,
    /// Per-dial READ/IDLE timeout for `tcp-egress` (copied from the engine).
    #[cfg(feature = "tcp-egress")]
    tcp_egress_idle_timeout: Duration,
    /// The invocation's SQL transaction state (begun lazily on first query).
    #[cfg(feature = "sql")]
    sql: bindings::sql::SqlSession,
    /// Live wire-security of THIS host-owned listener connection (mailroom cap-req #16), read by the
    /// `tcp-connection-context` import. `None` for every non-listener invocation (request / consumer
    /// / HTTP-session), which the binding fail-closes to `plaintext`. The listener dispatch
    /// (`dispatch_tcp_connection` / `dispatch_session_inner`) sets it after `new_store`; for a
    /// STARTTLS listener the pump flips it to TLS on upgrade through the shared handle.
    #[cfg(feature = "tcp-listener")]
    conn_security: Option<bindings::tcp_connection_context::ConnectionSecurity>,
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

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}
impl WasiHttpView for HostState {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            hooks: &mut self.http_hooks,
            table: &mut self.table,
            ctx: &mut self.http,
        }
    }
}

/// Per-invocation guest-egress policy, carried as the `wasi:http` [`WasiHttpHooks`] — wasmtime 49
/// moved the outbound-send override here from `WasiHttpView::send_request`. The security logic is
/// unchanged from the pre-49 override: resolve-and-refuse a non-globally-routable target (SSRF),
/// depth-cap a self-call over loopback, and widen TLS trust ONLY when an operator supplied extra
/// roots (the dev-posture option). `Default` ⇒ the closed posture (no private egress, no
/// self-egress, stock webpki trust).
#[derive(Default)]
struct GuestEgressHooks {
    /// Ceiling on this invocation's outbound connect + first-byte wait (from the engine).
    outbound_timeout: Option<Duration>,
    /// Whether this invocation may reach a private/loopback address. `false` is the SSRF default.
    allow_private_egress: bool,
    /// The instance's own serve socket(s) a guest self-call may reach (empty ⇒ self-egress off).
    self_egress_addrs: Arc<[SocketAddr]>,
    /// Operator-supplied EXTRA trust anchors for this invocation's egress TLS client. Empty ⇒ the
    /// stock webpki-only sender.
    guest_egress_extra_roots: Arc<[rustls::pki_types::CertificateDer<'static>]>,
    /// This invocation's inbound self-egress recursion depth (validated against `egress_nonce`).
    egress_depth: u32,
    /// The per-process nonce that authenticates a self-egress depth marker.
    egress_nonce: u64,
}

impl WasiHttpHooks for GuestEgressHooks {
    /// SSRF egress guard for **guest** outbound HTTP: before sending, resolve the destination and
    /// refuse it if any resolved address is not globally routable (loopback / private / link-local /
    /// CGNAT / the cloud-metadata IP). An adversarial guest therefore cannot reach internal
    /// infrastructure via `wasi:http`; public destinations pass through to the default sender. (The
    /// operator-config `proxy` rewrite has its own IP-pinning guard in the server.)
    fn send_request(
        &mut self,
        mut request: http::Request<wasmtime_wasi_http::WasiBody>,
        options: Option<wasmtime_wasi_http::RequestOptions>,
        _fut: Box<dyn Future<Output = Result<(), wasmtime_wasi_http::Error>> + Send>,
    ) -> Box<
        dyn Future<
                Output = Result<
                    (
                        http::Response<wasmtime_wasi_http::WasiBody>,
                        Box<dyn Future<Output = Result<(), wasmtime_wasi_http::Error>> + Send>,
                    ),
                    wasmtime_wasi_http::Error,
                >,
            > + Send,
    > {
        // Bound a hung upstream on its own terms (connect + first byte), so it can't silently ride
        // the whole invocation budget. The between-bytes timeout is left alone so a slow streaming
        // body (e.g. an LLM token stream) is not cut mid-flight.
        let mut options = options.unwrap_or_default();
        if let Some(timeout) = self.outbound_timeout {
            options.connect_timeout = Some(timeout);
            options.first_byte_timeout = Some(timeout);
        }
        // TLS is derived from the request scheme (the pre-49 `config.use_tls` bool is gone).
        let use_tls = request.uri().scheme() == Some(&http::uri::Scheme::HTTPS);
        let allow_private = self.allow_private_egress;
        let self_addrs = self.self_egress_addrs.clone();
        let egress_depth = self.egress_depth;
        let egress_nonce = self.egress_nonce;
        let extra_roots = self.guest_egress_extra_roots.clone();
        Box::new(async move {
            let plan = egress_target_allowed(
                request.uri(),
                use_tls,
                allow_private,
                &self_addrs,
                egress_depth,
            )
            .await?;
            // A self-call carries its (nonce-stamped) recursion depth so the re-entering invocation
            // sees it and the gate can cap the chain.
            if let Some(next) = plan.self_depth
                && let Ok(v) = format!("{egress_nonce:x}:{next}").parse()
            {
                request.headers_mut().insert(SELF_EGRESS_DEPTH_HEADER, v);
            }
            // Connect to the IP(s) the gate just resolved AND validated — never re-resolve the
            // hostname (that second `lookup_host` is the DNS-rebinding TOCTOU: an adversarial
            // resolver could return an internal IP between the SSRF check and the connect). SNI +
            // Host stay the original hostname. `extra_roots` empty ⇒ stock webpki-only trust; the
            // dev-posture extra-CA set widens it. This one sender replaces both the stock
            // `default_send_request` and the former extra-roots-only path.
            send_guest_request(request, options, use_tls, &extra_roots, &plan.addrs).await
        })
    }
}

/// Build the guest-egress TLS client config trusting the webpki roots **⊕** the operator's `extra_roots`.
///
/// This is the security-critical core of the dev-posture extra-CA option, factored out so it can be
/// exercised by a real loopback-TLS handshake test. It **adds** trust anchors — server-certificate
/// verification is still fully performed by rustls against the (widened) root set; it never disables
/// verification or accepts an unpinned cert. With `extra_roots` empty this is exactly the stock trust
/// set (webpki only). An explicit aws-lc-rs provider is used so the config does not depend on a
/// process-default `CryptoProvider` having been installed.
///
/// `pub(crate)` (mailroom #15 Build A): the `tcp-egress` host binding reuses this EXACT builder for
/// its own TLS dial — "the verifying rustls `ClientConfig`" the task calls out — rather than forking
/// a second copy. Same trust set, same explicit provider, same full verification.
pub(crate) fn guest_egress_client_config(
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<rustls::ClientConfig, wasmtime_wasi_http::Error> {
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
        wasmtime_wasi_http::Error::InternalError(Some("guest egress TLS config".into()))
    })
    .map(|b| b.with_root_certificates(root_store).with_no_client_auth())
}

/// The single guest-outbound HTTP sender, for BOTH plaintext and TLS. It connects to `addrs` — the
/// IP(s) [`egress_target_allowed`] already resolved AND cleared through the SSRF floor — and NEVER
/// re-resolves the hostname. That pinning is the fix for the DNS-rebinding TOCTOU: the stock
/// `wasmtime_wasi_http::default_send_request` (and the former extra-roots-only path) resolved the host
/// a SECOND time at connect, so an adversarial resolver could return a validated public IP to the gate
/// and then an internal IP (loopback / metadata / RFC1918) to the connect. Here the check and the use
/// are the same bytes.
///
/// The Host header and TLS SNI remain the original hostname (from the request URI), so virtual hosting
/// and certificate verification are unchanged — only the L3 peer is pinned. TLS trust is webpki ⊕
/// `extra_roots` via [`guest_egress_client_config`]; with `extra_roots` empty that is exactly the stock
/// webpki-only set (the production default). A faithful port of wasmtime-wasi-http 50.0.0's
/// `default_send_request` otherwise (origin-form rewrite, connect/first-byte/between-bytes timeouts,
/// concurrent connection driver). Version-coupled: on a wasmtime-wasi-http bump, re-diff against
/// `default_send_request`.
#[allow(clippy::type_complexity)]
async fn send_guest_request(
    request: http::Request<wasmtime_wasi_http::WasiBody>,
    options: wasmtime_wasi_http::RequestOptions,
    use_tls: bool,
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
    addrs: &[SocketAddr],
) -> Result<
    (
        http::Response<wasmtime_wasi_http::WasiBody>,
        Box<dyn Future<Output = Result<(), wasmtime_wasi_http::Error>> + Send>,
    ),
    wasmtime_wasi_http::Error,
> {
    use rustls::pki_types::ServerName;
    use wasmtime_wasi_http::Error;
    use wasmtime_wasi_http::io::TokioIo;

    let connect_timeout = options.connect_timeout.unwrap_or(Duration::from_secs(600));
    let first_byte_timeout = options
        .first_byte_timeout
        .unwrap_or(Duration::from_secs(600));
    let between_bytes_timeout = options
        .between_bytes_timeout
        .unwrap_or(Duration::from_secs(600));

    // The ORIGINAL hostname — used for SNI + cert verification, NEVER as the connect target. An IPv6
    // literal keeps its brackets in the authority; strip them for `ServerName`.
    let host = request
        .uri()
        .authority()
        .ok_or(Error::HttpRequestUriInvalid)?
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();

    // Connect to a PINNED, pre-validated peer — no second DNS resolution.
    let tcp_stream = connect_pinned(addrs, connect_timeout).await?;

    if use_tls {
        let tls_config = guest_egress_client_config(extra_roots)?;
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
        let domain = ServerName::try_from(host.as_str())
            .map_err(|e| {
                tracing::warn!("guest egress dns name error: {e:?}");
                Error::DnsError {
                    rcode: Some("invalid dns name".to_string()),
                    info_code: None,
                }
            })?
            .to_owned();
        let stream = connector.connect(domain, tcp_stream).await.map_err(|e| {
            tracing::warn!("guest egress tls protocol error: {e:?}");
            Error::Tls(e)
        })?;
        finish_guest_http1(
            TokioIo::new(stream),
            request,
            connect_timeout,
            first_byte_timeout,
            between_bytes_timeout,
        )
        .await
    } else {
        finish_guest_http1(
            TokioIo::new(tcp_stream),
            request,
            connect_timeout,
            first_byte_timeout,
            between_bytes_timeout,
        )
        .await
    }
}

/// Connect to the FIRST reachable pre-validated peer, trying each in turn (A/AAAA order). Every
/// address was already cleared by [`egress_target_allowed`], so trying the next on failure cannot
/// widen reach. `addrs` is non-empty whenever the gate returned `Ok`.
async fn connect_pinned(
    addrs: &[SocketAddr],
    connect_timeout: Duration,
) -> Result<tokio::net::TcpStream, wasmtime_wasi_http::Error> {
    use wasmtime_wasi_http::Error;
    let mut last: Option<Error> = None;
    for &addr in addrs {
        match tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last = Some(Error::Connect(e)),
            Err(_) => last = Some(Error::ConnectionTimeout),
        }
    }
    Err(last.unwrap_or(Error::DestinationNotFound))
}

/// Shared HTTP/1 tail over an already-connected stream (plaintext or TLS): handshake, origin-form
/// rewrite, send, and the between-bytes response-body timeout — mirroring `default_send_request`. The
/// connection is driven concurrently; the returned io-future awaits it.
#[allow(clippy::type_complexity)]
async fn finish_guest_http1<S>(
    stream: S,
    mut request: http::Request<wasmtime_wasi_http::WasiBody>,
    connect_timeout: Duration,
    first_byte_timeout: Duration,
    between_bytes_timeout: Duration,
) -> Result<
    (
        http::Response<wasmtime_wasi_http::WasiBody>,
        Box<dyn Future<Output = Result<(), wasmtime_wasi_http::Error>> + Send>,
    ),
    wasmtime_wasi_http::Error,
>
where
    S: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    use http_body_util::BodyExt;
    use wasmtime_wasi_http::Error;

    let (mut sender, conn) = tokio::time::timeout(
        connect_timeout,
        hyper::client::conn::http1::Builder::new().handshake(stream),
    )
    .await
    .map_err(|_| Error::ConnectionTimeout)?
    .map_err(Error::Hyper)?;
    // Drive the connection concurrently; the returned io-future awaits its completion (the wasi-http
    // layer drives it to flush the request body + trailing response), mirroring `default_send_request`.
    let worker = wasmtime_wasi::runtime::spawn(conn);

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

    let resp = tokio::time::timeout(first_byte_timeout, sender.send_request(request))
        .await
        .map_err(|_| Error::ConnectionReadTimeout)?
        .map_err(Error::Hyper)?;
    // Enforce the between-bytes response timeout that the stock `default_send_request` applies, so a
    // trickling upstream body is cut if a frame doesn't arrive within the cap. Tokio panics on a
    // zero-duration interval, so clamp to ~0.
    let between = if between_bytes_timeout == Duration::ZERO {
        Duration::new(0, 1)
    } else {
        between_bytes_timeout
    };
    let mut interval = tokio::time::interval(between);
    interval.reset();
    let resp = resp.map(|incoming| BetweenBytesBody { incoming, interval }.boxed_unsync());

    let io = async move {
        // Surface a connection-level failure during the trailing body/flush to the wasi-http layer
        // instead of reporting a dropped connection as success (parity with `default_send_request`).
        worker.await.map_err(|e| {
            tracing::warn!("guest egress connection dropped: {e}");
            Error::Hyper(e)
        })
    };
    Ok((resp, Box::new(io)))
}

/// Response-body wrapper that enforces a between-bytes timeout: if a frame does not arrive within the
/// interval, the body errors with [`wasmtime_wasi_http::Error::ConnectionReadTimeout`]. A faithful
/// mirror of the `IncomingResponseBody` wrapper inside wasmtime-wasi-http's `default_send_request`, so
/// the guest-egress sender (see [`send_guest_request`]) has the same trickle protection as the stock
/// sender.
struct BetweenBytesBody {
    incoming: hyper::body::Incoming,
    interval: tokio::time::Interval,
}

impl HttpBody for BetweenBytesBody {
    type Data = Bytes;
    type Error = wasmtime_wasi_http::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match Pin::new(&mut self.as_mut().incoming).poll_frame(cx) {
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(err))) => {
                let err = if err.is_timeout() {
                    wasmtime_wasi_http::Error::HttpResponseTimeout
                } else {
                    wasmtime_wasi_http::Error::Hyper(err)
                };
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(Some(Ok(frame))) => {
                self.interval.reset();
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Pending => {
                std::task::ready!(self.interval.poll_tick(cx));
                Poll::Ready(Some(Err(wasmtime_wasi_http::Error::ConnectionReadTimeout)))
            }
        }
    }

    // Delegate the body metadata to the wrapped stream, mirroring the stock `IncomingResponseBody`
    // (an empty/`content-length: 0` upstream still ends promptly and advertises its size).
    fn is_end_stream(&self) -> bool {
        self.incoming.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.incoming.size_hint()
    }
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
    /// The resolved-and-validated peer address(es) for the target host. The sender connects
    /// to THESE pinned IPs rather than re-resolving the hostname — closing the DNS-rebinding
    /// TOCTOU between the SSRF check here and the actual connect (a second `lookup_host` could
    /// otherwise return an internal IP this gate never saw). Non-empty whenever the gate
    /// returns `Ok` (an unresolvable host is already refused as `DestinationNotFound`).
    addrs: Vec<SocketAddr>,
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
) -> Result<EgressPlan, wasmtime_wasi_http::Error> {
    use wasmtime_wasi_http::Error;
    let authority = uri.authority().ok_or(Error::HttpRequestUriInvalid)?;
    let port = authority
        .port_u16()
        .unwrap_or(if use_tls { 443 } else { 80 });
    // `Authority::host` keeps the brackets on an IPv6 literal (`[::1]`), which
    // `lookup_host` won't parse — strip them.
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| Error::DestinationNotFound)?;
    // Retain every resolved+validated address so the sender can connect to a PINNED IP rather
    // than re-resolving the hostname (DNS-rebinding TOCTOU). Each entry here has already cleared
    // the SSRF floor (or is the instance's own socket) below.
    let mut addrs: Vec<SocketAddr> = Vec::new();
    let mut hit_self = false;
    for addr in resolved {
        // The instance's own serve socket is always permitted (it re-enters the pipeline);
        // depth-capped below. Otherwise apply the SSRF gate unless the posture trusts egress.
        if self_addrs.contains(&addr) {
            hit_self = true;
        } else if !allow_private && !boatramp_core::access::is_global_ip(addr.ip()) {
            return Err(Error::DestinationIpProhibited);
        }
        addrs.push(addr);
    }
    if addrs.is_empty() {
        return Err(Error::DestinationNotFound);
    }
    if hit_self {
        let next = egress_depth.saturating_add(1);
        if next > MAX_SELF_EGRESS_DEPTH {
            // Too deep a self-recursion — refuse rather than nest further.
            return Err(Error::DestinationIpProhibited);
        }
        return Ok(EgressPlan {
            self_depth: Some(next),
            addrs,
        });
    }
    Ok(EgressPlan {
        self_depth: None,
        addrs,
    })
}

// KNOWN / ACCEPTED LIMITATIONS (PLAN-handler-tcp-egress TE-3, security-review accepted — not fixed in
// this stage, tracked for a follow-up):
//  1. Per-connect DNS for DOMAIN allowlist entries is UNCACHED: every connect to a domain entry does a
//     fresh `lookup_host`. TODO(tcp-egress): add a short-TTL positive/negative resolve cache (the SSRF
//     floor still independently gates each resolved peer, so a stale cache can't widen reach) + a
//     per-handler egress-connect metric and an operator connect-rate/-count limit.
//  2. `allow_ip_name_lookup(true)` (enabled in `new_store` only under the posture + a non-empty
//     allowlist) lets a granted guest resolve ARBITRARY names host-side — a low-bandwidth DNS
//     side-channel/exfil vector independent of the connect allowlist (resolution ≠ connection; only an
//     allowlisted+SSRF-cleared peer is ever reachable). Accepted for now; a future tightening could
//     scope name lookups to the allowlist's own domains.
//  3. A broad CIDR entry (e.g. `0.0.0.0/0:443`) is a config FOOTGUN — it allowlists every global host
//     on that port (the SSRF floor still bars private/metadata unless `allow_guest_private_egress`).
//     The allowlist is host/operator config (never guest-supplied), so this is an operator-review
//     concern; TODO(tcp-egress): a deploy-time lint warning on an overly-broad entry.
//
/// Whether `addr` (a resolved TCP `connect` peer) is permitted by the per-handler outbound-TCP
/// `egress_allowlist` (`PLAN-handler-tcp-egress`). Each allowlist entry is `<target>:<port>`, where
/// `<target>` is an **IP literal** (exact match), a **CIDR** (membership), or a **domain** (resolved
/// host-side and matched against the peer IP — the resolve-then-compare of [`egress_target_allowed`]).
/// A match requires BOTH the port and the target to agree. An **empty** allowlist matches nothing
/// (deny-all). This answers ONLY the allowlist-membership question; the caller (the `new_store`
/// `socket_addr_check` closure) separately enforces connect-only + the `is_global_ip` SSRF floor, so
/// a private/loopback target is still refused here unless the posture also allows private egress.
async fn tcp_egress_allowed(allowlist: &[String], addr: SocketAddr) -> bool {
    for entry in allowlist {
        // Split the REQUIRED trailing `:<port>`. Split on the LAST colon so an IPv6 literal/CIDR
        // target (which itself contains colons) keeps its colons: `[::1]:993`, `2001:db8::/32:993`,
        // `10.0.0.0/8:5432`, `db.internal:5432`.
        let Some((target, port_s)) = entry.rsplit_once(':') else {
            continue; // no port ⇒ malformed, never matches (fail-closed)
        };
        let Ok(port) = port_s.parse::<u16>() else {
            continue;
        };
        if port != addr.port() {
            continue;
        }
        // Tolerate brackets on an IPv6 literal target (`[2001:db8::1]`).
        let target = target.trim_start_matches('[').trim_end_matches(']');
        // 1) Exact IP literal.
        if let Ok(ip) = target.parse::<IpAddr>() {
            if ip == addr.ip() {
                return true;
            }
            continue;
        }
        // 2) CIDR membership.
        if let Ok(net) = target.parse::<ipnet::IpNet>() {
            if net.contains(&addr.ip()) {
                return true;
            }
            continue;
        }
        // 3) Domain: resolve host-side and match the peer IP (resolve-then-compare). An
        //    unresolvable entry simply doesn't match — another entry may still permit the peer.
        if let Ok(resolved) = tokio::net::lookup_host((target, port)).await {
            for sa in resolved {
                if sa.ip() == addr.ip() {
                    return true;
                }
            }
        }
    }
    false
}

/// The full outbound-TCP connect authorization decision (`PLAN-handler-tcp-egress`): the single pure
/// predicate the installed `socket_addr_check` closure ([`HandlerEngine::new_store`]) calls, so the
/// TESTED code is the ENFORCED code. Returns `true` (permit) only when ALL hold:
/// 1. **posture** — `posture_tcp_egress` is on (`allow_guest_tcp_egress`). Defense-in-depth: the
///    closure is only INSTALLED when the posture is on, but carrying the check here means the gate
///    still denies even if the install site regressed.
/// 2. **connect-only** — `use_` is `TcpConnect`; every `bind`/`listen` and all UDP are denied
///    (inbound stays the container/microVM model).
/// 3. **SSRF floor** — the peer is globally routable, unless `allow_private_egress` is separately on
///    (so an allowlisted private/metadata target still needs that opt-in).
/// 4. **allowlist** — the peer matches a per-handler [`tcp_egress_allowed`] entry (IP/CIDR/domain + port).
///
/// Whether [`HandlerEngine::new_store`] installs the permissive GUEST `socket_addr_check`
/// (`allow_tcp(true)` + the gated check) for a store. This is the SINGLE SOURCE OF TRUTH + the REAL
/// enforcement of the cap-req 19 host-mediated-egress carve-out: a `host_mediated` invocation (a
/// host-owned listener guest) NEVER gets the guest check even with a non-empty allowlist — its
/// allowlist feeds ONLY the host-mediated `TcpEgressHost`, so the guest's raw `wasi:sockets` stays
/// deny-all. Extracted + tested (see `installs_guest_socket_check_honors_host_mediated`) so the
/// carve-out's actual enforcement point is anti-hollow-covered, not just the sibling
/// `conn_lane_sockets_denied` guard. Pure.
fn installs_guest_socket_check(
    allow_tcp_egress: bool,
    allowlist_empty: bool,
    host_mediated: bool,
) -> bool {
    allow_tcp_egress && !allowlist_empty && !host_mediated
}

/// The `tcpegress_mutation()` seam (test/`tcpegress-gate-mutation` only) neuters exactly one check at
/// a time so the CI gate proves each is load-bearing; a shipped build evaluates all four.
async fn tcp_connect_decision(
    use_: SocketAddrUse,
    addr: SocketAddr,
    allowlist: &[String],
    allow_private: bool,
    posture_tcp_egress: bool,
) -> bool {
    let mutation = tcpegress_mutation();
    let mutating = |m: &str| mutation.as_deref() == Some(m);

    // (1) Posture gate.
    if !posture_tcp_egress && !mutating("drop_posture") {
        return false;
    }
    // (2a) Permit wasmtime's implicit pre-connect LOCAL bind. wasmtime 50's `TcpSocket::connect`
    // runs `socket_addr_check(unspecified_addr, TcpBind)` — a permission check for the OS's
    // ephemeral local bind (0.0.0.0:0 / [::]:0), WITHOUT actually binding (IP_BIND_ADDRESS_NO_PORT)
    // — immediately BEFORE the real `TcpConnect` check. That is the connect's OWN local bind, not a
    // guest `bind`/`listen` to a real inbound address, so allow it outright (still gated by the
    // posture above); the actual peer is fully gated by the `TcpConnect` check `connect` runs next.
    // Without this, EVERY gated `wasi:sockets` connect is denied under wasmtime 50 — the v0.44.0
    // regression (older wasmtime ran no such pre-connect bind check). Narrow by construction: a
    // bind/listen to ANY specific address, or a non-zero port, still falls through to (2b) and is
    // denied — inbound stays the container/microVM model.
    if matches!(use_, SocketAddrUse::TcpBind) && addr.ip().is_unspecified() && addr.port() == 0 {
        return true;
    }
    // (2b) Connect-only: every OTHER non-`TcpConnect` use (a real bind/listen, all UDP) is denied.
    if !matches!(use_, SocketAddrUse::TcpConnect) && !mutating("admit_bind_listen") {
        return false;
    }
    // (3) SSRF floor (applied BEFORE the allowlist so an allowlisted private target still needs the
    // separate `allow_guest_private_egress` opt-in). No mutation neuters the floor here — the
    // metadata/private SSRF property is already gate-proven by `is_global_ip`'s own unit tests; this
    // gate's three mutations target the capability-specific checks (posture/connect-only/allowlist).
    if !allow_private && !boatramp_core::access::is_global_ip(addr.ip()) {
        return false;
    }
    // (4) Allowlist membership.
    if mutating("admit_unallowlisted") {
        return true;
    }
    tcp_egress_allowed(allowlist, addr).await
}

/// Why [`resolve_and_gate_tcp_egress`] refused a dial. Independent of any WIT/bindgen type — the
/// `tcp-egress` host binding maps this to the guest-facing `egress-error` variant.
#[cfg(feature = "tcp-egress")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpEgressResolveError {
    /// `host` did not resolve to any address.
    DnsFailure,
    /// Every resolved candidate address was denied by the reused egress gate (posture off, the SSRF
    /// floor, or not in the per-handler `egress_allowlist`).
    RefusedByGate,
}

/// The DNS-rebinding choke point for the `tcp-egress` host-terminated outbound-TLS dial
/// (`PLAN-handler-tcp-egress` Build A, mailroom cap-req #15) — the load-bearing security property
/// that makes a host-side dial on a guest-supplied hostname safe: resolve `host` **ONCE**, then run
/// [`tcp_connect_decision`] — the EXACT SAME predicate the gated `wasi:sockets` capability's
/// `socket_addr_check` closure calls, so this is one source of truth, never a forked copy — against
/// **EACH** resolved candidate address individually, returning only the addresses that pass. The
/// caller (`bindings::tcp_egress::TcpEgressHost::connect_tls`) MUST connect to one of the addresses
/// in the returned `Vec` and must **NEVER** resolve `host` again: a second lookup could return a
/// DIFFERENT address than the one just checked (the attacker flips their DNS record between the
/// check and the connect — classic DNS rebinding), which would let an SSRF-floored or
/// non-allowlisted target slip through a gate that "checks the name" instead of "checks the peer it
/// is about to dial". Checking (and later connecting to) the SAME resolved `SocketAddr` closes that
/// window structurally.
///
/// A hostname that resolves to SEVERAL addresses (e.g. a dual-stack A/AAAA name) is filtered
/// per-candidate, not per-name — some addresses may pass while others are denied; only a name whose
/// EVERY candidate is denied returns [`TcpEgressResolveError::RefusedByGate`].
#[cfg(feature = "tcp-egress")]
pub(crate) async fn resolve_and_gate_tcp_egress(
    host: &str,
    port: u16,
    allowlist: &[String],
    allow_private: bool,
    posture_tcp_egress: bool,
) -> Result<Vec<SocketAddr>, TcpEgressResolveError> {
    // ONE resolution. An IP-literal `host` "resolves" to itself synchronously (no network lookup);
    // everything else does a real DNS query. Either way, `addrs` is the FINAL, fixed candidate set —
    // nothing downstream of this function may call `lookup_host` again for this dial.
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| TcpEgressResolveError::DnsFailure)?
        .collect();
    if addrs.is_empty() {
        return Err(TcpEgressResolveError::DnsFailure);
    }
    let mut checked = Vec::with_capacity(addrs.len());
    for addr in addrs {
        if tcp_connect_decision(
            SocketAddrUse::TcpConnect,
            addr,
            allowlist,
            allow_private,
            posture_tcp_egress,
        )
        .await
        {
            checked.push(addr);
        }
    }
    if checked.is_empty() {
        return Err(TcpEgressResolveError::RefusedByGate);
    }
    Ok(checked)
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

/// The active TCP-egress gate mutation (`PLAN-handler-tcp-egress` TE-3 anti-hollow gate), or `None`.
/// Present ONLY under `cfg(test)` (the in-crate gate) or the `tcpegress-gate-mutation` feature; a
/// shipped build has neither, so [`tcp_connect_decision`]'s three security checks are unconditional
/// and this is a dead `None`. Each recognized value neuters ONE check so the CI gate can prove it
/// goes RED: `admit_unallowlisted` (bypass the allowlist), `admit_bind_listen` (drop connect-only),
/// `drop_posture` (ignore the posture gate). NOT a backdoor — it only reads a test env var.
#[cfg(any(test, feature = "tcpegress-gate-mutation"))]
fn tcpegress_mutation() -> Option<String> {
    std::env::var("BOATRAMP_TCPEGRESS_MUTATION").ok()
}
#[cfg(not(any(test, feature = "tcpegress-gate-mutation")))]
#[inline]
fn tcpegress_mutation() -> Option<String> {
    None
}

/// The inbound-TCP **listener dispatch** authorization decision (PLAN-handler-tcp-inbound). The single
/// pure predicate [`HandlerEngine::dispatch_tcp_connection`] calls BEFORE it ever instantiates a guest,
/// so the TESTED code is the ENFORCED code (mirrors the egress `tcp_connect_decision` convention).
/// Returns `true` (dispatch) only when BOTH belt-and-suspenders gates hold:
/// 1. **posture** — `posture_listener_enabled` is on (the node posture `allow_guest_tcp_listener`, off
///    under multi-tenant). The serve accept loop is ALSO gated on this before it ever binds, so
///    carrying it here is defense-in-depth: dispatch still denies even if the bind-site regressed.
/// 2. **declared** — the operator DECLARED this listener in `[serve.listeners.<name>]`. The accept loop
///    only runs for a declared listener (it iterates the config map), so the real call site passes the
///    config-lookup result; carrying the check here proves (via the gate mutation) it is load-bearing.
///
/// This gate grants NO socket authority — that invariant is a SEPARATE structural property
/// ([`HandlerEngine::conn_lane_grants_socket_authority`]). The `tcplistener_mutation()` seam
/// (test/`tcp-listener-gate-mutation` only) neuters exactly one check so the CI gate proves each is
/// load-bearing: `drop_posture` ignores (1); `admit_undeclared` ignores (2). A shipped build evaluates
/// both unconditionally.
#[cfg(feature = "tcp-listener")]
fn tcp_listener_dispatch_decision(posture_listener_enabled: bool, listener_declared: bool) -> bool {
    let mutation = tcplistener_mutation();
    let mutating = |m: &str| mutation.as_deref() == Some(m);

    // (1) Posture gate.
    if !posture_listener_enabled && !mutating("drop_posture") {
        return false;
    }
    // (2) Operator-declared gate.
    if !listener_declared && !mutating("admit_undeclared") {
        return false;
    }
    true
}

/// Whether the inbound-TCP **connection lane** grants the guest raw socket authority (`allow_tcp` /
/// a permissive `socket_addr_check`). ALWAYS `false` — the load-bearing safety invariant of
/// PLAN-handler-tcp-inbound is that a host-owned-listener guest receives ONLY the accepted
/// connection's `wasi:io` streams and NEVER `wasi:sockets` (operator owns the socket; bind/listen/
/// connect authority stays host-side; the v0.30.0 connect-only egress gate at the socket host is
/// untouched). [`HandlerEngine::dispatch_tcp_connection`] CALLS this to decide whether to grant the
/// conn-lane store socket authority (so tested == enforced) — and, being always-false, never does.
/// The `add_socket_authority` gate mutation flips it `true` so the CI gate's structural assertion goes
/// RED: a regression that handed this lane socket authority is caught at merge.
#[cfg(feature = "tcp-listener")]
fn conn_lane_grants_socket_authority() -> bool {
    tcplistener_mutation().as_deref() == Some("add_socket_authority")
}

/// The REAL no-raw-sockets invariant (PLAN-handler-tcp-inbound security-review MEDIUM): a conn-lane
/// dispatch MUST NOT cause [`HandlerEngine::new_store`] to install a permissive GUEST
/// `socket_addr_check`. new_store installs it only when
/// `self.allow_tcp_egress && !egress_allowlist.is_empty() && !host_mediated_egress_only`, so the
/// guest's raw sockets stay deny-all (its only network surface being the handed `wasi:io` streams)
/// iff the bindings carry an EMPTY allowlist OR are HOST-MEDIATED-egress-only. The latter is the
/// cap-req 19 case: a listener guest MAY carry a non-empty allowlist to drive the host-mediated
/// `tcp-egress` dial (the host dials + terminates TLS — the guest never touches a socket), and
/// because `host_mediated_egress_only` is set, new_store still installs NO guest socket check. Both
/// dispatches CALL this on the received bindings and fail CLOSED when it is violated (tested ==
/// enforced — the gate drives the SAME predicate, and the `add_socket_authority` mutation injects a
/// non-empty allowlist WITHOUT the host-mediated flag so this returns `false` ⇒ the gate goes RED).
/// Pure (no mutation seam itself) — the property is a fact of the bindings, not a flag.
#[cfg(feature = "tcp-listener")]
fn conn_lane_sockets_denied(bindings: &Bindings) -> bool {
    bindings.egress_allowlist().is_empty() || bindings.host_mediated_egress_only()
}

/// The active TCP-listener gate mutation (PLAN-handler-tcp-inbound anti-hollow gate), or `None`.
/// Present ONLY under `cfg(test)` (the in-crate gate) or the `tcp-listener-gate-mutation` feature; a
/// shipped build has neither, so [`tcp_listener_dispatch_decision`]'s two checks are unconditional and
/// [`conn_lane_grants_socket_authority`] is a constant `false`. Each recognized value neuters ONE
/// property so the CI gate proves it goes RED: `drop_posture` / `admit_undeclared` (the dispatch
/// gates), `add_socket_authority` (the no-raw-sockets structural invariant). NOT a backdoor — it only
/// reads a test env var.
#[cfg(feature = "tcp-listener")]
fn tcplistener_mutation() -> Option<String> {
    #[cfg(any(test, feature = "tcp-listener-gate-mutation"))]
    {
        std::env::var("BOATRAMP_TCPLISTENER_MUTATION").ok()
    }
    #[cfg(not(any(test, feature = "tcp-listener-gate-mutation")))]
    {
        None
    }
}

/// The write buffer (bytes) for a listener connection's host→guest→peer `AsyncWriteStream`
/// (PLAN-handler-tcp-inbound). 64 KiB — enough to keep a chatty writer from stalling on
/// per-chunk backpressure without buffering unboundedly.
#[cfg(feature = "tcp-listener")]
const TCP_CONN_WRITE_BUDGET: usize = 64 * 1024;

/// Node-global ceiling on concurrently-live session-mode listener connections (cap-req 08 / Security
/// review LOW backstop). Generous — sized for the many-mostly-idle-connections use case (thousands of
/// IMAP IDLE / long-poll sessions) so it never bites normal operation, while still capping a single
/// misconfigured listener's socket + checkpoint footprint across a multi-listener node. A parked
/// connection is cheap (no instance, no re-entry permit), so a high ceiling is safe. (A future config
/// knob can make this operator-tunable; a fixed generous default is the LOW hardening here.)
#[cfg(all(feature = "tcp-listener", feature = "session"))]
const DEFAULT_SESSION_CONN_CAP: usize = 16_384;

/// How many epoch ticks a conn-lane guest runs before the engine epoch forces its async fiber to
/// YIELD (`epoch_deadline_async_yield_and_update`) — PLAN-handler-tcp-inbound HIGH-fix. At
/// [`EPOCH_TICK_MS`] (10ms) this is ~250ms. Yield ≠ trap: a long-lived `handle` is preserved, but a
/// CPU-bound guest (a parser loop / decompression bomb on untrusted peer bytes) that never makes a
/// suspending host call is still forced to return `Poll::Pending` periodically, so (a) it can't pin a
/// shared tokio worker thread, and (b) the wall-clock idle/max-duration watchdog in the dispatch
/// `select!` actually gets re-polled and can drop the call. MUST be a small, non-zero budget — a
/// `u64::MAX` (or a trap deadline) would reintroduce the starvation. The engine-wide epoch ticker
/// ([`HandlerEngine::from_engine`]) drives the ticks for every store, this lane included.
#[cfg(feature = "tcp-listener")]
const CONN_EPOCH_YIELD_TICKS: u64 = 25;

// HIGH-fix regression guard (compile-time): the conn-lane yield budget MUST be a small, non-zero tick
// count — never 0 and never effectively infinite (a `u64::MAX`-style value would disable yielding and
// let a CPU-bound guest pin a worker + starve the watchdog). A sub-second window keeps the watchdog
// re-polled promptly. Fails the BUILD (not just a test) if someone widens or zeroes it.
#[cfg(feature = "tcp-listener")]
const _: () = assert!(
    CONN_EPOCH_YIELD_TICKS > 0
        && CONN_EPOCH_YIELD_TICKS <= 100
        && CONN_EPOCH_YIELD_TICKS * EPOCH_TICK_MS <= 1000,
    "CONN_EPOCH_YIELD_TICKS must be a small, non-zero, sub-second epoch-yield budget"
);

/// Why an inbound-TCP connection was torn down by the host (PLAN-handler-tcp-inbound) rather than the
/// guest returning. Both are a normal end of a long-lived connection — the conn lane's DoS bound —
/// NOT a handler failure.
#[cfg(feature = "tcp-listener")]
#[derive(Debug, PartialEq, Eq)]
enum ConnTimeout {
    /// No bytes flowed in EITHER direction for the listener's `idle_timeout`.
    Idle,
    /// The connection reached the listener's `max_conn_duration` absolute lifetime cap.
    MaxDuration,
}

/// The conn-lane wall-clock watchdog (PLAN-handler-tcp-inbound): resolves to [`ConnTimeout::Idle`]
/// when no bytes have moved in either direction for `idle_timeout`, or [`ConnTimeout::MaxDuration`]
/// when the connection has been live for `max_conn_duration` — whichever first. `started` is the
/// connection's start instant and `last_activity` the shared "last byte moved" instant the
/// [`IdleTracked`] stream adapters stamp. Extracted so the timing logic is unit-testable (via
/// `tokio::time::pause`) WITHOUT a guest component — it is driven concurrently with the guest
/// `call_handle` in the dispatch `select!`, so the two paths never drift. Uses [`tokio::time::Instant`]
/// throughout so a paused test clock controls it deterministically.
#[cfg(feature = "tcp-listener")]
async fn conn_watchdog(
    last_activity: Arc<Mutex<tokio::time::Instant>>,
    idle_timeout: Duration,
    max_conn_duration: Duration,
    started: tokio::time::Instant,
) -> ConnTimeout {
    // Poll at a fraction of the SHORTER of the two windows (bounded) so EITHER a short idle_timeout OR
    // a short max_conn_duration is observed promptly — an idle-only tick would miss a max-duration far
    // shorter than idle (and vice-versa).
    let tick = (idle_timeout.min(max_conn_duration) / 4)
        .clamp(Duration::from_millis(50), Duration::from_secs(5));
    loop {
        tokio::time::sleep(tick).await;
        let idle_for = last_activity
            .lock()
            .map(|g| g.elapsed())
            .unwrap_or_default();
        if idle_for >= idle_timeout {
            return ConnTimeout::Idle;
        }
        if started.elapsed() >= max_conn_duration {
            return ConnTimeout::MaxDuration;
        }
    }
}

/// An `AsyncRead`/`AsyncWrite` adapter that stamps a shared "last activity" instant whenever bytes
/// actually move (PLAN-handler-tcp-inbound), so the conn-lane idle watchdog can tear a silent
/// connection down. Wraps BOTH halves (read bytes from the peer AND write bytes to the peer count as
/// activity), so an actively-streaming connection is never killed as idle. The inner half is `Unpin`
/// (a tokio `OwnedReadHalf`/`OwnedWriteHalf`), so the adapter is `Unpin` and delegates by pin-projection.
#[cfg(feature = "tcp-listener")]
struct IdleTracked<T> {
    inner: T,
    last_activity: Arc<Mutex<tokio::time::Instant>>,
}

#[cfg(feature = "tcp-listener")]
impl<T> IdleTracked<T> {
    fn new(inner: T, last_activity: Arc<Mutex<tokio::time::Instant>>) -> Self {
        Self {
            inner,
            last_activity,
        }
    }
    fn touch(&self) {
        if let Ok(mut g) = self.last_activity.lock() {
            *g = tokio::time::Instant::now();
        }
    }
}

#[cfg(feature = "tcp-listener")]
impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for IdleTracked<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(r, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.touch();
        }
        r
    }
}

#[cfg(feature = "tcp-listener")]
impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for IdleTracked<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r
            && *n > 0
        {
            self.touch();
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
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
/// eviction signal for the instance-lifecycle stats (an instance-observability request). A
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
    /// surface (an instance-observability request). `Arc` so the server can hold a handle.
    stats: Arc<crate::instance_stats::InstanceStats>,
    cache: Mutex<LruCache<String, ProxyPre<HostState>>>,
    /// Request-lane **warm floor** (cold-start cap-req 09): a SEPARATE pinned set, checked
    /// before the main `cache` on the serve path, that the main serve-LRU can NEVER evict — so
    /// a latency-critical face does not cold-start under capacity pressure. It is itself a small
    /// `keep_warm_max`-capacity LRU: a serve promotes (keeps active faces), and a NEW pin at
    /// deploy time evicts the STALEST pinned entry rather than accumulating dead content-hashes
    /// across redeploys. Empty + inert when the floor is off (`keep_warm_max == 0`).
    pinned: Mutex<LruCache<String, ProxyPre<HostState>>>,
    /// The node-global cap on pinned (warm-floor) request components (`[handlers]
    /// keep_warm_max`). `0` ⇒ the warm floor is OFF (no component is ever pinned), so an
    /// engine built without it behaves exactly as before.
    keep_warm_max: usize,
    /// Separate compile cache for consumer (`wasi:messaging`) components — a
    /// different world (`handle` export) than the request `ProxyPre`.
    #[cfg(feature = "messaging")]
    consumer_cache: Mutex<LruCache<String, consumer_world::ConsumerPre<HostState>>>,
    /// Separate compile cache for session (`session-handler` export) components.
    #[cfg(feature = "session")]
    session_cache: Mutex<LruCache<String, session_world::SessionHostPre<HostState>>>,
    /// Separate compile cache for tcp-connection (`tcp-connection-handler` export) components
    /// (PLAN-handler-tcp-inbound) — a different world than the request `ProxyPre` / session cache.
    #[cfg(feature = "tcp-listener")]
    tcp_connection_cache:
        Mutex<LruCache<String, tcp_connection_world::TcpConnectionHostPre<HostState>>>,
    /// The **inbound-TCP connection lane** concurrency gate (PLAN-handler-tcp-inbound): a dedicated
    /// pool so a burst of long-lived listener connections can never exhaust the sync request pool nor
    /// starve the async drain. Each live connection holds one permit for its whole life (a single
    /// blocking `handle`); `max_conns` per listener + this global ceiling together bound the fan-out.
    /// Defaults to the sync `limits.max_concurrency` (no separate Phase 1 config knob).
    #[cfg(feature = "tcp-listener")]
    tcp_conn_semaphore: Semaphore,
    /// DEDICATED concurrency pool for socket-driven SESSION re-entries (cap-req 08). A session-mode
    /// listener re-entry must NOT share the [`Lane::Async`] semaphore (that lane serves messaging
    /// consumers, HTTP sessions, crons — untrusted, blocking, long-held socket work there would starve
    /// them; Security review HIGH-1), nor the connection pool (whose permits are held for a
    /// connection's whole life). This is its own ceiling, acquired per re-entry (transient: a parked
    /// idle connection holds none), bounded alongside the per-re-entry wall-clock watchdog in
    /// `dispatch_session_connection`. Defaults to `limits.max_concurrency`.
    #[cfg(all(feature = "tcp-listener", feature = "session"))]
    session_socket_semaphore: Semaphore,
    /// NODE-GLOBAL ceiling on concurrently-live session-mode listener connections across ALL session
    /// listeners (cap-req 08 / Security review LOW — a safety backstop above each listener's own
    /// `max_conns`). A permit is held for a connection's WHOLE life (parked included), so it bounds the
    /// aggregate socket + checkpoint footprint of a multi-listener node against a single misconfigured
    /// listener. Generous by default ([`DEFAULT_SESSION_CONN_CAP`]) so it never bites the
    /// many-idle-connections use case; `Arc` for owned per-connection permits.
    #[cfg(all(feature = "tcp-listener", feature = "session"))]
    session_conn_semaphore: std::sync::Arc<Semaphore>,
    /// The inbound-TCP connection lane ceiling — the (memory) clamp a listener dispatch is held to.
    /// Defaults to the sync `limits`; the per-invocation epoch deadline + CPU fuel are DISABLED for
    /// this lane in favor of idle + max-connection-duration timeouts (a long-lived `handle` must not
    /// trip the request epoch). See [`HandlerEngine::dispatch_tcp_connection`].
    #[cfg(feature = "tcp-listener")]
    tcp_conn_limits: Limits,
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
    ///
    /// `Arc` (unlike the sync/async gates) so the streaming permit can be taken as an
    /// [`OwnedSemaphorePermit`] and carried **inside the response body** — a streaming slot
    /// is occupied for the stream's whole life, not merely until the head is produced
    /// (PLAN-handler-stream-lifecycle GAP1). A plain borrowed permit would have to be dropped
    /// when `serve_lane` returns the head, un-bounding `streaming_max_concurrency`.
    streaming_semaphore: Arc<Semaphore>,
    /// Idle cap (ms) for a streaming-lane response: if no body frame flows to the client for
    /// this long, the host tears the stream down and reclaims its slot
    /// (PLAN-handler-stream-lifecycle GAP2 — the slowloris bound for the streaming lane, mirroring
    /// the inbound-TCP conn-lane idle watchdog). The absolute lifetime is separately bounded by the
    /// `streaming_limits.timeout_ms` epoch deadline. Defaults to [`DEFAULT_STREAMING_IDLE_MS`].
    streaming_idle_ms: u64,
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
    /// Whether a guest's gated `wasi:sockets` capability may open an outbound TCP `connect` (the
    /// operator posture's `allow_guest_tcp_egress`). `false` (the default) keeps the socket host
    /// deny-all: `new_store` never installs a permissive `socket_addr_check`, so every connect is
    /// refused regardless of the per-handler allowlist. `true` installs the connect-only,
    /// allowlist-gated, SSRF-floored check. Never affects `wasi:http` egress (its own gate).
    allow_tcp_egress: bool,
    /// Whether the node posture allows host-owned inbound-TCP **listeners** to dispatch to a guest
    /// (`allow_guest_tcp_listener`, off under multi-tenant) — PLAN-handler-tcp-inbound. `false` (the
    /// default) makes [`dispatch_tcp_connection`](Self::dispatch_tcp_connection) refuse before it ever
    /// instantiates a guest (via the pure [`tcp_listener_dispatch_decision`]); the serve accept loop is
    /// ALSO gated on it before it binds, so both layers fail closed. This is INDEPENDENT of
    /// `allow_tcp_egress` (inbound ≠ outbound authority). It NEVER grants the guest `wasi:sockets`.
    #[cfg_attr(not(feature = "tcp-listener"), allow(dead_code))]
    allow_tcp_listener: bool,
    /// Per-dial CONNECT timeout for the `tcp-egress` capability (`PLAN-handler-tcp-egress` Build A,
    /// mailroom #15): bounds the TCP connect AND the TLS handshake together (one "establish the
    /// connection" budget) so a hung/slow peer can't pin the invocation. Configurable via
    /// [`with_tcp_egress_timeouts`](Self::with_tcp_egress_timeouts); defaults to
    /// [`DEFAULT_TCP_EGRESS_CONNECT_TIMEOUT`]. Independent of `allow_tcp_egress` (which gates
    /// WHETHER a dial is permitted at all; this bounds how long a PERMITTED dial may take).
    #[cfg(feature = "tcp-egress")]
    tcp_egress_connect_timeout: Duration,
    /// Per-dial READ/IDLE timeout for `tcp-egress`: if the peer sends (or accepts) no bytes for this
    /// long AFTER the handshake, the guest's next read/write on the connection's streams surfaces a
    /// timeout error instead of hanging forever on a silent peer — there is no outer watchdog loop
    /// for these streams (unlike the inbound conn lane's `select!`; the guest drives `wasi:io` reads
    /// on its own schedule, possibly long after `connect-tls` returned), so the bound lives INSIDE
    /// the stream adapter itself. Configurable via
    /// [`with_tcp_egress_timeouts`](Self::with_tcp_egress_timeouts); defaults to
    /// [`DEFAULT_TCP_EGRESS_IDLE_TIMEOUT`].
    #[cfg(feature = "tcp-egress")]
    tcp_egress_idle_timeout: Duration,
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
            // Warm floor OFF by default (cap 0 ⇒ `pin_request_component` no-ops, so this stays
            // empty) — identical to prior behavior until an operator sets `[handlers]
            // keep_warm_max` via `with_keep_warm_max`, which rebuilds this at the real capacity.
            pinned: Mutex::new(LruCache::new(NonZeroUsize::new(1).expect("1 is non-zero"))),
            keep_warm_max: 0,
            #[cfg(feature = "messaging")]
            consumer_cache: Mutex::new(LruCache::new(capacity)),
            #[cfg(feature = "messaging")]
            consumer_gates: ConsumerGates::default(),
            request_gates: KeyedSemaphores::default(),
            #[cfg(feature = "session")]
            session_cache: Mutex::new(LruCache::new(capacity)),
            #[cfg(feature = "tcp-listener")]
            tcp_connection_cache: Mutex::new(LruCache::new(capacity)),
            // The inbound-TCP connection lane defaults to the sync ceiling + its own independent pool,
            // so an engine built without any listener behaves identically (the lane is inert until a
            // listener dispatches). PLAN-handler-tcp-inbound.
            #[cfg(feature = "tcp-listener")]
            tcp_conn_semaphore: Semaphore::new(limits.max_concurrency.max(1)),
            // Dedicated socket-session re-entry pool (cap-req 08 / Security review HIGH-1) — its own
            // ceiling, independent of the Async lane and the connection pool.
            #[cfg(all(feature = "tcp-listener", feature = "session"))]
            session_socket_semaphore: Semaphore::new(limits.max_concurrency.max(1)),
            // Node-global live-session-connection ceiling (cap-req 08 / Security review LOW backstop).
            #[cfg(all(feature = "tcp-listener", feature = "session"))]
            session_conn_semaphore: std::sync::Arc::new(Semaphore::new(DEFAULT_SESSION_CONN_CAP)),
            #[cfg(feature = "tcp-listener")]
            tcp_conn_limits: limits,
            semaphore: Semaphore::new(limits.max_concurrency.max(1)),
            // The async + streaming lanes default to the sync ceiling + an equally-sized,
            // *independent* pool each, so an engine built without opting in behaves
            // exactly as before (back-compat for tests and existing callers).
            async_semaphore: Semaphore::new(limits.max_concurrency.max(1)),
            async_limits: limits,
            streaming_semaphore: Arc::new(Semaphore::new(limits.max_concurrency.max(1))),
            streaming_limits: limits,
            streaming_idle_ms: DEFAULT_STREAMING_IDLE_MS,
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
            // Deny-by-default: the socket host stays deny-all until an operator opts the posture in
            // via `with_tcp_egress`. A node that never calls it can never grant outbound TCP.
            allow_tcp_egress: false,
            // Deny-by-default: inbound listeners dispatch only once an operator opts the posture in via
            // `with_tcp_listener`. A node that never calls it can never dispatch a listener connection.
            allow_tcp_listener: false,
            #[cfg(feature = "tcp-egress")]
            tcp_egress_connect_timeout: DEFAULT_TCP_EGRESS_CONNECT_TIMEOUT,
            #[cfg(feature = "tcp-egress")]
            tcp_egress_idle_timeout: DEFAULT_TCP_EGRESS_IDLE_TIMEOUT,
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
        self.streaming_semaphore =
            Arc::new(Semaphore::new(streaming_limits.max_concurrency.max(1)));
        self.streaming_limits = streaming_limits;
        self
    }

    /// Set the streaming-lane **idle cap** (`[handlers] streaming_idle_timeout_ms`): a streaming
    /// response whose body produces no frame to the client for this long is torn down and its slot
    /// reclaimed (PLAN-handler-stream-lifecycle GAP2). Floored at 1 s so a fat-fingered `0` can't
    /// make every stream instantly idle-killable. The absolute lifetime stays bounded by
    /// `streaming_limits.timeout_ms`.
    #[must_use]
    pub fn with_streaming_idle_ms(mut self, idle_ms: u64) -> Self {
        self.streaming_idle_ms = idle_ms.max(1_000);
        self
    }

    /// Set the **warm-floor** cap (`[handlers] keep_warm_max`): the maximum number of
    /// request components [`pin_request_component`](Self::pin_request_component) may pin in
    /// the never-evicted set. `0` (the default) keeps the floor OFF. An engine built without
    /// this behaves exactly as before.
    #[must_use]
    pub fn with_keep_warm_max(mut self, keep_warm_max: usize) -> Self {
        self.keep_warm_max = keep_warm_max;
        // Size the pinned set to the cap (floored at 1 for the NonZero invariant; when the floor
        // is off at 0, `pin_request_component` never inserts, so the set stays empty regardless).
        self.pinned = Mutex::new(LruCache::new(
            NonZeroUsize::new(keep_warm_max.max(1)).expect("max(1) is non-zero"),
        ));
        self
    }

    /// Pin component `hash` in the request-lane **warm floor** so it is never LRU-evicted —
    /// a latency-critical face stays warm under capacity pressure (cold-start cap-req 09).
    /// Compiles the component once (reusing [`compile`](Self::compile)) and inserts it into
    /// the pinned set. A no-op (returns `Ok`) when the floor is off (`keep_warm_max == 0`)
    /// or already at capacity with this hash not already pinned — the LRU then handles it as
    /// before (best-effort floor, never an error that would fail a deploy). Already-pinned ⇒
    /// re-compiled + replaced (a deploy re-point).
    pub fn pin_request_component(&self, hash: &str, wasm: &[u8]) -> Result<(), HandlerError> {
        if self.keep_warm_max == 0 {
            return Ok(());
        }
        // Already pinned (a re-deploy of the same content hash) ⇒ promote, no recompile.
        if self.pinned.lock().unwrap().get(hash).is_some() {
            return Ok(());
        }
        let pre = self.compile(wasm)?;
        // Insert into the pinned LRU; at capacity this evicts the STALEST pinned entry (a
        // superseded redeploy's hash), never a currently-served one (serving promotes it).
        self.pinned.lock().unwrap().put(hash.to_string(), pre);
        Ok(())
    }

    /// Drop component `hash` from the warm floor (explicit unpin). A no-op if it was not
    /// pinned. The component may still be served from the main LRU cache afterwards.
    pub fn unpin_request_component(&self, hash: &str) {
        self.pinned.lock().unwrap().pop(hash);
    }

    /// Compile `wasm` ONCE, warm the request-lane cache (like [`precompile`](Self::precompile)),
    /// AND return the portable **serialized artifact** for cross-node upload (cold-start
    /// cap-req 09, producer path). A single compile serves both the local warm-up and the
    /// artifact. The returned bytes are the wasmtime-serialized `Component` — the caller
    /// (serve layer) frames + MACs them before storing; they are NOT self-authenticating.
    pub fn precompile_and_serialize_request(
        &self,
        hash: &str,
        wasm: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        let component = Component::from_binary(&self.engine, wasm)
            .map_err(|err| HandlerError::Compile(err.to_string()))?;
        let artifact = component
            .serialize()
            .map_err(|err| HandlerError::Compile(format!("serialize component: {err}")))?;
        let instance_pre = self
            .build_linker()?
            .instantiate_pre(&component)
            .map_err(|err| HandlerError::Compile(err.to_string()))?;
        let pre = ProxyPre::new(instance_pre).map_err(|_| {
            HandlerError::Compile("component is not a wasi:http/proxy handler".into())
        })?;
        cache_insert_evicted(&self.cache, hash, pre);
        Ok(artifact)
    }

    /// Hydrate a **MAC-verified** serialized artifact into the request-lane cache, skipping
    /// cranelift entirely (cold-start cap-req 09, consumer path). The subsequent serve is a
    /// warm hit (no cold miss recorded), exactly as if the component had been compiled.
    ///
    /// # Security
    /// `artifact` MUST already have been integrity-verified by the caller (the cluster-keyed
    /// AOT MAC in `boatramp-server::aot`). `Component::deserialize` loads EXECUTABLE native
    /// code and is only lightly validated — its embedded version check fails closed on a
    /// cross-wasmtime-version blob but is explicitly NOT integrity protection against a
    /// same-version forgery. Passing unverified bytes here is arbitrary code execution. Any
    /// deserialize error returns `Err` so the caller falls back to compile-from-source.
    pub fn hydrate_request_artifact(
        &self,
        hash: &str,
        artifact: &[u8],
    ) -> Result<(), HandlerError> {
        // SAFETY: the caller has verified the cluster AOT MAC over exactly these bytes, so
        // they were produced by a trusted node's `Component::serialize` for this engine
        // fingerprint — satisfying `deserialize`'s "only previously-serialized bytes"
        // contract. A tampered/foreign blob never reaches here (MAC check precedes this call).
        let component = unsafe { Component::deserialize(&self.engine, artifact) }
            .map_err(|err| HandlerError::Compile(format!("deserialize AOT artifact: {err}")))?;
        let instance_pre = self
            .build_linker()?
            .instantiate_pre(&component)
            .map_err(|err| HandlerError::Compile(err.to_string()))?;
        let pre = ProxyPre::new(instance_pre).map_err(|_| {
            HandlerError::Compile("component is not a wasi:http/proxy handler".into())
        })?;
        cache_insert_evicted(&self.cache, hash, pre);
        Ok(())
    }

    /// A stable 32-byte fingerprint of this engine's codegen-relevant configuration, used to
    /// PARTITION the AOT artifact cache so an incompatible artifact is never fetched
    /// (cold-start cap-req 09). Derived from wasmtime's `precompile_compatibility_hash`
    /// ("binaries from one engine deserialize in another iff this matches") via a
    /// DETERMINISTIC (fixed-seed) reduction, domain-separated. Not security-load-bearing —
    /// the artifact MAC and `deserialize`'s own version check are the safety gates; a wrong
    /// fingerprint only ever causes a cache miss or a safe `Err`, never an unsafe load.
    pub fn artifact_fingerprint(&self) -> [u8; 32] {
        use sha2::Digest as _;
        use std::hash::Hash as _;
        // Feed wasmtime's compatibility hash through a SHA-256-backed hasher directly (no lossy
        // u64 reduction), so the full compat digest — not 64 bits of it — distinguishes engine
        // configs; this removes even a theoretical fingerprint collision that could make two
        // incompatible engines share an `aot/<fp>/…` partition. Domain-separated + deterministic
        // (SHA-256 has no per-process seed), so cluster peers on the same binary agree.
        let mut hasher = Sha256Hasher(sha2::Sha256::new());
        sha2::Digest::update(&mut hasher.0, AOT_FINGERPRINT_DOMAIN);
        self.engine
            .precompile_compatibility_hash()
            .hash(&mut hasher);
        let out = hasher.0.finalize();
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&out);
        fp
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

    /// Permit (or refuse) a guest's gated `wasi:sockets` capability to open an outbound TCP
    /// `connect` — the operator posture's `allow_guest_tcp_egress` (`PLAN-handler-tcp-egress`).
    /// Default (`false`) keeps the socket host deny-all (no permissive `socket_addr_check` is ever
    /// installed, so every target is refused). When `true`, `new_store` installs a check that is
    /// **connect-only** (denies `bind`/`listen`/UDP), permits a resolved peer ONLY if it matches
    /// this invocation's per-handler `egress_allowlist` (IP / CIDR / host-resolved domain + port),
    /// and still applies the `is_global_ip` SSRF floor unless `with_private_egress` is also on.
    /// Independent of every `wasi:http` egress knob.
    #[must_use]
    pub fn with_tcp_egress(mut self, allow: bool) -> Self {
        self.allow_tcp_egress = allow;
        self
    }

    /// Permit (or refuse) host-owned inbound-TCP **listeners** to dispatch an accepted connection to a
    /// guest — the operator posture's `allow_guest_tcp_listener` (PLAN-handler-tcp-inbound). Default
    /// (`false`, off under multi-tenant) makes [`dispatch_tcp_connection`](Self::dispatch_tcp_connection)
    /// refuse before instantiating any guest. This is INDEPENDENT of [`with_tcp_egress`](Self::with_tcp_egress)
    /// (inbound ≠ outbound authority) and NEVER grants the guest `wasi:sockets`: a dispatched connection
    /// is handed only its already-accepted `wasi:io` byte streams; the socket host's deny-all default
    /// (no permissive `socket_addr_check`, no `allow_tcp`) stands for this lane.
    #[must_use]
    pub fn with_tcp_listener(mut self, allow: bool) -> Self {
        self.allow_tcp_listener = allow;
        self
    }

    /// Override the `tcp-egress` capability's per-dial timeouts (`PLAN-handler-tcp-egress` Build A,
    /// mailroom #15): `connect` bounds the TCP connect + TLS handshake together; `idle` bounds how
    /// long the peer may go silent after the handshake before the connection's streams surface a
    /// timeout. Defaults are [`DEFAULT_TCP_EGRESS_CONNECT_TIMEOUT`] / [`DEFAULT_TCP_EGRESS_IDLE_TIMEOUT`]
    /// when never called. Independent of [`with_tcp_egress`](Self::with_tcp_egress) (which gates
    /// WHETHER a dial is permitted; this bounds how long a permitted one may take).
    #[cfg(feature = "tcp-egress")]
    #[must_use]
    pub fn with_tcp_egress_timeouts(mut self, connect: Duration, idle: Duration) -> Self {
        self.tcp_egress_connect_timeout = connect;
        self.tcp_egress_idle_timeout = idle;
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

    /// The [`Lane::Streaming`] idle cap, milliseconds (see [`with_streaming_idle_ms`](Self::with_streaming_idle_ms)).
    #[must_use]
    pub fn streaming_idle_ms(&self) -> u64 {
        self.streaming_idle_ms
    }

    /// Live permits currently available on the streaming lane — 0 when every slot is occupied.
    /// Exposed for tests asserting a streaming slot is held for the stream's whole life
    /// (PLAN-handler-stream-lifecycle GAP1), not merely until the head is produced.
    #[must_use]
    pub fn streaming_available_permits(&self) -> usize {
        self.streaming_semaphore.available_permits()
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

    /// [`precompile_and_serialize_request`](Self::precompile_and_serialize_request) behind the
    /// same compile-concurrency gate + off-runtime compile as
    /// [`precompile_gated`](Self::precompile_gated) — the producer path for the portable AOT
    /// artifact (cold-start cap-req 09): one gated compile both warms the local cache AND yields
    /// the serialized artifact the serve layer frames + publishes for fresh replicas.
    pub async fn precompile_and_serialize_gated(
        &self,
        hash: &str,
        wasm: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        let _permit = self
            .compile_gate
            .acquire()
            .await
            .expect("compile gate is never closed");
        Self::run_compile_off_runtime(|| self.precompile_and_serialize_request(hash, wasm))
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

    /// Read-only snapshot of the instance-lifecycle + memory stats (an
    /// instance-observability request): each lane's live warm set / capacity / in-flight, the lifetime
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
        // A pinned (warm-floor) component is always resident — count it warm so the serve
        // path elides the blob read exactly as for an LRU-warm component. `contains` does not
        // promote (a non-mutating peek), matching the main-cache check.
        self.pinned.lock().unwrap().contains(hash) || self.cache.lock().unwrap().contains(hash)
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
        // Warm floor first: a pinned component is a warm hit and never touches the LRU.
        if let Some(pre) = self.pinned.lock().unwrap().get(hash) {
            self.stats.request.record_warm_hit();
            return Ok((pre.clone(), false));
        }
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
        // the term a warm hit avoids — the signal needed to tell a cold start from execution.
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
        // HTTP-driven re-entry: a POST that can't get an Async-lane slot surfaces as a retryable 503,
        // so acquire non-blocking and return `Overloaded` on contention.
        let _permit = self
            .lane_semaphore(Lane::Async)
            .try_acquire()
            .map_err(|_| HandlerError::Overloaded)?;
        // HTTP-driven session: no raw-socket wire security at this layer (the edge terminates TLS);
        // pass no connection-security handle so `tcp-connection-context` fail-closes to plaintext.
        self.dispatch_session_inner(
            hash,
            wasm,
            batch,
            bindings,
            limits,
            #[cfg(feature = "tcp-listener")]
            None,
        )
        .await
    }

    /// Like [`dispatch_session`](Self::dispatch_session) but AWAITS the Async-lane permit instead of
    /// returning `Overloaded` immediately (cap-req 08, the socket-driven session path). A session
    /// driven over a raw listener socket cannot be 503'd mid-connection the way an HTTP POST can, so a
    /// re-entry applies backpressure by waiting for a lane slot. Total waiting is still bounded: the
    /// connection holds a per-listener `max_conns` slot and is reaped by its `max_conn_duration` cap.
    /// Try to admit one more live session-mode listener connection against the node-global ceiling
    /// ([`DEFAULT_SESSION_CONN_CAP`]). The returned owned permit is held by the connection driver for
    /// the connection's WHOLE life (parked included) and released on close/EOF; `None` ⇒ the node is at
    /// the ceiling and the connection must be refused (cap-req 08 / Security review LOW backstop).
    #[cfg(all(feature = "session", feature = "tcp-listener"))]
    pub fn acquire_session_conn(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        std::sync::Arc::clone(&self.session_conn_semaphore)
            .try_acquire_owned()
            .ok()
    }

    #[cfg(all(feature = "session", feature = "tcp-listener"))]
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_session_socket(
        &self,
        hash: &str,
        wasm: &[u8],
        batch: SessionBatch,
        bindings: Bindings,
        limits: Limits,
        listener_declared: bool,
        // Live wire-security of this connection (mailroom cap-req #16); the driver passes the SAME
        // handle on every re-entry (and, for STARTTLS, a clone is flipped to TLS by the pump).
        conn_security: crate::ConnectionSecurity,
    ) -> Result<(), HandlerError> {
        // The SAME mutation-verified structural gates the connection lane enforces (Security review
        // MEDIUM-1 — the session path must carry the same fail-closed backstop, so a future per-listener
        // egress or a bind-site regression can't silently serve under a disabled posture or grant the
        // guest socket authority). GATE 1: posture + operator-declared. GATE 2: never raw-socket
        // authority. GATE 3: no RAW (non-host-mediated) outbound-TCP egress allowlist — cap-req 19
        // lets a listener carry a host-mediated `tcp-egress` allowlist, which does NOT install a guest
        // socket check.
        if !tcp_listener_dispatch_decision(self.allow_tcp_listener, listener_declared) {
            return Err(HandlerError::Internal(
                "session listener dispatch refused (posture `allow_guest_tcp_listener` is off, or the \
                 listener is not operator-declared)"
                    .into(),
            ));
        }
        if conn_lane_grants_socket_authority() {
            return Err(HandlerError::Internal(
                "session listener lane must never grant the guest raw socket authority (wasi:sockets) \
                 — refusing to dispatch"
                    .into(),
            ));
        }
        if !conn_lane_sockets_denied(&bindings) {
            return Err(HandlerError::Internal(
                "session listener bindings carry a non-host-mediated outbound-TCP egress allowlist — \
                 refusing (would grant the guest raw wasi:sockets connect authority)"
                    .into(),
            ));
        }
        // DEDICATED pool (Security review HIGH-1): a socket-session re-entry must NOT take the shared
        // Async-lane permit (which serves consumers/HTTP-sessions/crons) — untrusted, blocking,
        // long-held socket work there would starve them. Acquire the session-socket pool instead; the
        // blocking wait is bounded by the per-re-entry wall-clock watchdog the driver wraps this in.
        let _permit = self
            .session_socket_semaphore
            .acquire()
            .await
            .map_err(|_| HandlerError::Overloaded)?;
        self.dispatch_session_inner(hash, wasm, batch, bindings, limits, Some(conn_security))
            .await
    }

    /// The body of a session re-entry, AFTER the lane permit is held (shared by the HTTP
    /// [`dispatch_session`](Self::dispatch_session) and the socket
    /// [`dispatch_session_socket`](Self::dispatch_session_socket) paths — they differ only in how the
    /// permit is acquired). Builds a fresh store, instantiates the `session-handler`, calls `handle`
    /// once with the batch, finalizes the per-invocation SQL txn, and drops the store (so NO instance
    /// survives the call — the hibernation property).
    #[cfg(feature = "session")]
    async fn dispatch_session_inner(
        &self,
        hash: &str,
        wasm: &[u8],
        batch: SessionBatch,
        bindings: Bindings,
        limits: Limits,
        // Live wire-security of the socket this session re-entry drives (mailroom cap-req #16),
        // exposed via `tcp-connection-context`. `None` for the HTTP-driven session path (no raw
        // socket at this layer — fail-closed to plaintext). Only present when the listener surface is
        // compiled in.
        #[cfg(feature = "tcp-listener")] conn_security: Option<crate::ConnectionSecurity>,
    ) -> Result<(), HandlerError> {
        let session_pre = self.session_pre(hash, wasm)?;
        let mut store = self.new_store(bindings, self.effective_limits(Lane::Async, limits));
        #[cfg(feature = "tcp-listener")]
        {
            store.data_mut().conn_security = conn_security;
        }
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

    /// Compile + pre-instantiate a **tcp-connection** component (`tcp-connection-handler` export),
    /// cached by hash (PLAN-handler-tcp-inbound). Mirrors [`session_pre`](Self::session_pre).
    #[cfg(feature = "tcp-listener")]
    fn tcp_connection_pre(
        &self,
        hash: &str,
        wasm: &[u8],
    ) -> Result<tcp_connection_world::TcpConnectionHostPre<HostState>, HandlerError> {
        if let Some(pre) = self.tcp_connection_cache.lock().unwrap().get(hash) {
            return Ok(pre.clone());
        }
        let compiled_at = std::time::Instant::now();
        let component = Component::from_binary(&self.engine, wasm)
            .map_err(|err| HandlerError::Compile(err.to_string()))?;
        let instance_pre = self
            .build_linker()?
            .instantiate_pre(&component)
            .map_err(|err| HandlerError::Compile(err.to_string()))?;
        let pre = tcp_connection_world::TcpConnectionHostPre::new(instance_pre).map_err(|_| {
            HandlerError::Compile("component is not a tcp-connection handler".into())
        })?;
        tracing::info!(
            component = %hash,
            lane = "tcp-connection",
            compile_ms = compiled_at.elapsed().as_millis() as u64,
            "wasm component cold-compiled (warm-cache miss)"
        );
        let _evicted = cache_insert_evicted(&self.tcp_connection_cache, hash, pre.clone());
        Ok(pre)
    }

    /// Drive one host-owned inbound-TCP **connection** through a guest `tcp-connection-handler`
    /// (`hash`), handing it the ALREADY-ACCEPTED connection's peer address + `wasi:io` byte streams
    /// (PLAN-handler-tcp-inbound). The host owns the socket (operator declared the listener + bound
    /// it); the guest receives NO `wasi:sockets` — only the connection's `input-stream`/`output-stream`
    /// as host-constructed resources. Runs on the dedicated **conn lane** (its own permit), with the
    /// per-invocation epoch deadline + CPU fuel DISABLED in favour of `idle_timeout` +
    /// `max_conn_duration` (a long-lived `handle` must not trip the request-sized epoch); the linear-
    /// memory ceiling still binds. A peer drop surfaces to the guest as a stream error; the guest
    /// returning, trapping, or either timeout all end the connection and drop the store (closing the
    /// socket — clean teardown).
    ///
    /// Two gates to dispatch (belt-and-suspenders, via the pure [`tcp_listener_dispatch_decision`]): the
    /// node posture must allow listeners AND the operator must have DECLARED this listener. Returns
    /// `Overloaded` when the conn lane is full. `listener_declared` is the caller's config-lookup result
    /// (the serve accept loop only runs for a declared listener).
    #[cfg(feature = "tcp-listener")]
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_tcp_connection<R, W>(
        &self,
        hash: &str,
        wasm: &[u8],
        peer: String,
        read_half: R,
        write_half: W,
        bindings: Bindings,
        limits: Limits,
        idle_timeout: Duration,
        max_conn_duration: Duration,
        listener_declared: bool,
        // Live wire-security of this connection (mailroom cap-req #16), exposed to the guest via the
        // `tcp-connection-context` import. For a STARTTLS listener the pump holds a clone and flips
        // it to TLS on upgrade.
        conn_security: crate::ConnectionSecurity,
    ) -> Result<(), HandlerError>
    where
        R: tokio::io::AsyncRead + Send + Unpin + 'static,
        W: tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        // TWO gates to dispatch, via the SINGLE enforced predicate the mutation-verified gate drives
        // (tested == enforced): the node posture allows inbound listeners AND this listener was declared.
        if !tcp_listener_dispatch_decision(self.allow_tcp_listener, listener_declared) {
            return Err(HandlerError::Internal(
                "inbound TCP listener dispatch refused (posture `allow_guest_tcp_listener` is off, \
                 or the listener is not operator-declared)"
                    .into(),
            ));
        }
        // STRUCTURAL SAFETY INVARIANT (mutation-gated): the conn lane NEVER grants the guest raw socket
        // authority (`wasi:sockets`). `conn_lane_grants_socket_authority()` is a constant `false` in
        // every shipped build, so this guard never fires — the guest's only network surface is the
        // handed `wasi:io` streams. The `add_socket_authority` gate mutation flips it, and this guard
        // then fails CLOSED here while the structural gate test goes RED (tested == enforced).
        if conn_lane_grants_socket_authority() {
            return Err(HandlerError::Internal(
                "inbound TCP connection lane must never grant the guest raw socket authority \
                 (wasi:sockets) — refusing to dispatch"
                    .into(),
            ));
        }
        // REAL no-raw-sockets invariant (security-review MEDIUM; cap-req 19): the received bindings
        // must not cause `new_store` to install a permissive GUEST `socket_addr_check` — i.e. the
        // allowlist is EMPTY, or the invocation is HOST-MEDIATED-egress-only (a non-empty allowlist
        // that feeds ONLY the host-mediated `tcp-egress` dial, never the guest's own `wasi:sockets`).
        // Fail CLOSED if a conn-lane dispatch ever carried a RAW (non-host-mediated) allowlist (a
        // future-refactor guard against silently handing the guest connect authority).
        if !conn_lane_sockets_denied(&bindings) {
            return Err(HandlerError::Internal(
                "inbound TCP connection lane bindings carry a non-host-mediated outbound-TCP egress \
                 allowlist — refusing (would grant the guest raw wasi:sockets connect authority)"
                    .into(),
            ));
        }
        // One conn-lane permit per live connection (held for the connection's whole life), so a burst of
        // long-lived listener connections can't exhaust the sync request pool nor starve the async drain.
        let _permit = self
            .tcp_conn_semaphore
            .try_acquire()
            .map_err(|_| HandlerError::Overloaded)?;
        let pre = self.tcp_connection_pre(hash, wasm)?;
        // Clamp the memory ceiling to the conn-lane ceiling (a per-listener override may only lower it).
        let eff = Limits {
            memory_bytes: limits.memory_bytes.min(self.tcp_conn_limits.memory_bytes),
            ..self.tcp_conn_limits
        };
        let mut store = self.new_store(bindings, eff);
        // Expose this connection's live wire-security to the guest's `tcp-connection-context` import
        // (mailroom cap-req #16).
        store.data_mut().conn_security = Some(conn_security);
        // Conn lane (security-review HIGH): the per-invocation epoch TRAP deadline + CPU fuel are the
        // wrong bound for a continuous byte stream (a long-lived `handle` would trip the request epoch).
        // But disabling the epoch outright (`u64::MAX`) lets a CPU-bound guest that makes no suspending
        // host call run forever inside ONE `call_handle` poll — pinning a tokio worker AND starving the
        // wall-clock watchdog in the `select!` below (so idle/max-duration could never fire). Instead
        // arm the epoch to YIELD every `CONN_EPOCH_YIELD_TICKS`: the fiber periodically returns
        // `Poll::Pending` (so the watchdog is re-polled and can drop the call, and no worker is pinned)
        // WITHOUT trapping (the long-lived goal is preserved). The engine-wide epoch ticker drives it.
        // Fuel stays unmetered — CPU is bounded by wall-clock `max_conn_duration` via the watchdog.
        store.epoch_deadline_async_yield_and_update(CONN_EPOCH_YIELD_TICKS);
        // `epoch_deadline_async_yield_and_update` sets only the BEHAVIOR (yield + re-arm by the budget);
        // it does NOT arm the first deadline, which `new_store` left at the request-sized value. Arm it
        // to the yield budget so the FIRST yield lands at ~CONN_EPOCH_YIELD_TICKS ticks, not seconds out
        // (otherwise a non-yielding guest would run unchecked until the request-sized deadline — the
        // exact starvation this fix prevents).
        store.set_epoch_deadline(CONN_EPOCH_YIELD_TICKS);
        let _ = store.set_fuel(u64::MAX);
        // Wrap the accepted socket halves so any byte movement (either direction) refreshes the idle
        // clock, then hand them to the guest as host-owned `wasi:io` stream resources. The guest imports
        // only `wasi:io/streams` (never `wasi:sockets`), so these are its sole network surface.
        let last_activity = Arc::new(Mutex::new(tokio::time::Instant::now()));
        let in_stream: wasmtime_wasi::p2::DynInputStream =
            Box::new(wasmtime_wasi::p2::pipe::AsyncReadStream::new(
                IdleTracked::new(read_half, Arc::clone(&last_activity)),
            ));
        let out_stream: wasmtime_wasi::p2::DynOutputStream =
            Box::new(wasmtime_wasi::p2::pipe::AsyncWriteStream::new(
                TCP_CONN_WRITE_BUDGET,
                IdleTracked::new(write_half, Arc::clone(&last_activity)),
            ));
        let in_res = store
            .data_mut()
            .table
            .push(in_stream)
            .map_err(|e| HandlerError::Internal(format!("push input-stream: {e}")))?;
        let out_res = store
            .data_mut()
            .table
            .push(out_stream)
            .map_err(|e| HandlerError::Internal(format!("push output-stream: {e}")))?;
        let conn = pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| classify(&e, store.data().oom()))?;
        // Drive the guest handler against the host idle + max-duration watchdog. Whichever resolves
        // first wins; a timeout cancels (drops) the guest future, and dropping the store below tears the
        // connection down (the stream resources' reader/writer tasks are cancelled, closing the socket).
        let outcome = {
            let call = conn
                .boatramp_handlers_tcp_connection_handler()
                .call_handle(&mut store, &peer, in_res, out_res);
            tokio::pin!(call);
            let watchdog = conn_watchdog(
                Arc::clone(&last_activity),
                idle_timeout,
                max_conn_duration,
                tokio::time::Instant::now(),
            );
            tokio::pin!(watchdog);
            tokio::select! {
                r = &mut call => Ok(r),
                kind = &mut watchdog => Err(kind),
            }
        };
        // Close any per-invocation SQL transaction: commit only on a clean guest return.
        #[cfg(feature = "sql")]
        store
            .data_mut()
            .sql
            .finalize(matches!(&outcome, Ok(Ok(Ok(())))))
            .await;
        match outcome {
            Ok(Ok(Ok(()))) => Ok(()),
            // The guest-returned `connection-error.message` is UNTRUSTED (guest-controlled length) and
            // the WIT promises it is bounded host-side — truncate it to `MAX_CONSUMER_ERROR_LEN` before
            // it is formatted into the error + logged, mirroring the consumer-error path (the DLQ/log
            // layer strips control chars). (security-review LOW).
            Ok(Ok(Err(err))) => Err(HandlerError::Trap(format!(
                "tcp-connection handler returned error: {}",
                err.message
                    .chars()
                    .take(MAX_CONSUMER_ERROR_LEN)
                    .collect::<String>()
            ))),
            Ok(Err(trap)) => Err(classify(&trap, store.data().oom())),
            // An idle/max-duration teardown is the normal end of a long-lived connection (the conn-lane
            // DoS bound), not a handler failure.
            Err(ConnTimeout::Idle) => {
                tracing::debug!(component = %hash, %peer, "tcp-connection idle-timeout teardown");
                Ok(())
            }
            Err(ConnTimeout::MaxDuration) => {
                tracing::debug!(component = %hash, %peer, "tcp-connection max-duration teardown");
                Ok(())
            }
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
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
        wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;
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
        // Host-terminated outbound-TLS egress (`PLAN-handler-tcp-egress` Build A, mailroom #15):
        // reuses the SAME per-invocation `egress_allowlist` the gated `wasi:sockets` capability
        // attaches (no new grant kind) + the engine's `allow_tcp_egress`/`allow_private_egress`
        // posture + its guest-egress extra-CA roots, so the dial is gated identically to a guest's
        // own `wasi:sockets` connect.
        #[cfg(feature = "tcp-egress")]
        bindings::tcp_egress::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::tcp_egress::TcpEgressHost::new(
                &mut state.table,
                state.tcp_egress_enabled,
                state.http_hooks.allow_private_egress,
                state.bindings.egress_allowlist(),
                state.http_hooks.guest_egress_extra_roots.clone(),
                state.tcp_egress_connect_timeout,
                state.tcp_egress_idle_timeout,
            )
        })?;
        // Host-owned-listener connection-context (mailroom cap-req #16): a listener guest reads the
        // CURRENT wire security of its connection. Always linked under `tcp-listener`; a non-listener
        // invocation has `conn_security == None`, which the binding fail-closes to `plaintext`.
        #[cfg(feature = "tcp-listener")]
        bindings::tcp_connection_context::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::tcp_connection_context::ConnContextHost::new(state.conn_security.clone())
        })?;
        // Host-side DNS resolver (mailroom cap-req #20): the resolver half of the egress story. Gated
        // deny-by-default (binding `None` ⇒ `access-denied`) AND by the SAME egress posture as
        // `tcp-egress` (`tcp_egress_enabled`); the SSRF floor on resolved addresses uses the same
        // `allow_private_egress` flag as a `tcp-egress` dial.
        #[cfg(feature = "tcp-egress")]
        bindings::dns_resolve::add_to_linker(&mut linker, |state: &mut HostState| {
            bindings::dns_resolve::DnsResolveHost::new(
                state.bindings.dns_resolve(),
                state.tcp_egress_enabled,
                state.http_hooks.allow_private_egress,
            )
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
            // The streaming lane acquires an OWNED permit directly off the `Arc` in `serve_lane`
            // (carried into the response body); this borrowed view is here only for symmetry /
            // `lane_ceiling` callers.
            Lane::Streaming => self.streaming_semaphore.as_ref(),
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
        // Gated `wasi:sockets` outbound-TCP (`PLAN-handler-tcp-egress`). Deny-by-default: unless the
        // node posture allows TCP egress AND this invocation carries a non-empty per-handler
        // allowlist, no permissive `socket_addr_check` is installed — so the socket host's default
        // (`SocketAddrCheck::default()` denies ALL) stands and every connect fails closed. When both
        // hold, install a check that is (a) **connect-only** — every non-`TcpConnect` use
        // (`bind`/`listen`, all UDP) is denied, so inbound stays the container/microVM model; (b)
        // **allowlisted** — a resolved peer is permitted only if it matches an `egress_allowlist`
        // entry (IP / CIDR / host-resolved domain + port); and (c) **SSRF-floored** — even an
        // allowlisted peer must be globally routable unless `allow_private_egress` is also on, so the
        // capability can't be an SSRF bypass to the metadata endpoint / private ranges. UDP is also
        // blanket-disabled and `ip-name-lookup` is enabled only here (gated to the posture) so a guest
        // can resolve an allowlisted domain before connecting.
        // cap-req 19: a HOST-MEDIATED-egress-only invocation (a host-owned listener guest) may carry a
        // non-empty allowlist to drive the `tcp-egress` binding (host dials + terminates TLS), but its
        // raw `wasi:sockets` must STAY deny-all — so skip the permissive GUEST socket check entirely for
        // it. `TcpEgressHost` reads the allowlist independently, so host-mediated egress still works.
        let egress_allowlist = bindings.egress_allowlist();
        if installs_guest_socket_check(
            self.allow_tcp_egress,
            egress_allowlist.is_empty(),
            bindings.host_mediated_egress_only(),
        ) {
            let allow_private = self.allow_private_egress;
            let posture_tcp_egress = self.allow_tcp_egress;
            let allowlist = egress_allowlist;
            wasi_builder.allow_tcp(true);
            wasi_builder.allow_udp(false);
            wasi_builder.allow_ip_name_lookup(true);
            wasi_builder.socket_addr_check(move |addr, use_| {
                let allowlist = allowlist.clone();
                // The decision is the pure `tcp_connect_decision` (the SAME predicate the TE-3 gate
                // tests + mutation-verifies), so the enforced path and the tested path never drift.
                Box::pin(async move {
                    tcp_connect_decision(use_, addr, &allowlist, allow_private, posture_tcp_egress)
                        .await
                })
            });
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
            http_hooks: GuestEgressHooks {
                outbound_timeout: self.outbound_timeout,
                allow_private_egress: self.allow_private_egress,
                self_egress_addrs: self.self_egress_addrs.clone(),
                guest_egress_extra_roots: self.guest_egress_extra_roots.clone(),
                egress_depth: 0,
                egress_nonce: self.egress_nonce,
            },
            #[cfg(feature = "tcp-egress")]
            tcp_egress_enabled: self.allow_tcp_egress,
            #[cfg(feature = "tcp-egress")]
            tcp_egress_connect_timeout: self.tcp_egress_connect_timeout,
            #[cfg(feature = "tcp-egress")]
            tcp_egress_idle_timeout: self.tcp_egress_idle_timeout,
            #[cfg(feature = "sql")]
            sql,
            // Set by the listener dispatch after `new_store`; a non-listener invocation leaves it
            // `None` (the `tcp-connection-context` import fail-closes to `plaintext`).
            #[cfg(feature = "tcp-listener")]
            conn_security: None,
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
        // Concurrency permit. The streaming lane takes an OWNED permit it carries INTO the response
        // body (released only when the stream ends / the client disconnects — GAP1), so
        // `streaming_max_concurrency` actually bounds concurrent open streams; the sync/async lanes
        // hold a borrowed permit for the serve scope (their bodies are short-lived). Both map a full
        // lane to `Overloaded`.
        let (_permit, streaming_permit) = if lane == Lane::Streaming {
            let owned = self
                .streaming_semaphore
                .clone()
                .try_acquire_owned()
                .map_err(|_| {
                    self.stats.record_overloaded(hash);
                    HandlerError::Overloaded
                })?;
            (None, Some(owned))
        } else {
            let borrowed = self.lane_semaphore(lane).try_acquire().map_err(|_| {
                self.stats.record_overloaded(hash);
                HandlerError::Overloaded
            })?;
            (Some(borrowed), None)
        };
        // Count this component's in-flight invocation (RAII: decremented on drop). For the streaming
        // lane this guard is moved into the response body so the in-flight count — like the permit —
        // tracks the stream's whole life, not just time-to-head; other lanes drop it at serve-scope end.
        let _cguard = self.stats.enter_component(hash);
        let (proxy_pre, cold) = self.proxy_pre(hash, wasm)?;

        let effective = self.effective_limits(lane, limits);
        let mut store = self.new_store(bindings, effective);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let out = store
            .data_mut()
            .http()
            .new_response_outparam(sender)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        // Build the incoming request with a **streamed**, byte-capped body (no up-front buffering).
        // `stream_incoming_body` bridges the live body frame-by-frame, enforcing `max_body_bytes` and
        // mapping read errors to `wasmtime_wasi_http::Error`; v49's `WasiHttpCtxView::new_incoming_request`
        // then wraps it as the guest's `wasi:http` incoming request and pushes it to the table.
        let (parts, body) = request.into_parts();
        // Inbound self-egress recursion depth (nonce-verified — an external client can't forge it;
        // a fresh external request is depth 0, a guest self-call continues the chain at depth+1). The
        // SAME verification the request dispatch uses to skip the serve-admission gate for a
        // re-entrant self-call, so the two can never drift.
        let egress_depth = self.verified_self_egress_depth(&parts.headers);
        store.data_mut().http_hooks.egress_depth = egress_depth;
        let bridged = stream_incoming_body(body, effective.max_body_bytes);
        let req = store
            .data_mut()
            .http()
            .new_incoming_request(Scheme::Http, http::Request::from_parts(parts, bridged))
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
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
        // signal (a latency-observability ask): distinguishes a cold (re)compile + the instantiate cost from
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
            // Guest produced a response head; `task` keeps streaming the body.
            Ok(Ok(response)) => {
                if lane == Lane::Streaming {
                    // Carry the lane slot + in-flight guard INTO the response body so the stream
                    // occupies a slot for its whole life (GAP1), and arm an idle/max-duration
                    // watchdog that tears the guest down and reclaims the slot (GAP2). Dropping the
                    // body (client disconnect, or the server finishing it) aborts the guest promptly.
                    let permit =
                        streaming_permit.expect("the streaming lane acquired an owned permit");
                    let guest_abort = task.abort_handle();
                    // `task` (the JoinHandle) is dropped here → the guest runs detached, reclaimed
                    // via `guest_abort` on idle / max-duration / body-drop.
                    let response = guard_streaming_response(
                        response,
                        guest_abort,
                        permit,
                        _cguard,
                        self.streaming_idle_ms,
                        effective.timeout_ms,
                    );
                    Ok((response, timing))
                } else {
                    // Non-streaming lanes: any (short) body keeps streaming on the detached `task`;
                    // the borrowed permit + `_cguard` drop at serve-scope end as before.
                    Ok((response, timing))
                }
            }
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

/// Teardown reason for a streaming-lane response (PLAN-handler-stream-lifecycle GAP2).
#[derive(Debug, PartialEq, Eq)]
enum StreamTimeout {
    /// No body frame was emitted to the client for the lane's idle window.
    Idle,
    /// The stream reached the lane's absolute `timeout_ms` lifetime.
    MaxDuration,
}

/// The streaming-lane wall-clock watchdog: resolves to [`StreamTimeout::Idle`] when no body frame
/// has flowed for `idle` (the shared `last_activity` is stamped by [`GuardedStreamBody::poll_frame`]),
/// or [`StreamTimeout::MaxDuration`] when the stream has been live for `max` — whichever first.
/// Deliberately the same shape as the inbound-TCP [`conn_watchdog`] so the two long-lived-lifecycle
/// bounds never drift, and unit-testable with `tokio::time::pause` (no guest component needed). Uses
/// [`tokio::time::Instant`] throughout so a paused test clock controls it deterministically.
async fn stream_watchdog(
    last_activity: Arc<Mutex<tokio::time::Instant>>,
    idle: Duration,
    max: Duration,
) -> StreamTimeout {
    let started = tokio::time::Instant::now();
    // Poll at a fraction of the shorter window (bounded) so either a short idle or a short max is
    // observed promptly.
    let tick = (idle.min(max) / 4).clamp(Duration::from_millis(50), Duration::from_secs(5));
    loop {
        tokio::time::sleep(tick).await;
        let idle_for = last_activity
            .lock()
            .map(|g| g.elapsed())
            .unwrap_or_default();
        if idle_for >= idle {
            return StreamTimeout::Idle;
        }
        if started.elapsed() >= max {
            return StreamTimeout::MaxDuration;
        }
    }
}

/// Aborts its wrapped tasks on drop. Carried by a [`GuardedStreamBody`] so that dropping the body
/// (client disconnect, or the server finishing the stream) promptly tears down both the guest task
/// and its idle watchdog — after which the lane permit + in-flight guard the body also carries are
/// released (PLAN-handler-stream-lifecycle).
struct AbortOnDrop(Vec<tokio::task::AbortHandle>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}

/// A streaming response body that occupies its lane slot for the stream's **whole life**
/// (PLAN-handler-stream-lifecycle GAP1): it carries the lane's [`OwnedSemaphorePermit`] and the
/// component in-flight [`ComponentGuard`](crate::instance_stats::ComponentGuard), released only when
/// the body is dropped (fully sent, or the client disconnected). It also stamps `last_activity` on
/// every emitted frame so the idle watchdog can reclaim a silent (slowloris) stream, and holds an
/// [`AbortOnDrop`] that tears the guest task + watchdog down when the body is dropped. Delegates all
/// body semantics to `inner`.
struct GuardedStreamBody {
    inner: HyperOutgoingBody,
    last_activity: Arc<Mutex<tokio::time::Instant>>,
    // Drop order (declaration order): abort the tasks first, then release the slot + in-flight count.
    _abort: AbortOnDrop,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _cguard: crate::instance_stats::ComponentGuard,
}

impl HttpBody for GuardedStreamBody {
    type Data = Bytes;
    type Error = wasmtime_wasi_http::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, wasmtime_wasi_http::Error>>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_frame(cx);
        // Stamp activity on a real frame to the client so the idle watchdog never kills an
        // actively-producing stream.
        if let Poll::Ready(Some(Ok(_))) = &r
            && let Ok(mut g) = this.last_activity.lock()
        {
            *g = tokio::time::Instant::now();
        }
        r
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Wrap a streaming guest's response so its lane slot + in-flight guard live for the stream's whole
/// life, and spawn the idle/max-duration watchdog that reclaims the slot. See [`GuardedStreamBody`].
fn guard_streaming_response(
    response: http::Response<HyperOutgoingBody>,
    guest_abort: tokio::task::AbortHandle,
    permit: tokio::sync::OwnedSemaphorePermit,
    cguard: crate::instance_stats::ComponentGuard,
    idle_ms: u64,
    max_ms: u64,
) -> http::Response<HyperOutgoingBody> {
    let (parts, inner) = response.into_parts();
    let last_activity = Arc::new(Mutex::new(tokio::time::Instant::now()));
    let wd_last = Arc::clone(&last_activity);
    let wd_abort = guest_abort.clone();
    let watchdog = tokio::spawn(async move {
        let reason = stream_watchdog(
            wd_last,
            Duration::from_millis(idle_ms.max(1_000)),
            Duration::from_millis(max_ms.max(1)),
        )
        .await;
        // Tear the guest down → its wasi-http outgoing body ends → the server finishes the response
        // → the body is dropped → the permit + guard release.
        tracing::debug!(target: "boatramp::handler", ?reason, "streaming response torn down by the lane watchdog");
        wd_abort.abort();
    });
    let body = GuardedStreamBody {
        inner,
        last_activity,
        _abort: AbortOnDrop(vec![guest_abort, watchdog.abort_handle()]),
        _permit: permit,
        _cguard: cguard,
    };
    http::Response::from_parts(parts, body.boxed_unsync())
}

/// An empty request body (for synthetic requests / requests without a body).
pub fn empty_body() -> http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error> {
    Empty::<bytes::Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// A `Send + Sync` [`HttpBody`] backed by an mpsc receiver — the bridge target
/// for [`stream_incoming_body`]. Holding only the receiver keeps it `Sync` (an
/// arbitrary streaming body, e.g. axum's, may not be), so it boxes into the
/// `Send + Sync` [`HyperIncomingBody`] the wasi-http layer requires.
struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, wasmtime_wasi_http::Error>>,
}

impl HttpBody for ChannelBody {
    type Data = Bytes;
    type Error = wasmtime_wasi_http::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, wasmtime_wasi_http::Error>>> {
        self.rx.poll_recv(cx)
    }
}

/// Bridge an arbitrary request body into a [`HyperIncomingBody`] for the guest,
/// **streaming** frame-by-frame (no up-front buffering) while enforcing a running
/// byte cap. A forwarder task reads `body` (it only needs `Send`, not `Sync`),
/// enforces `max_bytes`, maps any read error or cap breach to an `wasmtime_wasi_http::Error`, and
/// pushes frames through a channel the `Send + Sync` [`ChannelBody`] drains.
fn stream_incoming_body<B>(body: B, max_bytes: Option<u64>) -> HyperIncomingBody
where
    B: HttpBody<Data = Bytes> + Send + 'static,
    B::Error: std::fmt::Display + Send,
{
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, wasmtime_wasi_http::Error>>(8);
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
                                .send(Err(wasmtime_wasi_http::Error::InternalError(Some(
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
                        .send(Err(wasmtime_wasi_http::Error::InternalError(Some(
                            format!("request body read error: {err}"),
                        ))))
                        .await;
                    return;
                }
            }
        }
    });
    ChannelBody { rx }.boxed_unsync()
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

    #[test]
    fn engine_builds() {
        build_engine(None).expect("engine builds");
    }

    /// `PLAN-handler-tcp-egress` TE-2: the outbound-TCP allowlist-membership core. Covers the three
    /// entry shapes (IP literal / CIDR / host-resolved domain) + the REQUIRED port match + the
    /// empty-allowlist deny-all. The connect-only + SSRF-floor checks live in the `new_store` closure
    /// around this (and are exercised by the TE-3 live gate); this asserts the membership semantics.
    #[tokio::test]
    async fn tcp_egress_allowlist_membership() {
        let sa = |s: &str| s.parse::<SocketAddr>().unwrap();

        // Empty allowlist ⇒ deny-all (nothing to match).
        assert!(!tcp_egress_allowed(&[], sa("93.184.216.34:443")).await);

        // Exact IP + port.
        let ip = vec!["93.184.216.34:443".to_string()];
        assert!(tcp_egress_allowed(&ip, sa("93.184.216.34:443")).await);
        // Right IP, WRONG port ⇒ deny (the port is part of the target).
        assert!(!tcp_egress_allowed(&ip, sa("93.184.216.34:8443")).await);
        // Right port, WRONG IP ⇒ deny.
        assert!(!tcp_egress_allowed(&ip, sa("93.184.216.35:443")).await);

        // CIDR membership + port.
        let cidr = vec!["10.0.0.0/8:5432".to_string()];
        assert!(tcp_egress_allowed(&cidr, sa("10.1.2.3:5432")).await);
        assert!(!tcp_egress_allowed(&cidr, sa("11.0.0.1:5432")).await); // outside the block
        assert!(!tcp_egress_allowed(&cidr, sa("10.1.2.3:5433")).await); // wrong port

        // IPv6 literal + CIDR (last-colon split must keep the address colons).
        let v6 = vec![
            "[2001:db8::1]:993".to_string(),
            "2001:db8::/32:995".to_string(),
        ];
        assert!(tcp_egress_allowed(&v6, sa("[2001:db8::1]:993")).await);
        assert!(tcp_egress_allowed(&v6, sa("[2001:db8::dead]:995")).await); // CIDR
        assert!(!tcp_egress_allowed(&v6, sa("[2001:dead::1]:995")).await); // outside /32

        // Domain: resolve host-side and match the peer IP. `localhost` resolves to loopback, so this
        // exercises the resolve-then-compare path with no network dependency. (The SSRF floor that
        // would otherwise block loopback is applied by the closure, NOT by this membership helper.)
        let dom = vec!["localhost:993".to_string()];
        assert!(tcp_egress_allowed(&dom, sa("127.0.0.1:993")).await);
        assert!(!tcp_egress_allowed(&dom, sa("127.0.0.1:994")).await); // wrong port
        // A non-loopback IP is not what `localhost` resolves to ⇒ deny.
        assert!(!tcp_egress_allowed(&dom, sa("93.184.216.34:993")).await);

        // Malformed entries (no port) never match.
        assert!(!tcp_egress_allowed(&["93.184.216.34".to_string()], sa("93.184.216.34:443")).await);
    }

    /// Deny-by-default wiring: an engine built WITHOUT `with_tcp_egress` must leave the socket host
    /// deny-all. `new_store` is the only installer of a permissive `socket_addr_check`, and it does so
    /// only when `allow_tcp_egress && !allowlist.is_empty()`; a default engine has `allow_tcp_egress`
    /// false, so no check is ever installed regardless of the per-handler allowlist.
    #[tokio::test]
    async fn tcp_egress_defaults_denied() {
        let engine = HandlerEngine::new(Limits::default(), 4).expect("engine");
        assert!(
            !engine.allow_tcp_egress,
            "default posture denies TCP egress"
        );
        assert!(
            engine.with_tcp_egress(true).allow_tcp_egress,
            "the builder flips the posture flag"
        );
    }

    /// `PLAN-handler-tcp-egress` TE-3 (MUST-HAVE #1): direct tests of the ENFORCED decision
    /// [`tcp_connect_decision`] — the exact predicate the installed `socket_addr_check` closure calls
    /// — across all four security dimensions. (a) `bind`/`listen` + every UDP use are denied even
    /// with a matching allowlist + posture on; (b) an allowlisted PRIVATE/metadata peer is denied
    /// when `allow_private` is off and admitted when on; (c) a non-allowlisted global peer is denied
    /// and an allowlisted one admitted; (d) posture off denies everything.
    #[tokio::test]
    async fn tcp_connect_decision_enforces_all_dimensions() {
        let sa = |s: &str| s.parse::<SocketAddr>().unwrap();
        let allow = vec![
            "93.184.216.34:443".to_string(),  // allowlisted global
            "10.0.0.5:5432".to_string(),      // allowlisted private
            "169.254.169.254:80".to_string(), // allowlisted metadata
        ];
        let global = sa("93.184.216.34:443");

        // (a) Connect-only: bind/listen/accept + every UDP use denied, even allowlisted + posture on.
        for bad in [
            SocketAddrUse::TcpBind,
            SocketAddrUse::TcpListen,
            SocketAddrUse::TcpAccept,
            SocketAddrUse::UdpBind,
            SocketAddrUse::UdpSend,
            SocketAddrUse::UdpReceive,
        ] {
            assert!(
                !tcp_connect_decision(bad, global, &allow, true, true).await,
                "non-connect use {bad:?} must be denied"
            );
        }
        // …and TcpConnect to the same allowlisted global IS permitted.
        assert!(tcp_connect_decision(SocketAddrUse::TcpConnect, global, &allow, false, true).await);

        // (b) SSRF floor on an allowlisted PRIVATE + METADATA peer: denied w/o allow_private, admitted with.
        for peer in ["10.0.0.5:5432", "169.254.169.254:80"] {
            assert!(
                !tcp_connect_decision(SocketAddrUse::TcpConnect, sa(peer), &allow, false, true)
                    .await,
                "{peer} (allowlisted, non-global) must be denied without allow_private"
            );
            assert!(
                tcp_connect_decision(SocketAddrUse::TcpConnect, sa(peer), &allow, true, true).await,
                "{peer} must be admitted once allow_private is on"
            );
        }

        // (c) Allowlist: a non-allowlisted GLOBAL target is denied; an allowlisted one admitted.
        // `8.8.4.4` is a genuinely global public IP (NOT RFC-5737 documentation space), so the SSRF
        // floor passes and the ALLOWLIST is the actual decider here.
        assert!(
            !tcp_connect_decision(
                SocketAddrUse::TcpConnect,
                sa("8.8.4.4:443"),
                &allow,
                false,
                true
            )
            .await,
            "a non-allowlisted global target must be denied"
        );

        // (d) Posture gate: off ⇒ even an allowlisted global connect is denied.
        assert!(
            !tcp_connect_decision(SocketAddrUse::TcpConnect, global, &allow, true, false).await,
            "posture off must deny every connect"
        );
    }

    /// Regression (v0.44.0 wasmtime-50 bump): `TcpSocket::connect` runs a
    /// `socket_addr_check(unspecified_addr, TcpBind)` for the implicit ephemeral local bind BEFORE
    /// the `TcpConnect` check, so the gate MUST permit exactly that implicit bind — else every gated
    /// `wasi:sockets` connect is denied `access-denied` (the reported regression). It must NOT permit
    /// a bind to any specific address, or the unspecified address with a NON-zero port (inbound stays
    /// the container model — no guest bind/listen to a real inbound address).
    #[tokio::test]
    async fn tcp_connect_decision_permits_wasmtime50_implicit_connect_bind() {
        let sa = |s: &str| s.parse::<SocketAddr>().unwrap();
        let allow = vec!["127.0.0.1:9000".to_string()];
        // The implicit pre-connect local bind (both families) is permitted with posture on — even
        // with allow_private off and an allowlist that doesn't list the unspecified address.
        for implicit in ["0.0.0.0:0", "[::]:0"] {
            assert!(
                tcp_connect_decision(SocketAddrUse::TcpBind, sa(implicit), &allow, false, true)
                    .await,
                "the implicit pre-connect bind {implicit} must be permitted (the v0.44.0 regression)"
            );
        }
        // A REAL bind — a specific address, or the unspecified address with a non-zero port — stays
        // denied (only the wildcard:0 ephemeral connect-bind is the special case).
        for real in ["0.0.0.0:8080", "127.0.0.1:0", "127.0.0.1:9000", "[::]:443"] {
            assert!(
                !tcp_connect_decision(SocketAddrUse::TcpBind, sa(real), &allow, true, true).await,
                "a real bind {real} must stay denied"
            );
        }
        // Posture off ⇒ even the implicit bind is denied.
        assert!(
            !tcp_connect_decision(SocketAddrUse::TcpBind, sa("0.0.0.0:0"), &allow, true, false)
                .await,
            "posture off must deny even the implicit bind"
        );
        // End-to-end intent: the gated loopback connect (allowlisted + allow_private) now succeeds.
        assert!(
            tcp_connect_decision(
                SocketAddrUse::TcpConnect,
                sa("127.0.0.1:9000"),
                &allow,
                true,
                true
            )
            .await,
            "the gated loopback connect must be permitted"
        );
    }

    /// `PLAN-handler-tcp-egress` TE-3 (MUST-HAVE #2): the CI-hard, mutation-verified gate. Drives the
    /// ENFORCED [`tcp_connect_decision`] across the three security dimensions and prints the marker
    /// `TCP-EGRESS ALLOWLIST OK` so the merge gate can assert it RAN. MUTATION-VERIFIED: re-run under
    /// each `BOATRAMP_TCPEGRESS_MUTATION` — `admit_unallowlisted` (bypass the allowlist),
    /// `admit_bind_listen` (drop connect-only), `drop_posture` (ignore the posture gate) — EACH must
    /// make exactly one assertion flip and FAIL the gate. A pass-under-mutation = a hollow gate.
    #[tokio::test]
    async fn tcp_egress_allowlist_gate() {
        let sa = |s: &str| s.parse::<SocketAddr>().unwrap();
        let allow = vec!["93.184.216.34:443".to_string(), "10.0.0.5:5432".to_string()];
        let global = sa("93.184.216.34:443");

        // Dimension 1 — connect-only: bind + UDP denied (mutation `admit_bind_listen` flips this).
        assert!(
            !tcp_connect_decision(SocketAddrUse::TcpBind, global, &allow, true, true).await,
            "connect-only: TcpBind must be denied"
        );
        assert!(
            !tcp_connect_decision(SocketAddrUse::UdpSend, global, &allow, true, true).await,
            "connect-only: UdpSend must be denied"
        );

        // Dimension 2 — allowlist: allowlisted global admitted, non-allowlisted denied (mutation
        // `admit_unallowlisted` flips the deny).
        assert!(
            tcp_connect_decision(SocketAddrUse::TcpConnect, global, &allow, false, true).await,
            "allowlisted global must be admitted"
        );
        // `8.8.4.4` is genuinely global (not RFC-5737 documentation), so it clears the SSRF floor and
        // the ALLOWLIST is what denies it — exactly what the `admit_unallowlisted` mutation must flip.
        assert!(
            !tcp_connect_decision(
                SocketAddrUse::TcpConnect,
                sa("8.8.4.4:443"),
                &allow,
                false,
                true
            )
            .await,
            "non-allowlisted global must be denied"
        );

        // Dimension 3 — posture gate: off ⇒ deny-all (mutation `drop_posture` flips this).
        assert!(
            !tcp_connect_decision(SocketAddrUse::TcpConnect, global, &allow, true, false).await,
            "posture off must deny every connect"
        );

        // SSRF floor (bonus coverage; mutation-proven separately via is_global_ip's own gate).
        assert!(
            !tcp_connect_decision(
                SocketAddrUse::TcpConnect,
                sa("10.0.0.5:5432"),
                &allow,
                false,
                true
            )
            .await,
            "an allowlisted private target must still clear the SSRF floor"
        );

        println!("TCP-EGRESS ALLOWLIST OK");
    }

    /// The `Bindings` a conn-lane dispatch would carry: an EMPTY outbound-TCP egress allowlist ⇒
    /// `new_store` installs no socket check (the guest's only network surface is the handed `wasi:io`
    /// streams). Under the `add_socket_authority` gate mutation it injects a NON-EMPTY allowlist — the
    /// breach the structural gate must catch via the ENFORCED `conn_lane_sockets_denied` predicate
    /// (security-review MEDIUM: the gate now proves the REAL property, not a symbolic constant).
    #[cfg(feature = "tcp-listener")]
    fn gate_conn_lane_bindings() -> Bindings {
        let b = Bindings::default();
        if tcplistener_mutation().as_deref() == Some("add_socket_authority") {
            b.with_egress_allowlist(vec!["0.0.0.0/0:443".to_string()])
        } else {
            b
        }
    }

    /// PLAN-handler-tcp-inbound: direct tests of the ENFORCED inbound-listener dispatch decision
    /// [`tcp_listener_dispatch_decision`] — the exact predicate `dispatch_tcp_connection` calls — plus
    /// the REAL no-raw-sockets invariant [`conn_lane_sockets_denied`] (empty egress allowlist) and the
    /// defense-in-depth constant guard. (a) posture off denies; (b) an undeclared listener denies; (c)
    /// both on dispatches; (d) empty-allowlist bindings deny sockets while an allowlist-bearing one is
    /// correctly detected as a breach; (e) the constant guard is off.
    #[cfg(feature = "tcp-listener")]
    #[test]
    fn tcp_listener_dispatch_decision_enforces_both_gates() {
        // (a) Posture off ⇒ deny, even for a declared listener.
        assert!(
            !tcp_listener_dispatch_decision(false, true),
            "posture off must deny dispatch"
        );
        // (b) Undeclared listener ⇒ deny, even with the posture on.
        assert!(
            !tcp_listener_dispatch_decision(true, false),
            "an undeclared listener must deny dispatch"
        );
        // (c) Posture on AND declared ⇒ dispatch.
        assert!(
            tcp_listener_dispatch_decision(true, true),
            "posture on + declared must dispatch"
        );
        // (d) The REAL no-raw-sockets invariant reads the actual bindings fact: an empty egress
        // allowlist denies sockets; a bindings CARRYING an allowlist is correctly flagged as a breach
        // (proving the predicate isn't a constant — it's the precondition `new_store` checks).
        assert!(
            conn_lane_sockets_denied(&Bindings::default()),
            "empty-allowlist conn-lane bindings must deny socket authority"
        );
        assert!(
            !conn_lane_sockets_denied(
                &Bindings::default().with_egress_allowlist(vec!["93.184.216.34:443".to_string()])
            ),
            "bindings carrying an egress allowlist must be flagged (they WOULD grant connect authority)"
        );
        // (d') cap-req 19: the SAME non-empty allowlist, marked HOST-MEDIATED-egress-only, is NOT a
        // breach — it feeds only the host-mediated `tcp-egress` dial, so `new_store` installs no guest
        // socket check and the guest's raw `wasi:sockets` stays deny-all.
        assert!(
            conn_lane_sockets_denied(
                &Bindings::default()
                    .with_egress_allowlist(vec!["93.184.216.34:443".to_string()])
                    .with_host_mediated_egress()
            ),
            "a host-mediated-egress-only allowlist must NOT grant the guest raw sockets (cap-req 19)"
        );
        // (e) The defense-in-depth constant guard is off in a shipped build.
        assert!(
            !conn_lane_grants_socket_authority(),
            "the inbound-TCP conn lane must never grant the guest wasi:sockets authority"
        );
    }

    /// cap-req 19 (security-review LOW-2): the ACTUAL enforcement of the host-mediated-egress carve-out
    /// is the `installs_guest_socket_check` predicate `new_store` branches on — assert it directly, so
    /// the no-raw-sockets invariant is anti-hollow-covered at its real site, not only via the sibling
    /// `conn_lane_sockets_denied` guard.
    #[test]
    fn installs_guest_socket_check_honors_host_mediated() {
        // Request / HTTP-session / consumer lane, posture on + a non-empty allowlist ⇒ INSTALL the
        // gated guest socket check (the guest's own `wasi:sockets` is permitted, gated).
        assert!(installs_guest_socket_check(true, false, false));
        // The SAME posture + allowlist but HOST-MEDIATED (a listener guest) ⇒ do NOT install: the
        // allowlist feeds only the host-mediated `TcpEgressHost`, and the guest's raw `wasi:sockets`
        // stays deny-all. This is the real suppression behind the no-raw-sockets invariant.
        assert!(!installs_guest_socket_check(true, false, true));
        // Posture off ⇒ never install (the socket host's deny-all default stands).
        assert!(!installs_guest_socket_check(false, false, false));
        // Empty allowlist ⇒ never install (nothing to gate-permit).
        assert!(!installs_guest_socket_check(true, true, false));
    }

    /// PLAN-handler-tcp-inbound HIGH-fix: the conn-lane wall-clock watchdog (the enforcer the yield
    /// makes effective) resolves to `MaxDuration` / `Idle` on its own — tested WITHOUT a guest via a
    /// "guest that yields but never completes" (a bare pending future is never re-polled; the watchdog
    /// drives purely off its own timers). Short real-time thresholds, with the two bounds far apart so
    /// the SMALLER one deterministically wins (`idle_for ≈ started.elapsed()` from a shared clock).
    #[cfg(feature = "tcp-listener")]
    #[tokio::test]
    async fn conn_watchdog_fires_max_duration_then_idle() {
        // max (120ms) < idle (300ms) ⇒ MaxDuration fires first.
        let last = Arc::new(Mutex::new(tokio::time::Instant::now()));
        let kind = conn_watchdog(
            Arc::clone(&last),
            Duration::from_millis(300),
            Duration::from_millis(120),
            tokio::time::Instant::now(),
        )
        .await;
        assert_eq!(
            kind,
            ConnTimeout::MaxDuration,
            "max-duration must fire first"
        );

        // idle (120ms) < max (10s) ⇒ Idle fires first (no activity ever stamped).
        let last = Arc::new(Mutex::new(tokio::time::Instant::now()));
        let kind = conn_watchdog(
            Arc::clone(&last),
            Duration::from_millis(120),
            Duration::from_secs(10),
            tokio::time::Instant::now(),
        )
        .await;
        assert_eq!(kind, ConnTimeout::Idle, "idle must fire first");
    }

    /// PLAN-handler-stream-lifecycle GAP2: the streaming-lane watchdog resolves to `Idle` / `MaxDuration`
    /// on its own, without a guest — the same shape (and test shape) as the conn-lane watchdog above.
    #[tokio::test]
    async fn stream_watchdog_fires_idle_then_max_duration() {
        // idle (120ms) < max (10s), no frame ever stamped ⇒ Idle fires first.
        let last = Arc::new(Mutex::new(tokio::time::Instant::now()));
        let r = stream_watchdog(
            Arc::clone(&last),
            Duration::from_millis(120),
            Duration::from_secs(10),
        )
        .await;
        assert_eq!(r, StreamTimeout::Idle, "idle must fire when no frame flows");

        // max (120ms) < idle (10s) and the stream keeps emitting frames (stamped) ⇒ MaxDuration wins.
        let last = Arc::new(Mutex::new(tokio::time::Instant::now()));
        let stamper = {
            let last = Arc::clone(&last);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    if let Ok(mut g) = last.lock() {
                        *g = tokio::time::Instant::now();
                    }
                }
            })
        };
        let r = stream_watchdog(
            Arc::clone(&last),
            Duration::from_secs(10),
            Duration::from_millis(120),
        )
        .await;
        stamper.abort();
        assert_eq!(
            r,
            StreamTimeout::MaxDuration,
            "max-duration must fire even while the stream stays active"
        );
    }

    /// PLAN-handler-stream-lifecycle GAP1 (the HIGH): a streaming response occupies its lane slot for
    /// the body's WHOLE life — not merely until the head is produced — and releases it when the body is
    /// dropped (client disconnect / stream finished). Proven at the `guard_streaming_response` seam with
    /// a synthetic body + a 1-permit semaphore, so no wasm guest is needed. Before the fix the permit
    /// dropped when `serve_lane` returned the head, so this would read 1 while the stream was still live.
    #[tokio::test]
    async fn streaming_slot_held_for_body_life_and_released_on_drop() {
        let sem = Arc::new(Semaphore::new(1));
        let permit = sem.clone().try_acquire_owned().expect("one permit");
        assert_eq!(sem.available_permits(), 0, "owned permit taken");

        let stats = crate::instance_stats::InstanceStats::default();
        let cguard = stats.enter_component("h");

        // Stand-in for the still-streaming guest task (never completes on its own).
        let task = tokio::spawn(std::future::pending::<()>());
        let abort = task.abort_handle();

        let inner: HyperOutgoingBody = Empty::<Bytes>::new()
            .map_err(
                |never: std::convert::Infallible| -> wasmtime_wasi_http::Error { match never {} },
            )
            .boxed_unsync();
        // Long idle/max so the watchdog never fires during the test — we assert lifecycle, not teardown.
        let wrapped = guard_streaming_response(
            http::Response::new(inner),
            abort,
            permit,
            cguard,
            600_000,
            900_000,
        );

        assert_eq!(
            sem.available_permits(),
            0,
            "the streaming slot must stay held while the response body is alive (GAP1)"
        );

        drop(wrapped);
        tokio::task::yield_now().await; // let the aborted guest/watchdog tasks settle
        assert_eq!(
            sem.available_permits(),
            1,
            "dropping the response body must release the streaming slot"
        );
    }

    /// PLAN-handler-tcp-inbound: the CI-hard, mutation-verified gate. Drives the ENFORCED
    /// [`tcp_listener_dispatch_decision`] across BOTH dispatch gates AND the no-raw-sockets structural
    /// invariant [`conn_lane_grants_socket_authority`], then prints the marker `TCP-LISTENER DISPATCH
    /// OK` so the merge gate can assert it RAN. MUTATION-VERIFIED: re-run under each
    /// `BOATRAMP_TCPLISTENER_MUTATION` — `drop_posture` (dispatch when the posture is off),
    /// `admit_undeclared` (dispatch to a listener the operator never declared), `add_socket_authority`
    /// (hand the conn lane raw socket authority) — EACH must flip one assertion and FAIL the gate. A
    /// pass-under-mutation = a hollow gate.
    #[cfg(feature = "tcp-listener")]
    #[test]
    fn tcp_listener_dispatch_gate() {
        // Gate 1 — posture: off ⇒ deny-all (mutation `drop_posture` flips this).
        assert!(
            !tcp_listener_dispatch_decision(false, true),
            "posture off must deny every dispatch"
        );
        // Gate 2 — operator-declared: an undeclared listener is denied even with the posture on
        // (mutation `admit_undeclared` flips this).
        assert!(
            !tcp_listener_dispatch_decision(true, false),
            "an undeclared listener must be denied"
        );
        // Both on ⇒ dispatch (the positive path; no mutation flips this true→true, so it stays green
        // under every mutation and can't mask a RED).
        assert!(
            tcp_listener_dispatch_decision(true, true),
            "posture on + declared must dispatch"
        );
        // Structural no-raw-sockets invariant (security-review MEDIUM — now the REAL property, not a
        // symbolic constant): a conn-lane dispatch's bindings carry NO egress allowlist, the exact
        // precondition that keeps `new_store` from installing a socket check. The `add_socket_authority`
        // mutation injects a non-empty allowlist into these bindings, so the ENFORCED
        // `conn_lane_sockets_denied` predicate (the same one `dispatch_tcp_connection` fails closed on)
        // returns false ⇒ the gate goes RED.
        assert!(
            conn_lane_sockets_denied(&gate_conn_lane_bindings()),
            "conn-lane bindings must carry NO egress allowlist (empty ⇒ new_store grants no socket authority)"
        );
        // Defense-in-depth: the standalone dispatch-refusal constant guard also denies socket authority
        // (also flipped by `add_socket_authority`).
        assert!(
            !conn_lane_grants_socket_authority(),
            "the inbound-TCP conn lane must never grant the guest raw socket authority (wasi:sockets)"
        );

        println!("TCP-LISTENER DISPATCH OK");
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

    async fn egress(uri: &str, tls: bool) -> Result<(), wasmtime_wasi_http::Error> {
        egress_target_allowed(&uri.parse().unwrap(), tls, false, &[], 0)
            .await
            .map(|_| ())
    }

    async fn egress_priv(uri: &str, tls: bool) -> Result<(), wasmtime_wasi_http::Error> {
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
            Err(wasmtime_wasi_http::Error::DestinationIpProhibited)
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
            Err(wasmtime_wasi_http::Error::DestinationIpProhibited)
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
                    Err(wasmtime_wasi_http::Error::DestinationIpProhibited)
                ),
                "{blocked} should be prohibited"
            );
        }
        // A public IP literal is allowed.
        assert!(egress("http://1.1.1.1/", false).await.is_ok());
        // A request with no authority is rejected as an invalid URI.
        assert!(matches!(
            egress("/relative-only", false).await,
            Err(wasmtime_wasi_http::Error::HttpRequestUriInvalid)
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
            Err(wasmtime_wasi_http::Error::HttpRequestUriInvalid)
        ));
    }
}

/// The dev-posture guest-egress extra-CA gate: a REAL loopback TLS handshake proving
/// [`guest_egress_client_config`] trusts an operator-supplied CA **only when supplied**, and never
/// bypasses verification. This is the boatramp-side hard gate for the extra-CA feature (the
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

/// The DNS-rebinding TOCTOU pinning regression lives in its own module so the extra-CA gate above
/// (`egress_tls_tests::`, which CI pins to exactly one test by count) keeps its count unchanged.
#[cfg(test)]
mod egress_pin_tests {
    use super::*;

    /// INFO-A regression (DNS-rebinding TOCTOU): [`send_guest_request`] connects to the PINNED,
    /// pre-validated address and never re-resolves the request's host. The URI names
    /// `pinned-elsewhere.invalid` — a name RFC 6761 guarantees never resolves — yet the call reaches
    /// a loopback origin supplied only via `addrs`. The pre-fix sender (which did a SECOND
    /// `lookup_host` of the URI host at connect) would fail NXDOMAIN here; pinning makes it succeed,
    /// proving the resolve-then-reresolve window is closed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn guest_egress_pins_validated_ip_and_never_reresolves_host() {
        use bytes::Bytes;
        use http_body_util::{BodyExt, Empty};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Minimal one-shot loopback HTTP/1 origin: consume the request head, reply 204.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            if let Ok((mut tcp, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = tcp.read(&mut buf).await;
                let _ = tcp
                    .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
                    .await;
                let _ = tcp.flush().await;
            }
        });

        let body: wasmtime_wasi_http::WasiBody = Empty::<Bytes>::new()
            .map_err(|e: std::convert::Infallible| match e {})
            .boxed_unsync();
        let request = http::Request::builder()
            .method("GET")
            .uri("http://pinned-elsewhere.invalid/health")
            .body(body)
            .unwrap();

        let (resp, io) = send_guest_request(
            request,
            wasmtime_wasi_http::RequestOptions::default(),
            false,          // plaintext
            &[],            // no extra CA
            &[server_addr], // the validated, PINNED peer
        )
        .await
        .expect("pinned connect reaches the loopback origin despite a non-resolvable URI host");
        assert_eq!(
            resp.status(),
            http::StatusCode::NO_CONTENT,
            "the pinned loopback origin answered — the sender used `addrs`, not a DNS re-resolution"
        );
        let _ = std::pin::Pin::from(io).await;
        let _ = srv.await;
        println!(
            "GUEST-EGRESS PIN OK: send_guest_request connected to the validated pinned IP and never \
             re-resolved the request host — the DNS-rebinding window between the SSRF check and the \
             connect is closed (a non-resolvable `.invalid` URI host still reached the pinned origin)."
        );
    }
}
