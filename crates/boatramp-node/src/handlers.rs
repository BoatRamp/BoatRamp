//! WebAssembly handler-runtime assembly (moved from the binary — node-library N2b).
//!
//! Builds `boatramp_server::HandlerRuntime` from `[handlers]` config: the wasmtime
//! engine plus the libsql `sql` binding (single-node file per site, a cluster sqld
//! namespace, or an external Postgres/MySQL). Handlers-gated; a lean node gets a
//! disabled runtime. Lives here (not the backend-agnostic `boatramp-server`)
//! because it drives the concrete `boatramp-storage` SQL backends.

#[cfg(feature = "handlers")]
use crate::error::Error;
use crate::error::Result;
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use std::path::Path;
use std::sync::Arc;

/// Default async-lane wall-clock ceiling: 15 minutes. Large enough for a
/// genuinely long background job (an LLM generation, a batch transform) while
/// staying bounded — work that needs longer belongs in a workflow, one bounded
/// invocation per step. The lease that guards a crashed-node reclaim is sized
/// from this, so a bounded value also bounds the orphan-recovery window.
#[cfg(feature = "handlers")]
const DEFAULT_ASYNC_TIMEOUT_MS: u64 = 15 * 60 * 1000;

/// Default async-lane concurrency: a small, isolated pool. The point of the
/// separate budget is that a burst of long background jobs cannot exhaust the
/// (much larger) request pool live site traffic draws from.
#[cfg(feature = "handlers")]
const DEFAULT_ASYNC_CONCURRENCY: usize = 8;

/// Default streaming-lane wall-clock: like the async lane, a long-lived streaming
/// response (SSE, agent token streaming) can run for minutes.
#[cfg(feature = "handlers")]
const DEFAULT_STREAMING_TIMEOUT_MS: u64 = 15 * 60 * 1000;

/// Default streaming-lane concurrency: larger than the async drain because
/// concurrent connected SSE clients are the expected shape, but still an isolated
/// budget so a burst can't touch the fast request pool.
#[cfg(feature = "handlers")]
const DEFAULT_STREAMING_CONCURRENCY: usize = 64;

/// The host-parallelism default for the GLOBAL sync-lane concurrency ceiling, given the detected
/// core count: `cores * 4`, floored at the historical **64**. The `* 4` matches the per-component
/// `serve_concurrency` gate (so a single hot component can use its whole per-component budget without
/// the global lane binding first), and the 64 floor makes this purely additive — identical to the old
/// fixed `Limits::default().max_concurrency = 64` on any node up to ~16 vCPU, and only scaling ABOVE
/// that, where the fixed 64 used to cap aggregate live throughput with no knob to lift it. Factored out
/// of [`available_parallelism`] so the formula is unit-testable without a specific host.
#[cfg(feature = "handlers")]
fn sync_concurrency_for_cores(cores: usize) -> usize {
    cores.saturating_mul(4).max(64)
}

/// The effective default sync-lane concurrency for THIS host (detected cores → [`sync_concurrency_for_cores`]).
#[cfg(feature = "handlers")]
fn default_sync_concurrency() -> usize {
    let cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    sync_concurrency_for_cores(cores)
}

/// Resolve the effective global sync-lane ceiling from the operator's `sync_max_concurrency`.
///
/// `None` ⇒ the host-scaled default. A positive value is honored verbatim (an operator may
/// deliberately run a tight lane). `Some(0)` is treated as **invalid**, NOT as "disable": unlike the
/// per-component `serve_concurrency` gate (where `0` means pass-through), the global sync lane is a
/// required node-wide safety ceiling — remove it and a burst oversubscribes the workers again (the
/// bug this release fixes). The engine's own `.max(1)` floor means a `0` would otherwise *silently*
/// collapse the whole node to one concurrent live serve; instead we fall back to the host default (the
/// caller logs a loud WARN), so the boot log and the enforced value never diverge. Pure (the WARN is a
/// side effect at the call site) so the `0`-is-not-disable contract is unit-tested.
#[cfg(feature = "handlers")]
fn resolve_sync_concurrency(configured: Option<usize>) -> usize {
    match configured {
        // 0 is invalid (not "disable") → host default; the caller WARNs.
        None | Some(0) => default_sync_concurrency(),
        Some(n) => n,
    }
}

#[cfg(all(test, feature = "handlers"))]
mod sync_concurrency_default_tests {
    use super::sync_concurrency_for_cores;

    /// The core-scaled sync-lane default must be PURELY ADDITIVE: byte-identical to the historical
    /// fixed `max_concurrency = 64` on any node up to the ~16-vCPU crossover (`cores * 4 == 64`), and
    /// only scaling ABOVE that — so the fix lifts the big-node ceiling without tightening any node that
    /// worked before. Also must never underflow on a degenerate core count.
    #[test]
    fn sync_lane_default_is_additive_then_scales_with_cores() {
        for cores in [0usize, 1, 2, 4, 8, 16] {
            assert_eq!(
                sync_concurrency_for_cores(cores),
                64,
                "≤16 vCPU must stay at the historical 64 (cores={cores})"
            );
        }
        assert_eq!(
            sync_concurrency_for_cores(17),
            68,
            "just past the crossover scales"
        );
        assert_eq!(sync_concurrency_for_cores(32), 128);
        assert_eq!(sync_concurrency_for_cores(64), 256);
    }

    /// `0` must NOT behave like `serve_concurrency = 0` (disable). For the global sync lane it is
    /// invalid and resolves to the host default — never a silent collapse to 1 (the engine's `.max(1)`
    /// floor). A positive value passes through verbatim; `None` is the default.
    #[test]
    fn sync_max_concurrency_zero_is_not_disable() {
        use super::{default_sync_concurrency, resolve_sync_concurrency};
        let default = default_sync_concurrency();
        assert!(default >= 64, "host default is floored at 64");
        assert_eq!(
            resolve_sync_concurrency(Some(0)),
            default,
            "0 is invalid → host default, NOT 1 and NOT disable"
        );
        assert_eq!(
            resolve_sync_concurrency(None),
            default,
            "unset → host default"
        );
        assert_eq!(
            resolve_sync_concurrency(Some(1)),
            1,
            "a positive value is honored verbatim"
        );
        assert_eq!(resolve_sync_concurrency(Some(200)), 200);
    }
}

/// Build the WebAssembly handler runtime. With the `handlers` feature it wraps a
/// wasmtime engine serving the kv/blob bindings from the server's own backends;
/// otherwise it is an empty placeholder (handler routes fall through to static).
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
pub async fn build_handler_runtime(
    kv: Arc<dyn KvStore>,
    storage: Arc<dyn boatramp_core::Storage>,
    data_dir: &Path,
    handlers_cfg: Option<&crate::config::HandlersConfig>,
    messaging_override: Option<Arc<dyn boatramp_core::messaging::Messaging>>,
    max_blob_bytes: u64,
    max_component_bytes: u64,
    // Posture: whether a guest's outbound `wasi:http` may reach private/loopback hosts.
    allow_guest_private_egress: bool,
    // Posture: the instance's own serve socket(s) a guest self-call may reach (empty ⇒ off).
    self_egress_addrs: Vec<std::net::SocketAddr>,
    // Dev-posture guest-egress extra CA(s), DER-encoded (empty ⇒ stock webpki-only egress trust).
    // Parsed + posture-gated by the caller (`node.rs`), so an empty vec here means either the
    // posture forbids it (multi-tenant) or no CA file was configured.
    guest_egress_extra_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    // Posture: whether a site handler's / function's `secrets` map may resolve a bare /
    // `env:` reference against the serve process's own environment (on under single-tenant/
    // dev, off under multi-tenant — an untrusted tenant must not name arbitrary host env vars).
    allow_env_secret_refs: bool,
    // Posture: whether a guest's `email` capability may send (bind the SMTP gateway).
    // Off under multi-tenant; when off, email is simply not offered (a granted guest
    // gets `access-denied`). Only consulted with the `email` feature compiled in.
    allow_guest_email: bool,
    // Posture: whether a sql/orm importer must declare an explicit in-site tenancy decision
    // (on under multi-tenant — Dimension 0) and whether an `all` tenancy grant may cross tenants
    // (off under multi-tenant — the cross-tenant ceiling).
    require_tenancy_declaration: bool,
    allow_cross_tenant_db: bool,
    // The deploy store (for a managed compute-backed `sql` database's endpoint
    // resolution) and the `[secrets]` envelope (to seal a managed credential).
    deploy: &DeployStore,
    secrets_envelope: Option<Arc<dyn KeyEnvelope>>,
) -> Result<boatramp_server::HandlerRuntime> {
    // `allow_guest_email` is only consulted when the `email` feature wires the
    // gateway below; keep it from tripping unused-variable in a no-email build.
    #[cfg(not(feature = "email"))]
    let _ = allow_guest_email;
    // Front the shared blob backend with a process-wide, positive-only container-marker cache so the
    // serve path skips the per-request `.boatramp-container` HEAD round-trip for an already-verified
    // container. Confinement is UNTOUCHED — the binding's `container_access` still runs on every op and
    // the cache only ever sees fully-resolved, tenant-confined keys; it caches a marker only on a
    // confirmed `Ok` and invalidates on a marker delete (fail-closed). `0` disables it (pass-through).
    // Wrapped here (INSIDE the per-request `TimingStorage` the dispatch path adds), so a marker-cache hit
    // shows `blob_head_us≈0` in the v0.23.0 phase timing.
    const DEFAULT_BLOB_MARKER_CACHE: usize = 4096;
    let marker_cache_entries = handlers_cfg
        .and_then(|h| h.blob_marker_cache_entries)
        .unwrap_or(DEFAULT_BLOB_MARKER_CACHE);
    let storage: Arc<dyn boatramp_core::Storage> = Arc::new(
        boatramp_storage::MarkerHeadCache::new(storage, marker_cache_entries),
    );
    // Two engine ceilings by lane. The **sync** ceiling bounds connection-bearing
    // requests (site handlers, synchronous invokes) — kept tight so a slow
    // handler can't pin a client, a proxy, and the shared request pool; default
    // 10s. The **async** ceiling bounds the durable drain / workflow / trigger /
    // messaging path — no client is connected and the work is retried +
    // dead-lettered, so it can run far longer (default 15 min) on its own
    // concurrency budget, which is how a legitimately long background job (e.g.
    // an LLM generation) can declare and actually get minutes of runtime without
    // ever starving live site traffic.
    let defaults = boatramp_handlers::Limits::default();
    // MiB → bytes; a lane's memory ceiling defaults to the 64 MiB `Limits::default`
    // and is RAISED (never lowered below it) by the operator's `*_max_memory_mb` knob.
    // The existing `effective_limits` min()-clamp then lets a component's own
    // `memory_mb` clamp it back DOWN from the raised lane ceiling.
    let mib = |mb: usize| mb.saturating_mul(1024 * 1024);
    let sync_limits = boatramp_handlers::Limits {
        timeout_ms: handlers_cfg
            .and_then(|h| h.sync_max_timeout_ms)
            .unwrap_or(defaults.timeout_ms),
        memory_bytes: handlers_cfg
            .and_then(|h| h.sync_max_memory_mb)
            .map(mib)
            .unwrap_or(defaults.memory_bytes),
        // The GLOBAL sync-lane ceiling. Scales with host size by default (`cores * 4`, floored at the
        // historical 64) so adding vCPUs past ~16 actually raises aggregate live throughput instead of
        // pinning at a fixed 64 — the ceiling the per-component `serve_concurrency` gate hands off to.
        // A configured `0` is invalid (the lane is a required safety ceiling, NOT disable-able like the
        // per-component gate) → fall back to the host default with a loud WARN, never a silent collapse
        // to 1 concurrent live serve.
        max_concurrency: {
            let configured = handlers_cfg.and_then(|h| h.sync_max_concurrency);
            if configured == Some(0) {
                tracing::warn!(
                    default = default_sync_concurrency(),
                    "[handlers] sync_max_concurrency = 0 is invalid: the global sync lane is a \
                     required node-wide safety ceiling and cannot be disabled (unlike \
                     serve_concurrency, where 0 means pass-through). Using the host-scaled default \
                     instead — set a positive value to override."
                );
            }
            resolve_sync_concurrency(configured)
        },
        ..defaults
    };
    let async_limits = boatramp_handlers::Limits {
        timeout_ms: handlers_cfg
            .and_then(|h| h.async_max_timeout_ms)
            .unwrap_or(DEFAULT_ASYNC_TIMEOUT_MS),
        max_concurrency: handlers_cfg
            .and_then(|h| h.async_max_concurrency)
            .unwrap_or(DEFAULT_ASYNC_CONCURRENCY),
        fuel: handlers_cfg.and_then(|h| h.async_max_fuel),
        // Explicit (not inherited from `sync_limits`): the async memory ceiling is its
        // own knob, so a raised sync ceiling never silently raises async and vice versa.
        memory_bytes: handlers_cfg
            .and_then(|h| h.async_max_memory_mb)
            .map(mib)
            .unwrap_or(defaults.memory_bytes),
        ..sync_limits
    };
    // The **streaming** ceiling bounds a `#[handler(stream)]` response (SSE, chunked, agent
    // token streaming): connection-bearing but long-lived, so — like the async lane — a large
    // wall-clock on its own concurrency budget, kept apart from both the fast request pool and
    // the durable drain.
    let streaming_limits = boatramp_handlers::Limits {
        timeout_ms: handlers_cfg
            .and_then(|h| h.streaming_max_timeout_ms)
            .unwrap_or(DEFAULT_STREAMING_TIMEOUT_MS),
        max_concurrency: handlers_cfg
            .and_then(|h| h.streaming_max_concurrency)
            .unwrap_or(DEFAULT_STREAMING_CONCURRENCY),
        fuel: handlers_cfg.and_then(|h| h.streaming_max_fuel),
        memory_bytes: handlers_cfg
            .and_then(|h| h.streaming_max_memory_mb)
            .map(mib)
            .unwrap_or(defaults.memory_bytes),
        ..sync_limits
    };
    let outbound_timeout = handlers_cfg
        .and_then(|h| h.outbound_timeout_ms)
        .map(std::time::Duration::from_millis);
    // Opt-in pooling allocator: faster instantiation, large up-front virtual
    // reservation — benchmark before enabling. With a raised lane memory ceiling the
    // single shared pool must be sized off the LARGEST lane (so an instance on any
    // lane fits its slot); `with_pooling_lanes` does that + logs/fails loud on an
    // implausible reservation. The non-pooling path sizes memory per-invocation
    // (`StoreLimits`), so a raised ceiling there needs no reservation.
    // Per-lane warm compile-cache capacity (operator-configurable; default 64). A node serving more
    // than this many distinct components evicts the LRU-coldest, which recompiles on its next request;
    // `/api/instance-stats` reports `warm_capacity`/`evictions` so the value is measured, not guessed.
    // Clamped to `[1, 16384]`: the `lru` cache preallocates to capacity, so a fat-fingered giant value
    // would OOM at boot — 16384 is far beyond any realistic component count, so the clamp only catches
    // a typo (logged so the operator sees it), never a legitimate setting.
    const MAX_INSTANCE_CACHE: usize = 16_384;
    let requested_cache = handlers_cfg
        .and_then(|h| h.instance_cache_size)
        .unwrap_or(64);
    let instance_cache_size = requested_cache.clamp(1, MAX_INSTANCE_CACHE);
    if instance_cache_size != requested_cache {
        tracing::warn!(
            requested = requested_cache,
            applied = instance_cache_size,
            "[handlers] instance_cache_size clamped to [1, 16384]"
        );
    }
    // Pin the wasmtime compile cache to the persistent data volume so a component's compiled artifact
    // survives a restart/roll (the first request after a deploy then deserializes in ms instead of
    // paying a multi-second cranelift compile, which on a small node a concurrent burst stampedes
    // behind). Without this, wasmtime defaults to `~/.cache/wasmtime` on the ephemeral container
    // rootfs — wiped every restart. Best-effort inside the engine (an unwritable dir degrades to no
    // cache, never a boot failure).
    let compile_cache_dir = Some(data_dir);
    let engine = if handlers_cfg.is_some_and(|h| h.pooling) {
        boatramp_handlers::HandlerEngine::with_pooling_lanes(
            sync_limits,
            async_limits,
            streaming_limits,
            instance_cache_size,
            compile_cache_dir,
        )?
    } else {
        boatramp_handlers::HandlerEngine::new_with_cache_dir(
            sync_limits,
            instance_cache_size,
            compile_cache_dir,
        )?
        .with_async_limits(async_limits)
        .with_streaming_limits(streaming_limits)
    }
    .with_outbound_timeout(outbound_timeout)
    .with_private_egress(allow_guest_private_egress)
    .with_self_egress(self_egress_addrs)
    .with_guest_egress_extra_roots(guest_egress_extra_roots);
    let sql = build_sql_backends(
        handlers_cfg.and_then(|h| h.bindings.sql.as_ref()),
        data_dir,
        deploy,
        &kv,
        secrets_envelope.as_ref(),
        &boatramp_core::env::SystemEnv,
    )
    .await?;
    // The `wasi:messaging` substrate: single-node `LogMessaging` over the same
    // blob/KV backends by default, or the cluster coordinator when one is given.
    // Relaxed messaging-publish durability (operator opt-in; 0/absent ⇒ strong, the default). A
    // node that opts in acks publishes on the in-memory buffer with a durable checkpoint every N
    // messages — bounding the crash-loss window to N acked-but-unflushed messages. Loud WARN so the
    // weakened guarantee is never a silent surprise; control-plane durability is unaffected.
    let max_unflushed = handlers_cfg
        .and_then(|h| h.messaging_max_unflushed_msgs)
        .unwrap_or(0);
    if max_unflushed > 0 {
        tracing::warn!(
            max_unflushed,
            "messaging: RELAXED publish durability ENABLED (messaging_max_unflushed_msgs={max_unflushed}) \
             — publish() acks before the WAL flush; up to {max_unflushed} acknowledged-but-unflushed \
             messages are lost on a process crash / OOM / SIGKILL / power loss. Control-plane \
             durability is UNAFFECTED. Set 0 (the default) for stronger-than-JetStream durability."
        );
    }
    let messaging: Arc<dyn boatramp_core::messaging::Messaging> = messaging_override
        .unwrap_or_else(|| {
            Arc::new(
                boatramp_core::messaging::LogMessaging::new(storage.clone(), kv.clone())
                    .with_max_unflushed(max_unflushed),
            )
        });
    // Keep a KV handle for the internal secret store before `kv` is moved into the
    // runtime below.
    let kv_for_secrets = kv.clone();
    // Handles for the `email` gateway, captured before `kv` / `messaging` are moved
    // into the runtime. The durable spool reuses the messaging fabric; the store +
    // envelope back host-side credential resolution.
    #[cfg(feature = "email")]
    let kv_for_email = kv.clone();
    #[cfg(feature = "email")]
    let messaging_for_email = messaging.clone();
    #[cfg(feature = "email")]
    let email_envelope = secrets_envelope.clone();
    let runtime =
        boatramp_server::HandlerRuntime::new(engine, kv, storage, Some(sql), Some(messaging));
    // Apply the posture's host-side blob cap + component-size cap.
    runtime.set_max_blob_bytes(max_blob_bytes);
    runtime.set_max_component_bytes(max_component_bytes);
    // Per-component serve-admission cap (image-serve-latency Ask B). Only override the host-parallelism
    // default when the operator set `[handlers] serve_concurrency` explicitly (incl. `0` to disable).
    if let Some(cap) = handlers_cfg.and_then(|h| h.serve_concurrency) {
        runtime.set_serve_concurrency(cap);
    }
    // Log the EFFECTIVE cap at startup (default-on): an operator can then correlate a post-upgrade
    // latency change to the gate, and see what to raise / set to 0 to disable.
    match runtime.serve_concurrency() {
        0 => tracing::info!("serve-admission gate DISABLED ([handlers] serve_concurrency = 0)"),
        cap => tracing::info!(
            serve_concurrency = cap,
            "serve-admission gate active: ≤ {cap} concurrent serves per component"
        ),
    }
    // The GLOBAL sync-lane ceiling the gate hands off to — host-scaled by default (so a big node is not
    // silently pinned at the old fixed 64). Logged alongside the per-component gate so the two
    // concurrency ceilings are both visible at boot.
    tracing::info!(
        sync_concurrency = sync_limits.max_concurrency,
        "sync lane: ≤ {} concurrent live serves node-wide",
        sync_limits.max_concurrency
    );
    // Server-Timing RESPONSE HEADER — default OFF (the per-phase breakdown always goes to the log;
    // the header exposes it + a timing side-channel to clients, so it is opt-in).
    if let Some(enabled) = handlers_cfg.and_then(|h| h.server_timing) {
        runtime.set_server_timing(enabled);
    }
    if runtime.server_timing_enabled() {
        tracing::info!(
            "Server-Timing response header ENABLED ([handlers] server_timing = true) — the per-phase \
             breakdown is exposed to clients; disable it in production"
        );
    }
    // Event-driven delivery cadences (B17): the two operator `[handlers]` knobs (absent ⇒ default).
    // Pure latency/idle-cost tradeoff — never affects at-least-once.
    {
        let defaults = boatramp_server::DeliveryConfig::default();
        let safetynet = handlers_cfg
            .and_then(|h| h.messaging_safetynet_interval_ms)
            .map(std::time::Duration::from_millis)
            .unwrap_or(defaults.safetynet_interval);
        let rebuild = handlers_cfg
            .and_then(|h| h.messaging_readyset_rebuild_interval_ms)
            .map(std::time::Duration::from_millis)
            .unwrap_or(defaults.rebuild_interval);
        runtime.set_delivery_config(boatramp_server::DeliveryConfig {
            safetynet_interval: safetynet,
            rebuild_interval: rebuild,
        });
    }
    // JWKS freshness for the token-verification cache (the federated-gateway overhead fix): two tiers —
    // `own` (operator-fixed `jwks_url`/`jwks_env`) and `foreign` (user-declared multi-issuer discovery,
    // tighter by default). Each tier's `refresh` is the background-refresh age (no request blocks) and
    // `hard_ttl` is the revocation bound (past it a request blocks on a fresh fetch, fail-closed). Floor
    // each at 60 s and keep `refresh < hard_ttl` (clamp hard_ttl up with a loud warn otherwise).
    {
        // A 24 h sanity ceiling on the hard TTL (the revocation bound): a longer window is almost
        // certainly a misconfiguration (e.g. a fat-fingered value) and would defeat revocation for the
        // less-trusted FOREIGN tier. Not a policy — just a backstop; the normal 60 s–hours range is
        // untouched. `refresh` is held below half the ceiling so `hard > refresh` always has headroom.
        const JWKS_HARD_TTL_CEILING: u64 = 86_400;
        let jwks_tier = |refresh_secs: u64,
                         hard_secs: u64,
                         tier: &str|
         -> boatramp_server::JwksTier {
            let refresh = refresh_secs.clamp(60, JWKS_HARD_TTL_CEILING / 2);
            let mut hard = hard_secs.clamp(60, JWKS_HARD_TTL_CEILING);
            if hard_secs > JWKS_HARD_TTL_CEILING {
                tracing::warn!(
                    tier,
                    requested_hard_ttl_secs = hard_secs,
                    applied_hard_ttl_secs = hard,
                    "[handlers] jwks hard_ttl exceeds the 24 h sanity ceiling — clamped down (a \
                         longer revocation window is almost certainly a misconfiguration)"
                );
            }
            if hard <= refresh {
                let adjusted = refresh.saturating_mul(2).min(JWKS_HARD_TTL_CEILING);
                tracing::warn!(
                    tier,
                    refresh_secs = refresh,
                    requested_hard_ttl_secs = hard,
                    applied_hard_ttl_secs = adjusted,
                    "[handlers] jwks hard_ttl must exceed refresh — clamped up"
                );
                hard = adjusted;
            }
            boatramp_server::JwksTier {
                refresh: std::time::Duration::from_secs(refresh),
                hard_ttl: std::time::Duration::from_secs(hard),
            }
        };
        let own = jwks_tier(
            handlers_cfg
                .and_then(|h| h.jwks_refresh_secs)
                .unwrap_or(120),
            handlers_cfg
                .and_then(|h| h.jwks_hard_ttl_secs)
                .unwrap_or(600),
            "own",
        );
        let foreign = jwks_tier(
            handlers_cfg
                .and_then(|h| h.jwks_foreign_refresh_secs)
                .unwrap_or(60),
            handlers_cfg
                .and_then(|h| h.jwks_foreign_hard_ttl_secs)
                .unwrap_or(300),
            "foreign",
        );
        let prewarm = handlers_cfg.and_then(|h| h.jwks_prewarm).unwrap_or(true);
        boatramp_server::set_jwks_config(boatramp_server::JwksConfig {
            own,
            foreign,
            prewarm,
        });
        // Pre-warm of the first-party (`own`-tier) JWKS is wired at the node.rs startup call site
        // (`collect_own_jwks_prewarm` → `boatramp_server::prewarm_own_jwks`), where the `deploy` store
        // is in scope to enumerate configured sites. `prewarm_own_jwks` honors the `prewarm` flag set
        // just above.
    }
    // Apply the posture's host-env secret-ref gate (fail-closed if never set).
    runtime.set_allow_env_secret_refs(allow_env_secret_refs);
    // Apply the posture's in-site tenancy knobs (Stage 0; fail-closed if never set).
    runtime.set_tenancy_posture(require_tenancy_declaration, allow_cross_tenant_db);
    // Wire the project-scoped internal secret store when a `[secrets]` envelope is
    // configured, so `boatramp:<name>` refs resolve (sealed at rest). Without an
    // envelope there is no sealed store and such refs stay fail-closed.
    if let Some(envelope) = secrets_envelope {
        runtime.set_secret_store(Arc::new(boatramp_core::secret_store::SecretStore::new(
            kv_for_secrets,
            envelope,
        )));
    }
    // Wire the per-project SMTP email gateway when the `allow_guest_email` posture
    // permits it and a `[secrets]` envelope seals the profiles' passwords. The store
    // backs host-side profile resolution; the spool delivers (best-effort in-memory,
    // plus a durable path over the messaging fabric) via lettre, applying the SSRF
    // relay gate under the same private-egress posture. Left unwired (no store/spool)
    // when the posture is off or no envelope exists, so a granted guest's `send`
    // returns `access-denied` rather than reaching an unconfigured relay.
    #[cfg(feature = "email")]
    if allow_guest_email && let Some(envelope) = email_envelope {
        let store = Arc::new(boatramp_core::email_config::EmailProfileStore::new(
            kv_for_email,
            envelope,
        ));
        let backend = Arc::new(boatramp_handlers::LettreBackend::new(
            allow_guest_private_egress,
        ));
        let spool = boatramp_server::NodeEmailSpool::spawn(
            backend,
            Some(messaging_for_email),
            store.clone(),
        );
        runtime.set_email_profile_store(store);
        runtime.set_email_spool(spool);
    }
    Ok(runtime)
}

/// Resolve the `[handlers.bindings.sql]` config to the libsql SQL backend.
/// Single-node by default (an embedded file per site under `<data-dir>`); set
/// `url` to bind a shared sqld cluster (a namespace per site). Either way sites
/// get a real database boundary — see `boatramp_core::sql`.
#[cfg(feature = "handlers")]
async fn build_sql_backends(
    cfg: Option<&crate::config::SqlBindingConfig>,
    data_dir: &Path,
    deploy: &DeployStore,
    kv: &Arc<dyn KvStore>,
    secrets_envelope: Option<&Arc<dyn KeyEnvelope>>,
    env_source: &dyn boatramp_core::env::EnvSource,
) -> Result<Arc<dyn boatramp_core::sql::SqlBackends>> {
    let resolve_env = |var: &Option<String>| -> Result<Option<String>> {
        match var {
            Some(var) => Ok(Some(
                env_source
                    .get(var)
                    .ok_or_else(|| Error::SqlEnvUnset(var.clone()))?,
            )),
            None => Ok(None),
        }
    };

    let backend = match cfg.and_then(|c| c.url.as_ref()) {
        // Cluster: a sqld namespace per site. Auth tokens come from the
        // environment, never the config file.
        Some(url) => {
            let cfg = cfg.expect("url implies cfg");
            let admin_url = cfg.admin_url.as_ref().ok_or(Error::SqlAdminUrlRequired)?;
            let token = resolve_env(&cfg.token_env)?.unwrap_or_default();
            let admin_token = resolve_env(&cfg.admin_token_env)?;
            let backends = boatramp_storage::LibsqlSqlBackends::remote(
                url.clone(),
                admin_url.clone(),
                token,
                admin_token,
            );
            // Optional read-replica routing: reads → replica, writes → primary.
            match &cfg.replica_url {
                Some(replica_url) => backends.with_read_replica(replica_url.clone()),
                None => backends,
            }
        }
        // Single-node: an embedded file per site.
        None => {
            let dir = cfg
                .and_then(|c| c.dir.clone())
                .unwrap_or_else(|| data_dir.join("handlers-sql"));
            boatramp_storage::LibsqlSqlBackends::local(dir)
        }
    };
    // Preview SQL policy (how preview deployments relate to live data).
    let preview_mode = match cfg.and_then(|c| c.preview_mode.as_deref()) {
        None | Some("empty") => boatramp_core::sql::PreviewSqlMode::Empty,
        Some("branch") => boatramp_core::sql::PreviewSqlMode::Branch,
        Some("shared") => boatramp_core::sql::PreviewSqlMode::Shared,
        Some(other) => return Err(Error::UnknownPreviewMode(other.to_string())),
    };
    let preview_init = match cfg.and_then(|c| c.preview_init.as_ref()) {
        Some(path) => {
            Some(
                std::fs::read_to_string(path).map_err(|err| Error::PreviewInitRead {
                    path: path.clone(),
                    source: err,
                })?,
            )
        }
        None => None,
    };
    let default: Arc<dyn boatramp_core::sql::SqlBackends> =
        Arc::new(backend.with_preview_policy(preview_mode, preview_init));

    // Overlay any external (bring-your-own) databases on the managed default.
    // With none configured the default is returned unchanged (and a build
    // without an external SQL engine never has to link the sqlx path).
    let databases = cfg.map(|c| &c.databases);
    if databases.is_none_or(std::collections::BTreeMap::is_empty) {
        return Ok(default);
    }
    let databases = databases.expect("checked non-empty above");

    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    {
        use boatramp_core::sql::SqlBackend;
        use boatramp_storage::sql_sqlx::{
            CompositeSqlBackends, ExternalSqlKind, ExternalSqlOptions, connect,
        };
        let timeout = |db: &crate::config::ExternalDatabaseConfig| {
            db.connect_timeout_secs.map(std::time::Duration::from_secs)
        };
        let mut composite = CompositeSqlBackends::new(default);
        for (name, db) in databases {
            let kind = ExternalSqlKind::parse(&db.kind).ok_or_else(|| Error::SqlExternalKind {
                name: name.clone(),
                kind: db.kind.clone(),
            })?;
            if db.compute.as_deref().is_some_and(|c| !c.is_empty()) {
                // Compute-backed: EVERY such binding is per-tenant (Single or Shared
                // isolation, Project or Site scope). It resolves, per request
                // `(project, site)`, to the caller's OWN tenant database as its OWN
                // role — the isolation perimeter — through the per-tenant seam.
                //
                // A brought password (`password_env`) is not per-tenant-managed and
                // keeps its historical single-shared-endpoint shape.
                if let Some(var) = db.password_env.as_deref().filter(|v| !v.is_empty()) {
                    let workload = db.compute.as_deref().expect("compute checked above");
                    let password = env_source
                        .get(var)
                        .ok_or_else(|| Error::SqlEnvUnset(var.into()))?;
                    let resolver = Arc::new(crate::managed_sql::DeployEndpointResolver::new(
                        deploy.clone(),
                        boatramp_core::project::DEFAULT_PROJECT,
                    ));
                    let external: Arc<dyn SqlBackend> = Arc::new(
                        boatramp_storage::sql_compute::ComputeResolvedSqlBackend::new(
                            resolver,
                            workload,
                            kind,
                            db.database.clone().unwrap_or_default(),
                            db.user.clone().unwrap_or_default(),
                            password,
                            db.pool_max,
                            db.read_only,
                            timeout(db),
                        ),
                    );
                    composite = composite.with_external(name.clone(), external, db.allow_preview);
                    continue;
                }
                // Managed credential: fail closed without a secrets envelope (we will
                // not persist a DB password in cleartext).
                let envelope = secrets_envelope
                    .cloned()
                    .ok_or_else(|| Error::SqlManagedNeedsSecrets(name.clone()))?;
                let resolver = crate::tenant_sql::NodeTenantSqlResolver::new(
                    deploy.clone(),
                    kv.clone(),
                    envelope,
                    db,
                )
                .expect("a compute-backed managed binding builds a per-tenant resolver");
                let site_scoped = resolver.site_scoped();
                composite = composite.with_per_tenant(
                    name.clone(),
                    Arc::new(resolver),
                    site_scoped,
                    db.allow_preview,
                );
            } else {
                // Bring-your-own URL: a single shared endpoint, the connection URL(s)
                // are secrets, resolved from the environment.
                if db.url_env.trim().is_empty() {
                    return Err(Error::SqlExternalUrlEnvMissing(name.clone()));
                }
                let url = env_source
                    .get(&db.url_env)
                    .ok_or_else(|| Error::SqlEnvUnset(db.url_env.clone()))?;
                let read_url = match &db.read_url_env {
                    Some(var) => Some(
                        env_source
                            .get(var)
                            .ok_or_else(|| Error::SqlEnvUnset(var.clone()))?,
                    ),
                    None => None,
                };
                let opts = ExternalSqlOptions::new(url)
                    .with_read_url(read_url)
                    .with_max_connections(db.pool_max)
                    .read_only(db.read_only)
                    .with_connect_timeout(timeout(db));
                let external: Arc<dyn SqlBackend> =
                    connect(kind, &opts).map_err(|source| Error::SqlExternalConnect {
                        name: name.clone(),
                        source,
                    })?;
                composite = composite.with_external(name.clone(), external, db.allow_preview);
            }
        }
        Ok(Arc::new(composite))
    }
    #[cfg(not(any(feature = "sql-postgres", feature = "sql-mysql")))]
    {
        // The compute-backed arm (the only consumer of these) is compiled out
        // without a SQL engine; a `databases` entry then can't be served at all.
        let _ = (deploy, kv, secrets_envelope);
        let name = databases.keys().next().cloned().unwrap_or_default();
        Err(Error::SqlExternalUnavailable(name))
    }
}

#[cfg(not(feature = "handlers"))]
#[allow(clippy::too_many_arguments)]
pub async fn build_handler_runtime(
    _kv: Arc<dyn KvStore>,
    _storage: Arc<dyn boatramp_core::Storage>,
    _data_dir: &Path,
    _handlers_cfg: Option<&crate::config::HandlersConfig>,
    _messaging_override: Option<Arc<dyn boatramp_core::messaging::Messaging>>,
    _max_blob_bytes: u64,
    _max_component_bytes: u64,
    _allow_guest_private_egress: bool,
    _self_egress_addrs: Vec<std::net::SocketAddr>,
    // Kept in lockstep with the `#[cfg(feature = "handlers")]` signature + the single
    // node.rs caller (the caller passes the posture value unconditionally); a lean
    // node has no guest to gate, so it is ignored.
    _guest_egress_extra_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    _allow_env_secret_refs: bool,
    _allow_guest_email: bool,
    _require_tenancy_declaration: bool,
    _allow_cross_tenant_db: bool,
    _deploy: &DeployStore,
    _secrets_envelope: Option<Arc<dyn KeyEnvelope>>,
) -> Result<boatramp_server::HandlerRuntime> {
    Ok(boatramp_server::HandlerRuntime::disabled())
}

#[cfg(all(test, any(feature = "sql-postgres", feature = "sql-mysql")))]
mod tests {
    use super::*;
    // `super::*` brings the crate's 1-arg `Result` alias into scope; the trait impls
    // below need the std 2-arg `Result`, so shadow it back (explicit beats glob).
    use std::result::Result;

    use async_trait::async_trait;
    use boatramp_core::envelope::EnvelopeError;
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};

    /// A reversible test envelope (NOT encryption) — proves sealing round-trips.
    struct TestEnvelope;
    #[async_trait]
    impl KeyEnvelope for TestEnvelope {
        async fn wrap(&self, p: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(p.iter().rev().copied().collect())
        }
        async fn unwrap(&self, w: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(w.iter().rev().copied().collect())
        }
    }

    /// A no-op object store, so a `DeployStore` can be built (the endpoint resolver
    /// only reads KV replica state, which is empty here — the backend is lazy).
    struct NullStorage;
    #[async_trait]
    impl Storage for NullStorage {
        async fn get(&self, _: &str) -> Result<GetObject, StorageError> {
            Err(StorageError::NotFound(String::new()))
        }
        async fn get_range(
            &self,
            _: &str,
            _: u64,
            _: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            Err(StorageError::NotFound(String::new()))
        }
        async fn put(
            &self,
            _: &str,
            _: ByteStream,
            _: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            Err(StorageError::unsupported("null"))
        }
        async fn head(&self, _: &str) -> Result<ObjectMeta, StorageError> {
            Err(StorageError::NotFound(String::new()))
        }
        async fn delete(&self, _: &str) -> Result<(), StorageError> {
            Ok(())
        }
        async fn list(&self, _: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(Vec::new())
        }
    }

    /// A `sql` binding with one managed (compute-backed, no `password_env`) database.
    fn managed_sql_cfg() -> crate::config::SqlBindingConfig {
        let mut databases = std::collections::BTreeMap::new();
        databases.insert(
            "analytics".to_string(),
            crate::config::ExternalDatabaseConfig {
                kind: "postgres".into(),
                compute: Some("pg".into()),
                database: Some("analytics".into()),
                user: Some("app".into()),
                ..Default::default()
            },
        );
        crate::config::SqlBindingConfig {
            databases,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn managed_sql_fails_closed_without_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()));
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let cfg = managed_sql_cfg();
        // `Arc<dyn SqlBackends>` isn't `Debug`, so match rather than `unwrap_err`.
        match build_sql_backends(
            Some(&cfg),
            tmp.path(),
            &deploy,
            &kv,
            None,
            &boatramp_core::env::SystemEnv,
        )
        .await
        {
            Err(Error::SqlManagedNeedsSecrets(name)) => assert_eq!(name, "analytics"),
            Ok(_) => panic!("a managed DB without [secrets] must fail closed, got Ok"),
            Err(other) => panic!("expected SqlManagedNeedsSecrets, got: {other}"),
        }
    }

    #[tokio::test]
    async fn managed_sql_builds_lazily_and_seals_the_credential() {
        let tmp = tempfile::tempdir().unwrap();
        let deploy = DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()));
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let envelope: Arc<dyn KeyEnvelope> = Arc::new(TestEnvelope);
        let cfg = managed_sql_cfg();
        // No DB is running: assembly builds the composite without a connection AND
        // without minting any credential — every compute-backed managed binding is
        // now **per-tenant**, so a credential is sealed lazily per (tenant, server)
        // on first `open`, not eagerly at build (a tenant isn't known at build time).
        let backends = build_sql_backends(
            Some(&cfg),
            tmp.path(),
            &deploy,
            &kv,
            Some(&envelope),
            &boatramp_core::env::SystemEnv,
        )
        .await
        .expect("managed sql builds without a live DB (lazy connect)");
        assert!(
            kv.get("managed-sql-cred/default/pg")
                .await
                .unwrap()
                .is_none(),
            "nothing sealed at build — per-tenant credentials are minted on first open"
        );

        // Resolving the binding for the default project's site (the single-tenant
        // install) seals the credential under the plain default-project + workload
        // key, so the DB's server-init env (same key) and the handler connection agree.
        let _ = backends
            .database("default", "blog", "analytics")
            .await
            .unwrap();
        let sealed = kv
            .get("managed-sql-cred/default/pg")
            .await
            .unwrap()
            .expect("credential sealed on first resolve under the default project");
        assert_ne!(sealed.len(), 0);
    }
}
