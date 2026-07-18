//! boatramp HTTP server + publishing API.
//!
//! The server is backend-agnostic: it is handed a [`DeployStore`] (blobs in any
//! [`boatramp_core::Storage`], metadata in any [`boatramp_core::kv::KvStore`])
//! and exposes:
//!
//! - a **publishing API** used by `boatramp sync` — negotiate a manifest,
//!   upload missing blobs (streamed), then atomically activate;
//! - **public serving** of the currently-active deployment for each site.
//!
//! Every byte path streams: uploads flow request→backend, downloads flow
//! backend→response, and only small manifests are ever held in memory.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post, put};
use axum::{Extension, Json, Router};
use boatramp_core::access::{AccessConfig, BasicAuth};
use boatramp_core::authz::{GrantedRole, TokenMeta};
use boatramp_core::config::{DeployConfig, SiteConfig};
use boatramp_core::cose::{self, Claims, Signer};
use boatramp_core::deploy::{
    DeployMetaInput, DeployStore, FileEntry, GcOptions, GcReport, Manifest,
};
use boatramp_core::matcher::Pattern;
use boatramp_core::route::{self, Outcome};
use boatramp_core::{DeployError, StorageError};
use futures::StreamExt;
use serde::{Deserialize, Serialize};

mod auth;
#[cfg(feature = "console")]
pub mod console;
mod content;
mod control_api;
#[cfg(feature = "compression")]
pub(crate) use content::maybe_compress;
pub(crate) use content::multipart_byteranges;
pub(crate) use content::{
    negotiate_encoding, parse_ranges, response_headers, set_content_encoding, MAX_RANGES,
};
pub(crate) use control_api::{
    add_root_anchor, auth_whoami, bootstrap_token, cluster_join, cluster_members, cluster_promote,
    cluster_revoke, cluster_rotate_key, create_join_token, create_token, get_authz_policy,
    list_root_anchors, list_tokens, put_authz_policy, remove_root_anchor, revoke_token,
};
#[cfg(test)]
use control_api::{BootstrapRequest, CreateJoinTokenRequest, JoinRequest};
mod domain_verify;
pub use domain_verify::{spawn_domain_verify_reconcile, verification_pending_page};
pub mod envelope;
#[cfg(feature = "handlers")]
mod handler_dispatch;
#[cfg(feature = "handlers")]
pub(crate) use handler_dispatch::{
    build_bindings, dispatch_consumer_batch, dispatch_handler, precheck_component, read_blob_bytes,
    read_blob_fully,
};
#[cfg(all(feature = "handlers", test))]
use handler_dispatch::{resolve_env, set_forwarded_headers};
mod function_api;
pub(crate) use function_api::{
    alias_function, deploy_function, list_functions, remove_function, rollback_function,
};
#[cfg(test)]
use function_api::{AliasBody, FunctionUpsert, RollbackBody};
mod gateway;
mod host;
pub(crate) use host::{is_local_host, parse_deploy_host, strip_port};
#[cfg(feature = "http3")]
mod http3;
mod limits;
#[cfg(feature = "handlers")]
mod logs;
#[cfg(feature = "handlers")]
mod metrics;
#[cfg(feature = "oidc")]
mod oidc;
mod operator;
pub(crate) use operator::prometheus_metrics;
#[cfg(feature = "handlers")]
pub(crate) use operator::{
    operator_dlq, operator_handler_stats, operator_logs, operator_logs_stream,
};
mod proxy;
pub use proxy::spawn_compute_reconcile;
pub(crate) use proxy::{
    await_warm, compute_endpoint_regions, compute_endpoints, dispatch_gateway, has_parked_replica,
    is_upgrade_request, proxy, COMPUTE_WAKE_TIMEOUT,
};
#[cfg(test)]
use proxy::{gateway_addr_allowed, CLOUD_METADATA_IPV4};
mod ratelimit;
#[cfg(feature = "handlers")]
mod scheduler;
mod serve_pipeline;
pub use serve_pipeline::http_redirect_router;
#[cfg(test)]
use serve_pipeline::{apply_vary, parse_cookie_header, parse_query_string};
pub(crate) use serve_pipeline::{
    serve_bootstrap_identity, serve_by_host, serve_domain_challenge, serve_preview, serve_sites,
    BootstrapAttestation,
};
/// External token signer backends: KMS / HSM / Vault-hosted
/// control-plane root keys behind the [`boatramp_core::cose::Signer`] seam.
pub mod signer;
mod srvmetrics;
#[cfg(all(feature = "handlers", test))]
use scheduler::run_scheduler_tick;
#[cfg(feature = "handlers")]
pub(crate) use scheduler::{
    acquire_site_permit, effective_limits, handler_error_response, handler_unavailable, CronNow,
};
#[cfg(feature = "handlers")]
use scheduler::{CONSUMER_BATCH, CONSUMER_LEASE, CONSUMER_MAX_ATTEMPTS};
#[cfg(feature = "handlers")]
mod function_runtime;
#[cfg(feature = "handlers")]
pub(crate) use function_runtime::{
    b64_decode, b64_encode, blob_storage_prefix, capture_response, delete_trigger_handler,
    dispatch_function_triggers, drain_function_invocations, execute_function, get_function_usage,
    get_invocation_record, invoke_function, list_triggers_handler, new_invocation_id,
    put_trigger_handler, webhook_ingress,
};
#[cfg(feature = "handlers")]
mod stream;
#[cfg(feature = "handlers")]
mod workflow;
pub use auth::{require_auth, Auth};
#[cfg(feature = "http3")]
pub use http3::{
    advertise_http3, http3_endpoint, quinn_server_config, serve_http3, serve_http3_endpoint,
    Http3Error,
};
pub use limits::{ServerLimits, UploadGuard};
#[cfg(feature = "oidc")]
pub use oidc::{OidcConfig, OidcError, OidcVerifier};
use ratelimit::{KvRateLimiter, RateLimitStore, RateLimiter};
#[cfg(feature = "handlers")]
pub(crate) use stream::{route_matches, serve_stream, serve_ws_stream};
#[cfg(feature = "handlers")]
pub(crate) use workflow::{
    define_workflow, delete_workflow_handler, drain_workflow_runs, get_workflow_handler,
    get_workflow_run_handler, list_workflows_handler, start_workflow_run,
};
// The process-wide HTTP/lifecycle metrics registry. Re-exported so the CLI's
// certificate-renewal path can record renewals against the same counters.
pub use srvmetrics::{server_metrics, ServerMetrics};

/// The WebAssembly handler runtime: the shared engine plus the per-site binding
/// backends. Cheap to clone (it is an `Arc` inside). Without the `handlers`
/// feature it is an empty placeholder, so the serving signatures stay uniform —
/// pass [`HandlerRuntime::disabled`].
#[derive(Clone, Default)]
pub struct HandlerRuntime {
    #[cfg(feature = "handlers")]
    inner: Option<Arc<HandlerRuntimeInner>>,
}

#[cfg(feature = "handlers")]
struct HandlerRuntimeInner {
    engine: boatramp_handlers::HandlerEngine,
    kv: Arc<dyn boatramp_core::kv::KvStore>,
    storage: Arc<dyn boatramp_core::Storage>,
    /// Per-site SQL database provider (libsql — single-node files by default;
    /// absent = the `sql` capability is not offered, so handlers requesting it
    /// are refused at activation).
    sql: Option<Arc<dyn boatramp_core::sql::SqlBackends>>,
    /// Internal messaging substrate for the `wasi:messaging` binding (publish;
    /// consumer dispatch is driven separately). Absent = messaging not offered.
    messaging: Option<Arc<dyn boatramp_core::messaging::Messaging>>,
    /// Per-site concurrency semaphores (for sites that set `maxConcurrency`),
    /// created on first use.
    site_semaphores:
        std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Semaphore>>>,
    /// Per-scope SSE connection semaphores (per-site cap),
    /// created on first use and keyed by binding scope so a preview's streams
    /// can't exhaust the live site's budget.
    stream_semaphores:
        std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Semaphore>>>,
    /// Live SSE connection counts per `(scope, client-ip)`, for the per-IP cap.
    /// `Arc` so a connection's RAII guard can decrement it on drop.
    stream_ip_counts: Arc<std::sync::Mutex<std::collections::HashMap<(String, IpAddr), u32>>>,
    /// Per-invocation observability counters, read by the
    /// operator endpoint + Prometheus exporter.
    metrics: metrics::Metrics,
    /// Captured guest stdout/stderr: per-site ring + rate cap.
    logs: Arc<logs::LogStore>,
    /// Optional **cron leader gate**: in cluster mode the
    /// scheduler fires crons only when this returns `true` (the node is the Raft
    /// leader), so a cron fires exactly once cluster-wide. `None` (single-node)
    /// always fires. Consumers are *not* gated — leased dispatch distributes
    /// them across nodes.
    cron_leader_gate: std::sync::OnceLock<CronLeaderGate>,
    /// Max bytes a `wasi:blobstore` host read/range/copy may buffer (`0` =
    /// unlimited), from the security posture. Set once at serve
    /// startup via [`HandlerRuntime::set_max_blob_bytes`]; unset reads as `0`.
    max_blob_bytes: std::sync::OnceLock<u64>,
    /// Max size of a Wasm component blob accepted at activation (`0` = unlimited),
    /// from the security posture. Checked against the manifest's file
    /// size *before* the blob is read. Set via
    /// [`HandlerRuntime::set_max_component_bytes`]; unset reads as `0`.
    max_component_bytes: std::sync::OnceLock<u64>,
    /// Per-function locks serializing the metering + rate-limit read-modify-write
    /// (FA-4), so concurrent invocations of one function can't lose an update.
    /// Created on first use, keyed by function name.
    function_meter_locks:
        std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Per-function concurrency semaphores (for functions that set a
    /// `max_concurrent` quota), created on first use.
    function_semaphores:
        std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Semaphore>>>,
    /// Optional cloud **blob-change notification provisioner** (FA-5b2): when set,
    /// adding a `Blob` trigger provisions the native pipeline (S3→SQS, …) per the
    /// [`provision_tier`](Self::provision_tier), and removing it retracts. Absent
    /// on a self-watching backend (fs), which needs no provisioning.
    watch_provider: std::sync::OnceLock<Arc<dyn boatramp_core::blob_provision::WatchProvider>>,
    /// The operator tier governing the [`watch_provider`](Self::watch_provider):
    /// dry-run (recipe) / provision / verify-only / refuse. Unset reads as the
    /// fail-closed default (`Refuse`).
    provision_tier: std::sync::OnceLock<boatramp_core::blob_notify::ProvisionTier>,
}

/// Predicate gating cron firing to the cluster leader (see
/// [`HandlerRuntime::set_cron_leader_gate`]).
pub type CronLeaderGate = Arc<dyn Fn() -> bool + Send + Sync>;

impl HandlerRuntime {
    /// An empty runtime — handler dispatch disabled (the static path is unchanged).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Build a runtime over `engine`. The `wasi:keyvalue` / `wasi:blobstore`
    /// bindings are served from the server's own `kv` / `storage` backends (each
    /// namespaced per site); `sql`, if a provider is given, serves a per-site
    /// database (the default `""` database). `sql: None` means the `sql`
    /// capability is not offered.
    #[cfg(feature = "handlers")]
    pub fn new(
        engine: boatramp_handlers::HandlerEngine,
        kv: Arc<dyn boatramp_core::kv::KvStore>,
        storage: Arc<dyn boatramp_core::Storage>,
        sql: Option<Arc<dyn boatramp_core::sql::SqlBackends>>,
        messaging: Option<Arc<dyn boatramp_core::messaging::Messaging>>,
    ) -> Self {
        Self {
            inner: Some(Arc::new(HandlerRuntimeInner {
                engine,
                kv,
                storage,
                sql,
                messaging,
                site_semaphores: std::sync::Mutex::new(std::collections::HashMap::new()),
                stream_semaphores: std::sync::Mutex::new(std::collections::HashMap::new()),
                stream_ip_counts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
                metrics: metrics::Metrics::default(),
                logs: Arc::new(logs::LogStore::default()),
                cron_leader_gate: std::sync::OnceLock::new(),
                max_blob_bytes: std::sync::OnceLock::new(),
                max_component_bytes: std::sync::OnceLock::new(),
                function_meter_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
                function_semaphores: std::sync::Mutex::new(std::collections::HashMap::new()),
                watch_provider: std::sync::OnceLock::new(),
                provision_tier: std::sync::OnceLock::new(),
            })),
        }
    }

    /// Wire the cloud blob-change notification provisioner (FA-5b2). Set once at
    /// startup when the storage backend is a cloud object store; a no-op runtime,
    /// or a self-watching backend (fs), leaves it unset.
    #[cfg(feature = "handlers")]
    pub fn set_watch_provider(
        &self,
        provider: Arc<dyn boatramp_core::blob_provision::WatchProvider>,
    ) {
        if let Some(inner) = self.inner.as_ref() {
            let _ = inner.watch_provider.set(provider);
        }
    }

    /// Set the operator provisioning tier for the
    /// [`watch_provider`](Self::set_watch_provider). Set once at startup; unset is
    /// the fail-closed `Refuse`.
    #[cfg(feature = "handlers")]
    pub fn set_provision_tier(&self, tier: boatramp_core::blob_notify::ProvisionTier) {
        if let Some(inner) = self.inner.as_ref() {
            let _ = inner.provision_tier.set(tier);
        }
    }

    /// Cap the bytes a `wasi:blobstore` host read/range/copy may buffer (`0` =
    /// unlimited), from the security posture. Set once at startup; a
    /// no-op runtime ignores it.
    #[cfg(feature = "handlers")]
    pub fn set_max_blob_bytes(&self, max_bytes: u64) {
        if let Some(inner) = self.inner.as_ref() {
            let _ = inner.max_blob_bytes.set(max_bytes);
        }
    }

    /// Cap the size of a Wasm component blob accepted at activation (`0` =
    /// unlimited), from the security posture. Set once at startup.
    #[cfg(feature = "handlers")]
    pub fn set_max_component_bytes(&self, max_bytes: u64) {
        if let Some(inner) = self.inner.as_ref() {
            let _ = inner.max_component_bytes.set(max_bytes);
        }
    }

    /// Gate cron firing on a predicate (cluster mode: the node is the Raft
    /// leader), so a cron fires exactly once cluster-wide.
    /// Set once at startup; a no-op runtime ignores it. Consumers are never
    /// gated (leased dispatch already distributes them).
    #[cfg(feature = "handlers")]
    pub fn set_cron_leader_gate(&self, gate: CronLeaderGate) {
        if let Some(inner) = self.inner.as_ref() {
            let _ = inner.cron_leader_gate.set(gate);
        }
    }

    /// Pre-activation gate: refuse to flip a deployment
    /// whose handlers can't be satisfied — the site must enable handlers and
    /// allow each requested import (the resolution rule), and every component
    /// must compile (so a broken component never goes live; this also pre-warms
    /// the cache). `Err(reason)` means "do not activate". A no-op for deploys
    /// with no handlers, or without the `handlers` feature/runtime.
    #[cfg(feature = "handlers")]
    async fn precheck_activation(
        &self,
        deploy: &DeployStore,
        manifest: &Manifest,
        site_config: Option<&SiteConfig>,
    ) -> Result<(), String> {
        let Some(inner) = self.inner.as_ref() else {
            return Ok(());
        };
        // Consumer-only deploys must be prechecked too: skip only
        // when neither handlers nor consumers ship.
        if manifest.config.handlers.is_empty() && manifest.config.consumers.is_empty() {
            return Ok(());
        }
        // A deploy that ships handlers or consumers requires the site to enable them.
        let site_handlers = site_config
            .and_then(|c| c.handlers.as_ref())
            .filter(|h| h.enabled)
            .ok_or_else(|| {
                "deployment ships handlers/consumers but the site has them disabled".to_string()
            })?;
        let max_component = inner.max_component_bytes.get().copied().unwrap_or(0);

        // Same import/size/compile gate for every handler and consumer component.
        for handler in &manifest.config.handlers {
            precheck_component(
                deploy,
                manifest,
                site_handlers,
                inner,
                max_component,
                &handler.imports,
                &handler.component,
                &format!("handler {:?}", handler.route),
            )
            .await?;
        }
        for consumer in &manifest.config.consumers {
            precheck_component(
                deploy,
                manifest,
                site_handlers,
                inner,
                max_component,
                &consumer.imports,
                &consumer.component,
                &format!("consumer {:?}", consumer.topic),
            )
            .await?;
        }
        Ok(())
    }

    #[cfg(not(feature = "handlers"))]
    async fn precheck_activation(
        &self,
        _deploy: &DeployStore,
        _manifest: &Manifest,
        _site_config: Option<&SiteConfig>,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// Server runtime knobs that aren't part of the core (deploy, auth, handlers)
/// triple: operational request [`limits`](ServerLimits) and an optional custom
/// domain-ownership [`DomainProbe`] (defaults to the live network probe).
///
/// [`DomainProbe`]: boatramp_core::domain_verify::DomainProbe
#[derive(Default, Clone)]
pub struct ServerOptions {
    /// Operational upload limits (size / idle / concurrency).
    pub limits: ServerLimits,
    /// Domain-ownership probe override (tests inject a scripted one); `None`
    /// uses the live HTTP/DNS probe.
    pub probe: Option<Arc<dyn boatramp_core::domain_verify::DomainProbe>>,
    /// Site to serve for a `Host` that matches no domain, instead of `404`.
    /// `None` keeps the 404 default.
    pub default_site: Option<String>,
    /// Resolve an unmatched `Host` to a site **without** an explicit domain
    /// registration — by first host label (`<site>.host`), or, when exactly one
    /// site is served, as the sole site. The effective gate (posture knob OR a
    /// loopback bind), computed by `serve`. `false` (the default) keeps the
    /// strict behavior: an unmatched host resolves only to `default_site` or 404.
    pub implicit_routing: bool,
    /// Require a valid control-plane token to view a deployment **preview**
    /// (`/_deploy/<id>/…` and `<id>.deploy.<host>`) — the
    /// `previews.protect` setting. Off by default (previews are unguessable capability
    /// URLs).
    pub protect_previews: bool,
    /// When set, rate limiting uses a **cluster-wide** KV-backed fixed-window
    /// counter over this store instead of the per-node in-process buckets.
    /// Pass the shared/replicated KV (e.g. the cluster `RaftKv`).
    pub cluster_rate_limit_kv: Option<Arc<dyn boatramp_core::kv::KvStore>>,
    /// The token signer (root private key / KMS / HSM), when this node issues
    /// tokens (the `/api/tokens` create route and the OIDC→token exchange).
    /// `None` ⇒ verify-only.
    pub issuer: Option<Arc<dyn Signer>>,
    /// An operator-set, single-use **bootstrap secret** enabling the
    /// `POST /api/tokens/bootstrap` first-token route. `None` ⇒ that route returns
    /// `501`. Compared by SHA-256, single-use (rotating the secret re-enables it);
    /// unset once bootstrapped.
    pub bootstrap_secret: Option<String>,
    /// A **bootstrap-TLS identity attestation** (base64url `COSE_Sign1`) served at
    /// `GET /.well-known/boatramp-bootstrap-identity` — the root key vouching for
    /// this node's `--tls rpk` control-plane TLS public key, so a client pinning
    /// only the root key can learn + pin the TLS identity. Set by `serve` under
    /// `--tls rpk` when an issuer is present; `None` ⇒ the route returns `404`.
    pub bootstrap_attestation: Option<String>,
    /// The cluster mesh control hook, wired in cluster mode over
    /// `ClusterNode`. Backs `POST /api/cluster/join` + `/rotate-key`; `None`
    /// (single-node) ⇒ those routes return `501`.
    pub mesh_control: Option<Arc<dyn MeshControl>>,
    /// Origins allowed to call the control-plane `/api/*` routes cross-origin
    /// (CORS). Empty (the default) ⇒ no `Access-Control-*` headers at all, i.e.
    /// same-origin only — which is exactly the dogfood console, served from the
    /// same origin as the API. Set this to host the console (or any browser
    /// client) on a *different* origin: each entry is an exact
    /// `scheme://host[:port]` (e.g. `https://console.example.com`), or `*` to
    /// allow any origin. The API authenticates with a Bearer token (not cookies),
    /// so credentials are not enabled; the matched origin is echoed back with
    /// `Vary: Origin`, and a preflight `OPTIONS` is answered before auth runs.
    pub cors_allowed_origins: Vec<String>,
    /// The OIDC verifier for `/api/auth/exchange` (validates the IdP JWT before
    /// minting a token). Only with the `oidc` feature + an issuer key.
    #[cfg(feature = "oidc")]
    pub oidc_verifier: Option<Arc<oidc::OidcVerifier>>,
    /// The resolved operator security posture (the hardening knobs).
    /// Carried as an extension so the gateway, proxy, domain-verify, and upload
    /// paths can consult it. Defaults to the strict `multi-tenant` preset.
    pub posture: boatramp_core::security::SecurityPosture,
    /// Whether this server's listener terminates TLS (the connection scheme is
    /// `https`). Set by `serve` from the TLS mode; used to derive the request
    /// scheme when `X-Forwarded-Proto` can't be trusted. Default
    /// `false` (plain HTTP).
    pub served_over_tls: bool,
    /// The fleet's **canonical public origin** (e.g. `https://cp.example.com`) that
    /// a per-request PoP proof must be bound to (`aud`). Set from `[serve]
    /// pop_origin` in `boatramp.cfg`. Compared against a proof's bound origin —
    /// **never** derived from a `Host`/`X-Forwarded-*` header. A holder-bound
    /// (`cnf`) token cannot be used against a server that has not configured this
    /// (its proof can't be verified, so the request is rejected).
    pub pop_origin: Option<String>,
    /// A pre-built dynamic daemon-config runtime. `serve` supplies one (built via
    /// [`config_baseline`] + [`DaemonRuntime::new`]) so it can wake it on
    /// SIGHUP / changelog; `None` (tests, embedders) ⇒ the router builds its own.
    pub daemon_runtime: Option<Arc<DaemonRuntime>>,
    /// The embedded web-console mount (`[serve.console]`), when the operator
    /// enabled it and the binary was built with the `console` feature. `None` ⇒
    /// not served. The static SPA is served unauthenticated at this host+path.
    #[cfg(feature = "console")]
    pub console: Option<console::ConsoleMount>,
}

/// The listener's own connection scheme (`true` = `https`), carried as an
/// extension so the serving path can derive the scheme without trusting a
/// forged `X-Forwarded-Proto` from a direct client.
#[derive(Clone, Copy)]
struct ServedOverTls(bool);

/// Whether the host fallback may resolve an unmatched `Host` to a site without an
/// explicit domain registration (first-label `<site>.host`, or the sole served
/// site). Carried as an extension; the effective gate is resolved by `serve`
/// (posture knob OR loopback bind). `false` = strict (default_site or 404 only).
#[derive(Clone, Copy, Default)]
struct ImplicitRouting(bool);

/// Holds the live, resolved [`EffectiveConfig`] (`file baseline ⊕ dynamic
/// overrides`) plus the active generation hash. Request handlers read the current
/// operational values through [`effective`](Self::effective); the daemon-config
/// API and the SIGHUP handler [`reload`](Self::reload) it from the store, so a
/// change converges without a restart.
/// Defensive backstop interval for re-resolving the dynamic daemon config.
/// Convergence is **fully notification-driven** — a local write applies
/// immediately; a SIGHUP, a shared-store changelog invalidation of `daemon/*`, or
/// a Raft apply of a replicated `daemon/*` write each wakes an immediate reload via
/// [`DaemonRuntime::notify_reload`]. This long tick is only a safety net against a
/// missed wake; it is not the convergence mechanism.
const DAEMON_RELOAD_BACKSTOP: std::time::Duration = std::time::Duration::from_secs(300);

pub struct DaemonRuntime {
    baseline: boatramp_core::daemon_config::ConfigBaseline,
    state: std::sync::RwLock<DaemonState>,
    /// Woken (by SIGHUP / changelog / a local write) to trigger an immediate
    /// reload instead of waiting for the backstop tick.
    reload: tokio::sync::Notify,
}

struct DaemonState {
    effective: Arc<boatramp_core::daemon_config::EffectiveConfig>,
    generation: Option<String>,
}

/// The daemon-config file baseline derived from [`ServerOptions`] (the resolved
/// `boatramp.cfg`). `serve` uses this to build a [`DaemonRuntime`] it can wake on
/// SIGHUP/changelog; the posture's upload cap is the ceiling a dynamic override
/// may not exceed.
pub fn config_baseline(options: &ServerOptions) -> boatramp_core::daemon_config::ConfigBaseline {
    // The static `[serve.console]` mount is the baseline the dynamic
    // `DaemonConfig.console` override layers over. `Some(mount)` ⇒ enabled at the
    // file level; without the `console` feature there is nothing to serve.
    #[cfg(feature = "console")]
    let (console_enabled, console_host, console_path) = match options.console.as_ref() {
        Some(m) => (true, Some(m.host.clone()), Some(m.path.clone())),
        None => (false, None, None),
    };
    #[cfg(not(feature = "console"))]
    let (console_enabled, console_host, console_path) = (false, None, None);
    boatramp_core::daemon_config::ConfigBaseline {
        default_site: options.default_site.clone(),
        protect_previews: options.protect_previews,
        max_upload_bytes: options.limits.max_upload_bytes.unwrap_or(0),
        upload_idle_timeout_secs: options.limits.upload_idle_timeout.map(|d| d.as_secs()),
        max_concurrent_uploads: options.limits.max_concurrent_uploads.map(|n| n as u64),
        cluster_rate_limit: options.cluster_rate_limit_kv.is_some(),
        compute_vcpus: 0,
        compute_mem_mib: 0,
        console_enabled,
        console_host,
        console_path,
        max_upload_ceiling: options.posture.max_upload_bytes,
        max_concurrent_uploads_ceiling: None,
        posture: options.posture,
    }
}

impl DaemonRuntime {
    /// Build with the file baseline; the effective config starts equal to the
    /// baseline (no dynamic override) until [`reload`](Self::reload) runs. `serve`
    /// builds this (via [`config_baseline`]) so it can wake it on SIGHUP/changelog.
    pub fn new(baseline: boatramp_core::daemon_config::ConfigBaseline) -> Self {
        let effective =
            Arc::new(boatramp_core::daemon_config::DaemonConfig::default().resolve(&baseline));
        Self {
            baseline,
            state: std::sync::RwLock::new(DaemonState {
                effective,
                generation: None,
            }),
            reload: tokio::sync::Notify::new(),
        }
    }

    /// Wake an immediate re-resolve from the store. Called by the SIGHUP handler,
    /// the shared-store changelog poller (when a `daemon/*` key changed), and after
    /// a local write — so convergence is push-driven, not poll-driven.
    pub fn notify_reload(&self) {
        self.reload.notify_one();
    }

    /// The current effective operational config.
    pub fn effective(&self) -> Arc<boatramp_core::daemon_config::EffectiveConfig> {
        self.state
            .read()
            .expect("daemon config lock")
            .effective
            .clone()
    }

    /// The active generation hash (the `daemon/current` content address), or
    /// `None` when running on the pure file baseline.
    pub fn generation(&self) -> Option<String> {
        self.state
            .read()
            .expect("daemon config lock")
            .generation
            .clone()
    }

    /// The file baseline (+ static ceilings) a write is validated against.
    pub fn baseline(&self) -> &boatramp_core::daemon_config::ConfigBaseline {
        &self.baseline
    }

    /// Re-resolve `baseline ⊕ stored dynamic config` and hot-swap the live values.
    /// Called after a write and on SIGHUP.
    pub async fn reload(&self, deploy: &DeployStore) -> Result<(), DeployError> {
        let cfg = deploy.get_daemon_config().await?.unwrap_or_default();
        let generation = deploy.daemon_config_generation().await?;
        let effective = Arc::new(cfg.resolve(&self.baseline));
        *self.state.write().expect("daemon config lock") = DaemonState {
            effective,
            generation,
        };
        Ok(())
    }
}

/// Preview-access policy, carried as an extension so the preview handlers can
/// require a token when `protect` is set.
#[derive(Clone, Copy, Default)]
struct PreviewPolicy {
    protect: bool,
}

/// The token issuing signer (root private key / KMS / HSM), carried as an
/// extension for the token-create and OIDC-exchange handlers. `None` ⇒ this node
/// verifies tokens but does not issue them (it has only the public key); issuing
/// routes return `501`.
#[derive(Clone, Default)]
struct Issuer(Option<Arc<dyn Signer>>);

/// The first-token bootstrap gate: the SHA-256 hex of the operator-set bootstrap
/// secret plus an in-process lock that serializes the check-and-spend (the KV has
/// no compare-and-set; a persisted marker keeps it single-use across restarts).
/// `None` ⇒ bootstrap disabled (the route returns `501`).
#[derive(Clone, Default)]
struct BootstrapGate(Option<Arc<BootstrapInner>>);

struct BootstrapInner {
    /// SHA-256 hex of the configured secret — used for both the constant-work
    /// comparison and the single-use marker key.
    secret_hash: String,
    /// Serializes the read-marker → mint → write-marker section so two concurrent
    /// redemptions can't both mint.
    lock: tokio::sync::Mutex<()>,
}

impl BootstrapGate {
    fn new(secret: Option<&str>) -> Self {
        Self(secret.filter(|s| !s.is_empty()).map(|s| {
            Arc::new(BootstrapInner {
                secret_hash: boatramp_core::deploy::sha256_hex(s.as_bytes()),
                lock: tokio::sync::Mutex::new(()),
            })
        }))
    }
}

/// The cluster mesh control operations exposed to the control-plane API,
/// implemented by the cluster runtime over `ClusterNode`;
/// `None` on a non-cluster node (the routes then return `501`).
#[async_trait::async_trait]
pub trait MeshControl: Send + Sync {
    /// Admit a joining node presenting a bearer join token whose single-use handle
    /// is `jti`: **verify the possession proof** (`possession_proof` over
    /// `cose::join_challenge(jti, mesh_pubkey_hex, proof_iat)`, fresh at `now`)
    /// against `mesh_pubkey_hex`, then — if valid and the token isn't spent — trust
    /// the key cluster-wide, add it to membership (id derived from the key), and
    /// return the current members as **root-signed** assertions. `Err` is a
    /// human-readable failure (e.g. this node has no root key to vouch for members).
    async fn admit(
        &self,
        mesh_pubkey_hex: &str,
        jti: &str,
        possession_proof: &[u8],
        proof_iat: u64,
        now: u64,
        advertise_addr: Option<&str>,
    ) -> Result<JoinOutcome, String>;

    /// Rotate **this node's** mesh identity (make-before-break) and return the new
    /// public key (SPKI hex). Node-local: only the node itself can mint + persist
    /// its private key, so this rotates the key of the node whose API is hit.
    async fn rotate_key(&self) -> Result<String, String>;

    /// Revoke `node` from the mesh: delete its trust cluster-wide (so it can no
    /// longer authenticate) and drop it from the quorum. `Err` is a
    /// human-readable failure.
    async fn revoke(&self, node: u64) -> Result<(), String>;

    /// The current Raft membership (voters + learners), for the Kubernetes
    /// operator's membership reconciler. `caught_up` is meaningful only on the
    /// leader; hit the leader for a promote decision.
    async fn members(&self) -> Result<Vec<MeshMember>, String>;

    /// Promote a caught-up learner `node` to a voter (leader-only; a no-op on a
    /// follower). `Err` is a human-readable failure.
    async fn promote(&self, node: u64) -> Result<(), String>;
}

/// The result of a join admission ([`MeshControl::admit`]).
pub enum JoinOutcome {
    /// Admitted — carries the current members as root-signed assertions plus the
    /// advisory `node_id -> mesh URL` routing for them.
    Admitted {
        /// Root-signed member assertions the joiner verifies against the anchor.
        members: Vec<String>,
        /// Advisory `node_id -> mesh URL` routing (not signed).
        addrs: std::collections::BTreeMap<u64, String>,
    },
    /// The join token was already spent (single-use) → `409`.
    TokenSpent,
    /// The possession proof was missing/stale/invalid → `403`.
    ProofInvalid,
    /// The presented key is revoked (a durable tombstone bars it, F6) — an
    /// explicit un-revoke is required before it can rejoin → `403`.
    Revoked,
}

/// One node's Raft membership, reported by `GET /api/cluster/members`.
#[derive(Debug, Clone, Serialize)]
pub struct MeshMember {
    /// The node id.
    pub node: u64,
    /// `true` ⇒ a voter (counts toward quorum); `false` ⇒ a learner.
    pub voter: bool,
    /// Whether a learner has caught up to the leader's log (ready to promote).
    pub caught_up: bool,
    /// Whether this node is the current leader.
    pub leader: bool,
    /// The node's advisory mesh URL, if this node knows it — the address-primary
    /// handle `cluster status`/`remove` use (dynamic-join learns addresses at
    /// admit; a static-genesis node has them from config). `None` ⇒ unknown here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
}

/// The mesh control hook, carried as an extension for the join/rotate handlers.
/// `None` ⇒ this node is not a cluster node, so those routes return `501`.
#[derive(Clone, Default)]
struct MeshControlHandle(Option<Arc<dyn MeshControl>>);

/// The OIDC verifier for the exchange endpoint, carried as an extension.
#[cfg(feature = "oidc")]
#[derive(Clone, Default)]
struct OidcState(Option<Arc<oidc::OidcVerifier>>);

/// TTL for an OIDC-exchanged token: short, since the holder can re-exchange
/// against the IdP at any time.
#[cfg(feature = "oidc")]
const EXCHANGE_TTL_SECS: u64 = 3600;

use boatramp_core::time::now_unix;

/// Build the application router around a [`DeployStore`], [`Auth`] config, and
/// the WebAssembly handler runtime ([`HandlerRuntime::disabled`] for none), with
/// default [`ServerOptions`] (unlimited, live probe).
pub fn router(deploy: DeployStore, auth: Auth, handlers: HandlerRuntime) -> Router {
    router_with(deploy, auth, handlers, ServerOptions::default())
}

/// [`router`] with explicit [`ServerOptions`] — lets a caller set request limits
/// or inject a custom domain-ownership probe.
pub fn router_with(
    deploy: DeployStore,
    auth: Auth,
    handlers: HandlerRuntime,
    options: ServerOptions,
) -> Router {
    // Opt-in CORS allowlist for the control-plane API; empty ⇒ CORS off.
    // Captured before `options` is partially moved below.
    let cors_origins = options.cors_allowed_origins.clone();
    // The resolved security posture rides as an extension for the gateway /
    // proxy / domain-verify / upload paths (the hardening knobs).
    let posture = options.posture;
    // Bind the auth layer's per-request PoP enforcement: the fleet's canonical
    // origin (the proof's required `aud`) and whether every token must be
    // holder-bound (`require_pop`). A holder-bound (`cnf`) token always requires a
    // valid proof regardless of the knob (enforced in `Auth::authorize`).
    let auth = auth.with_pop(options.pop_origin.clone(), posture.require_pop);
    // The listener's own scheme, for deriving the request scheme when
    // `X-Forwarded-Proto` isn't from a trusted proxy.
    let served_over_tls = ServedOverTls(options.served_over_tls);
    // The dynamic daemon-config runtime: file baseline ⊕ stored overrides. When
    // `serve` supplies one (so it can wake it on SIGHUP/changelog) we use it; else
    // (tests, embedders) we build one from the options' baseline.
    let daemon = options
        .daemon_runtime
        .clone()
        .unwrap_or_else(|| Arc::new(DaemonRuntime::new(config_baseline(&options))));
    // A deploy handle for the daemon-config startup reload, captured before
    // `deploy` is moved into the router state below.
    let daemon_init_deploy = deploy.clone();
    let implicit_routing = ImplicitRouting(options.implicit_routing);
    let preview_policy = PreviewPolicy {
        protect: options.protect_previews,
    };
    // Clone for the preview gate before `auth` is moved into the API middleware.
    let preview_auth = auth.clone();
    // The token issuing signer + OIDC verifier ride as extensions for the token
    // and exchange handlers.
    let issuer = Issuer(options.issuer.clone());
    let bootstrap = BootstrapGate::new(options.bootstrap_secret.as_deref());
    let bootstrap_attestation = options.bootstrap_attestation.clone();
    // The mesh join admitter, for `POST /api/cluster/join`.
    let mesh_control = MeshControlHandle(options.mesh_control.clone());
    #[cfg(feature = "oidc")]
    let oidc_state = OidcState(options.oidc_verifier.clone());
    let probe = options.probe.unwrap_or_else(|| {
        Arc::new(domain_verify::ServerDomainProbe::new(
            posture.domain_verify_allow_private,
        ))
    });
    let upload_guard = Arc::new(UploadGuard::new(options.limits));
    // Rate-limit backend: a cluster-wide KV fixed-window when configured, else
    // the per-node in-process token buckets.
    let rate_limiter: Arc<dyn RateLimitStore> = match options.cluster_rate_limit_kv {
        Some(kv) => Arc::new(KvRateLimiter::new(kv, posture.ratelimit_fail_open)),
        None => Arc::new(RateLimiter::new()),
    };
    // Control-plane API — gated by the auth middleware.
    let api = Router::new()
        .route("/api/sites", get(list_sites))
        .route("/api/functions", get(list_functions))
        .route(
            "/api/functions/:name",
            put(deploy_function).delete(remove_function),
        )
        .route("/api/functions/:name/rollback", post(rollback_function))
        .route("/api/functions/:name/aliases/:label", put(alias_function))
        .route(
            "/api/sites/:site/deployments",
            post(create_deployment).get(list_deployments),
        )
        .route("/api/blobs/:hash", put(put_blob))
        .route(
            "/api/sites/:site/deployments/:id/activate",
            post(activate_deployment),
        )
        .route("/api/sites/:site/deployments/:id", get(get_deployment))
        .route("/api/sites/:site/current", get(current_deployment))
        .route(
            "/api/sites/:site/config",
            get(get_site_config).put(put_site_config),
        )
        .route("/api/sites/:site", axum::routing::delete(delete_site))
        .route(
            "/api/sites/:site/domains/:host/verification",
            get(domain_verify::get_domain_verification)
                .post(domain_verify::start_domain_verification)
                .delete(domain_verify::remove_domain_verification),
        )
        .route(
            "/api/sites/:site/domains/:host/verification/check",
            post(domain_verify::check_domain_verification),
        )
        .route(
            "/api/sites/:site/domain-verifications",
            get(domain_verify::list_domain_verifications),
        )
        // Admin-only: attach a host WITHOUT an ownership proof (`domain add
        // --unverified`). Gated at `system·admin` in `authz::Right::required`.
        .route(
            "/api/sites/:site/domains/:host/attach-unverified",
            post(domain_verify::attach_domain_unverified),
        )
        .route("/api/sites/:site/aliases", get(list_aliases))
        .route(
            "/api/sites/:site/aliases/:name",
            put(set_alias).delete(remove_alias),
        )
        .route("/api/tokens", post(create_token).get(list_tokens))
        // First-token bootstrap: RBAC-exempt (`Right::required` → None for exactly
        // this path); the handler verifies a single-use operator-set secret. The
        // static segment takes precedence over the `/:id` route below.
        .route("/api/tokens/bootstrap", post(bootstrap_token))
        .route("/api/tokens/:id", axum::routing::delete(revoke_token))
        // Mint a single-use mesh join token. Admin-scoped via the
        // deny-safe `Right::required` default for `/api/cluster/*`.
        .route("/api/cluster/join-token", post(create_join_token))
        // Admit a joining node presenting a join token. Gated only by the token
        // itself (`Right::required` returns `None` for exactly this path), not an
        // admin bearer — the handler verifies the join token.
        .route("/api/cluster/join", post(cluster_join))
        // Rotate this node's mesh key (make-before-break). Admin-scoped via the
        // deny-safe `Right::required` default for `/api/cluster/*`.
        .route("/api/cluster/rotate-key", post(cluster_rotate_key))
        // Revoke a node from the mesh. Admin-scoped (deny-safe default).
        .route("/api/cluster/revoke", post(cluster_revoke))
        // List the Raft membership + promote a caught-up learner (the Kubernetes
        // operator's scale reconciler). Admin-scoped (deny-safe default).
        .route("/api/cluster/members", get(cluster_members))
        .route("/api/cluster/promote", post(cluster_promote))
        .route("/api/prune", get(prune_report).post(prune_delete))
        .route("/api/scrub", post(scrub_blobs))
        .route("/api/certs", get(cert_status))
        .route("/api/cache/invalidate", post(invalidate_cache))
        .route(
            "/api/authz/policy",
            get(get_authz_policy).put(put_authz_policy),
        )
        // The replicated **root-anchor set** — make-before-break root rotation
        // (`auth rotate-root`). Admin-scoped (deny-safe `Right::required` default).
        .route(
            "/api/auth/root",
            get(list_root_anchors).put(add_root_anchor),
        )
        .route(
            "/api/auth/root/:pubkey",
            axum::routing::delete(remove_root_anchor),
        )
        // Dynamic daemon config — validated + committed on the leader, replicated,
        // hot-swapped without a restart. Admin-scoped (deny-safe `Right::required`).
        .route(
            "/api/daemon/config",
            get(get_daemon_config).put(put_daemon_config),
        )
        .route("/api/daemon/config/rollback", post(rollback_daemon_config))
        // Self-identity: any valid token may read its own roles.
        .route("/api/auth/whoami", get(auth_whoami))
        // Compute workloads — the control plane is uniform; only
        // *execution* needs KVM. Admin-scoped (deny-safe `Right::required`).
        .route("/api/compute", get(list_compute))
        .route(
            "/api/compute/:name",
            get(get_compute).put(put_compute).delete(delete_compute),
        );
    // OIDC → token exchange: validate the IdP JWT (presented as
    // the Bearer; `Right::required` returns None so the auth middleware lets it
    // through) and mint a short-TTL token. Only with the `oidc` feature.
    #[cfg(feature = "oidc")]
    let api = api.route("/api/auth/exchange", post(auth_exchange));
    // The admin-scoped Prometheus exporter is **always** available: it reports
    // the always-on serving + lifecycle metrics, so an operator
    // gets request/deploy/cert telemetry even on a build without handlers;
    // per-handler + consumer metrics are appended when the handlers feature is on.
    let api = api.route("/api/metrics", get(prometheus_metrics));
    // Per-site observability/ops endpoints, behind the same
    // auth: operator stats + captured logs. Only meaningful with handlers.
    #[cfg(feature = "handlers")]
    let api = api
        .route(
            "/api/sites/:site/_boatramp/handlers",
            get(operator_handler_stats),
        )
        .route("/api/sites/:site/_boatramp/logs", get(operator_logs))
        .route(
            "/api/sites/:site/_boatramp/logs/stream",
            get(operator_logs_stream),
        )
        .route("/api/sites/:site/_boatramp/dlq", post(operator_dlq))
        // The function **invoke** surface (FA-3) needs the engine, so it is
        // registered only with the handlers feature.
        .route("/api/functions/:name/invoke", post(invoke_function))
        .route(
            "/api/functions/:name/invocations/:id",
            get(get_invocation_record),
        )
        .route("/api/functions/:name/usage", get(get_function_usage))
        // Function triggers (scheduled + event sources): cron + queue triggers the
        // scheduler dispatches. Needs the engine, so behind the handlers feature.
        .route("/api/functions/:name/triggers", get(list_triggers_handler))
        .route(
            "/api/functions/:name/triggers/:id",
            put(put_trigger_handler).delete(delete_trigger_handler),
        )
        // Workflow orchestration (FA-6): definitions + runs. The executor drain
        // needs the engine, so the surface is registered with the handlers feature.
        .route("/api/workflows", get(list_workflows_handler))
        .route(
            "/api/workflows/:name",
            put(define_workflow)
                .get(get_workflow_handler)
                .delete(delete_workflow_handler),
        )
        .route("/api/workflows/:name/runs", post(start_workflow_run))
        .route(
            "/api/workflows/:name/runs/:id",
            get(get_workflow_run_handler),
        );
    let api = api
        .route_layer(axum::middleware::from_fn_with_state(
            auth,
            auth::require_auth,
        ))
        .with_state(deploy.clone());
    // Opt-in CORS, layered OUTSIDE the auth route-layer so a preflight `OPTIONS`
    // (which carries no `Authorization` header) is answered here before auth
    // runs. An empty allowlist leaves the API untouched (same-origin only),
    // preserving the default dogfood behavior.
    let api = if cors_origins.is_empty() {
        api
    } else {
        api.layer(axum::middleware::from_fn_with_state(
            CorsState(Arc::new(cors_origins)),
            cors,
        ))
    };

    // Public routes (never authenticated by token): health + serving +
    // immutable deploy-by-id previews. A deployment id is a SHA-256 of content,
    // so the `/_deploy/<id>/…` URL is an unguessable capability. Visitor access
    // control (basic auth / IP rules / rate limit) is applied per-site inside
    // the serving handlers via the shared [`RateLimiter`] extension.
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        // Explicit by-name admin/testing route: `/_sites/<name>/…`.
        .route("/_sites/*rest", any(serve_sites))
        .route("/_deploy/*rest", get(serve_preview))
        // Domain-ownership self-serve: serve a pending HTTP challenge token
        // before host routing, so an unattached host can verify itself. An
        // explicit route, so it wins over the `serve_by_host` fallback.
        .route(
            "/.well-known/boatramp-domain-verification/:token",
            get(serve_domain_challenge),
        )
        // Bootstrap-TLS identity: the root-key-signed attestation of this node's
        // `--tls rpk` control-plane TLS key, so a client pinning only the root key
        // can learn + pin the TLS identity. `404` when no attestation is set.
        .route(
            "/.well-known/boatramp-bootstrap-identity",
            get(serve_bootstrap_identity),
        );
    // Signed inbound-webhook ingress (FA-5): a **public** (signature-gated, not
    // token-gated) route that verifies the request signature before invoking the
    // function. Needs the engine, so it is registered only with the handlers
    // feature.
    #[cfg(feature = "handlers")]
    let app = app.route("/_webhooks/:name", post(webhook_ingress));
    let app = app
        .fallback(serve_by_host)
        .with_state(deploy)
        .layer(Extension(BootstrapAttestation(bootstrap_attestation)))
        .layer(Extension(rate_limiter))
        .merge(api)
        // The handler runtime (engine + per-site binding backends) rides as an
        // extension, like the rate limiter; added after `merge` so it reaches
        // both the public serving routes and the control-plane API (activation
        // runs the handler compile-gate). An empty runtime means handlers off.
        .layer(Extension(Arc::new(handlers)))
        // The domain-ownership probe (HTTP fetch / DNS resolve), used by the
        // verification check endpoint. Injectable for tests.
        .layer(Extension(probe))
        // Operational upload limits (size / idle / concurrency), enforced in the
        // blob-upload handler. Unlimited by default.
        .layer(Extension(upload_guard))
        // Whether an unmatched host may resolve implicitly (first-label / sole
        // site); gated to dev/single-tenant/loopback by `serve`.
        .layer(Extension(implicit_routing))
        // Preview-access policy + an Auth handle the preview handlers consult
        // when previews are token-gated.
        .layer(Extension(preview_policy))
        .layer(Extension(preview_auth));
    // The token issuing signer (token-create + OIDC exchange). Layered after the
    // merge so the API handlers can read it. (`whoami` reads the `Auth` extension
    // directly for full token validation.)
    let app = app.layer(Extension(issuer));
    // The first-token bootstrap gate, for `POST /api/tokens/bootstrap`.
    let app = app.layer(Extension(bootstrap));
    // The mesh join admitter (cluster mode), for the join handler.
    let app = app.layer(Extension(mesh_control));
    #[cfg(feature = "oidc")]
    let app = app.layer(Extension(oidc_state));
    // The resolved security posture, for the gateway / proxy / domain-verify /
    // upload paths to consult (the findings read it via `Extension`).
    let app = app.layer(Extension(posture));
    // The listener's connection scheme.
    let app = app.layer(Extension(served_over_tls));
    // The dynamic daemon-config runtime, for the API + request-path reads.
    // Convergence is notification-driven: an immediate reload at startup, then on
    // every `notify_reload()` (SIGHUP / changelog / local write), with a long
    // backstop tick for the Raft-follower path that isn't hooked to a notification.
    tokio::spawn({
        let daemon = daemon.clone();
        let deploy = daemon_init_deploy;
        async move {
            loop {
                if let Err(err) = daemon.reload(&deploy).await {
                    tracing::debug!(%err, "daemon-config reload failed; keeping current");
                }
                tokio::select! {
                    _ = daemon.reload.notified() => {}
                    _ = tokio::time::sleep(DAEMON_RELOAD_BACKSTOP) => {}
                }
            }
        }
    });
    // A handle for the console middleware (a live read of the daemon config),
    // captured before `daemon` is moved into the extension below.
    #[cfg(feature = "console")]
    let console_daemon = daemon.clone();
    let app = app.layer(Extension(daemon));
    // Embedded web console (feature `console`): a middleware that intercepts the
    // configured host+path before the site fallback. Always layered — the mount is
    // a live `DaemonConfig` value, so the console can be enabled/disabled at runtime
    // (a disabled console is a pass-through). See [`console::mount`].
    #[cfg(feature = "console")]
    let app = console::mount(app, console_daemon);
    app
        // Structured access log wraps every route (public + API).
        .layer(axum::middleware::from_fn(access_log))
}

/// The configured CORS allowlist, carried as middleware state for the API.
#[derive(Clone)]
struct CorsState(Arc<Vec<String>>);

/// Methods the control-plane API exposes; advertised in a preflight response.
const CORS_ALLOW_METHODS: &str = "GET, POST, PUT, DELETE, OPTIONS";
/// Request headers a browser client needs (Bearer auth + JSON bodies); the
/// fallback when a preflight doesn't list `Access-Control-Request-Headers`.
const CORS_ALLOW_HEADERS: &str = "authorization, content-type";
/// How long a browser may cache a preflight result (seconds).
const CORS_MAX_AGE: &str = "600";

/// Whether `origin` is permitted by the configured allowlist. `*` allows any
/// origin (the specific origin is still echoed back, with `Vary: Origin`);
/// otherwise the match is an exact `scheme://host[:port]` comparison.
fn cors_origin_allowed(allowed: &[String], origin: &str) -> bool {
    allowed.iter().any(|a| a == "*" || a == origin)
}

/// Opt-in CORS for the control-plane `/api/*` routes (see
/// [`ServerOptions::cors_allowed_origins`]). Answers a preflight `OPTIONS`
/// itself — before the auth layer, since a preflight carries no credentials —
/// and, for an allowed `Origin`, echoes `Access-Control-Allow-Origin` plus
/// `Vary: Origin` onto the response. A disallowed/absent origin gets no
/// `Access-Control-*` headers, so the browser blocks the cross-origin read.
async fn cors(
    State(allowed): State<CorsState>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .filter(|o| cors_origin_allowed(&allowed.0, o))
        .map(str::to_string);
    // A CORS preflight is an OPTIONS carrying `Access-Control-Request-Method`.
    let is_preflight = request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);
    if is_preflight {
        // Echo the browser's requested headers when present, else our known set.
        let allow_headers = request
            .headers()
            .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .unwrap_or_else(|| CORS_ALLOW_HEADERS.to_string());
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NO_CONTENT;
        if let Some(origin) = origin {
            let headers = response.headers_mut();
            set_header(headers, header::ACCESS_CONTROL_ALLOW_ORIGIN, &origin);
            set_header(headers, header::VARY, "Origin");
            set_header(
                headers,
                header::ACCESS_CONTROL_ALLOW_METHODS,
                CORS_ALLOW_METHODS,
            );
            set_header(
                headers,
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                &allow_headers,
            );
            set_header(headers, header::ACCESS_CONTROL_MAX_AGE, CORS_MAX_AGE);
        }
        return response;
    }
    let mut response = next.run(request).await;
    if let Some(origin) = origin {
        let headers = response.headers_mut();
        set_header(headers, header::ACCESS_CONTROL_ALLOW_ORIGIN, &origin);
        // `Vary: Origin` so a shared cache can't serve one origin's CORS
        // response to another; appended so any existing `Vary` is preserved.
        if let Ok(value) = HeaderValue::from_str("Origin") {
            headers.append(header::VARY, value);
        }
    }
    response
}

/// How long the shutdown drain may run before the listener is forced closed.
/// Generous enough for any in-flight handler invocation to finish (each is
/// itself bounded by the engine's epoch timeout); it only caps stuck or
/// abusive connections so a SIGTERM can't hang forever.
const DRAIN_DEADLINE: Duration = Duration::from_secs(30);

/// A failure starting or running the HTTP server.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// Binding the listener, or an axum serve I/O error.
    #[error("server I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Bind `addr` and serve until a shutdown signal (Ctrl-C / SIGTERM), then drain
/// in-flight requests under [`DRAIN_DEADLINE`]. Default [`ServerOptions`].
pub async fn serve(
    addr: SocketAddr,
    deploy: DeployStore,
    auth: Auth,
    handlers: HandlerRuntime,
) -> Result<(), ServeError> {
    serve_with(addr, deploy, auth, handlers, ServerOptions::default()).await
}

/// [`serve`] with explicit [`ServerOptions`] (e.g. operational request limits).
pub async fn serve_with(
    addr: SocketAddr,
    deploy: DeployStore,
    auth: Auth,
    handlers: HandlerRuntime,
    options: ServerOptions,
) -> Result<(), ServeError> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, auth = !auth.is_disabled(), "boatramp server listening");
    // Background scheduler: drives consumers/crons for active deployments
    // (no-op without the handlers feature/runtime). Aborted after the drain.
    #[cfg(feature = "handlers")]
    let scheduler = handlers.spawn_scheduler(deploy.clone());
    // Background gateway active-health prober: probes the
    // backends of upstreams with `active_health` so a dead one leaves rotation
    // before client traffic. Idle until a request arms an upstream.
    let gateway_prober = gateway::spawn_active_health_prober();
    // Connect-info make-service so handlers can see the peer address (for IP
    // rules / rate limiting / access logs).
    let app = router_with(deploy, auth, handlers, options)
        .into_make_service_with_connect_info::<SocketAddr>();

    // The graceful drain begins when the OS signal fires; `signalled` flips at
    // that instant so the drain deadline is measured from the signal, not from
    // server start.
    let (signalled_tx, signalled_rx) = tokio::sync::watch::channel(false);
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        shutdown_signal().await;
        let _ = signalled_tx.send(true);
    });
    let signalled = {
        let mut rx = signalled_rx;
        async move {
            let _ = rx.wait_for(|fired| *fired).await;
        }
    };
    let result = serve_with_drain_deadline(
        async move { server.await.map_err(ServeError::from) },
        signalled,
        DRAIN_DEADLINE,
    )
    .await;
    // Stop the scheduler once the server has drained.
    #[cfg(feature = "handlers")]
    if let Some(handle) = scheduler {
        handle.abort();
    }
    gateway_prober.abort();
    result
}

/// Run the graceful-serve future `server`, but if the drain runs longer than
/// `deadline` *after* `signalled` resolves, stop waiting and return (dropping
/// `server`, which closes any still-open connections). Pulled out of [`serve`]
/// so the deadline behaviour is unit-testable without sockets or real signals.
async fn serve_with_drain_deadline<Srv, Sig>(
    server: Srv,
    signalled: Sig,
    deadline: Duration,
) -> Result<(), ServeError>
where
    Srv: Future<Output = Result<(), ServeError>>,
    Sig: Future<Output = ()>,
{
    tokio::pin!(server);
    let drain_cap = async move {
        signalled.await;
        tokio::time::sleep(deadline).await;
    };
    tokio::select! {
        result = &mut server => result,
        _ = drain_cap => {
            tracing::warn!(
                deadline_s = deadline.as_secs(),
                "drain deadline exceeded; forcing shutdown with requests still in flight"
            );
            Ok(())
        }
    }
}

/// Resolve when the process receives Ctrl-C or SIGTERM, so in-flight requests
/// can drain before exit.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received; draining");
}

/// Liveness probe. Also reports the active daemon-config **generation** hash so an
/// operator can confirm every node in a cluster converged to the same config
/// (`ok` alone = running on the pure file baseline).
async fn healthz(Extension(daemon): Extension<Arc<DaemonRuntime>>) -> String {
    match daemon.generation() {
        Some(gen) => format!("ok gen={gen}"),
        None => "ok".to_string(),
    }
}

/// Readiness probe: `200 ready` when the metadata backend answers, else `503`.
async fn readyz(State(deploy): State<DeployStore>) -> Response {
    match deploy.ready().await {
        Ok(()) => (StatusCode::OK, "ready\n").into_response(),
        Err(err) => {
            tracing::warn!(error = %err, "readiness probe failed");
            (StatusCode::SERVICE_UNAVAILABLE, "not ready\n").into_response()
        }
    }
}

/// One access-log line, emitted when the response body finishes streaming, so
/// `bytes` (response size) and `elapsed_ms` (time-to-last-byte) are accurate for
/// fixed-size *and* streamed/proxied responses.
struct AccessLog {
    method: Method,
    path: String,
    host: String,
    client: String,
    status: u16,
    /// Response `Content-Encoding` (`br`/`gzip`/`identity`).
    encoding: String,
    start: std::time::Instant,
    bytes: std::sync::atomic::AtomicU64,
}

impl Drop for AccessLog {
    fn drop(&mut self) {
        let bytes = self.bytes.load(std::sync::atomic::Ordering::Relaxed);
        // Aggregate into the process-wide Prometheus counters (status class +
        // cache result + bytes) before emitting the per-request line.
        srvmetrics::server_metrics().record_request(self.status, bytes);
        tracing::info!(
            target: "boatramp::access",
            method = %self.method,
            path = %self.path,
            host = %self.host,
            client = %self.client,
            status = self.status,
            bytes = bytes,
            encoding = %self.encoding,
            cache_result = srvmetrics::cache_result(self.status),
            elapsed_ms = self.start.elapsed().as_millis() as u64,
            "request"
        );
    }
}

/// Structured access-log middleware: method, path, host, client IP, status,
/// response bytes, and duration. The line is emitted once the body has fully
/// streamed (or the connection drops), counting bytes as they pass through.
async fn access_log(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let client = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| "-".to_string());

    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let encoding = response
        .headers()
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("identity")
        .to_string();
    let log = AccessLog {
        method,
        path,
        host,
        client,
        status: response.status().as_u16(),
        encoding,
        start,
        bytes: std::sync::atomic::AtomicU64::new(0),
    };

    // Wrap the body so bytes are tallied as they stream; `log` is owned by the
    // stream closure, so its Drop emits the line when the body finishes (or the
    // client disconnects).
    let (parts, body) = response.into_parts();
    let counted = body.into_data_stream().map(move |chunk| {
        if let Ok(bytes) = &chunk {
            log.bytes
                .fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }
        chunk
    });
    Response::from_parts(parts, Body::from_stream(counted))
}

#[derive(Serialize)]
struct CreateDeploymentResponse {
    id: String,
    missing: Vec<String>,
}

/// Optional deploy provenance, supplied as query params on the create call
/// (e.g. `?source=<sha>&branch=main&message=...`). Kept out of the manifest
/// body so it never affects the content-addressed deployment id.
#[derive(Debug, Default, Deserialize)]
struct DeployMetaQuery {
    source: Option<String>,
    branch: Option<String>,
    author: Option<String>,
    message: Option<String>,
}

impl From<DeployMetaQuery> for DeployMetaInput {
    fn from(q: DeployMetaQuery) -> Self {
        Self {
            source: q.source,
            branch: q.branch,
            author: q.author,
            message: q.message,
        }
    }
}

/// Register a manifest; respond with its deployment id and the blob hashes the
/// client still needs to upload.
async fn create_deployment(
    State(deploy): State<DeployStore>,
    Path(_site): Path<String>,
    Query(meta): Query<DeployMetaQuery>,
    Json(manifest): Json<Manifest>,
) -> Response {
    let result = async {
        let id = deploy.put_manifest_with(&manifest, meta.into()).await?;
        let missing = deploy.missing_blobs(&manifest).await?;
        Ok::<_, DeployError>((id, missing))
    }
    .await;

    match result {
        Ok((id, missing)) => {
            srvmetrics::server_metrics().record_deployment();
            (
                StatusCode::OK,
                Json(CreateDeploymentResponse { id, missing }),
            )
                .into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Stream a blob into storage, verifying it hashes to `hash`.
async fn put_blob(
    State(deploy): State<DeployStore>,
    Extension(guard): Extension<Arc<UploadGuard>>,
    Path(hash): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // Cheap up-front reject on a declared length over the cap (avoids opening a
    // stream we'd only abort). The streaming guard below is the real backstop.
    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if guard.content_length_rejected(content_length) {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "blob exceeds the upload limit\n",
        )
            .into_response();
    }
    // Admit under the concurrency cap; the permit is held until the upload ends.
    let Some(_permit) = guard.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many concurrent uploads; retry shortly\n",
        )
            .into_response();
    };

    let stream = body
        .into_data_stream()
        .map(|chunk| chunk.map_err(|err| StorageError::backend(err.to_string())))
        .boxed();
    // Wrap so an over-size or stalled upload is aborted mid-stream (streaming
    // preserved — nothing is buffered to measure it).
    let stream = guard.limit_body(stream);

    match deploy.put_blob(&hash, stream).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

async fn activate_deployment(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path((site, id)): Path<(String, String)>,
) -> Response {
    // Activation compile-gate: a deploy whose handlers the
    // site can't satisfy, or whose components don't compile, must not flip.
    match deploy.get_manifest(&id).await {
        Ok(Some(manifest)) => {
            let site_config = match deploy.get_site_config(&site).await {
                Ok(config) => config,
                Err(err) => return deploy_error_response(err),
            };
            if let Err(reason) = handlers
                .precheck_activation(&deploy, &manifest, site_config.as_ref())
                .await
            {
                tracing::warn!(site, id, reason, "activation refused by handler pre-check");
                return (StatusCode::UNPROCESSABLE_ENTITY, format!("{reason}\n")).into_response();
            }
        }
        // A missing manifest falls through; `activate` returns the NotFound error.
        Ok(None) => {}
        Err(err) => return deploy_error_response(err),
    }
    match deploy.activate(&site, &id).await {
        Ok(()) => {
            srvmetrics::server_metrics().record_activation();
            StatusCode::NO_CONTENT.into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

#[derive(Serialize)]
struct CurrentResponse {
    site: String,
    deployment: Option<String>,
}

async fn current_deployment(
    State(deploy): State<DeployStore>,
    Path(site): Path<String>,
) -> Response {
    match deploy.current_id(&site).await {
        Ok(deployment) => Json(CurrentResponse { site, deployment }).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// List a site's deployment history (most recent first), with the current id.
async fn list_deployments(State(deploy): State<DeployStore>, Path(site): Path<String>) -> Response {
    match deploy.deployments(&site).await {
        Ok(list) => Json(list).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Get a site's [`SiteConfig`] (defaults if unset).
/// `GET /api/sites` — every known site name (admin-scoped). Backs the web UI /
/// tooling site navigation.
async fn list_sites(State(deploy): State<DeployStore>) -> Response {
    match deploy.all_sites().await {
        Ok(sites) => Json(sites).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

async fn get_site_config(State(deploy): State<DeployStore>, Path(site): Path<String>) -> Response {
    match deploy.get_site_config(&site).await {
        Ok(config) => Json(config.unwrap_or_default()).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `DELETE /api/sites/:site` — remove a site + its routing/config/aliases/pending
/// verifications (the Kubernetes operator's `Site` finalizer). Admin-scoped
/// (deny-safe `Right::required` default). Content-addressed deploy blobs are
/// shared and left to `prune`. Idempotent.
async fn delete_site(State(deploy): State<DeployStore>, Path(site): Path<String>) -> Response {
    match deploy.delete_site(&site).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Canonicalize a site-config domain entry for the verify-gate diff: fold case
/// and any trailing dot, but keep an exact host distinct from a `*.` wildcard
/// (they are different routing entities that must not collapse together).
fn canon_domain_entry(host: &str) -> String {
    match host.strip_prefix("*.") {
        Some(base) => format!(
            "*.{}",
            base.trim().trim_end_matches('.').to_ascii_lowercase()
        ),
        None => host.trim().trim_end_matches('.').to_ascii_lowercase(),
    }
}

/// Set a site's [`SiteConfig`] (rebuilds its host → site index).
///
/// A domain only enters routing once its ownership is proven. A host **newly
/// added** through this raw config write (rather than the verify→attach flow)
/// must therefore already carry a verified challenge, or a site-writer could
/// squat an unowned host by simply listing it. Hosts already on the site — and
/// any non-domain edit — pass untouched, so the ordinary `access`/`gateway`
/// config edits (which read-modify-write the current config) are unaffected.
async fn put_site_config(
    State(deploy): State<DeployStore>,
    Path(site): Path<String>,
    Json(config): Json<SiteConfig>,
) -> Response {
    let current = match deploy.get_site_config(&site).await {
        Ok(c) => c.unwrap_or_default(),
        Err(err) => return deploy_error_response(err),
    };
    // Diff on the *canonical* host form (case/trailing-dot folded, wildcard `*.`
    // preserved) so it agrees with the normalizing verification lookup — else a
    // case-variant of an already-attached host reads as "newly added" and a
    // never-verified variant could be laundered in.
    let existing: std::collections::BTreeSet<String> = current
        .domains
        .exact_hosts()
        .map(canon_domain_entry)
        .chain(
            current
                .domains
                .wildcards
                .iter()
                .map(|w| canon_domain_entry(w)),
        )
        .collect();
    let added: Vec<String> = config
        .domains
        .exact_hosts()
        .map(canon_domain_entry)
        .chain(
            config
                .domains
                .wildcards
                .iter()
                .map(|w| canon_domain_entry(w)),
        )
        .filter(|host| !existing.contains(host))
        .collect();
    for host in added {
        let verification = match deploy.get_domain_verification(&site, &host).await {
            Ok(v) => v,
            Err(err) => return deploy_error_response(err),
        };
        if !verification.as_ref().is_some_and(|v| v.verified) {
            return (
                StatusCode::FORBIDDEN,
                format!(
                    "{host} is not verified for {site}; run \
                     `boatramp domain add {host} --site {site}` first\n"
                ),
            )
                .into_response();
        }
        // A wildcard needs DNS proof (parity with `attach_verified_domain`).
        if host.starts_with("*.")
            && verification.as_ref().map(|v| v.method)
                != Some(boatramp_core::domain_verify::VerificationMethod::Dns)
        {
            return (
                StatusCode::FORBIDDEN,
                format!("wildcard {host} must be verified via DNS (an HTTP token proves only the base host)\n"),
            )
                .into_response();
        }
    }
    match deploy.set_site_config(&site, &config).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// GET the active dynamic daemon config + its generation hash.
async fn get_daemon_config(
    State(deploy): State<DeployStore>,
    Extension(daemon): Extension<Arc<DaemonRuntime>>,
) -> Response {
    match deploy.get_daemon_config().await {
        Ok(cfg) => Json(serde_json::json!({
            "generation": daemon.generation(),
            "config": cfg.unwrap_or_default(),
        }))
        .into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// PUT a new dynamic daemon config: validate against the file baseline (ceilings +
/// tighten-only ratchet), store it, and hot-swap the local runtime. Other nodes
/// converge via Raft replication + their SIGHUP/changelog reload.
async fn put_daemon_config(
    State(deploy): State<DeployStore>,
    Extension(daemon): Extension<Arc<DaemonRuntime>>,
    Json(cfg): Json<boatramp_core::daemon_config::DaemonConfig>,
) -> Response {
    if let Err(err) = cfg.validate(daemon.baseline()) {
        return (
            StatusCode::BAD_REQUEST,
            format!("invalid daemon config: {err}\n"),
        )
            .into_response();
    }
    match deploy.set_daemon_config(&cfg).await {
        Ok(generation) => {
            if let Err(err) = daemon.reload(&deploy).await {
                return deploy_error_response(err);
            }
            Json(serde_json::json!({ "generation": generation })).into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Roll the dynamic daemon config back to the previous generation, and hot-swap.
async fn rollback_daemon_config(
    State(deploy): State<DeployStore>,
    Extension(daemon): Extension<Arc<DaemonRuntime>>,
) -> Response {
    match deploy.rollback_daemon_config().await {
        Ok(Some(generation)) => {
            if let Err(err) = daemon.reload(&deploy).await {
                return deploy_error_response(err);
            }
            Json(serde_json::json!({ "generation": generation })).into_response()
        }
        Ok(None) => (
            StatusCode::CONFLICT,
            "no prior daemon config to roll back to\n",
        )
            .into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// List all compute workloads.
async fn list_compute(State(deploy): State<DeployStore>) -> Response {
    match deploy.list_compute_workloads().await {
        Ok(mut workloads) => {
            workloads.sort_by(|a, b| a.name.cmp(&b.name));
            Json(workloads).into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Get one workload's desired state.
async fn get_compute(State(deploy): State<DeployStore>, Path(name): Path<String>) -> Response {
    match deploy.get_compute_workload(&name).await {
        Ok(Some(workload)) => Json(workload).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no such workload\n").into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Body of `PUT /api/compute/:name` — the spec plus desired replicas/placement.
#[derive(Deserialize)]
struct PutComputeRequest {
    /// The immutable workload spec (rootfs/kernel blob hashes + sizing).
    spec: boatramp_core::compute::ComputeSpec,
    /// Desired replica count (default 1).
    #[serde(default = "one")]
    replicas: u32,
    /// Placement constraints.
    #[serde(default)]
    placement: boatramp_core::compute::PlacementConstraints,
}

fn one() -> u32 {
    1
}

#[derive(Serialize)]
struct PutComputeResponse {
    /// The content hash of the stored spec (`computever/<hash>`).
    spec: String,
}

/// Create/update a workload: content-address its spec, then flip the desired
/// state (replicas/placement) — the atomic activation pointer.
async fn put_compute(
    State(deploy): State<DeployStore>,
    Extension(daemon): Extension<Arc<DaemonRuntime>>,
    Path(name): Path<String>,
    Json(mut request): Json<PutComputeRequest>,
) -> Response {
    // A workload that omits its kernel uses the node's fleet **default kernel**
    // (from dynamic daemon config). Substituted at set time; the kernel is
    // verified against the posture bar at boot. No kernel and no default ⇒ a clear
    // error rather than a cryptic backend failure.
    if request.spec.kernel.is_empty() {
        match daemon.effective().default_kernel.as_ref() {
            Some(k) => request.spec.kernel = k.source.clone(),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    "workload has no kernel and no default kernel is configured; set one \
                     with `boatramp config set compute.default_kernel …`\n",
                )
                    .into_response()
            }
        }
    }
    let spec_hash = match deploy.put_compute_spec(&request.spec).await {
        Ok(hash) => hash,
        Err(err) => return deploy_error_response(err),
    };
    let workload = boatramp_core::compute::ComputeWorkload {
        version: boatramp_core::SCHEMA_VERSION,
        name,
        active: spec_hash.clone(),
        replicas: request.replicas,
        placement: request.placement,
    };
    match deploy.set_compute_workload(&workload).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(PutComputeResponse { spec: spec_hash }),
        )
            .into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Delete a workload (the scheduler then stops its replicas).
async fn delete_compute(State(deploy): State<DeployStore>, Path(name): Path<String>) -> Response {
    match deploy.delete_compute_workload(&name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such workload\n").into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Response for the OIDC→token exchange.
#[cfg(feature = "oidc")]
#[derive(Serialize)]
struct ExchangeResponse {
    /// The minted token (base64url COSE_Sign1 CWT).
    token: String,
    /// Its TTL in seconds.
    expires_in: u64,
}

/// Exchange a validated OIDC JWT (presented as the `Authorization: Bearer`) for
/// a short-TTL token whose roles come from the configured claim.
/// Needs both the OIDC verifier and the issuing key; otherwise `501`.
#[cfg(feature = "oidc")]
async fn auth_exchange(
    Extension(issuer): Extension<Issuer>,
    Extension(oidc): Extension<OidcState>,
    headers: HeaderMap,
) -> Response {
    let (Some(signer), Some(verifier)) = (issuer.0, oidc.0) else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "OIDC exchange is not configured on this node\n",
        )
            .into_response();
    };
    let Some(jwt) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return (StatusCode::UNAUTHORIZED, "missing bearer JWT\n").into_response();
    };
    // The configured claim's values are role specs (`"<role>[:<site>]"`).
    let Some(claims) = verifier.verify(jwt) else {
        return (StatusCode::UNAUTHORIZED, "invalid OIDC token\n").into_response();
    };
    let roles: Vec<GrantedRole> = claims.iter().map(|s| GrantedRole::parse(s)).collect();
    if roles.is_empty() {
        return (
            StatusCode::FORBIDDEN,
            "OIDC token carries no boatramp roles\n",
        )
            .into_response();
    }
    let claims = Claims {
        roles,
        kind: cose::KIND_ROLE.to_string(),
        ttl_secs: Some(EXCHANGE_TTL_SECS),
        now_unix: now_unix(),
    };
    match cose::mint(&claims, &*signer).await {
        Ok(token) => Json(ExchangeResponse {
            token,
            expires_in: EXCHANGE_TTL_SECS,
        })
        .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

/// Return the manifest for a specific deployment id.
async fn get_deployment(
    State(deploy): State<DeployStore>,
    Path((_site, id)): Path<(String, String)>,
) -> Response {
    match deploy.get_manifest(&id).await {
        Ok(Some(manifest)) => Json(manifest).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "deployment not found\n").into_response(),
        Err(err) => deploy_error_response(err),
    }
}

#[derive(Deserialize)]
struct SetAliasRequest {
    /// Deployment id (full content hash) to point the alias at.
    id: String,
}

/// Point a named alias at a deployment id.
async fn set_alias(
    State(deploy): State<DeployStore>,
    Path((site, name)): Path<(String, String)>,
    Json(request): Json<SetAliasRequest>,
) -> Response {
    match deploy.set_alias(&site, &name, &request.id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// List a site's named aliases (`name → deployment id`).
async fn list_aliases(State(deploy): State<DeployStore>, Path(site): Path<String>) -> Response {
    match deploy.list_aliases(&site).await {
        Ok(map) => Json(map).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Remove a named alias.
async fn remove_alias(
    State(deploy): State<DeployStore>,
    Path((site, name)): Path<(String, String)>,
) -> Response {
    match deploy.remove_alias(&site, &name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such alias\n").into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Garbage-collection tuning, from query params: `?grace=<secs>` safety window
/// (default 3600), `?keep_last=<n>` and `?keep_age=<secs>` retention.
#[derive(Debug, Default, Deserialize)]
struct PruneQuery {
    grace: Option<u64>,
    keep_last: Option<usize>,
    keep_age: Option<u64>,
}

impl PruneQuery {
    fn options(&self) -> GcOptions {
        GcOptions {
            // Default to a 1h grace window so a routine prune never races an
            // in-flight deploy. Callers can override (e.g. `?grace=0`).
            grace_secs: self.grace.unwrap_or(3600),
            keep_last: self.keep_last,
            keep_age_secs: self.keep_age,
        }
    }
}

/// Report reclaimable garbage without deleting anything (safe, read-only).
async fn prune_report(State(deploy): State<DeployStore>, Query(q): Query<PruneQuery>) -> Response {
    prune_response(deploy.collect_garbage_with(false, q.options()).await)
}

/// Delete orphan manifests and unreferenced blobs.
async fn prune_delete(State(deploy): State<DeployStore>, Query(q): Query<PruneQuery>) -> Response {
    prune_response(deploy.collect_garbage_with(true, q.options()).await)
}

fn prune_response(result: Result<GcReport, DeployError>) -> Response {
    match result {
        Ok(report) => Json(report).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Verify every stored blob still hashes to its key (integrity scrub).
/// Read-only; the JSON report lists any corrupted or unreadable blobs.
async fn scrub_blobs(State(deploy): State<DeployStore>) -> Response {
    match deploy.scrub_blobs().await {
        Ok(report) => Json(report).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Cluster-managed cert status (domain + expiry; never key material).
async fn cert_status(State(deploy): State<DeployStore>) -> Response {
    match deploy.cert_status().await {
        Ok(status) => Json(status).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Push cache-invalidation (shared-mode coherence):
/// a Cloudflare DO / Queue (or any pusher) POSTs the keys a peer changed for
/// real-time invalidation without waiting on the poll. Empty `keys` flushes the
/// whole cache (the coarse fallback). Admin-scoped (under `/api`, "*" required).
async fn invalidate_cache(
    State(deploy): State<DeployStore>,
    Json(body): Json<InvalidateRequest>,
) -> Response {
    if body.keys.is_empty() {
        deploy.invalidate_cache();
    } else {
        deploy.invalidate_cache_keys(&body.keys);
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
struct InvalidateRequest {
    #[serde(default)]
    keys: Vec<String>,
}

/// Whether the request's `If-None-Match` matches `etag` (or `*`).
fn if_none_match(req_headers: &HeaderMap, etag: &str) -> bool {
    req_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|tag| tag == "*" || tag == etag || tag.trim_start_matches("W/") == etag)
        })
}

fn set_header(headers: &mut HeaderMap, name: header::HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

fn redirect(status: u16, location: &str) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::FOUND);
    match HeaderValue::from_str(location) {
        Ok(location) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::LOCATION, location);
            (status, headers).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "bad redirect target\n").into_response(),
    }
}

/// Map a [`DeployError`] to an HTTP response.
fn deploy_error_response(err: DeployError) -> Response {
    let status = match &err {
        DeployError::NotFound(_) | DeployError::Storage(StorageError::NotFound(_)) => {
            StatusCode::NOT_FOUND
        }
        DeployError::HashMismatch { .. } => StatusCode::BAD_REQUEST,
        DeployError::Incomplete(_) => StatusCode::CONFLICT,
        // A host already claimed by another site — refuse the overwrite.
        DeployError::Conflict(_) => StatusCode::CONFLICT,
        // An ambiguous preview-id prefix is not a usable capability → not found.
        DeployError::Ambiguous(_) => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    tracing::warn!(error = %err, "request failed");
    (status, format!("{err}\n")).into_response()
}

#[cfg(test)]
mod drain_tests {
    use super::*;

    #[tokio::test]
    async fn deadline_forces_shutdown_after_signal() {
        // Server never finishes draining; once the signal has fired the
        // deadline must end the wait (Ok — we forced shutdown deliberately).
        let server = std::future::pending::<Result<(), ServeError>>();
        let signalled = async {}; // signal already fired
        let result = serve_with_drain_deadline(server, signalled, Duration::from_millis(20)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn server_finishing_first_wins() {
        // If the server drains before the deadline, its result is returned and
        // the deadline never trips (signal never even fires here).
        let server = async { Ok(()) };
        let signalled = std::future::pending::<()>();
        let result = serve_with_drain_deadline(server, signalled, Duration::from_secs(30)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn deadline_does_not_trip_before_signal() {
        // The deadline is measured from the signal: with no signal it never
        // trips, even past its length. The server completes (here with an
        // error) and that result propagates.
        let server = async {
            tokio::time::sleep(Duration::from_millis(40)).await;
            Err(ServeError::Io(std::io::Error::other("server error")))
        };
        let signalled = std::future::pending::<()>();
        let result = serve_with_drain_deadline(server, signalled, Duration::from_millis(10)).await;
        assert!(result.is_err());
    }
}

#[cfg(all(test, feature = "handlers"))]
mod tests {
    use super::*;
    use boatramp_core::cose::{LocalSigner, TokenAlg};

    #[test]
    fn query_string_parses_and_url_decodes() {
        let q = parse_query_string("lang=fr&city=S%C3%A3o+Paulo&flag&dup=1&dup=2");
        assert_eq!(q.get("lang").map(String::as_str), Some("fr"));
        assert_eq!(q.get("city").map(String::as_str), Some("São Paulo")); // %C3%A3 + '+'
        assert_eq!(q.get("flag").map(String::as_str), Some("")); // bare key
        assert_eq!(q.get("dup").map(String::as_str), Some("1")); // first value wins
    }

    #[test]
    fn cookie_header_parses_pairs() {
        let c = parse_cookie_header("beta=1; sid = abc ; empty=");
        assert_eq!(c.get("beta").map(String::as_str), Some("1"));
        assert_eq!(c.get("sid").map(String::as_str), Some("abc"));
        assert_eq!(c.get("empty").map(String::as_str), Some(""));
    }

    #[test]
    fn apply_vary_merges_without_duplicates() {
        let base = (StatusCode::OK, "x").into_response();
        let r = apply_vary(base, &["accept-language".into()]);
        assert_eq!(r.headers().get(header::VARY).unwrap(), "accept-language");
        // Merges into an existing Vary, de-duplicating case-insensitively.
        let r = apply_vary(r, &["cookie".into(), "accept-language".into()]);
        let v = r.headers().get(header::VARY).unwrap().to_str().unwrap();
        assert!(v.contains("accept-language") && v.contains("cookie"));
        assert_eq!(v.matches("accept-language").count(), 1);
        // Empty vary is a no-op.
        let plain = apply_vary((StatusCode::OK, "y").into_response(), &[]);
        assert!(plain.headers().get(header::VARY).is_none());
    }

    /// The `/api/cluster/join-token` handler mints a verifiable **bearer** token,
    /// and refuses cleanly on a verify-only node (no root key) → 501. Admin-gating
    /// is the deny-safe `Right::required` default for `/api/cluster/*`.
    #[tokio::test]
    async fn join_token_endpoint_mints_a_verifiable_bearer_token() {
        let keys: Arc<dyn Signer> = Arc::new(LocalSigner::generate(TokenAlg::Es256));
        let public = keys.public_key();

        // Happy path: the returned token verifies + yields a single-use jti.
        let resp = create_join_token(
            Extension(Issuer(Some(keys.clone()))),
            Json(CreateJoinTokenRequest {
                ttl_secs: Some(600),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = parsed["token"].as_str().unwrap();
        let jti = cose::verify_join(token, &public, now_unix()).unwrap();
        assert!(!jti.is_empty());

        // A verify-only node (no issuing key) cannot mint → 501.
        let no_issuer = create_join_token(
            Extension(Issuer(None)),
            Json(CreateJoinTokenRequest { ttl_secs: None }),
        )
        .await;
        assert_eq!(no_issuer.status(), StatusCode::NOT_IMPLEMENTED);
    }

    /// FA-2: the top-level function **write** path driven through the HTTP handlers —
    /// deploy two versions, roll back, alias, remove — plus the two 400/absent-blob
    /// guards. The store-layer semantics are the `boatramp-core` oracle; this pins the
    /// handler wrapper (status codes, blob gate, JSON echo).
    #[tokio::test]
    async fn function_write_path_deploy_rollback_alias_remove() {
        use boatramp_core::function::Lifecycle;
        use boatramp_core::kv::MemoryKv;
        use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};

        // A storage whose `head` (hence `has_blob`) is toggleable — enough to drive
        // both the blob-present deploy path and the absent-blob 400.
        struct FakeStorage {
            present: bool,
        }
        #[async_trait::async_trait]
        impl Storage for FakeStorage {
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
                Err(StorageError::unsupported("fake"))
            }
            async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
                if self.present {
                    Ok(ObjectMeta {
                        key: key.to_string(),
                        ..Default::default()
                    })
                } else {
                    Err(StorageError::NotFound(key.to_string()))
                }
            }
            async fn delete(&self, _: &str) -> Result<(), StorageError> {
                Ok(())
            }
            async fn list(&self, _: &str) -> Result<Vec<ObjectMeta>, StorageError> {
                Ok(Vec::new())
            }
        }

        async fn body_json(resp: Response) -> (StatusCode, serde_json::Value) {
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let value = if bytes.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            (status, value)
        }

        let deploy = DeployStore::new(
            Arc::new(FakeStorage { present: true }),
            Arc::new(MemoryKv::new()),
        );
        let v1 = "a".repeat(64);
        let v2 = "b".repeat(64);

        // Deploy v1 → created, active = v1.
        let (st, body) = body_json(
            deploy_function(
                State(deploy.clone()),
                Path("greeter".to_string()),
                Json(FunctionUpsert {
                    component: v1.clone(),
                    config: Default::default(),
                    lifecycle: Lifecycle::Independent,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["active"], v1);

        // Deploy v2 → active advances, two versions retained.
        let (_, body) = body_json(
            deploy_function(
                State(deploy.clone()),
                Path("greeter".to_string()),
                Json(FunctionUpsert {
                    component: v2.clone(),
                    config: Default::default(),
                    lifecycle: Lifecycle::Independent,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(body["active"], v2);
        assert_eq!(body["versions"].as_array().unwrap().len(), 2);

        // Roll back to v1.
        let (st, body) = body_json(
            rollback_function(
                State(deploy.clone()),
                Path("greeter".to_string()),
                Json(RollbackBody { to: v1.clone() }),
            )
            .await,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["active"], v1);

        // Rolling back to an unknown version is a 400 (plain-text body).
        let resp = rollback_function(
            State(deploy.clone()),
            Path("greeter".to_string()),
            Json(RollbackBody { to: "c".repeat(64) }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Alias prod → v2.
        let (st, body) = body_json(
            alias_function(
                State(deploy.clone()),
                Path(("greeter".to_string(), "prod".to_string())),
                Json(AliasBody {
                    version: v2.clone(),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["aliases"]["prod"], v2);

        // Remove → 204, and it's gone.
        let (st, _) =
            body_json(remove_function(State(deploy.clone()), Path("greeter".to_string())).await)
                .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        assert!(deploy.get_function("greeter").await.unwrap().is_none());

        // Deploying a component whose blob was never uploaded is a 400.
        let empty = DeployStore::new(
            Arc::new(FakeStorage { present: false }),
            Arc::new(MemoryKv::new()),
        );
        let resp = deploy_function(
            State(empty),
            Path("orphan".to_string()),
            Json(FunctionUpsert {
                component: v1.clone(),
                config: Default::default(),
                lifecycle: Lifecycle::default(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// A configurable stub: records the `(mesh_pubkey, jti)` it's asked to admit and
    /// returns a chosen [`JoinOutcome`] (the real possession-proof + member signing
    /// lives in the cluster impl; here we test the handler's dispatch + status map).
    struct StubControl {
        admits: std::sync::Mutex<Vec<(String, String)>>,
        respond: StubJoin,
    }
    #[derive(Clone, Copy)]
    enum StubJoin {
        Admit,
        Spent,
        Invalid,
        Revoked,
    }

    #[async_trait::async_trait]
    impl MeshControl for StubControl {
        async fn admit(
            &self,
            mesh_pubkey_hex: &str,
            jti: &str,
            _proof: &[u8],
            _proof_iat: u64,
            _now: u64,
            _advertise_addr: Option<&str>,
        ) -> Result<JoinOutcome, String> {
            self.admits
                .lock()
                .unwrap()
                .push((mesh_pubkey_hex.to_string(), jti.to_string()));
            Ok(match self.respond {
                StubJoin::Admit => JoinOutcome::Admitted {
                    members: vec!["signed-member".to_string()],
                    addrs: std::collections::BTreeMap::from([(7u64, "https://x:7000".to_string())]),
                },
                StubJoin::Spent => JoinOutcome::TokenSpent,
                StubJoin::Invalid => JoinOutcome::ProofInvalid,
                StubJoin::Revoked => JoinOutcome::Revoked,
            })
        }
        async fn rotate_key(&self) -> Result<String, String> {
            Ok("cafe".to_string())
        }
        async fn revoke(&self, _node: u64) -> Result<(), String> {
            Ok(())
        }
        async fn members(&self) -> Result<Vec<MeshMember>, String> {
            Ok(Vec::new())
        }
        async fn promote(&self, _node: u64) -> Result<(), String> {
            Ok(())
        }
    }

    /// `POST /api/cluster/join`: a valid bearer token dispatches to the admitter and
    /// maps its outcome (admitted→200+members, spent→409, proof-invalid→403); a bad
    /// token → 401, a non-hex proof → 400, and no cluster hook → 501.
    #[tokio::test]
    async fn cluster_join_dispatches_and_maps_outcomes() {
        let keys: Arc<dyn Signer> = Arc::new(LocalSigner::generate(TokenAlg::Es256));
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let auth = Auth::with_key(keys.public_key(), kv);
        let token = cose::mint_join(600, now_unix(), &*keys).await.unwrap();
        let req = |proof: &str| JoinRequest {
            token: token.clone(),
            mesh_pubkey: "302a300506032b6570032100feed".into(),
            possession_proof: proof.to_string(),
            proof_iat: now_unix(),
            advertise_addr: Some("https://joiner:7000".into()),
        };

        // Admitted → 200 + the signed members, and the admitter saw the jti.
        let admitter = Arc::new(StubControl {
            admits: std::sync::Mutex::new(Vec::new()),
            respond: StubJoin::Admit,
        });
        let resp = cluster_join(
            Extension(auth.clone()),
            Extension(MeshControlHandle(Some(admitter.clone()))),
            Json(req("aa01")),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(admitter.admits.lock().unwrap().len(), 1);

        // Spent token → 409; proof-invalid → 403 (the impl's verdicts, mapped).
        let spent = Arc::new(StubControl {
            admits: std::sync::Mutex::new(Vec::new()),
            respond: StubJoin::Spent,
        });
        assert_eq!(
            cluster_join(
                Extension(auth.clone()),
                Extension(MeshControlHandle(Some(spent))),
                Json(req("aa01")),
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let invalid = Arc::new(StubControl {
            admits: std::sync::Mutex::new(Vec::new()),
            respond: StubJoin::Invalid,
        });
        assert_eq!(
            cluster_join(
                Extension(auth.clone()),
                Extension(MeshControlHandle(Some(invalid))),
                Json(req("aa01")),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        // A revoked key → 403 (a tombstone bars re-admission until un-revoked).
        let revoked = Arc::new(StubControl {
            admits: std::sync::Mutex::new(Vec::new()),
            respond: StubJoin::Revoked,
        });
        assert_eq!(
            cluster_join(
                Extension(auth.clone()),
                Extension(MeshControlHandle(Some(revoked))),
                Json(req("aa01")),
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );

        // A non-hex possession proof → 400 (before dispatch).
        let ok = Arc::new(StubControl {
            admits: std::sync::Mutex::new(Vec::new()),
            respond: StubJoin::Admit,
        });
        assert_eq!(
            cluster_join(
                Extension(auth.clone()),
                Extension(MeshControlHandle(Some(ok))),
                Json(req("not-hex")),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );

        // No cluster hook → 501.
        let none = cluster_join(
            Extension(auth),
            Extension(MeshControlHandle(None)),
            Json(req("aa01")),
        )
        .await;
        assert_eq!(none.status(), StatusCode::NOT_IMPLEMENTED);
    }

    /// `POST /api/tokens/bootstrap`: the right single-use secret mints a verifiable,
    /// recorded first token exactly once; a wrong secret is `401`, a reused one
    /// `409`, and a node without a bootstrap secret configured is `501`.
    #[tokio::test]
    async fn bootstrap_mints_the_first_token_once() {
        use axum::http::{header::AUTHORIZATION, HeaderMap, HeaderValue};
        let keys: Arc<dyn Signer> = Arc::new(LocalSigner::generate(TokenAlg::Es256));
        let public = keys.public_key();
        let deploy = DeployStore::new(
            Arc::new(MemStorage::default()),
            Arc::new(MemoryKv::new()) as Arc<dyn KvStore>,
        );
        let secret = "s3cr3t-bootstrap-value";
        let gate = BootstrapGate::new(Some(secret));
        let issuer = Issuer(Some(keys.clone()));
        let bearer = |s: &str| {
            let mut h = HeaderMap::new();
            h.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {s}")).unwrap(),
            );
            h
        };
        let req = || BootstrapRequest {
            roles: vec!["admin".to_string()],
            ttl_secs: None,
        };

        // Wrong secret → 401.
        let bad = bootstrap_token(
            State(deploy.clone()),
            Extension(issuer.clone()),
            Extension(gate.clone()),
            bearer("wrong"),
            Json(req()),
        )
        .await;
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);

        // Correct secret → 201, a token the root key verifies as admin, recorded.
        let ok = bootstrap_token(
            State(deploy.clone()),
            Extension(issuer.clone()),
            Extension(gate.clone()),
            bearer(secret),
            Json(req()),
        )
        .await;
        assert_eq!(ok.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(ok.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = json["token"].as_str().unwrap();
        let id = json["id"].as_str().unwrap();
        let verified = cose::verify(token, &public, now_unix()).unwrap();
        assert!(verified.roles.iter().any(|r| r.name == "admin"));
        assert!(deploy
            .list_token_meta()
            .await
            .unwrap()
            .iter()
            .any(|m| m.revocation_id == id));

        // Reuse of the same secret → 409 (single-use).
        let reuse = bootstrap_token(
            State(deploy.clone()),
            Extension(issuer.clone()),
            Extension(gate),
            bearer(secret),
            Json(req()),
        )
        .await;
        assert_eq!(reuse.status(), StatusCode::CONFLICT);

        // No bootstrap secret configured → 501.
        let disabled = bootstrap_token(
            State(deploy),
            Extension(issuer),
            Extension(BootstrapGate(None)),
            bearer(secret),
            Json(req()),
        )
        .await;
        assert_eq!(disabled.status(), StatusCode::NOT_IMPLEMENTED);
    }

    /// `POST /api/cluster/rotate-key` rotates via the control hook and returns the
    /// new pubkey; `501` on a non-cluster node.
    #[tokio::test]
    async fn cluster_rotate_key_returns_the_new_pubkey_or_501() {
        let control = Arc::new(StubControl {
            admits: std::sync::Mutex::new(Vec::new()),
            respond: StubJoin::Admit,
        });
        let resp = cluster_rotate_key(Extension(MeshControlHandle(Some(control)))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["pubkey"].as_str(), Some("cafe"));

        let none = cluster_rotate_key(Extension(MeshControlHandle(None))).await;
        assert_eq!(none.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn gateway_addr_gate_refuses_metadata_and_private_per_posture() {
        use boatramp_core::security::SecurityProfile;
        let strict = SecurityProfile::MultiTenant.preset();
        let loose = SecurityProfile::SingleTenant.preset(); // allows private upstreams

        let public: IpAddr = "93.184.216.34".parse().unwrap(); // example.com
        let private: IpAddr = "10.1.2.3".parse().unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let metadata: IpAddr = IpAddr::V4(CLOUD_METADATA_IPV4);

        // Strict (multi-tenant): only globally-routable addresses are allowed.
        assert!(gateway_addr_allowed(public, &strict));
        assert!(!gateway_addr_allowed(private, &strict));
        assert!(!gateway_addr_allowed(loopback, &strict));
        assert!(!gateway_addr_allowed(metadata, &strict));

        // Operator opt-in: private/loopback allowed, but cloud-metadata is still
        // refused (defense in depth — it is never a legitimate target).
        assert!(gateway_addr_allowed(public, &loose));
        assert!(gateway_addr_allowed(private, &loose));
        assert!(gateway_addr_allowed(loopback, &loose));
        assert!(!gateway_addr_allowed(metadata, &loose));
    }

    #[test]
    fn resolve_env_merges_static_and_host_secrets() {
        use boatramp_core::config::HandlersSiteConfig;

        // A uniquely-named host var holds the real secret value.
        std::env::set_var("BOATRAMP_TEST_RESOLVE_SECRET", "topsecret");

        let deploy_env = std::collections::BTreeMap::from([
            ("GREETING".to_string(), "hi".to_string()),
            ("OVERRIDE_ME".to_string(), "static".to_string()),
        ]);
        let site_handlers = HandlersSiteConfig {
            enabled: true,
            secrets: std::collections::BTreeMap::from([
                // guest var <- host env var holding the value
                (
                    "SECRET_TOKEN".to_string(),
                    "BOATRAMP_TEST_RESOLVE_SECRET".to_string(),
                ),
                (
                    "OVERRIDE_ME".to_string(),
                    "BOATRAMP_TEST_RESOLVE_SECRET".to_string(),
                ),
                (
                    "MISSING".to_string(),
                    "BOATRAMP_TEST_NOT_SET_VAR".to_string(),
                ),
            ]),
            ..Default::default()
        };
        let env = resolve_env("blog", &deploy_env, &site_handlers);

        // Static var present; secret resolved from the host env; a secret
        // overrides a static of the same name; a secret whose host var is unset
        // is skipped (never injected as empty).
        assert!(env.contains(&("GREETING".to_string(), "hi".to_string())));
        assert!(env.contains(&("SECRET_TOKEN".to_string(), "topsecret".to_string())));
        assert!(env.contains(&("OVERRIDE_ME".to_string(), "topsecret".to_string())));
        assert!(!env.iter().any(|(k, _)| k == "MISSING"));

        std::env::remove_var("BOATRAMP_TEST_RESOLVE_SECRET");
    }

    fn req() -> Request {
        Request::builder()
            .uri("/")
            .header(header::HOST, "example.com")
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn forwarded_headers_set_standard_triple() {
        let mut request = req();
        set_forwarded_headers(&mut request, "203.0.113.7".parse().unwrap());
        let h = request.headers();
        assert_eq!(h.get("x-forwarded-for").unwrap(), "203.0.113.7");
        assert_eq!(h.get("x-forwarded-host").unwrap(), "example.com");
        assert_eq!(h.get("x-forwarded-proto").unwrap(), "http");
    }

    #[test]
    fn forwarded_for_overwrites_spoofed_value() {
        // A client-supplied X-Forwarded-For must not survive: the host stamps
        // the single resolved address, not an attacker-controlled chain.
        let mut request = Request::builder()
            .uri("/")
            .header(header::HOST, "example.com")
            .header("x-forwarded-for", "10.0.0.1, 1.2.3.4")
            .body(Body::empty())
            .unwrap();
        set_forwarded_headers(&mut request, "203.0.113.7".parse().unwrap());
        let values: Vec<_> = request
            .headers()
            .get_all("x-forwarded-for")
            .iter()
            .collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "203.0.113.7");
    }

    #[test]
    fn forwarded_proto_preserves_upstream_tls() {
        // A TLS-terminating reverse proxy in front already set https; keep it.
        let mut request = Request::builder()
            .uri("/")
            .header(header::HOST, "example.com")
            .header("x-forwarded-proto", "https")
            .body(Body::empty())
            .unwrap();
        set_forwarded_headers(&mut request, "203.0.113.7".parse().unwrap());
        assert_eq!(request.headers().get("x-forwarded-proto").unwrap(), "https");
    }

    #[test]
    fn forwarded_host_absent_when_no_host_header() {
        let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
        set_forwarded_headers(&mut request, "203.0.113.7".parse().unwrap());
        assert!(request.headers().get("x-forwarded-host").is_none());
        assert_eq!(
            request.headers().get("x-forwarded-for").unwrap(),
            "203.0.113.7"
        );
    }

    // ---- consumer dispatcher (#17) -----------------------------------------

    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::messaging::{LogMessaging, Messaging};
    use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, StorageError};

    const EVENT_CONSUMER: &[u8] =
        include_bytes!("../../boatramp-handlers/tests/fixtures/event-consumer.wasm");

    #[derive(Default)]
    struct MemStorage {
        objects: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl boatramp_core::Storage for MemStorage {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            let bytes = self
                .objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            let body: ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
            Ok(GetObject {
                meta: ObjectMeta {
                    key: key.to_string(),
                    ..Default::default()
                },
                body,
            })
        }
        async fn get_range(
            &self,
            key: &str,
            _: u64,
            _: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            self.get(key).await
        }
        async fn put(
            &self,
            key: &str,
            mut body: ByteStream,
            _: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            use futures::StreamExt;
            let mut buf = Vec::new();
            while let Some(chunk) = body.next().await {
                buf.extend_from_slice(&chunk?);
            }
            self.objects.lock().unwrap().insert(key.to_string(), buf);
            Ok(ObjectMeta {
                key: key.to_string(),
                ..Default::default()
            })
        }
        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            self.objects
                .lock()
                .unwrap()
                .get(key)
                .map(|_| ObjectMeta {
                    key: key.to_string(),
                    ..Default::default()
                })
                .ok_or_else(|| StorageError::NotFound(key.to_string()))
        }
        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.objects.lock().unwrap().remove(key);
            Ok(())
        }
        async fn list(&self, _: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(Vec::new())
        }
    }

    /// Build an `ObservedInstance` for the wake-from-zero helper tests.
    fn observed_state(
        workload: &str,
        healthy: bool,
        phase: boatramp_core::compute::ReplicaPhase,
    ) -> boatramp_core::compute::ObservedInstance {
        use boatramp_core::compute::{Endpoint, InstanceHandle, ReplicaPhase, Scheme, Snapshot};
        boatramp_core::compute::ObservedInstance {
            handle: InstanceHandle {
                workload: workload.into(),
                replica: 0,
                backend_ref: "ref-0".into(),
            },
            node: 1,
            backend: "vmm".into(),
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: "10.0.0.2".into(),
                port: 80,
            },
            region: None,
            healthy,
            phase,
            snapshot: matches!(phase, ReplicaPhase::Zero).then(|| Snapshot {
                workload: workload.into(),
                replica: 0,
                data_ref: "snap-0".into(),
            }),
        }
    }

    #[tokio::test]
    async fn has_parked_replica_detects_a_zeroed_replica() {
        use boatramp_core::compute::ReplicaPhase;
        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage, kv);

        // Nothing → false.
        assert!(!has_parked_replica(&deploy, "w").await);
        // A running replica → false (it's serving, not parked).
        deploy
            .set_replica_state(&observed_state("w", true, ReplicaPhase::Running))
            .await
            .unwrap();
        assert!(!has_parked_replica(&deploy, "w").await);
        // A parked (Zero) replica → true (wakeable).
        deploy
            .set_replica_state(&observed_state("w", false, ReplicaPhase::Zero))
            .await
            .unwrap();
        assert!(has_parked_replica(&deploy, "w").await);
    }

    #[tokio::test]
    async fn await_warm_returns_immediately_when_healthy_and_times_out_otherwise() {
        use boatramp_core::compute::ReplicaPhase;
        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage, kv);

        // No healthy replica → times out with an empty pool (short timeout).
        let empty = await_warm(&deploy, "w", std::time::Duration::from_millis(150)).await;
        assert!(empty.is_empty());

        // A healthy replica → returned promptly.
        deploy
            .set_replica_state(&observed_state("w", true, ReplicaPhase::Running))
            .await
            .unwrap();
        let warm = await_warm(&deploy, "w", std::time::Duration::from_secs(5)).await;
        assert_eq!(warm, vec!["http://10.0.0.2:80".to_string()]);
    }

    /// The delivery gate: a consumer receives every published message at-least-once
    /// (acked, counted once each), and a message that keeps failing is
    /// redelivered and then dead-lettered after `max_attempts`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dispatcher_delivers_at_least_once_then_dead_letters() {
        use boatramp_handlers::{Bindings, HandlerEngine, Limits};
        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let mq = LogMessaging::new(storage, kv.clone());
        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let hash = boatramp_core::deploy::sha256_hex(EVENT_CONSUMER);
        let bindings = Bindings::new("blog").with_keyvalue("blog", kv.clone());
        let topic = "blog/orders/created";

        // Three good messages → each delivered + acked exactly once.
        for _ in 0..3 {
            mq.publish(topic, b"ok").await.unwrap();
        }
        loop {
            let acked = dispatch_consumer_batch(
                &engine,
                &mq,
                &metrics::Metrics::default(),
                "blog",
                topic,
                "blog/",
                &hash,
                EVENT_CONSUMER,
                &bindings,
                Limits::default(),
                Duration::from_secs(30),
                5,
                10,
            )
            .await;
            if acked == 0 {
                break;
            }
        }
        assert_eq!(
            kv.get("hkv/blog/delivered/orders/created").await.unwrap(),
            Some(b"3".to_vec())
        );

        // A poison message keeps failing → redelivered, then dead-lettered after
        // max_attempts (zero lease makes redelivery immediate).
        mq.publish(topic, b"fail").await.unwrap();
        for _ in 0..5 {
            dispatch_consumer_batch(
                &engine,
                &mq,
                &metrics::Metrics::default(),
                "blog",
                topic,
                "blog/",
                &hash,
                EVENT_CONSUMER,
                &bindings,
                Limits::default(),
                Duration::ZERO,
                2,
                10,
            )
            .await;
        }
        assert_eq!(mq.dead_letter_count(topic).await.unwrap(), 1);
        // The good counter is untouched by the poison message.
        assert_eq!(
            kv.get("hkv/blog/delivered/orders/created").await.unwrap(),
            Some(b"3".to_vec())
        );
    }

    /// The activation policy: the scheduler runs the **current** deployment's
    /// consumers (production namespace `{site}`), but never a preview's — a
    /// preview-namespaced message is left untouched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scheduler_runs_current_consumers_not_previews() {
        use boatramp_core::config::{ConsumerConfig, DeployConfig, HandlersSiteConfig, SiteConfig};
        use boatramp_core::deploy::{DeployStore, FileEntry, Manifest};
        use boatramp_handlers::{HandlerEngine, Limits};
        use futures::StreamExt;

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());
        let messaging: Arc<dyn Messaging> =
            Arc::new(LogMessaging::new(storage.clone(), kv.clone()));

        // Store the consumer component + a deployment that subscribes to it.
        let hash = boatramp_core::deploy::sha256_hex(EVENT_CONSUMER);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(EVENT_CONSUMER)) })
                .boxed();
        deploy.put_blob(&hash, stream).await.unwrap();
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            "consumer.wasm".to_string(),
            FileEntry {
                hash: hash.clone(),
                size: EVENT_CONSUMER.len() as u64,
                content_type: None,
                variants: std::collections::BTreeMap::new(),
            },
        );
        let manifest = Manifest {
            files,
            config: DeployConfig {
                consumers: vec![ConsumerConfig {
                    topic: "orders/created".into(),
                    component: "consumer.wasm".into(),
                    imports: vec!["wasi:keyvalue".into()],
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let id = deploy.put_manifest(&manifest).await.unwrap();
        deploy.activate("blog", &id).await.unwrap();
        deploy
            .set_site_config(
                "blog",
                &SiteConfig {
                    handlers: Some(HandlersSiteConfig {
                        enabled: true,
                        allow_imports: vec!["wasi:keyvalue".into()],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        // One message in the production namespace, one in a preview namespace.
        messaging
            .publish("blog/orders/created", b"live")
            .await
            .unwrap();
        messaging
            .publish("blog/_preview/abc/orders/created", b"preview")
            .await
            .unwrap();

        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv.clone(), storage, None, Some(messaging));
        let inner = rt.inner.clone().unwrap();
        let mut cache = std::collections::HashMap::new();
        let mut crons = std::collections::HashMap::new();
        let now = CronNow {
            minute: 0,
            hour: 0,
            dom: 1,
            month: 1,
            dow: 0,
            minute_stamp: 0,
        };
        for _ in 0..3 {
            run_scheduler_tick(&inner, &deploy, &mut cache, &mut crons, now)
                .await
                .unwrap();
        }

        // The production message was delivered + counted.
        assert_eq!(
            kv.get("hkv/blog/delivered/orders/created").await.unwrap(),
            Some(b"1".to_vec())
        );
        // The preview-namespaced message was never claimed (no background work
        // for previews) — its counter doesn't exist.
        assert_eq!(
            kv.get("hkv/blog/_preview/abc/delivered/orders/created")
                .await
                .unwrap(),
            None
        );
    }

    // ---- cron driver (#18) -------------------------------------------------

    /// A `wasi:http` handler that increments `hits` per request (`kv-counter`),
    /// used here as a cron target so a fire is observable as a counter bump.
    const KV_COUNTER: &[u8] =
        include_bytes!("../../boatramp-handlers/tests/fixtures/kv-counter.wasm");

    /// The cron driver: a due cron fires its route (loopback), once per
    /// matching minute (dedup), and with `overlap: Skip` a fire is skipped while
    /// a previous one is still running.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scheduler_fires_crons_with_dedup_and_overlap_skip() {
        use boatramp_core::config::{
            CronConfig, DeployConfig, HandlerConfig, HandlersSiteConfig, Overlap, SiteConfig,
        };
        use boatramp_core::deploy::{DeployStore, FileEntry, Manifest};
        use boatramp_handlers::{HandlerEngine, Limits};
        use futures::StreamExt;
        use std::sync::atomic::Ordering;

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());

        let hash = boatramp_core::deploy::sha256_hex(KV_COUNTER);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(KV_COUNTER)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            "counter.wasm".to_string(),
            FileEntry {
                hash: hash.clone(),
                size: KV_COUNTER.len() as u64,
                content_type: None,
                variants: std::collections::BTreeMap::new(),
            },
        );
        let manifest = Manifest {
            files,
            config: DeployConfig {
                handlers: vec![HandlerConfig {
                    route: "/".into(),
                    methods: Vec::new(),
                    component: "counter.wasm".into(),
                    imports: vec!["wasi:keyvalue".into()],
                    limits: None,
                    env: std::collections::BTreeMap::new(),
                }],
                crons: vec![CronConfig {
                    schedule: "* * * * *".into(),
                    route: "/".into(),
                    overlap: Overlap::Skip,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let id = deploy.put_manifest(&manifest).await.unwrap();
        deploy.activate("blog", &id).await.unwrap();
        deploy
            .set_site_config(
                "blog",
                &SiteConfig {
                    handlers: Some(HandlersSiteConfig {
                        enabled: true,
                        allow_imports: vec!["wasi:keyvalue".into()],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
        let inner = rt.inner.clone().unwrap();
        let mut wasm = std::collections::HashMap::new();
        let mut crons = std::collections::HashMap::new();
        let at = |stamp| CronNow {
            minute: 0,
            hour: 0,
            dom: 1,
            month: 1,
            dow: 0,
            minute_stamp: stamp,
        };

        // Fires once for the minute.
        let (_, handles) = run_scheduler_tick(&inner, &deploy, &mut wasm, &mut crons, at(100))
            .await
            .unwrap();
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(kv.get("hkv/blog/hits").await.unwrap(), Some(b"1".to_vec()));

        // Same minute → deduped (no fire).
        let (_, handles) = run_scheduler_tick(&inner, &deploy, &mut wasm, &mut crons, at(100))
            .await
            .unwrap();
        assert!(handles.is_empty());
        assert_eq!(kv.get("hkv/blog/hits").await.unwrap(), Some(b"1".to_vec()));

        // Next minute → fires again.
        let (_, handles) = run_scheduler_tick(&inner, &deploy, &mut wasm, &mut crons, at(101))
            .await
            .unwrap();
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(kv.get("hkv/blog/hits").await.unwrap(), Some(b"2".to_vec()));

        // overlap=Skip: a previous fire still running → the next minute is skipped.
        crons
            .get("blog|cron|0")
            .unwrap()
            .running
            .store(true, Ordering::Release);
        let (_, handles) = run_scheduler_tick(&inner, &deploy, &mut wasm, &mut crons, at(102))
            .await
            .unwrap();
        assert!(handles.is_empty());
        assert_eq!(kv.get("hkv/blog/hits").await.unwrap(), Some(b"2".to_vec()));
    }

    /// Cluster cron single-firing: with a leader gate that
    /// returns `false` (this node is not the leader), the scheduler fires **no**
    /// crons — so a cron fires on exactly one node cluster-wide.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cron_leader_gate_suppresses_crons_off_leader() {
        use boatramp_core::config::{
            CronConfig, DeployConfig, HandlerConfig, HandlersSiteConfig, Overlap, SiteConfig,
        };
        use boatramp_core::deploy::{DeployStore, FileEntry, Manifest};
        use boatramp_handlers::{HandlerEngine, Limits};
        use futures::StreamExt;

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());

        let hash = boatramp_core::deploy::sha256_hex(KV_COUNTER);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(KV_COUNTER)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            "counter.wasm".to_string(),
            FileEntry {
                hash: hash.clone(),
                size: KV_COUNTER.len() as u64,
                content_type: None,
                variants: std::collections::BTreeMap::new(),
            },
        );
        let manifest = Manifest {
            files,
            config: DeployConfig {
                handlers: vec![HandlerConfig {
                    route: "/".into(),
                    methods: Vec::new(),
                    component: "counter.wasm".into(),
                    imports: vec!["wasi:keyvalue".into()],
                    limits: None,
                    env: std::collections::BTreeMap::new(),
                }],
                crons: vec![CronConfig {
                    schedule: "* * * * *".into(),
                    route: "/".into(),
                    overlap: Overlap::Skip,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let id = deploy.put_manifest(&manifest).await.unwrap();
        deploy.activate("blog", &id).await.unwrap();
        deploy
            .set_site_config(
                "blog",
                &SiteConfig {
                    handlers: Some(HandlersSiteConfig {
                        enabled: true,
                        allow_imports: vec!["wasi:keyvalue".into()],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
        // This node is "not the leader" — gate returns false.
        rt.set_cron_leader_gate(Arc::new(|| false));
        let inner = rt.inner.clone().unwrap();
        let mut wasm = std::collections::HashMap::new();
        let mut crons = std::collections::HashMap::new();
        let now = CronNow {
            minute: 0,
            hour: 0,
            dom: 1,
            month: 1,
            dow: 0,
            minute_stamp: 100,
        };

        let (_, handles) = run_scheduler_tick(&inner, &deploy, &mut wasm, &mut crons, now)
            .await
            .unwrap();
        // No cron fired (a follower); the counter was never written.
        assert!(handles.is_empty(), "a non-leader must not fire crons");
        assert_eq!(kv.get("hkv/blog/hits").await.unwrap(), None);
    }
}
