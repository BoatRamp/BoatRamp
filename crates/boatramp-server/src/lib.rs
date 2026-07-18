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
#[cfg(feature = "compression")]
pub(crate) use content::maybe_compress;
pub(crate) use content::multipart_byteranges;
pub(crate) use content::{
    negotiate_encoding, parse_ranges, response_headers, set_content_encoding, MAX_RANGES,
};
mod domain_verify;
pub use domain_verify::{spawn_domain_verify_reconcile, verification_pending_page};
pub mod envelope;
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
mod ratelimit;
/// External token signer backends: KMS / HSM / Vault-hosted
/// control-plane root keys behind the [`boatramp_core::cose::Signer`] seam.
pub mod signer;
mod srvmetrics;
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

/// `?site=` filter for the functions view.
#[derive(serde::Deserialize)]
struct FunctionQuery {
    site: Option<String>,
}

/// One entry in the `GET /api/functions` view.
#[derive(serde::Serialize)]
struct FunctionSummary {
    /// Function name (`<site>/<name>` for site-scoped; bare for top-level).
    name: String,
    /// Owner (`site:<site>` or `project:<project>`).
    owner: String,
    /// Execution substrate.
    runtime: String,
    /// Active version id (the component blob hash).
    version: String,
    /// Rendered triggers that reach this function.
    triggers: Vec<String>,
}

/// `GET /api/functions[?site=…]` — the derived, **read-only** site-scoped function
/// view (FA-1): desugar each site's active manifest into functions + triggers and
/// resolve component paths to their blob-hash version ids. A pure projection of the
/// manifests — the serve path is untouched, so a site's handlers are unchanged.
/// `system·read`.
async fn list_functions(
    State(deploy): State<DeployStore>,
    axum::extract::Query(query): axum::extract::Query<FunctionQuery>,
) -> Response {
    use boatramp_core::function;
    let sites = match &query.site {
        Some(s) => vec![s.clone()],
        None => match deploy.all_sites().await {
            Ok(s) => s,
            Err(err) => return deploy_error_response(err),
        },
    };
    let mut out: Vec<FunctionSummary> = Vec::new();
    for site in sites {
        let manifest = match deploy.current_manifest(&site).await {
            Ok(Some(m)) => m,
            Ok(None) => continue,
            Err(err) => return deploy_error_response(err),
        };
        let (specs, triggers) = function::desugar(&manifest.config);
        for f in function::materialize(&specs, &site, &manifest.files, 0) {
            let trigs = triggers
                .iter()
                .filter(|t| t.target.as_ref().map(|r| r.name.as_str()) == Some(f.name.as_str()))
                .map(std::string::ToString::to_string)
                .collect();
            out.push(FunctionSummary {
                name: format!("{site}/{}", f.name),
                owner: format!("site:{site}"),
                runtime: f.config.runtime.as_str().to_string(),
                version: f.active,
                triggers: trigs,
            });
        }
    }
    // Top-level (independently-stored) functions — FA-2. A `?site=` filter is
    // site-scoped only, so it excludes these.
    if query.site.is_none() {
        match deploy.list_stored_functions().await {
            Ok(stored) => {
                for f in stored {
                    out.push(FunctionSummary {
                        name: f.name.clone(),
                        owner: f.owner.to_string(),
                        runtime: f.config.runtime.as_str().to_string(),
                        version: f.active,
                        // A top-level function has a stable invoke URL (FA-3).
                        triggers: vec![format!("invoke {}", f.name)],
                    });
                }
            }
            Err(err) => return deploy_error_response(err),
        }
    }
    Json(out).into_response()
}

/// Body of `PUT /api/functions/:name` — deploy a version of a top-level function.
#[derive(serde::Deserialize)]
struct FunctionUpsert {
    /// The component blob hash (uploaded first via `PUT /api/blobs/<hash>`).
    component: String,
    /// Binding/capability config.
    #[serde(default)]
    config: boatramp_core::function::FunctionConfig,
    /// Version lifecycle (defaults to `deploy-pinned`; top-level functions choose
    /// `independent`).
    #[serde(default)]
    lifecycle: boatramp_core::function::Lifecycle,
}

/// `PUT /api/functions/:name` (FA-2) — deploy a version of a top-level function.
/// The component blob must already be uploaded. Creates the function if new;
/// otherwise appends + activates the version (idempotent per component hash).
/// `system·admin`.
async fn deploy_function(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
    Json(body): Json<FunctionUpsert>,
) -> Response {
    use boatramp_core::function::{Function, Owner};
    match deploy.has_blob(&body.component).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("component blob {} not uploaded\n", body.component),
            )
                .into_response()
        }
        Err(err) => return deploy_error_response(err),
    }
    let now = now_unix();
    let f = match deploy.get_function(&name).await {
        Ok(Some(mut existing)) => {
            existing.config = body.config;
            existing.upsert_version(&body.component, body.lifecycle, now);
            existing
        }
        // A brand-new top-level function is owned by the (single, for now) default
        // project; per-tenant ownership arrives with FA-4.
        Ok(None) => Function::new(
            name.clone(),
            Owner::Project("default".to_string()),
            &body.component,
            body.config,
            body.lifecycle,
            now,
        ),
        Err(err) => return deploy_error_response(err),
    };
    if let Err(err) = deploy.put_function(&f).await {
        return deploy_error_response(err);
    }
    Json(f).into_response()
}

/// Body of `POST /api/functions/:name/rollback`.
#[derive(serde::Deserialize)]
struct RollbackBody {
    to: String,
}

/// `POST /api/functions/:name/rollback` (FA-2) — point active at a prior version.
async fn rollback_function(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
    Json(body): Json<RollbackBody>,
) -> Response {
    match deploy.get_function(&name).await {
        Ok(Some(mut f)) => match f.rollback(&body.to) {
            Ok(()) => {
                if let Err(err) = deploy.put_function(&f).await {
                    return deploy_error_response(err);
                }
                Json(f).into_response()
            }
            Err(msg) => (StatusCode::BAD_REQUEST, format!("{msg}\n")).into_response(),
        },
        Ok(None) => (StatusCode::NOT_FOUND, format!("no function {name:?}\n")).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Body of `PUT /api/functions/:name/aliases/:label`.
#[derive(serde::Deserialize)]
struct AliasBody {
    version: String,
}

/// `PUT /api/functions/:name/aliases/:label` (FA-2) — point a label at a version.
async fn alias_function(
    State(deploy): State<DeployStore>,
    Path((name, label)): Path<(String, String)>,
    Json(body): Json<AliasBody>,
) -> Response {
    match deploy.get_function(&name).await {
        Ok(Some(mut f)) => match f.set_alias(&label, &body.version) {
            Ok(()) => {
                if let Err(err) = deploy.put_function(&f).await {
                    return deploy_error_response(err);
                }
                Json(f).into_response()
            }
            Err(msg) => (StatusCode::BAD_REQUEST, format!("{msg}\n")).into_response(),
        },
        Ok(None) => (StatusCode::NOT_FOUND, format!("no function {name:?}\n")).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `DELETE /api/functions/:name` (FA-2) — remove a top-level function (idempotent).
/// Content-addressed component blobs are shared and left to `prune`.
async fn remove_function(State(deploy): State<DeployStore>, Path(name): Path<String>) -> Response {
    match deploy.delete_function(&name).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

// ---- function invoke API (FA-3) ----------------------------------------------

/// The authority the engine sees for an invoked function. `wasi:http` needs a
/// scheme + authority; the public control-plane path is the host's concern, so
/// every function is invoked at `http://function.invoke/`.
#[cfg(feature = "handlers")]
const INVOKE_AUTHORITY: &str = "function.invoke";

/// Attempts a durable (async) invocation gets before it is dead-lettered
/// (left terminal-`failed` in its keyspace for inspection).
#[cfg(feature = "handlers")]
const MAX_INVOKE_ATTEMPTS: u32 = 5;

/// Max request body buffered when **enqueuing** an async invocation. The sync
/// path streams into the guest and never buffers; async must persist the body,
/// so it is bounded here (mirrors the engine's default body cap).
#[cfg(feature = "handlers")]
const MAX_ASYNC_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Query of `POST /api/functions/:name/invoke`.
#[cfg(feature = "handlers")]
#[derive(serde::Deserialize)]
struct InvokeQuery {
    /// Delivery mode: `sync` (default) or `async`.
    #[serde(default)]
    mode: Option<String>,
    /// Which version/alias to invoke (defaults to the active version).
    #[serde(default)]
    version: Option<String>,
}

/// A random 16-byte invocation id, hex, from the OS CSPRNG (the same source the
/// token layer draws its `cti` from). A CSPRNG failure implies a broken platform
/// and is logged; it is not expected on our targets.
#[cfg(feature = "handlers")]
fn new_invocation_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        tracing::error!("getrandom failed generating an invocation id");
    }
    hex::encode(bytes)
}

/// `POST /api/functions/:name/invoke` (FA-3) — invoke a function.
///
/// `?mode=sync` (default) runs inline and returns the function's response.
/// `?mode=async` durably enqueues the call and returns `202 Accepted` with an
/// invocation id to poll at `/invocations/:id`; a drain worker runs it (retried,
/// then dead-lettered). An `Idempotency-Key` header dedups: a repeat with the
/// same key replays the first call's outcome instead of running again.
/// `system·admin` (a finer per-function invoke right lands in FA-4).
#[cfg(feature = "handlers")]
async fn invoke_function(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(name): Path<String>,
    axum::extract::Query(query): axum::extract::Query<InvokeQuery>,
    request: Request,
) -> Response {
    let Some(inner) = handlers.inner.as_ref() else {
        return handler_unavailable();
    };
    let function = match deploy.get_function(&name).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, format!("no function {name:?}\n")).into_response()
        }
        Err(err) => return deploy_error_response(err),
    };
    let reference = query.version.as_deref().unwrap_or(&function.active);
    let Some(component) = function.resolve(reference).map(str::to_owned) else {
        return (
            StatusCode::NOT_FOUND,
            format!("no version {reference:?} in function {name:?}\n"),
        )
            .into_response();
    };
    let is_async = query.mode.as_deref() == Some("async");
    let idem_key = request
        .headers()
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // Idempotency replay: a recorded key returns the first call's outcome (its
    // captured result, or `202` + id while the async call is still in flight).
    // Checked *before* the quota so a replay never spends the rate budget.
    if let Some(key) = &idem_key {
        match deploy.get_idempotency(&name, key).await {
            Ok(Some(id)) => {
                if let Ok(Some(inv)) = deploy.get_invocation(&name, &id).await {
                    return replay_invocation(&inv);
                }
            }
            Ok(None) => {}
            Err(err) => return deploy_error_response(err),
        }
    }

    // Rate-limit quota (FA-4), fail-closed → 429, charged once at entry for both
    // sync and async (a drain retry does not re-charge).
    if let Err(response) = admit_by_quota(inner, &deploy, &function).await {
        return response;
    }

    if is_async {
        enqueue_invocation(&deploy, &function, &component, request, idem_key).await
    } else {
        execute_sync(inner, &deploy, &function, &component, request, idem_key).await
    }
}

/// Run a function inline and return its response. With an idempotency key the
/// response is captured + persisted (as a `succeeded` [`Invocation`]) so a repeat
/// replays it; without one it streams straight back.
#[cfg(feature = "handlers")]
async fn execute_sync(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
    component: &str,
    request: Request,
    idem_key: Option<String>,
) -> Response {
    let (response, duration_ms) =
        execute_function(inner, deploy, function, component, request).await;
    let Some(key) = idem_key else {
        // No capture on the plain streaming path: meter counts + duration + a
        // head-status success signal (byte totals are metered on the buffered
        // async / idempotent paths).
        let sample = boatramp_core::function::MeteringSample {
            success: response.status().as_u16() < 500,
            duration_ms,
            bytes_in: 0,
            bytes_out: 0,
        };
        record_metering(inner, deploy, &function.name, &sample).await;
        return response;
    };
    // Capture so the outcome can be replayed under the idempotency key.
    let (status, content_type, body) = capture_response(response).await;
    let sample = boatramp_core::function::MeteringSample {
        success: status.as_u16() < 500,
        duration_ms,
        bytes_in: 0,
        bytes_out: body.len() as u64,
    };
    record_metering(inner, deploy, &function.name, &sample).await;
    let now = now_unix();
    let id = new_invocation_id();
    let inv = boatramp_core::function::Invocation {
        id: id.clone(),
        function: function.name.clone(),
        version: component.to_string(),
        mode: boatramp_core::function::InvokeMode::Sync,
        status: boatramp_core::function::InvocationStatus::Succeeded,
        idempotency_key: Some(key.clone()),
        attempts: 1,
        request_b64: None,
        request_content_type: None,
        result: Some(boatramp_core::function::InvocationResult {
            status: status.as_u16(),
            content_type: content_type.clone(),
            body_b64: b64_encode(&body),
        }),
        created: now,
        updated: now,
    };
    if let Err(err) = deploy.put_invocation(&inv).await {
        return deploy_error_response(err);
    }
    if let Err(err) = deploy.put_idempotency(&function.name, &key, &id).await {
        return deploy_error_response(err);
    }
    rebuild_response(status, content_type.as_deref(), body)
}

/// Durably enqueue an async invocation: buffer the request body, persist a
/// `queued` [`Invocation`], bind the idempotency key, and return `202` + id.
#[cfg(feature = "handlers")]
async fn enqueue_invocation(
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
    component: &str,
    request: Request,
    idem_key: Option<String>,
) -> Response {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = match axum::body::to_bytes(request.into_body(), MAX_ASYNC_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "async invoke body exceeds the buffer cap\n",
            )
                .into_response()
        }
    };
    let now = now_unix();
    let id = new_invocation_id();
    let inv = boatramp_core::function::Invocation {
        id: id.clone(),
        function: function.name.clone(),
        version: component.to_string(),
        mode: boatramp_core::function::InvokeMode::Async,
        status: boatramp_core::function::InvocationStatus::Queued,
        idempotency_key: idem_key.clone(),
        attempts: 0,
        request_b64: (!body.is_empty()).then(|| b64_encode(&body)),
        request_content_type: content_type,
        result: None,
        created: now,
        updated: now,
    };
    if let Err(err) = deploy.put_invocation(&inv).await {
        return deploy_error_response(err);
    }
    if let Some(key) = &idem_key {
        if let Err(err) = deploy.put_idempotency(&function.name, key, &id).await {
            return deploy_error_response(err);
        }
    }
    (StatusCode::ACCEPTED, Json(inv)).into_response()
}

/// `GET /api/functions/:name/invocations/:id` (FA-3) — poll a durable
/// invocation's status/result. `system·read`.
#[cfg(feature = "handlers")]
async fn get_invocation_record(
    State(deploy): State<DeployStore>,
    Path((name, id)): Path<(String, String)>,
) -> Response {
    match deploy.get_invocation(&name, &id).await {
        Ok(Some(inv)) => Json(inv).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            format!("no invocation {id:?} for function {name:?}\n"),
        )
            .into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Reconstruct a `Response` for an idempotency replay / async poll shortcut: a
/// completed invocation replays its captured result; one still in flight returns
/// `202` + the record.
#[cfg(feature = "handlers")]
fn replay_invocation(inv: &boatramp_core::function::Invocation) -> Response {
    match &inv.result {
        Some(result) => {
            let body = b64_decode(&result.body_b64);
            rebuild_response(
                StatusCode::from_u16(result.status).unwrap_or(StatusCode::OK),
                result.content_type.as_deref(),
                body,
            )
        }
        None => (StatusCode::ACCEPTED, Json(inv.clone())).into_response(),
    }
}

/// The core engine run: enforce the per-function concurrency quota, load the
/// component blob, build the function's bindings under its own `fn/<name>` scope,
/// and serve the request. Returns the response and its time-to-head in ms (for
/// metering). Errors map to the same statuses as a handler dispatch; a
/// `max_concurrent`-full function yields `503` (a retryable delivery failure for
/// the async drain).
#[cfg(feature = "handlers")]
async fn execute_function(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
    component: &str,
    request: Request,
) -> (Response, u64) {
    // Concurrency quota (held through the head, mirroring the site permit).
    let _permit = match acquire_function_permit(inner, &function.name, &function.config.quota) {
        Ok(permit) => permit,
        Err(()) => {
            return (
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "function concurrency limit reached\n",
                )
                    .into_response(),
                0,
            )
        }
    };
    let wasm = match read_blob_fully(deploy, component).await {
        Ok(bytes) => bytes,
        Err(response) => return (response, 0),
    };
    let scope = format!("fn/{}", function.name);
    let bindings = build_function_bindings(inner, &scope, &function.config).await;
    let limits = function_limits(function.config.limits.as_ref());
    let request = prepare_invoke_request(request);
    let start = std::time::Instant::now();
    let result = inner
        .engine
        .serve_with_limits(component, &wasm, request, bindings, limits)
        .await;
    let elapsed = start.elapsed();
    inner.metrics.observe(
        &function.name,
        metrics::Trigger::Invoke,
        "invoke",
        component,
        metrics::Outcome::from_result(&result),
        elapsed,
    );
    let response = match result {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            axum::http::Response::from_parts(parts, axum::body::Body::new(body))
        }
        Err(err) => {
            tracing::warn!(function = %function.name, %err, "function invocation failed");
            handler_error_response(&err)
        }
    };
    (response, elapsed.as_millis() as u64)
}

/// Build a top-level function's bindings. Unlike a site handler (whose grants are
/// the site allowlist ∩ its imports), a top-level function is admin-deployed, so
/// its declared `imports` **are** its grants — served under its own `fn/<name>`
/// scope so kv/blob/messaging/sql land in an isolated namespace.
#[cfg(feature = "handlers")]
async fn build_function_bindings(
    inner: &HandlerRuntimeInner,
    scope: &str,
    config: &boatramp_core::function::FunctionConfig,
) -> boatramp_handlers::Bindings {
    let granted = |name: &str| config.imports.iter().any(|i| i == name);
    let mut bindings = boatramp_handlers::Bindings::new(scope);
    if granted("wasi:keyvalue") {
        bindings = bindings.with_keyvalue(scope, inner.kv.clone());
    }
    if granted("wasi:blobstore") {
        let max_blob = inner.max_blob_bytes.get().copied().unwrap_or(0);
        bindings = bindings.with_blobstore(scope, inner.storage.clone(), max_blob);
    }
    if granted("sql") {
        if let Some(provider) = &inner.sql {
            match provider.database(scope, "").await {
                Ok(backend) => bindings = bindings.with_sql("", backend),
                Err(err) => tracing::warn!(scope, %err, "opening function SQL database failed"),
            }
        }
    }
    if granted("wasi:messaging") {
        if let Some(messaging) = &inner.messaging {
            bindings = bindings.with_messaging(format!("{scope}/"), messaging.clone());
        }
    }
    inner.logs.configure(scope, None);
    bindings = bindings.with_logging(scope.to_string(), inner.logs.clone());
    let env: Vec<(String, String)> = config
        .env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    bindings.with_env(env)
}

/// Per-invocation limits for a function: its own `limits` (memory/timeout/fuel),
/// left at the engine default where unset. The engine clamps to its ceiling.
#[cfg(feature = "handlers")]
fn function_limits(
    limits: Option<&boatramp_core::config::HandlerLimits>,
) -> boatramp_handlers::Limits {
    let mut l = boatramp_handlers::Limits::default();
    if let Some(hl) = limits {
        if let Some(mb) = hl.memory_mb {
            l.memory_bytes = (mb as usize).saturating_mul(1024 * 1024);
        }
        if let Some(ms) = hl.timeout_ms {
            l.timeout_ms = ms as u64;
        }
        if let Some(fuel) = hl.fuel {
            l.fuel = Some(fuel);
        }
    }
    l
}

/// Point a request at the synthetic invoke authority so `wasi:http` sees a
/// well-formed absolute URI (`http://function.invoke/`), preserving method +
/// headers + body. The public `/api/functions/<name>/invoke` path is dropped —
/// the function sees a clean request, not the control-plane envelope.
#[cfg(feature = "handlers")]
fn prepare_invoke_request(mut request: Request) -> Request {
    if let Ok(uri) = format!("http://{INVOKE_AUTHORITY}/").parse() {
        *request.uri_mut() = uri;
    }
    request
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static(INVOKE_AUTHORITY));
    request
}

/// Buffer a response into `(status, content-type, body)` — for idempotency
/// capture and async result persistence.
#[cfg(feature = "handlers")]
async fn capture_response(response: Response) -> (StatusCode, Option<String>, Vec<u8>) {
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();
    (status, content_type, body)
}

/// Rebuild a `Response` from captured parts.
#[cfg(feature = "handlers")]
fn rebuild_response(status: StatusCode, content_type: Option<&str>, body: Vec<u8>) -> Response {
    let mut builder = axum::http::Response::builder().status(status);
    if let Some(ct) = content_type {
        if let Ok(value) = HeaderValue::from_str(ct) {
            builder = builder.header(header::CONTENT_TYPE, value);
        }
    }
    builder
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| handler_unavailable())
}

/// Standard base64 of bytes (invocation records are plain JSON).
#[cfg(feature = "handlers")]
fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode standard base64 back to bytes (empty on malformed input — a persisted
/// record we wrote is always valid).
#[cfg(feature = "handlers")]
fn b64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}

/// Drain a function's queued async invocations: run each once, capturing its
/// result. A failed run is retried next tick until [`MAX_INVOKE_ATTEMPTS`], then
/// dead-lettered (left `failed` for inspection). Driven from the scheduler tick.
#[cfg(feature = "handlers")]
async fn drain_function_invocations(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
) {
    let queued = match deploy.list_invocations(&function.name).await {
        Ok(list) => list,
        Err(err) => {
            tracing::warn!(function = %function.name, %err, "listing invocations failed");
            return;
        }
    };
    for inv in queued {
        if !matches!(
            inv.status,
            boatramp_core::function::InvocationStatus::Queued
        ) {
            continue;
        }
        run_queued_invocation(inner, deploy, function, inv).await;
    }
}

/// Execute one queued invocation against its pinned version, persisting the
/// terminal outcome (or re-queuing for retry / dead-lettering on failure).
#[cfg(feature = "handlers")]
async fn run_queued_invocation(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
    mut inv: boatramp_core::function::Invocation,
) {
    use boatramp_core::function::InvocationStatus;
    // The version was pinned at enqueue; a later deploy can't silently change it.
    let Some(component) = function.resolve(&inv.version).map(str::to_owned) else {
        // The pinned version is gone (rolled off / pruned) — unrunnable, so fail.
        inv.status = InvocationStatus::Failed;
        inv.updated = now_unix();
        let _ = deploy.put_invocation(&inv).await;
        return;
    };
    inv.status = InvocationStatus::Running;
    inv.attempts = inv.attempts.saturating_add(1);
    inv.updated = now_unix();
    if let Err(err) = deploy.put_invocation(&inv).await {
        tracing::warn!(function = %function.name, %err, "marking invocation running failed");
        return;
    }
    let bytes_in = inv
        .request_b64
        .as_deref()
        .map(|b| b64_decode(b).len() as u64)
        .unwrap_or(0);
    let request = build_stored_request(&inv);
    let (response, duration_ms) =
        execute_function(inner, deploy, function, &component, request).await;
    let (status, content_type, body) = capture_response(response).await;
    // A function that returns a 5xx from the engine wrapper (timeout/trap/etc.)
    // is a delivery failure worth retrying; any response the guest itself
    // produced (including its own 4xx/5xx) is a successful delivery.
    let delivered = status != StatusCode::INTERNAL_SERVER_ERROR
        && status != StatusCode::GATEWAY_TIMEOUT
        && status != StatusCode::SERVICE_UNAVAILABLE;
    if delivered {
        inv.status = InvocationStatus::Succeeded;
        inv.result = Some(boatramp_core::function::InvocationResult {
            status: status.as_u16(),
            content_type,
            body_b64: b64_encode(&body),
        });
    } else if inv.attempts >= MAX_INVOKE_ATTEMPTS {
        inv.status = InvocationStatus::Failed;
    } else {
        inv.status = InvocationStatus::Queued;
    }
    inv.updated = now_unix();
    let _ = deploy.put_invocation(&inv).await;
    // Meter a settled attempt (a requeue-for-retry is not yet a completed
    // invocation, so only the terminal transition is metered).
    if matches!(
        inv.status,
        InvocationStatus::Succeeded | InvocationStatus::Failed
    ) {
        let sample = boatramp_core::function::MeteringSample {
            success: matches!(inv.status, InvocationStatus::Succeeded),
            duration_ms,
            bytes_in,
            bytes_out: body.len() as u64,
        };
        record_metering(inner, deploy, &function.name, &sample).await;
    }
}

/// Rebuild the engine request for a stored async invocation from its buffered
/// body + content type (method is always `POST` for an enqueued call).
#[cfg(feature = "handlers")]
fn build_stored_request(inv: &boatramp_core::function::Invocation) -> Request {
    let body = inv
        .request_b64
        .as_deref()
        .map(b64_decode)
        .unwrap_or_default();
    let mut builder = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri(format!("http://{INVOKE_AUTHORITY}/"))
        .header(header::HOST, INVOKE_AUTHORITY);
    if let Some(ct) = &inv.request_content_type {
        if let Ok(value) = HeaderValue::from_str(ct) {
            builder = builder.header(header::CONTENT_TYPE, value);
        }
    }
    builder
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| Request::new(axum::body::Body::empty()))
}

// ---- function metering + quotas (FA-4) ---------------------------------------

/// The per-function lock serializing its metering + rate-limit read-modify-write,
/// created on first use so concurrent invocations of one function can't lose an
/// update (the KV is get/put, not atomic-increment).
#[cfg(feature = "handlers")]
fn function_meter_lock(inner: &HandlerRuntimeInner, name: &str) -> Arc<tokio::sync::Mutex<()>> {
    inner
        .function_meter_locks
        .lock()
        .unwrap()
        .entry(name.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Acquire a permit from the function's concurrency semaphore (created on first
/// use) when it sets a `max_concurrent` quota; `Ok(None)` if uncapped, `Err(())`
/// when at the limit (the caller turns that into a `503`).
#[cfg(feature = "handlers")]
fn acquire_function_permit(
    inner: &HandlerRuntimeInner,
    name: &str,
    quota: &boatramp_core::function::FunctionQuota,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, ()> {
    let Some(max) = quota.max_concurrent else {
        return Ok(None);
    };
    let semaphore = {
        let mut map = inner.function_semaphores.lock().unwrap();
        map.entry(name.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(max as usize)))
            .clone()
    };
    semaphore.try_acquire_owned().map(Some).map_err(|_| ())
}

/// Charge one invocation against the function's rate-limit quota (fixed window).
/// `Ok(())` admits; `Err(429)` means the window is full (fail-closed). A function
/// with no `max_invocations` cap always admits without touching the store.
#[cfg(feature = "handlers")]
async fn admit_by_quota(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
) -> Result<(), Response> {
    let quota = &function.config.quota;
    if quota.max_invocations.is_none() {
        return Ok(());
    }
    let lock = function_meter_lock(inner, &function.name);
    let _guard = lock.lock().await;
    let now = now_unix();
    let mut metering = match deploy.get_metering(&function.name).await {
        Ok(Some(m)) => m,
        Ok(None) => boatramp_core::function::Metering::new(&function.name),
        Err(err) => return Err(deploy_error_response(err)),
    };
    if !metering.admit(quota, now) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "function invocation quota exceeded\n",
        )
            .into_response());
    }
    if let Err(err) = deploy.put_metering(&metering).await {
        return Err(deploy_error_response(err));
    }
    Ok(())
}

/// Fold one invocation's measured cost into the function's usage aggregate
/// (best-effort: a metering write failure is logged, never surfaced to the
/// caller). Serialized per function so concurrent updates don't race.
#[cfg(feature = "handlers")]
async fn record_metering(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    function: &str,
    sample: &boatramp_core::function::MeteringSample,
) {
    let lock = function_meter_lock(inner, function);
    let _guard = lock.lock().await;
    let now = now_unix();
    let mut metering = match deploy.get_metering(function).await {
        Ok(Some(m)) => m,
        Ok(None) => boatramp_core::function::Metering::new(function),
        Err(err) => {
            tracing::warn!(function, %err, "reading metering failed");
            return;
        }
    };
    metering.record(sample, now);
    if let Err(err) = deploy.put_metering(&metering).await {
        tracing::warn!(function, %err, "writing metering failed");
    }
}

/// `GET /api/functions/:name/usage` (FA-4) — the function's usage aggregate.
/// `system·read`.
#[cfg(feature = "handlers")]
async fn get_function_usage(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
) -> Response {
    match deploy.get_metering(&name).await {
        Ok(Some(m)) => Json(m).into_response(),
        // No invocations yet ⇒ a zeroed aggregate, so the CLI always has a shape.
        Ok(None) => Json(boatramp_core::function::Metering::new(name)).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

// ---- function triggers: scheduled + event sources ----------------------------

/// `PUT /api/functions/:name/triggers/:id` — add/replace a stored trigger on a
/// function (the body is a [`TriggerKind`], e.g. `{"type":"cron","schedule":…}`).
/// The scheduler dispatches `cron` (→ a scheduled async invocation) and `queue`
/// (→ claim + invoke) triggers. `system·admin`.
#[cfg(feature = "handlers")]
async fn put_trigger_handler(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path((name, id)): Path<(String, String)>,
    Json(kind): Json<boatramp_core::function::TriggerKind>,
) -> Response {
    match deploy.get_function(&name).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (StatusCode::NOT_FOUND, format!("no function {name:?}\n")).into_response()
        }
        Err(err) => return deploy_error_response(err),
    }
    // Fail closed: a blob-change trigger is only meaningful on a backend that can
    // natively watch — refuse (never silently no-op) so the semantics stay uniform.
    if let boatramp_core::function::TriggerKind::Blob { prefix } = &kind {
        let Some(inner) = handlers.inner.as_ref() else {
            return (
                StatusCode::BAD_REQUEST,
                "this storage backend does not support blob-change triggers\n",
            )
                .into_response();
        };
        if !inner.storage.supports_watch() {
            return (
                StatusCode::BAD_REQUEST,
                "this storage backend does not support blob-change triggers\n",
            )
                .into_response();
        }
        // On a cloud object store a native pipeline (S3→SQS, …) must be
        // provisioned per the operator tier before the watch can fire. A
        // self-watching backend (fs) has no provider and needs nothing.
        if let Some(provider) = inner.watch_provider.get() {
            let storage_prefix = blob_storage_prefix(&name, prefix);
            let tier = inner.provision_tier.get().copied().unwrap_or_default();
            match boatramp_core::blob_provision::ensure_watch(
                provider.as_ref(),
                tier,
                &name,
                &storage_prefix,
                &deploy,
                now_unix(),
            )
            .await
            {
                Ok(boatramp_core::blob_provision::ProvisionOutcome::Ready) => {}
                // Dry-run: print the exact pipeline to apply; don't activate.
                Ok(boatramp_core::blob_provision::ProvisionOutcome::Recipe(recipe)) => {
                    return (StatusCode::BAD_REQUEST, format!("{recipe}\n")).into_response();
                }
                // Fail-closed refuse (no creds / nothing configured).
                Ok(boatramp_core::blob_provision::ProvisionOutcome::Refused(msg)) => {
                    return (StatusCode::BAD_REQUEST, format!("{msg}\n")).into_response();
                }
                Err(err) => {
                    return (StatusCode::BAD_GATEWAY, format!("{err}\n")).into_response();
                }
            }
        }
    }
    let trigger = boatramp_core::function::FunctionTrigger {
        id: id.clone(),
        kind,
        last_fired_minute: None,
    };
    if let Err(err) = deploy.put_trigger(&name, &trigger).await {
        return deploy_error_response(err);
    }
    Json(trigger).into_response()
}

/// `GET /api/functions/:name/triggers` — list a function's stored triggers.
/// `system·read`.
#[cfg(feature = "handlers")]
async fn list_triggers_handler(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
) -> Response {
    match deploy.list_triggers(&name).await {
        Ok(mut list) => {
            list.sort_by(|a, b| a.id.cmp(&b.id));
            Json(list).into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// `DELETE /api/functions/:name/triggers/:id` — remove a stored trigger.
/// `system·admin`. Idempotent. Removing a `Blob` trigger also **retracts** any
/// cloud notification pipeline provisioned for it (so no leaked queues), mirroring
/// auto-DNS retraction.
#[cfg(feature = "handlers")]
async fn delete_trigger_handler(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path((name, id)): Path<(String, String)>,
) -> Response {
    // Look the trigger up first: a `Blob` trigger may own a provisioned pipeline
    // to retract before the trigger record is gone.
    if let (Some(inner), Ok(Some(trigger))) = (
        handlers.inner.as_ref(),
        deploy.get_trigger(&name, &id).await,
    ) {
        if let (boatramp_core::function::TriggerKind::Blob { prefix }, Some(provider)) =
            (&trigger.kind, inner.watch_provider.get())
        {
            let storage_prefix = blob_storage_prefix(&name, prefix);
            if let Ok(Some(record)) = deploy
                .get_managed_notification(&name, &storage_prefix)
                .await
            {
                if let Err(err) = boatramp_core::blob_provision::retract_watch(
                    provider.as_ref(),
                    &record,
                    &deploy,
                )
                .await
                {
                    tracing::warn!(function = %name, %err, "retracting blob notification failed");
                }
            }
        }
    }
    match deploy.delete_trigger(&name, &id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// The full storage key prefix a function's `Blob { prefix }` trigger watches:
/// the function's blobstore namespace (`hblob/fn/<name>/`) joined with the
/// trigger-relative prefix. The provisioner (bucket-notification filter), the
/// notification ledger, and the [`spawn_blob_watcher`] consumer all key off this,
/// so they must agree.
#[cfg(feature = "handlers")]
fn blob_storage_prefix(function: &str, trigger_prefix: &str) -> String {
    format!("hblob/fn/{function}/{trigger_prefix}")
}

/// Dispatch a function's stored triggers on a scheduler tick: fire due **cron**
/// triggers (enqueue a durable async invocation, minute-deduped) and drain
/// **queue** triggers (claim a batch + invoke per message). Route/webhook/invoke
/// triggers are request-driven and not dispatched here.
#[cfg(feature = "handlers")]
async fn dispatch_function_triggers(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
    now: &CronNow,
) {
    use boatramp_core::function::TriggerKind;
    let triggers = match deploy.list_triggers(&function.name).await {
        Ok(t) => t,
        Err(err) => {
            tracing::warn!(function = %function.name, %err, "listing triggers failed");
            return;
        }
    };
    for mut trigger in triggers {
        match &trigger.kind {
            TriggerKind::Cron { schedule, .. } => {
                let Ok(parsed) = boatramp_core::cron::CronSchedule::parse(schedule) else {
                    continue;
                };
                if !parsed.fires_at(now.minute, now.hour, now.dom, now.month, now.dow) {
                    continue;
                }
                if trigger.last_fired_minute == Some(now.minute_stamp) {
                    continue; // already fired this minute
                }
                enqueue_scheduled_invocation(deploy, function).await;
                trigger.last_fired_minute = Some(now.minute_stamp);
                let _ = deploy.put_trigger(&function.name, &trigger).await;
            }
            TriggerKind::Queue { topic } => {
                dispatch_function_queue(inner, deploy, function, topic).await;
            }
            // Route / Invoke / Webhook are request-driven; Blob / Stream are not
            // dispatched from the scheduler in this pass.
            _ => {}
        }
    }
}

/// Enqueue a durable async invocation of a function's active version with no body
/// — the scheduled (cron) fire. The existing invoke drain runs it.
#[cfg(feature = "handlers")]
async fn enqueue_scheduled_invocation(
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
) {
    let now = now_unix();
    let inv = boatramp_core::function::Invocation {
        id: new_invocation_id(),
        function: function.name.clone(),
        version: function.active.clone(),
        mode: boatramp_core::function::InvokeMode::Async,
        status: boatramp_core::function::InvocationStatus::Queued,
        idempotency_key: None,
        attempts: 0,
        request_b64: None,
        request_content_type: None,
        result: None,
        created: now,
        updated: now,
    };
    if let Err(err) = deploy.put_invocation(&inv).await {
        tracing::warn!(function = %function.name, %err, "enqueuing scheduled invocation failed");
    }
}

/// Claim a batch from a function's queue-trigger topic and invoke the function per
/// message (ack on a delivered response, nack — for redelivery / eventual
/// dead-letter — otherwise). The topic is namespaced under the function's own
/// `fn/<name>/` scope, so it is a per-function work queue (fan-out to many
/// functions is future work).
#[cfg(feature = "handlers")]
async fn dispatch_function_queue(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    function: &boatramp_core::function::Function,
    topic: &str,
) {
    let Some(messaging) = inner.messaging.clone() else {
        return;
    };
    let namespaced = format!("fn/{}/{topic}", function.name);
    let batch = match messaging
        .claim(
            &namespaced,
            CONSUMER_LEASE,
            CONSUMER_BATCH,
            CONSUMER_MAX_ATTEMPTS,
        )
        .await
    {
        Ok(batch) => batch,
        Err(err) => {
            tracing::warn!(function = %function.name, topic, %err, "claiming queue messages failed");
            return;
        }
    };
    if batch.is_empty() {
        return;
    }
    let Some(component) = function.resolve(&function.active).map(str::to_owned) else {
        return;
    };
    for msg in batch {
        let bytes_in = msg.payload.len() as u64;
        let request = build_webhook_request(None, msg.payload.clone());
        let (response, duration_ms) =
            execute_function(inner, deploy, function, &component, request).await;
        let (status, _content_type, body) = capture_response(response).await;
        let delivered = status != StatusCode::INTERNAL_SERVER_ERROR
            && status != StatusCode::GATEWAY_TIMEOUT
            && status != StatusCode::SERVICE_UNAVAILABLE;
        let sample = boatramp_core::function::MeteringSample {
            success: delivered,
            duration_ms,
            bytes_in,
            bytes_out: body.len() as u64,
        };
        record_metering(inner, deploy, &function.name, &sample).await;
        if delivered {
            let _ = messaging.ack(&msg).await;
        } else {
            let _ = messaging.nack(&msg).await;
        }
    }
}

// ---- signed webhook ingress (FA-5) -------------------------------------------

/// `POST /_webhooks/:name` (FA-5) — signed inbound-webhook ingress. **Public** but
/// signature-gated: the request signature is verified over the raw body,
/// constant-time, **before** the guest runs (the SSRF/abuse guard). Requires the
/// function to declare a `webhook` config whose `secret_env` names a set host env
/// var. A valid signature invokes the function (sync, active version) and returns
/// its response; a missing/invalid signature is `401`, an oversize body `413`.
#[cfg(feature = "handlers")]
async fn webhook_ingress(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(name): Path<String>,
    request: Request,
) -> Response {
    let Some(inner) = handlers.inner.as_ref() else {
        return handler_unavailable();
    };
    let function = match deploy.get_function(&name).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, format!("no function {name:?}\n")).into_response()
        }
        Err(err) => return deploy_error_response(err),
    };
    let Some(webhook) = function.config.webhook.clone() else {
        return (
            StatusCode::NOT_FOUND,
            format!("function {name:?} has no webhook\n"),
        )
            .into_response();
    };
    // The verifying secret is a host env-var *reference*, never stored plaintext.
    let Ok(secret) = std::env::var(&webhook.secret_env) else {
        tracing::warn!(
            function = %name,
            env = %webhook.secret_env,
            "webhook secret env var is not set; refusing",
        );
        return (StatusCode::SERVICE_UNAVAILABLE, "webhook not configured\n").into_response();
    };
    // Capture the signature + content type *before* consuming the body.
    let provided = request
        .headers()
        .get(webhook.header())
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = match axum::body::to_bytes(request.into_body(), webhook.body_cap() as usize).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "webhook body exceeds the cap\n",
            )
                .into_response()
        }
    };
    let Some(provided) = provided else {
        return (StatusCode::UNAUTHORIZED, "missing webhook signature\n").into_response();
    };
    if !verify_webhook_signature(webhook.algorithm, secret.as_bytes(), &body, &provided) {
        return (StatusCode::UNAUTHORIZED, "invalid webhook signature\n").into_response();
    }
    // Rate-limit quota (fail-closed) applies to a verified webhook like any invoke.
    if let Err(response) = admit_by_quota(inner, &deploy, &function).await {
        return response;
    }
    let Some(component) = function.resolve(&function.active).map(str::to_owned) else {
        return handler_unavailable();
    };
    let bytes_in = body.len() as u64;
    let request = build_webhook_request(content_type, body.to_vec());
    let (response, duration_ms) =
        execute_function(inner, &deploy, &function, &component, request).await;
    let sample = boatramp_core::function::MeteringSample {
        success: response.status().as_u16() < 500,
        duration_ms,
        bytes_in,
        bytes_out: 0,
    };
    record_metering(inner, &deploy, &function.name, &sample).await;
    response
}

/// Verify a webhook signature over `body`, constant-time. HMAC-SHA256 accepts the
/// raw hex or a `sha256=`-prefixed hex (GitHub style).
#[cfg(feature = "handlers")]
fn verify_webhook_signature(
    algorithm: boatramp_core::function::WebhookAlgorithm,
    secret: &[u8],
    body: &[u8],
    provided: &str,
) -> bool {
    use boatramp_core::function::WebhookAlgorithm;
    use hmac::{Hmac, Mac};
    use subtle::ConstantTimeEq;
    match algorithm {
        WebhookAlgorithm::HmacSha256 => {
            let provided = provided.strip_prefix("sha256=").unwrap_or(provided);
            let Ok(provided_bytes) = hex::decode(provided) else {
                return false;
            };
            // HMAC accepts a key of any length, so this construction never fails.
            let Ok(mut mac) = <Hmac<sha2::Sha256> as Mac>::new_from_slice(secret) else {
                return false;
            };
            mac.update(body);
            let expected = mac.finalize().into_bytes();
            provided_bytes.ct_eq(&expected).into()
        }
    }
}

/// Build the engine request for a verified webhook: a `POST` carrying the raw body
/// (+ content type). `execute_function` rewrites the URI to the invoke authority.
#[cfg(feature = "handlers")]
fn build_webhook_request(content_type: Option<String>, body: Vec<u8>) -> Request {
    let mut builder = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/");
    if let Some(ct) = &content_type {
        if let Ok(value) = HeaderValue::from_str(ct) {
            builder = builder.header(header::CONTENT_TYPE, value);
        }
    }
    builder
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| Request::new(axum::body::Body::empty()))
}

// ---- workflow orchestration (FA-6) -------------------------------------------

/// Max request body buffered as a workflow run's initial input.
#[cfg(feature = "handlers")]
const MAX_WORKFLOW_INPUT_BYTES: usize = 1024 * 1024;

/// Body of `PUT /api/workflows/:name` — the step DAG (the name comes from the path).
#[cfg(feature = "handlers")]
#[derive(serde::Deserialize)]
struct WorkflowBody {
    steps: Vec<boatramp_core::workflow::Step>,
}

/// `PUT /api/workflows/:name` (FA-6) — define/replace a workflow. The DAG is
/// validated (unique ids, deps resolve, acyclic) before it is stored. `system·admin`.
#[cfg(feature = "handlers")]
async fn define_workflow(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
    Json(body): Json<WorkflowBody>,
) -> Response {
    let workflow = boatramp_core::workflow::Workflow {
        name: name.clone(),
        steps: body.steps,
    };
    if let Err(reason) = workflow.validate() {
        return (StatusCode::BAD_REQUEST, format!("{reason}\n")).into_response();
    }
    if let Err(err) = deploy.put_workflow(&workflow).await {
        return deploy_error_response(err);
    }
    Json(workflow).into_response()
}

/// `GET /api/workflows` (FA-6) — list workflow definitions. `system·read`.
#[cfg(feature = "handlers")]
async fn list_workflows_handler(State(deploy): State<DeployStore>) -> Response {
    match deploy.list_workflows().await {
        Ok(mut list) => {
            list.sort_by(|a, b| a.name.cmp(&b.name));
            Json(list).into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// `GET /api/workflows/:name` (FA-6) — a workflow definition. `system·read`.
#[cfg(feature = "handlers")]
async fn get_workflow_handler(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
) -> Response {
    match deploy.get_workflow(&name).await {
        Ok(Some(w)) => Json(w).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, format!("no workflow {name:?}\n")).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `DELETE /api/workflows/:name` (FA-6) — remove a workflow definition (runs are
/// left as history). `system·admin`. Idempotent.
#[cfg(feature = "handlers")]
async fn delete_workflow_handler(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
) -> Response {
    match deploy.delete_workflow(&name).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `POST /api/workflows/:name/runs` (FA-6) — start a run. The request body is the
/// run's initial input (delivered to the root steps). Returns `202` + the queued
/// run; the executor drain advances it. `system·admin`.
#[cfg(feature = "handlers")]
async fn start_workflow_run(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
    request: Request,
) -> Response {
    let workflow = match deploy.get_workflow(&name).await {
        Ok(Some(w)) => w,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, format!("no workflow {name:?}\n")).into_response()
        }
        Err(err) => return deploy_error_response(err),
    };
    let body = match axum::body::to_bytes(request.into_body(), MAX_WORKFLOW_INPUT_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "workflow input exceeds the cap\n",
            )
                .into_response()
        }
    };
    let now = now_unix();
    let id = new_invocation_id();
    let input_b64 = (!body.is_empty()).then(|| b64_encode(&body));
    let run = boatramp_core::workflow::WorkflowRun::start(&workflow, id, input_b64, now);
    if let Err(err) = deploy.put_workflow_run(&run).await {
        return deploy_error_response(err);
    }
    (StatusCode::ACCEPTED, Json(run)).into_response()
}

/// `GET /api/workflows/:name/runs/:id` (FA-6) — poll a run's status/step state.
/// `system·read`.
#[cfg(feature = "handlers")]
async fn get_workflow_run_handler(
    State(deploy): State<DeployStore>,
    Path((name, id)): Path<(String, String)>,
) -> Response {
    match deploy.get_workflow_run(&name, &id).await {
        Ok(Some(run)) => Json(run).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            format!("no run {id:?} for workflow {name:?}\n"),
        )
            .into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Drain a workflow's non-terminal runs, advancing each by one tick. Driven from
/// the scheduler tick, leader-gated like the invocation drain.
#[cfg(feature = "handlers")]
async fn drain_workflow_runs(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    workflow: &boatramp_core::workflow::Workflow,
) {
    let runs = match deploy.list_workflow_runs(&workflow.name).await {
        Ok(runs) => runs,
        Err(err) => {
            tracing::warn!(workflow = %workflow.name, %err, "listing workflow runs failed");
            return;
        }
    };
    for run in runs {
        if run.is_terminal() {
            continue;
        }
        advance_workflow_run(inner, deploy, workflow, run).await;
    }
}

/// Advance one run by a tick: run every ready step once, then settle the run
/// (succeeded when all steps did; failed + compensated when a step exhausted its
/// retries). A step whose function is missing or returns a `5xx` (engine wrapper)
/// is a failure, retried up to its `max_attempts`.
#[cfg(feature = "handlers")]
async fn advance_workflow_run(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    workflow: &boatramp_core::workflow::Workflow,
    mut run: boatramp_core::workflow::WorkflowRun,
) {
    use boatramp_core::workflow::StepStatus;
    let now = now_unix();
    for step_id in run.ready_steps(workflow) {
        let Some(step) = workflow.step(&step_id).cloned() else {
            continue;
        };
        let input = build_step_input(&run, &step);
        let outcome = run_workflow_step(inner, deploy, &step, input).await;
        let Some(sr) = run.steps.get_mut(&step_id) else {
            continue;
        };
        sr.attempts = sr.attempts.saturating_add(1);
        sr.updated = now;
        match outcome {
            Some(output) => {
                sr.status = StepStatus::Succeeded;
                sr.output_b64 = Some(b64_encode(&output));
                run.completed_order.push(step_id.clone());
            }
            None if sr.attempts >= step.retry.max_attempts => sr.status = StepStatus::Failed,
            None => sr.status = StepStatus::Pending, // retry next tick
        }
    }
    // Settle the run.
    let any_failed = run.steps.values().any(|r| r.status == StepStatus::Failed);
    if any_failed {
        compensate_run(inner, deploy, workflow, &mut run).await;
        run.status = boatramp_core::workflow::WorkflowStatus::Failed;
    } else if run.all_succeeded() {
        run.status = boatramp_core::workflow::WorkflowStatus::Succeeded;
    }
    run.updated = now_unix();
    let _ = deploy.put_workflow_run(&run).await;
}

/// Run a single step's function (active version) with `input` as its request body.
/// Returns the response body on a delivered guest response, or `None` on a
/// missing function / engine-level failure (a retryable step failure).
#[cfg(feature = "handlers")]
async fn run_workflow_step(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    step: &boatramp_core::workflow::Step,
    input: Vec<u8>,
) -> Option<Vec<u8>> {
    let function = match deploy.get_function(&step.function).await {
        Ok(Some(f)) => f,
        _ => return None,
    };
    let component = function.resolve(&function.active).map(str::to_owned)?;
    let request = build_step_request(input);
    let (response, _duration) =
        execute_function(inner, deploy, &function, &component, request).await;
    let (status, _content_type, body) = capture_response(response).await;
    // A guest response (any status the guest itself set, incl. 4xx) is delivered;
    // an engine wrapper 5xx (timeout/trap/overload/missing blob) is a failure.
    let delivered = status != StatusCode::INTERNAL_SERVER_ERROR
        && status != StatusCode::GATEWAY_TIMEOUT
        && status != StatusCode::SERVICE_UNAVAILABLE;
    delivered.then_some(body)
}

/// On a run failure, invoke each completed step's `compensate` function in reverse
/// completion order (best-effort) and mark those steps `compensated`.
#[cfg(feature = "handlers")]
async fn compensate_run(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    workflow: &boatramp_core::workflow::Workflow,
    run: &mut boatramp_core::workflow::WorkflowRun,
) {
    let completed = run.completed_order.clone();
    for step_id in completed.iter().rev() {
        let Some(step) = workflow.step(step_id) else {
            continue;
        };
        if let Some(compensate_fn) = &step.compensate {
            if let Ok(Some(function)) = deploy.get_function(compensate_fn).await {
                if let Some(component) = function.resolve(&function.active).map(str::to_owned) {
                    let request = build_step_request(Vec::new());
                    // Best-effort rollback; its outcome does not change the verdict.
                    let _ = execute_function(inner, deploy, &function, &component, request).await;
                }
            }
        }
        if let Some(sr) = run.steps.get_mut(step_id) {
            sr.status = boatramp_core::workflow::StepStatus::Compensated;
            sr.updated = now_unix();
        }
    }
}

/// The input a step's function receives: for a root step, the run's initial input;
/// otherwise a JSON object mapping each dependency's step id → its output (as a
/// string). Data-transform is deliberately minimal (the scope guard).
#[cfg(feature = "handlers")]
fn build_step_input(
    run: &boatramp_core::workflow::WorkflowRun,
    step: &boatramp_core::workflow::Step,
) -> Vec<u8> {
    if step.depends_on.is_empty() {
        return run.input_b64.as_deref().map(b64_decode).unwrap_or_default();
    }
    let mut map = serde_json::Map::new();
    for dep in &step.depends_on {
        let out = run
            .steps
            .get(dep)
            .and_then(|r| r.output_b64.as_deref())
            .map(b64_decode)
            .unwrap_or_default();
        map.insert(
            dep.clone(),
            serde_json::Value::String(String::from_utf8_lossy(&out).into_owned()),
        );
    }
    serde_json::to_vec(&serde_json::Value::Object(map)).unwrap_or_default()
}

/// Build the engine request for a step: a `POST` carrying the input body as JSON.
#[cfg(feature = "handlers")]
fn build_step_request(input: Vec<u8>) -> Request {
    axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(input))
        .unwrap_or_else(|_| Request::new(axum::body::Body::empty()))
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

#[derive(Deserialize)]
struct CreateTokenRequest {
    label: String,
    /// Role specs (`"<role>"` or `"<role>:<site>"`); at least one required.
    #[serde(default)]
    roles: Vec<String>,
    /// Optional TTL in seconds; omitted ⇒ no expiry.
    #[serde(default)]
    ttl_secs: Option<u64>,
    /// Optional holder public key (`"<alg>:<hex>"`) making the token
    /// **delegatable** (RFC 8747 `cnf`): the holder of the
    /// matching private key can mint narrowing delegation blocks offline. Absent ⇒
    /// a plain, non-delegatable token.
    #[serde(default)]
    holder_pubkey: Option<String>,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    /// The minted token (base64url `COSE_Sign1` CWT) — shown once, never stored.
    token: String,
    /// The revocation id (`cti`) — the `token rm` argument.
    id: String,
}

/// Mint a token carrying the requested roles and record its metadata. Needs the
/// token signer (the issuer); a verify-only node returns `501`. The token is
/// returned once and never stored — only its metadata is.
async fn create_token(
    State(deploy): State<DeployStore>,
    Extension(issuer): Extension<Issuer>,
    Json(request): Json<CreateTokenRequest>,
) -> Response {
    let Some(signer) = issuer.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node has no root private key and cannot issue tokens\n",
        )
            .into_response();
    };
    let roles: Vec<GrantedRole> = request
        .roles
        .iter()
        .map(|s| GrantedRole::parse(s))
        .collect();
    if roles.is_empty() {
        return (StatusCode::BAD_REQUEST, "at least one role is required\n").into_response();
    }
    let now = now_unix();
    let claims = Claims {
        roles: roles.clone(),
        kind: cose::KIND_ROLE.to_string(),
        ttl_secs: request.ttl_secs,
        now_unix: now,
    };
    // A `holder_pubkey` makes the token delegatable (embeds the holder `cnf`).
    let holder = match &request.holder_pubkey {
        Some(hex) => match cose::TokenPublicKey::from_hex(hex) {
            Ok(pk) => Some(pk),
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("invalid holder key: {err}\n"),
                )
                    .into_response()
            }
        },
        None => None,
    };
    let minted = match &holder {
        Some(holder) => cose::mint_delegatable(&claims, holder, &*signer).await,
        None => cose::mint(&claims, &*signer).await,
    };
    let token = match minted {
        Ok(t) => t,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    // The revocation id is the token's `cti`; read it back by verifying the
    // just-minted token against our own public key (always valid, unexpired).
    let id = match cose::verify(&token, &signer.public_key(), now) {
        Ok(v) => v.cti,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    let meta = TokenMeta {
        version: boatramp_core::SCHEMA_VERSION,
        label: request.label,
        roles,
        created_at: now,
        expires_at: request.ttl_secs.map(|t| now.saturating_add(t)),
        revocation_id: id.clone(),
    };
    match deploy.put_token_meta(&meta).await {
        Ok(()) => (StatusCode::CREATED, Json(CreateTokenResponse { token, id })).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

#[derive(Deserialize)]
struct BootstrapRequest {
    /// Roles for the first token. Defaults to `["admin"]` — the bootstrap token
    /// exists to configure the system (set policy, mint scoped tokens).
    #[serde(default)]
    roles: Vec<String>,
    /// TTL in seconds; defaults to 1 h so an unused first token expires on its own.
    ttl_secs: Option<u64>,
}

/// `POST /api/tokens/bootstrap` — mint the FIRST control-plane token by presenting
/// the operator-set, single-use **bootstrap secret** (as `Authorization: Bearer`),
/// not an admin token. RBAC-exempt at the router (`Right::required` → `None` for
/// exactly this path); this handler does the real verification. The token is
/// minted through the issuer (the root key never leaves the server), recorded as
/// [`TokenMeta`] (listable + revocable), and returned in the response — never
/// logged. `501` if bootstrap isn't enabled / this node can't issue; `401` on a
/// bad secret; `409` once the secret is spent (rotate it to re-bootstrap).
async fn bootstrap_token(
    State(deploy): State<DeployStore>,
    Extension(issuer): Extension<Issuer>,
    Extension(gate): Extension<BootstrapGate>,
    headers: axum::http::HeaderMap,
    Json(request): Json<BootstrapRequest>,
) -> Response {
    let Some(inner) = gate.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "bootstrap is not enabled on this node (set a bootstrap secret)\n",
        )
            .into_response();
    };
    let Some(signer) = issuer.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node has no root private key and cannot issue tokens\n",
        )
            .into_response();
    };
    // The presented secret arrives as the bearer (so `require_auth`'s presence
    // check passes). Compare by SHA-256 — the hash also keys the single-use marker.
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if boatramp_core::deploy::sha256_hex(presented.as_bytes()) != inner.secret_hash {
        return (StatusCode::UNAUTHORIZED, "invalid bootstrap secret\n").into_response();
    }
    // Serialize check-and-spend; the persisted marker makes it single-use across
    // restarts. Rotating the secret yields a fresh hash → re-enabled (recovery).
    let _guard = inner.lock.lock().await;
    match deploy.bootstrap_consumed(&inner.secret_hash).await {
        Ok(true) => {
            return (
                StatusCode::CONFLICT,
                "bootstrap secret already used — rotate it to re-bootstrap\n",
            )
                .into_response()
        }
        Ok(false) => {}
        Err(err) => return deploy_error_response(err),
    }
    let roles: Vec<GrantedRole> = if request.roles.is_empty() {
        vec![GrantedRole::parse("admin")]
    } else {
        request
            .roles
            .iter()
            .map(|s| GrantedRole::parse(s))
            .collect()
    };
    let now = now_unix();
    let ttl = request.ttl_secs.or(Some(3600));
    let claims = Claims {
        roles: roles.clone(),
        kind: cose::KIND_ROLE.to_string(),
        ttl_secs: ttl,
        now_unix: now,
    };
    let token = match cose::mint(&claims, &*signer).await {
        Ok(t) => t,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    let id = match cose::verify(&token, &signer.public_key(), now) {
        Ok(v) => v.cti,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    let meta = TokenMeta {
        version: boatramp_core::SCHEMA_VERSION,
        label: "bootstrap".to_string(),
        roles,
        created_at: now,
        expires_at: ttl.map(|t| now.saturating_add(t)),
        revocation_id: id.clone(),
    };
    if let Err(err) = deploy.put_token_meta(&meta).await {
        return deploy_error_response(err);
    }
    if let Err(err) = deploy.mark_bootstrap_consumed(&inner.secret_hash).await {
        return deploy_error_response(err);
    }
    tracing::warn!(cti = %id, "control-plane bootstrapped — first token minted via bootstrap secret");
    (StatusCode::CREATED, Json(CreateTokenResponse { token, id })).into_response()
}

#[derive(Deserialize)]
struct JoinRequest {
    /// The single-use **bearer** mesh join token (base64url), from `cluster add`.
    token: String,
    /// The joining node's own mesh public key (SPKI hex) — its self-derived
    /// identity. Not pre-authorized by the token; possession is proven below.
    mesh_pubkey: String,
    /// A **possession proof**: an Ed25519 signature (hex) over
    /// `cose::join_challenge(jti, mesh_pubkey, proof_iat)`, proving the joiner
    /// controls `mesh_pubkey` — so a token + an observed key admits nothing.
    possession_proof: String,
    /// The proof's issued-at (Unix seconds); must be fresh (anti-replay).
    proof_iat: u64,
    /// The joiner's own mesh base URL (e.g. `https://10.0.0.4:7000`) so the leader
    /// can dial it for Raft replication. Advisory routing only — the mesh TLS
    /// re-authenticates every dial by key. Absent ⇒ the joiner isn't reachable by
    /// address (the leader still admits it, but can't replicate until it learns one).
    #[serde(default)]
    advertise_addr: Option<String>,
}

#[derive(Serialize)]
struct JoinResponse {
    /// The cluster's current members as **root-signed** mesh-member assertions
    /// (base64url `COSE_Sign1`). The joiner verifies each against the root anchor
    /// before adding it to its trust set — so a malicious/stale seed can't inject a
    /// fabricated member (PLAN-cluster-join F3).
    members: Vec<String>,
    /// Advisory `node_id -> mesh URL` routing for the members, so the joiner can
    /// dial each one. Not signed (addressing is advisory; the mesh TLS
    /// re-authenticates by key), and only trusted for a `node_id` the joiner also
    /// verified via a root-signed member assertion above.
    #[serde(default)]
    member_addrs: std::collections::BTreeMap<u64, String>,
}

/// Admit a joining node presenting a mesh join token. Gated by
/// the token itself (`Right::required` returns `None` for this exact path), not
/// an admin bearer: the handler verifies the join token (signature + TTL),
/// confirms the presented `(node_id, pubkey)` is exactly the one the token
/// authorizes (a stolen token can't admit a different node/key), and hands the
/// verified claim to the cluster's [`MeshControl`] — which trusts the key
/// cluster-wide and adds membership, single-use enforced in the state machine.
/// `501` on a non-cluster node (no control hook) or a node without a root key.
async fn cluster_join(
    Extension(auth): Extension<Auth>,
    Extension(mesh_control): Extension<MeshControlHandle>,
    Json(request): Json<JoinRequest>,
) -> Response {
    let Some(admitter) = mesh_control.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node is not a cluster node\n",
        )
            .into_response();
    };
    let Some(public) = auth.public_key() else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "join requires control-plane auth (no root key configured)\n",
        )
            .into_response();
    };
    let _ = public; // presence gates 501; verification tries the anchor set below.
    let now = now_unix();
    let jti = match auth.verify_join_token(&request.token, now).await {
        Ok(jti) => jti,
        Err(err) => {
            // A signature/framing failure is unauthenticated (401); an authentic
            // token that is expired or the wrong kind is forbidden (403).
            let code = match err {
                cose::TokenError::Invalid(_) => StatusCode::UNAUTHORIZED,
                _ => StatusCode::FORBIDDEN,
            };
            return (code, format!("invalid join token: {err}\n")).into_response();
        }
    };
    let Ok(proof) = hex::decode(request.possession_proof.trim()) else {
        return (StatusCode::BAD_REQUEST, "possession_proof must be hex\n").into_response();
    };
    // The cluster verifies the possession proof against the presented key + spends
    // the token, then vouches for its members with root-signed assertions.
    match admitter
        .admit(
            request.mesh_pubkey.trim(),
            &jti,
            &proof,
            request.proof_iat,
            now,
            request.advertise_addr.as_deref(),
        )
        .await
    {
        Ok(JoinOutcome::Admitted { members, addrs }) => (
            StatusCode::OK,
            Json(JoinResponse {
                members,
                member_addrs: addrs,
            }),
        )
            .into_response(),
        Ok(JoinOutcome::TokenSpent) => {
            (StatusCode::CONFLICT, "join token already spent\n").into_response()
        }
        Ok(JoinOutcome::ProofInvalid) => (
            StatusCode::FORBIDDEN,
            "join possession proof is missing, stale, or invalid\n",
        )
            .into_response(),
        Ok(JoinOutcome::Revoked) => (
            StatusCode::FORBIDDEN,
            "this mesh key is revoked; an explicit un-revoke is required before it can rejoin\n",
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("admit failed: {err}\n"),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct RotateKeyResponse {
    /// The node's new mesh public key (SPKI hex) after rotation.
    pubkey: String,
}

/// Rotate **this node's** mesh identity, make-before-break.
/// Admin-scoped (the deny-safe `Right::required` default for `/api/cluster/*`).
/// Node-local: only the node itself can mint + persist its private key, so this
/// rotates the key of the node whose API is hit. `501` on a non-cluster node.
async fn cluster_rotate_key(Extension(mesh_control): Extension<MeshControlHandle>) -> Response {
    let Some(control) = mesh_control.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node is not a cluster node\n",
        )
            .into_response();
    };
    match control.rotate_key().await {
        Ok(pubkey) => (StatusCode::OK, Json(RotateKeyResponse { pubkey })).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("rotation failed: {err}\n"),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct RevokeRequest {
    /// The node id to revoke from the mesh.
    node_id: u64,
}

/// Revoke a node from the mesh: delete its trust cluster-wide (so
/// it can no longer authenticate — the live verifier rejects it on reconnect) and
/// drop it from the quorum. Admin-scoped (the deny-safe `Right::required`
/// default). `501` on a non-cluster node.
async fn cluster_revoke(
    Extension(mesh_control): Extension<MeshControlHandle>,
    Json(request): Json<RevokeRequest>,
) -> Response {
    let Some(control) = mesh_control.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node is not a cluster node\n",
        )
            .into_response();
    };
    match control.revoke(request.node_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("revocation failed: {err}\n"),
        )
            .into_response(),
    }
}

/// List the current Raft membership (`GET /api/cluster/members`) — voters +
/// learners with catch-up + leader flags. Admin-scoped (the deny-safe
/// `Right::required` default). `501` on a non-cluster node. The Kubernetes
/// operator reconciles this against the desired replica count.
async fn cluster_members(Extension(mesh_control): Extension<MeshControlHandle>) -> Response {
    let Some(control) = mesh_control.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node is not a cluster node\n",
        )
            .into_response();
    };
    match control.members().await {
        Ok(members) => Json(members).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("listing membership failed: {err}\n"),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct PromoteRequest {
    /// The node id (a caught-up learner) to promote to a voter.
    node_id: u64,
}

/// Promote a caught-up learner to a voter (`POST /api/cluster/promote`) — the
/// scale-up completion step the operator drives once a joined node has caught up.
/// Leader-only server-side (a no-op on a follower). Admin-scoped. `501` on a
/// non-cluster node.
async fn cluster_promote(
    Extension(mesh_control): Extension<MeshControlHandle>,
    Json(request): Json<PromoteRequest>,
) -> Response {
    let Some(control) = mesh_control.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node is not a cluster node\n",
        )
            .into_response();
    };
    match control.promote(request.node_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("promotion failed: {err}\n"),
        )
            .into_response(),
    }
}

/// List issued-token metadata (id, label, roles, timestamps — never the token).
async fn list_tokens(State(deploy): State<DeployStore>) -> Response {
    match deploy.list_token_meta().await {
        Ok(mut tokens) => {
            tokens.sort_by_key(|m| m.created_at);
            Json(tokens).into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Revoke a token by its revocation id or a unique id prefix.
async fn revoke_token(State(deploy): State<DeployStore>, Path(id): Path<String>) -> Response {
    match deploy.revoke_token(&id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no matching token\n").into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Default mesh-join-token TTL when the request omits one (1 hour). A join is a
/// prompt operator action, so the admission window stays short.
const DEFAULT_JOIN_TOKEN_TTL_SECS: u64 = 3600;

#[derive(Deserialize, Default)]
struct CreateJoinTokenRequest {
    /// Optional TTL in seconds; omitted ⇒ [`DEFAULT_JOIN_TOKEN_TTL_SECS`].
    #[serde(default)]
    ttl_secs: Option<u64>,
}

#[derive(Serialize)]
struct CreateJoinTokenResponse {
    /// The minted join token, base64url — shown once, never stored.
    token: String,
    /// The token's expiry (Unix seconds).
    expires_at: u64,
}

/// Mint a **single-use bearer mesh join token** with a TTL. It is not bound to a
/// node/key (the operator can't know a not-yet-booted node's key); the joiner
/// proves possession of its own mesh key at redemption, and the `jti` is spent
/// single-use cluster-side. Needs the root private key (the issuer); a verify-only
/// node returns `501`. Admin-scoped (the deny-safe `Right::required` default gates
/// `/api/cluster/*`). Returned once, never stored.
async fn create_join_token(
    Extension(issuer): Extension<Issuer>,
    Json(request): Json<CreateJoinTokenRequest>,
) -> Response {
    let Some(signer) = issuer.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node has no root private key and cannot issue join tokens\n",
        )
            .into_response();
    };
    let ttl = request.ttl_secs.unwrap_or(DEFAULT_JOIN_TOKEN_TTL_SECS);
    let now = now_unix();
    match cose::mint_join(ttl, now, &*signer).await {
        Ok(token) => (
            StatusCode::CREATED,
            Json(CreateJoinTokenResponse {
                token,
                expires_at: now.saturating_add(ttl),
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

/// A principal's own identity (`GET /api/auth/whoami`): the roles its token
/// grants. Gated only by holding a valid token (the handler verifies it).
#[derive(Serialize)]
struct WhoAmI {
    /// Whether control-plane auth is enabled on this node.
    auth_enabled: bool,
    /// The roles carried by the presented token.
    roles: Vec<GrantedRole>,
}

async fn auth_whoami(Extension(auth): Extension<Auth>, headers: HeaderMap) -> Response {
    if auth.is_disabled() {
        // Auth disabled (dev): no identity to report.
        return Json(WhoAmI {
            auth_enabled: false,
            roles: Vec::new(),
        })
        .into_response();
    }
    let Some(bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return (StatusCode::UNAUTHORIZED, "missing bearer token\n").into_response();
    };
    // Full validation (signature + TTL + revocation + caveats), not a bare
    // signature check, so an expired/revoked token can't disclose its roles.
    match auth.verify_bearer_roles(bearer).await {
        Some(roles) => Json(WhoAmI {
            auth_enabled: true,
            roles,
        })
        .into_response(),
        None => (StatusCode::UNAUTHORIZED, "invalid token\n").into_response(),
    }
}

/// Return the active RBAC policy (`authz/policy`), or the built-in default when
/// none is stored — so a `get` always shows the effective policy.
async fn get_authz_policy(State(deploy): State<DeployStore>) -> Response {
    match deploy.get_authz_policy().await {
        Ok(Some(policy)) => Json(policy).into_response(),
        Ok(None) => Json(boatramp_core::authz::AuthzPolicy::default_policy()).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Replace the RBAC policy. Rejected (`400`) unless it compiles to a valid Cedar
/// policy set, so a bad policy can never be stored and brick the edge.
async fn put_authz_policy(
    State(deploy): State<DeployStore>,
    Json(policy): Json<boatramp_core::authz::AuthzPolicy>,
) -> Response {
    if let Err(err) = boatramp_core::cedar::CompiledCedar::compile(&policy) {
        return (StatusCode::BAD_REQUEST, format!("invalid policy: {err}\n")).into_response();
    }
    match deploy.set_authz_policy(&policy).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// The extra trusted root anchors (make-before-break rotation).
async fn list_root_anchors(State(deploy): State<DeployStore>) -> Response {
    match deploy.list_root_anchors().await {
        Ok(anchors) => (StatusCode::OK, Json(anchors)).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

#[derive(Deserialize)]
struct RootAnchorRequest {
    /// The `alg:hex`-encoded root public key to trust alongside the primary.
    pubkey: String,
}

/// Trust an additional root anchor — rejects anything that isn't a valid
/// `TokenPublicKey` so a malformed anchor can never be added.
async fn add_root_anchor(
    State(deploy): State<DeployStore>,
    Json(req): Json<RootAnchorRequest>,
) -> Response {
    let pubkey = req.pubkey.trim();
    if cose::TokenPublicKey::from_hex(pubkey).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            "pubkey must be an alg:hex TokenPublicKey (e.g. es256:…)\n",
        )
            .into_response();
    }
    match deploy.add_root_anchor(pubkey).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Retire a root anchor (the old key, after a rotation propagates).
async fn remove_root_anchor(
    State(deploy): State<DeployStore>,
    Path(pubkey): Path<String>,
) -> Response {
    match deploy.remove_root_anchor(pubkey.trim()).await {
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

/// A request's network identity, threaded into the serving pipeline for
/// access control: the socket peer plus the shared rate limiter.
struct Visitor<'a> {
    peer: IpAddr,
    limiter: &'a dyn RateLimitStore,
}

/// Serve under the explicit by-name admin/testing route `/_sites/<site>/...`.
/// The catch-all captures `<site>` or `<site>/<path...>`. Accepts any method so a
/// proxy rewrite can forward non-`GET` requests. This route is not host-routed and
/// does not serve a root-mounted site — for that, use host routing (see the
/// addressing docs).
async fn serve_sites(
    State(deploy): State<DeployStore>,
    Extension(limiter): Extension<Arc<dyn RateLimitStore>>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let raw = request.uri().path();
    let rest = raw
        .strip_prefix("/_sites/")
        .unwrap_or("")
        .trim_start_matches('/');
    let (site, path) = rest.split_once('/').unwrap_or((rest, ""));
    if site.is_empty() {
        return not_found();
    }
    let (site, request_path) = (site.to_string(), format!("/{path}"));
    let visitor = Visitor {
        peer: peer.ip(),
        limiter: limiter.as_ref(),
    };
    // The explicit `/_sites/<name>/` admin/testing route is not host-routed, so
    // transport/canonical redirects don't apply.
    serve_request(
        &deploy,
        &site,
        &request_path,
        request,
        &visitor,
        &handlers,
        false,
    )
    .await
}

/// The root-key-signed bootstrap-TLS identity attestation (base64url
/// `COSE_Sign1`), carried as an extension for [`serve_bootstrap_identity`].
#[derive(Clone)]
struct BootstrapAttestation(Option<String>);

/// `GET /.well-known/boatramp-bootstrap-identity` — serve the root-key attestation
/// of this node's `--tls rpk` control-plane TLS key. Public + unauthenticated: a
/// signed statement that reveals nothing (the TLS public key is already presented
/// in the handshake). A client pinning only the root key verifies it (root
/// signature + validity), extracts the attested TLS key, and pins it. `404` when
/// no attestation is set (not `--tls rpk`, or a verify-only node with no issuer).
async fn serve_bootstrap_identity(Extension(att): Extension<BootstrapAttestation>) -> Response {
    match att.0 {
        Some(a) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            a,
        )
            .into_response(),
        None => not_found(),
    }
}

/// Serve a pending **HTTP domain-ownership challenge** from the edge, *before*
/// host routing — the fix for the verify-before-attach chicken-and-egg. A host
/// pointed at this server but not yet attached to any site (so it would
/// otherwise fall through to `default_site` and 404 its own challenge) fetches
/// its token here, letting `domain verify` succeed with no prior deploy. Returns
/// the token for a matching `(Host, token)` pending HTTP challenge, else `404`.
///
/// Gated by the `domain_verify_self_serve` posture knob (on by default). It only
/// ever echoes back a random token to the very host that owns the pending
/// challenge, so it leaks nothing and needs no auth (like an ACME http-01
/// challenge). Mounted on both the main router and the `:80` redirect router, so
/// the plain-HTTP probe is answered directly instead of 308-redirected to an
/// HTTPS endpoint that may have no cert yet.
async fn serve_domain_challenge(
    State(deploy): State<DeployStore>,
    Extension(posture): Extension<boatramp_core::security::SecurityPosture>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !posture.domain_verify_self_serve {
        return not_found();
    }
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(strip_port)
    else {
        return not_found();
    };
    match deploy
        .find_pending_http_challenge(host, &token, now_unix())
        .await
    {
        Ok(Some(v)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            v.token,
        )
            .into_response(),
        Ok(None) => not_found(),
        Err(err) => deploy_error_response(err),
    }
}

/// Virtualhost fallback: resolve the site from the `Host` header, serve the
/// request path. Catches everything not matched by `/healthz`, `/api/*`, or the
/// explicit `/_sites/*` route.
#[allow(clippy::too_many_arguments)] // axum extractors, not a real parameter list
async fn serve_by_host(
    State(deploy): State<DeployStore>,
    Extension(limiter): Extension<Arc<dyn RateLimitStore>>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(daemon): Extension<Arc<DaemonRuntime>>,
    Extension(implicit): Extension<ImplicitRouting>,
    Extension(preview_auth): Extension<Auth>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    // Catch-all site + preview protection are read live from the daemon-config
    // runtime, so `config set default_site …` / `protect_previews …` take effect
    // without a restart.
    let effective = daemon.effective();
    let preview_policy = PreviewPolicy {
        protect: effective.protect_previews,
    };
    let Some(host) = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(strip_port)
        .map(str::to_string)
    else {
        return not_found();
    };
    let request_path = request.uri().path().to_string();
    // Wildcard preview host form `<id>.deploy.<site-host>`: the deploy id rides
    // as a subdomain (an unguessable content-hash capability, like the path form
    // `<site-host>/_deploy/<id>/…`). The remaining host resolves the site, and
    // the deployment is served with a preview-scoped binding identity. Falls
    // through to normal virtualhost routing when the host isn't a preview host.
    if let Some((id_prefix, site_host)) = parse_deploy_host(&host) {
        if let Some(blocked) =
            preview_auth_gate(preview_policy, &preview_auth, request.headers()).await
        {
            return blocked;
        }
        return serve_host_preview(
            &deploy,
            &handlers,
            peer.ip(),
            &request_path,
            request,
            id_prefix,
            site_host,
        )
        .await;
    }
    match deploy.resolve_site_by_host(&host).await {
        Ok(Some(site)) => {
            let visitor = Visitor {
                peer: peer.ip(),
                limiter: limiter.as_ref(),
            };
            // Host-routed: transport/canonical redirects + HSTS apply.
            serve_request(
                &deploy,
                &site,
                &request_path,
                request,
                &visitor,
                &handlers,
                true,
            )
            .await
        }
        // Unmatched host — no verified, attached virtualhost. Resolution order:
        //   (0) mandatory verification — a **non-local** host that isn't verified
        //       gets the "verification pending" page (421), never a fallback;
        //   (A) implicit first-label routing — `<site>.host` names a served site;
        //   the configured catch-all `default_site` (explicit operator intent).
        // (A) runs only when `implicit` is on (dev / single-tenant / a loopback
        // bind). There is deliberately no implicit *sole-site* auto-default: an
        // operator makes a site the catch-all explicitly with `default_site`.
        Ok(None) => {
            // (0) Strict gate (DV-2): a non-local public host that matched no
            // verified virtualhost is refused with the holding page — so
            // `default_site`/implicit never silently serve an unverified host.
            // Local hosts (localhost/*.localhost/*.local/IPs) and a fleet with the
            // gate off (`[security] require_domain_verification = false`, or an
            // admin `domain add --unverified` that attached the host above) pass.
            if effective.posture.require_domain_verification && !is_local_host(&host, implicit.0) {
                return verification_pending_page(&deploy, &host).await;
            }
            // (A) First host label naming a served site: `blog.localhost` → `blog`.
            if implicit.0 {
                let label = host.split('.').next().unwrap_or("");
                if !label.is_empty() && matches!(deploy.current_id(label).await, Ok(Some(_))) {
                    let visitor = Visitor {
                        peer: peer.ip(),
                        limiter: limiter.as_ref(),
                    };
                    return serve_request(
                        &deploy,
                        label,
                        &request_path,
                        request,
                        &visitor,
                        &handlers,
                        true,
                    )
                    .await;
                }
            }
            match effective.default_site.as_deref() {
                Some(site) => {
                    let visitor = Visitor {
                        peer: peer.ip(),
                        limiter: limiter.as_ref(),
                    };
                    serve_request(
                        &deploy,
                        site,
                        &request_path,
                        request,
                        &visitor,
                        &handlers,
                        true,
                    )
                    .await
                }
                None => not_found(),
            }
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Serve a wildcard-host preview: resolve `id_prefix` to a full deployment id
/// and `site_host` to a site, then run the deployment with a **preview-scoped**
/// binding identity (like [`serve_preview`], but reached by subdomain). Handlers
/// run only when the host resolves to a real site; otherwise the preview serves
/// static content only. No visitor access control — the unguessable id is the
/// capability (consistent with the path-form preview).
#[allow(clippy::too_many_arguments)]
async fn serve_host_preview(
    deploy: &DeployStore,
    handlers: &HandlerRuntime,
    peer: IpAddr,
    request_path: &str,
    request: Request,
    id_prefix: &str,
    site_host: &str,
) -> Response {
    let id = match deploy.resolve_manifest_id(id_prefix).await {
        Ok(Some(id)) => id,
        Ok(None) => return not_found(),
        Err(err) => return deploy_error_response(err),
    };
    let site = match deploy.resolve_site_by_host(site_host).await {
        Ok(site) => site,
        Err(err) => return deploy_error_response(err),
    };
    let site_config = match &site {
        Some(site) => match deploy.get_site_config(site).await {
            Ok(config) => config,
            Err(err) => return deploy_error_response(err),
        },
        None => None,
    };
    match deploy.get_manifest(&id).await {
        Ok(Some(manifest)) => {
            serve_resolved(
                deploy,
                &manifest,
                request_path,
                request,
                peer,
                site.as_deref(),
                site_config.as_ref(),
                handlers,
                Some(&id),
            )
            .await
        }
        Ok(None) => not_found(),
        Err(err) => deploy_error_response(err),
    }
}

/// Run the serving pipeline for a resolved `site` and request path: apply the
/// deploy config (redirects, rewrites/SPA, clean URLs, custom 404, headers,
/// cache) via [`route::resolve`], then HTTP correctness (conditional `304`,
/// `Range`/`206`, `ETag`).
async fn serve_request(
    deploy: &DeployStore,
    site: &str,
    request_path: &str,
    request: Request,
    visitor: &Visitor<'_>,
    handlers: &HandlerRuntime,
    host_routed: bool,
) -> Response {
    // Load the site config once (for access policy + client-IP resolution).
    let site_config = match deploy.get_site_config(site).await {
        Ok(config) => config,
        Err(err) => return deploy_error_response(err),
    };

    // Transport redirects + HSTS. The effective scheme
    // honors `X-Forwarded-Proto` **only from a configured trusted proxy**
    // — otherwise a direct HTTP client could forge `…: https` to
    // skip the HTTPS redirect. For an untrusted/direct peer the scheme is the
    // listener's own (TLS ⇒ `https`, else `http`). Host-routed traffic only.
    let listener_scheme = if request
        .extensions()
        .get::<ServedOverTls>()
        .map(|s| s.0)
        .unwrap_or(false)
    {
        "https"
    } else {
        "http"
    };
    let peer_trusted = site_config
        .as_ref()
        .map(|c| c.access.is_trusted_proxy(visitor.peer))
        .unwrap_or(false);
    let effective_scheme = if peer_trusted {
        request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(listener_scheme)
            .to_string()
    } else {
        listener_scheme.to_string()
    };
    // Captured before the request body is consumed, for on-the-fly compression.
    #[cfg(feature = "compression")]
    let accept_encoding = request
        .headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    // Site-tier security response headers, applied (host-routed only) after the
    // response is built: HSTS (HTTPS only), plus opt-in CSP / X-Frame-Options.
    let mut security_headers: Vec<(HeaderName, String)> = Vec::new();
    if host_routed {
        if let Some(cfg) = site_config.as_ref() {
            let host = request
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(strip_port)
                .unwrap_or("");
            let path_and_query = request
                .uri()
                .path_and_query()
                .map(axum::http::uri::PathAndQuery::as_str)
                .unwrap_or(request_path);
            if let Some(target) = boatramp_core::config::transport_redirect(
                &cfg.security,
                &cfg.domains,
                &effective_scheme,
                host,
                path_and_query,
            ) {
                return redirect_to(&target);
            }
            // HSTS only over HTTPS (it's meaningless / ignored over plain HTTP).
            if effective_scheme == "https" {
                if let Some(hsts) = cfg.security.hsts.as_ref() {
                    security_headers.push((
                        HeaderName::from_static("strict-transport-security"),
                        hsts.header_value(),
                    ));
                }
            }
            // CSP + X-Frame-Options apply on either scheme, when configured.
            if let Some(csp) = cfg.security.csp.as_deref() {
                security_headers.push((header::CONTENT_SECURITY_POLICY, csp.to_string()));
            }
            if let Some(frame) = cfg.security.frame_options.as_deref() {
                security_headers.push((header::X_FRAME_OPTIONS, frame.to_string()));
            }
        }
    }

    let access = site_config.as_ref().map(|c| &c.access);

    // Resolve the real client IP, honoring X-Forwarded-For only from a
    // configured trusted proxy.
    let trusted = access.map(|a| a.trusted_proxies.as_slice()).unwrap_or(&[]);
    let forwarded_for = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());
    let client_ip = boatramp_core::access::resolve_client_ip(visitor.peer, forwarded_for, trusted);

    // Visitor access control (WAF → IP rules → rate limit → basic auth) runs
    // before any content is read.
    if let Some(access) = access {
        if let Some(denied) = enforce_access(
            access,
            site,
            request.headers(),
            request_path,
            client_ip,
            visitor.limiter,
        )
        .await
        {
            return denied;
        }
    }

    let manifest = match deploy.current_manifest(site).await {
        Ok(Some(manifest)) => manifest,
        Ok(None) => return not_found(),
        Err(err) => return deploy_error_response(err),
    };
    let mut response = serve_resolved(
        deploy,
        &manifest,
        request_path,
        request,
        client_ip,
        Some(site),
        site_config.as_ref(),
        handlers,
        None,
    )
    .await;
    // Site-tier security headers (HSTS / CSP / X-Frame-Options), computed above.
    for (name, value) in security_headers {
        if let Ok(value) = HeaderValue::from_str(&value) {
            response.headers_mut().insert(name, value);
        }
    }
    // On-the-fly compression (opt-in per site; covers dynamic + variant-less
    // static responses). A no-op without the `compression` feature.
    #[cfg(feature = "compression")]
    let response = match site_config.as_ref() {
        Some(cfg) if cfg.compression.enabled => maybe_compress(
            response,
            accept_encoding.as_deref(),
            cfg.compression.min_size,
        ),
        _ => response,
    };
    response
}

/// When previews are protected, require a valid control-plane token. Returns
/// `Some(401)` to block, `None` to allow. "Any valid token" (no scope needed).
async fn preview_auth_gate(
    policy: PreviewPolicy,
    auth: &Auth,
    headers: &HeaderMap,
) -> Option<Response> {
    if !policy.protect {
        return None;
    }
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let ok = match bearer {
        Some(token) => auth.verify_bearer(token).await,
        None => false,
    };
    (!ok).then(|| {
        (
            StatusCode::UNAUTHORIZED,
            "preview requires a valid bearer token\n",
        )
            .into_response()
    })
}

/// A `301 Moved Permanently` to `target` (transport/canonical redirects).
fn redirect_to(target: &str) -> Response {
    match HeaderValue::from_str(target) {
        Ok(location) => (
            StatusCode::MOVED_PERMANENTLY,
            [(header::LOCATION, location)],
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "bad redirect target\n").into_response(),
    }
}

/// A standalone router for a plain `:80` listener that permanently redirects
/// every request to its HTTPS equivalent. Bound alongside the HTTPS listener so
/// plain-HTTP visitors are upgraded even when boatramp terminates TLS itself.
///
/// It does serve one thing directly rather than redirecting: the HTTP
/// domain-ownership challenge (`/.well-known/boatramp-domain-verification/…`).
/// That probe arrives on plain `:80` for a host that may have no cert yet, so a
/// 308 to HTTPS would bounce it to an endpoint that can't answer — the token
/// must be served here. (ACME's own challenges use ALPN-01/DNS-01, so there is
/// no `/.well-known/acme-challenge` to serve.)
pub fn http_redirect_router(
    deploy: DeployStore,
    posture: boatramp_core::security::SecurityPosture,
) -> Router {
    Router::new()
        .route(
            "/.well-known/boatramp-domain-verification/:token",
            get(serve_domain_challenge),
        )
        .fallback(redirect_http_to_https)
        .with_state(deploy)
        .layer(Extension(posture))
}

/// 308-redirect any request to `https://<host><path-and-query>` (308 preserves
/// the method/body, unlike 301).
async fn redirect_http_to_https(req: Request) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(strip_port)
        .unwrap_or("");
    if host.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing Host header\n").into_response();
    }
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(axum::http::uri::PathAndQuery::as_str)
        .unwrap_or("/");
    match HeaderValue::from_str(&format!("https://{host}{path_and_query}")) {
        Ok(location) => (
            StatusCode::PERMANENT_REDIRECT,
            [(header::LOCATION, location)],
        )
            .into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "invalid host\n").into_response(),
    }
}

/// Evaluate a site's [`AccessConfig`] against an already-resolved `client_ip`.
/// Returns `Some(response)` to short-circuit (403/429/401), or `None` to allow.
/// Order: WAF → IP rules → rate limit → basic auth. `async` because the
/// cluster-wide rate-limit store does a KV round-trip.
async fn enforce_access(
    access: &AccessConfig,
    site: &str,
    req_headers: &HeaderMap,
    path: &str,
    client_ip: IpAddr,
    limiter: &dyn RateLimitStore,
) -> Option<Response> {
    if !access.is_enforced() {
        return None;
    }
    // WAF (user-agent rules + anomaly scoring) is the outermost filter: a blocked
    // request shouldn't reach rate limiting or auth.
    if access.waf.is_enabled() {
        let header_str = |name| req_headers.get(name).and_then(|v| v.to_str().ok());
        let waf_req = boatramp_core::waf::WafRequest {
            user_agent: header_str(header::USER_AGENT),
            accept: header_str(header::ACCEPT),
            path,
        };
        if let boatramp_core::waf::WafVerdict::Block(reason) =
            boatramp_core::waf::evaluate(&access.waf, &waf_req)
        {
            tracing::debug!(%client_ip, site, %reason, "request blocked by WAF");
            return Some((StatusCode::FORBIDDEN, "forbidden\n").into_response());
        }
    }
    if !access.ip.allows(client_ip) {
        tracing::debug!(%client_ip, site, "request blocked by IP rules");
        return Some((StatusCode::FORBIDDEN, "forbidden\n").into_response());
    }
    if let Some(limit) = &access.rate_limit {
        if !limiter.check(site, client_ip, limit).await {
            return Some(too_many_requests());
        }
    }
    if let Some(basic) = &access.basic_auth {
        if !verify_basic_auth(basic, req_headers) {
            return Some(basic_auth_challenge(basic));
        }
    }
    None
}

/// Verify an HTTP `Authorization: Basic` header against the site credentials.
fn verify_basic_auth(basic: &BasicAuth, req_headers: &HeaderMap) -> bool {
    use base64::Engine;
    let Some(encoded) = req_headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
    else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
        return false;
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return false;
    };
    match text.split_once(':') {
        Some((user, pass)) => basic.verify(user, pass),
        None => false,
    }
}

/// `401` with a `WWW-Authenticate: Basic` challenge.
fn basic_auth_challenge(basic: &BasicAuth) -> Response {
    let realm = basic.realm.replace(['"', '\\'], "");
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&format!("Basic realm=\"{realm}\", charset=\"UTF-8\""))
    {
        headers.insert(header::WWW_AUTHENTICATE, value);
    }
    (
        StatusCode::UNAUTHORIZED,
        headers,
        "authentication required\n",
    )
        .into_response()
}

/// `429 Too Many Requests` with a `Retry-After`.
fn too_many_requests() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    (
        StatusCode::TOO_MANY_REQUESTS,
        headers,
        "rate limit exceeded\n",
    )
        .into_response()
}

/// Serve an immutable deployment by id under `/_deploy/<id>/...`. Like
/// [`serve_sites`], a single catch-all captures `<id>` or `<id>/<path...>`, so
/// `/_deploy/<id>`, `/_deploy/<id>/`, and `/_deploy/<id>/about` all route here.
async fn serve_preview(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(daemon): Extension<Arc<DaemonRuntime>>,
    Extension(preview_auth): Extension<Auth>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let preview_policy = PreviewPolicy {
        protect: daemon.effective().protect_previews,
    };
    if let Some(blocked) = preview_auth_gate(preview_policy, &preview_auth, request.headers()).await
    {
        return blocked;
    }
    let raw = request.uri().path();
    let rest = raw
        .strip_prefix("/_deploy/")
        .unwrap_or("")
        .trim_start_matches('/');
    let (id, path) = rest.split_once('/').unwrap_or((rest, ""));
    if id.is_empty() {
        return not_found();
    }
    let (id, request_path) = (id.to_string(), format!("/{path}"));
    // When the preview is reached via the *site's own hostname*
    // (`site.example.com/_deploy/<id>/…`), resolve that site so handlers can run
    // — with **preview-scoped** bindings (`Some(&id)` below) so they never touch
    // the live site's kv/blob/sql. Reached via any other host
    // (no site resolves), handlers stay off — the preview serves static only.
    let site = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(strip_port);
    let site = match site {
        Some(host) => match deploy.resolve_site_by_host(host).await {
            Ok(site) => site,
            Err(err) => return deploy_error_response(err),
        },
        None => None,
    };
    let site_config = match &site {
        Some(site) => match deploy.get_site_config(site).await {
            Ok(config) => config,
            Err(err) => return deploy_error_response(err),
        },
        None => None,
    };
    match deploy.get_manifest(&id).await {
        Ok(Some(manifest)) => {
            serve_resolved(
                &deploy,
                &manifest,
                &request_path,
                request,
                peer.ip(),
                site.as_deref(),
                site_config.as_ref(),
                &handlers,
                Some(&id),
            )
            .await
        }
        Ok(None) => not_found(),
        Err(err) => deploy_error_response(err),
    }
}

/// Run the deploy-config routing pipeline against a resolved `manifest`, then
/// stream the chosen entry (or proxy). `client_ip` is the resolved visitor
/// address (for proxy `X-Forwarded-For`).
/// Build the [`RequestContext`](boatramp_core::predicate::RequestContext) a
/// conditional-routing `when` predicate reads from the live request. Only called
/// when the deployment actually has conditional rules, so the non-conditional hot
/// path never pays for it.
fn build_request_context(request: &Request) -> boatramp_core::predicate::RequestContext {
    use boatramp_core::predicate::RequestContext;
    let headers = request.headers();
    let mut hmap: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (name, value) in headers {
        if let Ok(v) = value.to_str() {
            hmap.entry(name.as_str().to_ascii_lowercase())
                .and_modify(|e| {
                    e.push_str(", ");
                    e.push_str(v);
                })
                .or_insert_with(|| v.to_string());
        }
    }
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default();
    let cookies = headers
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .map(parse_cookie_header)
        .unwrap_or_default();
    let query = request
        .uri()
        .query()
        .map(parse_query_string)
        .unwrap_or_default();
    let accept_languages = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|h| h.to_str().ok())
        .map(RequestContext::parse_accept_language)
        .unwrap_or_default();
    RequestContext {
        method: request.method().as_str().to_ascii_uppercase(),
        host,
        headers: hmap,
        cookies,
        query,
        accept_languages,
    }
}

/// Parse a `Cookie` header into name→value pairs (first value wins).
fn parse_cookie_header(raw: &str) -> std::collections::BTreeMap<String, String> {
    raw.split(';')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .fold(std::collections::BTreeMap::new(), |mut m, (k, v)| {
            m.entry(k).or_insert(v);
            m
        })
}

/// Parse a URL query string into key→value pairs (first value wins), with
/// `application/x-www-form-urlencoded` decoding (`+` → space, `%XX` → byte) so a
/// condition compares against the real value.
fn parse_query_string(raw: &str) -> std::collections::BTreeMap<String, String> {
    raw.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .fold(std::collections::BTreeMap::new(), |mut m, (k, v)| {
            m.entry(k).or_insert(v);
            m
        })
}

/// Decode a `application/x-www-form-urlencoded` component: `+` → space, `%XX` →
/// the byte, everything else verbatim. Invalid `%` escapes are left as-is;
/// non-UTF-8 results are lossily replaced.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Merge conditional-routing `Vary` header names into a response, so a per-visitor
/// (language/cookie/header) redirect or page is never shared across visitors by a
/// downstream cache. A no-op when `vary` is empty (the non-conditional case).
fn apply_vary(mut response: Response, vary: &[String]) -> Response {
    if vary.is_empty() {
        return response;
    }
    let mut names: Vec<String> = response
        .headers()
        .get(header::VARY)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_ascii_lowercase())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default();
    for v in vary {
        if !names.iter().any(|n| n == v) {
            names.push(v.clone());
        }
    }
    if let Ok(hv) = HeaderValue::from_str(&names.join(", ")) {
        response.headers_mut().insert(header::VARY, hv);
    }
    response
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(feature = "handlers"), allow(unused_variables))]
async fn serve_resolved(
    deploy: &DeployStore,
    manifest: &Manifest,
    request_path: &str,
    request: Request,
    client_ip: IpAddr,
    site: Option<&str>,
    site_config: Option<&SiteConfig>,
    handlers: &HandlerRuntime,
    // `Some(deploy_id)` when serving a by-id preview, so handler bindings get a
    // preview-scoped identity; `None` for live serving.
    preview: Option<&str>,
) -> Response {
    // Evaluate conditional (`when`) routing against the request. The request
    // context is built only when the deploy has conditional rules, and `vary`
    // carries the request dimensions those conditions read (applied to the
    // response below so a per-language/-cookie outcome isn't wrongly cached).
    let ctx = if manifest.config.redirects.iter().any(|r| r.when.is_some())
        || manifest.config.rewrites.iter().any(|r| r.when.is_some())
    {
        build_request_context(&request)
    } else {
        boatramp_core::predicate::RequestContext::default()
    };
    let route::ResolveResult { outcome, vary } =
        route::resolve_ctx(&manifest.config, &manifest.files, request_path, &ctx);
    // Routing precedence: redirects win over handlers, which
    // win over rewrites/static. A redirect short-circuits below; otherwise a
    // matching handler is dispatched in preference to the file/rewrite outcome.
    #[cfg(feature = "handlers")]
    if !matches!(outcome, Outcome::Redirect { .. }) {
        if let Some(site) = site {
            if let Some(handler) = route::match_handler(
                &manifest.config.handlers,
                request.method().as_str(),
                request_path,
            ) {
                return apply_vary(
                    dispatch_handler(
                        handlers,
                        deploy,
                        manifest,
                        site,
                        request_path,
                        site_config,
                        handler,
                        request,
                        client_ip,
                        preview,
                    )
                    .await,
                    &vary,
                );
            }
            // No handler matched: a GET to a configured SSE stream route fans out
            // its messaging topics. Streams are GET-only.
            if request.method() == Method::GET {
                if let Some(stream) = manifest
                    .config
                    .streams
                    .iter()
                    .find(|s| route_matches(&s.route, request_path))
                {
                    if let (Some(inner), Some(site_handlers)) = (
                        handlers.inner.as_ref(),
                        site_config
                            .and_then(|c| c.handlers.as_ref())
                            .filter(|h| h.enabled),
                    ) {
                        // A `websocket` stream upgraded by the client is served
                        // bidirectionally (WebSocket fan-out);
                        // otherwise it's SSE. Build the upgrade from the request
                        // parts (consuming the body, which isn't `Sync`, so it is
                        // never held across the dispatch await).
                        if stream.websocket && is_upgrade_request(request.headers()) {
                            use axum::extract::FromRequestParts;
                            let (mut parts, _body) = request.into_parts();
                            return apply_vary(
                                match axum::extract::ws::WebSocketUpgrade::from_request_parts(
                                    &mut parts,
                                    &(),
                                )
                                .await
                                {
                                    Ok(ws) => {
                                        serve_ws_stream(
                                            inner,
                                            site,
                                            site_handlers,
                                            stream,
                                            ws,
                                            client_ip,
                                            preview,
                                        )
                                        .await
                                    }
                                    Err(rejection) => rejection.into_response(),
                                },
                                &vary,
                            );
                        }
                        // Pull the only field needed from the request as an owned
                        // value: `&Request` is not `Send` (the body isn't `Sync`),
                        // so it must not be held across the dispatch await.
                        let after = request
                            .headers()
                            .get("last-event-id")
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_string);
                        return apply_vary(
                            serve_stream(
                                inner,
                                site,
                                site_handlers,
                                stream,
                                after,
                                client_ip,
                                preview,
                            )
                            .await,
                            &vary,
                        );
                    }
                    // A stream route on a site with handlers disabled / no runtime
                    // is not served (deny by default).
                    return apply_vary(not_found(), &vary);
                }
            }
        }
    }
    // Gateway: an operator-declared route forwards to a private
    // upstream. Independent of the handlers feature; runs after redirects/
    // handlers and **wins over static files** (the operator declared it). Access
    // control already ran up front; only declared upstreams reach private addrs.
    if !matches!(outcome, Outcome::Redirect { .. }) {
        if let Some(gw) = site_config
            .and_then(|c| c.gateway.as_ref())
            .filter(|g| g.is_enabled())
        {
            if let Some(route) = gw.match_route(request_path) {
                return apply_vary(
                    match gw.upstreams.get(&route.upstream) {
                        Some(upstream) => {
                            // A compute-backed upstream resolves its pool live from
                            // the workload's healthy replica endpoints. Record
                            // the request as activity so the reconcile loop
                            // keeps the workload warm / wakes it, and only sleeps it
                            // once genuinely idle.
                            let (compute_backends, compute_regions) = match &upstream.compute {
                                Some(workload) => {
                                    gateway::record_activity(workload);
                                    let mut pool = compute_endpoints(deploy, workload).await;
                                    // Wake-from-zero: no live replica but one
                                    // is parked → nudge the reconcile loop to restore it
                                    // and hold this request until it's serving. The cold
                                    // start is invisible to the client; only a genuine
                                    // restore failure (timeout) falls through to 502.
                                    if pool.is_empty() && has_parked_replica(deploy, workload).await
                                    {
                                        gateway::wake_reconcile();
                                        pool = await_warm(deploy, workload, COMPUTE_WAKE_TIMEOUT)
                                            .await;
                                    }
                                    // FA-8: for a nearest-region pool, tag each replica
                                    // endpoint with its node's region (from placement).
                                    let regions = if upstream.lb
                                        == boatramp_core::gateway::LbPolicy::Nearest
                                    {
                                        Some(compute_endpoint_regions(deploy, workload).await)
                                    } else {
                                        None
                                    };
                                    (Some(pool), regions)
                                }
                                None => (None, None),
                            };
                            dispatch_gateway(
                                request,
                                site.unwrap_or(""),
                                &route.upstream,
                                upstream,
                                request_path,
                                client_ip,
                                compute_backends,
                                compute_regions,
                            )
                            .await
                        }
                        None => (
                            StatusCode::BAD_GATEWAY,
                            "gateway route references an unknown upstream\n",
                        )
                            .into_response(),
                    },
                    &vary,
                );
            }
        }
    }
    let response = match outcome {
        Outcome::Redirect { location, status } => redirect(status, &location),
        Outcome::Proxy { url } => proxy(request, &url, &manifest.config, client_ip).await,
        Outcome::File {
            path: served,
            entry,
        } => {
            // Static content answers only GET/HEAD; other methods are 405.
            if !matches!(*request.method(), Method::GET | Method::HEAD) {
                return apply_vary(method_not_allowed(), &vary);
            }
            serve_entry(
                deploy,
                &manifest.config,
                request_path,
                &served,
                &entry,
                request.headers(),
                StatusCode::OK,
            )
            .await
        }
        Outcome::NotFound { error } => match error {
            Some((served, entry)) => {
                serve_entry(
                    deploy,
                    &manifest.config,
                    request_path,
                    &served,
                    &entry,
                    request.headers(),
                    StatusCode::NOT_FOUND,
                )
                .await
            }
            None => not_found(),
        },
    };
    apply_vary(response, &vary)
}

/// `405` for a non-`GET`/`HEAD` request to static content.
fn method_not_allowed() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
    (
        StatusCode::METHOD_NOT_ALLOWED,
        headers,
        "method not allowed\n",
    )
        .into_response()
}

/// Stream a resolved entry, applying conditional/range/headers. `base_status` is
/// `200` for a normal hit and `404` for a custom error document.
#[allow(clippy::too_many_arguments)]
async fn serve_entry(
    deploy: &DeployStore,
    config: &DeployConfig,
    request_path: &str,
    served_path: &str,
    entry: &FileEntry,
    req_headers: &HeaderMap,
    base_status: StatusCode,
) -> Response {
    let is_range = base_status == StatusCode::OK && req_headers.contains_key(header::RANGE);

    // Content-encoding negotiation. Range requests are served from the identity
    // representation (Range over a compressed variant is intentionally avoided).
    let chosen = if is_range {
        None
    } else {
        negotiate_encoding(entry, req_headers)
    };
    let (blob_hash, blob_size, encoding) = match chosen {
        Some((enc, variant)) => (variant.hash.as_str(), variant.size, Some(enc)),
        None => (entry.hash.as_str(), entry.size, None),
    };
    // ETag is per-representation (identity vs br vs gzip differ in bytes).
    let etag = format!("\"{blob_hash}\"");

    // Conditional GET — content hash is a strong validator.
    if base_status == StatusCode::OK && if_none_match(req_headers, &etag) {
        let mut headers = response_headers(config, request_path, served_path, entry, &etag);
        set_content_encoding(&mut headers, encoding);
        return (StatusCode::NOT_MODIFIED, headers).into_response();
    }

    // Range request (identity only).
    if is_range {
        if let Some(spec) = req_headers
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok())
        {
            match parse_ranges(spec, entry.size) {
                // A single range → `206` with `Content-Range`, streamed.
                Some(ranges) if ranges.len() == 1 => {
                    let (offset, len) = ranges[0];
                    let object = match deploy.open_blob_range(&entry.hash, offset, Some(len)).await
                    {
                        Ok(object) => object,
                        Err(err) => return deploy_error_response(err),
                    };
                    let mut headers =
                        response_headers(config, request_path, served_path, entry, &etag);
                    set_header(&mut headers, header::CONTENT_LENGTH, &len.to_string());
                    set_header(
                        &mut headers,
                        header::CONTENT_RANGE,
                        &format!("bytes {}-{}/{}", offset, offset + len - 1, entry.size),
                    );
                    return (
                        StatusCode::PARTIAL_CONTENT,
                        headers,
                        Body::from_stream(object.body),
                    )
                        .into_response();
                }
                // Several ranges → `206 multipart/byteranges`, streamed.
                Some(ranges) if ranges.len() <= MAX_RANGES => {
                    return multipart_byteranges(
                        deploy,
                        config,
                        request_path,
                        served_path,
                        entry,
                        &etag,
                        &ranges,
                    )
                    .await;
                }
                // Too many ranges: ignore `Range`, serve the full `200` body.
                Some(_) => {}
                // Malformed / wholly unsatisfiable → `416`.
                None => {
                    let mut headers = HeaderMap::new();
                    set_header(
                        &mut headers,
                        header::CONTENT_RANGE,
                        &format!("bytes */{}", entry.size),
                    );
                    return (StatusCode::RANGE_NOT_SATISFIABLE, headers).into_response();
                }
            }
        }
    }

    // Full body (identity or negotiated variant).
    let object = match deploy.open_blob(blob_hash).await {
        Ok(object) => object,
        Err(err) => return deploy_error_response(err),
    };
    let mut headers = response_headers(config, request_path, served_path, entry, &etag);
    set_header(&mut headers, header::CONTENT_LENGTH, &blob_size.to_string());
    set_content_encoding(&mut headers, encoding);
    (base_status, headers, Body::from_stream(object.body)).into_response()
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

/// Reverse-proxy a GET to an absolute upstream URL, streaming the response.
///
/// Guarded against SSRF: only `http`/`https`, the host must pass the deploy
/// config's `proxy_allow` list, and every resolved address must be public
/// (private/loopback/link-local/metadata targets are refused).
async fn proxy(request: Request, url: &str, config: &DeployConfig, client_ip: IpAddr) -> Response {
    // SSRF: validate scheme + allow-list, and pin the verified address so the
    // actual connection cannot be re-resolved to an internal host (no TOCTOU).
    let (parsed, addr, host) = match check_proxy_target(url, config).await {
        Ok(resolved) => resolved,
        Err(reason) => {
            tracing::warn!(%url, reason, "proxy target refused");
            return (StatusCode::FORBIDDEN, "proxy target not allowed\n").into_response();
        }
    };
    let client = match pinned_client(&host, addr) {
        Ok(client) => client,
        Err(_) => return (StatusCode::BAD_GATEWAY, "proxy client error\n").into_response(),
    };

    let (parts, body) = request.into_parts();
    let scheme = parts
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http")
        .to_string();

    let mut upstream = client.request(parts.method, parsed);
    // Forward request headers minus hop-by-hop and Host (reqwest sets Host).
    for (name, value) in &parts.headers {
        if name == header::HOST || is_hop_by_hop(name) {
            continue;
        }
        upstream = upstream.header(name, value);
    }
    upstream = upstream
        .header("x-forwarded-for", client_ip.to_string())
        .header("x-forwarded-proto", scheme);
    if let Some(host_header) = parts.headers.get(header::HOST) {
        upstream = upstream.header("x-forwarded-host", host_header);
    }
    upstream = upstream.body(reqwest::Body::wrap_stream(body.into_data_stream()));

    match upstream.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            // Pass response headers through, minus hop-by-hop + content-length
            // (we re-stream, so let the framing be recomputed).
            let mut headers = HeaderMap::new();
            for (name, value) in resp.headers() {
                if is_hop_by_hop(name) || name == header::CONTENT_LENGTH {
                    continue;
                }
                headers.insert(name.clone(), value.clone());
            }
            (status, headers, Body::from_stream(resp.bytes_stream())).into_response()
        }
        Err(err) => {
            tracing::warn!(%url, error = %err, "proxy request failed");
            (StatusCode::BAD_GATEWAY, "upstream error\n").into_response()
        }
    }
}

/// Connection-level (hop-by-hop) headers that must not be forwarded end to end.
fn is_hop_by_hop(name: &HeaderName) -> bool {
    const HOP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    HOP.contains(&name.as_str())
}

/// Validate a proxy target against the SSRF policy and return the parsed URL,
/// a verified public socket address to pin, and the host. `Err` carries a short
/// reason for logging.
async fn check_proxy_target(
    url: &str,
    config: &DeployConfig,
) -> Result<(reqwest::Url, SocketAddr, String), &'static str> {
    let parsed = reqwest::Url::parse(url).map_err(|_| "unparsable url")?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("scheme not http(s)"),
    }
    let host = parsed.host_str().ok_or("missing host")?.to_string();
    if !config.proxy_host_allowed(&host) {
        return Err("host not in proxy_allow");
    }
    // Resolve, require every address public, and keep one to pin the connection.
    let port = parsed.port_or_known_default().unwrap_or(80);
    let mut pinned = None;
    for addr in tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|_| "dns resolution failed")?
    {
        if !boatramp_core::access::is_global_ip(addr.ip()) {
            return Err("resolves to a non-public address");
        }
        pinned.get_or_insert(addr);
    }
    let addr = pinned.ok_or("no addresses resolved")?;
    Ok((parsed, addr, host))
}

/// Build a one-off client that resolves `host` to the pre-verified `addr`,
/// closing the SSRF DNS-rebinding window (the kernel never re-resolves).
fn pinned_client(host: &str, addr: SocketAddr) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder().resolve(host, addr).build()
}

/// The cloud-metadata service address — refused even for a declared gateway
/// upstream (defense in depth).
const CLOUD_METADATA_IPV4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(169, 254, 169, 254);

/// The resolved operator security posture carried in the request extensions
/// (inserted by [`router_with`]); falls back to the strict `multi-tenant`
/// default if absent (e.g. a router built without the layer in a test).
fn request_posture(request: &Request) -> boatramp_core::security::SecurityPosture {
    request
        .extensions()
        .get::<boatramp_core::security::SecurityPosture>()
        .copied()
        .unwrap_or_default()
}

/// Whether a resolved gateway-upstream address is permitted under `posture`.
/// The cloud-metadata endpoint is **always** refused (defense in
/// depth). Any other non-global address — loopback / private / link-local /
/// unique-local / CGNAT — is refused for a **site-declared** upstream unless the
/// operator opted in via `allow_site_private_upstreams`. Site config is
/// `site-write`, so without this gate a site writer could point the edge at
/// internal services; the operator posture is the authority.
fn gateway_addr_allowed(ip: IpAddr, posture: &boatramp_core::security::SecurityPosture) -> bool {
    if ip == IpAddr::V4(CLOUD_METADATA_IPV4) {
        return false;
    }
    posture.allow_site_private_upstreams || boatramp_core::access::is_global_ip(ip)
}

/// Proxy to a **declared gateway upstream**: a private address is
/// permitted *because the operator declared this upstream*, but the target is
/// still resolved once and pinned (no TOCTOU), the scheme is http(s)-only, and
/// the cloud-metadata address is always refused. Applies the upstream's
/// strip-prefix, host-header override, header rewrites, and timeouts.
/// Forward a request through a declared gateway upstream, picking a backend from
/// its pool (round-robin/random over the healthy set) and retrying the next
/// candidate on a backend failure — but only for body-less idempotent requests,
/// since a sent body can't be replayed. Each attempt's
/// outcome feeds passive health so future requests route around a dead backend.
#[allow(clippy::too_many_arguments)]
async fn dispatch_gateway(
    request: Request,
    site: &str,
    upstream_name: &str,
    upstream: &boatramp_core::gateway::Upstream,
    request_path: &str,
    client_ip: IpAddr,
    // When the upstream is compute-backed (`upstream.compute`), the caller passes
    // the workload's live healthy replica endpoints here; otherwise `None` and
    // the static/DNS pool is used.
    compute_backends: Option<Vec<String>>,
    // FA-8: per-replica region tags (endpoint URL → region) for a compute-backed
    // `LbPolicy::Nearest` pool, derived from node placement; merged over the
    // upstream's static `regions` so nearest-replica routing works without a manual
    // `--region` map. `None`/empty for non-nearest or non-compute pools.
    compute_regions: Option<std::collections::BTreeMap<String, String>>,
) -> Response {
    // Read the security posture once from the original request — the retry path
    // below rebuilds the request (dropping extensions), so we thread the resolved
    // (Copy) posture into the proxy fns rather than re-reading it per attempt.
    let posture = request_posture(&request);
    let state = gateway::upstream_state(site, upstream_name);
    // Arm active probing (no-op unless the upstream has active_health) so the
    // background prober has a current config snapshot.
    state.arm_active_probe(upstream);
    let now = std::time::Instant::now();
    // Merge compute-derived replica regions into the upstream so the nearest LB
    // sees them (a per-request clone only when there are regions to add).
    let merged_upstream = compute_regions.filter(|r| !r.is_empty()).map(|regions| {
        let mut u = upstream.clone();
        u.regions.extend(regions);
        u
    });
    let upstream = merged_upstream.as_ref().unwrap_or(upstream);
    let backends =
        compute_backends.unwrap_or_else(|| state.backends(upstream, &gateway::SystemResolver, now));
    if backends.is_empty() {
        return (
            StatusCode::BAD_GATEWAY,
            "gateway upstream has no backends\n",
        )
            .into_response();
    }
    // FA-8: extract the client's region from the configured edge header (set by a
    // CDN/edge, e.g. `fly-region` / `cf-ipcountry`), driving `LbPolicy::Nearest`.
    // Unset header ⇒ no client region ⇒ Nearest degrades to health-first order.
    let client_region = upstream
        .client_region_header
        .as_deref()
        .and_then(|name| request.headers().get(name))
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let candidates = state.candidates(&backends, upstream, now, client_region.as_deref());

    // Retry across backends only when the request body is replayable (none) —
    // GET/HEAD with no declared/streamed body. Otherwise use a single backend.
    if !gateway_retryable(&request) || candidates.len() == 1 {
        let target = &candidates[0];
        let response =
            proxy_upstream(request, upstream, target, request_path, client_ip, posture).await;
        state.record(
            target,
            !response.status().is_server_error(),
            upstream.passive_health,
            now,
        );
        return response;
    }

    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let mut last: Option<Response> = None;
    for target in &candidates {
        let mut attempt = axum::http::Request::new(Body::empty());
        *attempt.method_mut() = method.clone();
        *attempt.uri_mut() = uri.clone();
        *attempt.headers_mut() = headers.clone();
        let response =
            proxy_upstream(attempt, upstream, target, request_path, client_ip, posture).await;
        let ok = !response.status().is_server_error();
        state.record(target, ok, upstream.passive_health, now);
        if ok {
            return response;
        }
        last = Some(response);
    }
    last.unwrap_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            "gateway: all upstream backends failed\n",
        )
            .into_response()
    })
}

/// The live healthy replica endpoints of a compute workload, as upstream URLs.
/// Empty (→ 502) when no healthy replica exists.
async fn compute_endpoints(deploy: &DeployStore, workload: &str) -> Vec<String> {
    deploy
        .list_replica_states(workload)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|state| state.healthy)
        .map(|state| state.endpoint.url())
        .collect()
}

/// The region of each healthy replica endpoint of a compute workload (FA-8), as
/// `endpoint-url → region`, denormalized from the replica's node placement. Feeds
/// the nearest-replica LB; replicas whose node had no region are omitted
/// (region-neutral).
async fn compute_endpoint_regions(
    deploy: &DeployStore,
    workload: &str,
) -> std::collections::BTreeMap<String, String> {
    deploy
        .list_replica_states(workload)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|state| state.healthy)
        .filter_map(|state| state.region.map(|region| (state.endpoint.url(), region)))
        .collect()
}

/// How long a wake-from-zero request waits for the parked replica to be restored
/// and serving before giving up. A safety ceiling for a *failed*
/// restore, not a normal-path bound — a real resume is well under this, so the
/// cold start stays invisible to the client.
const COMPUTE_WAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Whether `workload` has a replica parked in the [`Zero`] phase — i.e. there's
/// something to wake (vs. a genuinely down/undeployed workload, which should just
/// 502 rather than hold the request).
///
/// [`Zero`]: boatramp_core::compute::ReplicaPhase::Zero
async fn has_parked_replica(deploy: &DeployStore, workload: &str) -> bool {
    deploy
        .list_replica_states(workload)
        .await
        .unwrap_or_default()
        .iter()
        .any(|state| state.phase == boatramp_core::compute::ReplicaPhase::Zero)
}

/// Hold a wake-from-zero request: poll the workload's healthy endpoints until one
/// appears (the reconcile loop restored the parked replica) or `timeout` elapses.
/// Returns the (possibly still-empty, on timeout) pool.
async fn await_warm(
    deploy: &DeployStore,
    workload: &str,
    timeout: std::time::Duration,
) -> Vec<String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let pool = compute_endpoints(deploy, workload).await;
        if !pool.is_empty() || std::time::Instant::now() >= deadline {
            return pool;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Spawn the leader-gated compute reconcile loop:
/// every `tick`, while `is_leader()`, run one [`reconcile_once`] pass over the
/// backend registry + node inventory to converge each workload's replicas. A
/// no-op while not leader or with an empty registry. Detached for the server's
/// lifetime; the same leader-gating pattern as cron/cert issuance.
pub fn spawn_compute_reconcile(
    deploy: DeployStore,
    backends: boatramp_core::compute::BackendRegistry,
    nodes: Vec<boatramp_core::compute::Node>,
    policy: boatramp_core::compute::BackendPolicy,
    is_leader: CronLeaderGate,
    tick: std::time::Duration,
    idle_timeout: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // drive scale-to-zero from the gateway's per-workload activity —
        // a workload idle for `idle_timeout` is slept, a requested one is woken.
        let activity = gateway::GatewayActivitySource::new(idle_timeout);
        let mut interval = tokio::time::interval(tick);
        loop {
            // Periodic convergence, or an immediate wake-from-zero nudge from the
            // serving path — whichever comes first.
            tokio::select! {
                _ = interval.tick() => {}
                _ = gateway::await_reconcile_wake() => {}
            }
            if !is_leader() {
                continue;
            }
            match boatramp_core::compute::reconcile_once(
                &deploy, &backends, &nodes, &policy, &activity,
            )
            .await
            {
                Ok(report) if !report.errors.is_empty() => tracing::warn!(
                    launched = report.launched,
                    stopped = report.stopped,
                    errors = ?report.errors,
                    "compute reconcile: partial",
                ),
                Ok(report) if report.launched + report.stopped > 0 => tracing::info!(
                    launched = report.launched,
                    stopped = report.stopped,
                    "compute reconcile",
                ),
                Ok(_) => {}
                Err(err) => tracing::warn!(%err, "compute reconcile tick failed"),
            }
        }
    })
}

/// Whether a request can be safely retried against another backend: a body-less
/// idempotent method, so re-sending replays nothing. Conservative on purpose.
fn gateway_retryable(request: &Request) -> bool {
    matches!(*request.method(), Method::GET | Method::HEAD)
        && request
            .headers()
            .get(header::CONTENT_LENGTH)
            .is_none_or(|v| v.as_bytes() == b"0")
        && !request.headers().contains_key(header::TRANSFER_ENCODING)
}

async fn proxy_upstream(
    request: Request,
    upstream: &boatramp_core::gateway::Upstream,
    target: &str,
    request_path: &str,
    client_ip: IpAddr,
    posture: boatramp_core::security::SecurityPosture,
) -> Response {
    // WebSocket / generic HTTP upgrade: bridge the upgraded connection both ways.
    // reqwest can't upgrade, so this uses a hyper client conn.
    if is_upgrade_request(request.headers()) {
        return proxy_upgrade(request, upstream, target, request_path, client_ip, posture).await;
    }
    // A `unix:/path` target forwards over a unix-domain socket.
    if let Some(socket_path) = target.strip_prefix("unix:") {
        // Site config is `site-write`; a unix-socket upstream can reach local
        // admin sockets (Docker/containerd/SSH-agent), so it requires operator
        // opt-in.
        if !posture.allow_site_unix_upstreams {
            tracing::warn!(
                %target,
                "gateway upstream refused: unix-socket upstreams disabled by security posture"
            );
            return (StatusCode::FORBIDDEN, "gateway upstream not allowed\n").into_response();
        }
        #[cfg(unix)]
        {
            return proxy_upstream_unix(request, upstream, socket_path, request_path, client_ip)
                .await;
        }
        #[cfg(not(unix))]
        {
            let _ = socket_path;
            return (
                StatusCode::NOT_IMPLEMENTED,
                "unix-socket upstreams are only supported on unix\n",
            )
                .into_response();
        }
    }
    // Resolve + pin the declared target (private allowed; metadata refused).
    let parsed = match reqwest::Url::parse(target) {
        Ok(url) => url,
        Err(_) => {
            tracing::warn!(target = %target, "gateway upstream target unparsable");
            return (StatusCode::BAD_GATEWAY, "bad gateway upstream\n").into_response();
        }
    };
    match parsed.scheme() {
        "http" | "https" => {}
        _ => {
            return (
                StatusCode::BAD_GATEWAY,
                "gateway upstream scheme not http(s)\n",
            )
                .into_response()
        }
    }
    let Some(host) = parsed.host_str().map(str::to_string) else {
        return (StatusCode::BAD_GATEWAY, "gateway upstream missing host\n").into_response();
    };
    let port = parsed.port_or_known_default().unwrap_or(80);
    let pinned = match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(addrs) => {
            let mut chosen = None;
            for addr in addrs {
                // Refuse cloud-metadata always, and (unless the operator opts in)
                // any non-global address — checked post-resolution so a hostname
                // can't DNS-rebind to an internal target.
                if !gateway_addr_allowed(addr.ip(), &posture) {
                    tracing::warn!(
                        %host, ip = %addr.ip(),
                        "gateway upstream refused: address not permitted by security posture"
                    );
                    return (StatusCode::FORBIDDEN, "gateway upstream not allowed\n")
                        .into_response();
                }
                chosen.get_or_insert(addr);
            }
            chosen
        }
        Err(_) => None,
    };
    let Some(addr) = pinned else {
        return (
            StatusCode::BAD_GATEWAY,
            "gateway upstream did not resolve\n",
        )
            .into_response();
    };

    // Build the upstream URL: target base path + forwarded (strip-prefixed) path
    // + the original query.
    let mut target = parsed.clone();
    let base = target.path().trim_end_matches('/').to_string();
    let forwarded = upstream.forward_path(request_path);
    target.set_path(&format!("{base}{forwarded}"));
    let (mut parts, body) = request.into_parts();
    target.set_query(parts.uri.query());

    // A client pinned to the resolved address, with the upstream's TLS + timeouts.
    let mut builder = reqwest::Client::builder().resolve(&host, addr);
    if let Some(ms) = upstream.connect_timeout_ms {
        builder = builder.connect_timeout(Duration::from_millis(ms));
    }
    if let Some(ms) = upstream.request_timeout_ms {
        builder = builder.timeout(Duration::from_millis(ms));
    }
    if upstream.tls_insecure {
        tracing::warn!(%host, "gateway upstream TLS verification disabled (tls_insecure)");
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = match builder.build() {
        Ok(client) => client,
        Err(_) => return (StatusCode::BAD_GATEWAY, "gateway client error\n").into_response(),
    };

    let scheme = parts
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http")
        .to_string();
    let requested_host = parts.headers.get(header::HOST).cloned();

    let mut up = client.request(parts.method.clone(), target);
    for (name, value) in &parts.headers {
        // reqwest sets Host from the URL (or our override below); drop the
        // client Host + hop-by-hop, and any header the upstream removes.
        if name == header::HOST
            || is_hop_by_hop(name)
            || upstream
                .header_up
                .remove
                .iter()
                .any(|h| name.as_str().eq_ignore_ascii_case(h))
        {
            continue;
        }
        up = up.header(name, value);
    }
    up = up
        .header("x-forwarded-for", client_ip.to_string())
        .header("x-forwarded-proto", scheme);
    if let Some(h) = &requested_host {
        up = up.header("x-forwarded-host", h);
    }
    // Host header: explicit override, else the upstream's own host.
    if let Some(hh) = &upstream.host_header {
        up = up.header(header::HOST, hh);
    }
    // Request header set/overrides.
    for (name, value) in &upstream.header_up.set {
        up = up.header(name, value);
    }
    up = up.body(reqwest::Body::wrap_stream(body.into_data_stream()));
    parts.headers.clear(); // release; not used past here

    match up.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut headers = HeaderMap::new();
            for (name, value) in resp.headers() {
                if is_hop_by_hop(name)
                    || name == header::CONTENT_LENGTH
                    || upstream
                        .header_down
                        .remove
                        .iter()
                        .any(|h| name.as_str().eq_ignore_ascii_case(h))
                {
                    continue;
                }
                headers.insert(name.clone(), value.clone());
            }
            // Response header set/overrides.
            for (name, value) in &upstream.header_down.set {
                set_header_str(&mut headers, name, value);
            }
            (status, headers, Body::from_stream(resp.bytes_stream())).into_response()
        }
        Err(err) => {
            tracing::warn!(%host, error = %err, "gateway upstream request failed");
            (StatusCode::BAD_GATEWAY, "upstream error\n").into_response()
        }
    }
}

/// Insert a header from string name/value, ignoring an invalid name/value
/// (operator-supplied header rewrites shouldn't 500 the response).
fn set_header_str(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.insert(name, value);
    }
}

/// Proxy to a gateway upstream over a **unix-domain socket**:
/// `target = unix:/path/to.sock`. Drives a hyper HTTP/1 client connection over
/// the `UnixStream`; applies the same strip-prefix / host / header / X-Forwarded
/// handling as the TCP path and streams both bodies.
#[cfg(unix)]
async fn proxy_upstream_unix(
    request: Request,
    upstream: &boatramp_core::gateway::Upstream,
    socket_path: &str,
    request_path: &str,
    client_ip: IpAddr,
) -> Response {
    let stream = match tokio::net::UnixStream::connect(socket_path).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!(socket = socket_path, %err, "gateway unix upstream unreachable");
            return (
                StatusCode::BAD_GATEWAY,
                "gateway unix upstream unreachable\n",
            )
                .into_response();
        }
    };
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "gateway unix handshake failed\n").into_response()
        }
    };
    // Drive the connection in the background for the lifetime of the exchange.
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let (parts, body) = request.into_parts();
    let scheme = parts
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http")
        .to_string();
    // Origin-form request URI: the strip-prefixed path + the original query.
    let forwarded = upstream.forward_path(request_path);
    let uri = match parts.uri.query() {
        Some(q) => format!("{forwarded}?{q}"),
        None => forwarded.into_owned(),
    };
    let host = upstream
        .host_header
        .clone()
        .unwrap_or_else(|| "localhost".to_string());

    let mut builder = hyper::Request::builder()
        .method(parts.method.clone())
        .uri(uri);
    for (name, value) in &parts.headers {
        if name == header::HOST
            || is_hop_by_hop(name)
            || upstream
                .header_up
                .remove
                .iter()
                .any(|h| name.as_str().eq_ignore_ascii_case(h))
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder = builder
        .header(header::HOST, &host)
        .header("x-forwarded-for", client_ip.to_string())
        .header("x-forwarded-proto", scheme);
    for (name, value) in &upstream.header_up.set {
        builder = builder.header(name, value);
    }
    let upstream_req = match builder.body(body) {
        Ok(req) => req,
        Err(_) => return (StatusCode::BAD_GATEWAY, "gateway unix request error\n").into_response(),
    };

    match sender.send_request(upstream_req).await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut headers = HeaderMap::new();
            for (name, value) in resp.headers() {
                if is_hop_by_hop(name)
                    || name == header::CONTENT_LENGTH
                    || upstream
                        .header_down
                        .remove
                        .iter()
                        .any(|h| name.as_str().eq_ignore_ascii_case(h))
                {
                    continue;
                }
                headers.insert(name.clone(), value.clone());
            }
            for (name, value) in &upstream.header_down.set {
                set_header_str(&mut headers, name, value);
            }
            (status, headers, Body::new(resp.into_body())).into_response()
        }
        Err(err) => {
            tracing::warn!(socket = socket_path, %err, "gateway unix upstream request failed");
            (StatusCode::BAD_GATEWAY, "upstream error\n").into_response()
        }
    }
}

/// Whether the request asks for an HTTP upgrade (`Connection: upgrade` +
/// `Upgrade: …`), e.g. a WebSocket handshake.
fn is_upgrade_request(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| {
            c.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        });
    connection_upgrade && headers.contains_key(header::UPGRADE)
}

/// Proxy an HTTP **upgrade** (WebSocket) to a gateway upstream: forward the
/// handshake over a hyper client connection and, on `101`, bridge the two
/// upgraded byte streams in both directions. Supports `http`
/// (ws) and `unix:` upstreams; `https` (wss) upgrade isn't wired yet.
async fn proxy_upgrade(
    mut request: Request,
    upstream: &boatramp_core::gateway::Upstream,
    target: &str,
    request_path: &str,
    client_ip: IpAddr,
    posture: boatramp_core::security::SecurityPosture,
) -> Response {
    // Register interest in the client-side upgrade before the request is moved.
    let client_on_upgrade = hyper::upgrade::on(&mut request);
    let method = request.method().clone();
    let req_headers = request.headers().clone();
    let query = request.uri().query().map(str::to_string);
    let forwarded = upstream.forward_path(request_path);
    let uri = match &query {
        Some(q) => format!("{forwarded}?{q}"),
        None => forwarded.into_owned(),
    };

    // Unix-socket upstream — operator opt-in only (see `proxy_upstream`).
    if let Some(socket_path) = target.strip_prefix("unix:") {
        if !posture.allow_site_unix_upstreams {
            tracing::warn!(
                %target,
                "gateway upgrade refused: unix-socket upstreams disabled by security posture"
            );
            return (StatusCode::FORBIDDEN, "gateway upstream not allowed\n").into_response();
        }
        #[cfg(unix)]
        {
            let stream = match tokio::net::UnixStream::connect(socket_path).await {
                Ok(s) => s,
                Err(_) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        "gateway unix upstream unreachable\n",
                    )
                        .into_response()
                }
            };
            let host = upstream
                .host_header
                .clone()
                .unwrap_or_else(|| "localhost".to_string());
            return upgrade_over(
                hyper_util::rt::TokioIo::new(stream),
                method,
                uri,
                req_headers,
                host,
                upstream,
                client_ip,
                client_on_upgrade,
            )
            .await;
        }
        #[cfg(not(unix))]
        {
            let _ = socket_path;
            return (
                StatusCode::NOT_IMPLEMENTED,
                "unix upstreams are unix-only\n",
            )
                .into_response();
        }
    }

    // TCP (http/ws) upstream: resolve + pin (private allowed; metadata refused).
    let parsed = match reqwest::Url::parse(target) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_GATEWAY, "bad gateway upstream\n").into_response(),
    };
    if parsed.scheme() != "http" {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "gateway upgrade supports http (ws) or unix upstreams\n",
        )
            .into_response();
    }
    let Some(host) = parsed.host_str().map(str::to_string) else {
        return (StatusCode::BAD_GATEWAY, "gateway upstream missing host\n").into_response();
    };
    let port = parsed.port_or_known_default().unwrap_or(80);
    let addr = match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(addrs) => {
            let mut chosen = None;
            for addr in addrs {
                // Cloud-metadata always refused; non-global refused unless the
                // operator opted in (see `proxy_upstream`).
                if !gateway_addr_allowed(addr.ip(), &posture) {
                    tracing::warn!(
                        %host, ip = %addr.ip(),
                        "gateway upgrade refused: address not permitted by security posture"
                    );
                    return (StatusCode::FORBIDDEN, "gateway upstream not allowed\n")
                        .into_response();
                }
                chosen.get_or_insert(addr);
            }
            chosen
        }
        Err(_) => None,
    };
    let Some(addr) = addr else {
        return (
            StatusCode::BAD_GATEWAY,
            "gateway upstream did not resolve\n",
        )
            .into_response();
    };
    let stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "gateway upstream unreachable\n").into_response()
        }
    };
    let host_hdr = upstream.host_header.clone().unwrap_or(host);
    upgrade_over(
        hyper_util::rt::TokioIo::new(stream),
        method,
        uri,
        req_headers,
        host_hdr,
        upstream,
        client_ip,
        client_on_upgrade,
    )
    .await
}

/// Drive a hyper HTTP/1 client connection (with upgrades) over `io`, forward the
/// upgrade handshake, and on `101` bridge the upgraded streams both ways.
#[allow(clippy::too_many_arguments)]
async fn upgrade_over<I>(
    io: I,
    method: Method,
    uri: String,
    req_headers: HeaderMap,
    host: String,
    upstream: &boatramp_core::gateway::Upstream,
    client_ip: IpAddr,
    client_on_upgrade: hyper::upgrade::OnUpgrade,
) -> Response
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(_) => return (StatusCode::BAD_GATEWAY, "gateway handshake failed\n").into_response(),
    };
    // `with_upgrades` keeps the connection alive for the upgraded stream.
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let mut builder = hyper::Request::builder().method(method).uri(uri);
    // Forward all headers (the handshake NEEDS Connection/Upgrade/Sec-WebSocket-*),
    // replacing Host and honoring the upstream's header rewrites.
    for (name, value) in &req_headers {
        if name == header::HOST
            || upstream
                .header_up
                .remove
                .iter()
                .any(|h| name.as_str().eq_ignore_ascii_case(h))
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder = builder
        .header(header::HOST, &host)
        .header("x-forwarded-for", client_ip.to_string())
        .header("x-forwarded-proto", "http");
    for (name, value) in &upstream.header_up.set {
        builder = builder.header(name, value);
    }
    let upstream_req = match builder.body(Body::empty()) {
        Ok(req) => req,
        Err(_) => return (StatusCode::BAD_GATEWAY, "gateway request error\n").into_response(),
    };

    let mut upstream_resp = match sender.send_request(upstream_req).await {
        Ok(resp) => resp,
        Err(_) => return (StatusCode::BAD_GATEWAY, "upstream error\n").into_response(),
    };

    if upstream_resp.status() == hyper::StatusCode::SWITCHING_PROTOCOLS {
        // Bridge the two upgraded connections once both sides flip.
        let upstream_on_upgrade = hyper::upgrade::on(&mut upstream_resp);
        tokio::spawn(async move {
            if let (Ok(client_io), Ok(upstream_io)) =
                (client_on_upgrade.await, upstream_on_upgrade.await)
            {
                let mut client_io = hyper_util::rt::TokioIo::new(client_io);
                let mut upstream_io = hyper_util::rt::TokioIo::new(upstream_io);
                let _ = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await;
            }
        });
        // Return the upstream's 101 (with its Upgrade/Sec-WebSocket-Accept headers).
        let mut headers = HeaderMap::new();
        for (name, value) in upstream_resp.headers() {
            headers.insert(name.clone(), value.clone());
        }
        return (StatusCode::SWITCHING_PROTOCOLS, headers, Body::empty()).into_response();
    }

    // Upstream declined the upgrade — pass its response through.
    let status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers() {
        if name == header::CONTENT_LENGTH {
            continue;
        }
        headers.insert(name.clone(), value.clone());
    }
    (status, headers, Body::new(upstream_resp.into_body())).into_response()
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

// ---- WebAssembly handler dispatch ----------------------
// Gated behind the `handlers` feature; without it the server carries no wasm
// dependency and handler routes fall through to the static pipeline.

/// Dispatch a matched handler: load its component blob, build the site's
/// granted bindings, run it on the engine, and adapt the response back to axum.
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
async fn dispatch_handler(
    runtime: &HandlerRuntime,
    deploy: &DeployStore,
    manifest: &Manifest,
    site: &str,
    request_path: &str,
    site_config: Option<&SiteConfig>,
    handler: &boatramp_core::config::HandlerConfig,
    mut request: Request,
    client_ip: IpAddr,
    preview: Option<&str>,
) -> Response {
    let Some(inner) = runtime.inner.as_ref() else {
        // The feature is compiled in but no runtime was configured.
        return not_found();
    };
    // Binding identity. Live requests bind to the site directly; a preview gets
    // a *preview-scoped* identity (`{site}/_preview/{id}`) so its kv/blob/sql
    // land in their own namespace and can never touch live state. Grants are
    // unaffected — they come from the site's HandlersSiteConfig,
    // so a preview can do only what the site already allows.
    let scope = match preview {
        Some(id) => format!("{site}/_preview/{id}"),
        None => site.to_string(),
    };
    // Add the standard reverse-proxy fields the guest expects (X-Forwarded-*)
    // *before* the URI rewrite drops the public host context. This is the only
    // request mutation the host makes beyond the URI; no application semantics.
    set_forwarded_headers(&mut request, client_ip);
    // The guest sees the *site-relative* path via a well-formed absolute URI
    // (wasi:http needs scheme + authority); the public `/_sites/<site>/…` prefix
    // and host routing are the server's concern, not the handler's.
    rewrite_request_uri(&mut request, request_path);
    // Handlers must be enabled for the site (deny by default).
    let Some(site_handlers) = site_config
        .and_then(|c| c.handlers.as_ref())
        .filter(|h| h.enabled)
    else {
        return not_found();
    };

    // The component `.wasm` is a content-addressed blob in the deployment.
    let Some(entry) = manifest.files.get(&handler.component) else {
        tracing::warn!(site, component = %handler.component, "handler component missing from deployment");
        return handler_unavailable();
    };
    let wasm = match read_blob_fully(deploy, &entry.hash).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };

    let bindings = build_bindings(
        inner,
        site,
        &scope,
        preview,
        &handler.imports,
        site_handlers,
        &handler.env,
    )
    .await;

    // Per-site concurrency cap (held through the head response; the engine has
    // its own global cap on top). Keyed by `scope`, so a preview's load can't
    // starve the live site's budget.
    let _site_permit = match acquire_site_permit(inner, &scope, site_handlers) {
        Ok(permit) => permit,
        Err(()) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "site handler concurrency limit reached\n",
            )
                .into_response()
        }
    };

    // The live request body streams into the guest: the engine
    // bridges it frame-by-frame and enforces the byte cap as it flows, so nothing
    // is buffered up front. (Previously the body was read into memory under a
    // 16 MiB cap; that cap is now `Limits.max_body_bytes`, enforced streaming.)

    // Per-invocation limits = the site's caps (and per-handler caps), clamped to
    // the engine's ceiling.
    let limits = effective_limits(site_handlers, handler);

    // The blob hash is the engine's compilation-cache key. `duration` here is
    // time-to-head (the body streams afterward on its own task) — the meaningful
    // latency of the handler logic.
    let start = std::time::Instant::now();
    let result = inner
        .engine
        .serve_with_limits(&entry.hash, &wasm, request, bindings, limits)
        .await;
    inner.metrics.observe(
        site,
        metrics::Trigger::Http,
        &handler.route,
        &entry.hash,
        metrics::Outcome::from_result(&result),
        start.elapsed(),
    );
    match result {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            axum::http::Response::from_parts(parts, axum::body::Body::new(body))
        }
        Err(err) => {
            tracing::warn!(site, route = %handler.route, %err, "handler invocation failed");
            handler_error_response(&err)
        }
    }
}

/// Add the standard reverse-proxy fields to the request the guest sees. The
/// host injects only the `X-Forwarded-*` triple and no application semantics:
///
/// * `X-Forwarded-For` — the *resolved* client IP. This value already honors
///   any trusted upstream chain (see [`resolve_client_ip`]), so we overwrite
///   rather than append: the guest sees one authoritative address and never an
///   attacker-spoofed entry.
/// * `X-Forwarded-Host` — the `Host` the client requested.
/// * `X-Forwarded-Proto` — defaults to `http`, but a TLS-terminating upstream
///   that already set it is preserved.
#[cfg(feature = "handlers")]
fn set_forwarded_headers(request: &mut Request, client_ip: IpAddr) {
    let headers = request.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&client_ip.to_string()) {
        headers.insert(HeaderName::from_static("x-forwarded-for"), value);
    }
    if let Some(host) = headers.get(header::HOST).cloned() {
        headers.insert(HeaderName::from_static("x-forwarded-host"), host);
    }
    if !headers.contains_key("x-forwarded-proto") {
        headers.insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static("http"),
        );
    }
}

/// Rewrite a request's URI to an absolute `http://{authority}{site-relative
/// path}{?query}` so the handler sees its own path (not the `/_sites/<site>/…`
/// or host-routed form) and `wasi:http` gets a well-formed request.
#[cfg(feature = "handlers")]
fn rewrite_request_uri(request: &mut Request, request_path: &str) {
    let authority = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|host| !host.is_empty())
        .unwrap_or("localhost")
        .to_string();
    let path_and_query = match request.uri().query() {
        Some(query) => format!("{request_path}?{query}"),
        None => request_path.to_string(),
    };
    if let Ok(uri) = format!("http://{authority}{path_and_query}").parse() {
        *request.uri_mut() = uri;
    }
}

/// Activation gate for one handler/consumer component: every
/// requested import must be allowed by the site *and* served by this node; the
/// component must be present, within the posture's `max_component` size cap
/// (checked against the manifest's recorded size **before** the blob is read),
/// and must compile. `label` identifies the component in errors.
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
async fn precheck_component(
    deploy: &DeployStore,
    manifest: &Manifest,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    inner: &HandlerRuntimeInner,
    max_component: u64,
    imports: &[String],
    component: &str,
    label: &str,
) -> Result<(), String> {
    for import in imports {
        if !site_handlers.allow_imports.iter().any(|a| a == import) {
            return Err(format!(
                "{label} requests import {import:?} the site does not allow"
            ));
        }
        if import == "sql" && inner.sql.is_none() {
            return Err(format!(
                "{label} requests `sql` but this server has no SQL backend configured"
            ));
        }
        if import == "wasi:messaging" && inner.messaging.is_none() {
            return Err(format!(
                "{label} requests `wasi:messaging` but this server has no messaging backend"
            ));
        }
    }
    let entry = manifest
        .files
        .get(component)
        .ok_or_else(|| format!("{label} component {component:?} missing from deployment"))?;
    // Size-gate from the manifest metadata before reading the blob.
    if max_component != 0 && entry.size > max_component {
        return Err(format!(
            "{label} component {component:?} is {} bytes, over the {max_component}-byte limit",
            entry.size
        ));
    }
    let wasm = read_blob_bytes(deploy, &entry.hash)
        .await
        .map_err(|err| format!("reading {label} component: {err}"))?;
    inner
        .engine
        .precompile(&entry.hash, &wasm)
        .map_err(|err| format!("{label} failed to compile: {err}"))?;
    Ok(())
}

/// Read a content-addressed blob fully into memory.
#[cfg(feature = "handlers")]
async fn read_blob_bytes(deploy: &DeployStore, hash: &str) -> Result<Vec<u8>, DeployError> {
    let object = deploy.open_blob(hash).await?;
    let mut body = object.body;
    let mut buf = Vec::new();
    while let Some(chunk) = body.next().await {
        buf.extend_from_slice(&chunk?);
    }
    Ok(buf)
}

/// Like [`read_blob_bytes`], mapping failure to an HTTP response (dispatch path).
#[cfg(feature = "handlers")]
async fn read_blob_fully(deploy: &DeployStore, hash: &str) -> Result<Vec<u8>, Response> {
    read_blob_bytes(deploy, hash)
        .await
        .map_err(deploy_error_response)
}

/// Grant the per-site bindings the handler requested *and* the site allows
/// (effective imports = deploy ∩ site), served from the runtime's backends.
///
/// `scope` is the binding *identity* (the site for live serving, or
/// `{site}/_preview/{id}` for a preview) — kv/blob land under it, isolated. SQL
/// is resolved against the real `site`: for a preview the runtime applies the
/// operator's configured [`PreviewSqlMode`](boatramp_core::sql::PreviewSqlMode)
/// (empty / branch / shared) rather than blindly using the scoped name.
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
async fn build_bindings(
    inner: &HandlerRuntimeInner,
    site: &str,
    scope: &str,
    preview: Option<&str>,
    imports: &[String],
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    deploy_env: &std::collections::BTreeMap<String, String>,
) -> boatramp_handlers::Bindings {
    let granted = |name: &str| {
        imports.iter().any(|i| i == name) && site_handlers.allow_imports.iter().any(|a| a == name)
    };
    let mut bindings = boatramp_handlers::Bindings::new(scope);
    if granted("wasi:keyvalue") {
        bindings = bindings.with_keyvalue(scope, inner.kv.clone());
    }
    if granted("wasi:blobstore") {
        let max_blob = inner.max_blob_bytes.get().copied().unwrap_or(0);
        bindings = bindings.with_blobstore(scope, inner.storage.clone(), max_blob);
    }
    if granted("sql") {
        // Grant the default (`""`) SQL database; the guest selects it via
        // `sql.open("")`. A live request gets the site's database; a preview
        // gets one per the configured preview mode. A provider error is logged
        // and left ungranted so the guest sees `access denied`, not a 500.
        if let Some(provider) = &inner.sql {
            let opened = match preview {
                Some(id) => provider.preview_database(site, "", id).await,
                None => provider.database(site, "").await,
            };
            match opened {
                Ok(backend) => bindings = bindings.with_sql("", backend),
                Err(err) => tracing::warn!(site, %err, "opening site SQL database failed"),
            }
        }
    }
    if granted("wasi:messaging") {
        // Topics are namespaced under the binding `scope` (the site, or the
        // preview scope), so a guest publishes only into its own namespace and
        // previews can't touch live topics.
        if let Some(messaging) = &inner.messaging {
            bindings = bindings.with_messaging(format!("{scope}/"), messaging.clone());
        }
    }
    // Capture stdout/stderr for *every* invocation — not a
    // guest-requested import, but host-side observability. Tagged by `site` (so
    // a site's live + preview output aggregates under it) and rate-capped per
    // the site's `maxLogRate`.
    inner.logs.configure(site, site_handlers.max_log_rate);
    bindings = bindings.with_logging(site.to_string(), inner.logs.clone());

    // Environment for the guest: the deploy's static `env`
    // strings, plus the site's `secrets` — each a *reference* to a host
    // environment variable holding the real value, resolved here and never
    // stored in the manifest/config. The guest sees only these; the host's own
    // environment is never inherited.
    bindings = bindings.with_env(resolve_env(site, deploy_env, site_handlers));
    bindings
}

/// Assemble the guest environment: static deploy `env` first, then site
/// `secrets` resolved from the host environment (a missing referent is logged
/// and skipped, never injected as empty). A secret name overrides a static one.
#[cfg(feature = "handlers")]
fn resolve_env(
    site: &str,
    deploy_env: &std::collections::BTreeMap<String, String>,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = deploy_env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (guest_name, host_ref) in &site_handlers.secrets {
        match std::env::var(host_ref) {
            Ok(value) => {
                env.retain(|(k, _)| k != guest_name);
                env.push((guest_name.clone(), value));
            }
            Err(_) => tracing::warn!(
                site,
                secret = %guest_name,
                "site secret references env var {host_ref}, which is not set; not injected"
            ),
        }
    }
    env
}

/// Process one claimed batch for a consumer subscribed to `namespaced_topic`
/// (the substrate topic, `{scope}/{topic}`). Claims up to `batch` messages,
/// runs each through the consumer component under `limits`, then **acks** the
/// ones the guest handled and **nacks** (for redelivery — eventually
/// dead-lettered after `max_attempts`) the ones it failed. Returns the count
/// acked. The dispatcher background task (alias activation policy) loops this.
///
/// The guest sees its *scope-relative* topic (the `scope_prefix` is stripped),
/// matching the topic it declared in its `consumers` config. Driven by the
/// background scheduler ([`run_scheduler_tick`]) per active consumer.
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
async fn dispatch_consumer_batch(
    engine: &boatramp_handlers::HandlerEngine,
    messaging: &dyn boatramp_core::messaging::Messaging,
    metrics: &metrics::Metrics,
    site: &str,
    namespaced_topic: &str,
    scope_prefix: &str,
    component_hash: &str,
    component: &[u8],
    bindings: &boatramp_handlers::Bindings,
    limits: boatramp_handlers::Limits,
    lease: Duration,
    max_attempts: u32,
    batch: usize,
) -> usize {
    let claimed = match messaging
        .claim(namespaced_topic, lease, batch, max_attempts)
        .await
    {
        Ok(claimed) => claimed,
        Err(err) => {
            tracing::warn!(topic = namespaced_topic, %err, "messaging claim failed");
            return 0;
        }
    };
    let mut acked = 0;
    for msg in claimed {
        let guest_topic = msg.topic.strip_prefix(scope_prefix).unwrap_or(&msg.topic);
        let start = std::time::Instant::now();
        let result = engine
            .dispatch_message(
                component_hash,
                component,
                guest_topic,
                &msg.payload,
                bindings.clone(),
                limits,
            )
            .await;
        metrics.observe(
            site,
            metrics::Trigger::Consumer,
            guest_topic,
            component_hash,
            metrics::Outcome::from_result(&result),
            start.elapsed(),
        );
        match result {
            Ok(()) => match messaging.ack(&msg).await {
                Ok(()) => acked += 1,
                Err(err) => tracing::warn!(id = msg.id, %err, "messaging ack failed"),
            },
            Err(err) => {
                tracing::warn!(
                    id = msg.id,
                    attempts = msg.attempts,
                    %err,
                    "consumer failed; redelivering (dead-letters after max attempts)"
                );
                let _ = messaging.nack(&msg).await;
            }
        }
    }
    acked
}

// ---- background scheduler: consumers (alias activation) ----

/// How often the scheduler polls each active consumer for messages.
#[cfg(feature = "handlers")]
const SCHEDULER_TICK: Duration = Duration::from_millis(500);
/// Visibility-timeout lease per consumer delivery.
#[cfg(feature = "handlers")]
const CONSUMER_LEASE: Duration = Duration::from_secs(30);
/// Deliveries before a message is dead-lettered.
#[cfg(feature = "handlers")]
const CONSUMER_MAX_ATTEMPTS: u32 = 5;
/// Messages claimed per consumer per tick.
#[cfg(feature = "handlers")]
const CONSUMER_BATCH: usize = 16;

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
struct CronNow {
    minute: u32,
    hour: u32,
    dom: u32,
    month: u32,
    dow: u32,
    minute_stamp: i64,
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
struct CronEntry {
    last_minute: i64,
    running: Arc<std::sync::atomic::AtomicBool>,
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
async fn spawn_blob_watcher(
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
async fn run_scheduler_tick(
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
fn handler_unavailable() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, "handler unavailable\n").into_response()
}

/// The per-invocation limits for a handler: the site's caps and any per-handler
/// caps (the lower of the two for each dimension). Left at the engine default
/// where neither is set; the engine then clamps to its own ceiling.
#[cfg(feature = "handlers")]
fn effective_limits(
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
fn acquire_site_permit(
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
fn handler_error_response(err: &boatramp_handlers::HandlerError) -> Response {
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

// ---- SSE topic streams ---------------------------------

/// SSE heartbeat interval: a `: keep-alive` comment is emitted this often so a
/// dead client (whose buffer never drains) is detected and its connection — and
/// the permits it holds — reclaimed.
#[cfg(feature = "handlers")]
const STREAM_HEARTBEAT: Duration = Duration::from_secs(15);
/// Close a stream that has produced no *event* (heartbeats aside) for this long,
/// reclaiming the connection permit from a quiet topic. A client that still
/// wants the feed reconnects (with `Last-Event-ID`).
#[cfg(feature = "handlers")]
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// Default per-scope SSE connection cap when the site sets no
/// `maxStreamConnections`, so streams can never grow unbounded.
#[cfg(feature = "handlers")]
const DEFAULT_STREAM_CONNECTIONS: u32 = 256;
/// Hard per-`(scope, IP)` concurrent SSE connection cap, so one client can't
/// monopolise the per-site budget.
#[cfg(feature = "handlers")]
const MAX_STREAMS_PER_IP: u32 = 8;

/// Whether a config route pattern matches `request_path` (leading-slash
/// normalised), mirroring [`route::match_handler`]'s path handling.
#[cfg(feature = "handlers")]
fn route_matches(route: &str, request_path: &str) -> bool {
    let path = if request_path.starts_with('/') {
        std::borrow::Cow::Borrowed(request_path)
    } else {
        std::borrow::Cow::Owned(format!("/{request_path}"))
    };
    Pattern::compile(route)
        .map(|pattern| pattern.is_match(&path))
        .unwrap_or(false)
}

/// RAII decrement for the per-`(scope, IP)` live-stream counter.
#[cfg(feature = "handlers")]
struct IpStreamGuard {
    counts: Arc<std::sync::Mutex<std::collections::HashMap<(String, IpAddr), u32>>>,
    key: (String, IpAddr),
}

#[cfg(feature = "handlers")]
impl Drop for IpStreamGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap();
        if let Some(n) = counts.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

/// The owned guards a live SSE connection holds for its whole lifetime: the
/// per-scope connection permit and the per-IP counter guard. Both are released
/// (dropped) when the client disconnects or the idle timeout fires.
#[cfg(feature = "handlers")]
struct StreamConn {
    events: futures::stream::BoxStream<'static, axum::response::sse::Event>,
    _site_permit: tokio::sync::OwnedSemaphorePermit,
    _ip_guard: IpStreamGuard,
}

/// Acquire a per-scope SSE connection permit (cap = the site's
/// `maxStreamConnections`, else [`DEFAULT_STREAM_CONNECTIONS`]). The semaphore is
/// created on first use and cached, so a later change to the cap takes effect
/// only once the scope's streams have drained (same as the per-site concurrency
/// semaphore). `Err(())` when the scope is at its cap.
#[cfg(feature = "handlers")]
fn acquire_stream_permit(
    inner: &HandlerRuntimeInner,
    scope: &str,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
) -> Result<tokio::sync::OwnedSemaphorePermit, ()> {
    let max = site_handlers
        .max_stream_connections
        .unwrap_or(DEFAULT_STREAM_CONNECTIONS)
        .max(1) as usize;
    let semaphore = {
        let mut map = inner.stream_semaphores.lock().unwrap();
        map.entry(scope.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(max)))
            .clone()
    };
    semaphore.try_acquire_owned().map_err(|_| ())
}

/// Acquire a per-`(scope, IP)` live-stream slot, returning an RAII guard that
/// decrements the counter on drop. `Err(())` when this IP already holds
/// [`MAX_STREAMS_PER_IP`] streams on the scope.
#[cfg(feature = "handlers")]
fn acquire_stream_ip_slot(
    inner: &HandlerRuntimeInner,
    scope: &str,
    ip: IpAddr,
) -> Result<IpStreamGuard, ()> {
    let key = (scope.to_string(), ip);
    {
        let mut counts = inner.stream_ip_counts.lock().unwrap();
        let n = counts.entry(key.clone()).or_insert(0);
        if *n >= MAX_STREAMS_PER_IP {
            return Err(());
        }
        *n += 1;
    }
    Ok(IpStreamGuard {
        counts: inner.stream_ip_counts.clone(),
        key,
    })
}

/// Serve a configured SSE stream: subscribe to each of its (scope-namespaced)
/// topics on the messaging backend and fan them out to the client as
/// `text/event-stream`, with `Last-Event-ID` resume, a heartbeat, an idle
/// timeout, and per-scope + per-IP connection caps.
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
async fn serve_stream(
    inner: &Arc<HandlerRuntimeInner>,
    site: &str,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    stream: &boatramp_core::config::StreamConfig,
    after: Option<String>,
    client_ip: IpAddr,
    preview: Option<&str>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures::StreamExt;

    let Some(messaging) = inner.messaging.clone() else {
        // Streams require a messaging backend; without one the route is dead.
        return not_found();
    };
    // Binding identity, same rule as request handlers: live binds to the site, a
    // preview gets its own `{site}/_preview/{id}` namespace so it can never
    // observe live topics.
    let scope = match preview {
        Some(id) => format!("{site}/_preview/{id}"),
        None => site.to_string(),
    };

    // Per-scope connection cap, then per-IP cap — both held for the connection's
    // lifetime via the guards moved into the stream below.
    let site_permit = match acquire_stream_permit(inner, &scope, site_handlers) {
        Ok(permit) => permit,
        Err(()) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "site stream connection limit reached\n",
            )
                .into_response()
        }
    };
    let ip_guard = match acquire_stream_ip_slot(inner, &scope, client_ip) {
        Ok(guard) => guard,
        Err(()) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "per-client stream connection limit reached\n",
            )
                .into_response()
        }
    };

    // `after` is the client's Last-Event-ID (best-effort resume).

    // One live subscription per configured topic, each namespaced under the
    // scope (so the client sees only its own site's/preview's traffic). The
    // event's `event:` field is the *config* topic (scope-relative), matching
    // what the guest published.
    let merged = futures::stream::select_all(stream.topics.iter().map(|topic| {
        let namespaced = format!("{scope}/{topic}");
        let label = topic.clone();
        messaging
            .subscribe(&namespaced, after.as_deref())
            .map(move |event| stream_event(&label, &event.id, &event.payload))
            .boxed()
    }));

    // Hold the permits for the connection's lifetime and apply the idle timeout:
    // if no event arrives within STREAM_IDLE_TIMEOUT the stream ends, dropping
    // the guards (releasing the permit + IP slot). The heartbeat keeps a live
    // client's connection warm in between.
    let conn = StreamConn {
        events: merged.boxed(),
        _site_permit: site_permit,
        _ip_guard: ip_guard,
    };
    let body = futures::stream::unfold(conn, |mut conn| async move {
        match tokio::time::timeout(STREAM_IDLE_TIMEOUT, conn.events.next()).await {
            Ok(Some(event)) => Some((Ok::<Event, std::convert::Infallible>(event), conn)),
            // All topics ended, or the topic went idle past the timeout: close.
            Ok(None) | Err(_) => None,
        }
    });

    Sse::new(body)
        .keep_alive(
            KeepAlive::new()
                .interval(STREAM_HEARTBEAT)
                .text("keep-alive"),
        )
        .into_response()
}

/// Serve a configured stream as a **WebSocket**: the same scope-namespaced
/// `topics` fan out to the client
/// (server→client, as binary frames), and — bidirectionally — frames the client
/// sends are published to the (scope-namespaced) `publish_topic` on the messaging
/// substrate, so a consumer/handler processes them. Reuses the per-scope + per-IP
/// connection caps; cluster fan-out rides the same `subscribe`/StreamBus the SSE
/// path uses, so the behavior is uniform across single-node, cluster, and CF
/// (where the edge Worker proxies the upgrade to the container).
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
async fn serve_ws_stream(
    inner: &Arc<HandlerRuntimeInner>,
    site: &str,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    stream: &boatramp_core::config::StreamConfig,
    ws: axum::extract::ws::WebSocketUpgrade,
    client_ip: IpAddr,
    preview: Option<&str>,
) -> Response {
    use futures::StreamExt;

    let Some(messaging) = inner.messaging.clone() else {
        return not_found();
    };
    // Same binding identity as SSE streams + request handlers: live binds to the
    // site, a preview to its own namespace.
    let scope = match preview {
        Some(id) => format!("{site}/_preview/{id}"),
        None => site.to_string(),
    };
    let site_permit = match acquire_stream_permit(inner, &scope, site_handlers) {
        Ok(permit) => permit,
        Err(()) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "site stream connection limit reached\n",
            )
                .into_response()
        }
    };
    let ip_guard = match acquire_stream_ip_slot(inner, &scope, client_ip) {
        Ok(guard) => guard,
        Err(()) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "per-client stream connection limit reached\n",
            )
                .into_response()
        }
    };

    // server→client: one live subscription per topic, merged (scope-namespaced so
    // a client only sees its own site's/preview's traffic).
    let mut downstream = futures::stream::select_all(stream.topics.iter().map(|topic| {
        let namespaced = format!("{scope}/{topic}");
        messaging
            .subscribe(&namespaced, None)
            .map(|e| e.payload)
            .boxed()
    }));
    // client→server: messages publish to this scope-namespaced topic (if set).
    let publish_topic = stream
        .publish_topic
        .as_ref()
        .map(|topic| format!("{scope}/{topic}"));

    ws.on_upgrade(move |socket| async move {
        use axum::extract::ws::Message;
        use futures::SinkExt;
        // Holding the permits for the socket's lifetime caps concurrent streams;
        // they drop (releasing the slot) when this task ends.
        let _permits = (site_permit, ip_guard);
        let (mut sink, mut incoming) = socket.split();
        loop {
            tokio::select! {
                // Forward a subscription payload to the client (binary frame).
                event = downstream.next() => match event {
                    Some(payload) => {
                        if sink.send(Message::Binary(payload)).await.is_err() {
                            break; // client gone
                        }
                    }
                    None => break, // all topics ended
                },
                // Publish a client message upstream; close on disconnect.
                msg = incoming.next() => match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Some(topic) = &publish_topic {
                            let _ = messaging.publish(topic, text.as_bytes()).await;
                        }
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        if let Some(topic) = &publish_topic {
                            let _ = messaging.publish(topic, &bytes).await;
                        }
                    }
                    // Ping/Pong are handled by axum; ignore them here.
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break, // closed / errored
                },
            }
        }
    })
}

/// Render one messaging payload as an SSE event. A UTF-8 (CR-free) payload is
/// sent verbatim under the topic's event name; a binary (or CR-bearing) payload
/// is base64-encoded under a `{topic}.b64` event so embedded control bytes can't
/// break the SSE framing. The durable message id rides as the SSE `id:` for
/// `Last-Event-ID` resume.
#[cfg(feature = "handlers")]
fn stream_event(topic: &str, id: &str, payload: &[u8]) -> axum::response::sse::Event {
    use axum::response::sse::Event;
    match std::str::from_utf8(payload) {
        // `Event::data` splits on '\n' into multiple `data:` lines but panics on
        // a lone '\r'; route those through base64 instead.
        Ok(text) if !text.contains('\r') => Event::default().id(id).event(topic).data(text),
        _ => {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
            Event::default()
                .id(id)
                .event(format!("{topic}.b64"))
                .data(encoded)
        }
    }
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
