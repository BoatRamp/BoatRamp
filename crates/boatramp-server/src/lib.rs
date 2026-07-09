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
mod domain_verify;
pub mod envelope;
mod gateway;
#[cfg(feature = "http3")]
mod http3;
mod limits;
#[cfg(feature = "handlers")]
mod logs;
#[cfg(feature = "handlers")]
mod metrics;
#[cfg(feature = "oidc")]
mod oidc;
mod ratelimit;
/// External token signer backends: KMS / HSM / Vault-hosted
/// control-plane root keys behind the [`boatramp_core::cose::Signer`] seam.
pub mod signer;
mod srvmetrics;
pub use auth::Auth;
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
            })),
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
}

/// The listener's own connection scheme (`true` = `https`), carried as an
/// extension so the serving path can derive the scheme without trusting a
/// forged `X-Forwarded-Proto` from a direct client.
#[derive(Clone, Copy)]
struct ServedOverTls(bool);

/// The configured catch-all site, carried as an extension so the
/// host fallback can serve it for an otherwise-unmatched `Host`.
#[derive(Clone, Default)]
struct DefaultSite(Option<Arc<str>>);

/// Whether the host fallback may resolve an unmatched `Host` to a site without an
/// explicit domain registration (first-label `<site>.host`, or the sole served
/// site). Carried as an extension; the effective gate is resolved by `serve`
/// (posture knob OR loopback bind). `false` = strict (default_site or 404 only).
#[derive(Clone, Copy, Default)]
struct ImplicitRouting(bool);

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
        BootstrapGate(secret.filter(|s| !s.is_empty()).map(|s| {
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
    /// Admit `(node, pubkey_hex)` from an already-verified join token whose
    /// single-use handle is `jti` — trusts the key cluster-wide and adds it to
    /// membership. `Ok(false)` = the token was already spent. `Err` is a
    /// human-readable failure.
    async fn admit(&self, node: u64, pubkey_hex: &str, jti: &str) -> Result<bool, String>;

    /// Rotate **this node's** mesh identity (make-before-break) and return the new
    /// public key (SPKI hex). Node-local: only the node itself can mint + persist
    /// its private key, so this rotates the key of the node whose API is hit.
    async fn rotate_key(&self) -> Result<String, String>;

    /// Revoke `node` from the mesh: delete its trust cluster-wide (so it can no
    /// longer authenticate) and drop it from the quorum. `Err` is a
    /// human-readable failure.
    async fn revoke(&self, node: u64) -> Result<(), String>;
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

/// The current Unix time in seconds.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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
    // The listener's own scheme, for deriving the request scheme when
    // `X-Forwarded-Proto` isn't from a trusted proxy.
    let served_over_tls = ServedOverTls(options.served_over_tls);
    let default_site = DefaultSite(options.default_site.map(Arc::from));
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
        .route("/api/prune", get(prune_report).post(prune_delete))
        .route("/api/scrub", post(scrub_blobs))
        .route("/api/certs", get(cert_status))
        .route("/api/cache/invalidate", post(invalidate_cache))
        .route(
            "/api/authz/policy",
            get(get_authz_policy).put(put_authz_policy),
        )
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
        .route("/api/sites/:site/_boatramp/dlq", post(operator_dlq));
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
        // Explicit by-name admin/testing route. `/_sites/<name>/…` is the
        // going-forward name; `/sites/<name>/…` is a deprecated alias (warns once).
        .route("/_sites/*rest", any(serve_sites))
        .route("/sites/*rest", any(serve_sites))
        .route("/_deploy/*rest", get(serve_preview))
        .fallback(serve_by_host)
        .with_state(deploy)
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
        // The catch-all site for unmatched hosts; `None` → 404.
        .layer(Extension(default_site))
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

async fn healthz() -> &'static str {
    "ok"
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

/// Set a site's [`SiteConfig`] (rebuilds its host → site index).
async fn put_site_config(
    State(deploy): State<DeployStore>,
    Path(site): Path<String>,
    Json(config): Json<SiteConfig>,
) -> Response {
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
    /// The joining node's id (must match the token's grant).
    node_id: u64,
    /// The joining node's mesh public key, hex (must match the token's grant).
    pubkey: String,
    /// The single-use mesh join token (base64), from `cluster join-token`.
    token: String,
}

#[derive(Serialize)]
struct JoinResponse {
    /// Whether this call admitted the node (`false` = the token was already spent).
    admitted: bool,
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
    let claim = match cose::verify_join(&request.token, &public, now_unix()) {
        Ok(claim) => claim,
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
    // Anti-theft / anti-replay: the presented identity must be exactly the one
    // the token authorizes.
    if request.node_id != claim.node_id || request.pubkey.trim() != claim.pubkey_hex {
        return (
            StatusCode::FORBIDDEN,
            "join token does not authorize this node/key\n",
        )
            .into_response();
    }
    match admitter
        .admit(claim.node_id, &claim.pubkey_hex, &claim.jti)
        .await
    {
        Ok(true) => (StatusCode::OK, Json(JoinResponse { admitted: true })).into_response(),
        Ok(false) => (StatusCode::CONFLICT, "join token already spent\n").into_response(),
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

#[derive(Deserialize)]
struct CreateJoinTokenRequest {
    /// The joining node's id.
    node_id: u64,
    /// The joining node's mesh public key (SPKI hex, from its startup log).
    pubkey: String,
    /// Optional TTL in seconds; omitted ⇒ [`DEFAULT_JOIN_TOKEN_TTL_SECS`].
    #[serde(default)]
    ttl_secs: Option<u64>,
}

#[derive(Serialize)]
struct CreateJoinTokenResponse {
    /// The minted join token, base64 — shown once, never stored.
    token: String,
    /// The node id the token admits.
    node_id: u64,
    /// The token's expiry (Unix seconds).
    expires_at: u64,
}

/// Mint a **single-use mesh join token** bound to `(node_id, pubkey)` with a TTL:
/// a stolen token cannot admit a different key, and its
/// single-use handle is spent atomically at admission. Needs the root private key
/// (the issuer); a verify-only node returns `501`. Admin-scoped (the deny-safe
/// `Right::required` default gates `/api/cluster/*`). Returned once, never stored
/// — single-use is enforced cluster-side, so there is no server-side metadata.
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
    let pubkey = request.pubkey.trim();
    if pubkey.is_empty() || pubkey.len() % 2 != 0 || !pubkey.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return (
            StatusCode::BAD_REQUEST,
            "pubkey must be a hex-encoded mesh public key\n",
        )
            .into_response();
    }
    let ttl = request.ttl_secs.unwrap_or(DEFAULT_JOIN_TOKEN_TTL_SECS);
    let now = now_unix();
    match cose::mint_join(request.node_id, pubkey, ttl, now, &*signer).await {
        Ok(token) => (
            StatusCode::CREATED,
            Json(CreateJoinTokenResponse {
                token,
                node_id: request.node_id,
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
    Path(name): Path<String>,
    Json(request): Json<PutComputeRequest>,
) -> Response {
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

/// Warn (once per process) that the legacy `/sites/<name>/…` prefix was hit,
/// pointing at the going-forward `/_sites/<name>/…` name.
fn warn_legacy_sites_prefix_once() {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            "the `/sites/<name>/` serving prefix is deprecated; use \
             `/_sites/<name>/` (an admin/testing route), or serve the site \
             at root via host routing"
        );
    }
}

/// Serve under the explicit by-name admin/testing route:
/// `/_sites/<site>/...` (the going-forward name) or the deprecated
/// `/sites/<site>/...` alias. The catch-all captures `<site>` or
/// `<site>/<path...>`. Accepts any method so a proxy rewrite can forward
/// non-`GET` requests. This route is not host-routed and does not serve a
/// root-mounted site — for that, use host routing (see the addressing docs).
async fn serve_sites(
    State(deploy): State<DeployStore>,
    Extension(limiter): Extension<Arc<dyn RateLimitStore>>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let raw = request.uri().path();
    let rest = if let Some(rest) = raw.strip_prefix("/_sites/") {
        rest.trim_start_matches('/')
    } else {
        warn_legacy_sites_prefix_once();
        raw.strip_prefix("/sites/")
            .unwrap_or("")
            .trim_start_matches('/')
    };
    let (site, path) = rest.split_once('/').unwrap_or((rest, ""));
    if site.is_empty() {
        return not_found();
    }
    let (site, request_path) = (site.to_string(), format!("/{path}"));
    let visitor = Visitor {
        peer: peer.ip(),
        limiter: limiter.as_ref(),
    };
    // The explicit `/sites/<name>/` admin/testing route is not host-routed, so
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

/// Virtualhost fallback: resolve the site from the `Host` header, serve the
/// request path. Catches everything not matched by `/healthz`, `/api/*`, or the
/// explicit `/sites/*` route.
#[allow(clippy::too_many_arguments)] // axum extractors, not a real parameter list
async fn serve_by_host(
    State(deploy): State<DeployStore>,
    Extension(limiter): Extension<Arc<dyn RateLimitStore>>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(default_site): Extension<DefaultSite>,
    Extension(implicit): Extension<ImplicitRouting>,
    Extension(preview_policy): Extension<PreviewPolicy>,
    Extension(preview_auth): Extension<Auth>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
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
        // Unmatched host. Resolution order (each step lower priority than an
        // explicit `domain`/`wildcard` match above):
        //   (A) implicit first-label routing — `<site>.host` names a served site;
        //   the configured catch-all `default_site` (explicit operator intent);
        //   (B) implicit sole-site routing — exactly one site is served.
        // (A)/(B) run only when `implicit` is on (dev / single-tenant / a loopback
        // bind), so a public multi-tenant host never resolves to a site by name.
        Ok(None) => {
            // (A) First host label naming a served site wins over the generic
            // catch-all: `blog.localhost` → site `blog` at root, zero DNS.
            if implicit.0 {
                let label = host.split('.').next().unwrap_or("");
                if !label.is_empty()
                    && matches!(deploy.current_id(label).await, Ok(Some(_)))
                {
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
            match &default_site.0 {
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
                // (B) No explicit catch-all: implicitly serve the sole site, so a
                // fresh single-site server answers at the bare host/root.
                None => {
                    if implicit.0 {
                        if let Ok(sites) = deploy.list_sites().await {
                            if let [only] = sites.as_slice() {
                                let visitor = Visitor {
                                    peer: peer.ip(),
                                    limiter: limiter.as_ref(),
                                };
                                return serve_request(
                                    &deploy,
                                    only,
                                    &request_path,
                                    request,
                                    &visitor,
                                    &handlers,
                                    true,
                                )
                                .await;
                            }
                        }
                    }
                    not_found()
                }
            }
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Strip a trailing `:port` from a `Host` value.
fn strip_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

/// Parse the wildcard preview host form `<id>.deploy.<site-host>` into
/// `(id-prefix, site-host)`. The reserved `deploy` label plus the requirement
/// that the id label be hex (a content-hash prefix) keep ordinary subdomains
/// from matching. `None` for any non-preview host. (The label is `deploy`, not
/// `_deploy` like the path form `/_deploy/<id>/`: an underscore is valid in DNS
/// but illegal in a TLS-cert SAN, so the `*.deploy.<host>` wildcard cert needs
/// an underscore-free label.)
fn parse_deploy_host(host: &str) -> Option<(&str, &str)> {
    let (id, after) = host.split_once('.')?;
    let site_host = after.strip_prefix("deploy.")?;
    if id.is_empty() || site_host.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((id, site_host))
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
                .map(|pq| pq.as_str())
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
/// every request to its HTTPS equivalent. Bound
/// alongside the HTTPS listener so plain-HTTP visitors are upgraded even when
/// boatramp terminates TLS itself. ACME challenges use ALPN-01/DNS-01, so this
/// listener is redirect-only (no `/.well-known/acme-challenge` to serve).
pub fn http_redirect_router() -> Router {
    Router::new().fallback(redirect_http_to_https)
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
        .map(|pq| pq.as_str())
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
    Extension(preview_policy): Extension<PreviewPolicy>,
    Extension(preview_auth): Extension<Auth>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
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
    let outcome = route::resolve(&manifest.config, &manifest.files, request_path);
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
                return dispatch_handler(
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
                .await;
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
                            return match axum::extract::ws::WebSocketUpgrade::from_request_parts(
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
                            };
                        }
                        // Pull the only field needed from the request as an owned
                        // value: `&Request` is not `Send` (the body isn't `Sync`),
                        // so it must not be held across the dispatch await.
                        let after = request
                            .headers()
                            .get("last-event-id")
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_string);
                        return serve_stream(
                            inner,
                            site,
                            site_handlers,
                            stream,
                            after,
                            client_ip,
                            preview,
                        )
                        .await;
                    }
                    // A stream route on a site with handlers disabled / no runtime
                    // is not served (deny by default).
                    return not_found();
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
                return match gw.upstreams.get(&route.upstream) {
                    Some(upstream) => {
                        // A compute-backed upstream resolves its pool live from
                        // the workload's healthy replica endpoints. Record
                        // the request as activity so the reconcile loop
                        // keeps the workload warm / wakes it, and only sleeps it
                        // once genuinely idle.
                        let compute_backends = match &upstream.compute {
                            Some(workload) => {
                                gateway::record_activity(workload);
                                let mut pool = compute_endpoints(deploy, workload).await;
                                // Wake-from-zero: no live replica but one
                                // is parked → nudge the reconcile loop to restore it
                                // and hold this request until it's serving. The cold
                                // start is invisible to the client; only a genuine
                                // restore failure (timeout) falls through to 502.
                                if pool.is_empty() && has_parked_replica(deploy, workload).await {
                                    gateway::wake_reconcile();
                                    pool = await_warm(deploy, workload, COMPUTE_WAKE_TIMEOUT).await;
                                }
                                Some(pool)
                            }
                            None => None,
                        };
                        dispatch_gateway(
                            request,
                            site.unwrap_or(""),
                            &route.upstream,
                            upstream,
                            request_path,
                            client_ip,
                            compute_backends,
                        )
                        .await
                    }
                    None => (
                        StatusCode::BAD_GATEWAY,
                        "gateway route references an unknown upstream\n",
                    )
                        .into_response(),
                };
            }
        }
    }
    match outcome {
        Outcome::Redirect { location, status } => redirect(status, &location),
        Outcome::Proxy { url } => proxy(request, &url, &manifest.config, client_ip).await,
        Outcome::File {
            path: served,
            entry,
        } => {
            // Static content answers only GET/HEAD; other methods are 405.
            if !matches!(*request.method(), Method::GET | Method::HEAD) {
                return method_not_allowed();
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
    }
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

/// Pick the best precompressed variant the client accepts (brotli preferred,
/// then gzip), or `None` to serve the identity representation.
fn negotiate_encoding<'a>(
    entry: &'a FileEntry,
    req_headers: &HeaderMap,
) -> Option<(&'a str, &'a boatramp_core::deploy::Variant)> {
    if entry.variants.is_empty() {
        return None;
    }
    let accept = req_headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|value| value.to_str().ok())?;
    for enc in ["br", "gzip"] {
        if accepts_encoding(accept, enc) {
            if let Some(variant) = entry.variants.get(enc) {
                // Only serve a variant that is actually smaller than identity.
                // A variant ≥ identity gains nothing and is a decompression-bomb
                // smell; fall back to identity. boatramp itself
                // never decompresses (it streams the precompressed bytes and the
                // client decodes), so this is the whole server-side surface.
                if variant.size < entry.size {
                    return Some((enc, variant));
                }
            }
        }
    }
    None
}

/// Whether a content type is worth compressing on the fly (text + structured
/// formats; never already-compressed media). Parameters (`; charset=…`) ignored.
#[cfg(feature = "compression")]
fn is_compressible(content_type: &str) -> bool {
    let ct = content_type.split(';').next().unwrap_or("").trim();
    matches!(
        ct,
        "application/javascript"
            | "application/json"
            | "application/manifest+json"
            | "application/xml"
            | "application/rss+xml"
            | "application/atom+xml"
            | "image/svg+xml"
            | "application/wasm"
    ) || ct.starts_with("text/")
}

/// On-the-fly compression, applied late so it covers
/// dynamic (handler/proxy) responses and static files with no precompressed
/// variant. Compresses only when the response is `200`, has no existing
/// `Content-Encoding` (a chosen variant / already-encoded upstream is left
/// alone), carries no `Set-Cookie` (BREACH safety), has a compressible type, and
/// (when its length is known) is at least `min_size`. Streams the encoder.
#[cfg(feature = "compression")]
fn maybe_compress(response: Response, accept_encoding: Option<&str>, min_size: u64) -> Response {
    use tokio_util::io::{ReaderStream, StreamReader};

    if response.status() != StatusCode::OK {
        return response;
    }
    let headers = response.headers();
    if headers.contains_key(header::CONTENT_ENCODING) || headers.contains_key(header::SET_COOKIE) {
        return response;
    }
    let compressible = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_compressible);
    if !compressible {
        return response;
    }
    if let Some(len) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        if len < min_size {
            return response;
        }
    }
    let accept = accept_encoding.unwrap_or("");
    // Prefer gzip for on-the-fly (fast); fall back to brotli.
    let encoding = if accepts_encoding(accept, "gzip") {
        "gzip"
    } else if accepts_encoding(accept, "br") {
        "br"
    } else {
        return response;
    };

    let (mut parts, body) = response.into_parts();
    let reader = StreamReader::new(
        body.into_data_stream()
            .map(|chunk| chunk.map_err(std::io::Error::other)),
    );
    let compressed = if encoding == "gzip" {
        Body::from_stream(ReaderStream::new(
            async_compression::tokio::bufread::GzipEncoder::new(reader),
        ))
    } else {
        Body::from_stream(ReaderStream::new(
            async_compression::tokio::bufread::BrotliEncoder::new(reader),
        ))
    };
    // The framing changes, so drop the old length and let it be re-chunked.
    parts.headers.remove(header::CONTENT_LENGTH);
    parts
        .headers
        .insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
    append_vary_accept_encoding(&mut parts.headers);
    Response::from_parts(parts, compressed)
}

/// Add `accept-encoding` to the `Vary` header (creating or extending it).
#[cfg(feature = "compression")]
fn append_vary_accept_encoding(headers: &mut HeaderMap) {
    let existing = headers
        .get(header::VARY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if existing
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case("accept-encoding"))
    {
        return;
    }
    let merged = if existing.is_empty() {
        "accept-encoding".to_string()
    } else {
        format!("{existing}, accept-encoding")
    };
    if let Ok(value) = HeaderValue::from_str(&merged) {
        headers.insert(header::VARY, value);
    }
}

/// Whether an `Accept-Encoding` value accepts `enc` (honoring an explicit
/// `;q=0` refusal and the `*` wildcard).
fn accepts_encoding(accept: &str, enc: &str) -> bool {
    accept.split(',').any(|part| {
        let mut bits = part.trim().split(';');
        let token = bits.next().unwrap_or("").trim();
        let refused = bits.any(|p| matches!(p.trim(), "q=0" | "q=0.0" | "q=0.00" | "q=0.000"));
        !refused && (token.eq_ignore_ascii_case(enc) || token == "*")
    })
}

/// Set `Content-Encoding` for a served variant (no-op for identity).
fn set_content_encoding(headers: &mut HeaderMap, encoding: Option<&str>) {
    if let Some(enc) = encoding {
        set_header(headers, header::CONTENT_ENCODING, enc);
    }
}

/// Build the common response headers: Content-Type (MIME override → entry),
/// ETag, Accept-Ranges, Cache-Control default, then deploy-config header rules.
fn response_headers(
    config: &DeployConfig,
    request_path: &str,
    served_path: &str,
    entry: &FileEntry,
    etag: &str,
) -> HeaderMap {
    let mut headers = HeaderMap::new();

    let content_type = mime_override(config, served_path).or_else(|| entry.content_type.clone());
    if let Some(value) = content_type
        .as_deref()
        .and_then(|ct| HeaderValue::from_str(ct).ok())
    {
        headers.insert(header::CONTENT_TYPE, value);
    }
    set_header(&mut headers, header::ETAG, etag);
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    // Safe defaults for a static host; operators can override either via a
    // header rule (or `Referrer-Policy` site-wide via SecurityConfig later).
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    // When precompressed variants exist, caches must key on Accept-Encoding.
    if !entry.variants.is_empty() {
        headers.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    }
    // Cache-Control: the operator's blanket `cache.default` wins; otherwise fall
    // back to smart per-file defaults (fingerprinted assets → immutable, HTML →
    // revalidate). Explicit header rules below override either.
    let cache = config
        .cache
        .default
        .as_deref()
        .or_else(|| route::cache_control_default(served_path, content_type.as_deref()));
    if let Some(cache) = cache {
        set_header(&mut headers, header::CACHE_CONTROL, cache);
    }
    apply_header_rules(config, request_path, &mut headers);
    headers
}

/// Apply matching deploy-config header rules (set/unset) to the response.
fn apply_header_rules(config: &DeployConfig, request_path: &str, headers: &mut HeaderMap) {
    for rule in &config.headers {
        let matches = Pattern::compile(&rule.matches)
            .ok()
            .is_some_and(|pattern| pattern.is_match(request_path));
        if !matches {
            continue;
        }
        for name in &rule.unset {
            if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
                headers.remove(name);
            }
        }
        for (key, value) in &rule.set {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(name, value);
            }
        }
    }
}

/// MIME override for `served_path`'s extension, from the deploy config.
fn mime_override(config: &DeployConfig, served_path: &str) -> Option<String> {
    let ext = std::path::Path::new(served_path).extension()?.to_str()?;
    config.mime_overrides.get(&format!(".{ext}")).cloned()
}

/// Most ranges honored in one `Range` request; beyond this the caller ignores
/// `Range` and serves the full `200` body (a cheap multi-range-amplification
/// guard — RFC 7233 permits ignoring the header).
const MAX_RANGES: usize = 64;

/// Parse a `Range: bytes=…` header against `total` into the satisfiable
/// `(offset, len)` ranges, in request order. `None` when the header is
/// malformed or **every** range is unsatisfiable (caller responds `416`); a
/// returned `Vec` has at least one range. Unsatisfiable ranges in an otherwise
/// satisfiable set are dropped (RFC 7233 §4.1).
fn parse_ranges(spec: &str, total: u64) -> Option<Vec<(u64, u64)>> {
    let spec = spec.strip_prefix("bytes=")?;
    let mut out = Vec::new();
    let mut saw_range = false;
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        saw_range = true;
        if let Some(range) = parse_one_range(part, total) {
            out.push(range);
        }
    }
    if !saw_range || out.is_empty() {
        return None;
    }
    Some(out)
}

/// Parse one `start-end` / `start-` / `-suffix` spec against `total`.
fn parse_one_range(part: &str, total: u64) -> Option<(u64, u64)> {
    let (start, end) = part.split_once('-')?;
    if start.is_empty() {
        let suffix: u64 = end.parse().ok()?;
        if suffix == 0 || total == 0 {
            return None;
        }
        let len = suffix.min(total);
        return Some((total - len, len));
    }
    let start: u64 = start.parse().ok()?;
    if start >= total {
        return None;
    }
    let end = if end.is_empty() {
        total - 1
    } else {
        end.parse::<u64>().ok()?.min(total - 1)
    };
    if end < start {
        return None;
    }
    Some((start, end - start + 1))
}

/// A `206 multipart/byteranges` response over `ranges` (each a satisfiable
/// `(offset, len)` of the identity blob), streamed part-by-part — the bytes are
/// never buffered. `Content-Length` is computed up front (every part header is
/// deterministic), so the response is not chunked.
async fn multipart_byteranges(
    deploy: &DeployStore,
    config: &DeployConfig,
    request_path: &str,
    served_path: &str,
    entry: &FileEntry,
    etag: &str,
    ranges: &[(u64, u64)],
) -> Response {
    let total = entry.size;
    // A boundary unlikely to occur in the body (the blob is content-addressed).
    let boundary = format!("boatramp{}", &entry.hash[..entry.hash.len().min(24)]);
    // The per-part `Content-Type` is the resource's own media type.
    let part_ct = mime_override(config, served_path).or_else(|| entry.content_type.clone());
    let part_ct_line = match &part_ct {
        Some(ct) => format!("Content-Type: {ct}\r\n"),
        None => String::new(),
    };

    // Open each range reader up front (bounded by MAX_RANGES) and assemble the
    // interleaved [header, body, header, body, …, closing] stream.
    let mut segments: Vec<boatramp_core::ByteStream> = Vec::with_capacity(ranges.len() * 2 + 1);
    let mut content_length: u64 = 0;
    for &(offset, len) in ranges {
        let header = format!(
            "\r\n--{boundary}\r\n{part_ct_line}Content-Range: bytes {}-{}/{}\r\n\r\n",
            offset,
            offset + len - 1,
            total
        );
        content_length += header.len() as u64 + len;
        let object = match deploy.open_blob_range(&entry.hash, offset, Some(len)).await {
            Ok(object) => object,
            Err(err) => return deploy_error_response(err),
        };
        segments.push(futures::stream::once(async move { Ok(bytes::Bytes::from(header)) }).boxed());
        segments.push(object.body);
    }
    let closing = format!("\r\n--{boundary}--\r\n");
    content_length += closing.len() as u64;
    segments.push(futures::stream::once(async move { Ok(bytes::Bytes::from(closing)) }).boxed());

    // Start from the resource headers but replace Content-Type with the
    // multipart type (each part carries the resource's own type instead).
    let mut headers = response_headers(config, request_path, served_path, entry, etag);
    set_header(
        &mut headers,
        header::CONTENT_TYPE,
        &format!("multipart/byteranges; boundary={boundary}"),
    );
    set_header(
        &mut headers,
        header::CONTENT_LENGTH,
        &content_length.to_string(),
    );
    let body = futures::stream::iter(segments).flatten();
    (
        StatusCode::PARTIAL_CONTENT,
        headers,
        Body::from_stream(body),
    )
        .into_response()
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
    for (name, value) in parts.headers.iter() {
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
            for (name, value) in resp.headers().iter() {
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
    let backends =
        compute_backends.unwrap_or_else(|| state.backends(upstream, &gateway::SystemResolver, now));
    if backends.is_empty() {
        return (
            StatusCode::BAD_GATEWAY,
            "gateway upstream has no backends\n",
        )
            .into_response();
    }
    let candidates = state.candidates(&backends, upstream, now);

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
    for (name, value) in parts.headers.iter() {
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
            for (name, value) in resp.headers().iter() {
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
    for (name, value) in parts.headers.iter() {
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
            for (name, value) in resp.headers().iter() {
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
    for (name, value) in req_headers.iter() {
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
        for (name, value) in upstream_resp.headers().iter() {
            headers.insert(name.clone(), value.clone());
        }
        return (StatusCode::SWITCHING_PROTOCOLS, headers, Body::empty()).into_response();
    }

    // Upstream declined the upgrade — pass its response through.
    let status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers().iter() {
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
    // (wasi:http needs scheme + authority); the public `/sites/<site>/…` prefix
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
/// path}{?query}` so the handler sees its own path (not the `/sites/<site>/…`
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
            }
        }))
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

// ---- operator / metrics endpoints ----------------------

#[cfg(feature = "handlers")]
impl HandlerRuntimeInner {
    /// Live SSE connection count attributable to `site` — its live scope plus
    /// any preview/alias sub-scopes (`{site}/…`).
    fn stream_connections_for_site(&self, site: &str) -> usize {
        let counts = self.stream_ip_counts.lock().unwrap();
        let sub_prefix = format!("{site}/");
        counts
            .iter()
            .filter(|((scope, _), _)| scope == site || scope.starts_with(&sub_prefix))
            .map(|(_, n)| *n as usize)
            .sum()
    }
}

/// One consumer's queue health for the operator view.
#[cfg(feature = "handlers")]
#[derive(Serialize)]
struct ConsumerStat {
    /// The deployment scope the consumer runs under (site, or `{site}/{alias}`).
    scope: String,
    /// The consumer's declared (scope-relative) topic.
    topic: String,
    /// Messages still queued (claimable or leased) — the consumer lag.
    backlog: usize,
    /// Messages parked in the dead-letter store (exhausted retries).
    dead_letters: usize,
}

/// The `/_boatramp/handlers` operator response: per-`(trigger, route)`
/// invocation stats, per-consumer queue health, and the live stream count.
#[cfg(feature = "handlers")]
#[derive(Serialize, Default)]
struct OperatorStats {
    handlers: Vec<metrics::HandlerStat>,
    consumers: Vec<ConsumerStat>,
    stream_connections: usize,
}

/// Authenticated per-site operator stats (`site:<site>` scope via the API auth
/// middleware). Reports handler invocation counters, consumer backlog +
/// dead-letter counts across the site's active deployments, and live SSE
/// connections.
#[cfg(feature = "handlers")]
async fn operator_handler_stats(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
) -> Response {
    let Some(inner) = handlers.inner.as_ref() else {
        // Handlers compiled in but no runtime configured: empty stats.
        return Json(OperatorStats::default()).into_response();
    };
    let handler_stats = inner.metrics.snapshot_site(&site);
    let mut consumers = Vec::new();
    if let Some(messaging) = &inner.messaging {
        match collect_consumer_stats(&deploy, messaging.as_ref(), &site).await {
            Ok(stats) => consumers = stats,
            Err(err) => return deploy_error_response(err),
        }
    }
    Json(OperatorStats {
        handlers: handler_stats,
        consumers,
        stream_connections: inner.stream_connections_for_site(&site),
    })
    .into_response()
}

/// Which dead-letter operation `POST …/_boatramp/dlq` should run.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum DlqAction {
    /// Drop the dead-lettered messages (records + payloads).
    Purge,
    /// Requeue them onto the live topic with a fresh attempt count.
    Redrive,
}

/// `POST …/_boatramp/dlq` request: which consumer topic, and what to do.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
struct DlqRequest {
    /// The consumer's topic (scope-relative, as declared in the deploy config).
    topic: String,
    /// Background-alias scope (`{site}/{alias}`); omitted = the live site.
    #[serde(default)]
    alias: Option<String>,
    /// `purge` or `redrive`.
    action: DlqAction,
}

#[cfg(feature = "handlers")]
#[derive(Serialize)]
struct DlqResponse {
    /// Number of dead-lettered messages affected.
    affected: usize,
}

/// Operator dead-letter management (`POST …/_boatramp/dlq`, site·write): purge or
/// redrive a consumer topic's dead-letter queue. The topic is
/// namespaced to the site (or a background alias) exactly as the dispatcher does,
/// so an operator can only touch their own site's queues.
#[cfg(feature = "handlers")]
async fn operator_dlq(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
    Json(req): Json<DlqRequest>,
) -> Response {
    let Some(inner) = handlers.inner.as_ref() else {
        return not_found();
    };
    let Some(messaging) = inner.messaging.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "messaging backend not configured\n",
        )
            .into_response();
    };
    // Same namespacing as `collect_consumer_stats`: `{site}/{topic}`, or
    // `{site}/{alias}/{topic}` for a background-alias consumer.
    let scope = match &req.alias {
        Some(alias) => format!("{site}/{alias}"),
        None => site.clone(),
    };
    let namespaced = format!("{scope}/{}", req.topic);
    let result = match req.action {
        DlqAction::Purge => messaging.purge_dead_letters(&namespaced).await,
        DlqAction::Redrive => messaging.redrive_dead_letters(&namespaced).await,
    };
    match result {
        Ok(affected) => Json(DlqResponse { affected }).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("dead-letter operation failed: {err}\n"),
        )
            .into_response(),
    }
}

/// Gather consumer backlog + dead-letter counts for every consumer across a
/// site's active deployments (current + background aliases), mirroring the
/// scheduler's activation policy (previews are never background-active).
#[cfg(feature = "handlers")]
async fn collect_consumer_stats(
    deploy: &DeployStore,
    messaging: &dyn boatramp_core::messaging::Messaging,
    site: &str,
) -> Result<Vec<ConsumerStat>, DeployError> {
    let mut out = Vec::new();
    let Some(site_config) = deploy.get_site_config(site).await? else {
        return Ok(out);
    };
    let Some(site_handlers) = site_config.handlers.as_ref().filter(|h| h.enabled) else {
        return Ok(out);
    };
    let mut active: Vec<(String, String)> = Vec::new();
    if let Some(id) = deploy.current_id(site).await? {
        active.push((id, site.to_string()));
    }
    for alias in &site_handlers.background_aliases {
        if let Some(id) = deploy.get_alias(site, alias).await? {
            active.push((id, format!("{site}/{alias}")));
        }
    }
    for (id, scope) in active {
        let Some(manifest) = deploy.get_manifest(&id).await? else {
            continue;
        };
        for consumer in &manifest.config.consumers {
            let namespaced = format!("{scope}/{}", consumer.topic);
            out.push(ConsumerStat {
                scope: scope.clone(),
                topic: consumer.topic.clone(),
                backlog: messaging.backlog(&namespaced).await.unwrap_or(0),
                dead_letters: messaging.dead_letter_count(&namespaced).await.unwrap_or(0),
            });
        }
    }
    Ok(out)
}

/// Query params for the logs endpoint:
/// `?limit=<n>&after=<seq>&stream=stdout|stderr`.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
struct LogsQuery {
    limit: Option<usize>,
    after: Option<u64>,
    stream: Option<String>,
}

/// The logs endpoint response: recent captured lines + the rate-cap drop count.
#[cfg(feature = "handlers")]
#[derive(Serialize)]
struct LogsResponse {
    entries: Vec<logs::LogEntry>,
    dropped: u64,
}

/// Authenticated per-site captured guest logs (`site:<site>` scope). Returns the
/// most recent lines (newest last), optionally filtered to one stream, plus the
/// count dropped by the per-site rate cap.
#[cfg(feature = "handlers")]
async fn operator_logs(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
    Query(query): Query<LogsQuery>,
) -> Response {
    let Some(inner) = handlers.inner.as_ref() else {
        return Json(LogsResponse {
            entries: Vec::new(),
            dropped: 0,
        })
        .into_response();
    };
    let stream = match query.stream.as_deref() {
        Some("stdout") => Some(boatramp_handlers::LogStream::Stdout),
        Some("stderr") => Some(boatramp_handlers::LogStream::Stderr),
        _ => None,
    };
    let limit = query.limit.unwrap_or(200).min(1000);
    let (entries, dropped) = inner
        .logs
        .tail(&site, limit, query.after.unwrap_or(0), stream);
    Json(LogsResponse { entries, dropped }).into_response()
}

/// Live log tail over SSE (`GET …/_boatramp/logs/stream`): subscribe to the
/// capture feed, filter to this site, and emit each line as an SSE `log` event
/// (the `id` is the line seq, so a reconnect can resume). The console uses this
/// instead of polling. Same `site·read` gating as the poll endpoint.
#[cfg(feature = "handlers")]
async fn operator_logs_stream(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    let Some(inner) = handlers.inner.as_ref() else {
        return (StatusCode::NOT_FOUND, "handlers disabled\n").into_response();
    };
    let rx = inner.logs.subscribe();
    let stream = futures::stream::unfold(rx, move |mut rx| {
        let site = site.clone();
        async move {
            loop {
                match rx.recv().await {
                    Ok((scope, entry)) if scope == site => {
                        let data = serde_json::to_string(&entry).unwrap_or_default();
                        let event = Event::default()
                            .id(entry.seq.to_string())
                            .event("log")
                            .data(data);
                        return Some((Ok::<_, std::convert::Infallible>(event), rx));
                    }
                    // Another site's line — keep waiting.
                    Ok(_) => continue,
                    // Fell behind: skip the gap and resume.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                }
            }
        }
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// Admin-scoped Prometheus text exporter (`*` scope via the API auth
/// middleware). Always renders the process-wide serving + lifecycle counters
/// (request status classes / cache results / bytes, deploys, activations, cert
/// renewals); with the handlers feature it also renders the
/// per-`(site, trigger, route)` invocation counters plus, sampled at scrape
/// time, per-consumer queue-depth + dead-letter gauges across every site
/// (queue depth / consumer lag / DLQ).
#[cfg_attr(not(feature = "handlers"), allow(unused_variables))]
async fn prometheus_metrics(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
) -> Response {
    // Without the handlers feature nothing is appended, so `body` is not mutated.
    #[cfg_attr(not(feature = "handlers"), allow(unused_mut))]
    let mut body = srvmetrics::server_metrics().render_prometheus();
    #[cfg(feature = "handlers")]
    if let Some(inner) = handlers.inner.as_ref() {
        body.push_str(&inner.metrics.render_prometheus());
        if let Some(messaging) = &inner.messaging {
            let mut rows = Vec::new();
            // Best-effort: a deploy-store error just omits the gauges rather
            // than failing the whole scrape.
            if let Ok(sites) = deploy.list_sites().await {
                for site in sites {
                    if let Ok(stats) =
                        collect_consumer_stats(&deploy, messaging.as_ref(), &site).await
                    {
                        for s in stats {
                            rows.push(metrics::ConsumerGauge {
                                site: site.clone(),
                                scope: s.scope,
                                topic: s.topic,
                                backlog: s.backlog,
                                dead_letters: s.dead_letters,
                            });
                        }
                    }
                }
            }
            body.push_str(&metrics::render_consumer_gauges(&rows));
        }
    }
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod host_tests {
    use super::parse_deploy_host;

    #[test]
    fn parses_preview_host_form() {
        assert_eq!(
            parse_deploy_host("abc123.deploy.example.com"),
            Some(("abc123", "example.com"))
        );
        // Deeper site host is preserved verbatim.
        assert_eq!(
            parse_deploy_host("deadbeef.deploy.staging.example.com"),
            Some(("deadbeef", "staging.example.com"))
        );
    }

    #[test]
    fn rejects_non_preview_hosts() {
        // No `deploy` label.
        assert_eq!(parse_deploy_host("www.example.com"), None);
        // Non-hex id label (a real subdomain).
        assert_eq!(parse_deploy_host("blog.deploy.example.com"), None);
        // Bare host / missing parts.
        assert_eq!(parse_deploy_host("example.com"), None);
        assert_eq!(parse_deploy_host("abc.deploy."), None);
        // The path-form label (`_deploy`, with the underscore) is NOT the host
        // form and must not match.
        assert_eq!(parse_deploy_host("abc._deploy.example.com"), None);
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

    /// The `/api/cluster/join-token` handler mints a token the mesh core actually
    /// accepts (bound to the requested node + pubkey), and refuses cleanly when
    /// it can't issue: a verify-only node (no root key) → 501, a non-hex pubkey →
    /// 400. Admin-gating is the deny-safe `Right::required`
    /// default for `/api/cluster/*`.
    #[tokio::test]
    async fn join_token_endpoint_mints_a_verifiable_token() {
        let keys: Arc<dyn Signer> = Arc::new(LocalSigner::generate(TokenAlg::Es256));
        let public = keys.public_key();

        // Happy path: the returned token verifies to the requested claim.
        let resp = create_join_token(
            Extension(Issuer(Some(keys.clone()))),
            Json(CreateJoinTokenRequest {
                node_id: 9,
                pubkey: "aa01bb02".into(),
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
        let claim = cose::verify_join(token, &public, now_unix()).unwrap();
        assert_eq!(claim.node_id, 9);
        assert_eq!(claim.pubkey_hex, "aa01bb02");

        // A verify-only node (no issuing key) cannot mint → 501.
        let no_issuer = create_join_token(
            Extension(Issuer(None)),
            Json(CreateJoinTokenRequest {
                node_id: 1,
                pubkey: "aa".into(),
                ttl_secs: None,
            }),
        )
        .await;
        assert_eq!(no_issuer.status(), StatusCode::NOT_IMPLEMENTED);

        // A non-hex pubkey is rejected before minting → 400.
        let bad = create_join_token(
            Extension(Issuer(Some(keys))),
            Json(CreateJoinTokenRequest {
                node_id: 1,
                pubkey: "not-hex".into(),
                ttl_secs: None,
            }),
        )
        .await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    }

    /// Records the admit calls it receives; the join handler must reach it only
    /// for a token whose bound `(node, pubkey)` matches the presented identity.
    struct StubControl {
        calls: std::sync::Mutex<Vec<(u64, String, String)>>,
    }

    #[async_trait::async_trait]
    impl MeshControl for StubControl {
        async fn admit(&self, node: u64, pubkey_hex: &str, jti: &str) -> Result<bool, String> {
            self.calls
                .lock()
                .unwrap()
                .push((node, pubkey_hex.to_string(), jti.to_string()));
            Ok(true)
        }
        async fn rotate_key(&self) -> Result<String, String> {
            Ok("cafe".to_string())
        }
        async fn revoke(&self, _node: u64) -> Result<(), String> {
            Ok(())
        }
    }

    /// `POST /api/cluster/join` admits only a token whose bound `(node, pubkey)`
    /// matches the presented identity (a stolen token can't admit a different
    /// key → 403, never reaching the admitter), and returns `501` on a
    /// non-cluster node.
    #[tokio::test]
    async fn cluster_join_admits_a_matching_token_and_rejects_theft() {
        let keys: Arc<dyn Signer> = Arc::new(LocalSigner::generate(TokenAlg::Es256));
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let auth = Auth::with_key(keys.public_key(), kv);
        let token = cose::mint_join(7, "aa01", 600, now_unix(), &*keys)
            .await
            .unwrap();

        // Matching node + pubkey → admitted, and the admitter sees the claim.
        let admitter = Arc::new(StubControl {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let resp = cluster_join(
            Extension(auth.clone()),
            Extension(MeshControlHandle(Some(admitter.clone()))),
            Json(JoinRequest {
                node_id: 7,
                pubkey: "aa01".into(),
                token: token.clone(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let (node, pubkey) = {
            let calls = admitter.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            (calls[0].0, calls[0].1.clone())
        };
        assert_eq!((node, pubkey.as_str()), (7, "aa01"));

        // Theft: the same token, a different presented pubkey → 403, and the
        // admitter is never called.
        let thief = Arc::new(StubControl {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let theft = cluster_join(
            Extension(auth.clone()),
            Extension(MeshControlHandle(Some(thief.clone()))),
            Json(JoinRequest {
                node_id: 7,
                pubkey: "bb02".into(),
                token: token.clone(),
            }),
        )
        .await;
        assert_eq!(theft.status(), StatusCode::FORBIDDEN);
        assert!(
            thief.calls.lock().unwrap().is_empty(),
            "a mismatched key must never reach the admitter"
        );

        // A non-cluster node (no admitter) → 501.
        let none = cluster_join(
            Extension(auth),
            Extension(MeshControlHandle(None)),
            Json(JoinRequest {
                node_id: 7,
                pubkey: "aa01".into(),
                token,
            }),
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
            calls: std::sync::Mutex::new(Vec::new()),
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
        use std::collections::BTreeMap;

        // A uniquely-named host var holds the real secret value.
        std::env::set_var("BOATRAMP_TEST_RESOLVE_SECRET", "topsecret");

        let deploy_env = BTreeMap::from([
            ("GREETING".to_string(), "hi".to_string()),
            ("OVERRIDE_ME".to_string(), "static".to_string()),
        ]);
        let site_handlers = HandlersSiteConfig {
            enabled: true,
            secrets: BTreeMap::from([
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
        use std::collections::BTreeMap;

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
        let mut files = BTreeMap::new();
        files.insert(
            "consumer.wasm".to_string(),
            FileEntry {
                hash: hash.clone(),
                size: EVENT_CONSUMER.len() as u64,
                content_type: None,
                variants: BTreeMap::new(),
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
        use std::collections::BTreeMap;
        use std::sync::atomic::Ordering;

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());

        let hash = boatramp_core::deploy::sha256_hex(KV_COUNTER);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(KV_COUNTER)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();
        let mut files = BTreeMap::new();
        files.insert(
            "counter.wasm".to_string(),
            FileEntry {
                hash: hash.clone(),
                size: KV_COUNTER.len() as u64,
                content_type: None,
                variants: BTreeMap::new(),
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
                    env: BTreeMap::new(),
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
        use std::collections::BTreeMap;

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());

        let hash = boatramp_core::deploy::sha256_hex(KV_COUNTER);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(KV_COUNTER)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();
        let mut files = BTreeMap::new();
        files.insert(
            "counter.wasm".to_string(),
            FileEntry {
                hash: hash.clone(),
                size: KV_COUNTER.len() as u64,
                content_type: None,
                variants: BTreeMap::new(),
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
                    env: BTreeMap::new(),
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
