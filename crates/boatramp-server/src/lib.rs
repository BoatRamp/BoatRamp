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

mod admin_api;
pub mod sql_shim;
#[cfg(feature = "oidc")]
pub(crate) use admin_api::auth_exchange;
pub(crate) use admin_api::{
    activate_deployment, cert_status, compute_dns, compute_dns_resolve, compute_exec, compute_ipam,
    compute_netdiag, compute_reconcile, compute_restart, compute_set_health, compute_status,
    create_deployment, current_deployment, delete_compute, delete_compute_volume,
    delete_project_tenancy, delete_site, get_compute, get_daemon_config, get_deployment,
    get_project_tenancy, get_site_config, invalidate_cache, list_aliases, list_compute,
    list_compute_volumes, list_deployments, list_sites, prune_delete, prune_report, put_blob,
    put_compute, put_daemon_config, put_project_tenancy, put_site_config, remove_alias,
    rollback_daemon_config, scrub_blobs, set_alias, sql_exec, sql_ping, sql_query,
};
#[cfg(feature = "handlers")]
pub(crate) use admin_api::{
    delete_graphql_safelist, delete_graphql_subgraph, get_graphql_supergraph,
    list_graphql_safelist, post_graphql_compose, put_graphql_function_subgraph,
    put_graphql_sql_subgraph, put_graphql_subgraph, register_graphql_safelist,
};
/// The server-side controller backing the guest `admin` capability (project self-config).
#[cfg(feature = "admin")]
mod admin_controller;
mod auth;
#[cfg(feature = "console")]
pub mod console;
mod content;
mod control_api;
/// The node-side email delivery spool (best-effort + durable) backing the `email`
/// guest capability.
#[cfg(feature = "email")]
mod email_spool;
/// The server-side session controller + re-entry driver (PLAN-session-primitive Stage 3).
#[cfg(feature = "session")]
mod session_driver;
/// The KV-backed session store backing the duplex/resumable `session` capability
/// (PLAN-session-primitive Stage 3).
#[cfg(feature = "session")]
mod session_store;
#[cfg(feature = "admin")]
pub use admin_controller::ServerAdminController;
#[cfg(feature = "compression")]
pub(crate) use content::maybe_compress;
pub(crate) use content::multipart_byteranges;
pub(crate) use content::{
    negotiate_encoding, parse_ranges, response_headers, set_content_encoding, MAX_RANGES,
};
pub(crate) use control_api::{
    add_root_anchor, auth_whoami, bootstrap_token, cluster_join, cluster_members, cluster_promote,
    cluster_revoke, cluster_rotate_key, create_join_token, create_token, delete_email_profile,
    delete_secret, get_authz_policy, list_email_profiles, list_root_anchors, list_secrets,
    list_tokens, put_authz_policy, remove_root_anchor, revoke_token, set_email_profile, set_secret,
    show_email_profile,
};
#[cfg(all(test, feature = "handlers"))]
use control_api::{BootstrapRequest, CreateJoinTokenRequest, JoinRequest};
#[cfg(feature = "email")]
pub use email_spool::NodeEmailSpool;
mod domain_verify;
pub use domain_verify::{spawn_domain_verify_reconcile, verification_pending_page};
pub mod envelope;
#[cfg(feature = "handlers")]
mod graphql_apq;
#[cfg(feature = "handlers")]
mod graphql_cache;
#[cfg(feature = "handlers")]
mod graphql_data;
#[cfg(feature = "handlers")]
mod graphql_federation;
#[cfg(feature = "handlers")]
mod graphql_gateway;
#[cfg(feature = "handlers")]
mod graphql_graphiql;
#[cfg(feature = "handlers")]
mod graphql_guard;
#[cfg(feature = "handlers")]
mod graphql_plan;
#[cfg(feature = "handlers")]
mod graphql_registry;
#[cfg(feature = "handlers")]
mod graphql_subscription;
#[cfg(feature = "handlers")]
mod handler_cache;
#[cfg(feature = "handlers")]
mod handler_dispatch;
#[cfg(feature = "handlers")]
pub(crate) use handler_dispatch::{
    build_bindings, dispatch_consumer_batch, dispatch_handler, precheck_component, read_blob_bytes,
    read_blob_fully, resolve_secret_env,
};
#[cfg(all(feature = "handlers", test))]
use handler_dispatch::{resolve_env, set_forwarded_headers};
mod function_api;
pub(crate) use function_api::{
    alias_function, deploy_function, get_deploy_status, list_functions, remove_function,
    rollback_function,
};
/// The capability **features** this host build implements — the registry a guest's manifest
/// `requires` is admission-checked against, re-exported so `boatramp capabilities` reports the
/// exact same set the deploy gate enforces (PLAN v2). `*_detailed` pairs each with its lifecycle;
/// `component_requires`/`unmet_requires` back the shift-left `capabilities check`.
#[cfg(feature = "handlers")]
pub use function_api::{
    component_requires, host_capability_features, host_capability_features_detailed, unmet_requires,
};
#[cfg(all(test, feature = "handlers"))]
use function_api::{AliasBody, DeployFunctionQuery, FunctionUpsert, RollbackBody};
/// Capability-surface types (`boatramp capabilities` / `/api/capabilities`). Ungated — a build
/// without `handlers` still names the vocabulary, it just implements nothing.
pub use function_api::{CapabilityFeature, Lifecycle};
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
    operator_dlq, operator_dlq_list, operator_function_logs, operator_function_logs_stream,
    operator_handler_stats, operator_logs, operator_logs_stream, operator_queue_group,
    operator_queue_groups, operator_queue_pause, operator_queue_peek, operator_queue_replay,
};
mod proxy;
pub use proxy::spawn_compute_reconcile;
pub(crate) use proxy::{
    await_warm, compute_endpoint_regions, compute_endpoints, dispatch_gateway, has_parked_replica,
    proxy, COMPUTE_WAKE_TIMEOUT,
};
mod splice;
// The unified serving front door: TLS + plaintext accept loops that drive every
// connection through boatramp-http's own h1+h2 stack (replaced hyper/axum_server).
mod http_serve;
pub use http_serve::{
    alpn_h1_h2, serve_plaintext, serve_plaintext_listener, serve_router_conn, serve_tls,
    serve_tls_listener, ReloadableTls, ServeInput,
};
// Only the `handlers`-gated websocket-upgrade path in the serve pipeline uses it.
#[cfg(feature = "handlers")]
pub(crate) use proxy::is_upgrade_request;
#[cfg(all(test, feature = "handlers"))]
use proxy::{gateway_addr_allowed, CLOUD_METADATA_IPV4};
mod project_api;
pub(crate) use project_api::{create_project, delete_project, get_project, list_projects};
mod project_scope;
pub(crate) use project_scope::{project_scope, OriginalPath, ProjectContext};
mod ratelimit;
mod routes;
pub use routes::{router, router_with, router_with_fast};
#[cfg(feature = "mcp")]
mod mcp_http;
#[cfg(feature = "handlers")]
mod scheduler;
mod serve_pipeline;
#[cfg(feature = "handlers")]
mod tenant_resolve;
pub use serve_pipeline::{http_redirect_router, FastServe};
#[cfg(test)]
mod hotpath_test;
#[cfg(all(test, feature = "handlers"))]
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
    acquire_site_permit, effective_limits, handler_error_response, handler_unavailable,
    sql_starting_response, CronNow,
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
/// SSE-out + POST-in serving of the duplex/resumable `session` capability
/// (PLAN-session-primitive Stage 4): a `GET` opens the resumable outbound stream, a `POST` delivers
/// an inbound frame that re-enters the guest `session-handler`.
#[cfg(feature = "session")]
mod session_serve;
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
    /// Claim gate for the durable async drain, sized to the engine's async-lane
    /// concurrency. The drain acquires an owned permit before claiming +
    /// spawning an invocation and holds it for the whole run, so a backlog can
    /// never spawn more background jobs than the async lane can run (bounded
    /// fan-out, no attempt-burning overload storm).
    async_drain_gate: Arc<tokio::sync::Semaphore>,
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
    /// Per-project memoized composed supergraph + query plans (the federation hot path),
    /// keyed on the registry composition version. Shared by the edge and in-process
    /// `graphql::run` paths; a registry mutation bumps the version and invalidates it.
    #[cfg(feature = "handlers")]
    graphql_cache: graphql_cache::GraphqlCache,
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
    /// Whether a site handler's / function's `secrets` map may resolve a **bare**
    /// or `env:`-scheme reference against the serve process's own (operator)
    /// environment, from the security posture's `allow_env_secret_refs`. Set once
    /// at startup via [`HandlerRuntime::set_allow_env_secret_refs`]; **unset reads
    /// as `false`** (fail-closed — a runtime that never wired the posture refuses
    /// host-env refs rather than leaking them). When `false`, `resolve_secret_env`
    /// refuses such a ref instead of injecting the host value, closing the
    /// cross-tenant host-env exfiltration path under the multi-tenant posture.
    allow_env_secret_refs: std::sync::OnceLock<bool>,
    /// Whether a site/function that imports `sql`/`orm` must declare an explicit in-site tenancy
    /// decision (Dimension 0), from the posture's `require_tenancy_declaration`. Set at startup
    /// via [`HandlerRuntime::set_tenancy_posture`]; **unset reads as `true`** (fail-closed — a
    /// runtime that never wired the posture refuses an undeclared db importer rather than running
    /// it plain).
    require_tenancy_declaration: std::sync::OnceLock<bool>,
    /// Whether an in-site tenancy `all` grant may actually reach across tenants, from the
    /// posture's `allow_cross_tenant_db`. Set via [`HandlerRuntime::set_tenancy_posture`];
    /// **unset reads as `false`** (fail-closed — an `all` grant is capped to `own` until the
    /// posture is wired to permit crossing tenants).
    allow_cross_tenant_db: std::sync::OnceLock<bool>,
    /// The project-scoped internal secret store (sealed with the `[secrets]`
    /// envelope). Backs the `boatramp:<name>` secret-ref scheme — the
    /// multi-tenant-safe alternative to a host-env ref. Set once at startup via
    /// [`HandlerRuntime::set_secret_store`]; **unset means no `boatramp:` ref can
    /// resolve** (fail-closed — `resolve_secret_env` errors rather than injecting).
    secret_store: std::sync::OnceLock<Arc<boatramp_core::secret_store::SecretStore>>,
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
    /// The function-to-function invoke resolver (FI): backs the `invoke`
    /// capability. Set once at startup with the deploy store (a self-referential
    /// `Weak` back to this runtime), so a granted function can call a sibling
    /// in-process. Unset ⇒ the `invoke` capability is not offered. Held as the
    /// concrete type so a binding can derive a **project-scoped** invoker
    /// ([`FunctionInvoker::scoped`]) resolving the caller's siblings within its
    /// own tenant project, not `default`.
    invoker: std::sync::OnceLock<Arc<function_runtime::FunctionInvoker>>,
    /// The supergraph runner backing the `graphql` capability: runs a guest's GraphQL
    /// operation against the project's composed supergraph in-process (plan + execute over
    /// the invoke path). Set once at startup alongside [`invoker`](Self::invoker); unset ⇒ the
    /// `graphql` capability is not offered. Project-scoped per grant, like the invoker.
    federation_runner: std::sync::OnceLock<Arc<graphql_gateway::FederationRunner>>,
    /// The per-project SMTP email-profile store backing the `email` capability's
    /// host-side profile resolution (sealed with the `[secrets]` envelope, like
    /// [`secret_store`](Self::secret_store)). Set via
    /// [`HandlerRuntime::set_email_profile_store`]; unset ⇒ no profile resolves.
    #[cfg(feature = "email")]
    email_profile_store: std::sync::OnceLock<Arc<boatramp_core::email_config::EmailProfileStore>>,
    /// The shared node email delivery spool backing the `email` capability. Set via
    /// [`HandlerRuntime::set_email_spool`] at startup **only when the
    /// `allow_guest_email` posture permits guest email**; unset ⇒ email is not
    /// offered (a guest granted `email` gets `access-denied`).
    #[cfg(feature = "email")]
    email_spool: std::sync::OnceLock<Arc<dyn boatramp_handlers::EmailSpool>>,
    /// The server-side controller backing the guest `admin` capability. Set at startup via
    /// [`HandlerRuntime::set_admin`]; unset ⇒ admin is not offered (a granted guest gets
    /// `access-denied`). `.scoped(project)` per grant.
    #[cfg(feature = "admin")]
    admin_controller: std::sync::OnceLock<Arc<admin_controller::ServerAdminController>>,
    /// The config surfaces the operator posture enables for guest admin (the posture-on subset
    /// of {domains,email,site,secrets}); a guest's grant is intersected with this. Empty/unset ⇒
    /// no surface is offered.
    #[cfg(feature = "admin")]
    admin_surfaces:
        std::sync::OnceLock<std::collections::BTreeSet<boatramp_handlers::AdminSurface>>,
    /// The KV-backed store behind the duplex/resumable `session` capability (PLAN-session-primitive).
    /// Lazily built over this runtime's own `kv` with the default [`SessionLimits`] on first session
    /// use ([`session_serve`]); a session needs no external wiring, so unlike `email`/`admin` there
    /// is no operator gate — the `session` cargo feature + the guest's declared capability + the
    /// site's import allowlist govern it. (Operator-tunable limits land with the Stage-7 posture
    /// knobs.)
    #[cfg(feature = "session")]
    session_store: std::sync::OnceLock<session_store::SessionStore>,
    /// The fleet [`Signer`] used to **mint + verify** anonymous session cookies (R3,
    /// PLAN-tenancy-principal — the `ScopeAxis::Session` fact). Set once at startup from the node's
    /// `issuer` (its public half is the verify anchor). **Unset ⇒ no session cookies are issued or
    /// verified** (the R3 disjunct then has only the tenant arm — fail-safe: no anon session axis).
    session_signer: std::sync::OnceLock<Arc<dyn Signer>>,
    /// The operator ceiling (seconds) on a guest-minted capability's TTL (R5,
    /// PLAN-delegable-capabilities). Set at startup **only when** the `allow_guest_mint_capability`
    /// posture is on and a positive ceiling is configured; **unset ⇒ guest capability minting is not
    /// offered** (the `capability` binding is never attached). The fleet signer is reused from
    /// [`session_signer`](Self::session_signer).
    #[cfg(feature = "capability")]
    capability_max_ttl_secs: std::sync::OnceLock<u64>,
    /// Per-project overrides (Gap 4a) of the resolved tenancy/capability knobs, project name →
    /// resolved knobs (base posture ⊕ the operator's `[security.projects.<p>]` override). Consulted
    /// at each in-project enforcement point via [`HandlerRuntimeInner::project_tenancy_knobs`];
    /// **unset / a project not listed ⇒ the node base** (today's behavior). Set once at startup.
    #[cfg(feature = "handlers")]
    tenancy_posture_overrides: std::sync::OnceLock<
        Arc<std::collections::BTreeMap<String, boatramp_core::security::ResolvedProjectTenancy>>,
    >,
}

#[cfg(feature = "handlers")]
impl HandlerRuntimeInner {
    /// Resolve the tenancy/capability knobs for `project` (Gap 4a): the operator's per-project
    /// override if one was declared, else the node base. The lookup key is the **host-routed**
    /// project (never guest input), so it can't be spoofed. Consulted at every in-project
    /// enforcement point (tenancy-declaration + cross-tenant `all` in `build_bindings` /
    /// `function_runtime`; the guest capability-mint gate).
    pub(crate) fn project_tenancy_knobs(
        &self,
        project: &str,
    ) -> boatramp_core::security::ResolvedProjectTenancy {
        if let Some(map) = self.tenancy_posture_overrides.get() {
            if let Some(knobs) = map.get(project) {
                return *knobs;
            }
        }
        boatramp_core::security::ResolvedProjectTenancy {
            require_tenancy_declaration: self
                .require_tenancy_declaration
                .get()
                .copied()
                .unwrap_or(true),
            allow_cross_tenant_db: self.allow_cross_tenant_db.get().copied().unwrap_or(false),
            #[cfg(feature = "capability")]
            capability_max_ttl_secs: self.capability_max_ttl_secs.get().copied(),
            #[cfg(not(feature = "capability"))]
            capability_max_ttl_secs: None,
        }
    }
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
        // Size the async drain gate to the engine's async-lane concurrency
        // (read before `engine` is moved into the runtime).
        let async_drain_slots = engine.async_max_concurrency().max(1);
        Self {
            inner: Some(Arc::new(HandlerRuntimeInner {
                engine,
                async_drain_gate: Arc::new(tokio::sync::Semaphore::new(async_drain_slots)),
                kv,
                storage,
                sql,
                messaging,
                site_semaphores: std::sync::Mutex::new(std::collections::HashMap::new()),
                stream_semaphores: std::sync::Mutex::new(std::collections::HashMap::new()),
                stream_ip_counts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
                metrics: metrics::Metrics::default(),
                logs: Arc::new(logs::LogStore::default()),
                #[cfg(feature = "handlers")]
                graphql_cache: graphql_cache::GraphqlCache::default(),
                cron_leader_gate: std::sync::OnceLock::new(),
                max_blob_bytes: std::sync::OnceLock::new(),
                max_component_bytes: std::sync::OnceLock::new(),
                allow_env_secret_refs: std::sync::OnceLock::new(),
                require_tenancy_declaration: std::sync::OnceLock::new(),
                allow_cross_tenant_db: std::sync::OnceLock::new(),
                secret_store: std::sync::OnceLock::new(),
                function_meter_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
                function_semaphores: std::sync::Mutex::new(std::collections::HashMap::new()),
                watch_provider: std::sync::OnceLock::new(),
                provision_tier: std::sync::OnceLock::new(),
                invoker: std::sync::OnceLock::new(),
                federation_runner: std::sync::OnceLock::new(),
                #[cfg(feature = "email")]
                email_profile_store: std::sync::OnceLock::new(),
                #[cfg(feature = "email")]
                email_spool: std::sync::OnceLock::new(),
                #[cfg(feature = "admin")]
                admin_controller: std::sync::OnceLock::new(),
                #[cfg(feature = "admin")]
                admin_surfaces: std::sync::OnceLock::new(),
                #[cfg(feature = "session")]
                session_store: std::sync::OnceLock::new(),
                session_signer: std::sync::OnceLock::new(),
                #[cfg(feature = "capability")]
                capability_max_ttl_secs: std::sync::OnceLock::new(),
                #[cfg(feature = "handlers")]
                tenancy_posture_overrides: std::sync::OnceLock::new(),
            })),
        }
    }

    /// The per-site SQL database provider, if one is configured. Lets the control plane
    /// introspect a site's database (e.g. to generate a SQL federation subgraph's SDL).
    #[cfg(feature = "handlers")]
    pub(crate) fn sql_provider(&self) -> Option<Arc<dyn boatramp_core::sql::SqlBackends>> {
        self.inner.as_ref().and_then(|inner| inner.sql.clone())
    }

    /// Precompile an uploaded **component** blob to warm the compiled-module cache
    /// (deploy-resilience #1a), so a later deploy-time introspection / first request finds a cache
    /// hit instead of paying a cold cranelift compile on the critical path. Runs **no guest code**
    /// (compile + pre-instantiate only) and is best-effort + concurrency-gated (#2). Always
    /// callable; a no-op when this node has no wasm engine. A component that fails to compile is
    /// simply not warmed — the deploy that later activates it is the authority that rejects it.
    pub async fn precompile_component(&self, hash: &str, wasm: &[u8]) -> Result<(), String> {
        #[cfg(feature = "handlers")]
        if let Some(inner) = self.inner.as_ref() {
            return inner
                .engine
                .precompile_gated(hash, wasm)
                .await
                .map_err(|e| e.to_string());
        }
        let _ = (hash, wasm);
        Ok(())
    }

    /// Acquire a compile permit (deploy-resilience #2/#1a), held by the caller across a blob read +
    /// [`precompile_component_holding_permit`](Self::precompile_component_holding_permit) so an
    /// upload burst holds at most `compile_concurrency` full blobs resident at once. `None` when
    /// this node has no engine — the caller then skips warming entirely (nothing to compile).
    #[cfg(feature = "handlers")]
    pub(crate) async fn acquire_compile_permit(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        match self.inner.as_ref() {
            Some(inner) => Some(inner.engine.acquire_compile_permit().await),
            None => None,
        }
    }

    /// Precompile a component the caller has already gated by holding a permit from
    /// [`acquire_compile_permit`](Self::acquire_compile_permit) — so it does NOT re-acquire the
    /// compile gate (which would deadlock at concurrency 1). Runs no guest code; best-effort.
    #[cfg(feature = "handlers")]
    pub(crate) async fn precompile_component_holding_permit(
        &self,
        hash: &str,
        wasm: &[u8],
    ) -> Result<(), String> {
        match self.inner.as_ref() {
            Some(inner) => inner
                .engine
                .precompile_off_runtime(hash, wasm)
                .await
                .map_err(|e| e.to_string()),
            None => Ok(()),
        }
    }

    /// The function invoker, if wired (set at serve startup). Lets the control plane run a
    /// deployed function in-process — e.g. to introspect a function subgraph's SDL via its
    /// federation `_service { sdl }` field when registering it.
    #[cfg(feature = "handlers")]
    pub(crate) fn invoker(&self) -> Option<Arc<function_runtime::FunctionInvoker>> {
        self.inner
            .as_ref()
            .and_then(|inner| inner.invoker.get().cloned())
    }

    /// Introspect a **specific component's** federation SDL by running `{ _service { sdl } }`
    /// against it — targeting a pending (not-yet-active) version so a subgraph redeploy can be
    /// composed-checked before it goes live. `Unavailable` if this node has no wasm engine.
    #[cfg(feature = "handlers")]
    pub(crate) async fn introspect_subgraph_sdl(
        &self,
        deploy: &DeployStore,
        project: boatramp_core::project::ProjectRef<'_>,
        function: &boatramp_core::function::Function,
        component: &str,
    ) -> Result<String, function_runtime::SubgraphSdlError> {
        match self.inner.as_ref() {
            Some(inner) => {
                function_runtime::introspect_service_sdl(
                    inner, deploy, project, function, component,
                )
                .await
            }
            None => Err(function_runtime::SubgraphSdlError::Unavailable),
        }
    }

    /// Wire the function-to-function invoke resolver (FI). Set once at startup,
    /// after the deploy store exists: it holds a `Weak` back to this runtime plus
    /// the deploy store, so a function granted `invoke` can resolve + run a
    /// sibling in-process. A no-op runtime (no `inner`) leaves it unset, and the
    /// `invoke` capability is then simply never granted.
    #[cfg(feature = "handlers")]
    pub fn set_invoker(&self, deploy: DeployStore) {
        if let Some(inner) = self.inner.as_ref() {
            let invoker = Arc::new(function_runtime::FunctionInvoker::new(
                deploy,
                Arc::downgrade(inner),
            ));
            let _ = inner.invoker.set(invoker);
            // The supergraph runner shares the same self-referential `Weak`; it reaches the
            // invoker (set above) to dispatch a guest run's sub-fetches in-process.
            let runner = Arc::new(graphql_gateway::FederationRunner::new(Arc::downgrade(
                inner,
            )));
            let _ = inner.federation_runner.set(runner);
        }
    }

    /// The per-site SQL provider, if the `sql` capability is offered. Backs the
    /// compute sql-shim (PLAN-compute-bindings) so an opaque workload reaches the
    /// same tenant-scoped database a handler does.
    #[cfg(feature = "handlers")]
    pub fn sql_backends(&self) -> Option<Arc<dyn boatramp_core::sql::SqlBackends>> {
        self.inner.as_ref().and_then(|inner| inner.sql.clone())
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

    /// Permit (or forbid) resolving a **bare** / `env:`-scheme secret ref against
    /// the serve process's own environment, from the security posture's
    /// `allow_env_secret_refs`. Set once at startup; **unset reads as `false`**
    /// (fail-closed), so a runtime that never wired the posture refuses host-env
    /// refs rather than leaking them. Under the multi-tenant posture (`false`) an
    /// untrusted tenant's `secrets` map can no longer name an arbitrary host env
    /// var to exfiltrate it into their guest.
    #[cfg(feature = "handlers")]
    pub fn set_allow_env_secret_refs(&self, allow: bool) {
        if let Some(inner) = self.inner.as_ref() {
            let _ = inner.allow_env_secret_refs.set(allow);
        }
    }

    /// Wire the in-site tenancy posture (Stage 0): `require_declaration` (a sql/orm importer must
    /// declare an explicit tenancy decision) and `allow_cross_tenant` (an `all` grant may reach
    /// across tenants). Set once at startup; **unset reads fail-closed** (`require = true`,
    /// `allow_cross_tenant = false`).
    #[cfg(feature = "handlers")]
    pub fn set_tenancy_posture(&self, require_declaration: bool, allow_cross_tenant: bool) {
        if let Some(inner) = self.inner.as_ref() {
            let _ = inner.require_tenancy_declaration.set(require_declaration);
            let _ = inner.allow_cross_tenant_db.set(allow_cross_tenant);
        }
    }

    /// Wire per-project tenancy/capability posture overrides (Gap 4a): project name → the resolved
    /// knobs (fleet base ⊕ the operator's `[security.projects.<p>]` override). A project not in the
    /// map uses the node base ([`set_tenancy_posture`](Self::set_tenancy_posture) +
    /// [`set_capability_minting`](Self::set_capability_minting)). Set once at startup; a per-project
    /// override tunes only that project's own in-project isolation + guest capability-mint ceiling
    /// (cross-project isolation is structural, never a knob). No-op on a plain runtime / empty map.
    #[cfg(feature = "handlers")]
    pub fn set_project_tenancy_overrides(
        &self,
        overrides: std::collections::BTreeMap<
            String,
            boatramp_core::security::ResolvedProjectTenancy,
        >,
    ) {
        if overrides.is_empty() {
            return;
        }
        if let Some(inner) = self.inner.as_ref() {
            let _ = inner.tenancy_posture_overrides.set(Arc::new(overrides));
        }
    }

    /// Wire the fleet [`Signer`] used to mint + verify anonymous session cookies (R3). Pass the
    /// node's issuing signer (typically the same `issuer` that mints control-plane tokens); its
    /// public half becomes the session-cookie verify anchor. Set once at startup; **unset ⇒ the
    /// host issues/verifies no session cookies** (the `Session` scope axis stays dormant — a
    /// project's `TenantOrSession` reads then carry only the tenant arm). No-op on a plain runtime.
    #[cfg(feature = "handlers")]
    pub fn set_session_signer(&self, signer: Arc<dyn Signer>) {
        if let Some(inner) = self.inner.as_ref() {
            let _ = inner.session_signer.set(signer);
        }
    }

    /// Enable guest capability minting (`boatramp:handlers/capability`, PLAN-delegable-capabilities)
    /// with an operator TTL ceiling (seconds). Call **only when** the `allow_guest_mint_capability`
    /// posture is on and `max_ttl_secs > 0`; unset (or `0`) ⇒ the `capability` binding is never
    /// attached and a guest `mint` returns `access-denied`. Minting reuses the fleet
    /// [`set_session_signer`](Self::set_session_signer) key (a capability is verified against the same
    /// anchor), so wire that too. No-op on a plain runtime.
    #[cfg(feature = "capability")]
    pub fn set_capability_minting(&self, max_ttl_secs: u64) {
        if max_ttl_secs == 0 {
            return;
        }
        if let Some(inner) = self.inner.as_ref() {
            let _ = inner.capability_max_ttl_secs.set(max_ttl_secs);
        }
    }

    /// Wire the project-scoped internal secret store (sealed with the `[secrets]`
    /// envelope) that backs the `boatramp:<name>` secret-ref scheme. Set once at
    /// startup; if never set, a `boatramp:` ref cannot resolve and
    /// `resolve_secret_env` errors fail-closed rather than injecting a value.
    #[cfg(feature = "handlers")]
    pub fn set_secret_store(&self, store: Arc<boatramp_core::secret_store::SecretStore>) {
        if let Some(inner) = self.inner.as_ref() {
            let _ = inner.secret_store.set(store);
        }
    }

    /// Wire the per-project SMTP email-profile store that backs the `email`
    /// capability's host-side profile resolution (same sealed store the admin API
    /// exposes redacted). Set once at startup; unset ⇒ no profile resolves.
    #[cfg(feature = "email")]
    pub fn set_email_profile_store(
        &self,
        store: Arc<boatramp_core::email_config::EmailProfileStore>,
    ) {
        if let Some(inner) = self.inner.as_ref() {
            let _ = inner.email_profile_store.set(store);
        }
    }

    /// Wire the shared node email delivery spool backing the `email` capability.
    /// Called at startup **only when the `allow_guest_email` posture permits guest
    /// email**, so leaving it unset (posture off, or no spool) makes email
    /// unavailable and a granted guest's `send` returns `access-denied`.
    #[cfg(feature = "email")]
    pub fn set_email_spool(&self, spool: Arc<dyn boatramp_handlers::EmailSpool>) {
        if let Some(inner) = self.inner.as_ref() {
            let _ = inner.email_spool.set(spool);
        }
    }

    /// Wire the guest `admin` capability: the server controller + the operator-enabled surface
    /// set (the posture-on subset). Called at startup only when at least one
    /// `allow_guest_admin_*` posture bit is on; unset ⇒ admin is not offered and a granted
    /// guest's calls return `access-denied`. A guest's grant is intersected with `surfaces`.
    #[cfg(feature = "admin")]
    pub fn set_admin(
        &self,
        controller: Arc<admin_controller::ServerAdminController>,
        surfaces: std::collections::BTreeSet<boatramp_handlers::AdminSurface>,
    ) {
        if let Some(inner) = self.inner.as_ref() {
            let _ = inner.admin_controller.set(controller);
            let _ = inner.admin_surfaces.set(surfaces);
        }
    }

    /// The resolved `allow_env_secret_refs` posture bool (fail-closed `false` if
    /// unset, or if there is no runtime). Lets the function deploy-admission path
    /// refuse a forbidden `secrets` map at deploy time — the same gate the
    /// resolution-time backstop enforces.
    #[cfg(feature = "handlers")]
    pub(crate) fn allow_env_secret_refs(&self) -> bool {
        self.inner
            .as_ref()
            .and_then(|inner| inner.allow_env_secret_refs.get().copied())
            .unwrap_or(false)
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

        // Fail loud at deploy on a `secrets` map the posture forbids: under the
        // multi-tenant posture a bare / `env:` ref reads the operator's environment
        // (cross-tenant host-env exfiltration), so refuse the activation with the
        // same message the resolution-time backstop would raise — the tenant sees
        // the failure now, not at first request. Uses the runtime's resolved
        // `allow_env_secret_refs` (fail-closed if never wired).
        let allow_env_secret_refs = inner.allow_env_secret_refs.get().copied().unwrap_or(false);
        crate::handler_dispatch::admit_secret_refs(&site_handlers.secrets, allow_env_secret_refs)
            .map_err(|err| format!("handler secrets: {err}"))?;

        // Sync-timeout footgun: a handler/site timeout above the sync ceiling is
        // silently clamped for connection-bearing (sync HTTP) calls, so a legit
        // long call dies as a mysterious runtime 504. Warn loudly at deploy. The
        // same value is valid for the async lane (`?mode=async` / triggers), clamped
        // to the larger async ceiling — so this is a warning, not a refusal.
        let sync_ceiling = inner.engine.sync_timeout_ms();
        let async_ceiling = inner.engine.async_timeout_ms();
        if let Some(ms) = site_handlers.max_timeout_ms {
            if u64::from(ms) > sync_ceiling {
                tracing::warn!(
                    "site max_timeout_ms={ms} exceeds sync_max_timeout_ms={sync_ceiling}: \
                     synchronous HTTP handlers are capped at {sync_ceiling}ms; the extra time \
                     applies only to async calls (?mode=async / triggers), capped at \
                     async_max_timeout_ms={async_ceiling}"
                );
            }
        }

        // Same import/size/compile gate for every handler and consumer component.
        for handler in &manifest.config.handlers {
            if let Some(ms) = handler.limits.as_ref().and_then(|l| l.timeout_ms) {
                if u64::from(ms) > sync_ceiling {
                    let route = &handler.route;
                    tracing::warn!(
                        "route {route:?} declares limits.timeout_ms={ms}, above \
                         sync_max_timeout_ms={sync_ceiling}: synchronous HTTP calls to this route \
                         are capped at {sync_ceiling}ms; the {ms}ms only applies to async calls \
                         (?mode=async / a queue trigger / a #[consumer]), capped at \
                         async_max_timeout_ms={async_ceiling}. If you need {ms}ms synchronously, \
                         that isn't possible — move the work to the async lane"
                    );
                }
            }
            // A guest that self-declares a streaming handler (`#[handler(stream)]`) but whose
            // config doesn't mark the route `streaming` would run on the tight sync request lane
            // and be cut at the sync timeout — a silent footgun for a long-lived SSE/agent stream.
            // Warn (don't block) so the operator sets `streaming = true` for the dedicated lane.
            if !handler.streaming {
                if let Some(entry) = manifest.files.get(&handler.component) {
                    if let Ok(bytes) = read_blob_bytes(deploy, &entry.hash).await {
                        if crate::function_api::component_declares_streaming_route(
                            &bytes,
                            &handler.route,
                        ) {
                            let route = &handler.route;
                            tracing::warn!(
                                "route {route:?} is a streaming handler (#[handler(stream)]) but \
                                 its config lacks streaming = true: it will run on the sync request \
                                 lane and be cut at sync_max_timeout_ms={sync_ceiling}ms. Set \
                                 streaming = true so it serves on the dedicated streaming lane (its \
                                 own concurrency budget + a much larger wall-clock)."
                            );
                        }
                    }
                }
            }
            // Fail loud at deploy if the guest's function-manifest `requires` a capability feature
            // this host build does not implement — availability lives in metadata, not the linkable
            // WIT (PLAN v2). A clear message beats an opaque runtime failure later.
            if let Some(entry) = manifest.files.get(&handler.component) {
                if let Ok(bytes) = read_blob_bytes(deploy, &entry.hash).await {
                    let unmet = crate::function_api::unmet_requires(&bytes);
                    if !unmet.is_empty() {
                        return Err(format!(
                            "route {:?} [{}] requires capabilities this host does not implement: \
                             {}. Upgrade boatramp or enable those features — see `boatramp \
                             capabilities`.",
                            handler.route,
                            handler.methods.join(","),
                            unmet.join(", ")
                        ));
                    }
                }
            }
            precheck_component(
                deploy,
                manifest,
                site_handlers,
                inner,
                max_component,
                &handler.imports,
                &handler.component,
                // Name route + methods (matching the client-side validator), so with
                // one component on several routes the operator sees which is at fault.
                &format!("route {:?} [{}]", handler.route, handler.methods.join(",")),
                false,
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
                true,
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
    /// Operator SQL capability for managed databases (migrations / queries via the
    /// sealed credential, resolved server-side). Backs `POST /api/sql/{db}/{exec,query}`;
    /// `None` ⇒ those routes return `501`. Wired by the node when a managed DB exists.
    pub operator_sql: Option<Arc<dyn boatramp_core::sql::OperatorSql>>,
    /// Tenant-deprovision capability: drops a deleted tenant's managed databases +
    /// roles + sealed credentials on project/site delete. `None` ⇒ delete does no
    /// managed-DB teardown. Wired by the node when a compute-backed managed database
    /// exists; the delete handlers call it best-effort after the store delete.
    pub tenant_deprovisioner: Option<Arc<dyn boatramp_core::sql::TenantDeprovisioner>>,
    /// Operator compute-exec capability (run a command inside a running workload).
    /// Backs `POST /api/compute/{name}/exec`; `None` ⇒ `501`. Gated at the handler by
    /// the `allow_compute_exec` posture. Wired by the node with the compute backends.
    pub compute_exec: Option<Arc<dyn boatramp_core::compute::ComputeExec>>,
    /// Operator volume-reclamation capability (list + remove persistent volumes).
    /// Backs `GET /api/compute/volumes` + `DELETE /api/compute/volumes/{name}`;
    /// `None` ⇒ `501`. Admin-scoped (the deny-safe `/api/compute/*` default). Wired
    /// by the node with the compute backends.
    pub compute_volumes: Option<Arc<dyn boatramp_core::compute::ComputeVolumes>>,
    /// Operator reconcile-plane control capability (restart a replica). Backs
    /// `POST /api/compute/maintenance/restart`; `None` ⇒ `501`. Admin-scoped
    /// (`is_compute_maintenance_path`). Wired by the node with the compute backends.
    pub compute_control: Option<Arc<dyn boatramp_core::compute::ComputeControl>>,
    /// The project-scoped internal secret store (sealed with the `[secrets]`
    /// envelope). Backs the admin secrets API (`/api/projects/{proj}/secrets{,/{name}}`,
    /// rewritten onto `/api/secrets{,/{name}}`) — set/list/delete of names + metadata,
    /// **never** values. `None` ⇒ no `[secrets]` envelope was configured, and every
    /// secrets endpoint returns a clear `501` ("no key envelope configured"), never a
    /// panic. Not `handlers`-gated: `SecretStore` lives in boatramp-core, so the admin
    /// API works on a lean node too. Wired by the node alongside the envelope.
    pub secret_store: Option<Arc<boatramp_core::secret_store::SecretStore>>,
    /// The per-project SMTP email-profile store backing the admin API
    /// (`/api/email/profiles{,/{name}}`) — set/list/show/delete of a profile's
    /// **redacted** config (the password is never returned). `None` ⇒ no
    /// `[secrets]` envelope was configured, and the email endpoints fail closed with
    /// a clear `501`. Not `handlers`-gated: `EmailProfileStore` lives in
    /// boatramp-core, so the admin API works on a lean node. Wired by the node
    /// alongside the envelope, like [`secret_store`](Self::secret_store).
    pub email_profile_store: Option<Arc<boatramp_core::email_config::EmailProfileStore>>,
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

/// Disable Nagle's algorithm on an accepted connection.
///
/// Without `TCP_NODELAY`, small HTTP responses on **keep-alive** connections stall
/// on Nagle's algorithm interacting with the peer's delayed ACK — a fixed ~40 ms
/// per request. That is boatramp's hot path in production: on Fly and Cloudflare
/// the platform terminates TLS and forwards **plaintext** HTTP to the app over
/// persistent connections, so the stall would hit every small response. This runs
/// on each accepted stream via [`axum::serve::ListenerExt::tap_io`]; it is
/// best-effort — a failure only forfeits the latency win, never the connection.
pub(crate) fn disable_nagle(stream: &mut tokio::net::TcpStream) {
    if let Err(err) = stream.set_nodelay(true) {
        tracing::debug!(%err, "failed to set TCP_NODELAY on an accepted connection");
    }
}

/// [`serve`] with explicit [`ServerOptions`] (e.g. operational request limits).
pub async fn serve_with(
    addr: SocketAddr,
    deploy: DeployStore,
    auth: Auth,
    handlers: HandlerRuntime,
    options: ServerOptions,
) -> Result<(), ServeError> {
    let tcp = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, auth = !auth.is_disabled(), "boatramp server listening");
    // Context for the Linux `splice()` reverse-proxy fast-path: the store, the
    // resolved posture (SSRF gate), and a live read of the catch-all `default_site`
    // (so host resolution matches the serving pipeline). The daemon runtime is the
    // one `serve` supplies (shared with the router); absent it, the fast-path just
    // falls back for default-site hosts.
    let splice_ctx = splice::SpliceCtx {
        deploy: deploy.clone(),
        posture: options.posture,
        daemon: options.daemon_runtime.clone(),
    };
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
    let (router, fast) = router_with_fast(deploy, auth, handlers, options);

    // The graceful drain begins when the OS signal fires; `signalled` flips at
    // that instant so the drain deadline is measured from the signal, not from
    // server start.
    let (signalled_tx, signalled_rx) = tokio::sync::watch::channel(false);
    // The splice serve loop intercepts eligible plaintext reverse-proxy connections
    // (Linux) and serves everything else through `boatramp-http` — an eligible plain
    // site GET/HEAD via the `fast` hot-path bypass, the rest through the full `router`.
    let server = splice::serve(tcp, splice_ctx, (router, fast), async move {
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

/// A per-request correlation id assigned by the access-log layer and readable downstream via
/// the request extensions — the handler dispatch tags captured guest logs with it, so a guest
/// line correlates with its `boatramp::access` line. Public so an embedder (or a test) can seed
/// its own id into the request extensions.
#[derive(Clone)]
pub struct RequestId(pub String);

/// The routed domain's opaque **tenant context tag** ([`boatramp_core::project::DomainOwner`]'s
/// `context`), stashed in the request extensions at host routing time so the handler-dispatch path
/// can resolve a [`boatramp_core::tenancy::TenantSource::Domain`] scope without re-reading the
/// routing index. Present only on the host-routed serving path; absent elsewhere (a domain source
/// then fails closed).
#[cfg(feature = "handlers")]
#[derive(Clone)]
pub struct DomainContext(pub String);

/// The correlation id for a request: an upstream proxy's `X-Request-Id` when present (sanitized,
/// length-capped), else a generated time-ordered, per-process-unique id.
fn request_id_for(headers: &HeaderMap) -> String {
    if let Some(id) = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return id.chars().filter(|c| !c.is_control()).take(128).collect();
    }
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}", boatramp_core::time::now_unix_ms(), n)
}

/// One access-log line, emitted when the response body finishes streaming, so
/// `bytes` (response size) and `elapsed_ms` (time-to-last-byte) are accurate for
/// fixed-size *and* streamed/proxied responses.
struct AccessLog {
    request_id: String,
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
            request_id = %self.request_id,
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

/// Assign the request correlation id (from the client's header or freshly minted) and
/// make it readable downstream — handler dispatch tags captured guest logs with it.
/// Runs for every request regardless of the access-log level; returns the id. Shared by
/// the [`access_log`] middleware and any direct serve path so correlation is never
/// skipped on a bypass. (Serve hot-path bypass, stage 1.)
pub(crate) fn assign_request_id(request: &mut axum::extract::Request) -> String {
    let request_id = request_id_for(request.headers());
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));
    request_id
}

/// Request metadata captured *before* the response is produced, for the access-log line
/// plus the Prometheus request counters — both emitted from [`AccessLog`]'s `Drop` once
/// the body has fully streamed (or the client disconnected). Extracted so the access-log
/// middleware and a direct serve path share one implementation.
pub(crate) struct AccessLogCtx {
    request_id: String,
    method: Method,
    path: String,
    host: String,
    client: String,
    start: std::time::Instant,
}

impl AccessLogCtx {
    /// Capture the request for logging, or `None` when the `boatramp::access` line is
    /// filtered out — in which case logging *and* the per-request metric aggregation are
    /// both skipped (~4 string allocations plus a body-stream wrapper avoided, matching
    /// how nginx/Envoy run with `access_log off`). The id is assigned separately and
    /// unconditionally via [`assign_request_id`].
    pub(crate) fn capture(request: &axum::extract::Request, request_id: String) -> Option<Self> {
        if !tracing::enabled!(target: "boatramp::access", tracing::Level::INFO) {
            return None;
        }
        Some(Self {
            request_id,
            method: request.method().clone(),
            path: request.uri().path().to_string(),
            host: request
                .headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .or_else(|| request.uri().host()) // HTTP/2: `:authority` lives in the URI
                .unwrap_or("-")
                .to_string(),
            client: request
                .extensions()
                .get::<axum::extract::ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip().to_string())
                .unwrap_or_else(|| "-".to_string()),
            start: std::time::Instant::now(),
        })
    }

    /// Wrap `response` so its bytes are tallied as they stream; the access line + request
    /// metrics emit from the counter's `Drop` when the body finishes (or the client
    /// disconnects).
    pub(crate) fn finish(self, response: Response) -> Response {
        let encoding = response
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("identity")
            .to_string();
        let log = AccessLog {
            request_id: self.request_id,
            method: self.method,
            path: self.path,
            host: self.host,
            client: self.client,
            status: response.status().as_u16(),
            encoding,
            start: self.start,
            bytes: std::sync::atomic::AtomicU64::new(0),
        };
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
}

/// Structured access-log middleware: assigns the correlation id, then (when access
/// logging is on) records method / path / host / client IP / status / response bytes /
/// duration once the body has fully streamed. Assignment and the capture/finish logic
/// are shared with any direct serve path via [`assign_request_id`] + [`AccessLogCtx`].
async fn access_log(mut request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let request_id = assign_request_id(&mut request);
    match AccessLogCtx::capture(&request, request_id) {
        None => next.run(request).await,
        Some(ctx) => ctx.finish(next.run(request).await),
    }
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
        // A submitted config failed content validation (e.g. an empty target public predicate).
        DeployError::Invalid(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    tracing::warn!(error = %err, "request failed");
    (status, format!("{err}\n")).into_response()
}

/// Reject a resource name (site/function/compute/workflow) that is unsafe at the
/// store-key boundary, returning `Some(422)` to short-circuit the handler. The
/// name arrives here already percent-decoded by axum's `Path` extractor, so a
/// smuggled `%2F` is caught as a literal `/`. `None` = the name is fine.
fn reject_invalid_name(kind: &'static str, value: &str) -> Option<Response> {
    boatramp_core::project::validate_resource_name(kind, value)
        .err()
        .map(|err| (StatusCode::UNPROCESSABLE_ENTITY, format!("{err}\n")).into_response())
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
    use boatramp_core::project::ProjectRef;

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
                axum::extract::Extension(crate::ProjectContext::default()),
                axum::extract::Extension(Arc::new(crate::HandlerRuntime::disabled())),
                axum::extract::Query(DeployFunctionQuery::default()),
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
                axum::extract::Extension(crate::ProjectContext::default()),
                axum::extract::Extension(Arc::new(crate::HandlerRuntime::disabled())),
                axum::extract::Query(DeployFunctionQuery::default()),
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
                axum::extract::Extension(crate::ProjectContext::default()),
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
            axum::extract::Extension(crate::ProjectContext::default()),
            Path("greeter".to_string()),
            Json(RollbackBody { to: "c".repeat(64) }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Alias prod → v2.
        let (st, body) = body_json(
            alias_function(
                State(deploy.clone()),
                axum::extract::Extension(crate::ProjectContext::default()),
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
        let (st, _) = body_json(
            remove_function(
                State(deploy.clone()),
                axum::extract::Extension(crate::ProjectContext::default()),
                Path("greeter".to_string()),
            )
            .await,
        )
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        assert!(deploy
            .get_function(ProjectRef::DEFAULT, "greeter")
            .await
            .unwrap()
            .is_none());

        // Deploying a component whose blob was never uploaded is a 400.
        let empty = DeployStore::new(
            Arc::new(FakeStorage { present: false }),
            Arc::new(MemoryKv::new()),
        );
        let resp = deploy_function(
            State(empty),
            axum::extract::Extension(crate::ProjectContext::default()),
            axum::extract::Extension(Arc::new(crate::HandlerRuntime::disabled())),
            axum::extract::Query(DeployFunctionQuery::default()),
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

    #[tokio::test]
    async fn resolve_env_merges_static_and_host_secrets() {
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
        // Single-tenant / dev: host-env secret refs are permitted (the operator
        // authors the site config), so this resolves exactly as before.
        let env = resolve_env(
            "blog",
            boatramp_core::project::ProjectRef::DEFAULT,
            &deploy_env,
            &site_handlers,
            true,
            None,
        )
        .await
        .expect("resolves");

        // Static var present; secret resolved from the host env; a secret
        // overrides a static of the same name; a secret whose host var is unset
        // is skipped (never injected as empty).
        assert!(env.contains(&("GREETING".to_string(), "hi".to_string())));
        assert!(env.contains(&("SECRET_TOKEN".to_string(), "topsecret".to_string())));
        assert!(env.contains(&("OVERRIDE_ME".to_string(), "topsecret".to_string())));
        assert!(!env.iter().any(|(k, _)| k == "MISSING"));

        std::env::remove_var("BOATRAMP_TEST_RESOLVE_SECRET");
    }

    #[tokio::test]
    async fn multi_tenant_posture_refuses_a_host_env_handler_secret() {
        use boatramp_core::config::HandlersSiteConfig;

        // The exfiltration vector: an untrusted tenant names another tenant's / the
        // operator's host env var (bare or `env:`) in its site `secrets` map. Under
        // the multi-tenant posture (`allow_env_secret_refs = false`) the resolver
        // must REFUSE — never read the host env — and name the offending guest var.
        std::env::set_var("BOATRAMP_TEST_OTHER_TENANT_SECRET", "leak-me");
        let deploy_env = std::collections::BTreeMap::new();
        let bare = HandlersSiteConfig {
            enabled: true,
            secrets: std::collections::BTreeMap::from([(
                "STOLEN".to_string(),
                "BOATRAMP_TEST_OTHER_TENANT_SECRET".to_string(),
            )]),
            ..Default::default()
        };
        let err = resolve_env(
            "evil",
            boatramp_core::project::ProjectRef::DEFAULT,
            &deploy_env,
            &bare,
            false,
            None,
        )
        .await
        .expect_err("multi-tenant must refuse a bare host-env ref");
        assert!(
            err.contains("STOLEN"),
            "error names the offending guest var: {err}"
        );
        assert!(
            err.contains("multi-tenant"),
            "error steers the tenant: {err}"
        );
        assert!(
            !err.contains("leak-me"),
            "the host value must never appear (never read): {err}"
        );

        // The explicit `env:` scheme is refused identically.
        let explicit = HandlersSiteConfig {
            enabled: true,
            secrets: std::collections::BTreeMap::from([(
                "STOLEN".to_string(),
                "env:BOATRAMP_TEST_OTHER_TENANT_SECRET".to_string(),
            )]),
            ..Default::default()
        };
        assert!(resolve_env(
            "evil",
            boatramp_core::project::ProjectRef::DEFAULT,
            &deploy_env,
            &explicit,
            false,
            None,
        )
        .await
        .is_err());

        // A reserved-but-unimplemented scheme is also refused (no silent fall-through).
        let reserved = HandlersSiteConfig {
            enabled: true,
            secrets: std::collections::BTreeMap::from([(
                "TOKEN".to_string(),
                "vault:kv/data/app#token".to_string(),
            )]),
            ..Default::default()
        };
        let err = resolve_env(
            "evil",
            boatramp_core::project::ProjectRef::DEFAULT,
            &deploy_env,
            &reserved,
            true,
            None,
        )
        .await
        .expect_err("a reserved scheme is not yet supported, even under single-tenant");
        assert!(err.contains("not yet supported"), "{err}");

        // The rule is provider-neutral: ANY value with a colon is a scheme, so an
        // un-enumerated one (a cloud secret manager) is refused too — never misread
        // as a bare host var literally named "aws:sm/prod/apikey".
        let arbitrary = HandlersSiteConfig {
            enabled: true,
            secrets: std::collections::BTreeMap::from([(
                "KEY".to_string(),
                "aws:sm/prod/apikey".to_string(),
            )]),
            ..Default::default()
        };
        let err = resolve_env(
            "evil",
            boatramp_core::project::ProjectRef::DEFAULT,
            &deploy_env,
            &arbitrary,
            true,
            None,
        )
        .await
        .expect_err("any unknown scheme is reserved, even under single-tenant");
        assert!(
            err.contains("not yet supported") && err.contains("aws"),
            "provider-neutral reservation names the scheme: {err}"
        );

        std::env::remove_var("BOATRAMP_TEST_OTHER_TENANT_SECRET");
    }

    #[tokio::test]
    async fn function_resolve_secret_env_reads_host_and_matches_handler_semantics() {
        // A top-level function resolves its `secrets` map exactly like a site
        // handler: `resolve_secret_env` reads the host env var named by the map's
        // value and injects it under the map's key. This is the SAME helper the
        // handler path uses, so the semantics are identical by construction.
        std::env::set_var("BOATRAMP_TEST_FN_SECRET", "fnsecret");

        let static_env = std::collections::BTreeMap::from([
            ("STAGE".to_string(), "prod".to_string()),
            ("OVERRIDE_ME".to_string(), "static".to_string()),
        ]);
        let secrets = std::collections::BTreeMap::from([
            // guest ENV_VAR <- host env var holding the value
            ("DB_URL".to_string(), "BOATRAMP_TEST_FN_SECRET".to_string()),
            // a secret overrides a static of the same name
            (
                "OVERRIDE_ME".to_string(),
                "BOATRAMP_TEST_FN_SECRET".to_string(),
            ),
            // an unset host referent is skipped, never injected empty
            (
                "MISSING".to_string(),
                "BOATRAMP_TEST_FN_NOT_SET".to_string(),
            ),
        ]);
        // Single-tenant / dev: host-env refs permitted, so this resolves as before.
        let env = resolve_secret_env(
            "fn/api",
            boatramp_core::project::ProjectRef::DEFAULT,
            &static_env,
            &secrets,
            true,
            None,
        )
        .await
        .expect("resolves");

        assert!(env.contains(&("STAGE".to_string(), "prod".to_string())));
        // The secret is injected under its target ENV_VAR, read from the host env.
        assert!(env.contains(&("DB_URL".to_string(), "fnsecret".to_string())));
        // A secret overrides a static of the same name.
        assert!(env.contains(&("OVERRIDE_ME".to_string(), "fnsecret".to_string())));
        // Absent host var → skipped (matches the handler's missing-var behavior).
        assert!(!env.iter().any(|(k, _)| k == "MISSING"));

        std::env::remove_var("BOATRAMP_TEST_FN_SECRET");
    }

    #[tokio::test]
    async fn multi_tenant_posture_refuses_a_host_env_function_secret() {
        // The function analog of the handler exfiltration vector: a function's
        // `secrets` map naming a host env var must be REFUSED under the multi-tenant
        // posture (never read), using the SAME helper the handler path uses — so the
        // fail-closed semantics are identical by construction.
        std::env::set_var("BOATRAMP_TEST_FN_LEAK", "leak-me");
        let static_env = std::collections::BTreeMap::new();
        let secrets = std::collections::BTreeMap::from([(
            "DB_URL".to_string(),
            "BOATRAMP_TEST_FN_LEAK".to_string(),
        )]);

        // Multi-tenant: refused, names the offending guest var, host value never read.
        let err = resolve_secret_env(
            "fn/api",
            boatramp_core::project::ProjectRef::DEFAULT,
            &static_env,
            &secrets,
            false,
            None,
        )
        .await
        .expect_err("multi-tenant must refuse a function host-env ref");
        assert!(
            err.contains("DB_URL"),
            "error names the offending guest var: {err}"
        );
        assert!(
            !err.contains("leak-me"),
            "host value must never appear: {err}"
        );

        // Single-tenant / dev: the same ref resolves + injects (operator owns config).
        let env = resolve_secret_env(
            "fn/api",
            boatramp_core::project::ProjectRef::DEFAULT,
            &static_env,
            &secrets,
            true,
            None,
        )
        .await
        .expect("resolves");
        assert!(env.contains(&("DB_URL".to_string(), "leak-me".to_string())));

        std::env::remove_var("BOATRAMP_TEST_FN_LEAK");
    }

    #[tokio::test]
    async fn boatramp_scheme_resolves_from_the_project_scoped_store() {
        use boatramp_core::project::ProjectRef;
        use boatramp_core::secret_store::SecretStore;
        use std::sync::Arc;

        // A reversible test envelope (XOR) so `set` seals and `get` unseals.
        struct XorEnvelope;
        #[async_trait::async_trait]
        impl boatramp_core::envelope::KeyEnvelope for XorEnvelope {
            async fn wrap(
                &self,
                p: &[u8],
            ) -> Result<Vec<u8>, boatramp_core::envelope::EnvelopeError> {
                Ok(p.iter().map(|b| b ^ 0x5a).collect())
            }
            async fn unwrap(
                &self,
                c: &[u8],
            ) -> Result<Vec<u8>, boatramp_core::envelope::EnvelopeError> {
                Ok(c.iter().map(|b| b ^ 0x5a).collect())
            }
        }

        let store = SecretStore::new(
            Arc::new(boatramp_core::kv::MemoryKv::new()),
            Arc::new(XorEnvelope),
        );
        store
            .set(ProjectRef::new("acme"), "api-key", b"s3cr3t")
            .await
            .unwrap();

        let static_env = std::collections::BTreeMap::new();
        let secrets = std::collections::BTreeMap::from([
            ("API_KEY".to_string(), "boatramp:api-key".to_string()),
            ("MISSING".to_string(), "boatramp:not-set".to_string()),
        ]);

        // Resolves under the MULTI-TENANT posture (allow_env_secret_refs = false):
        // the project-scoped store is the multi-tenant-safe path, not gated on it.
        let env = resolve_secret_env(
            "site",
            ProjectRef::new("acme"),
            &static_env,
            &secrets,
            false,
            Some(&store),
        )
        .await
        .expect("boatramp refs resolve without the host-env gate");
        assert!(env.contains(&("API_KEY".to_string(), "s3cr3t".to_string())));
        // A missing boatramp secret is skipped, never injected empty (like a missing env var).
        assert!(!env.iter().any(|(k, _)| k == "MISSING"));

        // Project isolation: the same ref under a different project does not see acme's secret.
        let other_secrets = std::collections::BTreeMap::from([(
            "API_KEY".to_string(),
            "boatramp:api-key".to_string(),
        )]);
        let other = resolve_secret_env(
            "site",
            ProjectRef::new("globex"),
            &static_env,
            &other_secrets,
            false,
            Some(&store),
        )
        .await
        .expect("resolves (a foreign project's secret is simply absent → skipped)");
        assert!(
            !other.iter().any(|(k, _)| k == "API_KEY"),
            "a tenant must not read another project's secret"
        );

        // Fail-closed: a boatramp: ref with no store configured errors (does not silently skip).
        let err = resolve_secret_env(
            "site",
            ProjectRef::new("acme"),
            &static_env,
            &other_secrets,
            false,
            None,
        )
        .await
        .expect_err("no store configured must fail closed");
        assert!(err.contains("no internal secret store"), "{err}");
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

    /// Build an `ObservedInstance` for the wake-from-zero helper tests, owned by
    /// `project` (so the project-scoped resolution can be exercised).
    fn observed_state_in(
        project: &str,
        workload: &str,
        host: &str,
        healthy: bool,
        phase: boatramp_core::compute::ReplicaPhase,
    ) -> boatramp_core::compute::ObservedInstance {
        use boatramp_core::compute::{Endpoint, InstanceHandle, ReplicaPhase, Scheme, Snapshot};
        boatramp_core::compute::ObservedInstance {
            handle: InstanceHandle {
                project: project.into(),
                workload: workload.into(),
                replica: 0,
                backend_ref: "ref-0".into(),
            },
            node: 1,
            backend: "vmm".into(),
            endpoint: Endpoint {
                scheme: Scheme::Http,
                host: host.into(),
                port: 80,
            },
            region: None,
            healthy,
            started_at: None,
            phase,
            snapshot: matches!(phase, ReplicaPhase::Zero).then(|| Snapshot {
                project: project.into(),
                workload: workload.into(),
                replica: 0,
                data_ref: "snap-0".into(),
            }),
        }
    }

    /// The default-project helper the wake-from-zero tests use.
    fn observed_state(
        workload: &str,
        healthy: bool,
        phase: boatramp_core::compute::ReplicaPhase,
    ) -> boatramp_core::compute::ObservedInstance {
        observed_state_in("default", workload, "10.0.0.2", healthy, phase)
    }

    #[tokio::test]
    async fn has_parked_replica_detects_a_zeroed_replica() {
        use boatramp_core::compute::ReplicaPhase;
        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage, kv);

        // Nothing → false.
        assert!(!has_parked_replica(&deploy, "default", "w").await);
        // A running replica → false (it's serving, not parked).
        deploy
            .set_replica_state(
                ProjectRef::DEFAULT,
                &observed_state("w", true, ReplicaPhase::Running),
            )
            .await
            .unwrap();
        assert!(!has_parked_replica(&deploy, "default", "w").await);
        // A parked (Zero) replica → true (wakeable).
        deploy
            .set_replica_state(
                ProjectRef::DEFAULT,
                &observed_state("w", false, ReplicaPhase::Zero),
            )
            .await
            .unwrap();
        assert!(has_parked_replica(&deploy, "default", "w").await);
    }

    #[tokio::test]
    async fn await_warm_returns_immediately_when_healthy_and_times_out_otherwise() {
        use boatramp_core::compute::ReplicaPhase;
        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage, kv);

        // No healthy replica → times out with an empty pool (short timeout).
        let empty = await_warm(
            &deploy,
            "default",
            "w",
            std::time::Duration::from_millis(150),
        )
        .await;
        assert!(empty.is_empty());

        // A healthy replica → returned promptly.
        deploy
            .set_replica_state(
                ProjectRef::DEFAULT,
                &observed_state("w", true, ReplicaPhase::Running),
            )
            .await
            .unwrap();
        let warm = await_warm(&deploy, "default", "w", std::time::Duration::from_secs(5)).await;
        assert_eq!(warm, vec!["http://10.0.0.2:80".to_string()]);
    }

    /// The project-scoped compute upstream resolution (v0.3.12): a workload named
    /// `web` exists in BOTH the `acme` project and `default`, on different endpoints.
    /// `compute_endpoints`/`has_parked_replica` must resolve against the project they
    /// are asked for — a non-default tenant no longer resolves against `default` (the
    /// project-blind bug that 502'd it / never woke it).
    #[tokio::test]
    async fn compute_endpoints_are_project_scoped() {
        use boatramp_core::compute::ReplicaPhase;
        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage, kv);

        // Same workload name `web`, one per project, distinct endpoints.
        deploy
            .set_replica_state(
                ProjectRef::new("acme"),
                &observed_state_in("acme", "web", "10.0.0.5", true, ReplicaPhase::Running),
            )
            .await
            .unwrap();
        deploy
            .set_replica_state(
                ProjectRef::DEFAULT,
                &observed_state_in("default", "web", "10.0.0.9", true, ReplicaPhase::Running),
            )
            .await
            .unwrap();

        // Asking for `acme` yields acme's endpoint — NOT default's.
        assert_eq!(
            compute_endpoints(&deploy, "acme", "web").await,
            vec!["http://10.0.0.5:80".to_string()],
            "acme's web resolves against acme, not default"
        );
        // Asking for `default` yields default's endpoint.
        assert_eq!(
            compute_endpoints(&deploy, "default", "web").await,
            vec!["http://10.0.0.9:80".to_string()]
        );
        // A project with no such workload resolves empty (→ 502), not another
        // project's replica.
        assert!(compute_endpoints(&deploy, "beta", "web").await.is_empty());
    }

    /// P2 flow control: `max_ack_pending` caps the claim window (across the per-tick `max_batch`),
    /// so a consumer never holds more than N leased-but-unacked at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn max_ack_pending_caps_the_claim_window() {
        use boatramp_handlers::{Bindings, HandlerEngine, Limits};
        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let mq = LogMessaging::new(storage, kv.clone());
        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let hash = boatramp_core::deploy::sha256_hex(EVENT_CONSUMER);
        let bindings = Bindings::new("blog").with_keyvalue("blog", kv.clone());
        let topic = "blog/orders/created";
        for _ in 0..5 {
            mq.publish(topic, b"ok").await.unwrap();
        }
        // max_batch=10 would take all 5 in one tick; max_ack_pending=2 caps the window to 2.
        let acked = dispatch_consumer_batch(
            &engine,
            &mq,
            &metrics::Metrics::default(),
            "blog",
            topic,
            "blog/",
            "",
            boatramp_core::messaging::StartPosition::Latest,
            &hash,
            EVENT_CONSUMER,
            &bindings,
            None,
            Limits::default(),
            Duration::from_secs(30),
            5,
            10,
            Some(2),
        )
        .await;
        assert_eq!(
            acked, 2,
            "MaxAckPending=2 caps the batch to 2 even though max_batch=10 and 5 are queued"
        );
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
                "",
                boatramp_core::messaging::StartPosition::Latest,
                &hash,
                EVENT_CONSUMER,
                &bindings,
                // No signed_context consumer in this test — reuse the built-once binding.
                None,
                Limits::default(),
                Duration::from_secs(30),
                5,
                10,
                None,
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
                "",
                boatramp_core::messaging::StartPosition::Latest,
                &hash,
                EVENT_CONSUMER,
                &bindings,
                // No signed_context consumer in this test — reuse the built-once binding.
                None,
                Limits::default(),
                Duration::ZERO,
                2,
                10,
                None,
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

    /// Config-driven fan-out through the dispatcher: two consumers with different
    /// **groups** on one topic each receive every message (not one-of-N), each
    /// with its own cursor + ack. The one delivered message increments the
    /// consumer's counter once *per group*.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn consumer_groups_fan_out_through_the_dispatcher() {
        use boatramp_handlers::{Bindings, HandlerEngine, Limits};
        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let mq = LogMessaging::new(storage, kv.clone());
        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let hash = boatramp_core::deploy::sha256_hex(EVENT_CONSUMER);
        let bindings = Bindings::new("blog").with_keyvalue("blog", kv.clone());
        let topic = "blog/orders/created";
        let start = boatramp_core::messaging::StartPosition::Latest;

        // Both groups subscribe first (registering them turns on retention), then
        // one event is published — the fabric shape (workers deployed, then events).
        for g in ["billing", "audit"] {
            let n = dispatch_consumer_batch(
                &engine,
                &mq,
                &metrics::Metrics::default(),
                "blog",
                topic,
                "blog/",
                g,
                start,
                &hash,
                EVENT_CONSUMER,
                &bindings,
                // No signed_context consumer in this test — reuse the built-once binding.
                None,
                Limits::default(),
                Duration::from_secs(30),
                5,
                10,
                None,
            )
            .await;
            assert_eq!(n, 0, "no events yet for group {g}");
        }
        mq.publish(topic, b"ok").await.unwrap();

        // Each group independently delivers the one message.
        for g in ["billing", "audit"] {
            let n = dispatch_consumer_batch(
                &engine,
                &mq,
                &metrics::Metrics::default(),
                "blog",
                topic,
                "blog/",
                g,
                start,
                &hash,
                EVENT_CONSUMER,
                &bindings,
                // No signed_context consumer in this test — reuse the built-once binding.
                None,
                Limits::default(),
                Duration::from_secs(30),
                5,
                10,
                None,
            )
            .await;
            assert_eq!(n, 1, "group {g} should receive the message");
        }
        // Delivered once per group ⇒ counted twice (fan-out), not once.
        assert_eq!(
            kv.get("hkv/blog/delivered/orders/created").await.unwrap(),
            Some(b"2".to_vec())
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
                    tenancy: None,
                    token_claims: None,
                    topic: "orders/created".into(),
                    component: "consumer.wasm".into(),
                    imports: vec!["wasi:keyvalue".into()],
                    group: String::new(),
                    start: Default::default(),
                    lease_ms: None,
                    max_attempts: None,
                    max_batch: None,
                    max_ack_pending: None,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let id = deploy.put_manifest(&manifest).await.unwrap();
        deploy
            .activate(ProjectRef::DEFAULT, "blog", &id)
            .await
            .unwrap();
        deploy
            .set_site_config(
                ProjectRef::DEFAULT,
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
        let mut sweep = std::collections::HashMap::new();
        let now = CronNow {
            minute: 0,
            hour: 0,
            dom: 1,
            month: 1,
            dow: 0,
            minute_stamp: 0,
        };
        for _ in 0..3 {
            run_scheduler_tick(&inner, &deploy, &mut cache, &mut crons, &mut sweep, now)
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

    /// The function-to-function invoke resolver (FI): a resolvable target runs on
    /// the real engine and its response is buffered back + metered; an unknown
    /// target is `NotFound`. (The caller-side capability gate — allowlist, depth,
    /// deny-by-default — is unit-tested in `boatramp_handlers::bindings::invoke`.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn function_invoker_runs_target_buffers_and_meters() {
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::function::{Function, FunctionVersion, Lifecycle, Owner};
        use boatramp_handlers::{HandlerEngine, InvokeError, InvokeRequest, Invoker, Limits};
        use futures::StreamExt;

        // The committed `http-200` fixture is the invoke *target* (a wasi:http
        // guest that returns 200); it needs no fixture of its own to be a callee.
        const HTTP_200: &[u8] =
            include_bytes!("../../boatramp-handlers/tests/fixtures/http-200.wasm");

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());

        let hash = boatramp_core::deploy::sha256_hex(HTTP_200);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(HTTP_200)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();
        let function = Function {
            name: "target".into(),
            owner: Owner::Project("default".into()),
            versions: vec![FunctionVersion {
                id: "v1".into(),
                component: hash.clone(),
                created: 0,
                lifecycle: Lifecycle::Independent,
            }],
            active: "v1".into(),
            aliases: Default::default(),
            config: Default::default(),
        };
        deploy
            .put_function(ProjectRef::DEFAULT, &function)
            .await
            .unwrap();

        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv, storage, None, None);
        rt.set_invoker(deploy.clone());
        let invoker = rt.inner.as_ref().unwrap().invoker.get().unwrap().clone();

        let request = || InvokeRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![],
            body: vec![],
        };

        // A resolvable target runs on the engine and returns its 200.
        let response = invoker.invoke("target", request(), 1).await.unwrap();
        assert_eq!(response.status, 200);

        // The call was metered against the target function.
        let metering = deploy
            .get_metering(ProjectRef::DEFAULT, "target")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(metering.invocations, 1);

        // An unknown target is NotFound (never reaches the engine).
        let err = invoker.invoke("ghost", request(), 1).await.unwrap_err();
        assert!(matches!(err, InvokeError::NotFound));
    }

    /// The supergraph runner backing the `graphql` capability, driven end-to-end through a real
    /// runtime: the safelist is the deny-by-default operation floor, and only a safelisted op
    /// reaches planning. (The host-side grant + depth cap are unit-tested in
    /// `boatramp_handlers::bindings::graphql`; stitching + bearer forwarding + depth dispatch in
    /// `graphql_gateway`.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn federation_runner_enforces_the_safelist_before_planning() {
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::project::ProjectRef;
        use boatramp_handlers::{GraphqlRequest, HandlerEngine, Limits, SupergraphRunError};

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());
        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
        rt.set_invoker(deploy.clone());
        let runner = rt
            .inner
            .as_ref()
            .unwrap()
            .federation_runner
            .get()
            .unwrap()
            .scoped(ProjectRef::new("default"), Vec::new());

        let req = |query: &str| GraphqlRequest {
            query: Some(query.to_string()),
            persisted_hash: None,
            variables: "{}".to_string(),
            operation_name: None,
            authorization: None,
        };

        // A query that was never registered is refused (deny-by-default) before any planning.
        assert!(matches!(
            runner.run(req("{ me { id } }"), 1).await,
            Err(SupergraphRunError::NotSafelisted)
        ));

        // Register it in the safelist (any writer of the APQ store) — now it passes the floor and
        // reaches planning; against an empty supergraph the plan fails (proving the gate opened).
        let query = "{ me { id } }";
        let hash = crate::graphql_apq::sha256_hex(query);
        kv.put(&format!("hapq/default/{hash}"), query.as_bytes().to_vec())
            .await
            .unwrap();
        assert!(matches!(
            runner.run(req(query), 1).await,
            Err(SupergraphRunError::PlanFailed(_))
        ));

        // A run-persisted with an unregistered hash is refused the same way.
        let persisted = GraphqlRequest {
            query: None,
            persisted_hash: Some("deadbeef".to_string()),
            variables: "{}".to_string(),
            operation_name: None,
            authorization: None,
        };
        assert!(matches!(
            runner.run(persisted, 1).await,
            Err(SupergraphRunError::NotSafelisted)
        ));
    }

    /// **Live gate (v0.4.6, PLAN-async-lane-propagation):** `graphql::run` propagates the caller's
    /// resolved **principal** to a federated sub-fetch, so a subgraph resolver reached over the
    /// supergraph with NO request bearer still resolves its own-tenancy from the inherited principal
    /// (symmetric to `emit::invoke`). Drives the REAL `FederationRunner` → invoke → engine over a REAL
    /// libsql-backed subgraph function (`graphql-scope-probe`, whose `items` field is host-scoped via
    /// the `{scope}` marker): running as tenant B returns ONLY B's rows; running with no principal
    /// fails closed (the pre-v0.4.6 behavior — never a leak). `#[ignore]`d (static-musl libsql
    /// segfault); the CI job runs it on the host toolchain + greps the marker.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "run on the host toolchain (real libsql static-musl segfault); wired in the CI graphql-propagation gate"]
    async fn graphql_run_propagates_caller_principal_to_a_scoped_subfetch() {
        use boatramp_core::deploy::{sha256_hex, DeployStore};
        use boatramp_core::function::{
            Function, FunctionConfig, FunctionVersion, Lifecycle, Owner,
        };
        use boatramp_core::project::ProjectRef;
        use boatramp_core::sql::{SqlBackends, SqlValue};
        use boatramp_core::tenancy::{AccessMode, ScopeAxis, Tenancy, TenantSource};
        use boatramp_handlers::{GraphqlRequest, HandlerEngine, Limits, ScopeFact};

        // The compiled subgraph probe: its one root field `items` is host-tenancy-scoped
        // (`SELECT id FROM items WHERE {scope}`), so its response reveals which tenant the host
        // resolved for it, and it fails closed with no principal.
        const PROBE: &[u8] = include_bytes!("../tests/fixtures/graphql-scope-probe.wasm");

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());

        // A real per-site libsql backend; seed tenant A + B rows in the probe's OWN function DB
        // (`fn/<name>` — the exact identity `build_function_bindings` opens for `sql_query::open("")`).
        let sql_dir = std::env::temp_dir().join(format!("br-gqlprop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sql_dir);
        let backends = boatramp_storage::LibsqlSqlBackends::local(&sql_dir);
        let db = backends
            .database("default", "fn/scopeprobe", "")
            .await
            .unwrap();
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE items (id TEXT PRIMARY KEY, tenant_id TEXT)",
                &[],
            )
            .await
            .unwrap();
            for (id, tenant) in [("a1", "tenant_A"), ("b1", "tenant_B"), ("b2", "tenant_B")] {
                tx.execute(
                    "INSERT INTO items (id, tenant_id) VALUES (?1, ?2)",
                    &[SqlValue::Text(id.into()), SqlValue::Text(tenant.into())],
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }
        let sql: Arc<dyn SqlBackends> = Arc::new(backends);

        // Deploy the probe as an invocable subgraph function, scoped on `tenant_id` (read own). The
        // declared source is irrelevant on the INHERITED path — the principal comes from the caller.
        let hash = sha256_hex(PROBE);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(PROBE)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();
        let function = Function {
            name: "scopeprobe".into(),
            owner: Owner::Project("default".into()),
            versions: vec![FunctionVersion {
                id: "v1".into(),
                component: hash.clone(),
                created: 0,
                lifecycle: Lifecycle::Independent,
            }],
            active: "v1".into(),
            aliases: Default::default(),
            config: FunctionConfig {
                imports: vec!["sql".into()],
                tenancy: Some(Tenancy::Scoped {
                    column: "tenant_id".into(),
                    sources: vec![TenantSource::None],
                    read: AccessMode::Own,
                    write: AccessMode::None,
                }),
                ..Default::default()
            },
        };
        deploy
            .put_function(ProjectRef::DEFAULT, &function)
            .await
            .unwrap();

        // Register it as a subgraph (default Function backend) + safelist the op.
        crate::graphql_registry::publish(
            kv.as_ref(),
            "default",
            "scopeprobe",
            "type Query { items: [Item!]! }\ntype Item @key(fields: \"id\") { id: ID! }",
        )
        .await
        .unwrap();
        let query = "{ items { id } }";
        let op_hash = crate::graphql_apq::sha256_hex(query);
        kv.put(
            &format!("hapq/default/{op_hash}"),
            query.as_bytes().to_vec(),
        )
        .await
        .unwrap();

        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv.clone(), storage, Some(sql), None);
        rt.set_invoker(deploy.clone());
        let fed = rt
            .inner
            .as_ref()
            .unwrap()
            .federation_runner
            .get()
            .unwrap()
            .clone();
        let req = || GraphqlRequest {
            query: Some(query.to_string()),
            persisted_hash: None,
            variables: "{}".to_string(),
            operation_name: None,
            authorization: None,
        };

        // (1) Propagation: run as tenant B → the subgraph inherits B → returns ONLY B's rows.
        let runner_b = fed.scoped(
            ProjectRef::new("default"),
            vec![ScopeFact {
                axis: ScopeAxis::Tenant,
                value: SqlValue::Text("tenant_B".into()),
            }],
        );
        let body_b = String::from_utf8_lossy(&runner_b.run(req(), 0).await.unwrap()).into_owned();
        assert!(
            body_b.contains("\"b1\"") && body_b.contains("\"b2\"") && !body_b.contains("\"a1\""),
            "graphql::run propagated principal B → the subgraph read ONLY tenant B's rows: {body_b}"
        );

        // (2) Control: run with NO principal → the subgraph's own read fails closed → no rows leak
        // (the pre-v0.4.6 behavior for the empty-caller_tenant path).
        let runner_empty = fed.scoped(ProjectRef::new("default"), Vec::new());
        let body_none =
            String::from_utf8_lossy(&runner_empty.run(req(), 0).await.unwrap()).into_owned();
        assert!(
            !body_none.contains("\"a1\"")
                && !body_none.contains("\"b1\"")
                && !body_none.contains("\"b2\""),
            "with NO propagated principal the subgraph fails closed — no rows leak: {body_none}"
        );

        let _ = std::fs::remove_dir_all(&sql_dir);
        println!(
            "GRAPHQL-RUN PRINCIPAL PROPAGATION OK: graphql::run carried the caller's resolved principal \
             (tenant B) to a federated subgraph sub-fetch, which resolved its own-tenancy from the \
             inherited principal and returned ONLY tenant B's rows over a real libsql engine; with no \
             principal the same sub-fetch failed closed (no rows) — the async lane can drive a \
             tenant-scoped supergraph read/write with no request bearer, symmetric to emit::invoke"
        );
    }

    /// Gap 1 live gate (v0.4.7): the external `/graphql` federation gateway serves a **target-tenant**
    /// field on a **WASM subgraph** — the gateway resolves `B` per fetch (domain source) and FORCES a
    /// `HostTenancy::target` binding onto the subgraph FUNCTION invocation via `invoke_target`, so the
    /// guest's own `sql` is confined to `tenant = B AND <public subset>`. Drives the REAL
    /// `BackendRouter` → `invoke_target` → engine over the REAL libsql-backed probe: a request whose
    /// routed domain resolves tenant B returns ONLY B's PUBLIC rows (never A's, never B's PRIVATE
    /// rows); with no resolved target it fails closed. `#[ignore]`d (static-musl libsql segfault); the
    /// CI job runs it on the host toolchain + greps the marker.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "run on the host toolchain (real libsql static-musl segfault); wired in the CI gateway-target gate"]
    async fn gateway_forces_target_confinement_onto_a_wasm_subgraph() {
        use boatramp_core::deploy::{sha256_hex, DeployStore};
        use boatramp_core::function::{
            Function, FunctionConfig, FunctionVersion, Lifecycle, Owner,
        };
        use boatramp_core::project::ProjectRef;
        use boatramp_core::sql::{SqlBackends, SqlValue};
        use boatramp_core::tenancy::{
            AccessMode, PublicPredicate, PublicSubset, PublicTerm, TableScope, Tenancy,
            TenancySchema, TenantSource,
        };
        use boatramp_handlers::{HandlerEngine, Limits};

        // The SAME compiled probe as the propagation gate — its `items` field runs
        // `SELECT id FROM items WHERE {scope}`. Under a FORCED TARGET binding the host neutralises
        // `{scope}` to `1=1` and AST-rewrites the statement to confine `items` to `tenant = B AND
        // <public predicate>` — so the probe's own declared tenancy is irrelevant (the gateway forces
        // the target); the fixture needs no change.
        const PROBE: &[u8] = include_bytes!("../tests/fixtures/graphql-scope-probe.wasm");

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());

        // Seed the probe's OWN function DB with A's row + B's PUBLIC and PRIVATE rows, so the gate
        // proves BOTH the tenant confinement (no A) AND the public-subset confinement (no B-private).
        let sql_dir = std::env::temp_dir().join(format!("br-gwtarget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sql_dir);
        let backends = boatramp_storage::LibsqlSqlBackends::local(&sql_dir);
        let db = backends
            .database("default", "fn/scopeprobe", "")
            .await
            .unwrap();
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE items (id TEXT PRIMARY KEY, tenant_id TEXT, published INTEGER)",
                &[],
            )
            .await
            .unwrap();
            for (id, tenant, published) in [
                ("a_pub", "tenant_A", 1),
                ("b_pub", "tenant_B", 1),
                ("b_priv", "tenant_B", 0),
            ] {
                tx.execute(
                    "INSERT INTO items (id, tenant_id, published) VALUES (?1, ?2, ?3)",
                    &[
                        SqlValue::Text(id.into()),
                        SqlValue::Text(tenant.into()),
                        SqlValue::Integer(published),
                    ],
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }
        let sql: Arc<dyn SqlBackends> = Arc::new(backends);

        // Deploy the probe as a subgraph FUNCTION (its Scoped-own config is bypassed under a forced
        // target — the composed SDL field's target class is the authority).
        let hash = sha256_hex(PROBE);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(PROBE)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();
        let function = Function {
            name: "scopeprobe".into(),
            owner: Owner::Project("default".into()),
            versions: vec![FunctionVersion {
                id: "v1".into(),
                component: hash.clone(),
                created: 0,
                lifecycle: Lifecycle::Independent,
            }],
            active: "v1".into(),
            aliases: Default::default(),
            config: FunctionConfig {
                imports: vec!["sql".into()],
                tenancy: Some(Tenancy::Scoped {
                    column: "tenant_id".into(),
                    sources: vec![TenantSource::None],
                    read: AccessMode::Own,
                    write: AccessMode::None,
                }),
                ..Default::default()
            },
        };
        deploy
            .put_function(ProjectRef::DEFAULT, &function)
            .await
            .unwrap();

        // Compose a supergraph whose `items` field is a TARGET field (via the routed domain), plan
        // the op, and build a router with the host-trusted target inputs resolving B = "tenant_B".
        let sdl = "type Query { items: [Item!]! @tenant(scope: target, via: [domain], public: \"items\") }\n\
                   type Item @key(fields: \"id\") { id: ID! }";
        let sg = crate::graphql_federation::compose(&[("scopeprobe".into(), sdl.into())]).unwrap();
        let plan = crate::graphql_plan::plan("{ items { id } }", &sg).unwrap();

        let mut schema = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: std::collections::BTreeMap::from([("items".into(), TableScope::Tenant)]),
            ..Default::default()
        };
        schema.public_subsets.insert(
            "items".into(),
            PublicSubset {
                predicate: PublicPredicate {
                    terms: vec![PublicTerm::Cmp {
                        column: "published".into(),
                        op: boatramp_core::tenancy::PublicCmp::Eq,
                        value: boatramp_core::tenancy::PublicLiteral::Int(1),
                    }],
                },
                world_public: true,
                listable: true,
            },
        );

        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv.clone(), storage, Some(sql), None);
        rt.set_invoker(deploy.clone());
        let inner = rt.inner.as_ref().unwrap();
        let invoker = inner.invoker.get().unwrap().clone();

        let make_router = |domain: Option<&str>| {
            crate::graphql_gateway::BackendRouter::new(
                invoker.scoped(ProjectRef::new("default"), Vec::new()),
                "default".to_string(),
                inner.sql.clone(),
                std::collections::BTreeMap::new(),
                None,
            )
            .with_target_inputs(Some(crate::graphql_gateway::TargetInputs {
                schema: Arc::new(schema.clone()),
                domain_context: domain.map(str::to_string),
                target_handle: None,
                capability_anchor: None,
            }))
        };

        // (1) Domain resolves B → the forced target confines the wasm subgraph to B's PUBLIC rows.
        let router_b = make_router(Some("tenant_B"));
        let out_b = crate::graphql_gateway::execute(&plan, &router_b, &serde_json::json!({})).await;
        let body_b = out_b.to_string();
        assert!(
            body_b.contains("\"b_pub\"")
                && !body_b.contains("\"b_priv\"")
                && !body_b.contains("\"a_pub\""),
            "gateway forced target B onto the wasm subgraph → ONLY B's PUBLIC row (b_pub), never B's \
             private row nor A's: {body_b}"
        );

        // (2) No resolved target (no domain, no capability, no handle) → fail closed, no rows.
        let router_none = make_router(None);
        let out_none =
            crate::graphql_gateway::execute(&plan, &router_none, &serde_json::json!({})).await;
        let body_none = out_none.to_string();
        assert!(
            !body_none.contains("\"a_pub\"")
                && !body_none.contains("\"b_pub\"")
                && !body_none.contains("\"b_priv\""),
            "with no resolved target the wasm-subgraph target fetch fails closed — no rows: {body_none}"
        );

        let _ = std::fs::remove_dir_all(&sql_dir);
        println!(
            "GATEWAY WASM-TARGET OK: the /graphql gateway resolved target tenant B from the routed \
             domain and FORCED a HostTenancy::target binding onto the wasm subgraph invocation \
             (invoke_target), confining the guest's own SQL to tenant=B AND published=1 over a real \
             libsql engine — returned ONLY B's public row (b_pub), never B's private row (b_priv) nor \
             tenant A's (a_pub); with no resolved target the fetch failed closed"
        );
    }

    /// **Live gate (v0.4.11):** the EXTERNAL `/graphql` federation gateway propagates the caller's
    /// resolved OWN principal to a WASM subgraph fetch, so a post-P48 host-forced `own` read reached
    /// through the gateway returns the CALLER's tenant rows instead of failing closed (the
    /// production topology: an authed console query fans across `own`-scoped wasm subgraphs). Drives
    /// the REAL `BackendRouter` → invoke → engine over the REAL libsql-backed probe (its `items`
    /// field is `own`-scoped via `{scope}`): caller principal = tenant B ⇒ ONLY B's rows; an EMPTY
    /// principal (anon) ⇒ fail closed (the pre-v0.4.11 bug — every federated `own` read returned
    /// nothing). `#[ignore]`d (static-musl libsql segfault); the CI job runs it on the host toolchain
    /// + greps the marker.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "run on the host toolchain (real libsql static-musl segfault); wired in the CI gateway-own-propagation gate"]
    async fn gateway_propagates_caller_own_principal_to_a_wasm_subgraph() {
        use boatramp_core::deploy::{sha256_hex, DeployStore};
        use boatramp_core::function::{
            Function, FunctionConfig, FunctionVersion, Lifecycle, Owner,
        };
        use boatramp_core::project::ProjectRef;
        use boatramp_core::sql::{SqlBackends, SqlValue};
        use boatramp_core::tenancy::{AccessMode, ScopeAxis, Tenancy, TenantSource};
        use boatramp_handlers::{HandlerEngine, Limits, ScopeFact};

        // The SAME compiled probe — its `items` field runs `SELECT id FROM items WHERE {scope}`. On
        // the INHERITED (own) path the host injects the caller's principal into `{scope}`, so the
        // response reveals which tenant the gateway propagated (and fails closed with none).
        const PROBE: &[u8] = include_bytes!("../tests/fixtures/graphql-scope-probe.wasm");

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());

        let sql_dir = std::env::temp_dir().join(format!("br-gwown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sql_dir);
        let backends = boatramp_storage::LibsqlSqlBackends::local(&sql_dir);
        let db = backends
            .database("default", "fn/scopeprobe", "")
            .await
            .unwrap();
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE items (id TEXT PRIMARY KEY, tenant_id TEXT)",
                &[],
            )
            .await
            .unwrap();
            for (id, tenant) in [("a1", "tenant_A"), ("b1", "tenant_B"), ("b2", "tenant_B")] {
                tx.execute(
                    "INSERT INTO items (id, tenant_id) VALUES (?1, ?2)",
                    &[SqlValue::Text(id.into()), SqlValue::Text(tenant.into())],
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }
        let sql: Arc<dyn SqlBackends> = Arc::new(backends);

        // Deploy the probe as an `own`-scoped subgraph FUNCTION (source `None` — on the inherited
        // path the principal comes from the caller, not a declared source).
        let hash = sha256_hex(PROBE);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(PROBE)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();
        let function = Function {
            name: "scopeprobe".into(),
            owner: Owner::Project("default".into()),
            versions: vec![FunctionVersion {
                id: "v1".into(),
                component: hash.clone(),
                created: 0,
                lifecycle: Lifecycle::Independent,
            }],
            active: "v1".into(),
            aliases: Default::default(),
            config: FunctionConfig {
                imports: vec!["sql".into()],
                tenancy: Some(Tenancy::Scoped {
                    column: "tenant_id".into(),
                    sources: vec![TenantSource::None],
                    read: AccessMode::Own,
                    write: AccessMode::None,
                }),
                ..Default::default()
            },
        };
        deploy
            .put_function(ProjectRef::DEFAULT, &function)
            .await
            .unwrap();

        // A PLAIN (own) supergraph — no `@tenant(scope: target)` — so the fetch takes the ordinary
        // inherited-principal `invoke` path (not `invoke_target`).
        let sdl = "type Query { items: [Item!]! }\ntype Item @key(fields: \"id\") { id: ID! }";
        let sg = crate::graphql_federation::compose(&[("scopeprobe".into(), sdl.into())]).unwrap();
        let plan = crate::graphql_plan::plan("{ items { id } }", &sg).unwrap();

        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv.clone(), storage, Some(sql), None);
        rt.set_invoker(deploy.clone());
        let inner = rt.inner.as_ref().unwrap();
        let invoker = inner.invoker.get().unwrap().clone();

        // The exact construction `federation_gateway` performs: a BackendRouter over an invoker
        // scoped to the caller's OWN principal (v0.4.11 — previously `Vec::new()`).
        let make_router = |facts: Vec<ScopeFact>| {
            crate::graphql_gateway::BackendRouter::new(
                invoker.scoped(ProjectRef::new("default"), facts),
                "default".to_string(),
                inner.sql.clone(),
                std::collections::BTreeMap::new(),
                None,
            )
        };

        // (1) Caller principal = tenant B → the wasm subgraph inherits B → returns ONLY B's rows.
        let router_b = make_router(vec![ScopeFact {
            axis: ScopeAxis::Tenant,
            value: SqlValue::Text("tenant_B".into()),
        }]);
        let body_b = crate::graphql_gateway::execute(&plan, &router_b, &serde_json::json!({}))
            .await
            .to_string();
        assert!(
            body_b.contains("\"b1\"") && body_b.contains("\"b2\"") && !body_b.contains("\"a1\""),
            "gateway propagated principal B → the wasm subgraph read ONLY tenant B's rows: {body_b}"
        );

        // (2) Empty principal (anonymous) → the own fetch fails closed — no rows, anon NOT widened.
        let router_anon = make_router(Vec::new());
        let body_anon =
            crate::graphql_gateway::execute(&plan, &router_anon, &serde_json::json!({}))
                .await
                .to_string();
        assert!(
            !body_anon.contains("\"a1\"")
                && !body_anon.contains("\"b1\"")
                && !body_anon.contains("\"b2\""),
            "with an empty principal the wasm-subgraph own fetch fails closed — no rows: {body_anon}"
        );

        let _ = std::fs::remove_dir_all(&sql_dir);
        println!(
            "GATEWAY OWN-PROPAGATION OK: the /graphql gateway propagated the caller's resolved OWN \
             principal (tenant B) to a wasm subgraph fetch, which scoped its own read to the \
             inherited principal and returned ONLY tenant B's rows over a real libsql engine; with \
             an empty principal the same own fetch failed closed (no rows) — anon is never widened"
        );
    }

    /// v0.4.8 live gate: `scope: target_or_null` on a WASM subgraph reads `B` ⊕ the shared
    /// `NULL`-tenant **base** rows (the funnel inheritance floor), still confined to the public
    /// subset on BOTH — a base-only tenant sees the base floor, never another tenant's rows nor any
    /// private (non-public) row. Drives the REAL gateway → invoke_target → libsql over the probe.
    /// `#[ignore]`d (static-musl libsql segfault); the CI job runs it on the host toolchain.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "run on the host toolchain (real libsql static-musl segfault); wired in the CI gateway-target gate"]
    async fn gateway_target_or_null_includes_the_shared_base() {
        use boatramp_core::deploy::{sha256_hex, DeployStore};
        use boatramp_core::function::{
            Function, FunctionConfig, FunctionVersion, Lifecycle, Owner,
        };
        use boatramp_core::project::ProjectRef;
        use boatramp_core::sql::{SqlBackends, SqlValue};
        use boatramp_core::tenancy::{
            AccessMode, PublicPredicate, PublicSubset, PublicTerm, TableScope, Tenancy,
            TenancySchema, TenantSource,
        };
        use boatramp_handlers::{HandlerEngine, Limits};

        const PROBE: &[u8] = include_bytes!("../tests/fixtures/graphql-scope-probe.wasm");

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());

        let sql_dir = std::env::temp_dir().join(format!("br-gwton-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sql_dir);
        let backends = boatramp_storage::LibsqlSqlBackends::local(&sql_dir);
        let db = backends
            .database("default", "fn/scopeprobe", "")
            .await
            .unwrap();
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE items (id TEXT PRIMARY KEY, tenant_id TEXT, published INTEGER)",
                &[],
            )
            .await
            .unwrap();
            // base_pub: shared floor (NULL tenant, public) → visible. base_priv: NULL but NOT public
            // → excluded (the subset conjoins the base too). b_pub: B public → visible. b_priv: B
            // private → excluded. a_pub: another tenant → excluded (never A's rows).
            for (id, tenant, published) in [
                ("base_pub", None, 1),
                ("base_priv", None, 0),
                ("b_pub", Some("tenant_B"), 1),
                ("b_priv", Some("tenant_B"), 0),
                ("a_pub", Some("tenant_A"), 1),
            ] {
                tx.execute(
                    "INSERT INTO items (id, tenant_id, published) VALUES (?1, ?2, ?3)",
                    &[
                        SqlValue::Text(id.into()),
                        tenant
                            .map(|t| SqlValue::Text(t.into()))
                            .unwrap_or(SqlValue::Null),
                        SqlValue::Integer(published),
                    ],
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }
        let sql: Arc<dyn SqlBackends> = Arc::new(backends);

        let hash = sha256_hex(PROBE);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(PROBE)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();
        let function = Function {
            name: "scopeprobe".into(),
            owner: Owner::Project("default".into()),
            versions: vec![FunctionVersion {
                id: "v1".into(),
                component: hash.clone(),
                created: 0,
                lifecycle: Lifecycle::Independent,
            }],
            active: "v1".into(),
            aliases: Default::default(),
            config: FunctionConfig {
                imports: vec!["sql".into()],
                tenancy: Some(Tenancy::Scoped {
                    column: "tenant_id".into(),
                    sources: vec![TenantSource::None],
                    read: AccessMode::Own,
                    write: AccessMode::None,
                }),
                ..Default::default()
            },
        };
        deploy
            .put_function(ProjectRef::DEFAULT, &function)
            .await
            .unwrap();

        // The funnel field: `scope: target_or_null` — base⊕B.
        let sdl = "type Query { items: [Item!]! @tenant(scope: target_or_null, via: [domain], public: \"items\") }\n\
                   type Item @key(fields: \"id\") { id: ID! }";
        let sg = crate::graphql_federation::compose(&[("scopeprobe".into(), sdl.into())]).unwrap();
        let plan = crate::graphql_plan::plan("{ items { id } }", &sg).unwrap();

        let mut schema = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: std::collections::BTreeMap::from([("items".into(), TableScope::Tenant)]),
            ..Default::default()
        };
        schema.public_subsets.insert(
            "items".into(),
            PublicSubset {
                predicate: PublicPredicate {
                    terms: vec![PublicTerm::Cmp {
                        column: "published".into(),
                        op: boatramp_core::tenancy::PublicCmp::Eq,
                        value: boatramp_core::tenancy::PublicLiteral::Int(1),
                    }],
                },
                world_public: true,
                listable: true,
            },
        );

        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv.clone(), storage, Some(sql), None);
        rt.set_invoker(deploy.clone());
        let inner = rt.inner.as_ref().unwrap();
        let router = crate::graphql_gateway::BackendRouter::new(
            inner
                .invoker
                .get()
                .unwrap()
                .clone()
                .scoped(ProjectRef::new("default"), Vec::new()),
            "default".to_string(),
            inner.sql.clone(),
            std::collections::BTreeMap::new(),
            None,
        )
        .with_target_inputs(Some(crate::graphql_gateway::TargetInputs {
            schema: Arc::new(schema),
            domain_context: Some("tenant_B".into()),
            target_handle: None,
            capability_anchor: None,
        }));

        let out = crate::graphql_gateway::execute(&plan, &router, &serde_json::json!({})).await;
        let body = out.to_string();
        assert!(
            body.contains("\"base_pub\"") && body.contains("\"b_pub\""),
            "target_or_null returned B's public row AND the shared base floor: {body}"
        );
        assert!(
            !body.contains("\"base_priv\"")
                && !body.contains("\"b_priv\"")
                && !body.contains("\"a_pub\""),
            "the public subset confines BOTH B and base (no base_priv, no b_priv), and no other \
             tenant's rows (no a_pub): {body}"
        );

        let _ = std::fs::remove_dir_all(&sql_dir);
        println!(
            "GATEWAY TARGET-OR-NULL OK: scope:target_or_null on a wasm subgraph read tenant B's \
             public row (b_pub) PLUS the shared NULL-tenant base floor (base_pub), each confined to \
             published=1 — never B's private row (b_priv), never a non-public base row (base_priv), \
             never another tenant's row (a_pub); the base-only funnel keeps its inheritance floor"
        );
    }

    /// deploy-resilience #1b/#3 live gate (v0.4.22): the accept-then-validate async deploy path,
    /// exercised over the REAL wasm engine + REAL libsql, proves the load-bearing invariant that a
    /// component which does not fully validate NEVER becomes the served `active` and NEVER serves —
    /// and that the batch compose validates-before-promoting. Concretely:
    ///   A. an async deploy of a component that fails to compile returns `Failed`, leaves the live
    ///      function's `active` pointer untouched, and the previously-active version keeps serving
    ///      real traffic through the gateway; the supergraph still composes.
    ///   B. a valid async deploy reaches `Active` and only THEN is `active` flipped to it.
    ///   C. a batch compose of N staged subgraphs promotes them with exactly ONE version bump; a
    ///      batch that does not compose promotes NOTHING and leaves the live set + version intact.
    /// `#[ignore]`d (real libsql segfaults under the static-musl test binary); the CI
    /// deploy-resilience gate runs it on the host toolchain and greps the success marker, so a
    /// silent skip fails the job.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "run on the host toolchain (real libsql static-musl segfault); wired in the CI deploy-resilience gate"]
    async fn async_deploy_never_activates_or_serves_an_unvalidated_component() {
        use crate::function_api::{run_async_deploy, DeployStatus};
        use boatramp_core::deploy::{sha256_hex, DeployStore};
        use boatramp_core::function::{
            Function, FunctionConfig, FunctionVersion, Lifecycle, Owner,
        };
        use boatramp_core::project::ProjectRef;
        use boatramp_core::sql::{SqlBackends, SqlValue};
        use boatramp_core::tenancy::{AccessMode, ScopeAxis, Tenancy, TenantSource};
        use boatramp_handlers::{GraphqlRequest, HandlerEngine, Limits, ScopeFact};

        // The compiled subgraph probe: `items` runs `SELECT id FROM items WHERE {scope}`, so it both
        // answers `_service { sdl }` (a real subgraph) and, invoked, reveals it actually served.
        const PROBE: &[u8] = include_bytes!("../tests/fixtures/graphql-scope-probe.wasm");
        const SVC_SDL: &str =
            "type Query { items: [Item!]! }\ntype Item @key(fields: \"id\") { id: ID! }";

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());

        // Real per-site libsql; seed the svc function's OWN DB (`fn/svc`) with tenant B rows.
        let sql_dir = std::env::temp_dir().join(format!("br-deployres-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sql_dir);
        let backends = boatramp_storage::LibsqlSqlBackends::local(&sql_dir);
        let db = backends.database("default", "fn/svc", "").await.unwrap();
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE items (id TEXT PRIMARY KEY, tenant_id TEXT)",
                &[],
            )
            .await
            .unwrap();
            for (id, tenant) in [("b1", "tenant_B"), ("b2", "tenant_B")] {
                tx.execute(
                    "INSERT INTO items (id, tenant_id) VALUES (?1, ?2)",
                    &[SqlValue::Text(id.into()), SqlValue::Text(tenant.into())],
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }
        let sql: Arc<dyn SqlBackends> = Arc::new(backends);

        // Deploy the probe as function "svc", active version id "v1" (component = the probe hash).
        let hash = sha256_hex(PROBE);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(PROBE)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();
        let svc_config = || FunctionConfig {
            imports: vec!["sql".into()],
            tenancy: Some(Tenancy::Scoped {
                column: "tenant_id".into(),
                sources: vec![TenantSource::None],
                read: AccessMode::Own,
                write: AccessMode::None,
            }),
            ..Default::default()
        };
        let function = Function {
            name: "svc".into(),
            owner: Owner::Project("default".into()),
            versions: vec![FunctionVersion {
                id: "v1".into(),
                component: hash.clone(),
                created: 0,
                lifecycle: Lifecycle::Independent,
            }],
            active: "v1".into(),
            aliases: Default::default(),
            config: svc_config(),
        };
        deploy
            .put_function(ProjectRef::DEFAULT, &function)
            .await
            .unwrap();

        // Register it as a subgraph + safelist the gateway op, so we can prove it actually SERVES.
        crate::graphql_registry::publish(kv.as_ref(), "default", "svc", SVC_SDL)
            .await
            .unwrap();
        let query = "{ items { id } }";
        let op_hash = crate::graphql_apq::sha256_hex(query);
        kv.put(
            &format!("hapq/default/{op_hash}"),
            query.as_bytes().to_vec(),
        )
        .await
        .unwrap();

        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = Arc::new(HandlerRuntime::new(
            engine,
            kv.clone(),
            storage,
            Some(sql),
            None,
        ));
        rt.set_invoker(deploy.clone());
        let fed = rt
            .inner
            .as_ref()
            .unwrap()
            .federation_runner
            .get()
            .unwrap()
            .clone();
        let serve_svc = || {
            let fed = fed.clone();
            async move {
                let runner = fed.scoped(
                    ProjectRef::new("default"),
                    vec![ScopeFact {
                        axis: ScopeAxis::Tenant,
                        value: SqlValue::Text("tenant_B".into()),
                    }],
                );
                let req = GraphqlRequest {
                    query: Some(query.to_string()),
                    persisted_hash: None,
                    variables: "{}".to_string(),
                    operation_name: None,
                    authorization: None,
                };
                String::from_utf8_lossy(&runner.run(req, 0).await.unwrap()).into_owned()
            }
        };

        // Good baseline: the active v1 serves tenant B's rows through the real gateway.
        let before = serve_svc().await;
        assert!(
            before.contains("\"b1\"") && before.contains("\"b2\""),
            "baseline: the active version serves through the gateway: {before}"
        );
        let version_good =
            crate::graphql_registry::composition_version(kv.as_ref(), "default").await;
        assert!(
            crate::graphql_registry::supergraph(kv.as_ref(), "default")
                .await
                .is_ok(),
            "baseline supergraph composes"
        );

        // (A) A component that FAILS TO COMPILE must never activate nor serve. Store a blob with the
        // wasm-component preamble but junk body, then async-deploy it as a new version of "svc".
        let garbage: Vec<u8> = vec![
            0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00, 0xff, 0xff, 0xde, 0xad,
        ];
        let garbage_hash = sha256_hex(&garbage);
        let g = garbage.clone();
        let gstream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from(g)) }).boxed();
        deploy.put_blob(&garbage_hash, gstream).await.unwrap();
        let status = run_async_deploy(
            deploy.clone(),
            rt.clone(),
            "default",
            "svc",
            &garbage_hash,
            svc_config(),
            Lifecycle::Independent,
            Some(false),
            false,
            0,
        )
        .await;
        assert!(
            matches!(status, DeployStatus::Failed { .. }),
            "an uncompilable component must fail validation, got {status:?}"
        );
        // active pointer untouched...
        let f = deploy
            .get_function(ProjectRef::DEFAULT, "svc")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            f.active, "v1",
            "the failed deploy must NOT flip `active` (still the validated v1), got {}",
            f.active
        );
        assert!(
            !f.versions.iter().any(|v| v.id == garbage_hash),
            "the failed component must not even be persisted as a version"
        );
        // ...the old version still serves real traffic...
        let after = serve_svc().await;
        assert!(
            after.contains("\"b1\"") && after.contains("\"b2\""),
            "the previously-active version must keep serving after a failed deploy: {after}"
        );
        // ...and the supergraph still composes, at the unchanged version.
        assert!(
            crate::graphql_registry::supergraph(kv.as_ref(), "default")
                .await
                .is_ok(),
            "the live supergraph must still compose after a failed deploy"
        );
        assert_eq!(
            crate::graphql_registry::composition_version(kv.as_ref(), "default").await,
            version_good,
            "a failed deploy must not touch the composition version"
        );

        // (B) A VALID async deploy reaches Active and only THEN flips `active` to the validated
        // version (id == component hash). register=false keeps the already-registered subgraph.
        let status = run_async_deploy(
            deploy.clone(),
            rt.clone(),
            "default",
            "svc",
            &hash,
            svc_config(),
            Lifecycle::Independent,
            Some(false),
            false,
            0,
        )
        .await;
        assert!(
            matches!(status, DeployStatus::Active),
            "a valid component must validate to Active, got {status:?}"
        );
        let f = deploy
            .get_function(ProjectRef::DEFAULT, "svc")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            f.active, hash,
            "a valid deploy flips `active` to the validated version only after Active"
        );

        // (C) Batch compose (#3) validate-before-promote, on a fresh project.
        const ACCOUNTS: &str =
            "type Query { me: User }\ntype User @key(fields: \"id\") { id: ID! name: String }";
        const REVIEWS: &str = "type Query { topReviews: [Review] }\ntype Review { id: ID! body: String author: User }\nextend type User @key(fields: \"id\") { id: ID! @external reviews: [Review] }";
        assert_eq!(
            crate::graphql_registry::composition_version(kv.as_ref(), "batchproj").await,
            0
        );
        crate::graphql_registry::stage_subgraph(
            kv.as_ref(),
            "batchproj",
            "accounts",
            ACCOUNTS,
            "h1",
        )
        .await
        .unwrap();
        crate::graphql_registry::stage_subgraph(kv.as_ref(), "batchproj", "reviews", REVIEWS, "h2")
            .await
            .unwrap();
        // Staging alone promotes nothing.
        assert!(
            crate::graphql_registry::subgraph_names(kv.as_ref(), "batchproj")
                .await
                .is_empty()
        );
        let sg = crate::graphql_registry::compose_batch(kv.as_ref(), "batchproj")
            .await
            .unwrap();
        assert!(
            sg.entities.contains_key("User"),
            "the batch composed as a whole"
        );
        assert_eq!(
            crate::graphql_registry::subgraph_names(kv.as_ref(), "batchproj").await,
            vec!["accounts".to_string(), "reviews".to_string()]
        );
        assert_eq!(
            crate::graphql_registry::composition_version(kv.as_ref(), "batchproj").await,
            1,
            "a batch of N subgraphs bumps the composition version exactly ONCE"
        );
        // A non-composing batch promotes nothing and leaves the live set + version intact.
        crate::graphql_registry::stage_subgraph(
            kv.as_ref(),
            "batchproj",
            "clash",
            "type Review { id: ID! body: String }",
            "h3",
        )
        .await
        .unwrap();
        assert!(matches!(
            crate::graphql_registry::compose_batch(kv.as_ref(), "batchproj").await,
            Err(crate::graphql_registry::PublishError::Composition(_))
        ));
        assert_eq!(
            crate::graphql_registry::subgraph_names(kv.as_ref(), "batchproj").await,
            vec!["accounts".to_string(), "reviews".to_string()],
            "a non-composing batch must promote NOTHING"
        );
        assert_eq!(
            crate::graphql_registry::composition_version(kv.as_ref(), "batchproj").await,
            1,
            "a non-composing batch must not bump the version"
        );

        let _ = std::fs::remove_dir_all(&sql_dir);
        println!(
            "DEPLOY-RESILIENCE ASYNC/BATCH OK: over a real wasm engine + real libsql, an async \
             deploy of an uncompilable component returned Failed WITHOUT flipping `active` (the \
             validated v1 kept serving tenant B's rows through the gateway and the supergraph still \
             composed); a valid async deploy reached Active and only then flipped `active`; and a \
             batch compose promoted N staged subgraphs with exactly ONE version bump while a \
             non-composing batch promoted nothing and left the live set + version intact"
        );
    }

    /// Tenant isolation (Step 7a): the background scheduler fans out over every
    /// project, so a **non-default** project's queued async invocation is drained
    /// and metered **within that project** — never leaking into `default`. Before
    /// the fan-out the tick only ever scanned `default`, so an `acme` function's
    /// queue would never drain at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scheduler_drains_a_non_default_projects_invocation_in_its_own_tenant() {
        use crate::scheduler::{run_scheduler_tick, CronNow};
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::function::{
            Function, FunctionVersion, Invocation, InvocationStatus, InvokeMode, Lifecycle, Owner,
        };
        use boatramp_handlers::{HandlerEngine, Limits};
        use futures::StreamExt;

        const HTTP_200: &[u8] =
            include_bytes!("../../boatramp-handlers/tests/fixtures/http-200.wasm");

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());

        let hash = boatramp_core::deploy::sha256_hex(HTTP_200);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(HTTP_200)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();

        // A function + a queued async invocation, both under project `acme`.
        let acme = ProjectRef::new("acme");
        let function = Function {
            name: "worker".into(),
            owner: Owner::Project("acme".into()),
            versions: vec![FunctionVersion {
                id: "v1".into(),
                component: hash.clone(),
                created: 0,
                lifecycle: Lifecycle::Independent,
            }],
            active: "v1".into(),
            aliases: Default::default(),
            config: Default::default(),
        };
        deploy.put_function(acme, &function).await.unwrap();
        let inv = Invocation {
            id: "inv1".into(),
            function: "worker".into(),
            version: "v1".into(),
            mode: InvokeMode::Async,
            status: InvocationStatus::Queued,
            idempotency_key: None,
            attempts: 0,
            lease_expires: None,
            request_b64: None,
            request_content_type: None,
            result: None,
            created: 0,
            updated: 0,
        };
        deploy.put_invocation(acme, &inv).await.unwrap();

        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv.clone(), storage.clone(), None, None);
        let inner = rt.inner.as_ref().unwrap();

        // One tick: `discover_projects()` yields `["acme"]`, so the drain runs
        // under `acme`. A fixed `CronNow` (no cron to match) keeps it deterministic.
        let mut wasm_cache = std::collections::HashMap::new();
        let mut cron_state = std::collections::HashMap::new();
        let mut sweep = std::collections::HashMap::new();
        let now = CronNow {
            minute: 0,
            hour: 0,
            dom: 1,
            month: 1,
            dow: 0,
            minute_stamp: 0,
        };
        run_scheduler_tick(
            inner,
            &deploy,
            &mut wasm_cache,
            &mut cron_state,
            &mut sweep,
            now,
        )
        .await
        .unwrap();

        // The drain claims + spawns the run off the tick, so poll for the
        // terminal transition rather than assuming synchronous settlement.
        let settled = poll_invocation_settled(&deploy, acme, "worker", "inv1").await;
        // The invocation settled Succeeded **in `acme`** …
        assert_eq!(settled.status, InvocationStatus::Succeeded);
        // … metered in `acme` …
        let metering = deploy.get_metering(acme, "worker").await.unwrap().unwrap();
        assert_eq!(metering.invocations, 1);
        // … and nothing leaked into `default` (no record, no metering there).
        assert!(deploy
            .get_invocation(ProjectRef::DEFAULT, "worker", "inv1")
            .await
            .unwrap()
            .is_none());
        assert!(deploy
            .get_metering(ProjectRef::DEFAULT, "worker")
            .await
            .unwrap()
            .is_none());
    }

    /// Poll a durable invocation until it leaves the in-flight states — the drain
    /// spawns the run off the tick, so settlement is asynchronous. Panics on
    /// timeout so a stuck run fails the test rather than hanging it.
    #[cfg(feature = "handlers")]
    async fn poll_invocation_settled(
        deploy: &boatramp_core::deploy::DeployStore,
        project: ProjectRef<'_>,
        function: &str,
        id: &str,
    ) -> boatramp_core::function::Invocation {
        use boatramp_core::function::InvocationStatus;
        for _ in 0..200 {
            if let Some(inv) = deploy.get_invocation(project, function, id).await.unwrap() {
                if matches!(
                    inv.status,
                    InvocationStatus::Succeeded | InvocationStatus::Failed
                ) {
                    return inv;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("invocation {function}/{id} never settled");
    }

    /// A `Running` invocation whose **lease has elapsed** (the node holding it
    /// crashed mid-run) is reclaimed by a later drain and runs to completion; one
    /// whose lease is still in the future is left untouched (no double-run). This
    /// is the crash-recovery guarantee that makes a large async ceiling safe.
    #[cfg(feature = "handlers")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_reclaims_an_expired_lease_and_skips_a_live_one() {
        use crate::scheduler::{run_scheduler_tick, CronNow};
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::function::{
            Function, FunctionVersion, Invocation, InvocationStatus, InvokeMode, Lifecycle, Owner,
        };
        use boatramp_handlers::{HandlerEngine, Limits};
        use futures::StreamExt;

        const HTTP_200: &[u8] =
            include_bytes!("../../boatramp-handlers/tests/fixtures/http-200.wasm");

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());
        let hash = boatramp_core::deploy::sha256_hex(HTTP_200);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(HTTP_200)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();

        let function = Function {
            name: "worker".into(),
            owner: Owner::Project("default".into()),
            versions: vec![FunctionVersion {
                id: "v1".into(),
                component: hash.clone(),
                created: 0,
                lifecycle: Lifecycle::Independent,
            }],
            active: "v1".into(),
            aliases: Default::default(),
            config: Default::default(),
        };
        deploy
            .put_function(ProjectRef::DEFAULT, &function)
            .await
            .unwrap();

        // Two `Running` records: one already claimed by a now-dead node (lease in
        // the past), one held by a live node (lease far in the future).
        let base = Invocation {
            id: String::new(),
            function: "worker".into(),
            version: "v1".into(),
            mode: InvokeMode::Async,
            status: InvocationStatus::Running,
            idempotency_key: None,
            attempts: 1,
            lease_expires: None,
            request_b64: None,
            request_content_type: None,
            result: None,
            created: 0,
            updated: 0,
        };
        let orphan = Invocation {
            id: "orphan".into(),
            lease_expires: Some(1),
            ..base.clone()
        };
        deploy
            .put_invocation(ProjectRef::DEFAULT, &orphan)
            .await
            .unwrap();
        let live = Invocation {
            id: "live".into(),
            lease_expires: Some(u64::MAX),
            ..base.clone()
        };
        deploy
            .put_invocation(ProjectRef::DEFAULT, &live)
            .await
            .unwrap();

        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv.clone(), storage.clone(), None, None);
        let inner = rt.inner.as_ref().unwrap();

        let now = CronNow {
            minute: 0,
            hour: 0,
            dom: 1,
            month: 1,
            dow: 0,
            minute_stamp: 0,
        };
        let mut wasm_cache = std::collections::HashMap::new();
        let mut cron_state = std::collections::HashMap::new();
        let mut sweep = std::collections::HashMap::new();
        run_scheduler_tick(
            inner,
            &deploy,
            &mut wasm_cache,
            &mut cron_state,
            &mut sweep,
            now,
        )
        .await
        .unwrap();

        // The orphan was reclaimed and ran to completion, its attempt advanced …
        let settled =
            poll_invocation_settled(&deploy, ProjectRef::DEFAULT, "worker", "orphan").await;
        assert_eq!(settled.status, InvocationStatus::Succeeded);
        assert_eq!(settled.attempts, 2, "a reclaim counts as another attempt");
        assert_eq!(
            settled.lease_expires, None,
            "a settled invocation drops its lease"
        );
        // … while the live-lease invocation was left exactly as it was.
        let live_after = deploy
            .get_invocation(ProjectRef::DEFAULT, "worker", "live")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(live_after.status, InvocationStatus::Running);
        assert_eq!(live_after.attempts, 1, "a live lease is never reclaimed");
        assert_eq!(live_after.lease_expires, Some(u64::MAX));
    }

    /// BR-TEN-1 (Critical) gate: a same-named **function** in two tenant
    /// projects must NOT share one guest kv namespace. Two functions both named
    /// `store` — one in `acme`, one in `globex` — each writes to guest kv key
    /// `hits` (via the committed `kv-counter` fixture, whose default bucket key
    /// is `hits`). We assert the writes land under DISTINCT host kv keys
    /// (`hkv/acme/fn/store/hits` vs `hkv/globex/fn/store/hits`) and that neither
    /// aliases the bare pre-project key (`hkv/fn/store/hits`). A third `store`
    /// under the reserved `default` project is asserted to keep exactly that bare
    /// key (back-compat: no data migration for a pre-project store).
    ///
    /// This is a real end-to-end kv-isolation assertion driven through the live
    /// engine (`execute_function`) with the existing `kv-counter` fixture — the
    /// preferred form over unit-testing scope construction — because that
    /// exercises the actual `build_function_bindings` scope path a guest sees.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn guest_kv_is_isolated_between_same_named_functions_in_two_projects() {
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::function::{
            Function, FunctionConfig, FunctionVersion, Lifecycle, Owner,
        };
        use boatramp_handlers::{HandlerEngine, Limits};
        use futures::StreamExt;

        let storage = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(storage.clone(), kv.clone());

        // The `kv-counter` fixture increments a "hits" counter in its default kv
        // bucket, so a single invocation writes `<scope>/hits`.
        let hash = boatramp_core::deploy::sha256_hex(KV_COUNTER);
        let stream: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(KV_COUNTER)) }).boxed();
        deploy.put_blob(&hash, stream).await.unwrap();

        // A single `store` function definition (imports `wasi:keyvalue`); the
        // guest binding scope comes from the `project` passed to
        // `execute_function`, not from the function's `owner`, so one definition
        // suffices to prove per-tenant scoping.
        let store = Function {
            name: "store".into(),
            owner: Owner::Project("default".into()),
            versions: vec![FunctionVersion {
                id: "v1".into(),
                component: hash.clone(),
                created: 0,
                lifecycle: Lifecycle::Independent,
            }],
            active: "v1".into(),
            aliases: Default::default(),
            config: FunctionConfig {
                imports: vec!["wasi:keyvalue".into()],
                ..Default::default()
            },
        };
        let acme = ProjectRef::new("acme");
        let globex = ProjectRef::new("globex");

        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
        let inner = rt.inner.as_ref().unwrap();

        let request = || {
            axum::http::Request::builder()
                .method("GET")
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap()
        };

        // Invoke `store` in each of the two non-default projects, plus once in
        // `default`, all named identically.
        let component = store.resolve(&store.active).unwrap().to_owned();
        for project in [acme, globex, ProjectRef::DEFAULT] {
            let (response, _) = execute_function(
                inner,
                &deploy,
                project,
                &store,
                &component,
                request(),
                0,
                boatramp_handlers::Lane::Sync,
                crate::function_runtime::FnTenant::Request,
            )
            .await;
            assert!(response.status().is_success(), "invocation should succeed");
        }

        // The three writes landed under THREE distinct host kv keys: the two
        // tenants are project-qualified, and `default` keeps the bare key.
        assert_eq!(
            kv.get("hkv/acme/fn/store/hits").await.unwrap(),
            Some(b"1".to_vec()),
            "acme's write must be tenant-qualified"
        );
        assert_eq!(
            kv.get("hkv/globex/fn/store/hits").await.unwrap(),
            Some(b"1".to_vec()),
            "globex's write must be tenant-qualified"
        );
        assert_eq!(
            kv.get("hkv/fn/store/hits").await.unwrap(),
            Some(b"1".to_vec()),
            "the default project must keep the byte-identical pre-project key"
        );
        // Sanity: had the fix regressed, all three would have collided on the
        // bare key and it would read "3", not "1".
    }

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
                    tenancy: None,
                    token_claims: None,
                    route: "/".into(),
                    methods: Vec::new(),
                    component: "counter.wasm".into(),
                    imports: vec!["wasi:keyvalue".into()],
                    streaming: false,
                    limits: None,
                    env: std::collections::BTreeMap::new(),
                    invoke_targets: Vec::new(),
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
        deploy
            .activate(ProjectRef::DEFAULT, "blog", &id)
            .await
            .unwrap();
        deploy
            .set_site_config(
                ProjectRef::DEFAULT,
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
        let mut sweep = std::collections::HashMap::new();
        let at = |stamp| CronNow {
            minute: 0,
            hour: 0,
            dom: 1,
            month: 1,
            dow: 0,
            minute_stamp: stamp,
        };

        // Fires once for the minute.
        let (_, handles) =
            run_scheduler_tick(&inner, &deploy, &mut wasm, &mut crons, &mut sweep, at(100))
                .await
                .unwrap();
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(kv.get("hkv/blog/hits").await.unwrap(), Some(b"1".to_vec()));

        // Same minute → deduped (no fire).
        let (_, handles) =
            run_scheduler_tick(&inner, &deploy, &mut wasm, &mut crons, &mut sweep, at(100))
                .await
                .unwrap();
        assert!(handles.is_empty());
        assert_eq!(kv.get("hkv/blog/hits").await.unwrap(), Some(b"1".to_vec()));

        // Next minute → fires again.
        let (_, handles) =
            run_scheduler_tick(&inner, &deploy, &mut wasm, &mut crons, &mut sweep, at(101))
                .await
                .unwrap();
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(kv.get("hkv/blog/hits").await.unwrap(), Some(b"2".to_vec()));

        // overlap=Skip: a previous fire still running → the next minute is skipped.
        // The cron dedup key is project-qualified (`default|blog|cron|0`) so a
        // same-named site in another project can't dedup this one.
        crons
            .get("default|blog|cron|0")
            .unwrap()
            .running
            .store(true, Ordering::Release);
        let (_, handles) =
            run_scheduler_tick(&inner, &deploy, &mut wasm, &mut crons, &mut sweep, at(102))
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
                    tenancy: None,
                    token_claims: None,
                    route: "/".into(),
                    methods: Vec::new(),
                    component: "counter.wasm".into(),
                    imports: vec!["wasi:keyvalue".into()],
                    streaming: false,
                    limits: None,
                    env: std::collections::BTreeMap::new(),
                    invoke_targets: Vec::new(),
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
        deploy
            .activate(ProjectRef::DEFAULT, "blog", &id)
            .await
            .unwrap();
        deploy
            .set_site_config(
                ProjectRef::DEFAULT,
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
        let mut sweep = std::collections::HashMap::new();
        let now = CronNow {
            minute: 0,
            hour: 0,
            dom: 1,
            month: 1,
            dow: 0,
            minute_stamp: 100,
        };

        let (_, handles) =
            run_scheduler_tick(&inner, &deploy, &mut wasm, &mut crons, &mut sweep, now)
                .await
                .unwrap();
        // No cron fired (a follower); the counter was never written.
        assert!(handles.is_empty(), "a non-leader must not fire crons");
        assert_eq!(kv.get("hkv/blog/hits").await.unwrap(), None);
    }

    /// Gap 4a: `project_tenancy_knobs` returns the operator's per-project override for a listed
    /// project and falls back to the node base for any unlisted project — the runtime half of
    /// per-project posture (the resolution half is `security::per_project_override_*`).
    #[tokio::test]
    async fn project_tenancy_knobs_override_wins_else_node_base() {
        use boatramp_core::security::ResolvedProjectTenancy;
        use boatramp_handlers::{HandlerEngine, Limits};

        let kv: Arc<dyn boatramp_core::kv::KvStore> = Arc::new(boatramp_core::kv::MemoryKv::new());
        let storage: Arc<dyn boatramp_core::Storage> = Arc::new(MemStorage::default());
        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv, storage, None, None);
        // Node base: strict multi-tenant (declaration required, no cross-tenant `all`).
        rt.set_tenancy_posture(true, false);
        // One project relaxes cross-tenant (its `all` twins) while KEEPING strict declaration.
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert(
            "preview".to_string(),
            ResolvedProjectTenancy {
                require_tenancy_declaration: true,
                allow_cross_tenant_db: true,
                capability_max_ttl_secs: Some(1800),
            },
        );
        rt.set_project_tenancy_overrides(overrides);
        let inner = rt.inner.as_ref().unwrap();

        // Listed project → the override.
        let p = inner.project_tenancy_knobs("preview");
        assert!(p.require_tenancy_declaration);
        assert!(p.allow_cross_tenant_db);
        assert_eq!(p.capability_max_ttl_secs, Some(1800));
        // Unlisted project → the node base (strict, no cross-tenant, no minting wired).
        let b = inner.project_tenancy_knobs("prod");
        assert!(b.require_tenancy_declaration);
        assert!(!b.allow_cross_tenant_db);
        assert_eq!(b.capability_max_ttl_secs, None);
    }

    /// Named SQL binding dispatch through the real `build_bindings` + a real (libsql) provider:
    /// the granted databases in the resulting `Bindings` are exactly what the per-handler grant
    /// grammar allows, with the site as the ceiling. This is the config→dispatch→backends half of
    /// the tenant-isolation story (the guest-open half is the binding layer's
    /// `two_named_databases_are_independent`; a full guest `open("named")` e2e needs a wasm
    /// fixture and is a live-validation follow-up).
    #[tokio::test]
    async fn build_bindings_dispatches_named_sql_databases_with_least_privilege() {
        use boatramp_core::config::HandlersSiteConfig;
        use boatramp_core::project::ProjectRef;
        use boatramp_handlers::{HandlerEngine, Limits};

        let kv: Arc<dyn boatramp_core::kv::KvStore> = Arc::new(boatramp_core::kv::MemoryKv::new());
        let storage: Arc<dyn boatramp_core::Storage> = Arc::new(MemStorage::default());
        // A real per-site libsql provider (opens a distinct database per name).
        let sql_dir =
            std::env::temp_dir().join(format!("boatramp-named-sql-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sql_dir);
        let sql: Arc<dyn boatramp_core::sql::SqlBackends> =
            Arc::new(boatramp_storage::LibsqlSqlBackends::local(&sql_dir));

        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv, storage, Some(sql), None);
        let inner = rt.inner.as_ref().unwrap();

        // The site exposes the default + two named databases — the ceiling. It declares tenancy
        // Disabled (this test is about named-sql dispatch, not tenancy) so the fail-closed
        // default posture (require a declaration) admits it.
        let site = HandlersSiteConfig {
            enabled: true,
            allow_imports: vec!["sql".into(), "sql:product".into(), "sql:privileged".into()],
            tenancy: Some(boatramp_core::tenancy::Tenancy::Disabled),
            ..Default::default()
        };
        let env = std::collections::BTreeMap::new();
        let build = |imports: &[&str]| {
            let imports: Vec<String> = imports.iter().copied().map(String::from).collect();
            let site = &site;
            let env = &env;
            async move {
                crate::handler_dispatch::build_bindings(
                    inner,
                    ProjectRef::new("default"),
                    "shop",
                    "shop",
                    None,
                    &imports,
                    site,
                    env,
                    &[],
                    0,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await
                .expect("no secrets → resolves")
                .sql_database_names()
            }
        };

        // Least-privilege: a handler asking only for the default + product gets exactly those —
        // never `privileged`, even though the site exposes it.
        assert_eq!(build(&["sql", "sql:product"]).await, vec!["", "product"]);
        // A wildcard handler gets every name the site exposes (default via bare `sql` + all named).
        assert_eq!(
            build(&["sql", "sql:*"]).await,
            vec!["", "privileged", "product"]
        );
        // Fail-closed: requesting a name the site does not expose grants nothing.
        assert!(build(&["sql:secret"]).await.is_empty());
        // No bare `sql` → the default `""` database is not granted either.
        assert_eq!(build(&["sql:product"]).await, vec!["product"]);

        let _ = std::fs::remove_dir_all(&sql_dir);
    }

    /// **Managed-dependency readiness gate (v0.4.19).** A component whose required host-managed
    /// database is still starting must NOT run into a confusing `orm: sql database "" not granted`
    /// (the post-mortem). Driven through the real `build_bindings` with a fake `SqlBackends`:
    ///   * a MANAGED db that is not ready (`SqlError::Unavailable`) → `BindingsError::NotReady` (the
    ///     caller renders a retryable 503 + `Retry-After`), fail-closed — the guest never runs;
    ///   * a db that is only a moment from ready (Unavailable then Ok) → the short readiness retry
    ///     catches it → the binding is granted (no 503);
    ///   * an external/local db down (`SqlError::Other`) → logged + SKIPPED, the request still runs
    ///     (per-DB resilience preserved — NOT gated);
    ///   * `sql_starting_response` is a 503 carrying `Retry-After`.
    #[tokio::test]
    async fn managed_dependency_not_ready_gates_with_a_retryable_503() {
        use crate::handler_dispatch::{build_bindings, BindingsError};
        use boatramp_core::config::HandlersSiteConfig;
        use boatramp_core::project::ProjectRef;
        use boatramp_core::sql::{SqlBackend, SqlBackends, SqlError};
        use boatramp_handlers::{HandlerEngine, Limits};
        use std::sync::atomic::{AtomicUsize, Ordering};

        // What the fake provider's `database()` yields (per call, in order for the retry case).
        enum Outcome {
            Unavailable,       // managed DB still starting → gate
            Other,             // external/local DB down → skip (resilience)
            Ready,             // opens fine
            UnavailableThenOk, // transient: not-ready once, then ready (exercises the retry)
        }
        struct FakeSql {
            outcome: Outcome,
            calls: AtomicUsize,
            real: Arc<dyn SqlBackend>,
        }
        #[async_trait::async_trait]
        impl SqlBackends for FakeSql {
            async fn database(
                &self,
                _project: &str,
                _site: &str,
                _name: &str,
            ) -> Result<Arc<dyn SqlBackend>, SqlError> {
                let n = self.calls.fetch_add(1, Ordering::SeqCst);
                match self.outcome {
                    Outcome::Unavailable => {
                        Err(SqlError::unavailable("workload has no replica yet"))
                    }
                    Outcome::Other => Err(SqlError::other("external db connection refused")),
                    Outcome::Ready => Ok(Arc::clone(&self.real)),
                    Outcome::UnavailableThenOk if n == 0 => {
                        Err(SqlError::unavailable("still initializing"))
                    }
                    Outcome::UnavailableThenOk => Ok(Arc::clone(&self.real)),
                }
            }
        }

        // A real libsql backend to hand back for the "ready" cases (never queried here).
        let sql_dir =
            std::env::temp_dir().join(format!("boatramp-readiness-gate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sql_dir);
        let real = boatramp_storage::LibsqlSqlBackends::local(&sql_dir)
            .database("default", "shop", "")
            .await
            .unwrap();

        // Build bindings for a handler granting the default `sql` database, tenancy Disabled (this
        // test is about the readiness gate, not tenancy), against a provider with `outcome`.
        async fn build_with(
            outcome: Outcome,
            real: &Arc<dyn SqlBackend>,
        ) -> (Result<boatramp_handlers::Bindings, BindingsError>, usize) {
            let kv: Arc<dyn boatramp_core::kv::KvStore> =
                Arc::new(boatramp_core::kv::MemoryKv::new());
            let storage: Arc<dyn boatramp_core::Storage> = Arc::new(MemStorage::default());
            let fake = Arc::new(FakeSql {
                outcome,
                calls: AtomicUsize::new(0),
                real: Arc::clone(real),
            });
            let sql: Arc<dyn SqlBackends> = fake.clone();
            let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
            let rt = HandlerRuntime::new(engine, kv, storage, Some(sql), None);
            let inner = rt.inner.as_ref().unwrap();
            let site = HandlersSiteConfig {
                enabled: true,
                allow_imports: vec!["sql".into()],
                tenancy: Some(boatramp_core::tenancy::Tenancy::Disabled),
                ..Default::default()
            };
            let imports = vec!["sql".to_string()];
            let env = std::collections::BTreeMap::new();
            let r = build_bindings(
                inner,
                ProjectRef::new("default"),
                "shop",
                "shop",
                None,
                &imports,
                &site,
                &env,
                &[],
                0,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await;
            (r, fake.calls.load(Ordering::SeqCst))
        }

        // (1) Managed not-ready → NotReady (retryable 503 + Retry-After). Fail-closed.
        let (r, _) = build_with(Outcome::Unavailable, &real).await;
        match r {
            Err(BindingsError::NotReady {
                retry_after_secs, ..
            }) => {
                assert!(retry_after_secs >= 1, "advertises a Retry-After");
            }
            Err(BindingsError::Refused(m)) => {
                panic!("a not-ready managed DB must gate with NotReady, got Refused({m})")
            }
            Ok(_) => panic!("a not-ready managed DB must gate, but bindings were built"),
        }

        // (2) External/local down → skipped, request still builds (per-DB resilience, NOT gated).
        let (r, _) = build_with(Outcome::Other, &real).await;
        let bindings = r.expect("a non-managed DB outage must NOT gate the whole request");
        assert!(
            !bindings.sql_database_names().contains(&String::new()),
            "the broken default DB is left ungranted (skipped), not gated"
        );

        // (3) Ready → the binding is granted.
        let (r, _) = build_with(Outcome::Ready, &real).await;
        let bindings = r.expect("a ready DB builds");
        assert!(bindings.sql_database_names().contains(&String::new()));

        // (4) Transient (not-ready then ready) → the short readiness retry catches it: granted, and
        // the provider was called twice (one retry).
        let (r, calls) = build_with(Outcome::UnavailableThenOk, &real).await;
        let bindings = r.expect("the readiness retry catches a DB a moment from ready");
        assert!(bindings.sql_database_names().contains(&String::new()));
        assert_eq!(calls, 2, "one bounded retry on Unavailable");

        // (5) The gate response is a 503 carrying Retry-After.
        let resp = crate::sql_starting_response(2);
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("2"),
            "the readiness 503 advertises Retry-After"
        );

        let _ = std::fs::remove_dir_all(&sql_dir);
        println!(
            "MANAGED-DEP READINESS GATE OK: a required managed database that is still starting gates \
             the invocation with a retryable 503 + Retry-After (fail-closed, guest never runs); a \
             brief startup blip is caught by the bounded readiness retry; an external/local DB \
             outage is skipped (per-DB resilience), never gating the whole request."
        );
    }

    /// **Consumer signed-context dispatch live gate (v0.4.17).** The site-`consumers` async lane
    /// now resolves EACH claimed message's host-sealed `signed_context` into that message's binding
    /// — the fix for the R1 producer-stamp the consumer never read (`dispatch_consumer_batch` built
    /// its bindings once, contextless). Exercised through the exact new seam
    /// (`ConsumerRebuild::bindings_for`, which every claimed message flows through) on a REAL libsql
    /// engine:
    ///   * a message carrying a VALID fleet-signed envelope for tenant `acme` resolves `acme` as the
    ///     consumer's own principal → a scoped read returns ONLY acme's row (never globex);
    ///   * an UNSEALED message (a plain background drain) resolves NO principal → the same scoped op
    ///     fails closed (`NoSource`), never runs unscoped;
    ///   * a FORGED (stranger-signed) envelope also resolves NO principal → fail closed;
    ///   * the resolved principal is the SAME value `build_bindings` threads onto an
    ///     `invoke`/`graphql::run` caller principal, so a signed-context worker drives an `own`
    ///     supergraph write on the async lane (the v0.4.6 propagation mechanism).
    #[tokio::test]
    async fn consumer_signed_context_dispatch_resolves_per_message_tenant_on_a_real_engine() {
        use crate::handler_dispatch::ConsumerRebuild;
        use boatramp_core::config::HandlersSiteConfig;
        use boatramp_core::cose::{mint_context, Signer};
        use boatramp_core::orm::{Expr, Select, SelectItem};
        use boatramp_core::sql::{Dialect, SqlBackends, SqlValue};
        use boatramp_core::tenancy::{AccessMode, Tenancy, TenantSource};
        use boatramp_handlers::{HandlerEngine, Limits, TenantAxis, TenantDenied};

        // A real per-site libsql provider; seed `notes` with an acme row and a globex row.
        let sql_dir =
            std::env::temp_dir().join(format!("boatramp-consumer-sctx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sql_dir);
        let backends = boatramp_storage::LibsqlSqlBackends::local(&sql_dir);
        let db = backends.database("default", "worker", "").await.unwrap();
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE notes (id TEXT PRIMARY KEY, tenant_id TEXT, body TEXT)",
                &[],
            )
            .await
            .unwrap();
            for (id, tenant, body) in [("n1", "acme", "acme-note"), ("n2", "globex", "globex-note")]
            {
                tx.execute(
                    "INSERT INTO notes (id, tenant_id, body) VALUES (?1, ?2, ?3)",
                    &[
                        SqlValue::Text(id.into()),
                        SqlValue::Text(tenant.into()),
                        SqlValue::Text(body.into()),
                    ],
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }

        let kv: Arc<dyn boatramp_core::kv::KvStore> = Arc::new(boatramp_core::kv::MemoryKv::new());
        let storage: Arc<dyn boatramp_core::Storage> = Arc::new(MemStorage::default());
        let sql: Arc<dyn boatramp_core::sql::SqlBackends> =
            Arc::new(boatramp_storage::LibsqlSqlBackends::local(&sql_dir));
        let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
        let rt = HandlerRuntime::new(engine, kv, storage, Some(sql), None);
        // Strict multi-tenant posture: the consumer must resolve its tenant from the SIGNATURE alone
        // (the async lane carries no bearer/domain/session), and undeclared tenancy is refused.
        rt.set_tenancy_posture(true, false);
        // The fleet signer's public half is BOTH the mint key and the consumer's verify anchor.
        let signer: Arc<dyn Signer> = Arc::new(LocalSigner::generate(TokenAlg::Es256));
        rt.set_session_signer(signer.clone());
        let stranger: Arc<dyn Signer> = Arc::new(LocalSigner::generate(TokenAlg::Es256));
        let inner = rt.inner.as_ref().unwrap();

        // The consumer declares `sources: [signed_context]` (own read+write) — the async-lane keystone.
        let tenancy = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::SignedContext],
            read: AccessMode::Own,
            write: AccessMode::Own,
        };
        let site = HandlersSiteConfig {
            enabled: true,
            allow_imports: vec!["sql".into()],
            // No site-level tenancy ceiling; the per-consumer decision is the whole story here.
            ..Default::default()
        };
        let imports = vec!["sql".to_string()];
        let rebuild = ConsumerRebuild {
            inner,
            project: ProjectRef::new("default"),
            site: "worker",
            scope: "worker",
            imports: &imports,
            site_handlers: &site,
            tenancy: Some(&tenancy),
            token_claims: None,
        };

        // Force the resolved own-read scope onto a SELECT and run it on the real engine.
        async fn read_bodies(
            db: &dyn boatramp_core::sql::SqlBackend,
            scope: &boatramp_core::orm::Scope,
        ) -> Vec<String> {
            let mut q = Select {
                columns: vec![SelectItem {
                    expr: Expr::col("body"),
                    alias: None,
                }],
                ..Select::from("notes")
            };
            q.force_scope(scope).unwrap();
            let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
            let mut tx = db.begin().await.unwrap();
            let rows = tx.query(&sql, &params).await.expect("query runs");
            tx.commit().await.unwrap();
            let mut out: Vec<String> = rows
                .rows
                .into_iter()
                .flatten()
                .filter_map(|v| match v {
                    SqlValue::Text(s) => Some(s),
                    _ => None,
                })
                .collect();
            out.sort();
            out
        }

        let now = boatramp_core::time::now_unix();

        // (1) SEALED: a valid fleet-signed envelope for `acme` → the consumer resolves `acme`.
        let env = mint_context("acme", 3600, now, signer.as_ref())
            .await
            .unwrap();
        let sealed = rebuild.bindings_for(Some(&env)).await.unwrap();
        let ht = sealed
            .resolved_tenancy()
            .expect("a signed-context consumer resolves a tenancy");
        assert_eq!(
            ht.value(),
            Some(&SqlValue::Text("acme".into())),
            "the sealed envelope's tenant is the consumer's own principal"
        );
        // The same principal `build_bindings` threads onto the invoke/graphql caller principal.
        assert!(
            ht.facts()
                .iter()
                .any(|f| f.value == SqlValue::Text("acme".into())),
            "the resolved fact carries acme (this is the graphql::run caller principal too)"
        );
        let read_scope = ht.orm_scope(TenantAxis::Read).unwrap().unwrap();
        assert_eq!(
            read_bodies(db.as_ref(), &read_scope).await,
            vec!["acme-note".to_string()],
            "the resolved tenant scopes a real engine to acme's row ONLY (never globex)"
        );
        // The write axis resolves acme too (a signed-context worker lands an `own` write on it).
        assert!(
            ht.orm_scope(TenantAxis::Write).unwrap().is_some(),
            "the write axis resolves the sealed tenant"
        );

        // (2) UNSEALED: a plain background drain carries no envelope → NO principal → fail closed.
        let plain = rebuild.bindings_for(None).await.unwrap();
        let ht = plain
            .resolved_tenancy()
            .expect("the tenancy decision is present (but factless)");
        assert!(
            ht.value().is_none(),
            "an unsealed message resolves no own tenant"
        );
        assert!(
            matches!(ht.orm_scope(TenantAxis::Read), Err(TenantDenied::NoSource)),
            "a scoped op with no resolved tenant fails closed (never runs unscoped)"
        );

        // (3) FORGED: a stranger-signed envelope fails verification → NO principal → fail closed.
        let forged = mint_context("globex", 3600, now, stranger.as_ref())
            .await
            .unwrap();
        let forged_b = rebuild.bindings_for(Some(&forged)).await.unwrap();
        let ht = forged_b
            .resolved_tenancy()
            .expect("the tenancy decision is present (but factless)");
        assert!(
            ht.value().is_none(),
            "a stranger-signed envelope resolves no own tenant (never masquerades as globex)"
        );
        assert!(
            matches!(ht.orm_scope(TenantAxis::Read), Err(TenantDenied::NoSource)),
            "a forged envelope fails the scoped op closed"
        );

        // (4) EXPIRED: a valid fleet signature whose envelope has already expired → NO principal →
        // fail closed (a stale producer stamp can never keep scoping the consumer past its TTL).
        let expired = mint_context("acme", 3600, now.saturating_sub(7200), signer.as_ref())
            .await
            .unwrap();
        let expired_b = rebuild.bindings_for(Some(&expired)).await.unwrap();
        let ht = expired_b
            .resolved_tenancy()
            .expect("the tenancy decision is present (but factless)");
        assert!(
            ht.value().is_none()
                && matches!(ht.orm_scope(TenantAxis::Read), Err(TenantDenied::NoSource)),
            "an expired envelope resolves no own tenant and fails the scoped op closed"
        );

        // (5) INTERLEAVING (per-message isolation across a batch): rebuild message A (acme) then a
        // DIFFERENT sealed message B (globex), and confirm each resolves to ITS OWN tenant and scopes
        // the engine to only that tenant's row — the resolve carries no state between messages, so a
        // batch mixing tenants can never cross-attribute (acme's binding is never reused for globex).
        let env_b = mint_context("globex", 3600, now, signer.as_ref())
            .await
            .unwrap();
        let a = rebuild.bindings_for(Some(&env)).await.unwrap();
        let b = rebuild.bindings_for(Some(&env_b)).await.unwrap();
        let ht_a = a.resolved_tenancy().unwrap();
        let ht_b = b.resolved_tenancy().unwrap();
        assert_eq!(ht_a.value(), Some(&SqlValue::Text("acme".into())));
        assert_eq!(ht_b.value(), Some(&SqlValue::Text("globex".into())));
        assert_eq!(
            read_bodies(
                db.as_ref(),
                &ht_a.orm_scope(TenantAxis::Read).unwrap().unwrap()
            )
            .await,
            vec!["acme-note".to_string()],
            "message A stays scoped to acme"
        );
        assert_eq!(
            read_bodies(
                db.as_ref(),
                &ht_b.orm_scope(TenantAxis::Read).unwrap().unwrap()
            )
            .await,
            vec!["globex-note".to_string()],
            "message B (interleaved) scopes to globex ONLY — no bleed from A's binding"
        );

        println!(
            "CONSUMER SIGNED-CONTEXT DISPATCH OK: the site-consumers async lane resolves each \
             claimed message's host-sealed signed_context per message; a valid fleet-signed \
             envelope scopes a real libsql engine to the originator's tenant ONLY, while an \
             unsealed or forged message resolves no principal and fails an own op closed (never \
             cross-tenant, never unscoped). The resolved principal is the same value that \
             propagates onto a graphql::run sub-fetch."
        );

        let _ = std::fs::remove_dir_all(&sql_dir);
    }
}
