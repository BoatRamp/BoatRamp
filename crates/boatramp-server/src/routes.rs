//! The application router: assemble the axum `Router` that wires every
//! control-plane and data-plane endpoint (deployments, sites, functions,
//! tokens, cluster, gateway, previews, host routing) together with the auth,
//! CORS, access-log, and rate-limit middleware. `router` is the public entry;
//! `router_with` takes explicit `ServerOptions`. Pulls the handlers and
//! middleware in via `use super::*`.

use super::*;

/// Build the application router around a [`DeployStore`], [`Auth`] config, and
/// the WebAssembly handler runtime ([`HandlerRuntime::disabled`] for none), with
/// default [`ServerOptions`] (unlimited, live probe).
pub fn router(deploy: DeployStore, auth: Auth, handlers: HandlerRuntime) -> Router {
    router_with(deploy, auth, handlers, ServerOptions::default())
}

/// [`router`] with explicit [`ServerOptions`] — lets a caller set request limits
/// or inject a custom domain-ownership probe. Returns just the axum [`Router`];
/// the serve loop uses [`router_with_fast`] to also obtain the hot-path handle.
pub fn router_with(
    deploy: DeployStore,
    auth: Auth,
    handlers: HandlerRuntime,
    options: ServerOptions,
) -> Router {
    router_with_fast(deploy, auth, handlers, options).0
}

/// Like [`router_with`] but also returns the [`FastServe`](crate::serve_pipeline::FastServe)
/// hot-path handle, so the serve loop can dispatch eligible requests directly to
/// `serve_by_host` and bypass the axum router/middleware composition tax. The handle is
/// opaque; a caller only passes it (with the router) into a serve loop
/// ([`serve_tls`](crate::serve_tls) / [`serve_plaintext`](crate::serve_plaintext) / the
/// splice loop) via [`ServeInput`](crate::ServeInput).
pub fn router_with_fast(
    deploy: DeployStore,
    auth: Auth,
    handlers: HandlerRuntime,
    options: ServerOptions,
) -> (Router, crate::serve_pipeline::FastServe) {
    // Opt-in CORS allowlist for the control-plane API; empty ⇒ CORS off.
    // Captured before `options` is partially moved below.
    let cors_origins = options.cors_allowed_origins.clone();
    // The resolved security posture rides as an extension for the gateway /
    // proxy / domain-verify / upload paths (the hardening knobs).
    let posture = options.posture;
    // Operator capabilities the node wires (managed-DB SQL + workload exec). Cheap
    // `Option<Arc>` clones; they ride as `api` extensions read by the admin handlers.
    // (`_cap` suffix so they don't shadow the `sql_exec`/`compute_exec` handler fns.)
    let operator_sql_cap = options.operator_sql.clone();
    let tenant_deprovisioner_cap = options.tenant_deprovisioner.clone();
    let compute_exec_cap = options.compute_exec.clone();
    let compute_volumes_cap = options.compute_volumes.clone();
    let compute_control_cap = options.compute_control.clone();
    // The project-scoped internal secret store (`None` when no `[secrets]` envelope
    // is configured — the admin secrets endpoints then fail closed with a clear 501).
    // Rides as an `api` extension read by the secrets handlers; not handlers-gated.
    let secret_store_cap = options.secret_store.clone();
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
        // Projects (0.2.0): the owning Workspace. Entity CRUD; the per-resource
        // `/api/projects/{proj}/sites/…` surface is served by the site/function/…
        // handlers via the `project_scope` rewrite layer added below.
        .route("/api/projects", get(list_projects).post(create_project))
        .route(
            "/api/projects/{proj}",
            get(get_project).delete(delete_project),
        )
        .route("/api/functions", get(list_functions))
        .route(
            "/api/functions/{name}",
            put(deploy_function).delete(remove_function),
        )
        .route("/api/functions/{name}/rollback", post(rollback_function))
        .route("/api/functions/{name}/aliases/{label}", put(alias_function))
        .route(
            "/api/sites/{site}/deployments",
            post(create_deployment).get(list_deployments),
        )
        .route("/api/blobs/{hash}", put(put_blob))
        .route(
            "/api/sites/{site}/deployments/{id}/activate",
            post(activate_deployment),
        )
        .route("/api/sites/{site}/deployments/{id}", get(get_deployment))
        .route("/api/sites/{site}/current", get(current_deployment))
        .route(
            "/api/sites/{site}/config",
            get(get_site_config).put(put_site_config),
        )
        .route("/api/sites/{site}", axum::routing::delete(delete_site))
        .route(
            "/api/sites/{site}/domains/{host}/verification",
            get(domain_verify::get_domain_verification)
                .post(domain_verify::start_domain_verification)
                .delete(domain_verify::remove_domain_verification),
        )
        .route(
            "/api/sites/{site}/domains/{host}/verification/check",
            post(domain_verify::check_domain_verification),
        )
        .route(
            "/api/sites/{site}/domain-verifications",
            get(domain_verify::list_domain_verifications),
        )
        // Admin-only: attach a host WITHOUT an ownership proof (`domain add
        // --unverified`). Gated at `system·admin` in `authz::Right::required`.
        .route(
            "/api/sites/{site}/domains/{host}/attach-unverified",
            post(domain_verify::attach_domain_unverified),
        )
        .route("/api/sites/{site}/aliases", get(list_aliases))
        .route(
            "/api/sites/{site}/aliases/{name}",
            put(set_alias).delete(remove_alias),
        )
        // Project-scoped internal secret store. The admin surface the client hits
        // is `/api/projects/{proj}/secrets{,/{name}}`; `project_scope` rewrites it
        // onto these global routes (tagging the request with its `ProjectContext`),
        // exactly like sites/functions/compute. Set (seal) + list (names + metadata
        // only) + delete; there is deliberately **no value-GET** — a value leaves the
        // store only into a guest at instantiation, never over the API. Authorized as
        // `Secrets·Read`/`Secrets·Write` against the original project-scoped path.
        // Bound the request body explicitly on the secrets route (rather than relying
        // on axum's 2 MB default): a secret value is capped at 64 KiB in the store, so
        // 512 KiB leaves headroom for JSON-escaping the value + the name/framing while
        // keeping the transiently-buffered body small — a project admin can't buffer a
        // large body before the store's size check runs.
        .route(
            "/api/secrets",
            post(set_secret)
                .get(list_secrets)
                .layer(axum::extract::DefaultBodyLimit::max(512 * 1024)),
        )
        .route("/api/secrets/{name}", axum::routing::delete(delete_secret))
        .route("/api/tokens", post(create_token).get(list_tokens))
        // First-token bootstrap: RBAC-exempt (`Right::required` → None for exactly
        // this path); the handler verifies a single-use operator-set secret. The
        // static segment takes precedence over the `/:id` route below.
        .route("/api/tokens/bootstrap", post(bootstrap_token))
        .route("/api/tokens/{id}", axum::routing::delete(revoke_token))
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
            "/api/auth/root/{pubkey}",
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
        // Persistent-volume management — registered BEFORE `/api/compute/{name}` so the
        // literal `volumes` segment wins over the `{name}` param. NODE-GLOBAL (lists/
        // removes volumes across every tenant), so `Right::required` gates it at
        // `system·admin` explicitly — NOT the per-project right the general
        // `/api/compute/*` mapping gives, which a project-scoped token would satisfy.
        // List flags in-use vs orphaned; DELETE refuses a still-referenced volume
        // (`409`) unless `?force=true`.
        .route("/api/compute/volumes", get(list_compute_volumes))
        .route(
            "/api/compute/volumes/{name}",
            axum::routing::delete(delete_compute_volume),
        )
        // Compute maintenance / diagnostics — the operator "maneuvering" surface, also
        // registered BEFORE `/api/compute/{name}` so the reserved `status`/`ipam`/
        // `maintenance` segments win over the `{name}` param. NODE-GLOBAL: they read and
        // override the reconcile plane across every tenant, so `Right::required` gates
        // them at `system·admin` (`is_compute_maintenance_path`) — never the per-project
        // right the general `/api/compute/*` mapping gives.
        .route("/api/compute/status", get(compute_status))
        .route("/api/compute/ipam", get(compute_ipam))
        .route("/api/compute/dns", get(compute_dns))
        .route("/api/compute/dns/resolve", post(compute_dns_resolve))
        .route("/api/compute/reconcile", post(compute_reconcile))
        .route(
            "/api/compute/maintenance/set-health",
            post(compute_set_health),
        )
        .route("/api/compute/maintenance/restart", post(compute_restart))
        .route("/api/compute/maintenance/netdiag", post(compute_netdiag))
        .route(
            "/api/compute/{name}",
            get(get_compute).put(put_compute).delete(delete_compute),
        )
        // Run a command inside a running workload replica (docker-exec style).
        // Admin-scoped (deny-safe `Right::required` default for `/api/compute/*`)
        // AND gated at the handler by the `allow_compute_exec` posture.
        .route("/api/compute/{name}/exec", post(compute_exec))
        // Operator SQL to a managed co-located database: run a migration script or a
        // single query via the sealed managed credential (resolved server-side).
        // Admin-scoped (deny-safe `Right::required` default for `/api/sql/*`).
        .route("/api/sql/{db}/exec", post(sql_exec))
        .route("/api/sql/{db}/query", post(sql_query))
        // Active per-replica reachability probe (bypasses the stored-health gate).
        // Same project-owned `sql`-family right (`/api/sql/*` → Project·Deploy).
        .route("/api/sql/{db}/ping", post(sql_ping));
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
            "/api/sites/{site}/_boatramp/handlers",
            get(operator_handler_stats),
        )
        .route("/api/sites/{site}/_boatramp/logs", get(operator_logs))
        .route(
            "/api/sites/{site}/_boatramp/logs/stream",
            get(operator_logs_stream),
        )
        .route("/api/sites/{site}/_boatramp/dlq", post(operator_dlq))
        // The function **invoke** surface (FA-3) needs the engine, so it is
        // registered only with the handlers feature.
        .route("/api/functions/{name}/invoke", post(invoke_function))
        .route(
            "/api/functions/{name}/invocations/{id}",
            get(get_invocation_record),
        )
        .route("/api/functions/{name}/usage", get(get_function_usage))
        // Function triggers (scheduled + event sources): cron + queue triggers the
        // scheduler dispatches. Needs the engine, so behind the handlers feature.
        .route("/api/functions/{name}/triggers", get(list_triggers_handler))
        .route(
            "/api/functions/{name}/triggers/{id}",
            put(put_trigger_handler).delete(delete_trigger_handler),
        )
        // Workflow orchestration (FA-6): definitions + runs. The executor drain
        // needs the engine, so the surface is registered with the handlers feature.
        .route("/api/workflows", get(list_workflows_handler))
        .route(
            "/api/workflows/{name}",
            put(define_workflow)
                .get(get_workflow_handler)
                .delete(delete_workflow_handler),
        )
        .route("/api/workflows/{name}/runs", post(start_workflow_run))
        .route(
            "/api/workflows/{name}/runs/{id}",
            get(get_workflow_run_handler),
        )
        // GraphQL subgraph schema registry: publish a subgraph's SDL (recomposes +
        // validates the supergraph) and read the composed supergraph. Parses SDL, so
        // it is behind the handlers feature.
        .route(
            "/api/graphql/subgraphs/{name}",
            put(put_graphql_subgraph).delete(delete_graphql_subgraph),
        )
        // Register a SQL-backed federation subgraph: introspect the named site's database,
        // generate its `@key` SDL, and record the SQL backend.
        .route(
            "/api/graphql/subgraphs/{name}/sql",
            put(put_graphql_sql_subgraph),
        )
        // Register a function-backed federation subgraph by introspection: invoke the deployed
        // function's `_service { sdl }` and publish the returned SDL (no hand-written SDL).
        .route(
            "/api/graphql/subgraphs/{name}/function",
            put(put_graphql_function_subgraph),
        )
        // The GraphQL operation safelist (the guest/agent allowlist): register (returns the
        // hash) + list trusted operations, and delete one by hash. Guest runs are deny-by-default.
        .route(
            "/api/graphql/safelist",
            post(register_graphql_safelist).get(list_graphql_safelist),
        )
        .route(
            "/api/graphql/safelist/{hash}",
            axum::routing::delete(delete_graphql_safelist),
        )
        .route("/api/graphql/supergraph", get(get_graphql_supergraph));
    // An `Auth` clone for the `/mcp` channel gate (captured before `auth` is moved
    // into the API's `require_auth` layer below) + the node's canonical origin, for
    // scoping the `/mcp` anti-DNS-rebinding host allowlist to the operator's domain.
    #[cfg(feature = "mcp")]
    let mcp_auth = auth.clone();
    #[cfg(feature = "mcp")]
    let mcp_origin = options.pop_origin.clone();
    let api = api
        // Added BEFORE require_auth so it is the INNER layer (require_auth runs first):
        // only an already-authorized request reaches the project-existence guard, so a
        // 404 "no project" is never an existence oracle for an unauthorized caller.
        .route_layer(axum::middleware::from_fn_with_state(
            deploy.clone(),
            crate::project_scope::require_project_exists,
        ))
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
    // Extensions only the control-plane API reads are layered on the `api`
    // sub-router here — before the merge below — so they wrap only the API routes,
    // not the `serve_by_host` fallback whose matched route axum clones on every
    // served request. Keeping these off the hot-path route shortens that
    // per-request boxed-service clone (profiled at a few percent of proxy CPU under
    // load). The extensions the serving / well-known / webhook routes actually read
    // stay app-level, added after the merge.
    let api = api
        .layer(Extension(issuer))
        .layer(Extension(bootstrap))
        .layer(Extension(mesh_control))
        .layer(Extension(probe))
        .layer(Extension(operator_sql_cap))
        .layer(Extension(tenant_deprovisioner_cap))
        .layer(Extension(compute_exec_cap))
        .layer(Extension(compute_volumes_cap))
        .layer(Extension(compute_control_cap))
        .layer(Extension(secret_store_cap))
        .layer(Extension(upload_guard));
    #[cfg(feature = "oidc")]
    let api = api.layer(Extension(oidc_state));

    // Public routes (never authenticated by token): health + serving +
    // immutable deploy-by-id previews. A deployment id is a SHA-256 of content,
    // so the `/_deploy/<id>/…` URL is an unguessable capability. Visitor access
    // control (basic auth / IP rules / rate limit) is applied per-site inside
    // the serving handlers via the shared [`RateLimiter`] extension.
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        // Explicit by-name admin/testing route: `/_sites/<name>/…`.
        .route("/_sites/{*rest}", any(serve_sites))
        .route("/_deploy/{*rest}", get(serve_preview))
        // Domain-ownership self-serve: serve a pending HTTP challenge token
        // before host routing, so an unattached host can verify itself. An
        // explicit route, so it wins over the `serve_by_host` fallback.
        .route(
            "/.well-known/boatramp-domain-verification/{token}",
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
    let app = app.route("/_webhooks/{name}", post(webhook_ingress));
    // Bundle the serve deps for the hot-path bypass (`FastServe`) before they move into
    // the router's Extension layers below — cloned so the fast path and the axum path serve
    // from identical state. `handlers` is bound as its `Arc` here so the layer below and the
    // bypass share one runtime.
    let handlers = Arc::new(handlers);
    let fast = crate::serve_pipeline::FastServe {
        deploy: deploy.clone(),
        limiter: rate_limiter.clone(),
        handlers: handlers.clone(),
        daemon: daemon.clone(),
        implicit: implicit_routing,
        preview_auth: preview_auth.clone(),
        // Same values as `Extension(posture)` / `Extension(served_over_tls)` below, so the
        // bypass re-inserts identical per-request extensions.
        posture,
        served_over_tls: served_over_tls.0,
        // Set later by `FastServe::advertise_http3` where the router gets the Alt-Svc layer.
        alt_svc: None,
    };
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
        .layer(Extension(handlers))
        // Whether an unmatched host may resolve implicitly (first-label / sole
        // site); gated to dev/single-tenant/loopback by `serve`.
        .layer(Extension(implicit_routing))
        // Preview-access policy + an Auth handle the preview handlers consult
        // when previews are token-gated.
        .layer(Extension(preview_policy))
        .layer(Extension(preview_auth));
    // (`issuer`, `bootstrap`, `mesh_control`, and `oidc_state` are control-plane
    // only; they are layered on the `api` sub-router above so they stay off the
    // hot-path serving route. `whoami` reads the `Auth` extension directly.)
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
    // Likewise for the `/mcp` live enable/disable kill-switch.
    #[cfg(feature = "mcp")]
    let mcp_daemon = daemon.clone();
    let app = app.layer(Extension(daemon));
    // Embedded web console (feature `console`): a middleware that intercepts the
    // configured host+path before the site fallback. Always layered — the mount is
    // a live `DaemonConfig` value, so the console can be enabled/disabled at runtime
    // (a disabled console is a pass-through). See [`console::mount`].
    #[cfg(feature = "console")]
    let app = console::mount(app, console_daemon);
    // The in-`serve` HTTP MCP endpoint (`/mcp`): on by default when compiled. Its
    // tools dispatch in-process through a clone of the fully-assembled app (all
    // extensions + the API's `require_auth`), carrying the caller's forwarded
    // bearer. Built from `app.clone()` here — before `/mcp` itself is merged in — so
    // the backend router has every handler extension but not `/mcp` (no recursion).
    #[cfg(feature = "mcp")]
    let app = {
        let mcp = crate::mcp_http::mcp_router(app.clone(), mcp_auth, mcp_origin, mcp_daemon);
        app.merge(mcp)
    };
    // Project-scope rewrite must run *before* routing so `/api/projects/{proj}/sites/…`
    // is rewritten to its global form (and tagged with its `ProjectContext`) before the
    // route/fallback is chosen. A `Router::layer` runs *after* routing, so instead wrap
    // the fully-assembled app as the `fallback_service` of a thin outer router: every
    // request hits that fallback, so the outer layer runs for all of them ahead of the
    // inner router's own routing. `access_log` stays outermost (it logs the original
    // path the client sent); `project_scope` is a no-op for every non-project path.
    let router = Router::new()
        .fallback_service(app)
        .layer(axum::middleware::from_fn(project_scope))
        .layer(axum::middleware::from_fn(access_log));
    (router, fast)
}

#[cfg(test)]
mod secrets_api_tests {
    //! Stage-3 admin secrets API, driven through the full router (project-scope
    //! rewrite + auth layer + handlers). Asserts the value-free contract end to end:
    //! set (201, seals) → list (names + metadata, **no values**) → delete (204/404),
    //! plus that the no-envelope wiring fails closed with a clear 501 rather than a
    //! panic. Auth is disabled (`Auth::disabled()`), so `ProjectContext` defaults to
    //! `default` and the request flows straight through.
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request, StatusCode};
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::secret_store::{SecretMeta, SecretStore};
    use tower::ServiceExt as _;

    use crate::{Auth, HandlerRuntime, ServerOptions};

    /// A reversible XOR test envelope: `set` seals, so a value is visibly different at
    /// rest, yet round-trips (mirrors the store's own unit tests).
    struct XorEnvelope;
    #[async_trait::async_trait]
    impl boatramp_core::envelope::KeyEnvelope for XorEnvelope {
        async fn wrap(&self, p: &[u8]) -> Result<Vec<u8>, boatramp_core::envelope::EnvelopeError> {
            Ok(p.iter().map(|b| b ^ 0x5a).collect())
        }
        async fn unwrap(
            &self,
            c: &[u8],
        ) -> Result<Vec<u8>, boatramp_core::envelope::EnvelopeError> {
            Ok(c.iter().map(|b| b ^ 0x5a).collect())
        }
    }

    /// Build the router with (or without) a secret store wired, over a fresh in-memory
    /// deploy store. (Sealing-at-rest is proved by the store's own unit tests and the
    /// resolver test; here we assert the API contract — including that no value ever
    /// crosses the wire.)
    fn router_with_store(store: Option<Arc<SecretStore>>) -> axum::Router {
        // The secrets flow only touches the KV; blobs are irrelevant here, so a
        // temp-dir FsStorage (as in the hot-path tests) is enough for the deploy store.
        let deploy = DeployStore::new(
            Arc::new(boatramp_storage::FsStorage::new(std::env::temp_dir())),
            Arc::new(MemoryKv::new()),
        );
        let options = ServerOptions {
            secret_store: store,
            ..Default::default()
        };
        crate::router_with_fast(
            deploy,
            Auth::disabled(),
            HandlerRuntime::disabled(),
            options,
        )
        .0
    }

    async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
        to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn set_list_delete_round_trips_and_never_returns_values() {
        let store = Arc::new(SecretStore::new(
            Arc::new(MemoryKv::new()),
            Arc::new(XorEnvelope),
        ));
        let app = router_with_store(Some(store));

        // POST /api/projects/default/secrets {name, value} → 201 + SecretMeta.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/projects/default/secrets")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"db-pw","value":"hunter2"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let created = body_bytes(resp).await;
        let meta: SecretMeta = serde_json::from_slice(&created).unwrap();
        assert_eq!(meta.name, "db-pw");
        assert_eq!(meta.revision, 1);
        // Even the 201 create response is value-free — it echoes metadata, not the value.
        let created_text = String::from_utf8(created).unwrap();
        assert!(
            !created_text.contains("hunter2"),
            "the create response must never echo the value: {created_text}"
        );

        // GET → the metadata (name + revision + timestamps), never a value.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/projects/default/secrets")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = body_bytes(resp).await;
        let metas: Vec<SecretMeta> = serde_json::from_slice(&raw).unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].name, "db-pw");
        // The value never crosses the API: the serialized list must not carry it, and
        // the value-free `SecretMeta` has no field that could.
        let text = String::from_utf8(raw).unwrap();
        assert!(
            !text.contains("hunter2") && !text.to_ascii_lowercase().contains("value"),
            "the secrets list must never carry a value: {text}"
        );

        // DELETE the secret → 204 first time, 404 the second (idempotent existence).
        let del = || {
            app.clone().oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/api/projects/default/secrets/db-pw")
                    .body(Body::empty())
                    .unwrap(),
            )
        };
        assert_eq!(del().await.unwrap().status(), StatusCode::NO_CONTENT);
        assert_eq!(del().await.unwrap().status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn no_envelope_wiring_fails_closed_with_a_clear_501() {
        // No secret store injected (no `[secrets]` envelope): every endpoint returns a
        // clear 501, never a 500 or a panic.
        let app = router_with_store(None);
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/projects/default/secrets")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"x","value":"y"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        let text = String::from_utf8(body_bytes(resp).await).unwrap();
        assert!(
            text.contains("no [secrets] key envelope configured"),
            "{text}"
        );
    }
}
