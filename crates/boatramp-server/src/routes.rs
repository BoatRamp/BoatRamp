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
