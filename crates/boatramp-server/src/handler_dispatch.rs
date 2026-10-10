//! The WebAssembly handler dispatch path: load a matched handler's component
//! blob, build the site's granted bindings, run it on the engine, and adapt
//! the response back to axum, plus the shared consumer-batch drain the
//! scheduler reuses. Gated behind the `handlers` feature; without it the
//! server carries no wasm dependency and handler routes fall through to the
//! static pipeline. Pulls the serve scope in via `use super::*`.

use super::*;

/// Dispatch a matched handler: load its component blob, build the site's
/// granted bindings, run it on the engine, and adapt the response back to axum.
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch_handler(
    runtime: &HandlerRuntime,
    deploy: &DeployStore,
    manifest: &Manifest,
    project: &str,
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
    //
    // The base identity is then **project-qualified** (BR-TEN-1): a same-named
    // site in two tenant projects must not share one kv/blob/messaging/logs
    // namespace or one concurrency semaphore. `default` → byte-identical to the
    // pre-project layout (no data migration); any other project prefixes
    // `"<project>/"`. SQL is resolved separately below (its provider qualifies
    // internally, so it takes the raw `site` + `project`, not this scope).
    let project_ref = boatramp_core::project::ProjectRef::new(project);
    let base = match preview {
        Some(id) => format!("{site}/_preview/{id}"),
        None => site.to_string(),
    };
    let scope = project_ref.qualified(&base);
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

    // Browser cookie session auth: if the site opts in and the request carries the configured
    // cookie but no `Authorization` header, use the cookie value as the app bearer for **every**
    // downstream consumer (managed handlers read it from the request; the GraphQL edge, data
    // connector, invoked functions, and `graphql::run` all flow from the same bearer). The
    // `Authorization` header always wins, so API clients are unaffected. boatramp only reads the
    // cookie — the app sets it. A cookie-authenticated request is CSRF-checked against the
    // configured origins first (boatramp's inbound defense, over the app's `SameSite=Lax`).
    match cookie_auth_outcome(request.headers(), site_handlers.cookie_auth.as_ref()) {
        CookieAuthOutcome::None => {}
        CookieAuthOutcome::Reject => {
            return (
                StatusCode::FORBIDDEN,
                "cross-origin cookie-authenticated request rejected\n",
            )
                .into_response();
        }
        CookieAuthOutcome::Inject(token) => {
            // The cookie value is the app bearer — inject it as the standard header so every
            // downstream consumer verifies it byte-identically to a client-supplied header bearer.
            if let Ok(value) = HeaderValue::try_from(format!("Bearer {token}")) {
                request.headers_mut().insert(header::AUTHORIZATION, value);
            }
        }
    }

    // GraphQL edge processing: resolve a persisted-query hash to its text (registering
    // it on a verified first miss unless safelisted), then reject an over-limit (or,
    // when disabled, introspection) query — all before the handler runs. Every
    // query-bearing POST is inspected: the body is buffered up to `MAX_QUERY_BYTES`
    // regardless of its declared length, and a body over that cap is rejected outright
    // (not passed through), so no chunked or oversized request can bypass the guard. Only
    // an upload/form POST (`multipart/form-data`, `x-www-form-urlencoded`) — which carries
    // no inspectable query — passes through untouched.
    // The GraphQL edge (query guard, federation / data-connector planner, and the GraphiQL
    // explorer) is a property of the graphql ENDPOINT ROUTE — not a site-wide interceptor. It
    // applies only when the REQUEST PATH matches the configured graphql route pattern (default
    // `/graphql`), so every other declared guest route (OAuth `/authorize`, `/jwks`, redirect
    // starts) is served by its own handler regardless of `Accept` — a browser always sends
    // `Accept: text/html`, which otherwise shadowed the guest handler with the IDE.
    //
    // Matching the request PATH (not the *matched handler's* route string) is deliberate: under
    // first-match routing a broader handler (e.g. `/**`) declared before the `/graphql` handler
    // would otherwise win the match and — with a raw `handler.route ==` gate — silently disable
    // the edge (query depth/complexity/introspection guard included) on the real endpoint. The
    // path match keeps the guard engaged on `/graphql` whichever handler served it.
    let is_graphql_endpoint = |g: &boatramp_core::config::HandlerGraphqlConfig| {
        boatramp_core::matcher::Pattern::compile(g.route.as_deref().unwrap_or("/graphql"))
            .map(|p| p.is_match(request_path))
            .unwrap_or(false)
    };
    if let Some(gql) = site_handlers
        .graphql
        .as_ref()
        .filter(|g| g.enabled && is_graphql_endpoint(g))
    {
        // GraphiQL explorer: a browser GET (Accept: text/html) gets the IDE, which posts
        // queries back to the same URL.
        if gql.graphiql && request.method() == Method::GET {
            let wants_html = request
                .headers()
                .get(header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|a| a.contains("text/html"));
            if wants_html {
                return graphql_graphiql::page();
            }
        }
        if request.method() == Method::POST {
            let content_type = request
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            // A GraphQL query travels as JSON or a raw `application/graphql` body. A
            // `multipart/form-data` / `x-www-form-urlencoded` POST is an upload or form
            // submission whose query (if any) the edge does not parse — pass it through
            // rather than buffer it under the small query cap.
            let is_upload = content_type.as_deref().is_some_and(|ct| {
                ct.contains("multipart/form-data")
                    || ct.contains("application/x-www-form-urlencoded")
            });
            if !is_upload {
                let (parts, body) = request.into_parts();
                // Buffer up to the cap regardless of Content-Length; a body over the cap
                // is refused (a GraphQL request is small, and an unbounded body must not
                // slip past the guard). `to_bytes` also enforces the cap, so this can
                // never exhaust host memory.
                let mut body_bytes =
                    match axum::body::to_bytes(body, graphql_guard::MAX_QUERY_BYTES).await {
                        Ok(raw) => raw.to_vec(),
                        Err(_) => return graphql_guard::too_large_response(),
                    };

                // The query to guard: from a JSON body's `query` (after APQ resolution)
                // or a raw `application/graphql` body.
                let mut effective_query: Option<String> = None;
                // The request's GraphQL variables (for the data connector); a raw
                // `application/graphql` body carries none.
                let mut variables = serde_json::Value::Object(Default::default());
                if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                    if let Some(vars) = json.get("variables").filter(|v| v.is_object()) {
                        variables = vars.clone();
                    }
                    if gql.persisted_queries || gql.enforce_safelist {
                        match graphql_apq::resolve_stored(
                            inner.kv.as_ref(),
                            &scope,
                            &json,
                            gql.enforce_safelist,
                        )
                        .await
                        {
                            graphql_apq::Resolved::Error(msg) => {
                                return graphql_apq::error_response(&msg);
                            }
                            graphql_apq::Resolved::Query(q) => {
                                // Inject the resolved query so the handler executes it.
                                json["query"] = serde_json::Value::String(q.clone());
                                if let Ok(v) = serde_json::to_vec(&json) {
                                    body_bytes = v;
                                }
                                effective_query = Some(q);
                            }
                            graphql_apq::Resolved::Passthrough => {}
                        }
                    }
                    if effective_query.is_none() {
                        effective_query = json
                            .get("query")
                            .and_then(|v| v.as_str())
                            .map(str::to_string);
                    }
                } else {
                    effective_query =
                        graphql_guard::query_from_body(content_type.as_deref(), &body_bytes);
                }

                if let Some(query) = &effective_query {
                    if let graphql_guard::GuardVerdict::Reject(reason) =
                        graphql_guard::guard_query(query, &graphql_guard::limits_from(gql))
                    {
                        return graphql_guard::error_response(&reason);
                    }
                    // The request's app bearer token (if any), whose verified claims the data
                    // connector's `row_filter` may bind — sourced only when the site configures
                    // `claims_from_token`, and only after full verification.
                    let bearer = parts
                        .headers
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| {
                            s.strip_prefix("Bearer ")
                                .or_else(|| s.strip_prefix("bearer "))
                        })
                        .map(str::to_string);
                    // The routed domain's context tag (R4/D8): the target-tenant `B` for a
                    // carried-domain target read (a same-origin funnel served on B's host). Stashed
                    // in the request extensions at host routing — never guest input.
                    let domain_context = parts
                        .extensions
                        .get::<crate::DomainContext>()
                        .map(|c| c.0.clone());
                    // R4/D8 5c: a target field with a `handle` source resolves `B` from a PUBLIC slug
                    // the request names in `?handle=` (read-only, world-public only). `None` ⇒ none.
                    let target_handle = parts
                        .uri
                        .query()
                        .and_then(|q| query_value(q, "handle"))
                        .map(str::to_string);
                    // GraphQL subscription: serve it as a graphql-sse event stream,
                    // deriving the messaging topic from the subscription's root field. A
                    // producer (a mutation, a function) publishes each execution result to
                    // that topic; the host frames it as graphql-sse `next`.
                    if let Some(topic) = graphql_subscription::subscription_topic(query) {
                        // #495: on the FEDERATED external edge, an edge-hidden (or unknown) root
                        // must not be streamable either — else a subscription would be an oracle /
                        // escape hatch around the planner's hide. Resolve the subscription's root
                        // through the SAME effective-hidden set as the planner; when it is hidden,
                        // DON'T open the stream — fall through to `federation_gateway`, which returns
                        // the generic "cannot be planned" outcome (a subscription is `Unsupported`
                        // there), byte-identical to a truly-unknown/unsupported field (no oracle).
                        // A non-federated graphql site is unaffected (streams as before).
                        let hide_subscription = if gql.federated {
                            subscription_root_is_hidden(
                                inner,
                                project,
                                query,
                                &gql.edge_hidden_operations,
                                &gql.edge_hidden_subgraphs,
                            )
                            .await
                        } else {
                            false
                        };
                        if !hide_subscription {
                            let after = parts
                                .headers
                                .get("last-event-id")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_string);
                            return crate::stream::serve_graphql_subscription(
                                inner,
                                site,
                                site_handlers,
                                &topic,
                                after,
                                client_ip,
                                preview,
                            )
                            .await;
                        }
                    }
                    // Both server-side GraphQL paths (the federation gateway and the data
                    // connector's delegated-field invoke) fan out to subgraph/sibling FUNCTIONS
                    // whose host-forced `own` reads no longer self-scope (post-P48) — so both must
                    // propagate the caller's resolved OWN principal (from the /graphql route's token
                    // source + token_claims, symmetric to a normal handler). Resolved once here;
                    // anon resolves none and every `own` fetch fail-closes (never widened). A plain
                    // GraphQL handler component (neither path) computes its own principal downstream,
                    // so skip the resolution (and its schema load) for it.
                    let runs_server_graphql =
                        gql.federated || gql.data.as_ref().is_some_and(|d| d.enabled);
                    // Time the auth phase (token verify + any JWKS fetch) — the phase that carried the
                    // ~1 s pre-TTL overhead; surfaced in the gateway phase log + `Server-Timing`.
                    let auth_start = std::time::Instant::now();
                    let (caller_own, caller_pass) = if runs_server_graphql {
                        match resolve_gateway_caller_facts(
                            inner,
                            project,
                            handler,
                            site_handlers,
                            bearer.as_deref(),
                            domain_context.as_deref(),
                        )
                        .await
                        {
                            Ok(pair) => pair,
                            Err(resp) => return resp,
                        }
                    } else {
                        (Vec::new(), false)
                    };
                    let auth_us = auth_start.elapsed().as_micros() as u64;
                    // Federation gateway: plan the query against the project's registered
                    // subgraphs and execute it by dispatching fetches to the subgraph
                    // functions, instead of running a single handler component.
                    if gql.federated {
                        return federation_gateway(
                            inner,
                            project,
                            query,
                            &variables,
                            bearer.as_deref(),
                            domain_context.as_deref(),
                            target_handle.as_deref(),
                            caller_own,
                            caller_pass,
                            // #495: the site's edge-visibility manifest (per-operation +
                            // per-subgraph excludes) — resolved fresh per request against the
                            // supergraph inside the gateway, so a manifest change takes effect
                            // immediately (no recomposition lag) and never widens.
                            &gql.edge_hidden_operations,
                            &gql.edge_hidden_subgraphs,
                            auth_us,
                        )
                        .await;
                    }
                    // Declarative data connector: serve the query from the site's managed
                    // database (compiled to SQL), instead of running a handler component.
                    if let Some(data) = gql.data.as_ref().filter(|d| d.enabled) {
                        return data_connector_serve(
                            inner,
                            project,
                            site,
                            data,
                            query,
                            &variables,
                            bearer.as_deref(),
                            caller_own,
                            caller_pass,
                        )
                        .await;
                    }
                }
                // Put the (possibly query-injected) body back on the request.
                request = Request::from_parts(parts, axum::body::Body::from(body_bytes));
            }
        }
    }

    // Edge response cache: on a cacheable request a fresh hit short-circuits the
    // whole handler path — no blob read, no bindings, no instantiation. The write
    // context is captured here because `serve_with_limits` below consumes `request`.
    // R3 (PLAN-tenancy-principal): resolve — or, on a first anonymous request to an R3 project,
    // mint — the host-signed session cookie. `session_cookie` feeds the `Session` scope-fact; a
    // freshly-minted `set_session_cookie` is added to the response (`Set-Cookie`) below. Resolved
    // **before** the edge cache so a session-scoped response is never shared-cached (see below).
    // Per-phase handler timing (Ask-1 observability, symmetric to the `boatramp::gateway` phase log +
    // `Server-Timing` the federated path got in v0.21.0): a plain `#[handler]` otherwise exposes only a
    // single `duration_ms` (time-to-head), so a host-side cost is unattributable. `dispatch_start` is the
    // plain-path wall-clock anchor (the cheap pre-session routing/scope setup is excluded).
    let dispatch_start = std::time::Instant::now();
    let t_session = std::time::Instant::now();
    let (session_cookie, set_session_cookie) = resolve_or_mint_session(
        request.headers(),
        inner,
        boatramp_core::project::ProjectRef::new(project),
    )
    .await;
    let session_us = t_session.elapsed().as_micros() as u64;
    // The edge cache is keyed on the project/site + path, NOT the session id, so it MUST NOT serve
    // or store a response computed under a per-visitor `Session` fact — that would leak one anon
    // visitor's `tenant IS NULL` rows to another. When a session fact is in play, bypass the cache
    // entirely (both read and write); non-R3 traffic caches as before.
    let cache_cfg = handler_cache::config_for(site_handlers);
    let cache_key = cache_cfg
        .as_ref()
        .filter(|_| session_cookie.is_none())
        .and_then(|cfg| {
            handler_cache::request_lookupable(cfg, request.method()).then(|| {
                let path_and_query = request.uri().path_and_query().map_or("/", |pq| pq.as_str());
                handler_cache::cache_key(&scope, request.method(), path_and_query)
            })
        });
    if let Some(key) = &cache_key
        && let Some(hit) = handler_cache::lookup_response(
            inner.kv.as_ref(),
            key,
            request.headers(),
            handler_cache::now_secs(),
        )
        .await
    {
        return hit;
    }
    let cache_write = match (&cache_cfg, &cache_key) {
        (Some(cfg), Some(key)) => Some((
            cfg.clone(),
            key.clone(),
            request.method().clone(),
            request.headers().clone(),
        )),
        _ => None,
    };

    // The component `.wasm` is a content-addressed blob in the deployment.
    let Some(entry) = manifest.files.get(&handler.component) else {
        tracing::warn!(site, component = %handler.component, "handler component missing from deployment");
        return handler_unavailable();
    };
    // PERF (construens memory-instance): on a WARM hit the engine serves from its compiled
    // `ProxyPre` cache and never looks at the component bytes — so re-reading them here, which on a
    // remote blob backend (S3/Tigris) is a full network GET of a multi-hundred-KB component just to
    // discard it, is pure per-request latency (the ~0.5 s "not compute" steady cost). Read the blob
    // ONLY on a cold miss; a warm component serves from memory with no backend hit.
    // `component_us`: the warm-check + (cold-miss only) component-blob GET — a known per-request cost on
    // a remote blob backend; the v0.14.0 warm-skip keeps it ~0 on a warm hit.
    let t_component = std::time::Instant::now();
    let wasm = if inner.engine.request_component_warm(&entry.hash) {
        Vec::new()
    } else {
        match read_blob_fully(deploy, &entry.hash).await {
            Ok(bytes) => bytes,
            Err(response) => return response,
        }
    };
    let component_us = t_component.elapsed().as_micros() as u64;

    // The correlation id assigned by the access-log layer, so captured guest logs carry the
    // same id as the request's `boatramp::access` line.
    let request_id = request
        .extensions()
        .get::<crate::RequestId>()
        .map(|r| r.0.clone());
    // Stage 0 tenant-source inputs: the request's app bearer (verified downstream for a token
    // source) and the routed domain's context tag (for a domain source), the latter stashed in
    // the request extensions at host routing.
    let bearer = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
        })
        .map(str::to_string);
    let domain_context = request
        .extensions()
        .get::<crate::DomainContext>()
        .map(|c| c.0.clone());
    // R4/D8 5c: a `Tenancy::Target` route with a `handle` source resolves the target tenant from a
    // guest-named PUBLIC slug carried in the `?handle=` query parameter (owned, so we hold no borrow
    // of `request` across the bind). Non-target routes ignore it.
    let target_handle = request
        .uri()
        .query()
        .and_then(|q| query_value(q, "handle"))
        .map(str::to_string);
    // Ask-1: a per-request blob-op timing handle; `build_bindings` wraps the `wasi:blobstore` storage in
    // a `TimingStorage` writing into it, and we snapshot it after `serve_lane` to fold the blob GET/HEAD
    // µs into the phase log (otherwise hidden inside `serve_us`).
    let blob_timing = std::sync::Arc::new(boatramp_storage::BlobOpTiming::default());
    // Ask B-1: split the opaque `bindings_us` into resolve vs binding-build vs messaging-build.
    let bindings_timing = std::sync::Arc::new(BindingsTiming::default());
    let t_bindings = std::time::Instant::now();
    let bindings = match build_bindings(
        inner,
        boatramp_core::project::ProjectRef::new(project),
        site,
        &scope,
        preview,
        &handler.imports,
        site_handlers,
        &handler.env,
        &handler.invoke_targets,
        &handler.stats_topics,
        // Per-component tenant-secret name allowlist (task #493): empty ⇒ deny-all.
        &handler.tenant_secret_names,
        // Per-component blob-upload container allowlist (S3 external ingress): empty ⇒ deny-all.
        &handler.upload_containers,
        // Per-component plain-`wasi:blobstore` container allowlist (host-enforced tenant confinement).
        &handler.blobstore_containers,
        // Per-guest secret allowlist (task #492): empty ⇒ the whole site pool, else only these keys.
        &handler.secrets,
        // A site handler is the entry point of a call chain (reached over HTTP), so it
        // invokes siblings at depth 0; the host caps each subsequent hop.
        0,
        request_id.as_deref(),
        bearer.as_deref(),
        domain_context.as_deref(),
        session_cookie.as_deref(),
        target_handle.as_deref(),
        handler.tenancy.as_ref(),
        handler.token_claims.as_ref(),
        // Synchronous request lane — no durable signed-context envelope.
        None,
        // The request/handler lane never fires as system (that is only a cron `run_as: deployer`).
        false,
        // Ask-1: time this request's blob reads (get / head / get_range) for the phase log.
        Some(blob_timing.clone()),
        // Ask B-1: record the resolve / messaging-build sub-phase µs for the phase log.
        Some(bindings_timing.clone()),
    )
    .await
    {
        Ok(bindings) => bindings,
        // A required managed database is still starting — gate this route with a retryable 503 +
        // Retry-After so the client / a migration probe waits, instead of running the guest into a
        // confusing "not granted" (the managed-dependency readiness gate). Fail-closed.
        Err(BindingsError::NotReady {
            detail,
            retry_after_secs,
        }) => {
            tracing::info!(site, route = %handler.route, %detail, "handler not ready: managed database starting");
            return sql_starting_response(retry_after_secs);
        }
        // A refused secret ref (host-env ref under the multi-tenant posture, or an
        // unsupported scheme) / a tenancy misconfiguration fails the handler closed rather than
        // instantiating it with a leaked or missing value.
        Err(BindingsError::Refused(err)) => {
            tracing::warn!(site, route = %handler.route, %err, "handler bindings refused");
            return handler_unavailable();
        }
    };
    // `bindings_us` = auth (JWKS/bearer verify) + tenancy-resolve + binding construction — there is no
    // standalone auth phase on the plain path; it all happens inside `build_bindings`.
    let bindings_us = t_bindings.elapsed().as_micros() as u64;

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
                .into_response();
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
    // A streaming handler runs on the isolated streaming lane (its own concurrency budget + a
    // much larger wall-clock), so a long-lived SSE/token stream never holds a fast-request slot;
    // a buffered handler stays on the tight sync request lane.
    // A streaming handler runs on the isolated streaming lane; a buffered one on the tight sync
    // request lane. One `serve_lane` call returns the per-serve `ServeTiming` for the
    // cold/instantiate_ms signal.
    let lane = if handler.streaming {
        boatramp_handlers::Lane::Streaming
    } else {
        boatramp_handlers::Lane::Sync
    };
    let timed = inner
        .engine
        .serve_lane(&entry.hash, &wasm, request, bindings, limits, lane)
        .await;
    let (result, cold, instantiate_ms, instantiate_us) = match timed {
        Ok((response, t)) => (
            Ok(response),
            Some(t.cold),
            Some(t.instantiate_us / 1_000),
            Some(t.instantiate_us),
        ),
        Err(err) => (Err(err), None, None, None),
    };
    // `serve_us` = time-to-head (the existing `duration_ms` metric, captured once and reused — the metric
    // is unchanged). The blob GET lives INSIDE this: the guest buffers the object before producing the head.
    let serve_elapsed = start.elapsed();
    inner.metrics.observe(
        site,
        metrics::Trigger::Http,
        &handler.route,
        &entry.hash,
        metrics::Outcome::from_result(&result),
        serve_elapsed,
        cold,
        instantiate_ms,
    );
    // `body_us` = response assembly (into_parts + the optional edge-cache store, which awaits a KV write
    // OUTSIDE time-to-head, + the Set-Cookie append) — NOT client transfer, which streams after return.
    let t_body = std::time::Instant::now();
    let mut response = match result {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            let response = axum::http::Response::from_parts(parts, axum::body::Body::new(body));
            // Cache the response if the site opted in and the response is cacheable.
            // On a non-cacheable request/response this returns it untouched, so
            // streaming is preserved.
            match &cache_write {
                Some((cfg, key, method, req_headers)) => {
                    handler_cache::maybe_store(
                        inner.kv.clone(),
                        cfg,
                        key,
                        method,
                        req_headers,
                        response,
                        handler_cache::now_secs(),
                    )
                    .await
                }
                None => response,
            }
        }
        Err(err) => {
            tracing::warn!(site, route = %handler.route, %err, "handler invocation failed");
            handler_error_response(&err)
        }
    };
    // Issue a freshly-minted R3 session cookie (added last so it lands on the guest's own response;
    // never cached — it is a per-visitor identity). Only present on a first anonymous request.
    if let Some(set_cookie) = set_session_cookie
        && let Ok(value) = axum::http::HeaderValue::from_str(&set_cookie)
    {
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, value);
    }
    let body_us = t_body.elapsed().as_micros() as u64;
    let cold = cold.unwrap_or(false);
    let instantiate_us = instantiate_us.unwrap_or(0);
    let serve_us = serve_elapsed.as_micros() as u64;
    let total_us = dispatch_start.elapsed().as_micros() as u64;
    // Blob read-op timings for THIS request, from the `TimingStorage` wrapping the `wasi:blobstore`
    // binding — the object GET + the container-marker HEAD that otherwise hide inside `serve_us`.
    // All-zero on a route with no blobstore binding. Separating `head_us` from `get_us`/`range_us` is
    // the Ask-3 signal (the per-serve marker check vs the object read); `blob_ops` counts the read ops.
    let (blob_get_us, blob_head_us, blob_range_us, blob_ops) = blob_timing.snapshot();
    // Ask B-1: split the opaque `bindings_us` so a ~multi-second bindings phase can be localized.
    // `resolve_us` = auth (token verify) + in-site tenancy-resolve + the per-table tenancy-schema KV
    // load; `binding_build_us` = the remainder (every `.with_*` construction, incl. messaging); and
    // `messaging_build_us` (⊆ binding_build) isolates the one binding that does per-request async work
    // (`mint_producer_context`). Together they answer "is the cost auth/tenancy, or a binding build?".
    let (resolve_us, messaging_build_us, blobstore_build_us) = bindings_timing.snapshot();
    let binding_build_us = bindings_us.saturating_sub(resolve_us);
    // Ask B-2: the part of `binding_build_us` NOT in the blobstore build nor the messaging mint. For a
    // route whose only post-resolve bindings are blobstore+messaging (e.g. the console `/img` leg), a
    // large `bindgap` with small `blobstore_build_us`/`messaging_build_us` means the multi-second cost
    // is dispatch-task scheduling PARK between operations (the runtime can't re-poll this task under a
    // burst), NOT any single call — exactly the distinction the earlier opaque number couldn't make.
    let bind_gap_us = binding_build_us
        .saturating_sub(messaging_build_us)
        .saturating_sub(blobstore_build_us);
    // One structured line per plain handler request: where the host-side time went — session / component
    // blob (cold only) / bindings (auth + tenancy + binding build, now sub-split) / instantiate /
    // serve-to-head / body assembly, plus the blob read ops — so a per-request cost is attributable from
    // the log alone (the Ask-1 observability). `total_us` is the true plain-path wall-clock; a gap vs the
    // phase sum is the un-instrumented warm-check / edge-cache lookup / header extraction between phases.
    // (The blob GET also counts inside `serve_us`: the guest buffers it before producing the head.)
    tracing::info!(
        target: "boatramp::handler",
        route = %handler.route,
        session_us,
        component_us,
        bindings_us,
        resolve_us,
        binding_build_us,
        messaging_build_us,
        blobstore_build_us,
        bind_gap_us,
        cold,
        instantiate_us,
        serve_us,
        body_us,
        total_us,
        blob_get_us,
        blob_head_us,
        blob_range_us,
        blob_ops,
        "handler request phase timing"
    );
    // Server-Timing (durations in ms, per spec) so the same breakdown is visible to the client / an
    // external probe without the node's logs (mirrors the federated gateway path).
    let server_timing = format!(
        "session;dur={:.1}, component;dur={:.1}, bindings;dur={:.1}, resolve;dur={:.1}, bindingbuild;dur={:.1}, blobbuild;dur={:.1}, msgbuild;dur={:.1}, bindgap;dur={:.1}, instantiate;dur={:.1}, serve;dur={:.1}, body;dur={:.1}, blob;dur={:.1}",
        session_us as f64 / 1000.0,
        component_us as f64 / 1000.0,
        bindings_us as f64 / 1000.0,
        resolve_us as f64 / 1000.0,
        binding_build_us as f64 / 1000.0,
        blobstore_build_us as f64 / 1000.0,
        messaging_build_us as f64 / 1000.0,
        bind_gap_us as f64 / 1000.0,
        instantiate_us as f64 / 1000.0,
        serve_us as f64 / 1000.0,
        body_us as f64 / 1000.0,
        (blob_get_us + blob_head_us + blob_range_us) as f64 / 1000.0,
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&server_timing) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("server-timing"),
            value,
        );
    }
    response
}

/// The federation gateway: load the project's composed supergraph, plan `query` against
/// it, execute the plan by dispatching each fetch to its subgraph function over the
/// in-process invoke path, and return the stitched `{ "data": … }` response.
#[cfg(feature = "handlers")]
/// Resolve the caller's OWN-axis principal (axis-tagged `ScopeFact`s) for the federated `/graphql`
/// gateway, symmetric to the `handler_caller_tenant` a normal handler resolves and already
/// propagates on the in-process `graphql::run` path (v0.4.6). The gateway fans out to wasm subgraphs
/// whose host-forced `own` reads no longer self-scope (post-P48), so they depend on this principal;
/// propagating an EMPTY set (the pre-v0.4.11 `Vec::new()`) fail-closed EVERY federated `own` read.
///
/// A SQL subgraph ignores these facts (its GDC `row_filter` binds the forwarded bearer); a `target`
/// fetch resolves `B` per-fetch (`with_target_inputs`), independent of this own principal — so this
/// changes only the own-axis wasm path.
///
/// Fail-closed is preserved: an anonymous caller (no verifiable bearer, no resolvable source)
/// resolves no facts, so a wasm `own` fetch still refuses — the gateway never widens anon access.
#[cfg(feature = "handlers")]
async fn resolve_gateway_caller_facts(
    inner: &HandlerRuntimeInner,
    project: &str,
    handler: &boatramp_core::config::HandlerConfig,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    bearer: Option<&str>,
    domain_context: Option<&str>,
) -> std::result::Result<(Vec<boatramp_handlers::ScopeFact>, bool), Response> {
    // The effective in-site tenancy for the `/graphql` route: the per-handler decision when it
    // narrows within the site ceiling (a widening is refused fail-closed), else the site decision.
    let effective = match handler.tenancy.as_ref() {
        Some(h) => {
            if let Some(ceiling) = site_handlers.tenancy.as_ref() {
                // A per-route widening is refused unless BOTH the site enables exceptions
                // (`allow_ceiling_exceptions`, key 1) AND the route carries `exceed_site_ceiling`
                // (key 2). The runtime clamp on `all` (key 3, the operator posture) stays separate.
                // This is the fail-closed backstop; the deploy validator produces the speaking error.
                if !h.narrows_within_authorized(ceiling, site_handlers.allow_ceiling_exceptions) {
                    return Err(graphql_guard::error_response(
                        "tenancy: the /graphql handler declares a tenancy that widens the site \
                         ceiling (authorize it with `exceed_site_ceiling: true` on the route AND \
                         `allow_ceiling_exceptions = true` on the site, or narrow the tenancy)",
                    ));
                }
            }
            Some(h)
        }
        None => site_handlers.tenancy.as_ref(),
    };
    // A `target`-class route tenancy is resolved PER FETCH by the gateway (`with_target_inputs`), not
    // as a caller own principal — so the own facts are empty here (any own fetch then fail-closes,
    // which is correct: a target route names no own tenant).
    if matches!(
        effective,
        Some(boatramp_core::tenancy::Tenancy::Target { .. })
    ) {
        return Ok((Vec::new(), false));
    }
    let knobs = inner.project_tenancy_knobs(project);
    let posture = crate::tenant_resolve::TenantPosture {
        require_declaration: knobs.require_tenancy_declaration,
        allow_cross_tenant: knobs.allow_cross_tenant_db,
    };
    // The `token` source's JWKS/issuer config: the per-handler `token_claims` wins over the site's
    // `[handlers.graphql.data].claims_from_token`.
    let token_cfg = handler.token_claims.as_ref().or_else(|| {
        site_handlers
            .graphql
            .as_ref()
            .and_then(|g| g.data.as_ref())
            .and_then(|d| d.claims_from_token.as_ref())
    });
    let session_anchor = inner.session_signer.get().map(|s| s.public_key());
    // The per-table tenancy schema (fail-closed to deny-all if unreadable), attached to the resolved
    // principal so a per-table-keyed subgraph read scopes on its own key.
    let schema = match boatramp_core::deploy::load_project_tenancy(
        inner.kv.as_ref(),
        boatramp_core::project::ProjectRef::new(project),
    )
    .await
    {
        Ok(s) => s,
        Err(_) => Some(boatramp_core::tenancy::TenancySchema::deny_all()),
    };
    let inputs = crate::tenant_resolve::TenantSourceInputs {
        bearer,
        domain_context,
        token_cfg,
        // The gateway resolves the token/own (and domain) axis; a cookie-auth caller already had its
        // cookie injected as the bearer upstream. An R3 anonymous-session principal is out of scope
        // for the federated gateway and fail-closes here — never widened.
        session_cookie: None,
        session_anchor: session_anchor.as_ref(),
        signed_context: None,
        context_anchor: None,
        env_source: Some(inner.env_source()),
    };
    // `imports_db = false`: the gateway component itself runs no `orm`/`sql` (it fans out); the
    // "undeclared tenancy refused under strict posture" check applies to a handler that DIRECTLY
    // queries. An undeclared gateway tenancy therefore yields no own facts (own fetches fail-closed),
    // never a hard refusal of the whole query.
    let resolved = crate::tenant_resolve::resolve_host_tenancy(effective, false, posture, inputs)
        .await
        .map_err(|_| {
            graphql_guard::error_response(
                "tenancy: the /graphql route requires a tenancy declaration under this project's posture",
            )
        })?
        .map(|h| h.with_schema(schema.as_ref()));
    // Carry BOTH the resolved caller own-facts AND the gateway-level `on_unresolved: "pass"` flag.
    // An unresolved caller under a gateway `pass` yields EMPTY own facts (never widened), but the
    // flag lets a subgraph's OWN read confine to zero rows (`1 = 0`) instead of fail-closing —
    // matching the direct-funnel pass. `pass_unresolved` is read-axis-only and inert the moment a
    // principal resolves (facts non-empty); writes always deny. So the worst case is read-deny →
    // zero-rows, never a widening.
    let caller_pass = resolved
        .as_ref()
        .is_some_and(boatramp_handlers::HostTenancy::pass_unresolved);
    let facts = resolved.map(|h| h.facts().to_vec()).unwrap_or_default();
    Ok((facts, caller_pass))
}

#[allow(clippy::too_many_arguments)] // host-trusted inputs threaded from dispatch; grouping them into a struct would only obscure the plumbing
async fn federation_gateway(
    inner: &HandlerRuntimeInner,
    project: &str,
    query: &str,
    variables: &serde_json::Value,
    bearer: Option<&str>,
    domain_context: Option<&str>,
    target_handle: Option<&str>,
    caller_own: Vec<boatramp_handlers::ScopeFact>,
    // Gateway-level `on_unresolved: "pass"`: when the caller is unresolved (empty `caller_own`) and
    // the /graphql route opts into pass, a subgraph's OWN read confines to zero rows instead of
    // fail-closing. Inert once `caller_own` is non-empty; never widens.
    caller_pass: bool,
    // #495: the site's edge-visibility manifest — `"subgraph.field"` per-operation excludes and
    // per-subgraph excludes. Resolved fresh per request against the supergraph (union-only, unknown
    // entries ignored+warned) so a change takes effect immediately with no recomposition lag.
    edge_hidden_operations: &[String],
    edge_hidden_subgraphs: &[String],
    // Micros spent in the auth phase (token verify + any JWKS fetch) at the call site — folded into
    // the per-phase timing (structured log + `Server-Timing`) so the JWKS cost is visible.
    auth_us: u64,
) -> Response {
    // Compose + plan, memoized per project by composition version (and the operation hash for
    // the plan) — the same `graphql_cache` the in-process `graphql::run` path uses, so neither
    // path re-lists/re-parses/re-plans a graph that only changes on deploy.
    let t_compose = std::time::Instant::now();
    let cached = match inner
        .graphql_cache
        .supergraph(inner.kv.as_ref(), project)
        .await
    {
        Ok(c) => c,
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("supergraph composition failed: {err}\n"),
            )
                .into_response();
        }
    };
    // Warm: a cache hit (version match) — just the version `kv.get`, not a recompose.
    let compose_us = t_compose.elapsed().as_micros() as u64;
    let op_hash = crate::graphql_apq::sha256_hex(query);
    // #495: the EFFECTIVE hidden set for the external edge =
    //   supergraph.edge_hidden_roots  ∪  resolve(edge_hidden_operations)  ∪  roots_owned_by(edge_hidden_subgraphs).
    // Union-only (can never widen the surface); unknown manifest entries are ignored + logged. Then
    // emit a server-side trace for each root this operation names that IS hidden (exists-but-hidden),
    // distinct from a truly-unknown field — NEVER surfaced to the client (no oracle).
    let effective_hidden = resolve_effective_hidden(
        &cached.supergraph,
        edge_hidden_operations,
        edge_hidden_subgraphs,
    );
    log_hidden_root_decisions(query, &effective_hidden, &op_hash);
    let t_plan = std::time::Instant::now();
    let plan = match inner.graphql_cache.plan(
        project,
        cached.version,
        &op_hash,
        query,
        &cached.supergraph,
        crate::graphql_cache::Visibility::External(&effective_hidden),
    ) {
        Ok(plan) => plan,
        Err(_) => {
            return graphql_guard::error_response(
                "the query cannot be planned against the supergraph",
            );
        }
    };
    // Warm: a per-(op,version,visibility) plan-cache hit — pure-CPU on a miss, no I/O either way.
    let plan_us = t_plan.elapsed().as_micros() as u64;
    let Some(invoker) = inner.invoker.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "federation gateway: no invoker configured\n",
        )
            .into_response();
    };
    // Route each fetch to its subgraph's backend: a SQL-backed subgraph resolves via the
    // data connector, a function subgraph via the invoke path. This is where a GraphQL→SQL
    // subgraph and a GraphQL→Wasi subgraph compose in one supergraph.
    let sql_subgraphs = (*cached.sql_subgraphs).clone();
    let mut runner = crate::graphql_gateway::BackendRouter::new(
        // v0.4.11: propagate the caller's resolved OWN principal to every wasm subgraph fetch,
        // symmetric to the in-process `graphql::run` path. A post-P48 wasm subgraph's `own` read is
        // host-forced and no longer self-scopes, so it needs this principal; the pre-v0.4.11 empty
        // set (`Vec::new()`) fail-closed every federated `own` read. A SQL subgraph ignores it (its
        // GDC `row_filter` binds the forwarded bearer); a `target` fetch resolves `B` per-fetch. An
        // anonymous caller resolves no facts, so an `own` fetch still refuses (anon is not widened).
        // The external `/graphql` edge is the SYNC lane (a bearer request, no `signed_context` seal),
        // so no sealed principal rides — `sealed-principal()` returns `none` here (PLAN-async-persona).
        invoker.scoped_with_pass(
            boatramp_core::project::ProjectRef::new(project),
            caller_own,
            None,
            caller_pass,
        ),
        project.to_string(),
        inner.sql.clone(),
        sql_subgraphs,
        bearer.map(str::to_string),
    )
    .with_env_source(inner.env_source_arc());
    // R4/D8: when the plan has any `target`-class fetch, (1) enforce the operator ceiling — every
    // target root field this query uses must be listed in the project's `target_eligible_fields`,
    // else refuse (the app's SDL alone can never make a field cross to another tenant) — and (2)
    // bind the host-trusted inputs the router uses to resolve each fetch's `B` per fetch from that
    // fetch's own `@tenant(via, public, write)`, over the full source model (domain/capability/handle,
    // Gap 1 — SQL *and* wasm subgraphs). The schema is loaded FRESH here (not the cached supergraph),
    // so removing a field's eligibility takes effect immediately. No project schema ⇒ no target inputs
    // ⇒ every target fetch fails closed.
    if plan.fetches.iter().any(|f| f.class.is_target()) {
        let schema = boatramp_core::deploy::load_project_tenancy(
            inner.kv.as_ref(),
            boatramp_core::project::ProjectRef::new(project),
        )
        .await
        .ok()
        .flatten();
        for field in crate::graphql_gateway::target_root_fields(query, &cached.supergraph) {
            let eligible = schema
                .as_ref()
                .is_some_and(|s| s.target_field_eligible(&field));
            if !eligible {
                return graphql_guard::error_response(&format!(
                    "field `{field}` is not an operator-permitted target-tenant field \
                     (add it to the project's target_eligible_fields)"
                ));
            }
        }
        if let Some(schema) = schema {
            // The fleet anchor that verifies a `capability` source (the session signer's public half),
            // exactly as the plain-wasm target route uses.
            let capability_anchor = inner.session_signer.get().map(|s| s.public_key());
            runner = runner.with_target_inputs(Some(crate::graphql_gateway::TargetInputs {
                schema: std::sync::Arc::new(schema),
                domain_context: domain_context.map(str::to_string),
                target_handle: target_handle.map(str::to_string),
                capability_anchor,
            }));
        }
    }
    let t_fanout = std::time::Instant::now();
    let result = crate::graphql_gateway::execute(&plan, &runner, variables).await;
    let fanout_us = t_fanout.elapsed().as_micros() as u64;
    let total_us = auth_us + compose_us + plan_us + fanout_us;
    // One structured line per federated request: where the gateway's time actually went (auth incl.
    // any JWKS fetch / compose / plan / subgraph fan-out), so a regression is attributable from the
    // log alone (this is how the ~1 s JWKS overhead was localized).
    tracing::info!(
        target: "boatramp::gateway",
        op_hash = %op_hash,
        auth_us,
        compose_us,
        plan_us,
        fanout_us,
        total_us,
        "graphql federated request phase timing"
    );
    let mut response = axum::Json(result).into_response();
    // Server-Timing (per the spec, durations in ms) so the same breakdown is visible to the client /
    // an external probe without reading the node's logs.
    let server_timing = format!(
        "auth;dur={:.1}, compose;dur={:.1}, plan;dur={:.1}, fanout;dur={:.1}",
        auth_us as f64 / 1000.0,
        compose_us as f64 / 1000.0,
        plan_us as f64 / 1000.0,
        fanout_us as f64 / 1000.0,
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&server_timing) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("server-timing"),
            value,
        );
    }
    response
}

/// Build the external edge's effective edge-hidden root set (#495) from the three sources, as a
/// **canonical resolved** `BTreeSet<(root_type, field)>`:
///
/// 1. `supergraph.edge_hidden_roots` — the `@edgeHidden` directive roots (travel with the code).
/// 2. `edge_hidden_operations` — each **qualified** `"subgraph.field"` resolved against the
///    supergraph's `root_query`/`root_mutation` (the named field must exist AND be owned by the
///    named subgraph). A **bare** (unqualified) entry is rejected+warned (UX-C3a); an entry naming
///    a non-existent / wrong-owner root is ignored+warned (UX-C3b).
/// 3. `edge_hidden_subgraphs` — every root field OWNED by a listed subgraph (root-only; entity-field
///    jumps to shared types are NOT covered — that's the resolver's authz). A subgraph that owns no
///    root field is ignored+warned.
///
/// The result is **union-only** — a manifest entry can only ever ADD to the hidden set, never widen
/// the surface. It is the exact set both hashed into the plan-cache key and threaded into the
/// planner, so key and plan agree.
fn resolve_effective_hidden(
    sg: &crate::graphql_federation::Supergraph,
    edge_hidden_operations: &[String],
    edge_hidden_subgraphs: &[String],
) -> std::collections::BTreeSet<(String, String)> {
    let mut hidden = sg.edge_hidden_roots.clone();

    // Source 2 — qualified per-operation excludes.
    for entry in edge_hidden_operations {
        let Some((subgraph, field)) = entry.split_once('.') else {
            tracing::warn!(
                entry = %entry,
                "graphql edge_hidden_operations: entry is not qualified `subgraph.field` — ignored \
                 (a bare field name is ambiguous across subgraphs; qualify it)"
            );
            continue;
        };
        if subgraph.is_empty() || field.is_empty() {
            tracing::warn!(
                entry = %entry,
                "graphql edge_hidden_operations: entry has an empty subgraph or field — ignored"
            );
            continue;
        }
        // The field must exist as a root AND be owned by the named subgraph (on either root type).
        let mut matched = false;
        for (root_type, roots) in [("Query", &sg.root_query), ("Mutation", &sg.root_mutation)] {
            if roots.get(field).is_some_and(|owner| owner == subgraph) {
                hidden.insert((root_type.to_string(), field.to_string()));
                matched = true;
            }
        }
        if !matched {
            tracing::warn!(
                entry = %entry,
                "graphql edge_hidden_operations: no root Query/Mutation field `{field}` owned by \
                 subgraph `{subgraph}` — ignored (never widens; the op may not exist yet)"
            );
        }
    }

    // Source 3 — per-subgraph excludes (all roots owned by the subgraph).
    for subgraph in edge_hidden_subgraphs {
        let mut owned_any = false;
        for (root_type, roots) in [("Query", &sg.root_query), ("Mutation", &sg.root_mutation)] {
            for (field, owner) in roots {
                if owner == subgraph {
                    hidden.insert((root_type.to_string(), field.to_string()));
                    owned_any = true;
                }
            }
        }
        if !owned_any {
            tracing::warn!(
                subgraph = %subgraph,
                "graphql edge_hidden_subgraphs: subgraph owns no root Query/Mutation field — \
                 ignored (root-only; entity-field jumps are the resolver's authz)"
            );
        }
    }

    hidden
}

/// Emit a server-side trace for each ROOT field this external operation names that IS in the
/// effective hidden set (#495, UX-C5) — an "exists-but-hidden" decision, distinct from a
/// truly-unknown field. This is observability for the operator ONLY; the client still receives the
/// generic `UnknownRootField` → "cannot be planned" outcome, byte-identical to an unknown field, so
/// the trace can NEVER become an oracle. Routes through the shared fragment-expanding helper so a
/// fragment-wrapped hidden root is logged too.
fn log_hidden_root_decisions(
    query: &str,
    effective_hidden: &std::collections::BTreeSet<(String, String)>,
    op_hash: &str,
) {
    if effective_hidden.is_empty() {
        return;
    }
    let Ok(doc) = async_graphql_parser::parse_query(query) else {
        return;
    };
    let fragments = crate::graphql_root_fields::document_fragments(&doc);
    let ops = match &doc.operations {
        async_graphql_parser::types::DocumentOperations::Single(op) => vec![&op.node],
        async_graphql_parser::types::DocumentOperations::Multiple(m) => {
            m.values().map(|o| &o.node).collect()
        }
    };
    for op in ops {
        for (root_type, field) in crate::graphql_root_fields::expanded_root_fields(op, &fragments) {
            let pair = (root_type.type_name().to_string(), field.clone());
            if effective_hidden.contains(&pair) {
                tracing::info!(
                    root_type = root_type.type_name(),
                    field = %field,
                    op_hash = %op_hash,
                    "graphql edge: refused a hidden root field on the external /graphql edge \
                     (planned as unknown — no client oracle)"
                );
            }
        }
    }
}

/// Whether the external federated edge must REFUSE to stream this subscription (#495): its root
/// field is edge-hidden (or otherwise not an edge-visible operation). Resolved through the SAME
/// effective-hidden set the planner uses, so a subscription can't be an escape hatch around a
/// hidden operation. Returns `false` (stream normally) on any resolution failure that isn't a hit —
/// the planner remains the hard gate for query/mutation, and a non-hidden subscription is served.
///
/// A subscription's root is not a federation-planned root (`plan` returns `Unsupported`), so
/// "hidden" here means the root **field name** matches a hidden `(Query|Mutation, field)` pair OR a
/// `(Subscription, field)` pair — a same-named operation marked edge-hidden implies its subscription
/// counterpart is edge-internal too (fail-closed). Routes the subscription's root through the shared
/// fragment-expanding helper so a fragment-wrapped root is caught.
async fn subscription_root_is_hidden(
    inner: &HandlerRuntimeInner,
    project: &str,
    query: &str,
    edge_hidden_operations: &[String],
    edge_hidden_subgraphs: &[String],
) -> bool {
    // Load the composed supergraph (cached by version). On a composition error, don't special-case
    // the subscription — let the normal path proceed (the planner/edge stays the authority).
    let Ok(cached) = inner
        .graphql_cache
        .supergraph(inner.kv.as_ref(), project)
        .await
    else {
        return false;
    };
    let effective_hidden = resolve_effective_hidden(
        &cached.supergraph,
        edge_hidden_operations,
        edge_hidden_subgraphs,
    );
    if effective_hidden.is_empty() {
        // Nothing is edge-hidden on this site ⇒ no hidden name to distinguish ⇒ no oracle; stream as
        // before. (A compose error above also returns here — during an outage every subscription
        // streams uniformly, so there is still no oracle.)
        return false;
    }
    let hidden_names: std::collections::BTreeSet<&str> =
        effective_hidden.iter().map(|(_, f)| f.as_str()).collect();
    // The edge-VISIBLE root field names. A federated bus subscription's topic mirrors a Query/Mutation
    // root a producer publishes to, so we stream ONLY when the subscription's root is a known,
    // edge-visible root. A root that is edge-hidden OR simply unknown is refused IDENTICALLY (falls
    // through to the generic "cannot be planned" outcome) — so a hidden op is byte-indistinguishable
    // from an unknown one on the subscription axis. Closes the C1 existence oracle: previously a direct
    // `subscription { unknownField }` streamed while `subscription { hiddenOp }` errored.
    let visible_roots: std::collections::BTreeSet<&str> = cached
        .supergraph
        .root_query
        .keys()
        .chain(cached.supergraph.root_mutation.keys())
        .map(String::as_str)
        .filter(|f| !hidden_names.contains(f))
        .collect();
    let Ok(doc) = async_graphql_parser::parse_query(query) else {
        return false;
    };
    let fragments = crate::graphql_root_fields::document_fragments(&doc);
    let ops = match &doc.operations {
        async_graphql_parser::types::DocumentOperations::Single(op) => vec![&op.node],
        async_graphql_parser::types::DocumentOperations::Multiple(m) => {
            m.values().map(|o| &o.node).collect()
        }
    };
    for op in ops {
        if op.ty != async_graphql_parser::types::OperationType::Subscription {
            continue;
        }
        for (_, field) in crate::graphql_root_fields::expanded_root_fields(op, &fragments) {
            if !visible_roots.contains(field.as_str()) {
                tracing::info!(
                    field = %field,
                    "graphql edge: refused a non-edge-visible root on an external /graphql subscription \
                     (edge-hidden OR unknown — not streamed; identical outcome, no client oracle)"
                );
                return true;
            }
        }
    }
    false
}

/// The declarative data connector: serve a GraphQL query from the site's managed database.
/// Resolve the site's SQL backend, introspect it into a schema, build the deny-by-default
/// policy from `[handlers.graphql.data]`, and compile + run the query to SQL — returning the
/// GraphQL response. The backend is opened with the same project/site scoping handlers use,
/// so tenant isolation is inherited; the policy's row filter binds the host-asserted
/// `project` claim, plus any claims from a verified app bearer token (`bearer`) when the site
/// configures `claims_from_token`.
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)] // host-trusted inputs threaded from dispatch; a params struct would only obscure the plumbing
async fn data_connector_serve(
    inner: &HandlerRuntimeInner,
    project: &str,
    site: &str,
    cfg: &boatramp_core::config::HandlerGraphqlDataConfig,
    query: &str,
    variables: &serde_json::Value,
    bearer: Option<&str>,
    caller_own: Vec<boatramp_handlers::ScopeFact>,
    // Gateway-level `on_unresolved: "pass"` (see `federation_gateway`): an unresolved caller's
    // delegated `own` fetch confines to zero rows instead of fail-closing. Inert once resolved.
    caller_pass: bool,
) -> Response {
    let Some(provider) = &inner.sql else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "graphql data connector: this server has no SQL backend configured\n",
        )
            .into_response();
    };
    let backend = match provider.database(project, site, &cfg.source).await {
        Ok(backend) => backend,
        Err(err) => {
            tracing::warn!(site, %err, "graphql data connector: opening the database failed");
            return (
                StatusCode::BAD_GATEWAY,
                "graphql data connector: database unavailable\n",
            )
                .into_response();
        }
    };
    let schema = match crate::graphql_data::introspect::introspect_sqlite(backend.as_ref()).await {
        Ok(schema) => schema,
        Err(err) => {
            tracing::warn!(site, %err, "graphql data connector: introspection failed");
            return (
                StatusCode::BAD_GATEWAY,
                "graphql data connector: schema introspection failed\n",
            )
                .into_response();
        }
    };
    // The compiler sees the full introspected schema (for structure — columns, foreign-key
    // relationships, join keys) and the policy enforces exposure per field: deny-by-default,
    // so an unexposed table/column is rejected even though it's structurally present.
    let policy = crate::graphql_data::policy_from_config(cfg);
    let claims =
        crate::graphql_data::request_claims(project, bearer, cfg, inner.env_source()).await;
    let dialect = crate::graphql_data::dialect::Sqlite;
    let response = if crate::graphql_data::compile::is_mutation(query) {
        // A write: gated on the site opting into mutations (deny-by-default), run on a write
        // transaction. Mutations don't delegate, so no invoker is needed.
        if !cfg.mutations {
            serde_json::json!({ "errors": [ { "message": "mutations are not enabled for this endpoint" } ] })
        } else {
            crate::graphql_data::runner::execute_mutation(
                backend.as_ref(),
                &dialect,
                &schema,
                &policy,
                &claims,
                query,
                variables,
            )
            .await
        }
    } else {
        // A delegated field is resolved by a sibling function over the invoke path (scoped to
        // this project); the connector is the root of that call chain (depth 0). v0.4.11: carry the
        // caller's resolved OWN principal so a delegated `own`-scoped wasm resolver inherits it —
        // symmetric to the federation gateway; the pre-v0.4.11 empty set fail-closed every delegated
        // `own` read post-P48. Anon resolves none, so the delegated `own` fetch still refuses.
        let invoker = inner.invoker.get().map(|inv| {
            inv.scoped_with_pass(
                boatramp_core::project::ProjectRef::new(project),
                caller_own.clone(),
                // The GDC edge is the sync request lane (no `signed_context` seal); no sealed principal
                // rides a delegated-field resolution here (PLAN-async-persona).
                None,
                caller_pass,
            )
        });
        crate::graphql_data::runner::execute(
            backend.as_ref(),
            &dialect,
            &schema,
            &policy,
            &claims,
            query,
            variables,
            invoker.as_deref(),
            bearer,
            0, // an external data-connector request is the root of the call chain
            // A direct (non-federated) data-connector endpoint is an OWN read; the target axis is a
            // federation-`@tenant` concern resolved in the gateway.
            None,
        )
        .await
    };
    axum::Json(response).into_response()
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
pub(super) fn set_forwarded_headers(request: &mut Request, client_ip: IpAddr) {
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
/// Extract a raw query-parameter value from a `key=value&…` query string (no URL-decoding — a slug
/// is simple; a value carrying escapes simply won't match the registry and fails closed).
fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then_some(v)
    })
}

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
pub(super) async fn precheck_component(
    deploy: &DeployStore,
    manifest: &Manifest,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    inner: &HandlerRuntimeInner,
    max_component: u64,
    imports: &[String],
    component: &str,
    label: &str,
    // `true` validates against the **consumer** world (`messaging-handler`),
    // `false` against the request-handler (`wasi:http/proxy`) world. A `consumers`
    // entry pointing at a non-consumer component must fail here, not silently at
    // drain.
    is_consumer: bool,
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
        // `email` needs a delivery spool; unset means the operator's
        // `allow_guest_email` posture disabled guest email (or none was wired). Fail
        // at activation with a clear message rather than deploying a handler whose
        // every `send` would return `access-denied`.
        #[cfg(feature = "email")]
        if import == "email" && inner.email_spool.get().is_none() {
            return Err(format!(
                "{label} requests `email` but this server does not offer guest email \
                 (no SMTP spool configured, or the `allow_guest_email` posture is off)"
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
    // A consumer must instantiate the **consumer** world (`messaging-handler`);
    // a handler the request world. Validating a consumer as an http handler was
    // the bug that let a non-consumer pass the gate and then under-deliver
    // silently. `handlers` always compiles in `boatramp-handlers/messaging`, so
    // `precompile_consumer` is always available here.
    // Through the compile-concurrency gate (#2) so a many-component activation doesn't spike RSS.
    if is_consumer {
        inner
            .engine
            .precompile_consumer_gated(&entry.hash, &wasm)
            .await
            .map_err(|err| {
                let e = err.to_string();
                translate_link_error(label, &e).unwrap_or_else(|| {
                    format!("{label} is not a valid wasi:messaging consumer: {e}")
                })
            })?;
    } else {
        inner
            .engine
            .precompile_gated(&entry.hash, &wasm)
            .await
            .map_err(|err| {
                let e = err.to_string();
                translate_link_error(label, &e)
                    .unwrap_or_else(|| format!("{label} failed to compile: {e}"))
            })?;
    }
    Ok(())
}

/// Turn wasmtime's opaque "a matching implementation was not found in the linker" into an
/// actionable capability message. That error means the component imports a `boatramp:handlers/*`
/// interface (or a shape of it) this host does not provide — the host predates the capability the
/// function targets, or was built without it. Returns `None` for any other error so the caller
/// keeps its own role-appropriate message (consumer vs. handler).
#[cfg(feature = "handlers")]
fn translate_link_error(label: &str, err: &str) -> Option<String> {
    if !err.contains("matching implementation was not found") {
        return None;
    }
    // Pull the imported interface out of "... imports instance `pkg/iface`, but ...".
    let iface = err
        .split_once("imports instance `")
        .and_then(|(_, rest)| rest.split_once('`'))
        .map(|(name, _)| name)
        .unwrap_or("a boatramp:handlers capability");
    Some(format!(
        "{label} imports `{iface}`, which this host does not provide. The host may predate \
         the capability this function targets, or be built without it — upgrade boatramp, or \
         check `boatramp capabilities` for the interfaces + features this host implements."
    ))
}

/// Read a content-addressed blob fully into memory.
#[cfg(feature = "handlers")]
pub(super) async fn read_blob_bytes(
    deploy: &DeployStore,
    hash: &str,
) -> Result<Vec<u8>, DeployError> {
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
pub(super) async fn read_blob_fully(deploy: &DeployStore, hash: &str) -> Result<Vec<u8>, Response> {
    read_blob_bytes(deploy, hash)
        .await
        .map_err(deploy_error_response)
}

/// What browser cookie session auth does with a request.
enum CookieAuthOutcome {
    /// Not cookie-authenticated (no config, an `Authorization` header is present, or the cookie
    /// is absent) — proceed unchanged.
    None,
    /// Authenticate from the cookie: inject this value as the bearer.
    Inject(String),
    /// A cookie-authenticated request from a disallowed origin — reject it (CSRF).
    Reject,
}

/// Decide browser cookie session auth for a request: use the configured cookie's value as the
/// bearer **only** when the site opts in, no `Authorization` header is present (the header always
/// wins), and the cookie is set — and only after the CSRF origin check passes. Pure over the
/// request headers + config, so the precedence/CSRF policy is unit-tested directly.
fn cookie_auth_outcome(
    headers: &HeaderMap,
    cookie_auth: Option<&boatramp_core::config::CookieAuthConfig>,
) -> CookieAuthOutcome {
    let Some(cookie_auth) = cookie_auth else {
        return CookieAuthOutcome::None;
    };
    // The Authorization header always wins — an API client is never cookie-authenticated.
    if headers.contains_key(header::AUTHORIZATION) {
        return CookieAuthOutcome::None;
    }
    let Some(token) = cookie_value(headers, &cookie_auth.cookie_name) else {
        return CookieAuthOutcome::None;
    };
    if !origin_allowed(headers, &cookie_auth.allowed_origins) {
        return CookieAuthOutcome::Reject;
    }
    CookieAuthOutcome::Inject(token)
}

/// The value of cookie `name` from the request's `Cookie` header, if present (browser cookie
/// session auth). A trivial `name=value; …` split — no attribute parsing, since the browser
/// sends only name/value pairs on the request.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|pair| {
        let (k, v) = pair.trim().split_once('=')?;
        (k == name).then(|| v.trim().to_string())
    })
}

/// The host-issued anonymous session cookie name (R3, PLAN-tenancy-principal).
const SESSION_COOKIE_NAME: &str = "br_session";
/// The anon-session cookie lifetime (a **long** returning-visitor identity — a privacy/consent
/// ceiling, not a security one, since the disjoint `session_id` column confines it to `tenant IS
/// NULL` rows). 30 days.
const SESSION_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// A random 16-byte session id (hex, OS CSPRNG) — unguessable so the anonymous partition can't be
/// enumerated (the cookie is a bearer for its own `tenant IS NULL` rows). **Fail-closed**: an RNG
/// failure returns `None` (no cookie minted) rather than a predictable/all-zero sid that would
/// collide two visitors' partitions — mirroring the token layer's `random_cti`.
fn new_session_sid() -> Option<String> {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        tracing::error!("getrandom failed generating a session id — not minting a session cookie");
        return None;
    }
    Some(hex::encode(bytes))
}

/// Resolve (or mint) the R3 anonymous session cookie for a request: `.0` is the cookie value to feed
/// the tenancy resolver (the `Session` fact), `.1` is a `Set-Cookie` header value to add to the
/// response when a fresh cookie was minted. Returns `(None, None)` — issuing NO cookie — unless the
/// project declares an R3 `session_key` AND the node wired a session signer (fail-safe: no signer /
/// no R3 ⇒ no anon session axis). A valid incoming cookie is reused (no re-issue); an
/// absent/invalid/expired one is replaced with a fresh CSPRNG cookie. `HttpOnly; Secure;
/// SameSite=Lax`.
#[cfg(feature = "handlers")]
async fn resolve_or_mint_session(
    headers: &HeaderMap,
    inner: &HandlerRuntimeInner,
    project: boatramp_core::project::ProjectRef<'_>,
) -> (Option<String>, Option<String>) {
    let Some(signer) = inner.session_signer.get() else {
        return (None, None); // the node issues no session cookies
    };
    // Only for projects that adopted R3 (declared a session_key) — a small KV read.
    let uses_r3 = matches!(
        boatramp_core::deploy::load_project_tenancy(inner.kv.as_ref(), project).await,
        Ok(Some(schema)) if schema.session_key.is_some()
    );
    if !uses_r3 {
        return (None, None);
    }
    let anchor = signer.public_key();
    let now = boatramp_core::time::now_unix();
    // Reuse a still-valid incoming cookie (its own per-fact lifetime); else mint fresh.
    if let Some(cookie) = cookie_value(headers, SESSION_COOKIE_NAME)
        && boatramp_core::cose::verify_session(&cookie, &anchor, now).is_ok()
    {
        return (Some(cookie), None);
    }
    let Some(sid) = new_session_sid() else {
        return (None, None); // fail-closed on an RNG failure — no cookie rather than a weak one
    };
    match boatramp_core::cose::mint_session(&sid, SESSION_TTL_SECS, now, signer.as_ref()).await {
        Ok(cookie) => {
            let set = format!(
                "{SESSION_COOKIE_NAME}={cookie}; Path=/; Max-Age={SESSION_TTL_SECS}; \
                 HttpOnly; Secure; SameSite=Lax"
            );
            (Some(cookie), Some(set))
        }
        Err(err) => {
            tracing::warn!(%err, "minting an anonymous session cookie failed");
            (None, None)
        }
    }
}

/// The origin (`scheme://host[:port]`) of a `Referer` URL, if parseable (the CSRF fallback when
/// no `Origin` header is present).
fn referer_origin(referer: &str) -> Option<String> {
    let (scheme, rest) = referer.split_once("://")?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|a| !a.is_empty())?;
    Some(format!("{scheme}://{authority}"))
}

/// Whether a cookie-authenticated request's origin is allowed (the CSRF check).
///
/// The request's `Origin` (or, absent that, the origin of `Referer`) passes when it is either:
/// - **same-origin** — its authority equals the request's own `Host` (a page calling its own
///   origin, the SPA's normal case), which is *always* allowed because it is definitionally
///   CSRF-safe: a cross-site attacker's browser sends *their* origin, never the target's `Host`;
///   or
/// - listed in `allowed` — the **additional cross-origin** allowlist for a browser app served
///   from a *different* origin than this API.
///
/// So an empty `allowed` means **same-origin only** (not "non-browser only" — an SPA's own
/// `fetch` carries an `Origin` and must not be rejected). An **absent** Origin *and* Referer —
/// a same-origin top-level navigation or a non-browser client — also passes; the browser's
/// `SameSite=Lax` cookie is the layer that withholds the cookie on a genuine cross-site
/// POST/fetch.
fn origin_allowed(headers: &HeaderMap, allowed: &[String]) -> bool {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| {
            headers
                .get(header::REFERER)
                .and_then(|v| v.to_str().ok())
                .and_then(referer_origin)
        });
    match origin {
        None => true,
        Some(origin) => is_same_origin(headers, &origin) || allowed.iter().any(|a| a == &origin),
    }
}

/// Whether `origin` is the request's **own** origin — its authority (host[:port]) equals the
/// request's `Host` header. Host-based (scheme-agnostic) on purpose: the cookie is `Secure`
/// (https-only) so a same-host http page never carries it, and a proxy may rewrite the scheme —
/// but a cross-site attacker's `Origin` carries a *different host*, so same-host is CSRF-safe.
fn is_same_origin(headers: &HeaderMap, origin: &str) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let origin_authority = origin.split_once("://").map_or(origin, |(_, a)| a);
    !host.is_empty() && origin_authority.eq_ignore_ascii_case(host)
}

/// Grant the per-site bindings the handler requested *and* the site allows
/// (effective imports = deploy ∩ site), served from the runtime's backends.
///
/// `scope` is the binding *identity* — the project-qualified site for live
/// serving (`{site}` for the `default` project, `{project}/{site}` otherwise),
/// or its `.../_preview/{id}` form for a preview — kv/blob/messaging/logs land
/// under it, tenant- and preview-isolated. SQL is resolved against the raw
/// `project` + `site` (the provider qualifies + validates them itself, so it is
/// *not* handed the composite `scope`): for a preview the runtime applies the
/// operator's configured [`PreviewSqlMode`](boatramp_core::sql::PreviewSqlMode)
/// (empty / branch / shared) rather than blindly using the scoped name.
/// The SQL databases a handler may open, resolving the named-binding grant grammar (the
/// security-critical core of least-privilege tenant isolation, pure + unit-tested):
///
/// - `""` (the default database) — granted only when **both** the handler and the site grant the
///   bare `sql` (backward-compatible).
/// - a **named** database — the site's `allow_imports` enumerates the names it exposes
///   (`sql:<name>`); the site is the ceiling. A handler is granted such a name when it requests it
///   explicitly (`sql:<name>`) or via its own `sql:*` wildcard. A handler that asks only for
///   `sql:product` therefore never receives a `privileged` backend, so a single missed
///   WHERE-clause can't reach across tenants. A name the site doesn't expose is never granted,
///   even if the handler requests it (fail-closed). A site-side `sql:*` is not a concrete name —
///   the site must enumerate — so it grants nothing.
#[cfg(feature = "handlers")]
pub(super) fn granted_sql_databases(imports: &[String], allow_imports: &[String]) -> Vec<String> {
    let has = |list: &[String], v: &str| list.iter().any(|i| i == v);
    let mut names: Vec<String> = Vec::new();
    if has(imports, "sql") && has(allow_imports, "sql") {
        names.push(String::new()); // the default database
    }
    let handler_wildcard = has(imports, "sql:*");
    for allowed in allow_imports {
        let Some(name) = allowed.strip_prefix("sql:") else {
            continue;
        };
        if name.is_empty() || name == "*" {
            continue; // `""` is the default; a site must enumerate concrete names, not wildcard
        }
        if handler_wildcard || has(imports, allowed) {
            names.push(name.to_string());
        }
    }
    names
}

#[cfg(feature = "handlers")]
/// Why [`build_bindings`] / [`build_function_bindings`](super::function_runtime::build_function_bindings)
/// could not produce bindings for an invocation.
#[derive(Debug)]
pub(super) enum BindingsError {
    /// A **permanent** refusal — a disallowed `secrets` ref (host-env ref under multi-tenant, an
    /// unsupported scheme), a tenancy misconfiguration, etc. The component cannot run as configured;
    /// rendered as a plain `503 handler unavailable`.
    Refused(String),
    /// A **required host-managed database is not ready yet** (still starting / recovering / no
    /// healthy replica) — [`SqlError::Unavailable`](boatramp_core::sql::SqlError::Unavailable) after
    /// the short readiness retry. Transient: rendered as a retryable `503` + `Retry-After` (the
    /// managed-dependency readiness gate), so a migration/health probe waits instead of the guest
    /// hitting a confusing "not granted". Fail-closed: the guest never runs without its DB.
    NotReady {
        detail: String,
        retry_after_secs: u32,
    },
}

impl std::fmt::Display for BindingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(m) => f.write_str(m),
            Self::NotReady { detail, .. } => write!(f, "managed database not ready: {detail}"),
        }
    }
}
impl std::error::Error for BindingsError {}

// A bare `String` error (e.g. secret-ref resolution) is a permanent refusal — let `?` lift it.
impl From<String> for BindingsError {
    fn from(s: String) -> Self {
        Self::Refused(s)
    }
}

/// `Retry-After` (seconds) advertised on the readiness-gate `503` — how soon a client / migration
/// probe should re-poll while a managed database finishes starting. Small: startup is usually a
/// handful of seconds and the probe is cheap.
pub(super) const SQL_NOT_READY_RETRY_AFTER_SECS: u32 = 2;

/// Open a granted SQL database for an invocation's bindings, applying a **short bounded readiness
/// retry**. A host-managed database that is still starting returns
/// [`SqlError::Unavailable`](boatramp_core::sql::SqlError::Unavailable); a DB that is only a moment
/// from ready is caught by one quick re-attempt, so a brief startup blip does not 503. If it is
/// still not ready, the `Unavailable` error is returned for the caller to turn into the readiness
/// gate (a retryable `503`). Any other error (an external/local DB down or misconfigured) is
/// returned as-is — the caller logs + skips it, preserving per-DB resilience (no gate).
#[cfg(feature = "handlers")]
pub(super) async fn open_bindings_sql(
    provider: &dyn boatramp_core::sql::SqlBackends,
    project: &str,
    site: &str,
    name: &str,
    preview: Option<&str>,
) -> Result<std::sync::Arc<dyn boatramp_core::sql::SqlBackend>, boatramp_core::sql::SqlError> {
    // One extra quick attempt (~250 ms) — enough for a DB moments from ready, short enough not to
    // tie up the handler pool. A DB further out is handled by the client-side `Retry-After` retry.
    const READINESS_RETRIES: usize = 1;
    const READINESS_BACKOFF: Duration = Duration::from_millis(250);
    let mut attempt = 0usize;
    loop {
        let opened = match preview {
            Some(id) => provider.preview_database(project, site, name, id).await,
            None => provider.database(project, site, name).await,
        };
        match opened {
            Err(ref e) if e.is_unavailable() && attempt < READINESS_RETRIES => {
                attempt += 1;
                tokio::time::sleep(READINESS_BACKOFF).await;
            }
            other => return other,
        }
    }
}

/// Ask B-1 observability (image-serve-latency): per-sub-phase µs inside [`build_bindings`], so the
/// otherwise-opaque `bindings_us` phase can be localized. `resolve_us` is auth (token verify) +
/// in-site tenancy-resolve + the per-table tenancy-schema KV load (the big suspect — it makes the
/// managed-DB / KV round-trips construens flagged); `messaging_build_us` is the `wasi:messaging`
/// producer-binding construction, which mints a per-publish signed-context (`mint_producer_context`),
/// the one post-resolution binding that does real per-request async work. The dispatch path derives
/// `binding_build_us = bindings_us − resolve_us` (every non-resolve binding build, messaging
/// included). `None` on the consumer/cron/test paths ⇒ no sub-timing recorded.
#[derive(Default)]
pub(super) struct BindingsTiming {
    resolve_us: std::sync::atomic::AtomicU64,
    messaging_build_us: std::sync::atomic::AtomicU64,
    // Ask B-2: the `wasi:blobstore` binding construction on its own, so the post-resolve
    // `binding_build_us` can be split into blobstore-build vs messaging-build vs an unaccounted
    // remainder (`bindgap`). The source shows the blobstore build is a cheap `Arc` clone + struct
    // build (no I/O / lock / await); if a multi-second `binding_build` shows `blobstore_build_us`
    // small AND `messaging_build_us` small, the cost is the REMAINDER — i.e. dispatch-task scheduling
    // park between operations under a burst, not any single call. That distinction is the whole point.
    blobstore_build_us: std::sync::atomic::AtomicU64,
}

impl BindingsTiming {
    fn set_resolve(&self, us: u64) {
        self.resolve_us
            .store(us, std::sync::atomic::Ordering::Relaxed);
    }
    fn set_messaging_build(&self, us: u64) {
        self.messaging_build_us
            .store(us, std::sync::atomic::Ordering::Relaxed);
    }
    fn set_blobstore_build(&self, us: u64) {
        self.blobstore_build_us
            .store(us, std::sync::atomic::Ordering::Relaxed);
    }
    /// `(resolve_us, messaging_build_us, blobstore_build_us)` as recorded during the build.
    pub(super) fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.resolve_us.load(std::sync::atomic::Ordering::Relaxed),
            self.messaging_build_us
                .load(std::sync::atomic::Ordering::Relaxed),
            self.blobstore_build_us
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

#[allow(clippy::too_many_arguments)] // host-trusted inputs threaded from dispatch; a params struct would only obscure the plumbing
pub(super) async fn build_bindings(
    inner: &HandlerRuntimeInner,
    project: boatramp_core::project::ProjectRef<'_>,
    site: &str,
    scope: &str,
    preview: Option<&str>,
    imports: &[String],
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    deploy_env: &std::collections::BTreeMap<String, String>,
    invoke_targets: &[String],
    // Declared `bus:` stats-topic templates for the read-only `messaging-stats` capability. Each may
    // carry a literal `{tenant}` placeholder the host fills with this invocation's resolved tenant;
    // the guest can never name the tenant. Empty ⇒ no bus stats readable (deny-by-default).
    stats_topics: &[String],
    // Per-component tenant-secret name allowlist (task #493): the secret names this component may
    // address for its resolved tenant via `boatramp:handlers/tenant-secrets`. Empty ⇒ deny-all
    // (least-privilege). Only consulted when a `tenant-secrets:*` right is granted + the substrate
    // (a `[secrets]` envelope) is wired.
    tenant_secret_names: &[String],
    // Per-component container allowlist for the guest `blob-upload` mint capability (S3 external
    // ingress): the blob containers this component may mint an upload credential for. Empty ⇒ deny-all
    // (least-privilege, mirroring `tenant_secret_names`). Only consulted when a `blob-upload:*` right
    // is granted + the local S3 face's minting config is wired.
    upload_containers: &[String],
    // Per-component container allowlist for the PLAIN `wasi:blobstore` capability (host-enforced
    // tenant confinement — SEPARATE from `upload_containers`, no inheritance). `{tenant}`-templated,
    // matched against the container the guest opens; non-empty ⇒ ALWAYS enforced. Empty on a
    // multi-tenant site ⇒ deny-all (fail-closed); empty single-tenant ⇒ permissive. Only consulted
    // when `wasi:blobstore` is granted.
    blobstore_containers: &[String],
    // Per-guest secret allowlist (task #492): the subset of the site `[handlers].secrets` pool KEYS
    // this guest is granted. Empty ⇒ inject the whole pool (default, non-breaking); non-empty ⇒ inject
    // only the named keys (least-privilege). Filtered at the `resolve_env` choke point below.
    secret_allowlist: &[String],
    depth: u32,
    request_id: Option<&str>,
    // Stage 0 tenant-source inputs (the verified bearer for a token source; the routed domain's
    // context tag for a domain source). Background triggers pass `None` for both.
    bearer: Option<&str>,
    domain_context: Option<&str>,
    // R3 session-cookie value from the request (already verified/minted by the caller); the verify
    // anchor is the runtime's own session signer. `None` ⇒ no session fact on this invocation.
    session_cookie: Option<&str>,
    // R4/D8 5c: the PUBLIC handle/slug the request named (from the `?handle=` query param on a
    // `Tenancy::Target` route with a `handle` source), used to resolve `B` against the operator's
    // handle registry — read-only, world-public only. `None` ⇒ no handle named.
    target_handle: Option<&str>,
    // Gap 2: per-handler tenancy override for the matched route. When `Some`, it replaces the
    // site-level decision for THIS invocation — after a fail-closed check that it narrows within
    // the site ceiling (a per-handler value may tighten but never widen `HandlersSiteConfig::tenancy`).
    // `None` ⇒ inherit the site decision (today's behavior).
    handler_tenancy: Option<&boatramp_core::tenancy::Tenancy>,
    // Gap 2: per-handler `token` verification config, overriding the site's `claims_from_token`
    // when this handler's (own or inherited) tenancy names a `token` source. `None` ⇒ inherit.
    handler_token_claims: Option<&boatramp_core::config::HandlerGraphqlTokenClaims>,
    // R1 async lane: the durable `signed_context` envelope carried on a drained message, so a
    // **consumer** declaring `sources: [signed_context]` resolves the producer's sealed tenant
    // (host-verified against the fleet anchor, guest-blind). `None` on every synchronous request/
    // handler path (that lane carries no envelope) — passed per-message by the consumer dispatch.
    signed_context: Option<&str>,
    // PLAN-system-principal P2/P3: fire this invocation as the SYSTEM principal — coerce the resolved
    // (non-target) tenancy to the system class and seal a system `signed_context` on `emit`. Set `true`
    // ONLY by `fire_cron` for a `run_as: deployer` cron whose captured deployer was a System·Admin
    // (the sole provenance-verified system source on this path); `false` on every other call.
    run_as_system: bool,
    // Ask-1 observability (image-serve latency): when `Some`, the `wasi:blobstore` binding's storage is
    // wrapped in a `TimingStorage` decorator recording per-read-op µs into this shared handle, so the
    // blob GET + container-marker HEAD — otherwise hidden inside the guest invoke — are attributable in
    // the `boatramp::handler` phase log. Behavior-frozen (times only; no path/prefix/marker change).
    // `None` on every non-request lane (consumer/cron/test) ⇒ bare storage, identical to before.
    blob_timing: Option<std::sync::Arc<boatramp_storage::BlobOpTiming>>,
    // Ask B-1 observability: when `Some`, the per-sub-phase µs (resolve vs messaging-binding build)
    // are recorded here so the dispatch path can split the opaque `bindings_us`. `None` on every
    // non-request lane ⇒ no sub-timing (identical behavior).
    bindings_timing: Option<std::sync::Arc<BindingsTiming>>,
) -> Result<boatramp_handlers::Bindings, BindingsError> {
    let granted = |name: &str| {
        imports.iter().any(|i| i == name) && site_handlers.allow_imports.iter().any(|a| a == name)
    };
    let mut bindings = boatramp_handlers::Bindings::new(scope);
    if granted("wasi:keyvalue") {
        bindings = bindings.with_keyvalue(scope, inner.kv.clone());
    }
    // NOTE: `wasi:blobstore` is granted AFTER the `handler_caller_tenant` block below, because its
    // host-side tenant confinement needs THIS invocation's resolved OWN tenant + the multi-tenant
    // fact to expand a `{tenant}` allowlist entry / apply the deny-default. Mirrors where the
    // `blob-upload` mint binding is built (also post-resolution).
    if let Some(provider) = &inner.sql {
        // The SQL provider validates + qualifies `project`/`site` internally (it rejects a
        // `/`-bearing composite `site`), so pass the *raw* project + bare site here — never the
        // already-qualified `scope`. A preview routes through `preview_database` so a named external
        // DB honors its `allow_preview`. Two failure classes (WS1/WS2 of the managed-dependency
        // readiness plan): a MANAGED database still starting (`Unavailable`, after a short readiness
        // retry) gates the whole invocation with a retryable 503 — a migration/health probe waits
        // instead of the guest hitting a confusing "not granted". Any OTHER error (external/local DB
        // down or misconfigured) is logged and that binding left ungranted, so one broken secondary
        // can't fail an unrelated request (per-DB resilience is preserved, unchanged).
        for name in granted_sql_databases(imports, &site_handlers.allow_imports) {
            match open_bindings_sql(provider.as_ref(), project.as_str(), site, &name, preview).await
            {
                Ok(backend) => bindings = bindings.with_sql(name.clone(), backend),
                Err(err) if err.is_unavailable() => {
                    tracing::info!(
                        site, database = %name, %err,
                        "required managed database not ready — gating with a retryable 503"
                    );
                    return Err(BindingsError::NotReady {
                        detail: format!("database `{name}`: {err}"),
                        retry_after_secs: SQL_NOT_READY_RETRY_AFTER_SECS,
                    });
                }
                Err(err) => {
                    tracing::warn!(site, database = %name, %err, "opening SQL database failed");
                }
            }
        }
    }
    // Stage 0: resolve the in-site tenant scope for this invocation (applied to BOTH sql + orm).
    // A sql/orm importer that declares no tenancy is refused under the strict posture (Dimension
    // 0); an `all` grant is capped to `own` unless the posture opens cross-tenant access. The
    // resolved value is carried into the `invoke` binding below so a sibling inherits it.
    // Ask B-1: time the resolve block (auth + tenancy-resolve + per-table schema KV load) on its own.
    let t_resolve = std::time::Instant::now();
    let (handler_caller_tenant, handler_caller_kind, handler_caller_pass) = {
        let imports_db = !granted_sql_databases(imports, &site_handlers.allow_imports).is_empty();
        // Security HIGH-1: `wasi:blobstore` carries per-tenant blob assets ⇒ it is a tenant-scoped
        // DATA capability like sql/orm, so a blob-importing handler on a multi-tenant posture must
        // ALSO declare a tenancy decision (Dimension 0) — else it would run permissive and could
        // open another tenant's container. `granted` already encodes "imported AND site-allowed", so
        // this bites exactly when the blob binding is actually grantable.
        let imports_tenant_scoped_data = imports_db || granted("wasi:blobstore");
        // Gap 4a: the tenancy posture for THIS project — the operator's per-project override if any,
        // else the node base. `project` is host-routed (never guest input), so it can't be spoofed.
        let project_knobs = inner.project_tenancy_knobs(project.as_str());
        let posture = crate::tenant_resolve::TenantPosture {
            require_declaration: project_knobs.require_tenancy_declaration,
            allow_cross_tenant: project_knobs.allow_cross_tenant_db,
        };
        // Per-handler token config (Gap 2) wins over the site's `claims_from_token`.
        let token_cfg = handler_token_claims.or_else(|| {
            site_handlers
                .graphql
                .as_ref()
                .and_then(|g| g.data.as_ref())
                .and_then(|d| d.claims_from_token.as_ref())
        });
        // The R3 session-cookie verify anchor is the runtime's own session signer's public half
        // (set at startup from the node issuer). Absent ⇒ no session fact.
        let session_anchor = inner.session_signer.get().map(|s| s.public_key());
        // The project per-table tenancy schema (R2/D2), loaded from the KV — needed by BOTH the own
        // path (`with_schema`) and a target route (per-table keys + public subsets + eligibility).
        // Absent ⇒ the legacy single-column `Uniform` scoping; present-but-unreadable ⇒ **fail
        // closed** with a deny-all schema (every table refused), never a silent downgrade.
        let schema =
            match boatramp_core::deploy::load_project_tenancy(inner.kv.as_ref(), project).await {
                Ok(s) => s,
                Err(_) => Some(boatramp_core::tenancy::TenancySchema::deny_all()),
            };
        // Gap 2: the effective in-site tenancy for this route — the per-handler override when it
        // narrows within the site ceiling (a widening is refused fail-closed), else the site
        // decision. The posture (`resolve_host_tenancy`) still caps `All` + refuses undeclared on
        // top of this.
        let effective_tenancy = match handler_tenancy {
            Some(h) => {
                if let Some(ceiling) = site_handlers.tenancy.as_ref() {
                    // A per-route widening is refused unless BOTH the site enables exceptions
                    // (`allow_ceiling_exceptions`, key 1) AND the route carries `exceed_site_ceiling`
                    // (key 2). `all` still needs the operator posture at runtime (key 3, `cap()`).
                    // Fail-closed backstop; the deploy validator emits the speaking, key-aware error.
                    if !h.narrows_within_authorized(ceiling, site_handlers.allow_ceiling_exceptions)
                    {
                        return Err(BindingsError::Refused(format!(
                            "tenancy: a handler on site `{site}` declares a tenancy that widens the \
                             site ceiling (a per-handler decision may narrow within the site's \
                             `tenancy`; to widen deliberately, set `exceed_site_ceiling: true` on the \
                             route AND `allow_ceiling_exceptions = true` on the site)"
                        )));
                    }
                }
                Some(h)
            }
            None => site_handlers.tenancy.as_ref(),
        };
        let tenancy: Option<boatramp_handlers::HostTenancy> = match effective_tenancy {
            // R4/D8 plain-wasm TARGET route: bind a target scope for a SECOND tenant `B`'s public
            // subset (the non-federated analog of a `@tenant(scope: target)` field). `B` is
            // host-derived from the routed domain (5a's carried-domain source); the guest never
            // names it. Confinement rides on BOTH the `orm` binding (PerTableTarget) and the raw-SQL
            // `{scope}` marker. Fail-closed on every gap (not eligible / no domain / no schema).
            Some(boatramp_core::tenancy::Tenancy::Target {
                via,
                public,
                write,
                null_base,
            }) => {
                // Operator ceiling: the site must be listed in target_eligible_fields.
                if !schema
                    .as_ref()
                    .is_some_and(|s| s.target_field_eligible(site))
                {
                    return Err(BindingsError::Refused(format!(
                        "tenancy: site `{site}` is not an operator-permitted target-tenant route \
                         (add it to the project's target_eligible_fields)"
                    )));
                }
                // Ruling A (5c): the visibility `public_subset` is mandatory only for an ANONYMOUS
                // source (`domain`/`handle`) — for an unauthenticated actor the visibility predicate
                // is the only guard against reaching B's private rows. A `via: [capability]`-only
                // field is EXEMPT: the host-verified, audience-bound capability (naming `tid = B` +
                // the granted scope) IS the authorization, so the confinement is `tenant = B` and the
                // within-tenant per-client filter stays in-guest.
                // v0.4.8: `null_base` forces the subset (like an anonymous source) — the shared
                // `NULL`-base rows are a different trust partition than the capability-authorized `B`,
                // so a `target_or_null` read must visibility-gate the base arm (a subset-less table is
                // refused deny-by-default even under a capability). Plain `target` keeps the A-exemption.
                let require_public = *null_base
                    || via.iter().any(|s| {
                        matches!(
                            s,
                            boatramp_core::tenancy::TargetSource::Domain
                                | boatramp_core::tenancy::TargetSource::Handle
                        )
                    });
                // Under an anonymous source the named `public` subset MUST be declared
                // (deny-by-default) — a missing/typo'd subset name would degrade the raw-SQL/orm
                // confinement OPEN, exposing B's private rows. For a capability-only field the `public`
                // is just a scope label matched against the capability's own grant, so a declared
                // predicate is not required.
                if require_public
                    && schema
                        .as_ref()
                        .and_then(|s| s.public_subset(public))
                        .is_none()
                {
                    return Err(BindingsError::Refused(format!(
                        "tenancy: target route `{site}` names public subset `{public}` which the \
                         project schema does not declare (deny-by-default)"
                    )));
                }
                // G3 (schema-admission fact): the `handle` source is admissible ONLY on a
                // `world_public` subset — regardless of the via list. A route that lists `handle` on
                // a non-world-public subset is a misconfiguration that could expose non-public data,
                // so refuse it at bind rather than silently letting handle be inert.
                if via.contains(&boatramp_core::tenancy::TargetSource::Handle)
                    && !schema
                        .as_ref()
                        .is_some_and(|s| s.subset_is_world_public(public))
                {
                    return Err(BindingsError::Refused(format!(
                        "tenancy: target route `{site}` lists the `handle` source but its public \
                         subset `{public}` is not `world_public` (deny-by-default; a public handle \
                         may only reach world-public data)"
                    )));
                }
                // R4/D8 5c: resolve `B` from the first applicable `via` source (first-resolves-wins).
                // `domain` = the host-stamped routed-domain context tag; `capability` = the request
                // bearer verified as a signed capability envelope bound to THIS project + this route's
                // `public` subset (both honor the route's `write` grant); `handle` = a guest-named
                // public slug resolved against the operator's registry, read-only + world-public only.
                let resolved = schema.as_ref().and_then(|sc| {
                    crate::tenant_resolve::resolve_target_via(
                        via,
                        public,
                        write,
                        sc,
                        domain_context,
                        // Under a target route the bearer is a capability candidate (an app bearer
                        // simply fails the capability kind/audience check → no capability fact).
                        bearer,
                        session_anchor.as_ref(),
                        target_handle,
                        project.as_str(),
                        boatramp_core::time::now_unix(),
                    )
                });
                match (resolved, schema.as_ref()) {
                    (Some(rt), Some(sc)) => Some(
                        boatramp_handlers::HostTenancy::target(
                            boatramp_core::sql::SqlValue::Text(rt.value),
                            // `target_or_null` (v0.4.8) widens the READ to `(B OR NULL) AND <public>`
                            // via the `OwnOrNull` mode; `target` reads `B` alone. The write axis is
                            // unaffected either way (a target write still stamps `B`).
                            if *null_base {
                                boatramp_core::tenancy::AccessMode::OwnOrNull
                            } else {
                                boatramp_core::tenancy::AccessMode::Own
                            },
                            sc,
                            public,
                            // The effective write-allowlist: the route's grant for domain/capability,
                            // forced empty (read-only, G1) for a handle source. Raw-SQL writes refused.
                            &rt.write,
                            // Mandatory visibility subset for anonymous sources; exempt for capability-only.
                            require_public,
                        )
                        // The verified capability's opaque app-context (empty for domain/handle),
                        // surfaced to the resolver via `target-context` for its within-tenant filter.
                        .with_target_context(rt.context),
                    ),
                    // No `via` source resolved ⇒ refuse (a target route must never fall back to an
                    // own/plain — that would read the caller's own or every tenant's rows).
                    _ => {
                        return Err(BindingsError::Refused(
                            "tenancy: this target route could not resolve a target tenant \
                                    (no routed domain, no valid capability, and no resolvable handle)"
                                .to_string(),
                        ))
                    }
                }
            }
            // Own / session / signed-context / disabled: today's path, plus the R1 async-lane
            // `signed_context` source (resolved only when a consumer dispatch passes the drained
            // message's envelope; `None` on every synchronous request/handler path).
            other => {
                // The signed-context verify anchor is the fleet signer's public half (same key that
                // mints/verifies the durable envelope) — present only when a signer is wired.
                let context_anchor = signed_context.and_then(|_| {
                    inner
                        .session_signer
                        .get()
                        .map(|s| boatramp_core::cose::Signer::public_key(s.as_ref()))
                });
                let inputs = crate::tenant_resolve::TenantSourceInputs {
                    bearer,
                    domain_context,
                    token_cfg,
                    session_cookie,
                    session_anchor: session_anchor.as_ref(),
                    signed_context,
                    context_anchor: context_anchor.as_ref(),
                    env_source: Some(inner.env_source()),
                };
                crate::tenant_resolve::resolve_host_tenancy(
                    other,
                    imports_tenant_scoped_data,
                    posture,
                    inputs,
                )
                .await
                .map_err(|e| BindingsError::Refused(e.to_string()))?
                .map(|h| h.with_schema(schema.as_ref()))
            }
        };
        // PLAN-system-principal P2/P3: a `run_as: deployer` cron whose captured deployer was a
        // System·Admin fires as the SYSTEM principal. Coerce the resolved (non-target) tenancy to the
        // system class — base/`IS NULL`, `app.principal_kind='system'`, no tenant GUC — so the cron
        // handler's own SQL base-writes; a handler that declared NO tenancy keeps `None` (plain SQL).
        // A target route is left untouched (its confinement is its own safe behavior). The emit CLASS
        // below is forced to System regardless, so the handler's `emit` seals a system `signed_context`
        // for a downstream `signed_context` consumer (construens' worker). `run_as_system` is only ever
        // `true` on a cron fire whose deployer capture was System (set in `fire_cron`).
        let tenancy = if run_as_system {
            tenancy.map(|h| if h.is_target() { h } else { h.coerce_system() })
        } else {
            tenancy
        };
        bindings = bindings.with_tenancy(tenancy.clone());
        // The resolved principal's CLASS (PLAN-system-principal P3): a SYSTEM handler seals a system
        // `signed_context` on `emit`. Default `Tenant` for an unscoped handler, unchanged.
        let kind = if run_as_system {
            boatramp_core::tenancy::PrincipalKind::System
        } else {
            tenancy
                .as_ref()
                .map(boatramp_handlers::HostTenancy::principal_kind)
                .unwrap_or_default()
        };
        // The resolved `on_unresolved: "pass"` flag — carried out alongside the facts so the
        // `wasi:blobstore` bind below honors pass the same way the SQL/ORM scope does (the facts
        // vec alone drops it). `false` for a resolved/absent principal.
        let pass_unresolved = tenancy
            .as_ref()
            .is_some_and(boatramp_handlers::HostTenancy::pass_unresolved);
        // Carry the resolved principal (axis-tagged facts) so a sibling this handler invokes
        // inherits it (each fact keeps its axis).
        (
            tenancy.map(|h| h.facts().to_vec()).unwrap_or_default(),
            kind,
            pass_unresolved,
        )
    };
    if let Some(t) = &bindings_timing {
        t.set_resolve(t_resolve.elapsed().as_micros() as u64);
    }
    // Ask B-2: time the `wasi:blobstore` binding construction on its own (the construens `/img` suspect).
    let t_blobstore_build = std::time::Instant::now();
    // `wasi:blobstore` (REORDERED to here, post tenant-resolution): the host-side tenant confinement
    // (`blobstore.rs::container_prefix`) needs THIS invocation's resolved OWN tenant to expand a
    // `{tenant}` allowlist entry, and the multi-tenant fact to apply the deny-default. `multi_tenant`
    // is derived from the SAME tenancy that scopes `sql`/`orm`: the route/site DECLARES a tenancy
    // (`handler_tenancy` or `site_handlers.tenancy` — together the `effective_tenancy` used above; a
    // `Tenancy::Target` route is one of these) OR a confining `HostTenancy` was resolved
    // (`handler_caller_tenant` non-empty). The resolved own tenant is
    // `resolved_tenant_string(&handler_caller_tenant)` (the OWN-`Tenant` axis only; `None` for a
    // target/anon/unscoped invocation ⇒ `{tenant}` entries fail closed).
    if granted("wasi:blobstore") {
        use boatramp_core::tenancy::Tenancy;
        let max_blob = inner.max_blob_bytes.get().copied().unwrap_or(0);
        // Security MEDIUM-1: only a SCOPING tenancy (`Scoped`/`Target`) makes the site multi-tenant.
        // An explicit `Tenancy::Disabled` is deliberate single-tenant — `Some(..)` but NOT multi-tenant
        // (so the deny-default must not fire for a Disabled blob guest). `!handler_caller_tenant`
        // -`.is_empty()` stays false under Disabled (it resolves to no facts).
        let scoping = |t: Option<&Tenancy>| {
            matches!(t, Some(Tenancy::Scoped { .. } | Tenancy::Target { .. }))
        };
        let multi_tenant = scoping(handler_tenancy)
            || scoping(site_handlers.tenancy.as_ref())
            || !handler_caller_tenant.is_empty();
        // UX (C4): a multi-tenant site that grants `wasi:blobstore` without declaring an allowlist
        // will DENY every container op — surface it loudly at bind so operators find affected
        // handlers, naming the one-line remedy.
        if multi_tenant && blobstore_containers.is_empty() {
            tracing::warn!(
                project = %project.as_str(),
                site,
                "multi-tenant site grants wasi:blobstore but declares no blobstore_containers — \
                 every container op will be denied; add blobstore_containers: [\"assets-{{tenant}}\"]"
            );
        }
        // Ask-1: time this invocation's blob read ops (get / head / get_range) WITHOUT touching the blob
        // path — `TimingStorage` delegates every method unchanged, recording only read-op µs. `None`
        // (non-request lanes) ⇒ bare storage, byte-identical to before.
        let blob_storage: std::sync::Arc<dyn boatramp_core::Storage> = match &blob_timing {
            Some(t) => std::sync::Arc::new(boatramp_storage::TimingStorage::new(
                inner.storage.clone(),
                t.clone(),
            )),
            None => inner.storage.clone(),
        };
        bindings = bindings.with_blobstore(
            scope,
            blob_storage,
            max_blob,
            super::function_runtime::resolved_tenant_string(&handler_caller_tenant),
            blobstore_containers.to_vec(),
            multi_tenant,
            // Honor `on_unresolved: "pass"` on the blob surface too: a null-principal pass bind with
            // no resolved tenant gets an EMPTY own-space for its `{tenant}` container (not a 500).
            handler_caller_pass,
        );
    }
    if let Some(t) = &bindings_timing {
        t.set_blobstore_build(t_blobstore_build.elapsed().as_micros() as u64);
    }
    // The host-verified sealed principal for THIS invocation (PLAN-async-persona): resolved from the
    // durable `signed_context` envelope (verified against the fleet anchor — the SAME verify/expiry/
    // kind checks the tenancy source uses), so a consumer's `sealed-principal()` returns the host
    // -verified `{tenant, persona}`. `None` on the sync/request lane (no envelope) ⇒ `sealed-principal()`
    // returns `none`. Threaded onto the `graphql::run`/`invoke` sub-fetch below alongside the tenant.
    let sealed_principal = {
        let anchor = signed_context.and_then(|_| {
            inner
                .session_signer
                .get()
                .map(|s| boatramp_core::cose::Signer::public_key(s.as_ref()))
        });
        resolve_sealed_principal(signed_context, anchor.as_ref())
    };
    if let Some(principal) = sealed_principal.clone() {
        bindings = bindings.with_sealed_principal(principal);
    }
    // Ask B-1: time the `wasi:messaging` producer-binding build specifically — it is the one
    // post-resolution binding that does real per-request async work (`mint_producer_context` below),
    // so construens can see whether it contributes to the opaque `bindings_us` on a messaging route.
    let t_messaging_build = std::time::Instant::now();
    if granted("wasi:messaging") {
        // Plain topics are namespaced under the binding `scope` (the site, or the
        // preview scope), so a guest publishes only into its own namespace and
        // previews can't touch live topics; `bus:<topic>` publishes route to the
        // shared, project-scoped bus.
        if let Some(messaging) = &inner.messaging {
            // Stamp this handler's resolved own-tenant onto every message it publishes (R1,
            // guest-blind), so a consumer declaring `sources: [signed_context]` resolves it on the
            // async lane. `None` for an unscoped handler ⇒ the message carries no context.
            let signed_context = super::function_runtime::mint_producer_context(
                inner,
                &handler_caller_tenant,
                handler_caller_kind,
            )
            .await;
            bindings = bindings.with_messaging(
                format!("{scope}/"),
                format!("{}/", project.qualified("bus")),
                messaging.clone(),
                signed_context,
            );
        }
    }
    if let Some(t) = &bindings_timing {
        t.set_messaging_build(t_messaging_build.elapsed().as_micros() as u64);
    }
    // The read-only `messaging-stats` capability: surface the already-computed per-topic bus gauges
    // (dead-letter/backlog/in-flight + per-group depth) to a granted guest. A plain topic resolves
    // under the same component-private `scope` prefix as `with_messaging`; a `bus:<template>` topic
    // must be one of `stats_topics`, and the host substitutes THIS invocation's resolved tenant for
    // the template's `{tenant}` placeholder — the guest never names a tenant, so no cross-tenant
    // oracle. Deny-by-default (needs the import, the site allowlist, and the messaging substrate).
    if granted("messaging-stats")
        && let Some(messaging) = &inner.messaging
    {
        let resolved_tenant =
            super::function_runtime::resolved_tenant_string(&handler_caller_tenant);
        bindings = bindings.with_messaging_stats(
            format!("{scope}/"),
            format!("{}/", project.qualified("bus")),
            messaging.clone(),
            stats_topics.to_vec(),
            resolved_tenant,
        );
    }
    // The per-tenant sealed-secret capability (task #493): read/write secrets sealed to THIS
    // invocation's resolved OWN-tenant. Two INDEPENDENT rights — `tenant-secrets:read` (get/list)
    // and `tenant-secrets:admin` (set/delete) — each separately granted (import ∩ site allowlist);
    // the binding carries both flags so the host re-checks the right per call. The resolved tenant
    // is `resolved_tenant_string` of the OWN-`Tenant` fact (the SAME value the SQL scope injector
    // uses); `None` ⇒ every call is `no-resolved-tenant`. `tenant_secret_names` is the per-component
    // name allowlist (empty ⇒ deny-all). Deny-by-default: without a `[secrets]` envelope (no store)
    // OR without either right the binding is not built and every call fails closed. The guest never
    // names a tenant — the host injects the resolved one.
    if (granted("tenant-secrets:read") || granted("tenant-secrets:admin"))
        && let Some(store) = inner.tenant_secret_store.get()
    {
        let resolved_tenant =
            super::function_runtime::resolved_tenant_string(&handler_caller_tenant);
        bindings = bindings.with_tenant_secrets(
            store.clone(),
            project.as_str(),
            resolved_tenant,
            tenant_secret_names.to_vec(),
            granted("tenant-secrets:read"),
            granted("tenant-secrets:admin"),
        );
    }
    // Gap 3: `tenancy::present-token` — a site handler that verified a tenant credential IN-GUEST
    // (a POST-body app JWT, a cookie bearer) hands it to the host, which RE-verifies it against this
    // handler's effective `token_claims` + `token` source and seals the tenant onto the
    // producer-context cell (so a subsequent `emit::message` stamps it). Deny-by-default: needs the
    // `tenancy` import, a messaging cell, a declared `token` source + `token_claims`, and a signer.
    if granted("tenancy") {
        let effective_token_claims = handler_token_claims.or_else(|| {
            site_handlers
                .graphql
                .as_ref()
                .and_then(|g| g.data.as_ref())
                .and_then(|d| d.claims_from_token.as_ref())
        });
        let effective_tenancy = handler_tenancy.or(site_handlers.tenancy.as_ref());
        if let (Some(cell), Some(token_cfg), Some(signer), Some(claim)) = (
            bindings.producer_context_cell(),
            effective_token_claims.cloned(),
            inner.session_signer.get().cloned(),
            super::function_runtime::token_source_claim(effective_tenancy),
        ) {
            // Apply the SAME claim transform (if any) the request path uses, so a presented token
            // on a site handler seals the DERIVED key (async-lane symmetry).
            let (extract, namespace) =
                super::function_runtime::token_source_transform(effective_tenancy);
            bindings = bindings.with_present_token(
                std::sync::Arc::new(super::function_runtime::ServerProducerContextSource {
                    token_cfg,
                    claim,
                    extract,
                    namespace,
                    signer,
                    env_source: inner.env_source_arc(),
                    // The handler's site identifies the component for the persona seal-time signal.
                    component_hash: site.to_string(),
                }),
                cell,
            );
        }
    }
    // Function-to-function invoke (FI): a site handler reached over HTTP can call
    // sibling functions in-process — mirroring the top-level-function path
    // (`function_runtime::build_function_bindings`). Granted only when the site allows
    // `invoke`, the handler imports it and names at least one allowed target, and the
    // runtime has an invoker (set at serve startup). A handler is the *root* of a call
    // chain, so it invokes at depth 0; the host caps the next hop. The callee's own
    // Authorization comes from the invoke-request headers, so the guest-side ambient
    // bearer forwarding reaches it unchanged.
    if granted("invoke")
        && !invoke_targets.is_empty()
        && let Some(invoker) = inner.invoker.get()
    {
        // A site handler invokes siblings within its own tenant project, propagating its
        // resolved in-site tenant + host-verified sealed principal so the sibling inherits both
        // (host-carried, not guest-set) — PLAN-async-persona.
        bindings = bindings.with_invoke(
            // Parity with the top-level-function fan-out: carry THIS handler's own
            // `on_unresolved: "pass"` into its in-process sibling invokes, so an unresolved
            // directly-served handler zero-rows its sub-fetches instead of fail-closing. Inert
            // once a principal resolves (`handler_caller_pass` rides the resolved HostTenancy).
            invoker.scoped_with_pass(
                project,
                handler_caller_tenant.clone(),
                sealed_principal.clone(),
                handler_caller_pass,
            ),
            invoke_targets.to_vec(),
            depth,
        );
    }
    // GraphQL supergraph capability: a handler may run a GraphQL operation against the project's
    // composed supergraph in-process (cross-subgraph planning), forwarding its own bearer.
    // Granted when the site allows `graphql`, the handler imports it, and the runtime has a
    // supergraph runner. The handler is the root of the call chain (depth 0); the host caps the
    // next hop against the depth budget shared with invoke.
    if granted("graphql")
        && let Some(runner) = inner.federation_runner.get()
    {
        // Propagate the handler's resolved principal AND host-verified sealed principal so a
        // `graphql::run` sub-fetch inherits its tenancy + persona (symmetric to `with_invoke` above),
        // rather than failing closed on an `own` op or a `role(…)` field (PLAN-async-persona).
        bindings = bindings.with_graphql(
            // Same parity: carry the handler's own `on_unresolved: "pass"` into its in-process
            // `graphql::run` sub-fetch (symmetric to `with_invoke` above and the function fan-out).
            runner.scoped_with_pass(
                project,
                handler_caller_tenant.clone(),
                sealed_principal.clone(),
                handler_caller_pass,
            ),
            depth,
        );
    }
    // Per-project SMTP email gateway: a handler may submit a finished message to one
    // of the project's SMTP profiles. Granted when the site allows `email`, the
    // handler imports it, and the runtime offers email (a spool + profile store are
    // set — gated at startup by the `allow_guest_email` posture). The SMTP
    // credentials are resolved host-side and never exposed to the guest.
    #[cfg(feature = "email")]
    if granted("email")
        && let (Some(store), Some(spool)) =
            (inner.email_profile_store.get(), inner.email_spool.get())
    {
        match store.resolve_all(project).await {
            Ok(profiles) => {
                bindings = bindings.with_email(
                    project.as_str(),
                    std::sync::Arc::new(profiles),
                    spool.clone(),
                );
            }
            Err(err) => {
                tracing::warn!(site, %err, "resolving email profiles failed; email not granted");
            }
        }
    }
    // Guest project self-config (`boatramp:handlers/admin`): grant the surfaces the site allows,
    // the handler imports, AND the operator posture enables — project-scoped host-side.
    // Deny-by-default; an unenabled/ungranted surface's verbs return `access-denied`.
    #[cfg(feature = "admin")]
    if let (Some(controller), Some(enabled)) =
        (inner.admin_controller.get(), inner.admin_surfaces.get())
    {
        use boatramp_handlers::AdminSurface;
        let mut surfaces = std::collections::BTreeSet::new();
        for (imp, surface) in [
            ("admin:domains", AdminSurface::Domains),
            ("admin:email", AdminSurface::Email),
            ("admin:site", AdminSurface::Site),
            ("admin:secrets", AdminSurface::Secrets),
        ] {
            if enabled.contains(&surface) && granted(imp) {
                surfaces.insert(surface);
            }
        }
        if !surfaces.is_empty() {
            bindings = bindings.with_admin(controller.scoped(project), surfaces);
        }
    }
    // Guest capability minting (`boatramp:handlers/capability`, PLAN-delegable-capabilities): a guest
    // mints a fleet-signed target capability redeemable ONLY at its own project. Granted when the site
    // allows `capability`, the handler imports it, the operator posture set a positive TTL ceiling (via
    // `set_capability_minting` at startup, gated by `allow_guest_mint_capability`), AND the fleet signer
    // is wired. The audience is host-forced to `project` by the binding; the TTL is clamped to the
    // ceiling. Deny-by-default: absent any of these, no binding is attached and `mint` is access-denied.
    #[cfg(feature = "capability")]
    if granted("capability") {
        // Gap 4a: the per-project capability-mint ceiling (operator override, else node base). A
        // project may enable minting the fleet base leaves off, or disable one the base enables.
        if let (Some(max_ttl), Some(signer)) = (
            inner
                .project_tenancy_knobs(project.as_str())
                .capability_max_ttl_secs,
            inner.session_signer.get(),
        ) {
            let minter = std::sync::Arc::new(ServerCapabilityMinter {
                signer: signer.clone(),
            });
            bindings = bindings.with_capability(project.as_str(), minter, max_ttl);
        }
    }
    // Guest blob-upload minting (`boatramp:handlers/blob-upload`, S3 external ingress): a guest mints a
    // short-lived, scoped S3 upload credential for one of its OWN project+site's blob containers.
    // Granted when the site allows a `blob-upload:*` right, the handler imports it, the local S3 face's
    // minting config is wired (`set_blob_upload_minting` at startup), AND the fleet signer is present.
    // Project + site are host-forced by the binding from `project` (host-routed) + this handler's
    // `site` (host-routed); the resolved OWN tenant (host-resolved, never guest-supplied) is threaded so
    // a `{tenant}`-templated `upload_containers` entry expands only to this handler's own tenant's
    // container (cross-tenant mint structurally impossible; mirrors `tenant-secrets`); the TTL +
    // max-bytes are clamped to the operator ceilings; the container is checked against
    // `upload_containers`. Deny-by-default: absent any of these, no binding is attached and `mint` fails
    // closed. The two rights are INDEPENDENT (`:write` single-shot, `:multipart`).
    #[cfg(feature = "blob-upload")]
    if (granted("blob-upload:write") || granted("blob-upload:multipart"))
        && let Some(cfg) = inner.blob_upload_config.get()
        // Prefer a wired cloud minter (M4); else the local-face minter (needs the fleet signer). Both
        // are the SAME `BlobUploadMinter` seam — the binding still host-forces project+site + clamps.
        && let Some(minter) = inner
            .blob_upload_cloud_minter
            .get()
            .cloned()
            .or_else(|| {
                inner.session_signer.get().map(|signer| {
                    std::sync::Arc::new(crate::blob_upload_minter::ServerBlobUploadMinter {
                        signer: signer.clone(),
                        secret: cfg.secret.clone(),
                        config: cfg.face.clone(),
                    })
                        as std::sync::Arc<dyn boatramp_handlers::BlobUploadMinter>
                })
            })
    {
        bindings = bindings.with_blob_upload(
            project.as_str(),
            // The site is host-routed for a request handler — a single resolved site, always present
            // on this path (an `all`/anonymous funnel has no single site; that fail-closed
            // `no-resolved-site` case is exercised on the function/consumer path where `site` may be
            // absent). Pass it as the host-forced site.
            Some(site.to_string()),
            // The resolved OWN tenant (the SAME value the SQL scope injector uses); `None` for an
            // unscoped invocation ⇒ a `{tenant}`-only container fails closed `no-resolved-tenant`.
            super::function_runtime::resolved_tenant_string(&handler_caller_tenant),
            minter,
            cfg.max_ttl_secs,
            cfg.max_bytes_ceiling,
            upload_containers.to_vec(),
            granted("blob-upload:write"),
            granted("blob-upload:multipart"),
        );
    }
    // Capture stdout/stderr (+ `wasi:logging`) for every invocation — not a guest-requested
    // import, but host-side observability. Tagged by `site` (so a site's live + preview output
    // aggregates under it), rate-capped per the site's `maxLogRate`, and correlated with the
    // request id. A site may opt out (`disable_log_capture`), e.g. when guest output may carry
    // secrets/PII; then no sink is wired and the guest's stdio is discarded.
    if !site_handlers.disable_log_capture {
        inner.logs.configure(site, site_handlers.max_log_rate);
        bindings = bindings.with_logging(
            site.to_string(),
            request_id.map(str::to_string),
            inner.logs.clone(),
        );
    }

    // Environment for the guest: the deploy's static `env`
    // strings, plus the site's `secrets` — each a *reference* to a secret value,
    // resolved here and never stored in the manifest/config. The guest sees only
    // these; the host's own environment is never inherited. Under the multi-tenant
    // posture a bare / `env:` ref into the operator's environment is refused
    // (fail-closed) — the site config's author is an untrusted tenant.
    let allow_env_secret_refs = inner.allow_env_secret_refs.get().copied().unwrap_or(false);
    let env = resolve_env(
        site,
        project,
        deploy_env,
        site_handlers,
        secret_allowlist,
        allow_env_secret_refs,
        inner.secret_store.get().map(std::convert::AsRef::as_ref),
        inner.env_source(),
    )
    .await?;
    bindings = bindings.with_env(env);
    Ok(bindings)
}

/// Filter the site `[handlers].secrets` pool to a per-guest **allowlist** (task #492):
/// the single choke point every guest kind that injects the site pool (handlers,
/// consumers, and cron-triggered handlers) shares, so they can never diverge.
///
/// - `allowlist` **empty** ⇒ return the whole pool (today's behavior; the field is a
///   non-breaking opt-in, so an absent/empty allowlist means "inject everything").
/// - `allowlist` **non-empty** ⇒ keep only the pool entries whose KEY (the guest env-var
///   name) is named in the allowlist — least-privilege. An allowlist name that is not a
///   pool key is silently dropped **here** (the resolve path is not the enforcement point
///   for typos); activation-time validation ([`SecurityRuntime::precheck_activation`]) is
///   what turns an unknown name into a hard error, so this stays a pure projection.
///
/// The map is cloned (returned owned) so the caller can pass it to
/// [`resolve_secret_env`] alongside a `deploy_env` borrow without a lifetime tangle; the
/// pool is small (a handful of entries), so the clone is negligible.
#[cfg(feature = "handlers")]
pub(super) fn filter_site_secrets(
    pool: &std::collections::BTreeMap<String, String>,
    allowlist: &[String],
) -> std::collections::BTreeMap<String, String> {
    if allowlist.is_empty() {
        return pool.clone();
    }
    pool.iter()
        .filter(|(key, _)| allowlist.iter().any(|a| a == *key))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Assemble the guest environment: static deploy `env` first, then site
/// `secrets` resolved from the host environment (a missing referent is logged
/// and skipped, never injected as empty). A secret name overrides a static one.
///
/// `secret_allowlist` is the per-guest opt-in subset of the site pool KEYS
/// ([`filter_site_secrets`]): empty ⇒ the whole pool (default), non-empty ⇒ only the
/// named keys (least-privilege). Applied **before** resolution, so a secret the guest is
/// not granted is never even read from the store/env for this guest.
///
/// `allow_env_secret_refs` is the security posture's `allow_env_secret_refs`
/// (on under single-tenant/dev, off under multi-tenant): when off, a bare /
/// `env:`-scheme ref is **refused** (fail-closed) so an untrusted tenant's
/// `secrets` map can't name an arbitrary host env var to exfiltrate it.
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)] // env_source (task #498) is the 8th; a single choke point for site-secret env resolution
pub(super) async fn resolve_env(
    site: &str,
    project: boatramp_core::project::ProjectRef<'_>,
    deploy_env: &std::collections::BTreeMap<String, String>,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    secret_allowlist: &[String],
    allow_env_secret_refs: bool,
    secret_store: Option<&boatramp_core::secret_store::SecretStore>,
    env_source: &dyn boatramp_core::env::EnvSource,
) -> Result<Vec<(String, String)>, String> {
    let scoped = filter_site_secrets(&site_handlers.secrets, secret_allowlist);
    resolve_secret_env(
        site,
        project,
        deploy_env,
        &scoped,
        allow_env_secret_refs,
        secret_store,
        env_source,
    )
    .await
}

/// Assemble a guest environment: static `env` first, then each `secrets` entry
/// (`GUEST_NAME` → `SECRET_REF`) resolved. A missing host referent is logged and
/// skipped — **never** injected as an empty value — and a resolved secret
/// overrides a static `env` of the same name. This is the single indirection both
/// site handlers and top-level functions use, so the referenced value is only
/// injected at instantiation and never lands in the stored config/manifest.
/// `label` tags the warn log (site or function scope).
///
/// A `SECRET_REF` carries an optional scheme:
/// - `env:HOST_VAR` (explicit) or a **bare** `HOST_VAR` (back-compat) — read the
///   serve process's own environment. That namespace is the **operator's**, so a
///   bare/`env:` ref is honored only when `allow_env_secret_refs` is true
///   (single-tenant/dev). Under the multi-tenant posture (`false`) it is
///   **refused** with a clear error — the config author is an untrusted tenant,
///   and a permitted bare ref would let them exfiltrate any host env var (another
///   tenant's DB password, a cloud key) into their guest. Fail-closed: the whole
///   env resolution errors so the handler/function never instantiates with a
///   leaked value.
/// - any other `scheme:` (a value with a colon whose scheme isn't `env`) — reserved
///   for a future resolver (the project-scoped `boatramp:` store, or an external
///   secret manager); **not yet supported**, so any such ref errors rather than
///   silently resolving. We don't enumerate provider names: a colon means "scheme".
#[cfg(feature = "handlers")]
pub(super) async fn resolve_secret_env(
    label: &str,
    project: boatramp_core::project::ProjectRef<'_>,
    static_env: &std::collections::BTreeMap<String, String>,
    secrets: &std::collections::BTreeMap<String, String>,
    allow_env_secret_refs: bool,
    secret_store: Option<&boatramp_core::secret_store::SecretStore>,
    env_source: &dyn boatramp_core::env::EnvSource,
) -> Result<Vec<(String, String)>, String> {
    let mut env: Vec<(String, String)> = static_env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (guest_name, secret_ref) in secrets {
        match parse_secret_ref(secret_ref) {
            // Bare / `env:` — the operator's own namespace. Permitted only when
            // the config author IS the operator (single-tenant/dev).
            SecretRef::Env(host_var) => {
                if !allow_env_secret_refs {
                    return Err(format!(
                        "host-env secret ref {guest_name:?} → {host_var:?} is not permitted \
                         under the multi-tenant posture (it would read the operator's \
                         environment); use a project-scoped secret instead"
                    ));
                }
                match env_source.get(host_var) {
                    Some(value) => {
                        env.retain(|(k, _)| k != guest_name);
                        env.push((guest_name.clone(), value));
                    }
                    None => tracing::warn!(
                        label,
                        secret = %guest_name,
                        "secret references env var {host_var}, which is not set; not injected"
                    ),
                }
            }
            // `boatramp:NAME` — the project-scoped internal store. Resolves only
            // within *this* project's sealed keyspace (multi-tenant-safe: never the
            // host env or another tenant's secret), so it is not gated on
            // `allow_env_secret_refs`. Fail-closed if no store is configured; a
            // missing secret is warned + skipped (like a missing env var).
            SecretRef::Boatramp(name) => {
                let Some(store) = secret_store else {
                    return Err(format!(
                        "secret ref {guest_name:?} → boatramp:{name} cannot be resolved: no \
                         internal secret store is configured (a [secrets] key envelope is required)"
                    ));
                };
                match store.get(project, name).await {
                    Ok(Some(bytes)) => {
                        let value = String::from_utf8(bytes).map_err(|_| {
                            format!("boatramp secret {name:?} is not valid UTF-8 for an env var")
                        })?;
                        env.retain(|(k, _)| k != guest_name);
                        env.push((guest_name.clone(), value));
                    }
                    Ok(None) => tracing::warn!(
                        label,
                        secret = %guest_name,
                        "secret references boatramp:{name}, which is not set; not injected"
                    ),
                    Err(err) => {
                        return Err(format!(
                            "resolving boatramp secret {name:?} for {guest_name:?} failed: {err}"
                        ));
                    }
                }
            }
            // A reserved scheme we recognise but don't yet implement — fail-closed
            // rather than fall through to reading the env.
            SecretRef::Unsupported(scheme) => {
                return Err(format!(
                    "secret ref {guest_name:?} uses the {scheme:?} scheme, which is not yet \
                     supported"
                ));
            }
        }
    }
    Ok(env)
}

/// Deploy-time admission for a `secrets` map: the same scheme gate
/// [`resolve_secret_env`] applies at instantiation, but **without** reading any
/// env var — so a tenant deploying under the multi-tenant posture gets a clear
/// failure at deploy time (naming the offending guest var), not only when the
/// handler/function first runs. `Err(msg)` refuses the deploy. Kept in lockstep
/// with `resolve_secret_env` so the two never diverge.
#[cfg(feature = "handlers")]
pub(super) fn admit_secret_refs(
    secrets: &std::collections::BTreeMap<String, String>,
    allow_env_secret_refs: bool,
) -> Result<(), String> {
    for (guest_name, secret_ref) in secrets {
        match parse_secret_ref(secret_ref) {
            SecretRef::Env(host_var) => {
                if !allow_env_secret_refs {
                    return Err(format!(
                        "host-env secret ref {guest_name:?} → {host_var:?} is not permitted \
                         under the multi-tenant posture (it would read the operator's \
                         environment); use a project-scoped secret instead"
                    ));
                }
            }
            // `boatramp:` is the project-scoped store — always admissible (it can't
            // reach the host env or another tenant). Its value isn't checked here;
            // the secret may be set after deploy, resolved (or warned-missing) at run.
            SecretRef::Boatramp(_) => {}
            SecretRef::Unsupported(scheme) => {
                return Err(format!(
                    "secret ref {guest_name:?} uses the {scheme:?} scheme, which is not yet \
                     supported"
                ));
            }
        }
    }
    Ok(())
}

/// Deploy-time admission for a guest's per-guest **secret allowlist** (task #492): every
/// name in `allowlist` must be a KEY of the site `[handlers].secrets` `pool`. Mirrors the
/// unknown-import check ([`boatramp_core::config`]'s `check_import`) — a typo or a
/// removed/rotated secret name is caught at activation with a speaking error naming the
/// guest (`label`) + the offending name, rather than silently injecting nothing at
/// runtime. `Err(msg)` refuses the activation.
///
/// - An **empty** allowlist means "inject the whole pool" (the non-breaking default) and
///   is never an error, even when the pool itself is empty.
/// - A **non-empty** allowlist against an **empty** pool is refused: the guest asks to be
///   granted named secrets but the site defines none — there is nothing to grant, so this
///   is a misconfiguration, not a silent no-op.
/// - Otherwise every name must be a key of the pool; the first unknown name errors.
#[cfg(feature = "handlers")]
pub(super) fn admit_secret_allowlist(
    pool: &std::collections::BTreeMap<String, String>,
    allowlist: &[String],
    label: &str,
) -> Result<(), String> {
    if allowlist.is_empty() {
        return Ok(());
    }
    if pool.is_empty() {
        return Err(format!(
            "{label} declares a secret allowlist {allowlist:?} but the site defines no \
             [handlers].secrets pool — add the named secrets to the site pool, or drop the \
             allowlist (an empty allowlist injects the whole pool)"
        ));
    }
    for name in allowlist {
        if !pool.contains_key(name) {
            let mut known: Vec<&str> = pool.keys().map(String::as_str).collect();
            known.sort_unstable();
            return Err(format!(
                "{label} secret allowlist names {name:?}, which is not a key of the site \
                 [handlers].secrets pool (known: {}) — a typo or a removed/rotated secret. Fix the \
                 name or add it to the site pool",
                known.join(", ")
            ));
        }
    }
    Ok(())
}

/// **#503 apply-time validation** of a route's per-route write-global allowlist
/// ([`Tenancy::Scoped::unscoped_writes`](boatramp_core::tenancy::Tenancy)) against the stored
/// project tenancy `schema` — the defense-in-depth companion to the runtime resolve-gate (which
/// stays the PRIMARY guard; this is fail-fast, NOT a replacement). An empty allowlist ⇒ `Ok`
/// (nothing to check). Mirrors [`admit_secret_allowlist`]: an unknown/mis-classified entry is a
/// hard **refusal** naming the guest + the offending table. A `warn` (never a refusal) is returned
/// when an entry is REDUNDANT because the table is already declared `writable: true` (the kind
/// authorizes the write project-wide, so listing it changes nothing). Rules (each fail-fast):
/// - the table must EXIST in the schema (an unknown table is a typo/rot);
/// - it must resolve to **plain `Unscoped`** — NOT a tenant kind (the list can never write a tenant
///   table unstamped, so listing one is a misconfiguration), NOT undeclared, and (for the error
///   case) NOT `writable: true` (that is the redundancy warning, not an error).
///
/// `Ok(warnings)` — the redundant-entry advisories to log; `Err` — the hard refusal.
#[cfg(feature = "handlers")]
pub(super) fn admit_unscoped_writes(
    schema: Option<&boatramp_core::tenancy::TenancySchema>,
    allowlist: &[String],
    label: &str,
) -> Result<Vec<String>, String> {
    use boatramp_core::tenancy::{ResolvedScope, TableScope};
    if allowlist.is_empty() {
        return Ok(Vec::new());
    }
    // A route lists write-global tables but the project declares NO tenancy schema at all: the
    // runtime binds the legacy `Uniform` posture (no `Unscoped` resolution exists), so the list can
    // never fire — refuse it fail-fast rather than let it silently no-op.
    let Some(schema) = schema else {
        return Err(format!(
            "{label} declares tenancy.unscoped_writes {allowlist:?} but the project has no tenancy \
             schema — declare the tables (each `{{ \"kind\": \"unscoped\" }}`) in the project \
             tenancy schema, or drop the allowlist"
        ));
    };
    let mut warnings = Vec::new();
    for table in allowlist {
        match schema.tables.get(table) {
            // The redundancy WARNING: the table is already project-wide write-global, so listing it
            // per-route adds nothing (the kind authorizes it for every route).
            Some(TableScope::Unscoped { writable: true }) => {
                warnings.push(format!(
                    "{label} tenancy.unscoped_writes lists {table:?}, but that table is already \
                     declared write-global (`{{ \"kind\": \"unscoped\", \"writable\": true }}`) — \
                     the per-route entry is redundant (the kind authorizes the write project-wide). \
                     Remove it, or make the table plain `unscoped` if you want per-route control"
                ));
            }
            // The one valid case: a plain read-only-reference global the route opts into writing.
            Some(TableScope::Unscoped { writable: false }) => {}
            // A tenant kind: the list can NEVER write it unstamped (G1 keeps it stamped at runtime);
            // listing it is a misconfiguration — refuse fail-fast (defense-in-depth for G1).
            Some(other) => {
                // Resolve for a precise message (the identity table's key etc.).
                let resolved = schema.resolve(table);
                let kind = match resolved {
                    Some(ResolvedScope::Column(_)) => "a per-tenant table",
                    Some(ResolvedScope::TenantOrSession { .. }) => "an anonymous-first table",
                    Some(ResolvedScope::TenantOrBase { .. }) => "a base-inclusive table",
                    _ => "a non-global table",
                };
                let _ = other;
                return Err(format!(
                    "{label} tenancy.unscoped_writes lists {table:?}, but that table is {kind}, not \
                     a global — a per-route write-global allowlist may only name a plain `unscoped` \
                     table. Writes to a tenant table are always tenant-stamped; remove {table:?} \
                     from the allowlist"
                ));
            }
            None => {
                let mut known: Vec<&str> = schema.tables.keys().map(String::as_str).collect();
                known.sort_unstable();
                return Err(format!(
                    "{label} tenancy.unscoped_writes names {table:?}, which is not a table in the \
                     project tenancy schema (known: {}) — a typo, or a table missing its \
                     `{{ \"kind\": \"unscoped\" }}` declaration. Fix the name or declare the table",
                    known.join(", ")
                ));
            }
        }
    }
    Ok(warnings)
}

/// A parsed secret reference from a `secrets` map value.
#[cfg(feature = "handlers")]
enum SecretRef<'a> {
    /// A bare `HOST_VAR` or explicit `env:HOST_VAR` — the serve process's own
    /// environment (the operator's namespace). Carries the host variable name.
    Env(&'a str),
    /// `boatramp:NAME` — the project-scoped internal secret store. Resolves only
    /// within the request's own project (multi-tenant-safe). Carries the secret name.
    Boatramp(&'a str),
    /// A reserved-but-unimplemented scheme — anything before the first `:` that we
    /// don't yet resolve (an external manager). Carries the scheme keyword for the
    /// error message.
    Unsupported(&'a str),
}

/// Parse a `secrets` map value into a [`SecretRef`]. A **colon-free** value is a
/// bare host-env var name (back-compat). Otherwise the part before the first `:` is
/// a **scheme**: `env` is the explicit host-env form, `boatramp` the project-scoped
/// internal store; every other scheme is reserved (a future external secret manager)
/// and is surfaced as unsupported rather than misread as a host var. We deliberately
/// do not enumerate external provider names — any `scheme:` we don't resolve is
/// refused, so a value containing a colon is never silently treated as an env var.
#[cfg(feature = "handlers")]
fn parse_secret_ref(secret_ref: &str) -> SecretRef<'_> {
    match secret_ref.split_once(':') {
        Some(("env", host_var)) => SecretRef::Env(host_var),
        Some(("boatramp", name)) => SecretRef::Boatramp(name),
        Some((scheme, _)) => SecretRef::Unsupported(scheme),
        None => SecretRef::Env(secret_ref),
    }
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
/// background scheduler (`run_scheduler_tick`) per active consumer.
/// The inputs needed to rebuild a consumer's [`Bindings`] **per message** — required for a consumer
/// that declares the R1 `signed_context` source, whose tenancy (and therefore the `graphql::run`
/// caller principal, baked at bind time from the resolved facts) must reflect EACH drained message's
/// sealed originator tenant. A consumer that does not declare `signed_context` resolves identically
/// with or without an envelope, so it reuses the once-per-tick binding instead (no rebuild).
#[cfg(feature = "handlers")]
pub(super) struct ConsumerRebuild<'a> {
    pub inner: &'a HandlerRuntimeInner,
    pub project: boatramp_core::project::ProjectRef<'a>,
    pub site: &'a str,
    pub scope: &'a str,
    pub imports: &'a [String],
    pub site_handlers: &'a boatramp_core::config::HandlersSiteConfig,
    pub tenancy: Option<&'a boatramp_core::tenancy::Tenancy>,
    pub token_claims: Option<&'a boatramp_core::config::HandlerGraphqlTokenClaims>,
    /// The consumer's declared `bus:` stats-topic templates for the `messaging-stats` capability.
    pub stats_topics: &'a [String],
    /// The consumer's per-component tenant-secret name allowlist (task #493). Empty ⇒ deny-all.
    /// Threaded so a per-message rebuild scopes tenant secrets identically to the once-per-tick build.
    pub tenant_secret_names: &'a [String],
    /// The consumer's per-component `blob-upload` container allowlist (S3 external ingress). Empty ⇒
    /// deny-all. Threaded so a per-message rebuild scopes upload minting identically to the tick build.
    pub upload_containers: &'a [String],
    /// The consumer's per-component plain-`wasi:blobstore` container allowlist (host-enforced tenant
    /// confinement). Threaded so a per-message rebuild confines blob access identically to the tick build.
    pub blobstore_containers: &'a [String],
    /// The consumer's per-guest secret allowlist (task #492): the subset of the site pool KEYS it is
    /// granted. Empty ⇒ the whole pool. Threaded so a per-message rebuild scopes secrets identically
    /// to the once-per-tick build.
    pub secret_allowlist: &'a [String],
}

#[cfg(feature = "handlers")]
impl ConsumerRebuild<'_> {
    /// Build the consumer's bindings resolving its tenancy against `signed_context` (the drained
    /// message's host-sealed envelope). Mirrors the scheduler's once-per-tick `build_bindings` call
    /// exactly (consumers get no `env`, no `invoke` capability, no request context) — only the
    /// `signed_context` differs, per message.
    pub(super) async fn bindings_for(
        &self,
        signed_context: Option<&str>,
    ) -> Result<boatramp_handlers::Bindings, String> {
        build_bindings(
            self.inner,
            self.project,
            self.site,
            self.scope,
            None,
            self.imports,
            self.site_handlers,
            &std::collections::BTreeMap::new(),
            &[],
            self.stats_topics,
            self.tenant_secret_names,
            self.upload_containers,
            self.blobstore_containers,
            self.secret_allowlist,
            0,
            None,
            None,
            None,
            None,
            None,
            self.tenancy,
            self.token_claims,
            signed_context,
            // A consumer resolves the system class from the drained seal (`signed_context`), never a
            // cron flag — so it is never a `run_as_system` fire itself.
            false,
            // Ask-1 blob timing is request-lane only; the async consumer lane passes None (bare storage).
            None,
            // Ask B-1 bindings sub-timing is request-lane only; the consumer lane passes None.
            None,
        )
        .await
        // The async lane has no HTTP response to 503 — a consumer nacks on any bindings failure
        // (a not-ready managed DB included), so the message redelivers and is retried once the DB
        // is up. Flatten to a string for the nack log.
        .map_err(|e| e.to_string())
    }
}

/// Resolve a drained message's SEALED originator tenant from its durable `signed_context` envelope
/// (v0.7.1 tenant-template bind-verify). Verifies the envelope (signature + expiry + `br_kind ==
/// "context"`) against the fleet `anchor` — the SAME [`verify_context`](boatramp_core::cose::verify_context)
/// the `signed_context` tenancy source uses — and returns the bound tenant. `None` for a message with
/// no envelope, no fleet anchor, or a forged/altered/expired envelope: the caller then fails closed
/// (a templated delivery with no verifiable seal is quarantined, never delivered). The guest never
/// names the tenant — only a host signature over the producer's principal resolves here.
#[cfg(feature = "handlers")]
fn resolve_sealed_tenant(
    signed_context: Option<&str>,
    anchor: Option<&boatramp_core::cose::TokenPublicKey>,
) -> Option<String> {
    let (env, anchor) = (signed_context?, anchor?);
    boatramp_core::cose::verify_context(env, anchor, boatramp_core::time::now_unix()).ok()
}

/// Sanitize an UNTRUSTED guest-returned error string before it lands in the DLQ `last_error` (which
/// an operator reads via `dlq ls/show` and which may be echoed into a structured log). Strips ASCII
/// control chars (incl. newlines/tabs — no log-injection / DLQ-record corruption), collapses runs of
/// whitespace, and re-caps length as defense-in-depth (the engine already bounds it at
/// [`MAX_CONSUMER_ERROR_LEN`](boatramp_handlers::MAX_CONSUMER_ERROR_LEN)). Returns a trimmed, single
/// -line, printable summary — empty if nothing printable remains (caller falls back to the bare label).
#[cfg(feature = "handlers")]
fn sanitize_dlq_detail(detail: &str) -> String {
    let mut out =
        String::with_capacity(detail.len().min(boatramp_handlers::MAX_CONSUMER_ERROR_LEN));
    let mut prev_space = false;
    for c in detail.chars() {
        // Drop C0/C1 controls (newline, tab, CR, NUL, ESC, …) — the injection/corruption surface.
        if c.is_control() {
            if !prev_space && !out.is_empty() {
                out.push(' ');
                prev_space = true;
            }
            continue;
        }
        if c == ' ' {
            if prev_space || out.is_empty() {
                continue;
            }
            prev_space = true;
        } else {
            prev_space = false;
        }
        out.push(c);
        if out.len() >= boatramp_handlers::MAX_CONSUMER_ERROR_LEN {
            break;
        }
    }
    out.trim_end().to_string()
}

/// The terminal-outcome classification of a durable message's `signed_context` seal for a consumer
/// that REQUIRES one (PLAN-async-persona legible-terminal-outcome taxonomy). Each maps to a distinct,
/// operator-legible dead-letter reason + metric label. Honestly recoverable-or-not: an expired seal
/// can't be revived (re-ingest from source); a missing/invalid seal points at a producer that did not
/// `present_token`.
#[cfg(feature = "handlers")]
enum SealOutcome {
    /// The seal verified (signature + expiry + kind) — deliver as normal.
    Verified,
    /// A well-formed, correctly-signed seal that aged past the `signed_context` TTL before it was
    /// consumed. Terminal + loud: `context-seal-expired`.
    Expired,
    /// No `signed_context` envelope on a consumer that requires one. Terminal: `context-seal-missing`.
    Missing,
    /// A present envelope that fails verification (bad signature / wrong kind / malformed / no fleet
    /// anchor wired). Terminal: `context-seal-invalid`.
    Invalid,
}

/// Classify a `signed_context`-requiring consumer's message seal (PLAN-async-persona). Uses the SAME
/// verify/expiry/kind checks as the tenancy source + the bind-verify, distinguishing an EXPIRED seal
/// (recoverable only by re-ingesting from source) from an ABSENT one (a producer never presented) and
/// an INVALID one (forged/wrong-kind/no-anchor). Read only for a consumer that declares
/// `sources: [signed_context]` (the caller gates on that); a non-requiring consumer never reaches here.
#[cfg(feature = "handlers")]
fn classify_seal(
    signed_context: Option<&str>,
    anchor: Option<&boatramp_core::cose::TokenPublicKey>,
) -> SealOutcome {
    let Some(env) = signed_context else {
        return SealOutcome::Missing;
    };
    // No fleet anchor wired ⇒ nothing can verify a present envelope ⇒ invalid (fail-closed).
    let Some(anchor) = anchor else {
        return SealOutcome::Invalid;
    };
    match boatramp_core::cose::verify_context_full(env, anchor, boatramp_core::time::now_unix()) {
        Ok(_) => SealOutcome::Verified,
        Err(boatramp_core::cose::TokenError::Expired) => SealOutcome::Expired,
        // Any other failure (bad signature, wrong kind, malformed, missing claim) is invalid.
        Err(_) => SealOutcome::Invalid,
    }
}

/// Resolve a drained message's host-verified **sealed principal** (`{tenant, persona}`) from its
/// durable `signed_context` envelope (PLAN-async-persona). Uses the SAME verify/expiry/kind checks as
/// [`resolve_sealed_tenant`] (via [`verify_context_full`](boatramp_core::cose::verify_context_full)),
/// so the persona rides the SAME verified envelope as the tenant — bound to the same tenant, sharing
/// its TTL. `None` for a message with no envelope, no fleet anchor, or a forged/altered/expired
/// envelope: the consumer's `sealed-principal()` then returns `none` and a `role(…)`-gated sub-fetch
/// fails closed. The guest never names the persona — only a host signature over the producer's
/// verified bearer claim resolves here.
#[cfg(feature = "handlers")]
pub(super) fn resolve_sealed_principal(
    signed_context: Option<&str>,
    anchor: Option<&boatramp_core::cose::TokenPublicKey>,
) -> Option<boatramp_handlers::SealedPrincipal> {
    let (env, anchor) = (signed_context?, anchor?);
    let v = boatramp_core::cose::verify_context_full(env, anchor, boatramp_core::time::now_unix())
        .ok()?;
    // Lower the verified seal's CLASS to the matching `SealedPrincipal` arm — a `System` seal (no
    // tenant) becomes `System`, a `Tenant` seal keeps its tenant. The seal's own positive marker is
    // the only thing that produces `System` (C2), so this never fabricates a system principal.
    Some(match v.kind {
        boatramp_core::tenancy::PrincipalKind::System => {
            boatramp_handlers::SealedPrincipal::System { persona: v.persona }
        }
        boatramp_core::tenancy::PrincipalKind::Tenant => {
            // A Tenant seal always carries `br_ctx` (verify rejects otherwise), so `tenant` is `Some`.
            boatramp_handlers::SealedPrincipal::Tenant {
                tenant: v.tenant?,
                persona: v.persona,
            }
        }
    })
}

/// **Async-lane persona gate battery** (PLAN-async-persona) — mutation-verified, host toolchain.
/// Proves the host mechanism is fail-closed: a valid seal yields the host-verified `{tenant,
/// persona}`; an absent / anchor-less / expired / forged / garbage seal yields NONE (so a consumer's
/// `current-principal()` returns `none` and a `role(…)` field fails closed); the terminal-outcome
/// taxonomy distinguishes each reason (an expired seal is NOT lumped with a forged one — the
/// operator's "re-ingest from source" signal); and the untrusted guest DLQ detail is
/// injection-sanitized + bounded. Each assertion is anti-hollow: a fail-closed→open mutation, a
/// collapsed reason, or a dropped sanitizer step turns it red.
#[cfg(all(test, feature = "handlers"))]
mod persona_seal_gate {
    use super::*;
    use boatramp_core::cose::{LocalSigner, TokenAlg, mint_context};

    fn now() -> u64 {
        boatramp_core::time::now_unix()
    }

    #[tokio::test]
    async fn resolve_sealed_principal_is_fail_closed_on_every_bad_seal() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let anchor = signer.public_key();
        // A valid, current seal → the host-verified {tenant, persona}.
        let sealed = mint_context("acme", Some("Integration"), 300, now(), &signer)
            .await
            .unwrap();
        let p = resolve_sealed_principal(Some(&sealed), Some(&anchor))
            .expect("a valid seal resolves the principal");
        assert_eq!(p.tenant(), Some("acme"));
        assert_eq!(p.persona(), Some("Integration"));
        // Fail-closed #1 — ABSENT envelope (a producer that never presented a token).
        assert!(resolve_sealed_principal(None, Some(&anchor)).is_none());
        // Fail-closed #2 — NO fleet anchor wired ⇒ nothing can verify.
        assert!(resolve_sealed_principal(Some(&sealed), None).is_none());
        // Fail-closed #3 — EXPIRED (minted in 1970 with a 1s TTL vs the real wall clock).
        let expired = mint_context("acme", Some("Integration"), 1, 1000, &signer)
            .await
            .unwrap();
        assert!(
            resolve_sealed_principal(Some(&expired), Some(&anchor)).is_none(),
            "an expired seal must not resolve a persona"
        );
        // Fail-closed #4 — FORGED (a stranger's key never verifies the fleet signature).
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        assert!(
            resolve_sealed_principal(Some(&sealed), Some(&stranger.public_key())).is_none(),
            "a seal not signed by the fleet anchor must not resolve"
        );
        // Fail-closed #5 — GARBAGE token.
        assert!(resolve_sealed_principal(Some("not-a-cose-token"), Some(&anchor)).is_none());
    }

    #[tokio::test]
    async fn classify_seal_distinguishes_every_terminal_reason() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let anchor = signer.public_key();
        let good = mint_context("acme", None, 300, now(), &signer)
            .await
            .unwrap();
        assert!(matches!(
            classify_seal(Some(&good), Some(&anchor)),
            SealOutcome::Verified
        ));
        // Missing — no envelope on a templated consumer (the producer didn't present a token).
        assert!(matches!(
            classify_seal(None, Some(&anchor)),
            SealOutcome::Missing
        ));
        // Invalid — no anchor wired.
        assert!(matches!(
            classify_seal(Some(&good), None),
            SealOutcome::Invalid
        ));
        // Invalid — forged (a stranger's signature).
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        assert!(matches!(
            classify_seal(Some(&good), Some(&stranger.public_key())),
            SealOutcome::Invalid
        ));
        // Expired — the anti-hollow crux: a well-signed but stale seal is Expired, NOT Invalid, so the
        // operator gets the honest "re-ingest from source" reason instead of a "forged" red herring.
        let expired = mint_context("acme", None, 1, 1000, &signer).await.unwrap();
        assert!(
            matches!(
                classify_seal(Some(&expired), Some(&anchor)),
                SealOutcome::Expired
            ),
            "a well-signed past-TTL seal must classify as Expired, not Invalid"
        );
    }

    #[test]
    fn sanitize_dlq_detail_strips_injection_and_bounds() {
        // Control chars (newline / CR / tab / NUL / ESC) are stripped — no DLQ-record or log-line
        // injection from untrusted guest text.
        let dirty = "denied: role\nInjected: FAKE\r\tvalue\u{0}\u{1b}[31m";
        let clean = sanitize_dlq_detail(dirty);
        assert!(!clean.contains('\n') && !clean.contains('\r') && !clean.contains('\t'));
        assert!(!clean.contains('\u{0}') && !clean.contains('\u{1b}'));
        // Content survives (collapsed to a single printable line).
        assert!(clean.contains("denied: role"));
        assert!(clean.contains("Injected: FAKE"));
        // Bounded (defense-in-depth) at the engine cap.
        let huge = "a ".repeat(boatramp_handlers::MAX_CONSUMER_ERROR_LEN);
        assert!(sanitize_dlq_detail(&huge).len() <= boatramp_handlers::MAX_CONSUMER_ERROR_LEN);
        // All-control input → empty (the caller then falls back to the bare host label).
        assert!(sanitize_dlq_detail("\n\r\t\u{0}").is_empty());
    }
}

/// The tenant-seal bind-verify **mutation seam** (anti-hollow gate). In a non-test build this is a
/// hard `false` — the check is ALWAYS enforced in the shipped binary (there is no runtime toggle, so
/// a production process can never be tricked into skipping it). In a `cfg(test)` build a THREAD-LOCAL
/// flag ([`with_tenant_seal_check_skipped`]) lets the gate neuter the check ON ITS OWN THREAD ONLY,
/// so a concurrent consumer-dispatch test in the same process is unaffected (a process-global env var
/// would race across the parallel test harness — the flake this avoids). When set, a message whose
/// sealed tenant does NOT match its concrete `{tenant}` topic segment is DELIVERED instead of
/// quarantined; the gate asserts the clean lane quarantines and the mutated lane delivers — a
/// two-sided property proving the check is load-bearing. Unlike the older env-var mutation seams
/// elsewhere in the tree, this is a TEST-ONLY THREAD-LOCAL — there is NO env var and NO runtime
/// path, so it is both race-free across the parallel harness and impossible to trip in production.
#[cfg(all(feature = "handlers", not(test)))]
fn tenant_seal_mutate_skip() -> bool {
    false
}

#[cfg(all(feature = "handlers", test))]
thread_local! {
    static TENANT_SEAL_MUTATE_SKIP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(all(feature = "handlers", test))]
fn tenant_seal_mutate_skip() -> bool {
    TENANT_SEAL_MUTATE_SKIP.with(std::cell::Cell::get)
}

/// Test-only: run `f` with the tenant-seal bind-verify check NEUTERED on THIS thread (the anti-hollow
/// mutation lane). Restores the prior value after, so the neuter is scoped to `f` and never leaks to
/// a sibling test thread.
#[cfg(all(feature = "handlers", test))]
pub(super) async fn with_tenant_seal_check_skipped<F, Fut, T>(f: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    TENANT_SEAL_MUTATE_SKIP.with(|c| c.set(true));
    let out = f().await;
    TENANT_SEAL_MUTATE_SKIP.with(|c| c.set(false));
    out
}

#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch_consumer_batch(
    engine: &boatramp_handlers::HandlerEngine,
    messaging: &dyn boatramp_core::messaging::Messaging,
    metrics: &metrics::Metrics,
    site: &str,
    namespaced_topic: &str,
    scope_prefix: &str,
    // Empty `group` = the default work-queue (one consumer per message); a
    // non-empty group is a durable fan-out subscriber with its own cursor.
    group: &str,
    start: boatramp_core::messaging::StartPosition,
    component_hash: &str,
    component: &[u8],
    bindings: &boatramp_handlers::Bindings,
    // `Some` for a consumer declaring `sources: [signed_context]`: rebuild the bindings per message
    // from that message's sealed envelope (the `bindings` above is then unused). `None` ⇒ reuse the
    // built-once `bindings` (non-signed-context consumer).
    rebuild: Option<&ConsumerRebuild<'_>>,
    // SECURITY CRUX (v0.7.1 tenant-template bind-verify, Item 3): `Some(t)` when THIS concrete topic
    // was reached via a `{tenant}` template match — `t` is the concrete topic's bound `{tenant}`
    // segment. Every drained message's sealed `signed_context` tenant MUST equal `t`; a message whose
    // sealed tenant differs (or is absent/unverifiable) is QUARANTINED — dead-lettered into THIS
    // concrete topic's DLQ with reason `tenant-seal-mismatch`, never delivered, never plain-retried
    // (a permanent anomaly). `None` ⇒ a non-templated exact match: no bound tenant, no check
    // (unchanged). The sealed tenant is resolved from the message envelope via `context_anchor`,
    // independent of whether the consumer declares the `signed_context` tenancy source.
    expected_tenant: Option<&str>,
    // The fleet signer's public half — the anchor the durable `signed_context` envelope is verified
    // against (the SAME key `mint_context`/`verify_context` use). Threaded so the bind-verify resolves
    // a message's sealed tenant EVEN when the consumer does not declare the `signed_context` tenancy
    // source (so `rebuild` is `None`). Absent (no fleet signer wired) ⇒ a templated topic cannot
    // verify any envelope, so EVERY message on it fails closed (quarantine) — a templated subscription
    // is meaningless without the anchor. Ignored when `expected_tenant` is `None` (non-templated).
    context_anchor: Option<&boatramp_core::cose::TokenPublicKey>,
    limits: boatramp_handlers::Limits,
    lease: Duration,
    max_attempts: u32,
    batch: usize,
    max_ack_pending: Option<usize>,
    // Per-consumer redelivery backoff base (ms); the redelivery of a failed message is held
    // `backoff_ms × attempts` before it's claimable again. 0 ⇒ immediate (historical behavior).
    backoff_ms: u64,
    // Per-consumer concurrency cap (P2 resource isolation): `Some(n>0)` bounds this consumer to
    // `min(n, async-lane)` simultaneous invocations node-wide (acquired around each `dispatch_message`
    // via the engine's per-consumer semaphore), so one consumer's burst can't occupy the shared async
    // lane and starve others. `None`/0 ⇒ shares the lane budget as before (no regression).
    consumer_max_concurrency: Option<usize>,
) -> usize {
    // Flow control (P2 MaxAckPending): cap the claim so total leased-but-unacked never exceeds the
    // ceiling, across ticks. `in_flight_count` is the topic's outstanding (a slight over-count for a
    // single group — the safe direction: it caps sooner). At/over the cap, claim nothing this tick.
    let batch = match max_ack_pending {
        Some(cap) => {
            let in_flight = messaging
                .in_flight_count(namespaced_topic)
                .await
                .unwrap_or(0);
            let available = cap.saturating_sub(in_flight);
            if available == 0 {
                return 0;
            }
            batch.min(available)
        }
        None => batch,
    };
    let claimed = match messaging
        .claim_grouped(namespaced_topic, group, start, lease, batch, max_attempts)
        .await
    {
        Ok(claimed) => claimed,
        Err(err) => {
            tracing::warn!(topic = namespaced_topic, %err, "messaging claim failed");
            return 0;
        }
    };
    let mut acked = 0;
    // Gap 3 isolation: the batch reuses one `Bindings` (hence one shared producer-context cell)
    // across every message. A `tenancy::present-token` earlier in the batch host-seals that cell,
    // so WITHOUT this reset a later message that does not present (or whose token fails) would
    // publish under the PRIOR message's tenant — a cross-tenant misattribution on the async lane.
    // Snapshot the bind-time value and restore it before each message so `present-token` is
    // strictly per-message (never carried across a batch).
    let bind_time_context = bindings
        .producer_context_cell()
        .and_then(|cell| cell.lock().ok().and_then(|guard| guard.clone()));
    // P2 resource isolation: resolve the per-consumer concurrency gate ONCE per batch (the key +
    // semaphore are loop-invariant — `site`/`namespaced_topic`/`group` are batch-level). Each message
    // then only `.acquire_owned()`s a permit off this Arc, so the engine's gate map is locked once per
    // batch, not once per message. `None` ⇒ the consumer declared no `max_concurrency` (shares the lane).
    let consumer_gate = match consumer_max_concurrency {
        Some(cap) if cap > 0 => {
            Some(engine.consumer_gate(&format!("{site}\u{1}{namespaced_topic}\u{1}{group}"), cap))
        }
        _ => None,
    };
    for msg in claimed {
        // SECURITY CRUX (v0.7.1 tenant-template bind-verify, Item 3). This concrete topic was reached
        // via a `{tenant}` template match ⇒ `expected_tenant = Some(bound)`, `bound` being the topic's
        // concrete `{tenant}` segment. Verify the message's SEALED originator tenant (resolved from its
        // durable `signed_context` envelope against the fleet anchor — signature + expiry + kind, the
        // SAME `verify_context` the `signed_context` tenancy source uses) EQUALS `bound`. A mismatch —
        // or an absent/unverifiable envelope — is a PERMANENT anomaly (a message sealed for tenant A can
        // never legitimately run off `sync/B/import`), so QUARANTINE it fail-closed: dead-letter into
        // THIS concrete topic's DLQ (per-tenant DLQ preserved), never deliver, never plain-retry.
        //
        // The seal (`signed_context`), NOT the topic segment, is the authority: the topic segment only
        // SELECTS which bound value the seal must match, so a templated delivery does not weaken the
        // per-message seal (the topic is operational; the seal is the security boundary). A
        // non-templated topic passes `None` here — no bound tenant, no check (unchanged).
        if let Some(bound) = expected_tenant {
            let sealed = resolve_sealed_tenant(msg.signed_context.as_deref(), context_anchor);
            // The mutation seam (anti-hollow gate): a TEST-ONLY thread-local (see
            // `tenant_seal_mutate_skip`) that, when set, SKIPS the check so a mismatched message
            // DELIVERS instead of quarantining — the gate asserts the clean lane quarantines and the
            // mutated lane delivers, proving the check is load-bearing. No env var, no production path.
            let skip_check = tenant_seal_mutate_skip();
            // Defense-in-depth: an empty bound can NEVER match (a `{tenant}` segment is provably
            // non-empty today — the matcher rejects empty captures — so this only guards a future
            // matcher refactor from letting `Some("") == Some("")` deliver cross-tenant).
            let matches = !bound.is_empty() && sealed.as_deref() == Some(bound);
            if !skip_check && !matches {
                // Fail-closed quarantine. `dead_letter` is TERMINAL (no redelivery). If the backend
                // can't dead-letter (unsupported), STILL refuse to deliver (a plain nack redelivers
                // the same anomaly forever, but never delivers it cross-tenant — fail-closed).
                //
                // Legible terminal-outcome taxonomy (PLAN-async-persona): distinguish WHY the seal
                // isn't a verified match — a message with a well-signed seal for a DIFFERENT tenant is
                // `tenant-seal-mismatch` (the v0.7.1 meaning, unchanged), but an EXPIRED / ABSENT /
                // INVALID seal each gets its own operator-legible reason (an expired seal can't be
                // revived → re-ingest from source; a missing/invalid one points at a producer that
                // didn't `present_token`). The reason is persisted as the DLQ `last_error` by
                // `dead_letter`, so `dlq ls/show` shows it in one read.
                let (reason, operator_msg): (&str, &str) = match classify_seal(
                    msg.signed_context.as_deref(),
                    context_anchor,
                ) {
                    // A verified seal that simply names a different tenant than this concrete
                    // topic — the original v0.7.1 cross-tenant anomaly.
                    SealOutcome::Verified => (
                        "tenant-seal-mismatch",
                        "sealed tenant does not match this concrete `{tenant}` topic segment",
                    ),
                    SealOutcome::Expired => (
                        "context-seal-expired",
                        "the message's signed context expired before it was consumed; the seal \
                             cannot be revived — re-ingest from source",
                    ),
                    SealOutcome::Missing => (
                        "context-seal-missing",
                        "the message carried no signed context on a templated (`{tenant}`) topic; \
                             the producer did not present a token",
                    ),
                    SealOutcome::Invalid => (
                        "context-seal-invalid",
                        "the message's signed context failed verification (forged / wrong-kind / \
                             no fleet anchor); the seal is not trusted",
                    ),
                };
                match messaging.dead_letter(&msg, reason).await {
                    Ok(()) => {}
                    Err(err) => {
                        tracing::warn!(
                            id = msg.id,
                            topic = namespaced_topic,
                            %err,
                            reason,
                            "seal quarantine could not be recorded (backend has no DLQ); \
                             refusing delivery"
                        );
                        // Do NOT deliver. Leave the message leased (it re-claims on lease expiry and
                        // quarantines again once a DLQ-capable backend is present) — never delivered
                        // to the wrong tenant.
                    }
                }
                metrics.observe(
                    site,
                    metrics::Trigger::Consumer,
                    msg.topic.strip_prefix(scope_prefix).unwrap_or(&msg.topic),
                    component_hash,
                    metrics::Outcome::Error,
                    std::time::Duration::ZERO,
                    // Pre-delivery refusal — no serve; consumer-lane instance timing lives in the
                    // per-lane + per-component stats.
                    None,
                    None,
                );
                tracing::warn!(
                    id = msg.id,
                    topic = namespaced_topic,
                    expected_tenant = bound,
                    sealed_tenant = sealed.as_deref().unwrap_or("<none>"),
                    reason,
                    "quarantined a message on a `{{tenant}}` topic ({operator_msg})"
                );
                continue;
            }
        }
        // Per-message bindings. A `signed_context` consumer (R1 async lane) is rebuilt from THIS
        // message's host-sealed envelope, so the originator's tenant resolves onto its orm/sql scope
        // AND the `graphql::run` caller principal — symmetric to the `FnTenant::Durable` drain path,
        // and per-message-isolated for free (a fresh binding, own producer-context cell). A consumer
        // that does not declare `signed_context` reuses the built-once binding; its shared cell is
        // reset to bind-time first (Gap 3: a `present-token` earlier in the batch must not carry to a
        // later message that doesn't present — a cross-tenant misattribution on the async lane).
        let per_msg_bindings = match rebuild {
            Some(rb) => match rb.bindings_for(msg.signed_context.as_deref()).await {
                Ok(b) => b,
                Err(err) => {
                    tracing::warn!(
                        id = msg.id,
                        %err,
                        "consumer per-message bindings refused; redelivering"
                    );
                    let _ = messaging
                        .nack_after(&msg, backoff_ms.saturating_mul(u64::from(msg.attempts)))
                        .await;
                    continue;
                }
            },
            None => {
                if let Some(cell) = bindings.producer_context_cell()
                    && let Ok(mut guard) = cell.lock()
                {
                    *guard = bind_time_context.clone();
                }
                bindings.clone()
            }
        };
        let guest_topic = msg.topic.strip_prefix(scope_prefix).unwrap_or(&msg.topic);
        let start = std::time::Instant::now();
        // P2 resource isolation: hold a per-consumer permit across this invocation (off the
        // once-per-batch `consumer_gate` resolved above), so at most `min(max_concurrency, async-lane)`
        // of THIS consumer run at once node-wide and a burst can't monopolize the shared async lane.
        // Cloning the `Arc` + `acquire_owned` is the only per-message cost (no key alloc, no map lock).
        let _consumer_permit = match &consumer_gate {
            Some(sem) => Some(
                sem.clone()
                    .acquire_owned()
                    .await
                    .expect("per-consumer semaphore is never closed"),
            ),
            None => None,
        };
        let result = engine
            .dispatch_message(
                component_hash,
                component,
                guest_topic,
                &msg.payload,
                per_msg_bindings,
                limits,
            )
            .await;
        let outcome = metrics::Outcome::from_result(&result);
        metrics.observe(
            site,
            metrics::Trigger::Consumer,
            guest_topic,
            component_hash,
            outcome,
            start.elapsed(),
            // Consumer lane serves via `dispatch_message` (not `serve_lane`); its cold/instantiate
            // cost is captured in the consumer per-lane counters + the per-component stats.
            None,
            None,
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
                // Record the failure reason so it survives into the dead-letter for `dlq ls/show` +
                // `--match`, ONLY on the final attempt (whose failure dead-letters the message next
                // claim): last_error means "why it dead-lettered", not a transient retry — and this
                // keeps the hot redelivery path a single write (nack). Best-effort — annotating must
                // never block redelivery. The reason is the host-classified label (`trap`, `timeout`,
                // …) EXCEPT for a clean guest `Err`, where we ALSO surface the guest's returned text
                // (PLAN-async-persona: a denied downstream op must read as `consumer-error: <why>`, not
                // an opaque label — the multi-day-diagnosis fix). The guest text is UNTRUSTED: already
                // length-bounded at the engine (`MAX_CONSUMER_ERROR_LEN`) and sanitized here (control
                // chars stripped) so it cannot injection-corrupt the DLQ / a downstream log line. This
                // deliberately narrows the prior "never the guest's error text" rule to ONLY the
                // clean-error case, keeping the host label authoritative as the greppable prefix.
                if msg.attempts >= max_attempts {
                    let reason = match &err {
                        boatramp_handlers::HandlerError::ConsumerError(detail) => {
                            let d = sanitize_dlq_detail(detail);
                            if d.is_empty() {
                                outcome.as_str().to_string()
                            } else {
                                format!("{}: {d}", outcome.as_str())
                            }
                        }
                        _ => outcome.as_str().to_string(),
                    };
                    let _ = messaging.set_last_error(&msg, &reason).await;
                }
                let _ = messaging
                    .nack_after(&msg, backoff_ms.saturating_mul(u64::from(msg.attempts)))
                    .await;
            }
        }
    }
    acked
}

#[cfg(all(test, feature = "handlers"))]
mod vhost_tests {
    use super::*;

    #[test]
    fn a_wildcard_routed_request_carries_the_real_public_host_to_the_guest() {
        // A tenant host routed via a *wildcard* site: the guest must still see the **real** Host
        // so it can resolve tenant-by-host. The host survives on the `Host` header AND becomes the
        // `wasi:http` request authority (the URI the guest observes), plus `X-Forwarded-Host`. The
        // URI rewrite swaps only the *path* to the site-relative form — it never rewrites the host.
        let mut req = Request::builder()
            .method("GET")
            .uri("/_sites/portal/dashboard?tenant=7")
            .header("host", "tenant7.construens.com")
            .body(Body::empty())
            .unwrap();
        set_forwarded_headers(&mut req, std::net::IpAddr::from([203, 0, 113, 9]));
        rewrite_request_uri(&mut req, "/dashboard");
        // The guest's `wasi:http` request authority is the real public host — not `localhost`, and
        // not the internal `/_sites/<site>/…` form. This is what a handler resolving its tenant
        // reads off the incoming request.
        assert_eq!(req.uri().host(), Some("tenant7.construens.com"));
        assert_eq!(req.uri().path(), "/dashboard");
        assert_eq!(req.uri().query(), Some("tenant=7"));
        // The `Host` header is preserved verbatim (the other channel a guest may read).
        assert_eq!(
            req.headers().get(header::HOST).unwrap(),
            "tenant7.construens.com"
        );
        // ...and mirrored to `X-Forwarded-Host`.
        assert_eq!(
            req.headers().get("x-forwarded-host").unwrap(),
            "tenant7.construens.com"
        );
    }
}

#[cfg(all(test, feature = "handlers"))]
mod sql_grant_tests {
    use super::granted_sql_databases;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().copied().map(String::from).collect()
    }

    #[test]
    fn bare_sql_grants_only_the_default_database() {
        // Backward-compatible: `sql` on both sides → the default (`""`) database, nothing named.
        assert_eq!(granted_sql_databases(&v(&["sql"]), &v(&["sql"])), v(&[""]));
        // Bare `sql` granted by only one side → nothing (the existing intersection).
        assert!(granted_sql_databases(&v(&["sql"]), &v(&[])).is_empty());
        assert!(granted_sql_databases(&v(&[]), &v(&["sql"])).is_empty());
    }

    #[test]
    fn a_named_grant_is_the_intersection_and_the_site_is_the_ceiling() {
        // The handler asks for `product`; the site exposes it → granted.
        assert_eq!(
            granted_sql_databases(&v(&["sql:product"]), &v(&["sql:product"])),
            v(&["product"])
        );
        // The handler asks for `privileged` but the site exposes only `product` → fail-closed.
        assert!(granted_sql_databases(&v(&["sql:privileged"]), &v(&["sql:product"])).is_empty());
        // Least-privilege: a `product`-only handler on a site that also exposes `privileged`
        // never receives the `privileged` backend.
        assert_eq!(
            granted_sql_databases(
                &v(&["sql", "sql:product"]),
                &v(&["sql", "sql:product", "sql:privileged"]),
            ),
            v(&["", "product"])
        );
    }

    #[test]
    fn a_handler_wildcard_grants_every_name_the_site_exposes() {
        // `sql:*` on the handler → every named database the site enumerates (but not the default,
        // which is the bare `sql`).
        assert_eq!(
            granted_sql_databases(&v(&["sql:*"]), &v(&["sql:product", "sql:privileged"])),
            v(&["product", "privileged"])
        );
        // The site is still the ceiling: a `sql:*` handler on a site that exposes only the
        // default (no named entries) gets nothing named.
        assert!(granted_sql_databases(&v(&["sql:*"]), &v(&["sql"])).is_empty());
        // A site-side `sql:*` is not a concrete name — the site must enumerate — so it grants
        // nothing named even to a wildcard handler.
        assert!(granted_sql_databases(&v(&["sql:*"]), &v(&["sql:*"])).is_empty());
    }
}

/// The host-side capability minter (PLAN-delegable-capabilities): signs a target capability with the
/// fleet [`Signer`](boatramp_core::cose::Signer), stamping the audience to the minting project. The
/// audience host-forcing (R1), the TTL clamp (R5), and the app-context bounds (R6) are enforced by the
/// [`CapabilityBinding`](boatramp_handlers::CapabilityBinding) before this is called; `mint_capability`
/// re-checks the context bounds authoritatively.
#[cfg(feature = "capability")]
struct ServerCapabilityMinter {
    signer: Arc<dyn boatramp_core::cose::Signer>,
}

#[cfg(feature = "capability")]
#[async_trait::async_trait]
impl boatramp_handlers::CapabilityMinter for ServerCapabilityMinter {
    async fn mint(
        &self,
        project: &str,
        target_tenant: &str,
        public_subset: &str,
        app_context: &std::collections::BTreeMap<String, String>,
        ttl_secs: u64,
    ) -> Result<String, String> {
        boatramp_core::cose::mint_capability(
            target_tenant,
            project, // audience = the minting project (host-forced by the binding, R1)
            public_subset,
            app_context,
            ttl_secs,
            boatramp_core::time::now_unix(),
            self.signer.as_ref(),
        )
        .await
        .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod cookie_auth_tests {
    use super::*;
    use boatramp_core::config::CookieAuthConfig;

    fn cfg(origins: &[&str]) -> CookieAuthConfig {
        CookieAuthConfig {
            cookie_name: "session".to_string(),
            allowed_origins: origins
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in pairs {
            h.insert(
                header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        h
    }

    #[test]
    fn cookie_value_extracts_the_named_cookie() {
        let h = headers(&[("cookie", "a=1; session=tok123; b=2")]);
        assert_eq!(cookie_value(&h, "session").as_deref(), Some("tok123"));
        assert_eq!(cookie_value(&h, "missing"), None);
        assert_eq!(cookie_value(&HeaderMap::new(), "session"), None);
    }

    #[test]
    fn referer_origin_is_the_scheme_host_port() {
        assert_eq!(
            referer_origin("https://app.example.com/a/b?q=1"),
            Some("https://app.example.com".to_string())
        );
        assert_eq!(
            referer_origin("http://localhost:3000/x"),
            Some("http://localhost:3000".to_string())
        );
        assert_eq!(referer_origin("not a url"), None);
    }

    #[test]
    fn origin_check_allows_listed_cross_origins_and_absent_signal_but_rejects_others() {
        // No Host header here, so `is_same_origin` never fires — this exercises purely the
        // *additional cross-origin* allowlist path (a browser app served from a different origin).
        let allowed = ["https://app.example.com".to_string()];
        // Origin present + allowed.
        assert!(origin_allowed(
            &headers(&[("origin", "https://app.example.com")]),
            &allowed
        ));
        // Origin present + not allowed → reject.
        assert!(!origin_allowed(
            &headers(&[("origin", "https://evil.example.net")]),
            &allowed
        ));
        // No Origin, but Referer's origin is allowed.
        assert!(origin_allowed(
            &headers(&[("referer", "https://app.example.com/page")]),
            &allowed
        ));
        // No Origin, Referer's origin not allowed → reject.
        assert!(!origin_allowed(
            &headers(&[("referer", "https://evil.example.net/page")]),
            &allowed
        ));
        // Neither Origin nor Referer (same-origin top-level nav) → allow.
        assert!(origin_allowed(&HeaderMap::new(), &allowed));
    }

    #[test]
    fn origin_check_auto_allows_same_origin_even_with_an_empty_allowlist() {
        // The footgun fix: a page calling its own origin (Origin authority == Host) is
        // same-origin and always passes, so `allowed_origins: []` means "same-origin only",
        // not "non-browser only". An SPA's own `fetch` must never be CSRF-rejected.
        let empty: [String; 0] = [];
        assert!(origin_allowed(
            &headers(&[
                ("host", "app.example.com"),
                ("origin", "https://app.example.com"),
            ]),
            &empty
        ));
        // Same-origin via Referer (no Origin header) also passes.
        assert!(origin_allowed(
            &headers(&[
                ("host", "app.example.com"),
                ("referer", "https://app.example.com/dashboard"),
            ]),
            &empty
        ));
        // Same host, non-default port carried on both Origin and Host → still same-origin.
        assert!(origin_allowed(
            &headers(&[
                ("host", "localhost:3000"),
                ("origin", "http://localhost:3000"),
            ]),
            &empty
        ));
        // A genuine cross-origin request with an empty allowlist → reject (attacker's Origin
        // carries their host, never the target's Host).
        assert!(!origin_allowed(
            &headers(&[
                ("host", "app.example.com"),
                ("origin", "https://evil.example.net"),
            ]),
            &empty
        ));
        // Cross-scheme is *not* rejected on scheme alone (host-based check): the cookie is
        // `Secure` so a same-host http page never carries it — a deliberate, safe relaxation.
        assert!(origin_allowed(
            &headers(&[
                ("host", "app.example.com"),
                ("origin", "http://app.example.com")
            ]),
            &empty
        ));
    }

    #[test]
    fn outcome_injects_a_same_origin_cookie_with_an_empty_allowlist() {
        // The end-to-end footgun regression: same-origin SPA fetch + `allowed_origins: []`.
        let h = headers(&[
            ("cookie", "session=tok"),
            ("host", "app.example.com"),
            ("origin", "https://app.example.com"),
        ]);
        assert!(matches!(
            cookie_auth_outcome(&h, Some(&cfg(&[]))),
            CookieAuthOutcome::Inject(t) if t == "tok"
        ));
    }

    #[test]
    fn outcome_injects_a_listed_cross_origin_cookie() {
        // A browser app served from a *different* origin, explicitly allowlisted.
        let h = headers(&[
            ("cookie", "session=tok"),
            ("host", "api.example.com"),
            ("origin", "https://app.example.com"),
        ]);
        assert!(matches!(
            cookie_auth_outcome(&h, Some(&cfg(&["https://app.example.com"]))),
            CookieAuthOutcome::Inject(t) if t == "tok"
        ));
    }

    #[test]
    fn outcome_rejects_a_cross_origin_cookie_request() {
        let h = headers(&[
            ("cookie", "session=tok"),
            ("host", "app.example.com"),
            ("origin", "https://evil.example.net"),
        ]);
        assert!(matches!(
            cookie_auth_outcome(&h, Some(&cfg(&["https://app.example.com"]))),
            CookieAuthOutcome::Reject
        ));
    }

    #[test]
    fn outcome_lets_the_authorization_header_win() {
        // Both a cookie and a header → the header wins, cookie ignored (API clients unaffected).
        let h = headers(&[
            ("cookie", "session=cookietok"),
            ("authorization", "Bearer headertok"),
            ("origin", "https://evil.example.net"), // even a bad origin doesn't matter here
        ]);
        assert!(matches!(
            cookie_auth_outcome(&h, Some(&cfg(&["https://app.example.com"]))),
            CookieAuthOutcome::None
        ));
    }

    #[test]
    fn outcome_is_none_without_a_cookie_or_config() {
        // No cookie → anonymous (None), so only public fields resolve downstream.
        assert!(matches!(
            cookie_auth_outcome(&HeaderMap::new(), Some(&cfg(&["https://app.example.com"]))),
            CookieAuthOutcome::None
        ));
        // No cookie_auth config → never engaged.
        assert!(matches!(
            cookie_auth_outcome(&headers(&[("cookie", "session=tok")]), None),
            CookieAuthOutcome::None
        ));
    }
}

/// Task #492 per-guest secret allowlist: the pure projection ([`filter_site_secrets`]) and the
/// activation-time admission ([`admit_secret_allowlist`]). These are the two halves the choke point
/// relies on — the filter is what a bound guest actually sees, the admission is what a typo trips.
#[cfg(all(test, feature = "handlers"))]
mod secret_allowlist_tests {
    use super::{admit_secret_allowlist, admit_unscoped_writes, filter_site_secrets};
    use std::collections::BTreeMap;

    fn pool(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn allow(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn filter_keeps_only_declared_keys() {
        let p = pool(&[
            ("SECRET_A", "env:HOST_A"),
            ("SECRET_B", "env:HOST_B"),
            ("SECRET_C", "boatramp:c"),
        ]);
        let scoped = filter_site_secrets(&p, &allow(&["SECRET_A"]));
        // Only the declared key survives — the very property the gate observes (B must be ABSENT).
        assert_eq!(scoped.len(), 1);
        assert!(scoped.contains_key("SECRET_A"));
        assert!(!scoped.contains_key("SECRET_B"));
        assert!(!scoped.contains_key("SECRET_C"));
        // The kept entry's VALUE (the ref) is preserved verbatim for resolution.
        assert_eq!(
            scoped.get("SECRET_A").map(String::as_str),
            Some("env:HOST_A")
        );

        // A multi-name allowlist keeps exactly that set.
        let two = filter_site_secrets(&p, &allow(&["SECRET_A", "SECRET_C"]));
        assert_eq!(two.len(), 2);
        assert!(two.contains_key("SECRET_A") && two.contains_key("SECRET_C"));
        assert!(!two.contains_key("SECRET_B"));
    }

    #[test]
    fn empty_allowlist_passes_the_whole_pool() {
        // The non-breaking default: absent/empty ⇒ inject everything (today's behavior).
        let p = pool(&[("SECRET_A", "env:HOST_A"), ("SECRET_B", "env:HOST_B")]);
        let all = filter_site_secrets(&p, &[]);
        assert_eq!(all, p);
    }

    #[test]
    fn filter_drops_an_unknown_allowlist_name_without_inventing_entries() {
        // The projection is not the enforcement point for typos (admission is) — it must never
        // fabricate a key. An allowlist naming only an unknown key yields an EMPTY scoped map.
        let p = pool(&[("SECRET_A", "env:HOST_A")]);
        let scoped = filter_site_secrets(&p, &allow(&["NOPE"]));
        assert!(scoped.is_empty());
    }

    #[test]
    fn admit_accepts_a_known_allowlist_and_an_empty_one() {
        let p = pool(&[("SECRET_A", "env:HOST_A"), ("SECRET_B", "env:HOST_B")]);
        // Every name is a pool key ⇒ OK.
        admit_secret_allowlist(&p, &allow(&["SECRET_A"]), "handler route \"/a\" [GET]")
            .expect("a known allowlist is admitted");
        // Empty allowlist ⇒ inject-all, always OK (even against an empty pool).
        admit_secret_allowlist(&p, &[], "handler route \"/b\" [GET]").expect("empty is admitted");
        admit_secret_allowlist(&BTreeMap::new(), &[], "handler route \"/c\" [GET]")
            .expect("empty allowlist against empty pool is admitted");
    }

    #[test]
    fn admit_rejects_an_undefined_secret_naming_the_guest_and_the_name() {
        let p = pool(&[("SECRET_A", "env:HOST_A")]);
        let err =
            admit_secret_allowlist(&p, &allow(&["SECRET_TYPO"]), "handler route \"/x\" [POST]")
                .expect_err("an allowlist naming an undefined secret is refused");
        // The error names BOTH the offending guest (its label) and the unknown secret — typo/rot help.
        assert!(
            err.contains("handler route \"/x\" [POST]"),
            "names the guest: {err}"
        );
        assert!(
            err.contains("SECRET_TYPO"),
            "names the unknown secret: {err}"
        );
        // And it lists what IS known, so the fix is obvious.
        assert!(err.contains("SECRET_A"), "lists the known keys: {err}");
    }

    #[test]
    fn admit_rejects_any_allowlist_when_the_site_pool_is_empty() {
        // A guest asking to be granted named secrets while the site defines none is a
        // misconfiguration, not a silent no-op (there is nothing to grant).
        let err = admit_secret_allowlist(
            &BTreeMap::new(),
            &allow(&["SECRET_A"]),
            "consumer \"orders\"",
        )
        .expect_err("a non-empty allowlist against an empty pool is refused");
        assert!(
            err.contains("consumer \"orders\""),
            "names the guest: {err}"
        );
        assert!(
            err.contains("no") && err.contains("[handlers].secrets"),
            "explains the empty pool: {err}"
        );
    }

    // ---- #503: apply-time validation of tenancy.unscoped_writes -------------------------------

    fn schema_503_apply() -> boatramp_core::tenancy::TenancySchema {
        use boatramp_core::tenancy::{TableScope, TenancySchema};
        let mut s = TenancySchema::default();
        s.tables.insert("orders".into(), TableScope::Tenant);
        s.tables
            .insert("countries".into(), TableScope::Unscoped { writable: false });
        s.tables.insert(
            "oauth_state".into(),
            TableScope::Unscoped { writable: true },
        );
        s
    }

    #[test]
    fn admit_unscoped_writes_accepts_a_plain_global_and_empty() {
        let s = schema_503_apply();
        // Empty ⇒ OK, no warnings.
        assert!(
            admit_unscoped_writes(Some(&s), &[], "handler route \"/a\" [GET]")
                .unwrap()
                .is_empty()
        );
        // A plain `unscoped` table is the valid opt-in — accepted, no warning.
        assert!(
            admit_unscoped_writes(
                Some(&s),
                &["countries".to_string()],
                "handler route \"/oauth\" [POST]"
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn admit_unscoped_writes_warns_on_a_redundant_writable_true_entry() {
        // Listing an already-`writable:true` table is redundant (the kind authorizes it) — a WARNING,
        // never a refusal.
        let s = schema_503_apply();
        let warns = admit_unscoped_writes(
            Some(&s),
            &["oauth_state".to_string()],
            "handler route \"/oauth\" [POST]",
        )
        .expect("a redundant entry is a warning, not an error");
        assert_eq!(warns.len(), 1);
        assert!(warns[0].contains("oauth_state") && warns[0].contains("redundant"));
    }

    #[test]
    fn admit_unscoped_writes_refuses_a_tenant_table_and_an_unknown_table() {
        let s = schema_503_apply();
        // A tenant-kind table can NEVER be written unstamped via the list (G1) — refused fail-fast.
        let err = admit_unscoped_writes(
            Some(&s),
            &["orders".to_string()],
            "handler route \"/x\" [POST]",
        )
        .expect_err("a tenant table in the allowlist is refused");
        assert!(err.contains("handler route \"/x\" [POST]") && err.contains("orders"));
        assert!(err.contains("per-tenant"), "explains the kind: {err}");
        // An unknown table names the guest + the table + lists the known tables.
        let err2 =
            admit_unscoped_writes(Some(&s), &["typo_table".to_string()], "consumer \"jobs\"")
                .expect_err("an unknown table is refused");
        assert!(err2.contains("consumer \"jobs\"") && err2.contains("typo_table"));
        assert!(
            err2.contains("orders") && err2.contains("countries"),
            "lists known: {err2}"
        );
    }

    #[test]
    fn admit_unscoped_writes_refuses_a_list_with_no_project_schema() {
        // A route listing write-global tables while the project has NO schema can never fire at
        // runtime (legacy Uniform) — refuse it fail-fast rather than silently no-op.
        let err = admit_unscoped_writes(
            None,
            &["countries".to_string()],
            "handler route \"/a\" [GET]",
        )
        .expect_err("a list with no project schema is refused");
        assert!(err.contains("no tenancy schema") && err.contains("countries"));
    }
}
