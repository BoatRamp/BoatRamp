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
    if let Some(gql) = site_handlers.graphql.as_ref().filter(|g| g.enabled) {
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
                    if gql.persisted_queries || gql.safelist {
                        match graphql_apq::resolve_stored(
                            inner.kv.as_ref(),
                            &scope,
                            &json,
                            gql.safelist,
                        )
                        .await
                        {
                            graphql_apq::Resolved::Error(msg) => {
                                return graphql_apq::error_response(&msg)
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
                    // GraphQL subscription: serve it as a graphql-sse event stream,
                    // deriving the messaging topic from the subscription's root field. A
                    // producer (a mutation, a function) publishes each execution result to
                    // that topic; the host frames it as graphql-sse `next`.
                    if let Some(topic) = graphql_subscription::subscription_topic(query) {
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
    let cache_cfg = handler_cache::config_for(site_handlers);
    let cache_key = cache_cfg.as_ref().and_then(|cfg| {
        handler_cache::request_lookupable(cfg, request.method()).then(|| {
            let path_and_query = request.uri().path_and_query().map_or("/", |pq| pq.as_str());
            handler_cache::cache_key(&scope, request.method(), path_and_query)
        })
    });
    if let Some(key) = &cache_key {
        if let Some(hit) = handler_cache::lookup_response(
            inner.kv.as_ref(),
            key,
            request.headers(),
            handler_cache::now_secs(),
        )
        .await
        {
            return hit;
        }
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
    let wasm = match read_blob_fully(deploy, &entry.hash).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };

    // The correlation id assigned by the access-log layer, so captured guest logs carry the
    // same id as the request's `boatramp::access` line.
    let request_id = request
        .extensions()
        .get::<crate::RequestId>()
        .map(|r| r.0.clone());
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
        // A site handler is the entry point of a call chain (reached over HTTP), so it
        // invokes siblings at depth 0; the host caps each subsequent hop.
        0,
        request_id.as_deref(),
    )
    .await
    {
        Ok(bindings) => bindings,
        // A refused secret ref (host-env ref under the multi-tenant posture, or an
        // unsupported scheme) fails the handler closed rather than instantiating it
        // with a leaked or missing value.
        Err(err) => {
            tracing::warn!(site, route = %handler.route, %err, "handler bindings refused");
            return handler_unavailable();
        }
    };

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
    // A streaming handler runs on the isolated streaming lane (its own concurrency budget + a
    // much larger wall-clock), so a long-lived SSE/token stream never holds a fast-request slot;
    // a buffered handler stays on the tight sync request lane.
    let result = if handler.streaming {
        inner
            .engine
            .serve_with_limits_streaming(&entry.hash, &wasm, request, bindings, limits)
            .await
    } else {
        inner
            .engine
            .serve_with_limits(&entry.hash, &wasm, request, bindings, limits)
            .await
    };
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
    }
}

/// The federation gateway: load the project's composed supergraph, plan `query` against
/// it, execute the plan by dispatching each fetch to its subgraph function over the
/// in-process invoke path, and return the stitched `{ "data": … }` response.
#[cfg(feature = "handlers")]
async fn federation_gateway(
    inner: &HandlerRuntimeInner,
    project: &str,
    query: &str,
    variables: &serde_json::Value,
    bearer: Option<&str>,
) -> Response {
    // Compose + plan, memoized per project by composition version (and the operation hash for
    // the plan) — the same `graphql_cache` the in-process `graphql::run` path uses, so neither
    // path re-lists/re-parses/re-plans a graph that only changes on deploy.
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
                .into_response()
        }
    };
    let op_hash = crate::graphql_apq::sha256_hex(query);
    let plan =
        match inner
            .graphql_cache
            .plan(project, cached.version, &op_hash, query, &cached.supergraph)
        {
            Ok(plan) => plan,
            Err(_) => {
                return graphql_guard::error_response(
                    "the query cannot be planned against the supergraph",
                )
            }
        };
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
    let runner = crate::graphql_gateway::BackendRouter::new(
        invoker.scoped(boatramp_core::project::ProjectRef::new(project)),
        project.to_string(),
        inner.sql.clone(),
        sql_subgraphs,
        bearer.map(str::to_string),
    );
    axum::Json(crate::graphql_gateway::execute(&plan, &runner, variables).await).into_response()
}

/// The declarative data connector: serve a GraphQL query from the site's managed database.
/// Resolve the site's SQL backend, introspect it into a schema, build the deny-by-default
/// policy from `[handlers.graphql.data]`, and compile + run the query to SQL — returning the
/// GraphQL response. The backend is opened with the same project/site scoping handlers use,
/// so tenant isolation is inherited; the policy's row filter binds the host-asserted
/// `project` claim, plus any claims from a verified app bearer token (`bearer`) when the site
/// configures `claims_from_token`.
#[cfg(feature = "handlers")]
async fn data_connector_serve(
    inner: &HandlerRuntimeInner,
    project: &str,
    site: &str,
    cfg: &boatramp_core::config::HandlerGraphqlDataConfig,
    query: &str,
    variables: &serde_json::Value,
    bearer: Option<&str>,
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
    let claims = crate::graphql_data::request_claims(project, bearer, cfg).await;
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
        // this project); the connector is the root of that call chain (depth 0).
        let invoker = inner
            .invoker
            .get()
            .map(|inv| inv.scoped(boatramp_core::project::ProjectRef::new(project)));
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
    if is_consumer {
        inner
            .engine
            .precompile_consumer(&entry.hash, &wasm)
            .map_err(|err| {
                let e = err.to_string();
                translate_link_error(label, &e).unwrap_or_else(|| {
                    format!("{label} is not a valid wasi:messaging consumer: {e}")
                })
            })?;
    } else {
        inner.engine.precompile(&entry.hash, &wasm).map_err(|err| {
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
#[allow(clippy::too_many_arguments)]
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
    depth: u32,
    request_id: Option<&str>,
) -> Result<boatramp_handlers::Bindings, String> {
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
    if let Some(provider) = &inner.sql {
        // The SQL provider validates + qualifies `project`/`site` internally (it rejects a
        // `/`-bearing composite `site`), so pass the *raw* project + bare site here — never the
        // already-qualified `scope`. Each granted database is opened independently; a provider
        // error is logged and that binding left ungranted (the guest sees `access denied` for
        // that name, not a 500 for the whole request), so one broken database can't fail the
        // others. A preview routes through `preview_database` so a named external DB honors its
        // `allow_preview`.
        for name in granted_sql_databases(imports, &site_handlers.allow_imports) {
            let opened = match preview {
                Some(id) => {
                    provider
                        .preview_database(project.as_str(), site, &name, id)
                        .await
                }
                None => provider.database(project.as_str(), site, &name).await,
            };
            match opened {
                Ok(backend) => bindings = bindings.with_sql(name.clone(), backend),
                Err(err) => {
                    tracing::warn!(site, database = %name, %err, "opening SQL database failed");
                }
            }
        }
    }
    if granted("wasi:messaging") {
        // Plain topics are namespaced under the binding `scope` (the site, or the
        // preview scope), so a guest publishes only into its own namespace and
        // previews can't touch live topics; `bus:<topic>` publishes route to the
        // shared, project-scoped bus.
        if let Some(messaging) = &inner.messaging {
            bindings = bindings.with_messaging(
                format!("{scope}/"),
                format!("{}/", project.qualified("bus")),
                messaging.clone(),
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
    if granted("invoke") && !invoke_targets.is_empty() {
        if let Some(invoker) = inner.invoker.get() {
            // A site handler invokes siblings within its own tenant project.
            bindings =
                bindings.with_invoke(invoker.scoped(project), invoke_targets.to_vec(), depth);
        }
    }
    // GraphQL supergraph capability: a handler may run a GraphQL operation against the project's
    // composed supergraph in-process (cross-subgraph planning), forwarding its own bearer.
    // Granted when the site allows `graphql`, the handler imports it, and the runtime has a
    // supergraph runner. The handler is the root of the call chain (depth 0); the host caps the
    // next hop against the depth budget shared with invoke.
    if granted("graphql") {
        if let Some(runner) = inner.federation_runner.get() {
            bindings = bindings.with_graphql(runner.scoped(project), depth);
        }
    }
    // Per-project SMTP email gateway: a handler may submit a finished message to one
    // of the project's SMTP profiles. Granted when the site allows `email`, the
    // handler imports it, and the runtime offers email (a spool + profile store are
    // set — gated at startup by the `allow_guest_email` posture). The SMTP
    // credentials are resolved host-side and never exposed to the guest.
    #[cfg(feature = "email")]
    if granted("email") {
        if let (Some(store), Some(spool)) =
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
        allow_env_secret_refs,
        inner.secret_store.get().map(std::convert::AsRef::as_ref),
    )
    .await?;
    bindings = bindings.with_env(env);
    Ok(bindings)
}

/// Assemble the guest environment: static deploy `env` first, then site
/// `secrets` resolved from the host environment (a missing referent is logged
/// and skipped, never injected as empty). A secret name overrides a static one.
///
/// `allow_env_secret_refs` is the security posture's `allow_env_secret_refs`
/// (on under single-tenant/dev, off under multi-tenant): when off, a bare /
/// `env:`-scheme ref is **refused** (fail-closed) so an untrusted tenant's
/// `secrets` map can't name an arbitrary host env var to exfiltrate it.
#[cfg(feature = "handlers")]
pub(super) async fn resolve_env(
    site: &str,
    project: boatramp_core::project::ProjectRef<'_>,
    deploy_env: &std::collections::BTreeMap<String, String>,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    allow_env_secret_refs: bool,
    secret_store: Option<&boatramp_core::secret_store::SecretStore>,
) -> Result<Vec<(String, String)>, String> {
    resolve_secret_env(
        site,
        project,
        deploy_env,
        &site_handlers.secrets,
        allow_env_secret_refs,
        secret_store,
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
                match std::env::var(host_var) {
                    Ok(value) => {
                        env.retain(|(k, _)| k != guest_name);
                        env.push((guest_name.clone(), value));
                    }
                    Err(_) => tracing::warn!(
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
    limits: boatramp_handlers::Limits,
    lease: Duration,
    max_attempts: u32,
    batch: usize,
) -> usize {
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
