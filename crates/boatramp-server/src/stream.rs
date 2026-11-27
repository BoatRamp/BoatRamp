//! Live topic streaming — the SSE and WebSocket fan-out of `wasi:messaging`
//! topics, with per-connection and per-IP permit accounting (RAII-reclaimed).
//! `handlers`-gated; pulls the serve-pipeline scope in via `use super::*`.

use super::*;

/// SSE heartbeat interval: a `: keep-alive` comment is emitted this often so a
/// dead client (whose buffer never drains) is detected and its connection — and
/// the permits it holds — reclaimed.
///
/// `pub(super)` so the external bus-consumer durable-stream surface
/// ([`crate::bus_consumer`], PLAN-messaging-consumer-delivery (b)) reuses the SAME heartbeat
/// cadence as the configured-stream fan-out.
#[cfg(feature = "handlers")]
pub(super) const STREAM_HEARTBEAT: Duration = Duration::from_secs(15);
/// Close a stream that has produced no *event* (heartbeats aside) for this long,
/// reclaiming the connection permit from a quiet topic. A client that still
/// wants the feed reconnects (with `Last-Event-ID`).
///
/// `pub(super)` so [`crate::bus_consumer`]'s durable stream reuses the SAME idle-close bound.
#[cfg(feature = "handlers")]
pub(super) const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// Default per-scope SSE connection cap when the site sets no
/// `maxStreamConnections`, so streams can never grow unbounded. `pub(super)` so the external
/// bus-consumer durable stream ([`crate::bus_consumer`]) caps its per-`{project}/bus/<topic>`
/// connections with the same default.
#[cfg(feature = "handlers")]
pub(super) const DEFAULT_STREAM_CONNECTIONS: u32 = 256;
/// Hard per-`(scope, IP)` concurrent SSE connection cap, so one client can't
/// monopolise the per-site budget.
#[cfg(feature = "handlers")]
const MAX_STREAMS_PER_IP: u32 = 8;

/// The shared WebSocket **proactive-ping** interval both WS serve loops use (the configured-stream
/// `serve_ws_stream` and the durable bus-consumer `serve_bus_ws`). A half-open WS — the peer gone but
/// the TCP connection not yet torn down — would otherwise hold its connection permit + task until the
/// OS eventually reaps the socket. Firing a `Ping` every [`STREAM_HEARTBEAT`] detects it: a dead TCP
/// errors the `sink.send`, and a silent peer that answers nothing trips the idle close
/// ([`ws_idle_deadline`]) when no inbound frame (a pong counts) arrives within [`STREAM_IDLE_TIMEOUT`].
/// The first tick is one interval out (not immediate), so a freshly-opened socket is not pinged before
/// it has done anything.
#[cfg(feature = "handlers")]
pub(super) fn ws_ping_interval() -> tokio::time::Interval {
    let period = STREAM_HEARTBEAT;
    let mut iv = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    iv
}

/// The shared WS **idle deadline**: the instant a WS connection is closed if no inbound frame has
/// arrived since (a client data/ack frame, or a pong answering our [`ws_ping_interval`] ping). Both WS
/// loops seed one at accept and push it out ([`ws_idle_deadline`] again) on every inbound frame; the
/// ping-tick arm closes the socket once `now >= deadline`. Reuses the SAME [`STREAM_IDLE_TIMEOUT`] the
/// SSE path closes a quiet stream after, so all stream transports share one idle bound.
#[cfg(feature = "handlers")]
pub(super) fn ws_idle_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + STREAM_IDLE_TIMEOUT
}

/// Whether a config route pattern matches `request_path` (leading-slash
/// normalised), mirroring [`route::match_handler`]'s path handling.
#[cfg(feature = "handlers")]
pub(super) fn route_matches(route: &str, request_path: &str) -> bool {
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
pub(super) struct IpStreamGuard {
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
pub(super) fn acquire_stream_permit(
    inner: &HandlerRuntimeInner,
    scope: &str,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
) -> Result<tokio::sync::OwnedSemaphorePermit, ()> {
    let max = site_handlers
        .max_stream_connections
        .unwrap_or(DEFAULT_STREAM_CONNECTIONS)
        .max(1);
    acquire_stream_permit_capped(inner, scope, max)
}

/// Acquire a per-scope SSE/stream connection permit against an EXPLICIT `max` cap, rather than a
/// site config's `maxStreamConnections`. The seam [`acquire_stream_permit`] delegates to (passing the
/// resolved site cap) and the one the external bus-consumer durable stream ([`crate::bus_consumer`])
/// uses directly — a `{project}/bus/<topic>` connection has no `HandlersSiteConfig`, so it caps with
/// [`DEFAULT_STREAM_CONNECTIONS`] — so BOTH surfaces share one per-scope semaphore pool + the
/// shed-to-503 / reload-resize semantics (`KeyedSemaphores::gate`). `Err(())` when at the cap.
#[cfg(feature = "handlers")]
pub(super) fn acquire_stream_permit_capped(
    inner: &HandlerRuntimeInner,
    scope: &str,
    max: u32,
) -> Result<tokio::sync::OwnedSemaphorePermit, ()> {
    inner
        .stream_semaphores
        .gate(scope, max.max(1) as usize)
        .try_acquire_owned()
        .map_err(|_| ())
}

/// Acquire a per-`(scope, IP)` live-stream slot, returning an RAII guard that
/// decrements the counter on drop. `Err(())` when this IP already holds
/// [`MAX_STREAMS_PER_IP`] streams on the scope.
#[cfg(feature = "handlers")]
pub(super) fn acquire_stream_ip_slot(
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

/// #11 — Authorize a stream connection and resolve the scope-relative topic set it may subscribe to.
///
/// - No `authz` ⇒ the static `topics` (backward-compatible broadcast).
/// - `Scoped` (A) ⇒ verify the bearer via `token_claims`, resolve the route's captured params with
///   the SAME matcher the route match used, require EVERY membership check to pass (claim and/or a
///   parameterized SQL predicate), then return the `{param}`-substituted topics. A missing/invalid
///   token is `401`; a non-member (or a non-existent scope — no oracle) is `403`.
/// - `GuestMediated` (B) ⇒ wired in Stage 3.
#[cfg(feature = "handlers")]
pub(super) async fn authorize_stream_topics(
    inner: &Arc<HandlerRuntimeInner>,
    project: &str,
    site: &str,
    stream: &boatramp_core::config::StreamConfig,
    request_path: &str,
    bearer: Option<&str>,
) -> Result<(Vec<String>, std::collections::BTreeMap<String, String>), Response> {
    use boatramp_core::config::{StreamAuthz, StreamMembership};
    let Some(authz) = &stream.authz else {
        return Ok((stream.topics.clone(), std::collections::BTreeMap::new()));
    };
    // Resolve captured route params with the SAME matcher `route_matches` used (no differential).
    let path = if request_path.starts_with('/') {
        std::borrow::Cow::Borrowed(request_path)
    } else {
        std::borrow::Cow::Owned(format!("/{request_path}"))
    };
    let params = Pattern::compile(&stream.route)
        .ok()
        .and_then(|p| p.match_path(&path))
        .map(|m| m.params)
        .unwrap_or_default();
    // sec-review LOW-2: a captured scope must be a plain segment — reject `.`/`..` (messaging keys
    // are opaque, so this is defense-in-depth for the disclosure boundary).
    if params.values().any(|v| v == "." || v == "..") {
        return Err((
            StatusCode::FORBIDDEN,
            "not authorized for this stream scope\n",
        )
            .into_response());
    }

    match authz {
        StreamAuthz::Scoped {
            token_claims,
            membership,
        } => {
            let Some(bearer) = bearer else {
                return Err(
                    (StatusCode::UNAUTHORIZED, "stream requires a bearer token\n").into_response(),
                );
            };
            let claims = verify_stream_bearer(inner, token_claims, bearer).await?;
            for check in membership {
                let ok = match check {
                    StreamMembership::Claim { param, claim } => match params.get(param) {
                        Some(want) => claim_allows(claims.get(claim), want),
                        None => false,
                    },
                    StreamMembership::Sql { source, query, .. } => {
                        sql_membership(inner, project, site, source, query, &params, &claims)
                            .await?
                    }
                };
                if !ok {
                    // `403` for non-member AND non-existent scope alike — no existence oracle.
                    return Err((
                        StatusCode::FORBIDDEN,
                        "not authorized for this stream scope\n",
                    )
                        .into_response());
                }
            }
            Ok((resolve_topic_templates(&stream.topics, &params), params))
        }
        StreamAuthz::GuestMediated {
            token_claims,
            handler,
            max_topics_per_connection,
        } => {
            // When `token_claims` is set the host verifies the principal first (401 on failure) and
            // forwards the verified claims to the guest; otherwise the guest authorizes from the raw
            // request alone.
            let principal = match token_claims {
                Some(tc) => {
                    let Some(bearer) = bearer else {
                        return Err(
                            (StatusCode::UNAUTHORIZED, "stream requires a bearer token\n")
                                .into_response(),
                        );
                    };
                    Some(verify_stream_bearer(inner, tc, bearer).await?)
                }
                None => None,
            };
            let topics = guest_authorize_topics(
                inner,
                project,
                handler,
                request_path,
                bearer,
                principal.as_ref(),
                &stream.topics,
                *max_topics_per_connection,
            )
            .await?;
            Ok((topics, params))
        }
    }
}

/// (B) Invoke the guest authorizer `handler` (a deployed function) with the connection's request
/// (GET + path + bearer, plus the host-verified principal as `x-boatramp-stream-principal` when
/// `token_claims` resolved one), and return the per-subscriber topic set it grants — CONFINED to the
/// declared `topics` templates (the ceiling), so a compromised guest can only select declared scopes,
/// never invent a new topic namespace. A non-2xx from the guest, or an invalid topic body, denies.
///
/// `max_topics` is the opt-in per-connection topic cap: when `Some(n)`, a confined set LARGER than
/// `n` REFUSES the connection (fail-closed, before any subscribe) rather than silently truncating, so
/// an over-returning authorizer is loud. `None` ⇒ unlimited (back-compat).
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
async fn guest_authorize_topics(
    inner: &Arc<HandlerRuntimeInner>,
    project: &str,
    handler: &str,
    request_path: &str,
    bearer: Option<&str>,
    principal: Option<&serde_json::Map<String, serde_json::Value>>,
    templates: &[String],
    max_topics: Option<u32>,
) -> Result<Vec<String>, Response> {
    let Some(invoker) = inner.invoker.get() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "guest-mediated stream authz requires the invoke runtime\n",
        )
            .into_response());
    };
    let scoped = invoker.scoped(
        boatramp_core::project::ProjectRef::new(project),
        Vec::new(),
        None,
    );
    let mut headers: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(b) = bearer {
        headers.push((
            "authorization".to_string(),
            format!("Bearer {b}").into_bytes(),
        ));
    }
    if let Some(p) = principal
        && let Ok(json) = serde_json::to_vec(p)
    {
        headers.push(("x-boatramp-stream-principal".to_string(), json));
    }
    let request = boatramp_handlers::InvokeRequest {
        method: "GET".to_string(),
        path: request_path.to_string(),
        headers,
        body: Vec::new(),
    };
    let deny = || -> Response {
        (
            StatusCode::FORBIDDEN,
            "not authorized for this stream scope\n",
        )
            .into_response()
    };
    let resp = match scoped.invoke(handler, request, 0).await {
        Ok(resp) => resp,
        Err(boatramp_handlers::InvokeError::NotFound) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "guest-mediated stream authz handler is not deployed\n",
            )
                .into_response());
        }
        Err(_) => return Err(deny()),
    };
    // Any non-2xx is a refusal (no oracle: same 403 as a non-member).
    if !(200..300).contains(&resp.status) {
        return Err(deny());
    }
    let Some(returned) = parse_guest_topics(&resp.body) else {
        return Err((
            StatusCode::BAD_GATEWAY,
            "guest stream authorizer returned an invalid topic set\n",
        )
            .into_response());
    };
    // Confine to the declared templates (the ceiling). A topic the operator never declared is dropped
    // (never a new namespace), so the resolved set is ⊆ what `topics` permits.
    let confined: Vec<String> = returned
        .into_iter()
        .filter(|t| templates.iter().any(|tmpl| topic_matches_template(tmpl, t)))
        .collect();
    // Opt-in per-connection topic cap (N1): enforced AFTER confinement, on the IN-TEMPLATE set a
    // trusted guest selected. An over-cap return REFUSES the connection (fail-closed, before any
    // subscribe/hub-attach) — never a silent truncate, so a bug/compromise in the authorizer is
    // loud. `None` ⇒ unlimited (unchanged for existing deploys). A 502 (not the 403 deny) marks this
    // as an authorizer-returned-too-much condition, independent of the client's scope (no oracle).
    if let Some(max) = max_topics
        && confined.len() as u64 > u64::from(max)
    {
        return Err((
            StatusCode::BAD_GATEWAY,
            "guest stream authorizer returned more topics than max_topics_per_connection permits\n",
        )
            .into_response());
    }
    Ok(confined)
}

/// Parse a guest authorizer's topic set: a bare JSON array `["a","b"]` or `{"topics":["a","b"]}`.
/// Any non-string element, or another shape, is rejected (fail-closed).
#[cfg(feature = "handlers")]
fn parse_guest_topics(body: &[u8]) -> Option<Vec<String>> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let array = match value {
        serde_json::Value::Array(a) => a,
        serde_json::Value::Object(mut o) => match o.remove("topics") {
            Some(serde_json::Value::Array(a)) => a,
            _ => return None,
        },
        _ => return None,
    };
    array
        .into_iter()
        .map(|v| v.as_str().map(str::to_string))
        .collect()
}

/// Whether `topic` matches a `{name}`-templated `template`, segment-wise: equal segment count, each
/// template segment either a whole-segment `{name}` placeholder (matches one non-empty segment) or a
/// literal that must match exactly. Used to confine a guest authorizer's returned topics to the
/// declared `topics` ceiling.
#[cfg(feature = "handlers")]
fn topic_matches_template(template: &str, topic: &str) -> bool {
    let t: Vec<&str> = template.split('/').collect();
    let s: Vec<&str> = topic.split('/').collect();
    t.len() == s.len()
        && t.iter().zip(&s).all(|(tp, sg)| {
            if tp.starts_with('{') && tp.ends_with('}') && tp.len() > 2 {
                // A captured segment must be a plain, non-empty, non-`.`/`..` segment (sec LOW-2).
                !sg.is_empty() && *sg != "." && *sg != ".."
            } else {
                tp == sg
            }
        })
}

/// Verify the connection's bearer against the stream's `token_claims` and return its claims, or an
/// error Response. Token verification needs the `oidc` feature (for `jsonwebtoken`, like the data
/// connector); without it a scoped stream fails CLOSED (`503`) rather than serving unverified.
#[cfg(all(feature = "handlers", feature = "oidc"))]
async fn verify_stream_bearer(
    inner: &Arc<HandlerRuntimeInner>,
    token_claims: &boatramp_core::config::HandlerGraphqlTokenClaims,
    bearer: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, Response> {
    match crate::graphql_data::token::verified_claims(token_claims, bearer, inner.env_source())
        .await
    {
        Some(claims) => Ok(claims),
        None => Err((
            StatusCode::UNAUTHORIZED,
            "stream bearer token did not verify\n",
        )
            .into_response()),
    }
}

#[cfg(all(feature = "handlers", not(feature = "oidc")))]
async fn verify_stream_bearer(
    _inner: &Arc<HandlerRuntimeInner>,
    _token_claims: &boatramp_core::config::HandlerGraphqlTokenClaims,
    _bearer: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, Response> {
    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        "scoped stream authz requires the `oidc` feature for bearer verification\n",
    )
        .into_response())
}

/// Whether a verified-token `claim` authorizes `want`: a string array containing it, or a single /
/// comma-separated string listing it. Any other shape ⇒ deny.
#[cfg(feature = "handlers")]
fn claim_allows(claim: Option<&serde_json::Value>, want: &str) -> bool {
    match claim {
        Some(serde_json::Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(want)),
        Some(serde_json::Value::String(s)) => s.split(',').any(|c| c.trim() == want),
        _ => false,
    }
}

/// Run a membership SQL predicate against the site's managed database, binding `$name` placeholders
/// from the resolved route params + verified claims as POSITIONAL parameters (never interpolated).
/// Member iff ≥1 row. No SQL backend, or any query error, denies (fail-closed).
#[cfg(feature = "handlers")]
async fn sql_membership(
    inner: &Arc<HandlerRuntimeInner>,
    project: &str,
    site: &str,
    source: &str,
    query: &str,
    params: &std::collections::BTreeMap<String, String>,
    claims: &serde_json::Map<String, serde_json::Value>,
) -> Result<bool, Response> {
    let deny = || -> Response {
        (
            StatusCode::FORBIDDEN,
            "not authorized for this stream scope\n",
        )
            .into_response()
    };
    let Some(sql) = inner.sql.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "stream sql-membership requires a managed database\n",
        )
            .into_response());
    };
    let (rewritten, binds) = bind_named_params(query, params, claims);
    let db = sql
        .database(project, site, source)
        .await
        .map_err(|_| deny())?;
    let rows = db
        .query_autocommit(&rewritten, &binds)
        .await
        .map_err(|_| deny())?;
    Ok(!rows.rows.is_empty())
}

/// Rewrite `$name` placeholders in a membership query to canonical positional `?1..?N` (the portable
/// style the SQL backend re-renders per dialect) and collect the bound values in order. A `$name`
/// binds the route param `name`, else the verified claim `name`, else `NULL` (so the predicate
/// denies — fail-safe). A repeated `$name` reuses its one positional bind.
#[cfg(feature = "handlers")]
fn bind_named_params(
    query: &str,
    params: &std::collections::BTreeMap<String, String>,
    claims: &serde_json::Map<String, serde_json::Value>,
) -> (String, Vec<boatramp_core::sql::SqlValue>) {
    use boatramp_core::sql::SqlValue;
    let resolve = |name: &str| -> SqlValue {
        if let Some(v) = params.get(name) {
            return SqlValue::Text(v.clone());
        }
        match claims.get(name) {
            Some(serde_json::Value::String(s)) => SqlValue::Text(s.clone()),
            Some(serde_json::Value::Bool(b)) => SqlValue::Boolean(*b),
            Some(serde_json::Value::Number(n)) if n.is_i64() => {
                SqlValue::Integer(n.as_i64().unwrap())
            }
            Some(serde_json::Value::Number(n)) => SqlValue::Real(n.as_f64().unwrap_or(0.0)),
            _ => SqlValue::Null,
        }
    };
    let mut out = String::with_capacity(query.len());
    let mut binds: Vec<SqlValue> = Vec::new();
    let mut seen: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let bytes = query.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let name_start = bytes[i] == b'$'
            && query[i + 1..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        if name_start {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            let name = &query[start..j];
            let idx = if let Some(&idx) = seen.get(name) {
                idx
            } else {
                binds.push(resolve(name));
                let idx = binds.len();
                seen.insert(name.to_string(), idx);
                idx
            };
            out.push('?');
            out.push_str(&idx.to_string());
            i = j;
        } else {
            let ch = query[i..].chars().next().expect("char boundary");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    (out, binds)
}

/// Substitute `{name}` templates in each topic with the connection's resolved route params; an
/// unknown `{name}` is left verbatim.
#[cfg(feature = "handlers")]
fn resolve_topic_templates(
    topics: &[String],
    params: &std::collections::BTreeMap<String, String>,
) -> Vec<String> {
    topics
        .iter()
        .map(|t| substitute_template(t, params))
        .collect()
}

/// Substitute `{name}` templates in one topic with the connection's resolved route params; an
/// unknown `{name}` is left verbatim. A substituted value is not re-scanned (a value containing
/// `{…}` can't trigger a second expansion).
#[cfg(feature = "handlers")]
fn substitute_template(t: &str, params: &std::collections::BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(t.len());
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{'
            && let Some(end) = t[i..].find('}')
        {
            let name = &t[i + 1..i + end];
            if let Some(v) = params.get(name) {
                out.push_str(v);
                i += end + 1;
                continue;
            }
        }
        let ch = t[i..].chars().next().expect("char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Serve a configured stream: subscribe to each of its (scope-namespaced) topics on the messaging
/// backend and fan them out to the client, with `Last-Event-ID` resume, an idle timeout, and
/// per-scope + per-IP connection caps.
///
/// Two framings over the one fan-out, selected by `connect_wire`:
/// * `None` — **SSE** (`text/event-stream`): each payload is an `event: <topic>` line, with a
///   heartbeat (today's behavior, unchanged).
/// * `Some(wire)` — **Connect / gRPC-web server-stream** (PLAN-connect-grpc §7 / IU-4): each
///   payload is a length-prefixed envelope data frame, terminated by an in-body end-of-stream
///   frame (a Connect EndStream `{}` or a gRPC-web `grpc-status: 0` trailers frame) when the
///   fan-out ends or goes idle. The authz, topic resolution, permits, and fan-out are IDENTICAL —
///   only the on-wire framing of each delivered payload differs — so per-subscriber
///   `br-stream-authz` holds on the Connect path exactly as it does on SSE (same
///   [`authorize_stream_topics`] call, run before any byte is produced). The host does not decode
///   the request protobuf (it stays protobuf-agnostic); the subscribed scope rides the route
///   params + bearer like every scoped stream.
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_stream(
    inner: &Arc<HandlerRuntimeInner>,
    project: &str,
    site: &str,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    stream: &boatramp_core::config::StreamConfig,
    after: Option<String>,
    request_path: &str,
    bearer: Option<&str>,
    client_ip: IpAddr,
    preview: Option<&str>,
    connect_wire: Option<boatramp_connect_frame::Wire>,
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
    // #14: project-qualify the scope to match where a deployed guest's `wasi:messaging` binding
    // publishes — `{project}/{site}/<topic>` (`ProjectRef::qualified` prefixes the project for every
    // project incl. `default`). The bare-site scope was unreachable by any deployed handler/function.
    let base = match preview {
        Some(id) => format!("{site}/_preview/{id}"),
        None => site.to_string(),
    };
    let scope = boatramp_core::project::ProjectRef::new(project).qualified(&base);
    // #11: authorize the connection and resolve the per-connection topic set BEFORE acquiring any
    // permit (deny before resource use). No `authz` ⇒ the static broadcast topics.
    let (topics, _params) =
        match authorize_stream_topics(inner, project, site, stream, request_path, bearer).await {
            Ok(resolved) => resolved,
            Err(resp) => return resp,
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
                .into_response();
        }
    };
    let ip_guard = match acquire_stream_ip_slot(inner, &scope, client_ip) {
        Ok(guard) => guard,
        Err(()) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "per-client stream connection limit reached\n",
            )
                .into_response();
        }
    };

    // `after` is the client's Last-Event-ID (best-effort resume).

    // Connect / gRPC-web server-stream framing (PLAN §7 / IU-4): the SAME fan-out, but each
    // delivered payload is a length-prefixed envelope frame + a terminal end frame on close,
    // instead of an SSE `event:` line. Authz + permits above already ran identically.
    if let Some(wire) = connect_wire {
        return serve_connect_stream(
            messaging,
            &scope,
            &topics,
            after,
            wire,
            site_permit,
            ip_guard,
        );
    }

    // One live subscription per configured topic, each namespaced under the
    // scope (so the client sees only its own site's/preview's traffic). The
    // event's `event:` field is the *config* topic (scope-relative), matching
    // what the guest published.
    let merged = futures::stream::select_all(topics.iter().map(|topic| {
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

/// Build the **Connect / gRPC-web server-stream** response body (PLAN-connect-grpc §7 / IU-4):
/// the SAME scope-namespaced topic fan-out as [`serve_stream`]'s SSE path, but each delivered
/// payload is a length-prefixed envelope **data** frame, and the body ends with one terminal
/// end-of-stream frame (a Connect **EndStream** `{}` for `application/connect+*`, or a gRPC-web
/// `grpc-status: 0` **trailers** frame for `application/grpc-web*`) once the fan-out ends or goes
/// idle past [`STREAM_IDLE_TIMEOUT`]. HTTP status is always `200`; the RPC status rides the end
/// frame (that is the Connect-first lever — no HTTP/2 trailers, PLAN §4). The permits are held for
/// the body's lifetime (moved into the stream state) and released when the client disconnects or
/// the stream completes, exactly like the SSE path.
///
/// The payloads published to the topic are the already-protobuf-encoded reply messages (a producer
/// — a mutation handler, a function, a consumer — publishes each one), so the host only has to
/// frame them: it never decodes the protobuf, keeping the fan-out protobuf-agnostic.
#[cfg(feature = "handlers")]
fn serve_connect_stream(
    messaging: Arc<dyn boatramp_core::messaging::Messaging>,
    scope: &str,
    topics: &[String],
    after: Option<String>,
    wire: boatramp_connect_frame::Wire,
    site_permit: tokio::sync::OwnedSemaphorePermit,
    ip_guard: IpStreamGuard,
) -> Response {
    use boatramp_connect_frame::{
        Protocol, Status, encode_connect_end_stream, encode_envelope, encode_grpc_web_trailers,
    };
    use futures::StreamExt;

    // One live subscription per configured (scope-namespaced) topic, merged — identical to the SSE
    // path, but keeping only the raw payload bytes (the envelope carries no topic label; a Connect
    // server-stream is one method's reply stream).
    let merged = futures::stream::select_all(topics.iter().map(|topic| {
        let namespaced = format!("{scope}/{topic}");
        messaging
            .subscribe(&namespaced, after.as_deref())
            .map(|event| event.payload)
            .boxed()
    }));

    // Stream state: the merged payloads, the permits (held for the connection's lifetime), the
    // wire (for the terminal frame), and whether the terminal frame has been emitted.
    struct ConnectConn {
        events: futures::stream::BoxStream<'static, Vec<u8>>,
        _site_permit: tokio::sync::OwnedSemaphorePermit,
        _ip_guard: IpStreamGuard,
        wire: boatramp_connect_frame::Wire,
        ended: bool,
    }
    let conn = ConnectConn {
        events: merged.boxed(),
        _site_permit: site_permit,
        _ip_guard: ip_guard,
        wire,
        ended: false,
    };

    let body = futures::stream::unfold(conn, |mut conn| async move {
        // After the terminal frame, the body is complete.
        if conn.ended {
            return None;
        }
        match tokio::time::timeout(STREAM_IDLE_TIMEOUT, conn.events.next()).await {
            // A delivered payload → one envelope data frame.
            Ok(Some(payload)) => {
                let frame = encode_envelope(0, &payload);
                Some((
                    Ok::<bytes::Bytes, std::convert::Infallible>(bytes::Bytes::from(frame)),
                    conn,
                ))
            }
            // All topics ended, or the topic went idle past the timeout: emit the terminal
            // end-of-stream frame as the LAST body chunk, then stop.
            Ok(None) | Err(_) => {
                let end = match conn.wire.protocol {
                    Protocol::GrpcWeb => encode_grpc_web_trailers(&Status::ok(), &[]),
                    _ => encode_connect_end_stream(&Status::ok(), &[]),
                };
                conn.ended = true;
                Some((Ok(bytes::Bytes::from(end)), conn))
            }
        }
    });

    // Always `200` (Connect/gRPC-web carry status in-body); the content.rs residual keeps these
    // framed content-types off the compression allowlist, so the envelope framing is never mangled.
    let mut resp = Body::from_stream(body).into_response();
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(wire.response_content_type()),
    );
    resp
}

/// Serve a GraphQL **subscription** as a [graphql-sse] event stream ("distinct
/// connections" mode): subscribe to the subscription's topic and frame each published
/// payload as an `event: next` carrying the execution-result JSON, so a standard
/// graphql-sse client (Apollo Client, urql, `graphql-sse`) consumes it directly — unlike
/// [`serve_stream`], which frames boatramp's own `event: <topic>` shape that no GraphQL
/// client understands. Resume (`Last-Event-ID`), heartbeat, idle timeout, and the
/// per-scope + per-IP connection caps are shared with `serve_stream`.
///
/// boatramp stays GraphQL-*aware*, not an engine: the host does not execute the
/// subscription. Its single root field names a messaging **topic**; a producer (a
/// mutation handler, a function, a consumer) publishes each event's **execution result**
/// (`{"data": …}`) to that topic, and the host frames it as graphql-sse `next`. The
/// payload delivered is exactly what the producer published.
///
/// [graphql-sse]: https://github.com/enisdenjo/graphql-sse/blob/master/PROTOCOL.md
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_graphql_subscription(
    inner: &Arc<HandlerRuntimeInner>,
    project: &str,
    site: &str,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    topic: &str,
    after: Option<String>,
    client_ip: IpAddr,
    preview: Option<&str>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures::StreamExt;

    let Some(messaging) = inner.messaging.clone() else {
        // Subscriptions require a messaging backend; without one the route is dead.
        return not_found();
    };
    // Binding identity, same rule as request handlers and `serve_stream`: live binds to
    // the site, a preview to its own `{site}/_preview/{id}` namespace.
    // #14: project-qualify the scope to match where a deployed guest's `wasi:messaging` binding
    // publishes — `{project}/{site}/<topic>` (`ProjectRef::qualified` prefixes the project for every
    // project incl. `default`). The bare-site scope was unreachable by any deployed handler/function.
    let base = match preview {
        Some(id) => format!("{site}/_preview/{id}"),
        None => site.to_string(),
    };
    let scope = boatramp_core::project::ProjectRef::new(project).qualified(&base);
    let site_permit = match acquire_stream_permit(inner, &scope, site_handlers) {
        Ok(permit) => permit,
        Err(()) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "site stream connection limit reached\n",
            )
                .into_response();
        }
    };
    let ip_guard = match acquire_stream_ip_slot(inner, &scope, client_ip) {
        Ok(guard) => guard,
        Err(()) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "per-client stream connection limit reached\n",
            )
                .into_response();
        }
    };

    // One live subscription on the (scope-namespaced) topic, each payload framed as a
    // graphql-sse `next` event carrying the producer's execution result.
    let namespaced = format!("{scope}/{topic}");
    let events = messaging
        .subscribe(&namespaced, after.as_deref())
        .map(|event| graphql_sse_next(&event.id, &event.payload))
        .boxed();

    let conn = StreamConn {
        events,
        _site_permit: site_permit,
        _ip_guard: ip_guard,
    };
    let body = futures::stream::unfold(conn, |mut conn| async move {
        match tokio::time::timeout(STREAM_IDLE_TIMEOUT, conn.events.next()).await {
            Ok(Some(event)) => Some((Ok::<Event, std::convert::Infallible>(event), conn)),
            // Idle past the timeout, or the topic ended: close. The client's EventSource
            // reconnects (with `Last-Event-ID`) on its own — we deliberately do not
            // synthesize a graphql-sse `complete`, which would tell the client the
            // subscription is finished and stop it resuming.
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

/// Frame one messaging payload as a graphql-sse `next` event: `event: next` whose `data`
/// is the producer's execution-result JSON. The durable message id rides as the SSE `id:`
/// for `Last-Event-ID` resume.
#[cfg(feature = "handlers")]
fn graphql_sse_next(id: &str, payload: &[u8]) -> axum::response::sse::Event {
    axum::response::sse::Event::default()
        .id(id)
        .event("next")
        .data(graphql_sse_data(payload))
}

/// The `data` for a graphql-sse `next` event: the payload verbatim when it is UTF-8 and
/// CR-free (a valid execution-result JSON, which `Event::data` can frame), else a
/// well-formed GraphQL error result — a non-UTF-8 or CR-bearing payload can't be valid
/// execution-result JSON, and `Event::data` panics on a lone `\r`.
#[cfg(feature = "handlers")]
fn graphql_sse_data(payload: &[u8]) -> String {
    match std::str::from_utf8(payload) {
        Ok(text) if !text.contains('\r') => text.to_string(),
        _ => r#"{"errors":[{"message":"subscription payload was not valid UTF-8 GraphQL JSON"}]}"#
            .to_string(),
    }
}

/// The graphql-sse `complete` event that ENDS a run-attach subscription (PLAN-run-streaming P3): the
/// protocol's terminal signal telling the client the operation is finished so it does NOT reconnect.
/// Carries an empty `data` line (graphql-sse clients parse the raw stream and dispatch on the event
/// name). Unlike the topic-fan-out path — which deliberately never completes, so a dropped client
/// resumes with `Last-Event-ID` — a RUN has a DEFINITIVE end (its terminal event), so completing is
/// correct: the run is over, and a reconnect would only replay a concluded log.
#[cfg(all(feature = "handlers", feature = "run-streaming"))]
fn graphql_sse_complete() -> axum::response::sse::Event {
    axum::response::sse::Event::default()
        .event("complete")
        .data("")
}

/// Map a host-internal run error onto the pre-stream HTTP response for the GraphQL run-attach face.
/// A non-existent run (the cross-tenant / fabricated-id case, which surfaces as `NotFound` because the
/// key does not exist under the subscriber's resolved scope) is a flat `404` — never a cross-tenant
/// touch, and no oracle beyond what the already-authenticated subscriber could learn about its own run.
#[cfg(all(feature = "handlers", feature = "run-streaming"))]
fn run_attach_err(e: &boatramp_core::run::RunError) -> Response {
    use boatramp_core::run::RunError;
    match e {
        RunError::NotFound => (StatusCode::NOT_FOUND, "run not found\n").into_response(),
        RunError::Invalid(m) => (
            StatusCode::BAD_REQUEST,
            format!("invalid run request: {m}\n"),
        )
            .into_response(),
        RunError::Terminal | RunError::Cancelled => {
            (StatusCode::CONFLICT, "run already concluded\n").into_response()
        }
        RunError::Backend(_) => {
            (StatusCode::BAD_GATEWAY, "run backend unavailable\n").into_response()
        }
    }
}

/// A drop guard that GCs the ephemeral per-attach consumer group a run attach opened (mirrors the
/// engine seam's cleanup hook). The GraphQL run-attach face deliberately does NOT drop-cancel on a
/// client disconnect (see [`serve_graphql_run_subscription`]), so this only cleans up group state.
#[cfg(all(feature = "handlers", feature = "run-streaming"))]
struct RunGroupCleanup(Option<Box<dyn FnOnce() -> futures::future::BoxFuture<'static, ()> + Send>>);

#[cfg(all(feature = "handlers", feature = "run-streaming"))]
impl Drop for RunGroupCleanup {
    fn drop(&mut self) {
        if let Some(cleanup) = self.0.take() {
            tokio::spawn(async move {
                cleanup().await;
            });
        }
    }
}

/// The streaming phase of a run-attach SSE body: deliver envelopes, then (on the terminal) a
/// graphql-sse `complete`, then end.
#[cfg(all(feature = "handlers", feature = "run-streaming"))]
enum RunSsePhase {
    /// Draining the run's envelope stream, framing each payload as `next`.
    Streaming,
    /// The terminal `next` was delivered; emit the graphql-sse `complete` on the next poll, then end.
    CompleteThenEnd,
    /// The body is complete.
    Done,
}

/// Serve a GraphQL **run-attach** subscription (PLAN-run-streaming P3, D2 Option A) as a graphql-sse
/// event stream: ATTACH to the durable RUN `run_id` (fenced to the subscriber's resolved tenant
/// `run_scope`) via P1's [`RunEngine`](crate::run_stream::RunEngine), frame each `RunEnvelope`'s
/// payload as a graphql-sse `next` event (`id:` = the `seq`, for `Last-Event-ID` resume), and end with
/// a graphql-sse `complete` on the run's terminal event. Resume (`after_seq` from `Last-Event-ID`),
/// heartbeat, idle timeout, and the per-run connection caps mirror the other stream transports.
///
/// boatramp stays **GraphQL-AWARE, not an engine**: it does NOT execute the subscription resolver.
/// The guest's own resolver is the authority for which run a subscriber may see (its START mutation
/// minted + handed out the unguessable id via the `run` capability); this transport only CARRIES the
/// run's events for the id the client presents, confined by the tenancy scope — a subscription can
/// NEVER attach a run outside its own tenant (a foreign-tenant id composes a different key ⇒ `404`).
///
/// **No drop-cancel.** graphql-sse is a RESUMABLE transport (the client reconnects with
/// `Last-Event-ID`), so a transient `EventSource` drop must NOT cancel the run — that would kill a run
/// on a normal reconnect and defeat resume. A genuinely abandoned run is reclaimed by the idle-TTL
/// sweep (and an explicit stop goes through the guest `run.cancel` or the P2 cancel route). The
/// ephemeral attach consumer group is still GC'd on every teardown.
#[cfg(all(feature = "handlers", feature = "run-streaming"))]
pub(super) async fn serve_graphql_run_subscription(
    inner: &Arc<HandlerRuntimeInner>,
    project: &str,
    run_scope: &str,
    run_id: &str,
    after_seq: Option<u64>,
    client_ip: IpAddr,
) -> Response {
    use crate::run_stream::{EngineAttach, RunEngine};
    use axum::response::sse::{Event, KeepAlive, Sse};
    use boatramp_core::run::{RunEnvelope, RunError};

    // Posture gate (defensive — the dispatch branch gates first): the OFF-by-default node posture
    // `allow_guest_run_streaming`. Off ⇒ `403`, zero runtime exposure, the SAME gate as the guest door
    // and the P2 external door.
    if !inner.engine.allow_run_streaming() {
        return (
            StatusCode::FORBIDDEN,
            "run streaming is not enabled on this node (allow_guest_run_streaming is off)\n",
        )
            .into_response();
    }
    let Some(messaging) = inner.messaging.clone() else {
        // Runs ride the durable messaging substrate; without one the route is dead.
        return not_found();
    };

    // deny-before-resource-use: the per-scope + per-IP stream permits, keyed by the RUN (identical to
    // the P2 external door — one shared pool per run) so each run's graphql subscribers are bounded
    // independently and share the configured-stream pools.
    let scope_key = format!("run:{run_id}");
    let site_permit =
        match acquire_stream_permit_capped(inner, &scope_key, DEFAULT_STREAM_CONNECTIONS) {
            Ok(p) => p,
            Err(()) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "run stream connection limit reached\n",
                )
                    .into_response();
            }
        };
    let ip_guard = match acquire_stream_ip_slot(inner, &scope_key, client_ip) {
        Ok(g) => g,
        Err(()) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "per-client run stream connection limit reached\n",
            )
                .into_response();
        }
    };

    // Build the run engine fenced to (project, resolved tenant scope) — the IDENTICAL keyspace the
    // guest `run.create` binding and the P2 door address — and attach, resuming strictly past
    // `after_seq` (lossless). The tenancy fence rides the resolved scope, never the subscription.
    let engine = RunEngine::new(
        messaging,
        inner.kv.clone(),
        project.to_string(),
        run_scope.to_string(),
    );
    let attach = match engine.attach(run_id, after_seq).await {
        Ok(a) => a,
        Err(e) => return run_attach_err(&e),
    };
    // Drop drop-cancel (see the fn doc): a graphql-sse reconnect must not cancel the run. We keep only
    // the ephemeral-group cleanup hook; the run's own `drop_cancel_armed` is intentionally ignored.
    let EngineAttach {
        stream, cleanup, ..
    } = attach;

    struct RunSseState {
        stream: futures::stream::BoxStream<'static, Result<RunEnvelope, RunError>>,
        phase: RunSsePhase,
        _cleanup: RunGroupCleanup,
        _site_permit: tokio::sync::OwnedSemaphorePermit,
        _ip_guard: IpStreamGuard,
    }
    let state = RunSseState {
        stream,
        phase: RunSsePhase::Streaming,
        _cleanup: RunGroupCleanup(cleanup),
        _site_permit: site_permit,
        _ip_guard: ip_guard,
    };

    let body = futures::stream::unfold(state, |mut st| async move {
        match st.phase {
            RunSsePhase::Done => None,
            RunSsePhase::CompleteThenEnd => {
                // The terminal payload was delivered last poll; send `complete`, then end.
                st.phase = RunSsePhase::Done;
                Some((
                    Ok::<Event, std::convert::Infallible>(graphql_sse_complete()),
                    st,
                ))
            }
            RunSsePhase::Streaming => loop {
                match tokio::time::timeout(STREAM_IDLE_TIMEOUT, st.stream.next()).await {
                    Ok(Some(Ok(env))) => {
                        let terminal = env.kind.is_terminal();
                        if env.payload.is_empty() {
                            // A terminal with no distinct payload (e.g. `end` / `cancelled`): emit
                            // `complete` now and end. A non-terminal empty payload is skipped.
                            if terminal {
                                st.phase = RunSsePhase::Done;
                                return Some((Ok(graphql_sse_complete()), st));
                            }
                            continue;
                        }
                        let event = graphql_sse_next(&env.seq.to_string(), &env.payload);
                        if terminal {
                            // Deliver the terminal payload now; `complete` + end on the next poll.
                            st.phase = RunSsePhase::CompleteThenEnd;
                        }
                        return Some((Ok(event), st));
                    }
                    // Stream error or the already-terminal empty-stream fast path → close the body
                    // WITHOUT a `complete`: a resume whose cursor already covers the terminal, or an
                    // idle gap, is a reconnect case (the client re-attaches with `Last-Event-ID`), so
                    // we don't tell it the operation finished here.
                    Ok(Some(Err(_))) | Ok(None) => return None,
                    // Idle past the timeout → close; the client reconnects.
                    Err(_) => return None,
                }
            },
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

#[cfg(all(test, feature = "handlers"))]
mod tests {
    use super::graphql_sse_data;

    #[test]
    fn graphql_sse_frames_a_json_result_verbatim() {
        let payload = br#"{"data":{"messageAdded":{"id":"1","body":"hi"}}}"#;
        assert_eq!(
            graphql_sse_data(payload),
            r#"{"data":{"messageAdded":{"id":"1","body":"hi"}}}"#
        );
    }

    #[test]
    fn graphql_sse_replaces_an_unframable_payload_with_an_error_result() {
        // A lone CR would panic `Event::data`; a non-UTF-8 byte can't be JSON. Both
        // become a well-formed GraphQL error result the client can parse.
        for bad in [b"{\"data\":1}\r".to_vec(), vec![0xff, 0xfe]] {
            let data = graphql_sse_data(&bad);
            assert!(data.contains("\"errors\""), "unexpected: {data}");
            let _: serde_json::Value = serde_json::from_str(&data).expect("valid JSON");
        }
    }

    // #11 — scoped-stream authz helpers.
    use super::{bind_named_params, claim_allows, resolve_topic_templates};
    use boatramp_core::sql::SqlValue;

    #[test]
    fn claim_membership_allows_array_csv_and_single_denies_otherwise() {
        use serde_json::json;
        assert!(claim_allows(Some(&json!(["a", "b"])), "b"));
        assert!(!claim_allows(Some(&json!(["a", "b"])), "c"));
        assert!(claim_allows(Some(&json!("a, b ,c")), "b")); // CSV, trimmed
        assert!(claim_allows(Some(&json!("solo")), "solo"));
        assert!(
            !claim_allows(Some(&json!(42)), "42"),
            "non-string/array shape denies"
        );
        assert!(!claim_allows(None, "x"), "absent claim denies");
    }

    #[test]
    fn named_params_bind_positionally_with_param_precedence_dedup_and_null() {
        let params = std::collections::BTreeMap::from([("mailbox".to_string(), "mbx".to_string())]);
        let claims = serde_json::json!({ "sub": "user-1" })
            .as_object()
            .unwrap()
            .clone();
        let (sql, binds) = bind_named_params(
            "SELECT 1 FROM m WHERE mailbox=$mailbox AND subject=$sub AND owner=$mailbox AND x=$absent",
            &params,
            &claims,
        );
        // `$mailbox`→?1 (reused for `owner`), `$sub`→?2, `$absent`→?3: positional, first-seen order.
        assert_eq!(
            sql,
            "SELECT 1 FROM m WHERE mailbox=?1 AND subject=?2 AND owner=?1 AND x=?3"
        );
        assert_eq!(
            binds,
            vec![
                SqlValue::Text("mbx".into()),    // route param wins over any claim
                SqlValue::Text("user-1".into()), // claim
                SqlValue::Null,                  // absent → NULL ⇒ predicate denies (fail-safe)
            ]
        );
    }

    #[test]
    fn topic_templates_substitute_resolved_params_and_leave_unknown_verbatim() {
        let params = std::collections::BTreeMap::from([("mailbox".to_string(), "abc".to_string())]);
        let topics = vec![
            "shared/{mailbox}/events".to_string(),
            "sys/{unknown}".to_string(),
        ];
        assert_eq!(
            resolve_topic_templates(&topics, &params),
            vec!["shared/abc/events".to_string(), "sys/{unknown}".to_string(),]
        );
    }

    use super::{parse_guest_topics, topic_matches_template};

    #[test]
    fn guest_topics_parse_array_and_object_reject_otherwise() {
        assert_eq!(
            parse_guest_topics(br#"["a","b"]"#).unwrap(),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(
            parse_guest_topics(br#"{"topics":["x"]}"#).unwrap(),
            vec!["x".to_string()]
        );
        assert!(
            parse_guest_topics(br#"[1,2]"#).is_none(),
            "non-string elements rejected"
        );
        assert!(parse_guest_topics(br#"{"other":[]}"#).is_none());
        assert!(parse_guest_topics(b"not json").is_none());
    }

    #[test]
    fn guest_topics_confine_to_declared_templates() {
        assert!(topic_matches_template(
            "shared/{mailbox}/events",
            "shared/abc/events"
        ));
        assert!(
            !topic_matches_template("shared/{mailbox}/events", "shared/abc/presence"),
            "a literal tail segment must match"
        );
        assert!(
            !topic_matches_template("shared/{mailbox}/events", "shared//events"),
            "an empty captured segment is rejected"
        );
        assert!(
            !topic_matches_template("shared/{mailbox}", "shared/a/b"),
            "segment count must match (no namespace invention)"
        );
        assert!(topic_matches_template("fixed/topic", "fixed/topic"));
        assert!(!topic_matches_template("fixed/topic", "fixed/other"));
    }
}

/// The `Sec-WebSocket-Accept` response token (RFC 6455 §1.3): base64 of the SHA-1 of the
/// client's `Sec-WebSocket-Key` concatenated with the WebSocket GUID.
#[cfg(feature = "handlers")]
fn ws_accept_key(key: &[u8]) -> String {
    use base64::Engine;
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(key);
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
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
pub(super) async fn serve_ws_stream(
    inner: &Arc<HandlerRuntimeInner>,
    project: &str,
    site: &str,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    stream: &boatramp_core::config::StreamConfig,
    mut request: Request,
    // sec-review LOW-1: the SAME dispatch-resolved path the SSE path uses (prefix-stripped for the
    // admin/preview path-form routes), so WS + SSE authz match the route identically.
    request_path: &str,
    client_ip: IpAddr,
    preview: Option<&str>,
) -> Response {
    use futures::StreamExt;

    // WebSocket opening handshake (RFC 6455 §4.2.1): require version 13 + a key, derive
    // the accept token, and take over the connection via boatramp-http's upgrade seam
    // (the inbound connection is served by serve_connection, not hyper).
    let version_ok = request
        .headers()
        .get("sec-websocket-version")
        .is_some_and(|v| v.as_bytes() == b"13");
    let accept_key = request
        .headers()
        .get("sec-websocket-key")
        .map(|k| ws_accept_key(k.as_bytes()));
    let (Some(accept), true) = (accept_key, version_ok) else {
        return (StatusCode::BAD_REQUEST, "invalid websocket handshake\n").into_response();
    };
    // #11: capture the owned bearer BEFORE releasing the request — `&Request` must not be held
    // across the authz awaits. The path is threaded in (LOW-1), matching the SSE path exactly.
    let bearer = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string);
    let on_upgrade = match boatramp_http::on_upgrade(&mut request) {
        Some(u) => u,
        None => return (StatusCode::BAD_REQUEST, "no upgrade handle\n").into_response(),
    };
    drop(request); // the WS handshake carries no body; release it before any await

    let Some(messaging) = inner.messaging.clone() else {
        return not_found();
    };
    // Same binding identity as SSE streams + request handlers: live binds to the
    // site, a preview to its own namespace.
    // #14: project-qualify the scope to match where a deployed guest's `wasi:messaging` binding
    // publishes — `{project}/{site}/<topic>` (`ProjectRef::qualified` prefixes the project for every
    // project incl. `default`). The bare-site scope was unreachable by any deployed handler/function.
    let base = match preview {
        Some(id) => format!("{site}/_preview/{id}"),
        None => site.to_string(),
    };
    let scope = boatramp_core::project::ProjectRef::new(project).qualified(&base);
    // #11: authorize + resolve the per-connection topic set (or 401/403) before acquiring a permit.
    let (topics, params) = match authorize_stream_topics(
        inner,
        project,
        site,
        stream,
        request_path,
        bearer.as_deref(),
    )
    .await
    {
        Ok(resolved) => resolved,
        Err(resp) => return resp,
    };
    let site_permit = match acquire_stream_permit(inner, &scope, site_handlers) {
        Ok(permit) => permit,
        Err(()) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "site stream connection limit reached\n",
            )
                .into_response();
        }
    };
    let ip_guard = match acquire_stream_ip_slot(inner, &scope, client_ip) {
        Ok(guard) => guard,
        Err(()) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "per-client stream connection limit reached\n",
            )
                .into_response();
        }
    };

    // server→client: one live subscription per topic, merged (scope-namespaced so
    // a client only sees its own site's/preview's traffic).
    let mut downstream = futures::stream::select_all(topics.iter().map(|topic| {
        let namespaced = format!("{scope}/{topic}");
        messaging
            .subscribe(&namespaced, None)
            .map(|e| e.payload)
            .boxed()
    }));
    // client→server: messages publish to this scope-namespaced topic (if set). sec-review MEDIUM-2:
    // substitute the connection's resolved `{param}`s so the INBOUND topic carries the same scope as
    // the outbound fan-out (an unscoped `publish_topic` would drop the per-connection write scope).
    let publish_topic = stream
        .publish_topic
        .as_ref()
        .map(|topic| format!("{scope}/{}", substitute_template(topic, &params)));

    // The fan-out runs once the serve loop hands us the upgraded connection (after it
    // writes our 101). tungstenite drives the WebSocket framing over the raw stream.
    tokio::spawn(async move {
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::tungstenite::protocol::Role;

        let Ok(upgraded) = on_upgrade.await else {
            return;
        };
        let socket =
            tokio_tungstenite::WebSocketStream::from_raw_socket(upgraded, Role::Server, None).await;
        // Holding the permits for the socket's lifetime caps concurrent streams;
        // they drop (releasing the slot) when this task ends.
        let _permits = (site_permit, ip_guard);
        let (mut sink, mut incoming) = socket.split();
        // #7: proactive ping + idle close, so a half-open WS does not hold its permit+task until TCP
        // teardown. Any inbound frame (data OR a pong) pushes the idle deadline out.
        let mut ping = ws_ping_interval();
        let mut idle_deadline = ws_idle_deadline();
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
                // Publish a client message upstream; close on disconnect. Any inbound frame is activity.
                msg = incoming.next() => {
                    idle_deadline = ws_idle_deadline();
                    match msg {
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
                        // Ping/Pong/Close: tungstenite auto-answers pings; ignore the rest.
                        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                        Some(Ok(_)) => {}
                    }
                },
                // Proactive ping; close if the peer has been silent past the idle deadline (half-open).
                _ = ping.tick() => {
                    if tokio::time::Instant::now() >= idle_deadline {
                        break;
                    }
                    if sink.send(Message::Ping(Vec::new())).await.is_err() {
                        break; // dead TCP
                    }
                }
            }
        }
    });

    // The 101 that triggers the serve loop's upgrade handoff. `Connection`/`Upgrade` are
    // required by the client to complete the handshake — the serve bridge must NOT strip
    // them from a 101 response.
    (
        StatusCode::SWITCHING_PROTOCOLS,
        [
            (header::CONNECTION, "upgrade"),
            (header::UPGRADE, "websocket"),
            (header::SEC_WEBSOCKET_ACCEPT, accept.as_str()),
        ],
        axum::body::Body::empty(),
    )
        .into_response()
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

// ---- PLAN-run-streaming P3 — the GraphQL run-attach subscription face -------------------------
#[cfg(all(test, feature = "handlers", feature = "run-streaming"))]
mod run_graphql_subscription_tests {
    use super::*;
    use crate::run_stream::RunEngine;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::messaging::{LogMessaging, Messaging};
    use boatramp_core::run::RunEventKind;
    use boatramp_core::{
        ByteStream, GetObject, ListPage, ObjectMeta, PutMeta, Storage, StorageError,
    };
    use bytes::Bytes as RawBytes;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    // Minimal in-memory `Storage` so the REAL `LogMessaging` durable substrate can be built — mirrors
    // the run-engine / run-door test `MemStorage`.
    #[derive(Default, Clone)]
    struct MemStorage {
        map: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    }
    fn meta(key: &str, len: usize) -> ObjectMeta {
        ObjectMeta {
            key: key.to_string(),
            size: Some(len as u64),
            content_type: None,
            etag: None,
        }
    }
    fn once_stream(bytes: RawBytes) -> ByteStream {
        futures::stream::once(async move { Ok::<_, StorageError>(bytes) }).boxed()
    }
    #[async_trait::async_trait]
    impl Storage for MemStorage {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            let data = self
                .map
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(GetObject {
                meta: meta(key, data.len()),
                body: once_stream(RawBytes::from(data)),
            })
        }
        async fn get_range(
            &self,
            key: &str,
            offset: u64,
            len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            let data = self
                .map
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            let start = (offset as usize).min(data.len());
            let end = match len {
                Some(l) => (start + l as usize).min(data.len()),
                None => data.len(),
            };
            Ok(GetObject {
                meta: meta(key, end - start),
                body: once_stream(RawBytes::from(data[start..end].to_vec())),
            })
        }
        async fn put(
            &self,
            key: &str,
            mut body: ByteStream,
            _meta: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            let mut buf = Vec::new();
            while let Some(chunk) = body.next().await {
                buf.extend_from_slice(&chunk?);
            }
            let m = meta(key, buf.len());
            self.map.lock().unwrap().insert(key.to_string(), buf);
            Ok(m)
        }
        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            let map = self.map.lock().unwrap();
            let data = map
                .get(key)
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(meta(key, data.len()))
        }
        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.map.lock().unwrap().remove(key);
            Ok(())
        }
        async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(self
                .map
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| meta(k, v.len()))
                .collect())
        }
        async fn list_page(
            &self,
            prefix: &str,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<ListPage, StorageError> {
            Ok(ListPage {
                metas: self.list(prefix).await?,
                cursor: None,
            })
        }
    }

    /// A runtime wired to a REAL durable messaging + KV, with the `run` posture ON (or off, for the
    /// posture test). Returns the runtime plus the SAME messaging + kv a target engine emits through.
    fn setup(run_streaming: bool) -> (Arc<HandlerRuntime>, Arc<dyn Messaging>, Arc<dyn KvStore>) {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let mq_kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let messaging: Arc<dyn Messaging> = Arc::new(LogMessaging::new(storage.clone(), mq_kv));
        let engine =
            boatramp_handlers::HandlerEngine::new(boatramp_handlers::Limits::default(), 16)
                .unwrap()
                .with_run_streaming(run_streaming);
        let rt = Arc::new(HandlerRuntime::new(
            engine,
            kv.clone(),
            storage,
            None,
            Some(messaging.clone()),
        ));
        (rt, messaging, kv)
    }

    /// The target-side run engine emitting to the run (what the real guest `run.emit` binding does),
    /// fenced to the SAME (project, scope) the subscription will attach under.
    fn target_engine(
        messaging: &Arc<dyn Messaging>,
        kv: &Arc<dyn KvStore>,
        scope: &str,
    ) -> RunEngine {
        RunEngine::new(
            messaging.clone(),
            kv.clone(),
            "acme".to_string(),
            scope.to_string(),
        )
    }

    fn local_ip() -> IpAddr {
        IpAddr::from([127u8, 0, 0, 1])
    }

    async fn body_text(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// Parse an SSE body into `(event, id, data)` triples, ignoring `:`-comment (keep-alive) lines.
    fn sse_events(body: &str) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        for block in body.split("\n\n") {
            let (mut event, mut id, mut data) = (String::new(), String::new(), String::new());
            let mut any = false;
            for line in block.lines() {
                if let Some(v) = line.strip_prefix("event:") {
                    event = v.trim().to_string();
                    any = true;
                } else if let Some(v) = line.strip_prefix("id:") {
                    id = v.trim().to_string();
                    any = true;
                } else if let Some(v) = line.strip_prefix("data:") {
                    data = v.trim().to_string();
                    any = true;
                }
            }
            if any {
                out.push((event, id, data));
            }
        }
        out
    }

    /// A GraphQL subscription ATTACHES to a run and receives the envelopes framed as graphql-sse
    /// `next` events (payload verbatim, `id:` = `seq`), ending with a `complete` on the terminal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graphql_subscription_attaches_and_frames_next_then_complete() {
        let (rt, messaging, kv) = setup(true);
        let inner = rt.inner.as_ref().unwrap();
        let te = target_engine(&messaging, &kv, "u");
        let run = te.create(false).await.unwrap();
        te.emit(
            &run,
            RunEventKind::Progress,
            br#"{"data":{"stage":"ocr"}}"#.to_vec(),
        )
        .await
        .unwrap();
        te.emit(
            &run,
            RunEventKind::Result,
            br#"{"data":{"done":true}}"#.to_vec(),
        )
        .await
        .unwrap();

        let resp = serve_graphql_run_subscription(inner, "acme", "u", &run, None, local_ip()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let events = sse_events(&body_text(resp).await);
        // next(progress) · next(result/terminal) · complete.
        assert_eq!(events.len(), 3, "events: {events:?}");
        assert_eq!(events[0].0, "next");
        assert_eq!(events[0].1, "0");
        assert_eq!(events[0].2, r#"{"data":{"stage":"ocr"}}"#);
        assert_eq!(events[1].0, "next");
        assert_eq!(events[1].1, "1");
        assert_eq!(events[1].2, r#"{"data":{"done":true}}"#);
        assert_eq!(events[2].0, "complete");
    }

    /// Resume strictly AFTER a `seq` (the `Last-Event-ID` cursor): only the un-consumed suffix, then
    /// `complete` — lossless, no gap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graphql_subscription_resumes_after_seq() {
        let (rt, messaging, kv) = setup(true);
        let inner = rt.inner.as_ref().unwrap();
        let te = target_engine(&messaging, &kv, "u");
        let run = te.create(false).await.unwrap();
        let p = te
            .emit(
                &run,
                RunEventKind::Progress,
                br#"{"data":{"p":1}}"#.to_vec(),
            )
            .await
            .unwrap();
        te.emit(
            &run,
            RunEventKind::Result,
            br#"{"data":{"done":true}}"#.to_vec(),
        )
        .await
        .unwrap();

        let resp =
            serve_graphql_run_subscription(inner, "acme", "u", &run, Some(p), local_ip()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let events = sse_events(&body_text(resp).await);
        assert_eq!(
            events.len(),
            2,
            "resume sees only the suffix + complete: {events:?}"
        );
        assert_eq!((events[0].0.as_str(), events[0].1.as_str()), ("next", "1"));
        assert_eq!(events[1].0, "complete");
    }

    /// A subscription CANNOT attach a run outside its tenancy scope: a run created under tenant `u`
    /// is `404` when the resolved subscriber scope is a DIFFERENT tenant (the key does not exist
    /// there) — never a cross-tenant touch.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graphql_subscription_cannot_attach_a_run_outside_its_scope() {
        let (rt, messaging, kv) = setup(true);
        let inner = rt.inner.as_ref().unwrap();
        // The run lives under the single-tenant `u` scope.
        let te = target_engine(&messaging, &kv, "u");
        let run = te.create(false).await.unwrap();
        te.emit(
            &run,
            RunEventKind::Progress,
            br#"{"data":{"x":1}}"#.to_vec(),
        )
        .await
        .unwrap();
        // Attaching under a DIFFERENT tenant scope composes a different key ⇒ NotFound ⇒ 404.
        let resp =
            serve_graphql_run_subscription(inner, "acme", "t_other", &run, None, local_ip()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // The real `u`-scoped run is untouched (still active).
        assert_eq!(
            te.status(&run).await.unwrap(),
            boatramp_core::run::RunStatus::Active
        );
    }

    /// Posture OFF (the default) ⇒ the run-attach face returns `403`, zero runtime exposure.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graphql_subscription_posture_off_is_refused() {
        let (rt, messaging, kv) = setup(false); // allow_run_streaming = false
        let inner = rt.inner.as_ref().unwrap();
        // Even a real, existing run under `u` is refused while the posture is off.
        let te = target_engine(&messaging, &kv, "u");
        let run = te.create(false).await.unwrap();
        let resp = serve_graphql_run_subscription(inner, "acme", "u", &run, None, local_ip()).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
