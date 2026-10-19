//! Live topic streaming — the SSE and WebSocket fan-out of `wasi:messaging`
//! topics, with per-connection and per-IP permit accounting (RAII-reclaimed).
//! `handlers`-gated; pulls the serve-pipeline scope in via `use super::*`.

use super::*;

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
        .max(1) as usize;
    // `KeyedSemaphores::gate` re-sizes on a `maxStreamConnections` reload; `try_acquire` keeps the
    // shed-to-503 semantics.
    inner
        .stream_semaphores
        .gate(scope, max)
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
) -> Result<Vec<String>, Response> {
    use boatramp_core::config::{StreamAuthz, StreamMembership};
    let Some(authz) = &stream.authz else {
        return Ok(stream.topics.clone());
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
            Ok(resolve_topic_templates(&stream.topics, &params))
        }
        StreamAuthz::GuestMediated { .. } => Err((
            StatusCode::NOT_IMPLEMENTED,
            "guest-mediated stream authz is not yet wired\n",
        )
            .into_response()),
    }
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

/// Rewrite `$name` placeholders in a membership query to canonical positional `$1..$N` (the backend
/// re-renders them per dialect) and collect the bound values in order. A `$name` binds the route
/// param `name`, else the verified claim `name`, else `NULL` (so the predicate denies — fail-safe).
/// A repeated `$name` reuses its one positional bind.
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
            out.push('$');
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
        .map(|t| {
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
        })
        .collect()
}

/// Serve a configured SSE stream: subscribe to each of its (scope-namespaced)
/// topics on the messaging backend and fan them out to the client as
/// `text/event-stream`, with `Last-Event-ID` resume, a heartbeat, an idle
/// timeout, and per-scope + per-IP connection caps.
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
    // #11: authorize the connection and resolve the per-connection topic set BEFORE acquiring any
    // permit (deny before resource use). No `authz` ⇒ the static broadcast topics.
    let topics =
        match authorize_stream_topics(inner, project, site, stream, request_path, bearer).await {
            Ok(topics) => topics,
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
        // `$mailbox`→$1 (reused for `owner`), `$sub`→$2, `$absent`→$3: positional, first-seen order.
        assert_eq!(
            sql,
            "SELECT 1 FROM m WHERE mailbox=$1 AND subject=$2 AND owner=$1 AND x=$3"
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
    // #11: capture the owned bits the authz check needs (bearer + path) BEFORE releasing the
    // request — `&Request` must not be held across the authz awaits.
    let request_path = request.uri().path().to_string();
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
    let scope = match preview {
        Some(id) => format!("{site}/_preview/{id}"),
        None => site.to_string(),
    };
    // #11: authorize + resolve the per-connection topic set (or 401/403) before acquiring a permit.
    let topics = match authorize_stream_topics(
        inner,
        project,
        site,
        stream,
        &request_path,
        bearer.as_deref(),
    )
    .await
    {
        Ok(topics) => topics,
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
    // client→server: messages publish to this scope-namespaced topic (if set).
    let publish_topic = stream
        .publish_topic
        .as_ref()
        .map(|topic| format!("{scope}/{topic}"));

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
                    // Ping/Pong/Close: tungstenite auto-answers pings; ignore the rest.
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => {}
                },
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
