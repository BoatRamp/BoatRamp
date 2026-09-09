//! SSE-out + POST-in serving of the duplex/resumable `session` capability — **Stage 4** of
//! `PLAN-session-primitive`. Two entry points, both reached from [`serve_pipeline::serve_resolved`]
//! when a request path matches a deploy's [`SessionConfig`] route:
//!
//! - [`serve_session_open`] — a `GET` opens the **outbound** stream. It resolves + verifies the
//!   caller's principal (binding it to the session id on first open, and re-verifying it on every
//!   reconnect so a within-project id can't be hijacked), acks the client's `Last-Event-ID`, then
//!   fans the session's buffered outbound frames out as `text/event-stream`, resuming from the
//!   client's cursor. The producer polls the KV [`SessionStore`], so a frame the guest `send`s
//!   during a re-entry is delivered on the next tick — durable + multi-node-ready by construction.
//!
//! - [`dispatch_session_post`] — a `POST` delivers one **inbound** frame. It resolves + verifies the
//!   caller's principal (same admission), dedupes by an optional `Idempotency-Key`, then re-enters
//!   the guest `session-handler` via [`HandlerEngine::dispatch_session`] with the resume checkpoint
//!   and the inbound frame, binding the session controller (so the guest's `send`/`checkpoint`/
//!   `close` land in the store) plus the verified principal's tenancy (so a frame-triggered
//!   `sql`/`orm` is host-scoped identically to a normal handler).
//!
//! Frames are **opaque bytes** end to end — the host never parses one. On the SSE wire an outbound
//! frame's payload is base64 in the event `data:` (so any byte string survives the text-only SSE
//! framing), the event `id:` is its monotonic cursor (the client's `Last-Event-ID` resume token),
//! and a terminal `event: close` carries the close reason. The session id, principal, and tenancy
//! are all **host-stamped**; the guest never names another session or forges a tenant.
//!
//! ## Security model (what the admission does and does NOT isolate)
//!
//! - **Cross-tenant isolation is structural.** The store key is `session/<project>/<id>` with
//!   `project` host-stamped from the resolved site owner (never guest input), so a caller can only
//!   ever address a session under its own project — cross-tenant reach is absent by construction.
//! - **Binding is by the resolved TENANT value, not a per-user identity.** The sealed `principal`
//!   is the tenancy value (the tenant-column value / domain tag), so the reconnect re-verification
//!   isolates across *tenants*, not across users *within* one tenant. **Within a tenant a session id
//!   is a bearer capability**: two users of the same tenant seal identically, so anyone who learns
//!   the id can drive/read that session. Apps MUST therefore treat the id as a secret (the shim
//!   generates an unguessable UUID) and must not use a session as a per-user auth boundary beyond
//!   the tenant. Anonymous (`tenancy = none`) sessions have `principal = None` — the id secrecy is
//!   then the *only* boundary. `valid_session_id` bounds + charset-restricts the id but does not
//!   mint entropy; that is the app/shim's responsibility.
//! - **Delivery is at-least-once, so re-entries may replay.** The inbound dedup key is committed only
//!   after a successful re-entry, so a trapped dispatch redelivers the frame rather than dropping it;
//!   a guest's `send`s from a partially-run then-trapped re-entry are already persisted, so a guest
//!   handler must be **idempotent w.r.t. its own effects** across a redelivery (checkpoint-gated).
//! - **Resource bounds:** per-frame size, outbound buffer, dedup window, checkpoint size, and the
//!   idle-TTL (enforced by the scheduler-driven reaper) + a per-project open cap bound KV growth;
//!   the SSE GET and the POST re-entry both hold a per-scope + per-`(scope,IP)` admission slot.
//! - **Preview caveat:** a session route served under a by-id preview inherits the preview path's
//!   "unguessable id = the capability" model (site visitor access-control/WAF/rate-limit does not run
//!   on preview serving) — but its session record is preview-scoped (a distinct key), so live and
//!   preview never share state.

use super::*;

use std::sync::Arc;

use boatramp_core::session::Cursor;
#[cfg(test)]
use boatramp_core::sql::SqlValue;
use boatramp_core::time::now_unix_ms;

use crate::session_store::{SessionStore, StoreError};

/// How often the SSE producer re-reads the store for freshly-`send`'d outbound frames when idle. A
/// poll that returns frames loops again immediately, so this bounds only the empty-poll latency;
/// replacing it with a notify is the measured Stage-6 refinement. Frames are never lost by polling —
/// they are buffered in the store until acked.
const SESSION_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// SSE heartbeat: a `: keep-alive` comment on this cadence detects a dead client (its socket write
/// fails, tearing the stream down and dropping the connection's permits) between outbound frames.
const SESSION_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(15);

/// Seal the resolved **principal** (the axis-tagged fact set) to the opaque bytes stored as a
/// session's `principal`. Compared for **equality** at re-open/re-entry admission (never parsed back
/// or shown to the guest), so the [`Debug`] rendering — total over every [`ScopeFact`]/[`SqlValue`]
/// variant and stable within a process — is a sufficient, maintenance-free encoding. An empty fact
/// set (anonymous) seals to `None`. Sealing the whole set (not just the tenant value) binds the
/// session to the full principal, so a later `Session`/`TargetTenant` fact is part of the identity.
fn seal_principal(facts: &[boatramp_handlers::ScopeFact]) -> Option<Vec<u8>> {
    if facts.is_empty() {
        None
    } else {
        Some(format!("{facts:?}").into_bytes())
    }
}

/// Upper bound on the client-chosen session id — it lands verbatim in a KV key and the record.
const MAX_SESSION_ID_LEN: usize = 256;

/// Whether a client-supplied session id is acceptable: non-empty, bounded, and made of only RFC 3986
/// **unreserved** characters. The charset restriction is load-bearing — it forbids `/`, `%`, and
/// other bytes, so a client can neither inject extra path segments into the `session/<project>/…`
/// keyspace nor collide with the host's own `_preview/<id>/` scoping prefix. The id is a bearer
/// capability *within* a tenant (the principal-match only isolates across principals/tenants), so an
/// app must use an unguessable value — the shim generates a UUID.
fn valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SESSION_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
}

/// The store-facing session id: the raw client id for live serving, or a `_preview/<pid>/` prefixed
/// id under a by-id preview, so a preview's session record is **distinct** from the live one on the
/// same client id (its guest bindings are already preview-isolated — the record must match). The
/// `/` here is host-injected and can't come from the client id (see [`valid_session_id`]).
fn store_id(preview: Option<&str>, id: &str) -> String {
    match preview {
        Some(pid) => format!("_preview/{pid}/{id}"),
        None => id.to_string(),
    }
}

/// The per-scope key for the shared topic-stream connection caps: the raw site, or the
/// preview-namespaced form. **Not** project-qualified (matches `serve_stream`) — this is an operator
/// resource budget, not a tenant boundary (the tenant boundary is the store's project-keyed record).
fn stream_scope(site: &str, preview: Option<&str>) -> String {
    match preview {
        Some(pid) => format!("{site}/_preview/{pid}"),
        None => site.to_string(),
    }
}

/// The lazily-built, KV-backed session store for this runtime (default [`SessionLimits`]; no operator
/// gate — the `session` feature + the guest's declared capability + the site allowlist govern it).
pub(super) fn session_store(inner: &HandlerRuntimeInner) -> SessionStore {
    inner
        .session_store
        .get_or_init(|| {
            SessionStore::new(
                inner.kv.clone(),
                boatramp_core::session::SessionLimits::default(),
            )
        })
        .clone()
}

/// The `id` query parameter (the client-chosen, host-namespaced session id) from a request URI.
/// Sessions are addressed by `?id=<id>`; a missing/empty id is rejected by the caller.
fn query_param<'a>(uri: &'a axum::http::Uri, key: &str) -> Option<&'a str> {
    uri.query().and_then(|q| {
        q.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == key).then_some(v)
        })
    })
}

/// The app bearer (verified downstream) carried on a request, for the `token` tenant source.
fn request_bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
        })
        .map(str::to_string)
}

/// Resolve the caller's **in-site tenant value** for a session request from its verified source
/// (bearer / routed domain), applying the operator posture — the same resolution
/// [`build_function_bindings`] runs for a function, but returning just the value so the serving layer
/// can seal it for admission before building the bindings. `Ok(None)` = anonymous / null-only;
/// `Err` = an `sql`/`orm` importer that declared no tenancy under the strict posture (fail-closed).
async fn resolve_session_principal(
    inner: &HandlerRuntimeInner,
    session: &boatramp_core::config::SessionConfig,
    bearer: Option<&str>,
    domain_context: Option<&str>,
) -> Result<Vec<boatramp_handlers::ScopeFact>, String> {
    let imports_db = session.imports.iter().any(|i| i == "sql")
        || session.imports.iter().any(|i| i.starts_with("sql:"));
    let posture = crate::tenant_resolve::TenantPosture {
        require_declaration: inner
            .require_tenancy_declaration
            .get()
            .copied()
            .unwrap_or(true),
        allow_cross_tenant: inner.allow_cross_tenant_db.get().copied().unwrap_or(false),
    };
    let resolved = crate::tenant_resolve::resolve_host_tenancy(
        session.tenancy.as_ref(),
        imports_db,
        posture,
        crate::tenant_resolve::TenantSourceInputs {
            bearer,
            domain_context,
            token_cfg: session.token_claims.as_ref(),
            session_cookie: None,
            session_anchor: None,
            // The session-primitive serving path is the sync request lane, not the durable async
            // lane, so it carries no signed-context envelope.
            signed_context: None,
            context_anchor: None,
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(resolved.map(|h| h.facts().to_vec()).unwrap_or_default())
}

/// The binding identity for a session: the preview-namespaced site, project-qualified (BR-TEN-1) —
/// identical to a handler's `scope`, so a session's kv/blob/messaging/logs land in its own
/// tenant-isolated namespace.
fn session_scope(project: &str, site: &str, preview: Option<&str>) -> String {
    let base = match preview {
        Some(id) => format!("{site}/_preview/{id}"),
        None => site.to_string(),
    };
    boatramp_core::project::ProjectRef::new(project).qualified(&base)
}

/// Open (or resume) a session's **outbound** SSE stream. `GET` half of a session route.
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_session_open(
    inner: &Arc<HandlerRuntimeInner>,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    project: &str,
    site: &str,
    session: &boatramp_core::config::SessionConfig,
    request: Request,
    client_ip: IpAddr,
    preview: Option<&str>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};

    // The session id (client-chosen, host-namespaced under `project`). Required + bounded/charset.
    let Some(id) = query_param(request.uri(), "id").filter(|s| valid_session_id(s)) else {
        return (
            StatusCode::BAD_REQUEST,
            "session open requires a valid `id` query parameter\n",
        )
            .into_response();
    };
    // Store-facing id (preview-scoped so a preview session is a distinct record).
    let id = store_id(preview, id);
    // Resume cursor: the reconnect `Last-Event-ID` header (EventSource sets it), else an explicit
    // `?cursor=` on first connect, else 0 (from the beginning).
    let after: Cursor = request
        .headers()
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .or_else(|| query_param(request.uri(), "cursor"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Resolve + verify the caller's principal, then admit: bind it to the id on first open, or
    // refuse a reconnect whose principal differs (within-project hijack). Cross-tenant reach is
    // already impossible — the store key is namespaced under `project`.
    let bearer = request_bearer(request.headers());
    let domain_context = request
        .extensions()
        .get::<crate::DomainContext>()
        .map(|c| c.0.clone());
    let principal = match resolve_session_principal(
        inner,
        session,
        bearer.as_deref(),
        domain_context.as_deref(),
    )
    .await
    {
        Ok(facts) => seal_principal(&facts),
        Err(err) => {
            tracing::warn!(site, route = %session.route, %err, "session tenancy refused");
            return (StatusCode::FORBIDDEN, "session tenancy refused\n").into_response();
        }
    };
    let store = session_store(inner);
    let now = now_unix_ms();
    match store
        .open_or_verify(project, &id, &session.route, principal, now)
        .await
    {
        Ok(()) => {}
        Err(StoreError::PrincipalMismatch) => {
            return (StatusCode::FORBIDDEN, "session principal mismatch\n").into_response();
        }
        Err(StoreError::ProjectSessionsFull) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "project session limit reached\n",
            )
                .into_response();
        }
        Err(err) => {
            tracing::warn!(site, %err, "opening session failed");
            return handler_unavailable();
        }
    }
    // The client's `Last-Event-ID` confirms delivery up to `after`: ack it (GC the acked buffer) and
    // refresh liveness so an actively-listening session isn't reaped mid-stream.
    let _ = store.ack(project, &id, after, now).await;

    // Per-scope + per-IP SSE connection caps, shared with the topic-stream fan-out and held for the
    // connection's lifetime via the guards moved into the producer below.
    let scope = stream_scope(site, preview);
    let site_permit = match crate::stream::acquire_stream_permit(inner, &scope, site_handlers) {
        Ok(permit) => permit,
        Err(()) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "site stream connection limit reached\n",
            )
                .into_response()
        }
    };
    let ip_guard = match crate::stream::acquire_stream_ip_slot(inner, &scope, client_ip) {
        Ok(guard) => guard,
        Err(()) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "per-client stream connection limit reached\n",
            )
                .into_response()
        }
    };

    // The poll-based outbound producer: drain the store's buffered frames past the client's cursor,
    // then poll for more; end on close (emit a final `close` event) or expiry/reap.
    struct Producer {
        store: SessionStore,
        project: String,
        id: String,
        cursor: Cursor,
        pending: std::collections::VecDeque<Event>,
        done: bool,
        _site_permit: tokio::sync::OwnedSemaphorePermit,
        _ip_guard: crate::stream::IpStreamGuard,
    }
    let producer = Producer {
        store,
        project: project.to_string(),
        id,
        cursor: after,
        pending: std::collections::VecDeque::new(),
        done: false,
        _site_permit: site_permit,
        _ip_guard: ip_guard,
    };
    let body = futures::stream::unfold(producer, |mut p| async move {
        loop {
            if let Some(event) = p.pending.pop_front() {
                return Some((Ok::<Event, std::convert::Infallible>(event), p));
            }
            if p.done {
                return None;
            }
            match p
                .store
                .poll(&p.project, &p.id, p.cursor, now_unix_ms())
                .await
            {
                Ok(poll) => {
                    for frame in poll.frames {
                        p.cursor = frame.cursor;
                        p.pending
                            .push_back(frame_event(frame.cursor, &frame.payload));
                    }
                    if let Some(reason) = poll.closed {
                        p.pending.push_back(close_event(&reason));
                        p.done = true;
                        continue;
                    }
                    if !p.pending.is_empty() {
                        continue; // deliver what we drained, then loop (poll again immediately)
                    }
                    if poll.expired {
                        // Idle past the TTL: tell the client it's terminal, then end.
                        p.pending.push_back(close_event("idle"));
                        p.done = true;
                        continue;
                    }
                    // Nothing new and still live: wait a tick (heartbeats keep the socket warm).
                    tokio::time::sleep(SESSION_POLL_INTERVAL).await;
                }
                // Reaped (or never opened): the stream is over.
                Err(_) => return None,
            }
        }
    });

    Sse::new(body)
        .keep_alive(
            KeepAlive::new()
                .interval(SESSION_HEARTBEAT)
                .text("keep-alive"),
        )
        .into_response()
}

/// One outbound frame as an SSE event: base64 `data:` (opaque bytes survive text-only framing), the
/// monotonic cursor as the `id:` (the client's `Last-Event-ID` resume token), event name `frame`.
fn frame_event(cursor: Cursor, payload: &[u8]) -> axum::response::sse::Event {
    use base64::Engine;
    axum::response::sse::Event::default()
        .id(cursor.to_string())
        .event("frame")
        .data(base64::engine::general_purpose::STANDARD.encode(payload))
}

/// The terminal `event: close` carrying the close reason; the client stops resuming on it.
fn close_event(reason: &str) -> axum::response::sse::Event {
    axum::response::sse::Event::default()
        .event("close")
        .data(reason)
}

/// Deliver one **inbound** frame, re-entering the guest `session-handler`. `POST` half of a session
/// route.
#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch_session_post(
    inner: &Arc<HandlerRuntimeInner>,
    deploy: &DeployStore,
    manifest: &Manifest,
    site_handlers: &boatramp_core::config::HandlersSiteConfig,
    project: &str,
    site: &str,
    session: &boatramp_core::config::SessionConfig,
    request: Request,
    client_ip: IpAddr,
    preview: Option<&str>,
) -> Response {
    let (parts, body) = request.into_parts();
    // The session id (required + bounded/charset) + an optional `ack` cursor (the client's confirmed
    // `Last-Event-ID`, GCing the acked outbound buffer mid-stream) + an optional idempotency key
    // (dedupe a retried POST). EventSource can't POST, so the client's own fetch supplies these.
    let Some(id) = query_param(&parts.uri, "id").filter(|s| valid_session_id(s)) else {
        return (
            StatusCode::BAD_REQUEST,
            "session frame requires a valid `id` query parameter\n",
        )
            .into_response();
    };
    // Store-facing id (preview-scoped so a preview session is a distinct record).
    let id = store_id(preview, id);

    // Bound inbound amplification: hold a per-scope + per-(scope,IP) admission slot for this POST's
    // duration BEFORE any KV work, so a client can't drive unbounded open/record/instantiate churn.
    // (The engine's async lane caps the expensive dispatch itself; this caps the pre-dispatch KV
    // round-trips too.) Shares the topic-stream connection budget for the scope.
    let permit_scope = stream_scope(site, preview);
    let _site_permit =
        match crate::stream::acquire_stream_permit(inner, &permit_scope, site_handlers) {
            Ok(permit) => permit,
            Err(()) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "site stream connection limit reached\n",
                )
                    .into_response()
            }
        };
    let _ip_guard = match crate::stream::acquire_stream_ip_slot(inner, &permit_scope, client_ip) {
        Ok(guard) => guard,
        Err(()) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "per-client stream connection limit reached\n",
            )
                .into_response()
        }
    };

    let ack: Option<Cursor> = query_param(&parts.uri, "ack").and_then(|s| s.parse().ok());
    let idem_key = parts
        .headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| query_param(&parts.uri, "idem").map(str::to_string));

    // Resolve + verify the caller's principal (same admission as open), then bind/verify it on the
    // id. A frame on an id bound to a different principal is refused (within-project hijack).
    let bearer = request_bearer(&parts.headers);
    let domain_context = parts
        .extensions
        .get::<crate::DomainContext>()
        .map(|c| c.0.clone());
    let caller_tenant = match resolve_session_principal(
        inner,
        session,
        bearer.as_deref(),
        domain_context.as_deref(),
    )
    .await
    {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(site, route = %session.route, %err, "session tenancy refused");
            return (StatusCode::FORBIDDEN, "session tenancy refused\n").into_response();
        }
    };
    let principal = seal_principal(&caller_tenant);
    let store = session_store(inner);
    let now = now_unix_ms();
    match store
        .open_or_verify(project, &id, &session.route, principal, now)
        .await
    {
        Ok(()) => {}
        Err(StoreError::PrincipalMismatch) => {
            return (StatusCode::FORBIDDEN, "session principal mismatch\n").into_response();
        }
        Err(StoreError::ProjectSessionsFull) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "project session limit reached\n",
            )
                .into_response();
        }
        Err(err) => {
            tracing::warn!(site, %err, "opening session failed");
            return handler_unavailable();
        }
    }
    if let Some(cursor) = ack {
        let _ = store.ack(project, &id, cursor, now).await;
    }
    // A frame on a closed session is refused cleanly up front (410) rather than letting the guest's
    // `send` fail mid-re-entry. NotFound (reaped between admission and here) is likewise terminal.
    match store.is_closed(project, &id).await {
        Ok(false) => {}
        Ok(true) | Err(StoreError::NotFound) => {
            return (StatusCode::GONE, "session is closed\n").into_response();
        }
        Err(err) => {
            tracing::warn!(site, %err, "checking session state failed");
            return handler_unavailable();
        }
    }

    // Buffer the inbound frame, capped at the session frame-size limit (opaque bytes, one frame).
    let max_frame = store.limits().max_frame_bytes;
    let frame = match axum::body::to_bytes(body, max_frame).await {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "session frame too large\n").into_response();
        }
    };

    // Inbound dedup — CHECK only (don't record yet): a retried POST with the same idempotency key
    // within the dedup window returns 200 without re-running. The key is COMMITTED only after a
    // successful re-entry (below), so a trapped dispatch redelivers the frame (at-least-once) rather
    // than silently dropping it — honoring the WIT contract. A frame on a closed/reaped session is
    // gone. (NOTE: at-least-once permits replay, and a guest's `send`s from a partially-run,
    // then-trapped re-entry are already committed; a guest handler must therefore be idempotent
    // w.r.t. its own effects across a redelivery — documented in the WIT + how-to.)
    if let Some(key) = &idem_key {
        match store.seen(project, &id, key).await {
            Ok(true) => {
                return (StatusCode::OK, "duplicate frame ignored\n").into_response();
            }
            Ok(false) => {}
            Err(StoreError::NotFound) => {
                return (StatusCode::GONE, "session is closed\n").into_response();
            }
            Err(err) => {
                tracing::warn!(site, %err, "checking session inbound dedup failed");
                return handler_unavailable();
            }
        }
    }

    // Build the guest's bindings exactly as a function's, with the verified principal's tenancy
    // carried in (Inherited — already resolved above, so no second bearer verification), then bind
    // the session controller scoped to this `(project, id)` so `send`/`checkpoint`/`close` reach the
    // store.
    let scope = session_scope(project, site, preview);
    let fn_config = boatramp_core::function::FunctionConfig {
        imports: session.imports.clone(),
        limits: session.limits.clone(),
        env: session.env.clone(),
        invoke_targets: session.invoke_targets.clone(),
        tenancy: session.tenancy.clone(),
        token_claims: session.token_claims.clone(),
        ..Default::default()
    };
    let project_ref = boatramp_core::project::ProjectRef::new(project);
    let bindings = match crate::function_runtime::build_function_bindings(
        inner,
        project_ref,
        &scope,
        site,
        &fn_config,
        0,
        &crate::function_runtime::FnTenant::Inherited(caller_tenant),
        bearer.as_deref(),
        domain_context.as_deref(),
    )
    .await
    {
        Ok(bindings) => bindings.with_session(crate::session_driver::controller(
            store.clone(),
            project,
            &id,
        )),
        Err(err) => {
            tracing::warn!(site, route = %session.route, %err, "session bindings refused");
            return handler_unavailable();
        }
    };

    // The component `.wasm` is a content-addressed blob in the deployment.
    let Some(entry) = manifest.files.get(&session.component) else {
        tracing::warn!(site, component = %session.component, "session component missing from deployment");
        return handler_unavailable();
    };
    let wasm = match read_blob_fully(deploy, &entry.hash).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };

    // Re-enter the guest with the resume checkpoint + this inbound frame.
    let resumed = store.resumed(project, &id).await.ok().flatten();
    let batch = boatramp_handlers::SessionBatch {
        id: id.clone(),
        resumed,
        frames: vec![frame],
    };
    let limits = crate::function_runtime::function_limits(session.limits.as_ref());
    let start = std::time::Instant::now();
    let result = inner
        .engine
        .dispatch_session(&entry.hash, &wasm, batch, bindings, limits)
        .await;
    inner.metrics.observe(
        site,
        metrics::Trigger::Http,
        &session.route,
        &entry.hash,
        metrics::Outcome::from_result(&result),
        start.elapsed(),
    );
    match result {
        Ok(()) => {
            // Commit the dedup key only now the re-entry succeeded — a later retry with the same key
            // is deduped, while a trapped dispatch (the Err arm) left it unrecorded so the frame
            // redelivers. Best-effort: if the guest closed the session during the re-entry the record
            // is gone, which is fine (a retry then gets `GONE`). The guest's sends/checkpoint already
            // committed to the store; the SSE stream delivers them.
            if let Some(key) = &idem_key {
                let _ = store.record_inbound(project, &id, key, now_unix_ms()).await;
            }
            (StatusCode::ACCEPTED, "frame accepted\n").into_response()
        }
        Err(err) => {
            tracing::warn!(site, route = %session.route, %err, "session re-entry failed");
            handler_error_response(&err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_is_deterministic_total_and_distinguishes_values() {
        use boatramp_core::tenancy::ScopeAxis;
        // A single-Tenant-fact principal for a value (the Stage-2 shape).
        let fact = |v: SqlValue| {
            vec![boatramp_handlers::ScopeFact {
                axis: ScopeAxis::Tenant,
                value: v,
            }]
        };
        // Anonymous (empty fact set) seals to None; every value variant seals to some stable bytes.
        assert_eq!(seal_principal(&[]), None);
        for v in [
            SqlValue::Null,
            SqlValue::Boolean(true),
            SqlValue::Integer(42),
            SqlValue::Real(1.5),
            SqlValue::Text("acme".into()),
            SqlValue::Blob(vec![0, 255, 7]),
        ] {
            let a = seal_principal(&fact(v.clone()));
            let b = seal_principal(&fact(v.clone()));
            assert_eq!(a, b, "seal must be deterministic for {v:?}");
            assert!(a.is_some());
        }
        // Different values (and an empty vs a value) must not collide — the admission check is an
        // equality compare of these bytes.
        assert_ne!(
            seal_principal(&fact(SqlValue::Integer(1))),
            seal_principal(&fact(SqlValue::Integer(2)))
        );
        assert_ne!(
            seal_principal(&fact(SqlValue::Integer(1))),
            seal_principal(&fact(SqlValue::Text("1".into())))
        );
        assert_ne!(seal_principal(&fact(SqlValue::Null)), seal_principal(&[]));
    }

    #[test]
    fn query_param_extracts_by_key() {
        let uri: axum::http::Uri = "http://x/s?id=abc&cursor=7&ack=3".parse().unwrap();
        assert_eq!(query_param(&uri, "id"), Some("abc"));
        assert_eq!(query_param(&uri, "cursor"), Some("7"));
        assert_eq!(query_param(&uri, "ack"), Some("3"));
        assert_eq!(query_param(&uri, "missing"), None);
        // No query string at all.
        let bare: axum::http::Uri = "http://x/s".parse().unwrap();
        assert_eq!(query_param(&bare, "id"), None);
    }
}
