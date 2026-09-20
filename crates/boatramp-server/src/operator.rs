//! The operator / metrics endpoints: consumer + DLQ queue health, the dead-letter
//! redrive/purge actions, the operator log tail (poll + SSE), and the Prometheus
//! `/metrics` scrape. All handler-runtime introspection, so the whole module is
//! `handlers`-gated; it pulls the serve-pipeline scope in via `use super::*`.

use super::*;
#[cfg(feature = "handlers")]
use boatramp_core::project::ProjectRef;

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
    /// In-flight (leased-but-unacked) messages — a subset of `backlog`. Lets an operator tell
    /// "queued and draining" from "queued and wedged". (Additive; older clients ignore it.)
    in_flight: usize,
    /// Age in ms of the oldest still-pending message (the work-queue frontier), or `null` if empty
    /// — "how stale is my backlog". (Additive.)
    #[serde(skip_serializing_if = "Option::is_none")]
    oldest_pending_ms: Option<u64>,
    /// For a fan-out (grouped) consumer: retained messages this group has not yet leased ("who's
    /// lagging"). `0` for the default work-queue (there `backlog` is the lag). (Additive.)
    lag: usize,
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
pub(super) async fn operator_handler_stats(
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

/// The versioned DLQ view schema (UX5): bumped only on a breaking shape change, so a client can
/// detect an incompatible server.
#[cfg(feature = "handlers")]
const DLQ_VIEW_VERSION: u32 = 1;

/// Which dead-letter operation `POST …/_boatramp/dlq` should run (all mutating → operator-auth,
/// site-scoped). Reads (`ls`/`show`) go through the GET endpoint.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum DlqAction {
    /// Drop the dead-lettered messages (records + payloads).
    Purge,
    /// Requeue them onto the live topic with a fresh attempt count.
    Redrive,
    /// Selectively drop only the filter-matching dead-letters (never re-queued).
    Discard,
}

/// An AND-composed dead-letter filter as sent over the wire (mirrors
/// [`boatramp_core::messaging::DeadLetterFilter`], flattened into the request/query).
#[cfg(feature = "handlers")]
#[derive(Deserialize, Default)]
pub(super) struct DlqFilterWire {
    /// Exact message id.
    #[serde(default)]
    id: Option<String>,
    /// Lane: `""` = work-queue, else a group; omitted = all lanes.
    #[serde(default)]
    group: Option<String>,
    /// Only messages older than this many ms (age from the time-ordered id).
    #[serde(default)]
    older_than_ms: Option<u64>,
    /// Substring match on the host `last_error`.
    #[serde(default, rename = "match")]
    match_last_error: Option<String>,
    /// Cap the number listed/acted on.
    #[serde(default)]
    limit: Option<usize>,
}

#[cfg(feature = "handlers")]
impl DlqFilterWire {
    fn into_core(self) -> boatramp_core::messaging::DeadLetterFilter {
        boatramp_core::messaging::DeadLetterFilter {
            id: self.id,
            group: self.group,
            older_than_ms: self.older_than_ms,
            match_last_error: self.match_last_error,
            limit: self.limit,
        }
    }

    fn is_empty(&self) -> bool {
        self.id.is_none()
            && self.group.is_none()
            && self.older_than_ms.is_none()
            && self.match_last_error.is_none()
            && self.limit.is_none()
    }
}

/// `POST …/_boatramp/dlq` request: which consumer topic, and what to do.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct DlqRequest {
    /// The consumer's topic (scope-relative, as declared in the deploy config).
    topic: String,
    /// Background-alias scope (`{site}/{alias}`); omitted = the live site.
    #[serde(default)]
    alias: Option<String>,
    /// `purge`, `redrive`, or `discard`.
    action: DlqAction,
    /// The selective filter (P1). Absent/empty ⇒ the WHOLE-DLQ op (back-compat): `purge`/`redrive`
    /// over everything. A `discard` with an empty filter still acts on all (explicit intent).
    #[serde(default)]
    filter: DlqFilterWire,
    /// Preview only: return the matching set WITHOUT acting (`--dry-run`). No mutation is proposed.
    #[serde(default)]
    dry_run: bool,
}

/// One dead-letter in an operator DLQ view. `payload_b64` is present only in a `show`; the
/// producer's signed-context is exposed as PRESENCE only (never the tenant-bearing envelope value).
#[cfg(feature = "handlers")]
#[derive(Serialize)]
struct DlqEntry {
    id: String,
    group: String,
    attempts: u32,
    last_error: Option<String>,
    signed_context_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_b64: Option<String>,
}

#[cfg(feature = "handlers")]
impl DlqEntry {
    fn from_dead(dl: boatramp_core::messaging::DeadLetter) -> Self {
        use base64::Engine as _;
        Self {
            id: dl.id,
            group: dl.group,
            attempts: dl.attempts,
            last_error: dl.last_error,
            signed_context_present: dl.signed_context.is_some(),
            payload_b64: dl
                .payload
                .map(|p| base64::engine::general_purpose::STANDARD.encode(p)),
        }
    }
}

#[cfg(feature = "handlers")]
#[derive(Serialize)]
struct DlqResponse {
    /// Number of dead-lettered messages affected (or that WOULD be, for `dry_run`).
    affected: usize,
    /// The matching dead-letters — metadata only, populated for a `dry_run` (a preview) so an
    /// operator can see exactly what a `redrive`/`discard` would touch before confirming.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    matched: Vec<DlqEntry>,
}

#[cfg(feature = "handlers")]
#[derive(Serialize)]
struct DlqListResponse {
    /// The DLQ view schema version (UX5).
    version: u32,
    dead_letters: Vec<DlqEntry>,
}

/// `GET …/_boatramp/dlq` query: list (metadata) or show one (with payload). Site-scoped, read-only.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct DlqListQuery {
    topic: String,
    #[serde(default)]
    alias: Option<String>,
    /// Return one dead-letter IN FULL (with payload) instead of a list — requires `id`.
    #[serde(default)]
    show: bool,
    #[serde(flatten)]
    filter: DlqFilterWire,
}

/// Namespace a scope-relative topic exactly as the dispatcher does: `{site}/{topic}`, or
/// `{site}/{alias}/{topic}` for a background-alias consumer — so an operator only touches their own
/// site's queues.
#[cfg(feature = "handlers")]
fn dlq_namespace(site: &str, alias: &Option<String>, topic: &str) -> String {
    match alias {
        Some(alias) => format!("{site}/{alias}/{topic}"),
        None => format!("{site}/{topic}"),
    }
}

/// Namespace a project-bus topic exactly as the dispatcher does for a `bus:<topic>` publish:
/// `{project}/bus/{topic}` (bare `bus/{topic}` for the reserved `default` project, matching
/// [`ProjectRef::qualified`]) — the shared, project-scoped bus keyspace common to every site in
/// the project (see `handler_dispatch`'s `project.qualified("bus")`). An operator token scoped to
/// project P thus only ever touches P's bus.
#[cfg(feature = "handlers")]
fn bus_namespace(project: &ProjectRef<'_>, topic: &str) -> String {
    project.qualified(&format!("bus/{topic}"))
}

/// The `messaging` backend, or the shared "not configured" 503 the DLQ/queue endpoints all return
/// when no bus is wired — hoisted so the site and project-bus handlers share one guard.
#[cfg(feature = "handlers")]
fn messaging_or_unavailable(
    handlers: &HandlerRuntime,
) -> Result<&std::sync::Arc<dyn boatramp_core::messaging::Messaging>, Response> {
    let Some(inner) = handlers.inner.as_ref() else {
        return Err(not_found());
    };
    inner.messaging.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "messaging backend not configured\n",
        )
            .into_response()
    })
}

/// Operator dead-letter INSPECTION (`GET …/_boatramp/dlq`, read): `ls` (filter-matching metadata) or
/// `show` (one dead-letter in full, incl. payload). Site-scoped like the mutating POST.
#[cfg(feature = "handlers")]
pub(super) async fn operator_dlq_list(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
    axum::extract::Query(q): axum::extract::Query<DlqListQuery>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = dlq_namespace(&site, &q.alias, &q.topic);
    dlq_list_core(messaging.as_ref(), &namespaced, q.show, q.filter).await
}

/// Shared inner logic of the DLQ INSPECTION endpoint (`ls`/`show`), over an
/// already-namespaced topic — so the site (`{site}/{topic}`) and project-bus
/// (`{project}/bus/{topic}`) endpoints share one implementation and one response shape.
#[cfg(feature = "handlers")]
async fn dlq_list_core(
    messaging: &dyn boatramp_core::messaging::Messaging,
    namespaced: &str,
    show: bool,
    filter: DlqFilterWire,
) -> Response {
    if show {
        let Some(id) = filter.id.clone() else {
            return (StatusCode::BAD_REQUEST, "show requires ?id=<id>\n").into_response();
        };
        let group = filter.group.clone().unwrap_or_default();
        return match messaging.show_dead_letter(namespaced, &group, &id).await {
            Ok(Some(dl)) => Json(DlqListResponse {
                version: DLQ_VIEW_VERSION,
                dead_letters: vec![DlqEntry::from_dead(dl)],
            })
            .into_response(),
            Ok(None) => not_found(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("dead-letter show failed: {err}\n"),
            )
                .into_response(),
        };
    }
    match messaging
        .list_dead_letters(namespaced, &filter.into_core())
        .await
    {
        Ok(list) => Json(DlqListResponse {
            version: DLQ_VIEW_VERSION,
            dead_letters: list.into_iter().map(DlqEntry::from_dead).collect(),
        })
        .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("dead-letter list failed: {err}\n"),
        )
            .into_response(),
    }
}

/// `GET …/_boatramp/queue/peek` query: inspect the head of a LIVE work-queue without consuming.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct QueuePeekQuery {
    topic: String,
    #[serde(default)]
    alias: Option<String>,
    /// How many messages to peek (head of the queue, delivery order). Defaults to 10; hard-capped.
    #[serde(default)]
    limit: Option<usize>,
}

/// One peeked live message in the operator view (payload base64; signed-context as presence only).
#[cfg(feature = "handlers")]
#[derive(Serialize)]
struct QueuePeekEntry {
    id: String,
    attempts: u32,
    leased: bool,
    signed_context_present: bool,
    payload_b64: String,
}

#[cfg(feature = "handlers")]
#[derive(Serialize)]
struct QueuePeekResponse {
    version: u32,
    messages: Vec<QueuePeekEntry>,
}

/// The most messages one `queue peek` returns — bounds the payload bytes a single read can pull.
#[cfg(feature = "handlers")]
const QUEUE_PEEK_MAX: usize = 100;

/// Operator live-queue INSPECTION (`GET …/_boatramp/queue/peek`, read): the head of a topic's
/// work-queue WITHOUT consuming (no lease, no attempt charge). Site-scoped like the DLQ endpoints.
#[cfg(feature = "handlers")]
pub(super) async fn operator_queue_peek(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
    axum::extract::Query(q): axum::extract::Query<QueuePeekQuery>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = dlq_namespace(&site, &q.alias, &q.topic);
    queue_peek_core(messaging.as_ref(), &namespaced, q.limit).await
}

/// Shared inner logic of the live-queue PEEK endpoint, over an already-namespaced topic.
#[cfg(feature = "handlers")]
async fn queue_peek_core(
    messaging: &dyn boatramp_core::messaging::Messaging,
    namespaced: &str,
    limit: Option<usize>,
) -> Response {
    let limit = limit.unwrap_or(10).min(QUEUE_PEEK_MAX);
    match messaging.peek(namespaced, limit).await {
        Ok(msgs) => {
            use base64::Engine as _;
            let messages = msgs
                .into_iter()
                .map(|m| QueuePeekEntry {
                    id: m.id,
                    attempts: m.attempts,
                    leased: m.leased,
                    signed_context_present: m.signed_context.is_some(),
                    payload_b64: base64::engine::general_purpose::STANDARD.encode(m.payload),
                })
                .collect();
            Json(QueuePeekResponse {
                version: DLQ_VIEW_VERSION,
                messages,
            })
            .into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("queue peek failed: {err}\n"),
        )
            .into_response(),
    }
}

/// `GET …/_boatramp/queue/replay` query: re-read a GROUPED topic's retained history from an offset,
/// without consuming or touching any group's cursor (P2 durable replay).
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct QueueReplayQuery {
    topic: String,
    #[serde(default)]
    alias: Option<String>,
    /// Exclusive start offset (a prior message id); omit to replay from the beginning.
    #[serde(default)]
    after: Option<String>,
    /// How many messages to return (publish order). Defaults to 10; hard-capped at `QUEUE_PEEK_MAX`.
    #[serde(default)]
    limit: Option<usize>,
}

#[cfg(feature = "handlers")]
#[derive(Serialize)]
struct QueueReplayResponse {
    version: u32,
    messages: Vec<QueuePeekEntry>,
    /// The last id returned — the caller passes it back as `after` to page forward (absent = no more).
    #[serde(skip_serializing_if = "Option::is_none")]
    next_after: Option<String>,
}

/// Operator durable REPLAY (`GET …/_boatramp/queue/replay`, read): re-read a grouped topic's retained
/// history from an offset WITHOUT consuming (no lease, no attempt, no cursor touch). Site-scoped like
/// the other queue endpoints. Grouped-only — a work-queue deletes on ack (use `queue peek` there).
#[cfg(feature = "handlers")]
pub(super) async fn operator_queue_replay(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
    axum::extract::Query(q): axum::extract::Query<QueueReplayQuery>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = dlq_namespace(&site, &q.alias, &q.topic);
    queue_replay_core(messaging.as_ref(), &namespaced, q.after.as_deref(), q.limit).await
}

/// Shared inner logic of the durable-REPLAY endpoint, over an already-namespaced topic.
#[cfg(feature = "handlers")]
async fn queue_replay_core(
    messaging: &dyn boatramp_core::messaging::Messaging,
    namespaced: &str,
    after: Option<&str>,
    limit: Option<usize>,
) -> Response {
    let limit = limit.unwrap_or(10).min(QUEUE_PEEK_MAX);
    match messaging.replay(namespaced, after, limit).await {
        Ok(msgs) => {
            use base64::Engine as _;
            let next_after = msgs.last().map(|m| m.id.clone());
            let messages = msgs
                .into_iter()
                .map(|m| QueuePeekEntry {
                    id: m.id,
                    attempts: m.attempts,
                    leased: m.leased,
                    signed_context_present: m.signed_context.is_some(),
                    payload_b64: base64::engine::general_purpose::STANDARD.encode(m.payload),
                })
                .collect();
            Json(QueueReplayResponse {
                version: DLQ_VIEW_VERSION,
                messages,
                next_after,
            })
            .into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("queue replay failed: {err}\n"),
        )
            .into_response(),
    }
}

/// `GET …/_boatramp/queue/groups` query: list the consumer groups on a topic.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct QueueGroupsQuery {
    topic: String,
    #[serde(default)]
    alias: Option<String>,
}

#[cfg(feature = "handlers")]
#[derive(Serialize)]
struct GroupEntry {
    group: String,
    hwm: String,
    in_flight: usize,
    lag: usize,
}

#[cfg(feature = "handlers")]
#[derive(Serialize)]
struct QueueGroupsResponse {
    version: u32,
    groups: Vec<GroupEntry>,
}

/// Operator consumer-group LISTING (`GET …/_boatramp/queue/groups`, read). Site-scoped.
#[cfg(feature = "handlers")]
pub(super) async fn operator_queue_groups(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
    axum::extract::Query(q): axum::extract::Query<QueueGroupsQuery>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = dlq_namespace(&site, &q.alias, &q.topic);
    queue_groups_core(messaging.as_ref(), &namespaced).await
}

/// Shared inner logic of the consumer-group LISTING endpoint, over an already-namespaced topic.
#[cfg(feature = "handlers")]
async fn queue_groups_core(
    messaging: &dyn boatramp_core::messaging::Messaging,
    namespaced: &str,
) -> Response {
    match messaging.list_groups(namespaced).await {
        Ok(groups) => Json(QueueGroupsResponse {
            version: DLQ_VIEW_VERSION,
            groups: groups
                .into_iter()
                .map(|g| GroupEntry {
                    group: g.group,
                    hwm: g.hwm,
                    in_flight: g.in_flight,
                    lag: g.lag,
                })
                .collect(),
        })
        .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("group list failed: {err}\n"),
        )
            .into_response(),
    }
}

/// `POST …/_boatramp/queue/pause` request: pause or resume a topic (P2 flow control).
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct QueuePauseRequest {
    topic: String,
    #[serde(default)]
    alias: Option<String>,
    /// `true` = pause (suppress delivery), `false` = resume.
    paused: bool,
}

/// Operator flow-control MUTATION (`POST …/_boatramp/queue/pause`, write): pause/resume a topic.
/// Site-scoped so an operator only controls their own site's topics.
#[cfg(feature = "handlers")]
pub(super) async fn operator_queue_pause(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
    Json(req): Json<QueuePauseRequest>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = dlq_namespace(&site, &req.alias, &req.topic);
    queue_pause_core(messaging.as_ref(), &namespaced, req.paused).await
}

/// Shared inner logic of the pause/resume MUTATION, over an already-namespaced topic.
#[cfg(feature = "handlers")]
async fn queue_pause_core(
    messaging: &dyn boatramp_core::messaging::Messaging,
    namespaced: &str,
    paused: bool,
) -> Response {
    match messaging.set_paused(namespaced, paused).await {
        Ok(()) => Json(serde_json::json!({ "ok": true, "paused": paused })).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("pause/resume failed: {err}\n"),
        )
            .into_response(),
    }
}

/// `POST …/_boatramp/queue/policy` request: set a per-topic operator flow-control policy (v0.4.24).
/// Each policy field is optional (omit = no cap on that axis); the request carries the topic + the
/// [`TopicPolicy`](boatramp_core::messaging::TopicPolicy) fields flattened.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct QueuePolicyRequest {
    topic: String,
    #[serde(default)]
    alias: Option<String>,
    /// Reject a publish once the backlog is at/above this (fail-closed).
    #[serde(default)]
    max_depth: Option<usize>,
    /// Per-node publish rate cap (tokens/sec, best-effort).
    #[serde(default)]
    max_rate_per_sec: Option<u32>,
    /// Per-topic relaxed-durability budget override (single-node only; inert on the cluster).
    #[serde(default)]
    max_unflushed: Option<usize>,
}

/// Operator flow-control MUTATION (`POST …/_boatramp/queue/policy`, write → `Site·Write`): set a
/// topic's per-topic policy. Site-scoped so an operator only controls their own site's topics.
#[cfg(feature = "handlers")]
pub(super) async fn operator_queue_policy(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
    Json(req): Json<QueuePolicyRequest>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = dlq_namespace(&site, &req.alias, &req.topic);
    queue_policy_core(messaging.as_ref(), &namespaced, &req).await
}

/// Shared inner logic of the policy MUTATION, over an already-namespaced topic. Refuses (fail-closed)
/// on any backend that doesn't support per-topic policy — surfaced as a `501 Not Implemented` so an
/// operator's cap is never silently dropped.
#[cfg(feature = "handlers")]
async fn queue_policy_core(
    messaging: &dyn boatramp_core::messaging::Messaging,
    namespaced: &str,
    req: &QueuePolicyRequest,
) -> Response {
    let policy = boatramp_core::messaging::TopicPolicy {
        max_depth: req.max_depth,
        max_rate_per_sec: req.max_rate_per_sec,
        max_unflushed: req.max_unflushed,
    };
    match messaging.set_topic_policy(namespaced, policy).await {
        Ok(()) => Json(serde_json::json!({
            "ok": true,
            "max_depth": req.max_depth,
            "max_rate_per_sec": req.max_rate_per_sec,
            "max_unflushed": req.max_unflushed,
        }))
        .into_response(),
        Err(boatramp_core::messaging::MessagingError::Unsupported(msg)) => {
            (StatusCode::NOT_IMPLEMENTED, format!("{msg}\n")).into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("set policy failed: {err}\n"),
        )
            .into_response(),
    }
}

/// Which group-lifecycle mutation `POST …/_boatramp/queue/group` runs.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum GroupAction {
    /// Reset the group's cursor (re-consume from earliest / skip to latest) + drop in-flight.
    Reset,
    /// Delete the group (state + its dead-letters).
    Delete,
}

#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct QueueGroupRequest {
    topic: String,
    #[serde(default)]
    alias: Option<String>,
    group: String,
    action: GroupAction,
    /// For `reset`: `earliest` (re-consume the backlog) or `latest` (skip to the head). Defaults
    /// `earliest`. Ignored for `delete`.
    #[serde(default)]
    start: Option<boatramp_core::messaging::StartPosition>,
}

/// Operator consumer-group MUTATION (`POST …/_boatramp/queue/group`, write): reset or delete a group.
/// Site-scoped so an operator only touches their own site's groups.
#[cfg(feature = "handlers")]
pub(super) async fn operator_queue_group(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
    Json(req): Json<QueueGroupRequest>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = dlq_namespace(&site, &req.alias, &req.topic);
    queue_group_core(
        messaging.as_ref(),
        &namespaced,
        req.group,
        req.action,
        req.start,
    )
    .await
}

/// Shared inner logic of the consumer-group MUTATION (reset/delete), over an
/// already-namespaced topic.
#[cfg(feature = "handlers")]
async fn queue_group_core(
    messaging: &dyn boatramp_core::messaging::Messaging,
    namespaced: &str,
    group: String,
    action: GroupAction,
    start: Option<boatramp_core::messaging::StartPosition>,
) -> Response {
    let result = match action {
        GroupAction::Reset => {
            let start = start.unwrap_or(boatramp_core::messaging::StartPosition::Earliest);
            messaging.reset_group(namespaced, &group, start).await
        }
        GroupAction::Delete => messaging.delete_group(namespaced, &group).await,
    };
    match result {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("group operation failed: {err}\n"),
        )
            .into_response(),
    }
}

/// Operator dead-letter MUTATION (`POST …/_boatramp/dlq`, write): purge / redrive / discard, whole
/// or filter-selective, with a `dry_run` preview. Site-scoped so an operator only touches their own
/// site's queues.
#[cfg(feature = "handlers")]
pub(super) async fn operator_dlq(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
    Json(req): Json<DlqRequest>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = dlq_namespace(&site, &req.alias, &req.topic);
    dlq_mutate_core(
        messaging.as_ref(),
        &namespaced,
        req.action,
        req.filter,
        req.dry_run,
    )
    .await
}

/// Shared inner logic of the DLQ MUTATION endpoint (purge/redrive/discard, whole-or-selective,
/// with a `dry_run` preview), over an already-namespaced topic.
#[cfg(feature = "handlers")]
async fn dlq_mutate_core(
    messaging: &dyn boatramp_core::messaging::Messaging,
    namespaced: &str,
    action: DlqAction,
    filter: DlqFilterWire,
    dry_run: bool,
) -> Response {
    let selective = !filter.is_empty();

    // `--dry-run`: return exactly the matching set (never mutate), so an operator can confirm a
    // redrive/discard before it runs. A whole-DLQ dry-run lists everything.
    if dry_run {
        let filter = filter.into_core();
        return match messaging.list_dead_letters(namespaced, &filter).await {
            Ok(list) => {
                let matched: Vec<DlqEntry> = list.into_iter().map(DlqEntry::from_dead).collect();
                Json(DlqResponse {
                    affected: matched.len(),
                    matched,
                })
                .into_response()
            }
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("dead-letter dry-run failed: {err}\n"),
            )
                .into_response(),
        };
    }

    let result = match action {
        DlqAction::Purge => {
            // Purge is whole-DLQ; if a filter was supplied, honor it as a selective discard instead.
            if selective {
                messaging
                    .discard_dead_letters(namespaced, &filter.into_core())
                    .await
            } else {
                messaging.purge_dead_letters(namespaced).await
            }
        }
        DlqAction::Discard => {
            messaging
                .discard_dead_letters(namespaced, &filter.into_core())
                .await
        }
        DlqAction::Redrive => {
            if selective {
                messaging
                    .redrive_dead_letters_filtered(namespaced, &filter.into_core())
                    .await
            } else {
                messaging.redrive_dead_letters(namespaced).await
            }
        }
    };
    match result {
        Ok(affected) => Json(DlqResponse {
            affected,
            matched: Vec::new(),
        })
        .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("dead-letter operation failed: {err}\n"),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Project-bus operator surface (`/api/projects/<proj>/_boatramp/bus/…`).
//
// The SITE surface above manages a site's own per-site queues (`{site}/…`). This
// mirror manages the SHARED PROJECT BUS — the `{project}/bus/{topic}` keyspace a
// `bus:<topic>` publish routes to (see `handler_dispatch`'s `project.qualified("bus")`),
// common to every site in the project. The tenant boundary is the request path's
// `<proj>` segment: these handlers read it from the injected [`ProjectContext`] (set
// by the `project_scope` middleware) and namespace via [`bus_namespace`], so a token
// authorized (via `authz::Right::required`) for project P can only ever touch P's bus.
// There is no `alias` axis — the bus is not per-deployment. Each handler is thin: it
// resolves the messaging backend + namespace, then delegates to the same `*_core`
// helper the site handler uses, for an identical response shape (`DLQ_VIEW_VERSION`).
// ---------------------------------------------------------------------------

/// `GET …/bus/dlq` query: list (metadata) or show one (with payload) on the project bus.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct BusDlqListQuery {
    topic: String,
    #[serde(default)]
    show: bool,
    #[serde(flatten)]
    filter: DlqFilterWire,
}

/// Project-bus dead-letter INSPECTION (`GET …/bus/dlq`, read → `Project·Read`).
#[cfg(feature = "handlers")]
pub(super) async fn operator_bus_dlq_list(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<crate::project_scope::ProjectContext>,
    axum::extract::Query(q): axum::extract::Query<BusDlqListQuery>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = bus_namespace(&project.as_ref(), &q.topic);
    dlq_list_core(messaging.as_ref(), &namespaced, q.show, q.filter).await
}

/// `POST …/bus/dlq` request: purge/redrive/discard on the project bus (destructive → `Project·Admin`).
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct BusDlqRequest {
    topic: String,
    action: DlqAction,
    #[serde(default)]
    filter: DlqFilterWire,
    #[serde(default)]
    dry_run: bool,
}

/// Project-bus dead-letter MUTATION (`POST …/bus/dlq`, write → `Project·Admin`).
#[cfg(feature = "handlers")]
pub(super) async fn operator_bus_dlq(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<crate::project_scope::ProjectContext>,
    Json(req): Json<BusDlqRequest>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = bus_namespace(&project.as_ref(), &req.topic);
    dlq_mutate_core(
        messaging.as_ref(),
        &namespaced,
        req.action,
        req.filter,
        req.dry_run,
    )
    .await
}

/// `GET …/bus/queue/peek` query on the project bus.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct BusQueuePeekQuery {
    topic: String,
    #[serde(default)]
    limit: Option<usize>,
}

/// Project-bus live-queue PEEK (`GET …/bus/queue/peek`, read → `Project·Read`).
#[cfg(feature = "handlers")]
pub(super) async fn operator_bus_queue_peek(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<crate::project_scope::ProjectContext>,
    axum::extract::Query(q): axum::extract::Query<BusQueuePeekQuery>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = bus_namespace(&project.as_ref(), &q.topic);
    queue_peek_core(messaging.as_ref(), &namespaced, q.limit).await
}

/// `GET …/bus/queue/replay` query on the project bus.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct BusQueueReplayQuery {
    topic: String,
    #[serde(default)]
    after: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// Project-bus durable REPLAY (`GET …/bus/queue/replay`, read → `Project·Read`).
#[cfg(feature = "handlers")]
pub(super) async fn operator_bus_queue_replay(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<crate::project_scope::ProjectContext>,
    axum::extract::Query(q): axum::extract::Query<BusQueueReplayQuery>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = bus_namespace(&project.as_ref(), &q.topic);
    queue_replay_core(messaging.as_ref(), &namespaced, q.after.as_deref(), q.limit).await
}

/// `GET …/bus/queue/groups` query on the project bus.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct BusQueueGroupsQuery {
    topic: String,
}

/// Project-bus consumer-group LISTING (`GET …/bus/queue/groups`, read → `Project·Read`).
#[cfg(feature = "handlers")]
pub(super) async fn operator_bus_queue_groups(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<crate::project_scope::ProjectContext>,
    axum::extract::Query(q): axum::extract::Query<BusQueueGroupsQuery>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = bus_namespace(&project.as_ref(), &q.topic);
    queue_groups_core(messaging.as_ref(), &namespaced).await
}

/// `POST …/bus/queue/pause` request on the project bus.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct BusQueuePauseRequest {
    topic: String,
    paused: bool,
}

/// Project-bus flow-control MUTATION (`POST …/bus/queue/pause`, write → `Project·Admin`).
#[cfg(feature = "handlers")]
pub(super) async fn operator_bus_queue_pause(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<crate::project_scope::ProjectContext>,
    Json(req): Json<BusQueuePauseRequest>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = bus_namespace(&project.as_ref(), &req.topic);
    queue_pause_core(messaging.as_ref(), &namespaced, req.paused).await
}

/// `POST …/bus/queue/policy` request on the project bus (no `alias` — the bus has no per-deployment
/// scope). Carries the topic + the flattened [`TopicPolicy`](boatramp_core::messaging::TopicPolicy)
/// fields.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct BusQueuePolicyRequest {
    topic: String,
    #[serde(default)]
    max_depth: Option<usize>,
    #[serde(default)]
    max_rate_per_sec: Option<u32>,
    #[serde(default)]
    max_unflushed: Option<usize>,
}

/// Project-bus flow-control MUTATION (`POST …/bus/queue/policy`, write → `Project·Admin`): set a
/// bus topic's per-topic policy for the shared project bus.
#[cfg(feature = "handlers")]
pub(super) async fn operator_bus_queue_policy(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<crate::project_scope::ProjectContext>,
    Json(req): Json<BusQueuePolicyRequest>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = bus_namespace(&project.as_ref(), &req.topic);
    // Reuse the shared core over a synthesized site-shaped request (no alias on the bus).
    let site_req = QueuePolicyRequest {
        topic: req.topic.clone(),
        alias: None,
        max_depth: req.max_depth,
        max_rate_per_sec: req.max_rate_per_sec,
        max_unflushed: req.max_unflushed,
    };
    queue_policy_core(messaging.as_ref(), &namespaced, &site_req).await
}

/// `POST …/bus/queue/group` request on the project bus.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct BusQueueGroupRequest {
    topic: String,
    group: String,
    action: GroupAction,
    #[serde(default)]
    start: Option<boatramp_core::messaging::StartPosition>,
}

/// Project-bus consumer-group MUTATION (`POST …/bus/queue/group`, write → `Project·Admin`).
#[cfg(feature = "handlers")]
pub(super) async fn operator_bus_queue_group(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<crate::project_scope::ProjectContext>,
    Json(req): Json<BusQueueGroupRequest>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let namespaced = bus_namespace(&project.as_ref(), &req.topic);
    queue_group_core(
        messaging.as_ref(),
        &namespaced,
        req.group,
        req.action,
        req.start,
    )
    .await
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
    let Some(site_config) = deploy.get_site_config(ProjectRef::DEFAULT, site).await? else {
        return Ok(out);
    };
    let Some(site_handlers) = site_config.handlers.as_ref().filter(|h| h.enabled) else {
        return Ok(out);
    };
    let mut active: Vec<(String, String)> = Vec::new();
    if let Some(id) = deploy.current_id(ProjectRef::DEFAULT, site).await? {
        active.push((id, site.to_string()));
    }
    for alias in &site_handlers.background_aliases {
        if let Some(id) = deploy.get_alias(ProjectRef::DEFAULT, site, alias).await? {
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
                in_flight: messaging.in_flight_count(&namespaced).await.unwrap_or(0),
                oldest_pending_ms: messaging
                    .oldest_pending_ms(&namespaced)
                    .await
                    .unwrap_or(None),
                lag: if consumer.group.is_empty() {
                    0
                } else {
                    messaging
                        .group_lag(&namespaced, &consumer.group)
                        .await
                        .unwrap_or(0)
                },
            });
        }
    }
    Ok(out)
}

/// Query params for the logs endpoint:
/// `?limit=<n>&after=<seq>&stream=stdout|stderr`.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct LogsQuery {
    limit: Option<usize>,
    after: Option<u64>,
    stream: Option<String>,
}

/// The logs endpoint response: recent captured lines + the rate-cap drop count
/// (the shared `boatramp_types::logs::LogsResponse`).
#[cfg(feature = "handlers")]
use boatramp_core::logs::LogsResponse;

/// Authenticated per-site captured guest logs (`site:<site>` scope). Returns the
/// most recent lines (newest last), optionally filtered to one stream, plus the
/// count dropped by the per-site rate cap.
#[cfg(feature = "handlers")]
pub(super) async fn operator_logs(
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

/// Authenticated captured guest logs for a **function** (`GET
/// /api/functions/{name}/_boatramp/logs`) — the symmetric counterpart to
/// [`operator_logs`] for standalone functions (GraphQL subgraphs, auth functions,
/// workers) whose `println!`/`eprintln!` output is otherwise unreadable. Reads the
/// SAME [`LogStore`] the capture already writes to (see
/// `function_runtime::build_function_bindings`), under the function's project-qualified
/// scope `<project>/fn/<name>` (bare `fn/<name>` for the default project) — so this is
/// pure exposure, no new capture. Project-owned + operator-gated by the surrounding
/// `/api/functions/*` authz (Project·Read); multi-tenant safe (the scope is
/// project-qualified, and the token must hold read on that project).
#[cfg(feature = "handlers")]
pub(super) async fn operator_function_logs(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<crate::project_scope::ProjectContext>,
    Path(name): Path<String>,
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
    // The exact scope the function runtime tags its guest lines with — must match
    // `function_runtime`'s `project.qualified("fn/<name>")` or the tail finds nothing.
    let scope = project.as_ref().qualified(&format!("fn/{name}"));
    let (entries, dropped) = inner
        .logs
        .tail(&scope, limit, query.after.unwrap_or(0), stream);
    Json(LogsResponse { entries, dropped }).into_response()
}

/// Live log tail over SSE (`GET …/_boatramp/logs/stream`): subscribe to the
/// capture feed, filter to this site, and emit each line as an SSE `log` event
/// (the `id` is the line seq, so a reconnect can resume). The console uses this
/// instead of polling. Same `site·read` gating as the poll endpoint.
#[cfg(feature = "handlers")]
pub(super) async fn operator_logs_stream(
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

/// Live function-log tail over SSE (`GET /api/functions/{name}/_boatramp/logs/stream`)
/// — the counterpart to [`operator_logs_stream`] for the web console's function view.
/// Subscribes to the same capture feed and filters to the function's project-qualified
/// scope (`<project>/fn/<name>`; bare `fn/<name>` for the default project), matching
/// what [`operator_function_logs`] tails and what the function runtime writes. Same
/// `/api/functions/*` project-owned read gating.
#[cfg(feature = "handlers")]
pub(super) async fn operator_function_logs_stream(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<crate::project_scope::ProjectContext>,
    Path(name): Path<String>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    let Some(inner) = handlers.inner.as_ref() else {
        return (StatusCode::NOT_FOUND, "handlers disabled\n").into_response();
    };
    let want = project.as_ref().qualified(&format!("fn/{name}"));
    let rx = inner.logs.subscribe();
    let stream = futures::stream::unfold(rx, move |mut rx| {
        let want = want.clone();
        async move {
            loop {
                match rx.recv().await {
                    Ok((scope, entry)) if scope == want => {
                        let data = serde_json::to_string(&entry).unwrap_or_default();
                        let event = Event::default()
                            .id(entry.seq.to_string())
                            .event("log")
                            .data(data);
                        return Some((Ok::<_, std::convert::Infallible>(event), rx));
                    }
                    // Another scope's line — keep waiting.
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
pub(super) async fn prometheus_metrics(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(daemon): Extension<Arc<DaemonRuntime>>,
) -> Response {
    let mut body = srvmetrics::server_metrics().render_prometheus();
    // The active dynamic-config generation, as an info gauge whose `generation`
    // label is the `daemon/current` content address (`none` on the pure file
    // baseline). Scraping it across a cluster shows whether every node converged.
    let generation = daemon.generation().unwrap_or_else(|| "none".to_string());
    body.push_str(
        "# HELP boatramp_daemon_config_info Active dynamic daemon-config generation.\n\
         # TYPE boatramp_daemon_config_info gauge\n",
    );
    body.push_str(&format!(
        "boatramp_daemon_config_info{{generation=\"{generation}\"}} 1\n"
    ));
    #[cfg(feature = "handlers")]
    if let Some(inner) = handlers.inner.as_ref() {
        body.push_str(&inner.metrics.render_prometheus());
        if let Some(messaging) = &inner.messaging {
            let mut rows = Vec::new();
            // Best-effort: a deploy-store error just omits the gauges rather
            // than failing the whole scrape.
            if let Ok(sites) = deploy.list_sites(ProjectRef::DEFAULT).await {
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
        // Function usage series (FA-4), from the persisted metering aggregates.
        // Best-effort: a store error omits the block rather than failing the scrape.
        if let Ok(mut usage) = deploy.list_metering(ProjectRef::DEFAULT).await {
            if !usage.is_empty() {
                usage.sort_by(|a, b| a.function.cmp(&b.function));
                body.push_str(
                    "# HELP boatramp_function_invocations_total Function invocations metered.\n\
                     # TYPE boatramp_function_invocations_total counter\n",
                );
                for m in &usage {
                    let f = metrics::escape_label(&m.function);
                    body.push_str(&format!(
                        "boatramp_function_invocations_total{{function=\"{f}\"}} {}\n",
                        m.invocations
                    ));
                }
                body.push_str(
                    "# HELP boatramp_function_failures_total Function invocations that failed to deliver.\n\
                     # TYPE boatramp_function_failures_total counter\n",
                );
                for m in &usage {
                    let f = metrics::escape_label(&m.function);
                    body.push_str(&format!(
                        "boatramp_function_failures_total{{function=\"{f}\"}} {}\n",
                        m.failures
                    ));
                }
                body.push_str(
                    "# HELP boatramp_function_duration_ms_total Summed function wall-clock duration, ms.\n\
                     # TYPE boatramp_function_duration_ms_total counter\n",
                );
                for m in &usage {
                    let f = metrics::escape_label(&m.function);
                    body.push_str(&format!(
                        "boatramp_function_duration_ms_total{{function=\"{f}\"}} {}\n",
                        m.duration_ms_total
                    ));
                }
            }
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
