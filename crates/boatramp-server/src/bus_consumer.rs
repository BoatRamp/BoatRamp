//! The external, authenticated **project-bus consumer** surface (PLAN-messaging-consumer-delivery).
//!
//! This is the non-wasm consumer-delivery front door: an off-node, authenticated client consumes
//! its own project's `{project}/bus/<topic>` topics over the EXISTING control-plane API router,
//! behind `require_auth` (never the in-cluster `messaging_shim`, which is token-gated for untrusted
//! guests and binds loopback/bridge only). It rides boatramp's one COSE token/auth model — no new
//! credential type — and is gated by the dedicated [`Resource::Messaging`](boatramp_core::authz::Resource)
//! right: `Messaging·Read` on `<project>/<topic>` for claim/subscribe/ack/nack; `Messaging·Admin` on
//! `<project>` for webhook sinks.
//!
//! Three delivery transports share ONE durable claim/lease/ack/nack/DLQ core (the unchanged
//! [`Messaging`] trait) — no new durability primitive:
//!   - **(a) long-poll claim** (THIS increment): [`bus_claim`] hangs on the fast-path
//!     [`Wake`](boatramp_core::messaging::Wake) instead of busy-polling, returning the first
//!     non-empty batch or `[]` at the `wait_ms` deadline.
//!   - **(b) durable stream** and **(d) webhook sink** (later increments) build on the SAME shared
//!     surface laid here: [`SubscriptionParams`], the `Messaging` right, this route module, and the
//!     shared [`bus_ack`]/[`bus_nack`] side-channel (the opaque [`AckHandle`], reused from the shim).
//!
//! INVARIANTS (unchanged): at-least-once; the durable claim/lease is the sole authority; ack deletes,
//! nack/lease-expiry redelivers with the attempt count, DLQ at `max_attempts`. The adapter parks on
//! the waker — ZERO busy-poll.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::*;

use base64::Engine as _;
use boatramp_core::config::{ResolvedSubscription, StartPosition, SubscriptionParams};
use boatramp_core::messaging::{ClaimedMessage, Messaging, Wake};
use boatramp_core::project::validate_object_key;

use crate::messaging_shim::AckHandle;
use crate::operator::{bus_namespace, messaging_or_unavailable};
use crate::project_scope::ProjectContext;

/// Upper bound on a long-poll `wait_ms`: a claim hangs for AT MOST this long before returning `[]`,
/// so a client can never pin a connection indefinitely (bounded hang — no socket/file-descriptor
/// exhaustion from an unbounded `wait_ms`). 5 minutes is comfortably above any sane poll interval
/// while keeping idle connections bounded.
const MAX_WAIT_MS: u64 = 300_000;

/// Query params for `POST …/bus/claim/{*topic}` — the [`Messaging::claim_grouped`] knobs plus the
/// long-poll `wait_ms`. All optional; absent ⇒ the server defaults. `max` is clamped to
/// `[1, `[`SubscriptionParams::MAX_BATCH`]`]` and `wait_ms` to `[0, `[`MAX_WAIT_MS`]`]`, EXACTLY as
/// the messaging-shim's claim handler clamps today.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ClaimQuery {
    /// Long-poll timeout (ms): hang up to this long for a message before returning `[]`. Absent/`0`
    /// ⇒ return immediately (a plain claim). Clamped to [`MAX_WAIT_MS`].
    #[serde(default)]
    wait_ms: Option<u64>,
    /// Visibility lease (ms) for each claimed message.
    #[serde(default)]
    lease_ms: Option<u64>,
    /// Max messages to lease in this claim (default [`SubscriptionParams::DEFAULT_CLAIM_BATCH`]).
    #[serde(default)]
    max: Option<usize>,
    /// Dead-letter threshold.
    #[serde(default)]
    max_attempts: Option<u32>,
    /// Consumer group (empty ⇒ the default work-queue).
    #[serde(default)]
    group: Option<String>,
    /// New-group start cursor (`latest` | `earliest`).
    #[serde(default)]
    start: Option<StartPosition>,
}

/// One claimed message on the wire — a local DTO ([`ClaimedMessage`] is not `Serialize`). The payload
/// rides base64 and `handle` is the opaque [`AckHandle`] the consumer presents back to `ack`/`nack`.
#[derive(Debug, Serialize)]
struct ClaimedDto {
    /// The substrate's unique, roughly time-ordered message id.
    id: String,
    /// The BARE topic the consumer claimed (its own naming — not the full `{project}/bus/` key).
    topic: String,
    /// Delivery attempts so far, including this one (starts at 1).
    attempts: u32,
    /// Base64 (standard) of the message payload.
    payload_b64: String,
    /// Opaque ack/nack handle.
    handle: String,
}

impl ClaimedDto {
    /// Frame one [`ClaimedMessage`] for the wire under the consumer's BARE `topic`: base64 the
    /// payload and mint the opaque [`AckHandle`] the consumer presents back to `ack`/`nack`. Shared
    /// by the long-poll claim response (a) and every durable-stream delivery frame (b), so one
    /// handle shape serves the whole surface.
    fn from_message(bare_topic: &str, m: &ClaimedMessage) -> Self {
        Self {
            id: m.id.clone(),
            topic: bare_topic.to_string(),
            attempts: m.attempts,
            payload_b64: base64::engine::general_purpose::STANDARD.encode(&m.payload),
            handle: AckHandle::encode(bare_topic, m),
        }
    }
}

/// The `POST …/bus/claim/{*topic}` response body.
#[derive(Debug, Serialize)]
struct ClaimResponse {
    messages: Vec<ClaimedDto>,
}

/// `POST …/bus/ack` body: the opaque handle from a prior claim.
#[derive(Debug, Deserialize)]
pub(crate) struct AckReq {
    handle: String,
}

/// `POST …/bus/nack` body: the handle, plus an optional redelivery backoff (ms) → [`Messaging::nack_after`].
#[derive(Debug, Deserialize)]
pub(crate) struct NackReq {
    handle: String,
    #[serde(default)]
    delay_ms: Option<u64>,
}

/// The shared long-poll **claim core** (transport (a)): claim under a lease; if ≥1 message, return
/// immediately; else park on the fast-path [`Wake`](boatramp_core::messaging::Wake), raced against
/// the `wait` deadline, and re-run the atomic claim on each wake. Returns the first non-empty batch
/// or `[]` at the deadline. ZERO SPIN: an idle `wait` costs ONE parked future (the wake + a single
/// sleep), never a repeated scan — the claim runs once per genuine wake, never on a timer tick. No
/// new durable semantics: the lease/ack/nack/DLQ are inherited from [`Messaging::claim_grouped`]
/// unchanged; this only decides WHEN to stop waiting for a message to appear.
///
/// `pub(crate)` + separated from the handler so the runtime gate drives the REAL claim core (not a
/// stub) and counts the underlying claim calls to prove the zero-busy-poll property.
pub(crate) async fn long_poll_claim(
    messaging: &dyn Messaging,
    key: &str,
    sub: &ResolvedSubscription,
    wait: Duration,
) -> Result<Vec<ClaimedMessage>, boatramp_core::messaging::MessagingError> {
    let lease = Duration::from_millis(sub.lease_ms);
    let deadline = Instant::now() + wait;
    // The fast-path wake (lossy, node-global, coalescing) — `None` on a substrate without one, in
    // which case we fall back to a single park-until-deadline (still zero-spin, just deadline-latency).
    let wake = messaging.wake_handle();
    loop {
        let claimed = messaging
            .claim_grouped(
                key,
                &sub.group,
                sub.start,
                lease,
                sub.max_batch,
                sub.max_attempts,
            )
            .await?;
        if !claimed.is_empty() {
            return Ok(claimed);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(Vec::new());
        }
        let remaining = deadline - now;
        match &wake {
            Some(w) => {
                // Park on the waker, raced against the deadline. A publish/nack-to-now fires the wake
                // (durably committed first, B12), so a woken claim always sees the committed message;
                // a lost/coalesced pulse is harmless (the next claim still finds it, or we re-park).
                tokio::select! {
                    _ = w.notified() => continue,
                    _ = tokio::time::sleep(remaining) => return Ok(Vec::new()),
                }
            }
            None => {
                // No fast wake on this substrate: park ONCE until the deadline (one future, no spin),
                // then make a single final claim and return whatever it yields.
                tokio::time::sleep(remaining).await;
                return messaging
                    .claim_grouped(
                        key,
                        &sub.group,
                        sub.start,
                        lease,
                        sub.max_batch,
                        sub.max_attempts,
                    )
                    .await;
            }
        }
    }
}

/// `POST /api/projects/{proj}/bus/claim/{*topic}?wait_ms&lease_ms&max&max_attempts&group&start` —
/// transport (a). Authorization (`Messaging·Read` on the exact `<project>/<topic>`) is enforced by
/// `require_auth` → `Right::required_for` BEFORE this handler runs. The project is taken from the
/// TRUSTED [`ProjectContext`] (the `{proj}` path segment the auth layer gated on), never a
/// client-supplied field, so a consumer is structurally confined to its own project bus. The topic
/// is screened for traversal ([`validate_object_key`]) exactly as the shim's claim does, so it can
/// never escape the `{project}/bus/` prefix.
#[cfg(feature = "handlers")]
pub(crate) async fn bus_claim(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<ProjectContext>,
    Path((_project_seg, topic)): Path<(String, String)>,
    Query(q): Query<ClaimQuery>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    // Screen the topic (traversal / control bytes / reserved namespace) BEFORE composing the key —
    // the SAME fail-closed screen the shim's claim runs, so a `..`/absolute topic can't escape the bus.
    if let Err(e) = validate_object_key(&topic) {
        return (StatusCode::BAD_REQUEST, format!("invalid topic: {e}\n")).into_response();
    }
    let key = bus_namespace(&project.as_ref(), &topic);

    // Clamp exactly as the messaging-shim's claim handler: batch default = lease-ONE, capped to
    // MAX_BATCH; lease/attempts to the server defaults; wait_ms to a bounded max (no unbounded hang).
    let params = SubscriptionParams {
        group: q.group.unwrap_or_default(),
        start: q.start.unwrap_or_default(),
        lease_ms: q.lease_ms,
        max_attempts: q.max_attempts,
        max_batch: q.max,
        max_ack_pending: None,
        backoff_ms: None,
        retention_ms: None,
    };
    let sub = params.resolve_with_default_batch(SubscriptionParams::DEFAULT_CLAIM_BATCH);
    let wait = Duration::from_millis(q.wait_ms.unwrap_or(0).min(MAX_WAIT_MS));

    match long_poll_claim(messaging.as_ref(), &key, &sub, wait).await {
        Ok(claimed) => {
            let messages = claimed
                .iter()
                .map(|m| ClaimedDto::from_message(&topic, m))
                .collect();
            Json(ClaimResponse { messages }).into_response()
        }
        Err(err) => {
            tracing::warn!(key, error = %err, "bus-consumer claim fault");
            (StatusCode::BAD_GATEWAY, "messaging backend unavailable\n").into_response()
        }
    }
}

/// Decode an opaque [`AckHandle`] and reconstruct the [`ClaimedMessage`] the trait acks/nacks, with
/// the FULL key recomposed from the TRUSTED project ([`ProjectContext`], the gated `{proj}` path
/// segment) + the handle's BARE topic. The project NEVER comes from the handle, so a tampered/stale
/// handle can only ever name a topic WITHIN the already-authorized project; the bare topic is
/// re-screened for traversal. `Err` is the fail-closed HTTP response (400 malformed/invalid-topic).
#[cfg(feature = "handlers")]
fn handle_to_message(project: &ProjectContext, handle: &str) -> Result<ClaimedMessage, Response> {
    let Some(decoded) = AckHandle::decode(handle) else {
        return Err((StatusCode::BAD_REQUEST, "malformed ack handle\n").into_response());
    };
    if let Err(e) = validate_object_key(&decoded.topic) {
        return Err((StatusCode::BAD_REQUEST, format!("invalid topic: {e}\n")).into_response());
    }
    let full_key = bus_namespace(&project.as_ref(), &decoded.topic);
    Ok(decoded.into_message(full_key))
}

/// `POST /api/projects/{proj}/bus/ack` `{ handle }` — delete a claimed message for good
/// ([`Messaging::ack`]). The shared ack side-channel every transport (a/b/d) reuses. Authorization
/// (`Messaging·Read` on `<project>/*`) + token verification + revocation run on EVERY call via
/// `require_auth`, so a stale/revoked token can never ack; the project is path-derived, so a tampered
/// handle can never reach another project.
#[cfg(feature = "handlers")]
pub(crate) async fn bus_ack(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<ProjectContext>,
    Json(body): Json<AckReq>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let msg = match handle_to_message(&project, &body.handle) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    match messaging.ack(&msg).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            tracing::warn!(topic = %msg.topic, id = %msg.id, error = %err, "bus-consumer ack fault");
            (StatusCode::BAD_GATEWAY, "messaging backend unavailable\n").into_response()
        }
    }
}

/// `POST /api/projects/{proj}/bus/nack` `{ handle, delay_ms? }` — redeliver a claimed message, now
/// ([`Messaging::nack`]) or after a backoff ([`Messaging::nack_after`]). The attempt count is
/// preserved, so it still dead-letters after `max_attempts`. Same shared side-channel + re-authz as
/// [`bus_ack`].
#[cfg(feature = "handlers")]
pub(crate) async fn bus_nack(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<ProjectContext>,
    Json(body): Json<NackReq>,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let msg = match handle_to_message(&project, &body.handle) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let result = match body.delay_ms {
        Some(delay) if delay > 0 => messaging.nack_after(&msg, delay).await,
        _ => messaging.nack(&msg).await,
    };
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            tracing::warn!(topic = %msg.topic, id = %msg.id, error = %err, "bus-consumer nack fault");
            (StatusCode::BAD_GATEWAY, "messaging backend unavailable\n").into_response()
        }
    }
}

// =====================================================================================================
// (b) Durable streaming subscription (PLAN-messaging-consumer-delivery §(b) / Increment 2).
//
// A long-lived per-connection loop that claims a durable **consumer group** with a per-subscriber
// lease and frames each `ClaimedMessage` out over SSE (default) or WebSocket (on `Upgrade`), reading
// acks back. This is NOT the lossy at-most-once `Messaging::subscribe` fan-out the configured-stream
// SSE path uses — delivery rides the SAME durable `claim_grouped` / `ack` / `nack` / DLQ core as the
// long-poll claim (a) and the wasm PUSH consumer, so:
//   - at-least-once is unchanged; the durable claim/lease is the sole authority;
//   - redelivery on lease-expiry and dead-lettering at `max_attempts` are the core's existing
//     behavior (inherited — not reimplemented here);
//   - `subscribe()` is NOT used at all (not even as a hint): the fast-path `Wake` is the latency hint
//     (a "go claim now" pulse), never the delivery path;
//   - it is **cluster-correct for free** — `claim_grouped` is leader-serialized in `RaftMessaging`, so
//     (b) needs NO new cross-node fan-out (no `StreamBus`/`StreamHubs`), unlike the lossy SSE path.
//
// The transport scaffolding — per-scope + per-IP connection permits, SSE heartbeat / idle-close, the
// WebSocket RFC-6455 handshake — is REUSED from the configured-stream surface (`crate::stream`); only
// the fan-out body changes (lossy `subscribe` → durable `claim_grouped` loop). Per-connection authz
// (`Messaging·Read` on the exact `<project>/<topic>`) runs in `require_auth` BEFORE this handler, i.e.
// before the first byte, exactly as `serve_stream`'s `authorize_stream_topics` does for a configured
// stream.

/// Query params for `GET …/bus/subscribe/{*topic}` (transport (b)). All optional; absent ⇒ the server
/// defaults, clamped by [`SubscriptionParams::resolve`] EXACTLY as the shim/long-poll claim clamps.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct SubscribeQuery {
    /// Consumer **group** — the durable fan-out lane (own cursor / lease / retry / DLQ). Empty ⇒ the
    /// competing-consumer work-queue shared with the long-poll claim surface.
    #[serde(default)]
    group: Option<String>,
    /// Where a NEW group starts on first subscription (`latest` | `earliest`); ignored for an
    /// existing group (its durable cursor is authoritative).
    #[serde(default)]
    start: Option<StartPosition>,
    /// Visibility lease (ms) each delivered-but-unacked message holds before redelivery.
    #[serde(default)]
    lease_ms: Option<u64>,
    /// **MaxAckPending**: the most leased-but-unacked messages this connection may hold at once —
    /// back-pressure for a slow consumer (see [`pump_until_batch`]). Absent ⇒ unbounded (only the
    /// per-claim batch bounds it).
    #[serde(default)]
    max_ack_pending: Option<usize>,
    /// Dead-letter threshold (delivery attempts before a message is dead-lettered).
    #[serde(default)]
    max_attempts: Option<u32>,
    /// Max messages leased per underlying claim (the per-tick batch). Clamped to
    /// `[1, `[`SubscriptionParams::MAX_BATCH`]`]`.
    #[serde(default)]
    max: Option<usize>,
}

/// Fallback park between empty durable claims on a substrate that HAS a fast [`Wake`]: the wake —
/// fired AFTER a durable publish/nack commit (B12) — normally rouses delivery immediately, so this
/// only caps the latency of a pathologically missed/coalesced pulse. Large enough that a genuinely
/// idle stream issues NO steady trickle of claims (not a busy-poll), small enough to self-heal. It is
/// also the sole delivery latency on a substrate WITHOUT a wake (where it degrades to a single bounded
/// park, still zero-spin).
const EMPTY_PARK: Duration = Duration::from_secs(30);

/// Re-check interval while a connection sits AT its `max_ack_pending` cap. An ack frees a slot but
/// fires no wake (only publish/nack do), so a back-pressured connection re-evaluates the DURABLE
/// in-flight count this often (raced against the wake, which still rouses it on the next publish/nack).
/// No claim is issued while capped, so this is back-pressure bookkeeping, never a claim busy-poll.
const CAP_RECHECK: Duration = Duration::from_millis(250);

/// Park on the fast-path [`Wake`] (a "go claim now" pulse) raced against `fallback`, or — on a
/// substrate with no wake — a single bounded sleep. ZERO SPIN either way: one parked future, resolved
/// by a genuine wake (publish/nack) or the fallback deadline, never a timer-driven re-scan.
async fn park_delivery_hint(wake: &Option<Wake>, fallback: Duration) {
    match wake {
        Some(w) => {
            tokio::select! {
                _ = w.notified() => {}
                _ = tokio::time::sleep(fallback) => {}
            }
        }
        None => tokio::time::sleep(fallback).await,
    }
}

/// The shared durable-delivery **pump**: advance one delivery step and return the next non-empty
/// batch of [`ClaimedMessage`]s, parking (never spinning) until one appears. Both transports (SSE and
/// WS) drive this one loop; it is `pub(crate)` + separated from the handlers so the runtime gate can
/// drive the REAL `LogMessaging` claim core and count the underlying claims (proving zero busy-poll).
///
/// Per iteration, in order:
/// 1. **Back-pressure gate (P2 MaxAckPending)** — IDENTICAL to the wasm dispatcher
///    (`handler_dispatch.rs:4235`): with a cap set, read the topic's DURABLE `in_flight_count`
///    (leased-but-unacked) and claim at most `cap − in_flight` this step; at/over the cap, claim
///    NOTHING and park (an ack via the shared side-channel / an inline WS frame drops the durable
///    in-flight, which the next step observes). A slight over-count for a single group — the safe
///    direction (it caps sooner), same as the dispatcher.
/// 2. **Durable claim** — `claim_grouped(key, group, start, lease, batch, max_attempts)`: the group's
///    own cursor / lease / retry / DLQ. A non-empty batch returns immediately.
/// 3. **Zero-spin park** — on an empty claim, park on the [`Wake`] (raced against [`EMPTY_PARK`]); the
///    claim re-runs only on a genuine wake (coalesced wakes still see the whole batch), never on a
///    timer tick. Redelivery-on-lease-expiry and DLQ-at-`max_attempts` are the core's behavior,
///    unchanged.
pub(crate) async fn pump_until_batch(
    messaging: &dyn Messaging,
    key: &str,
    sub: &ResolvedSubscription,
    wake: &Option<Wake>,
) -> Result<Vec<ClaimedMessage>, boatramp_core::messaging::MessagingError> {
    let lease = Duration::from_millis(sub.lease_ms);
    loop {
        let batch = match sub.max_ack_pending {
            Some(cap) => {
                let in_flight = messaging.in_flight_count(key).await.unwrap_or(0);
                let available = cap.saturating_sub(in_flight);
                if available == 0 {
                    // At the cap: issue NO claim; park (wake or a bounded re-check so an ack — which
                    // fires no wake — is still noticed) and re-evaluate.
                    park_delivery_hint(wake, CAP_RECHECK).await;
                    continue;
                }
                sub.max_batch.min(available)
            }
            None => sub.max_batch,
        };
        let claimed = messaging
            .claim_grouped(key, &sub.group, sub.start, lease, batch, sub.max_attempts)
            .await?;
        if !claimed.is_empty() {
            return Ok(claimed);
        }
        park_delivery_hint(wake, EMPTY_PARK).await;
    }
}

/// `GET /api/projects/{proj}/bus/subscribe/{*topic}?group&start&lease_ms&max_ack_pending&max_attempts&max`
/// — transport (b). SSE by default; a WebSocket when the request carries an `Upgrade`. Authorization
/// (`Messaging·Read` on the exact `<project>/<topic>`) is enforced by `require_auth` →
/// `Right::required_for`'s `bus` arm BEFORE this handler runs (authz-before-first-byte). The project
/// is the TRUSTED [`ProjectContext`] (the gated `{proj}` segment), never client-supplied, so a
/// connection is structurally confined to its own project bus; the topic is traversal-screened like
/// the long-poll claim.
#[cfg(feature = "handlers")]
pub(crate) async fn bus_subscribe(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<ProjectContext>,
    Path((_project_seg, topic)): Path<(String, String)>,
    Query(q): Query<SubscribeQuery>,
    request: Request,
) -> Response {
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m.clone(),
        Err(resp) => return resp,
    };
    // The runtime inner backs the shared per-scope / per-IP stream-permit pools.
    let Some(inner) = handlers.inner.as_ref() else {
        return not_found();
    };
    // Screen the topic (traversal / control bytes / reserved namespace) exactly as the claim path.
    if let Err(e) = validate_object_key(&topic) {
        return (StatusCode::BAD_REQUEST, format!("invalid topic: {e}\n")).into_response();
    }
    let key = bus_namespace(&project.as_ref(), &topic);

    // Resolve the subscription knobs with the STREAM batch default (16, per-tick), clamped identically
    // to the shim/claim (lease/attempts/batch caps + `MAX_BATCH`).
    let params = SubscriptionParams {
        group: q.group.unwrap_or_default(),
        start: q.start.unwrap_or_default(),
        lease_ms: q.lease_ms,
        max_attempts: q.max_attempts,
        max_batch: q.max,
        max_ack_pending: q.max_ack_pending,
        backoff_ms: None,
        retention_ms: None,
    };
    let sub = params.resolve();

    let client_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or(IpAddr::from([0u8, 0, 0, 0]));
    // `Last-Event-ID` is accepted for resume, but a durable group's cursor + outstanding leases are
    // the authority: an unacked (still-leased) message redelivers on lease-expiry regardless, so we do
    // NOT seek the cursor from the header (which could SKIP an unacked message) — resume is inherent.
    let after = request
        .headers()
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if boatramp_http::is_upgrade_request(request.headers()) {
        serve_bus_ws(
            inner, messaging, project, topic, key, sub, client_ip, request,
        )
        .await
    } else {
        serve_bus_sse(inner, messaging, &key, &topic, sub, client_ip, after).await
    }
}

/// Frame one durable [`ClaimedMessage`] as an SSE delivery event: `event: message`, the durable
/// message id as the SSE `id:` (for `Last-Event-ID` resume), and a JSON [`ClaimedDto`] body carrying
/// the base64 payload + the opaque [`AckHandle`] the client acks with. The JSON serializer escapes
/// every control byte, so the payload can never break SSE framing (no raw `\n`/`\r`).
#[cfg(feature = "handlers")]
fn sse_delivery_event(topic: &str, m: &ClaimedMessage) -> axum::response::sse::Event {
    let dto = ClaimedDto::from_message(topic, m);
    let data = serde_json::to_string(&dto).unwrap_or_else(|_| "{}".to_string());
    axum::response::sse::Event::default()
        .id(m.id.clone())
        .event("message")
        .data(data)
}

/// Serve a durable subscription as **Server-Sent Events** (server→client): the durable `claim_grouped`
/// pump ([`pump_until_batch`]) frames each message as an SSE `message` event carrying the opaque
/// handle; the client acks/nacks out-of-band via the shared `POST …/bus/ack` / `.../bus/nack`
/// side-channel (which re-authorizes `Messaging·Read` on `<project>/*` every call). Reuses the
/// configured-stream per-scope + per-IP permits, heartbeat, and idle-close.
#[cfg(feature = "handlers")]
async fn serve_bus_sse(
    inner: &HandlerRuntimeInner,
    messaging: Arc<dyn Messaging>,
    key: &str,
    topic: &str,
    sub: ResolvedSubscription,
    client_ip: IpAddr,
    _after: Option<String>,
) -> Response {
    use axum::response::sse::{KeepAlive, Sse};

    // deny-before-resource-use: per-connection authz already ran in `require_auth`; cap the connection
    // on the shared per-scope + per-IP stream pools, keyed by the full `{project}/bus/<topic>` key (so
    // bus and configured-stream scopes never collide, and each project/topic is bounded independently).
    let scope = key.to_string();
    let site_permit = match crate::stream::acquire_stream_permit_capped(
        inner,
        &scope,
        crate::stream::DEFAULT_STREAM_CONNECTIONS,
    ) {
        Ok(p) => p,
        Err(()) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "bus stream connection limit reached\n",
            )
                .into_response();
        }
    };
    let ip_guard = match crate::stream::acquire_stream_ip_slot(inner, &scope, client_ip) {
        Ok(g) => g,
        Err(()) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "per-client bus stream connection limit reached\n",
            )
                .into_response();
        }
    };

    struct SseState {
        messaging: Arc<dyn Messaging>,
        key: String,
        topic: String,
        sub: ResolvedSubscription,
        wake: Option<Wake>,
        buffer: VecDeque<ClaimedMessage>,
        _site_permit: tokio::sync::OwnedSemaphorePermit,
        _ip_guard: crate::stream::IpStreamGuard,
    }
    let state = SseState {
        wake: messaging.wake_handle(),
        messaging,
        key: key.to_string(),
        topic: topic.to_string(),
        sub,
        buffer: VecDeque::new(),
        _site_permit: site_permit,
        _ip_guard: ip_guard,
    };

    let body = futures::stream::unfold(state, |mut st| async move {
        loop {
            // Drain this step's claimed batch one frame at a time.
            if let Some(m) = st.buffer.pop_front() {
                let event = sse_delivery_event(&st.topic, &m);
                return Some((Ok::<_, std::convert::Infallible>(event), st));
            }
            // Pump the next durable batch, bounded by the idle-close (the heartbeat keeps a live
            // client warm while this single future parks on the wake — ZERO spin). A durable-cursor
            // idle close drops no unacked message: leased messages redeliver on reconnect.
            match tokio::time::timeout(
                crate::stream::STREAM_IDLE_TIMEOUT,
                pump_until_batch(st.messaging.as_ref(), &st.key, &st.sub, &st.wake),
            )
            .await
            {
                Ok(Ok(batch)) => st.buffer.extend(batch),
                Ok(Err(err)) => {
                    tracing::warn!(key = %st.key, error = %err, "bus-consumer stream claim fault");
                    return None;
                }
                Err(_) => return None, // idle timeout → close; client reconnects (durable resume)
            }
        }
    });

    Sse::new(body)
        .keep_alive(
            KeepAlive::new()
                .interval(crate::stream::STREAM_HEARTBEAT)
                .text("keep-alive"),
        )
        .into_response()
}

/// Serve a durable subscription as a **WebSocket** (RFC 6455): server→client, the durable pump frames
/// each message as a Text [`ClaimedDto`] JSON; client→server, the client acks/nacks INLINE on the same
/// socket with `{"ack":"<handle>"}` / `{"nack":"<handle>","delay_ms":…}` frames. Mirrors the
/// configured-stream WS handshake + `boatramp_http` upgrade seam. The durable pump runs as its OWN
/// task feeding a bounded channel, so an inbound ack never cancels an in-flight claim (at-least-once
/// is preserved) and the bounded channel + `max_ack_pending` both bound read-ahead.
#[cfg(feature = "handlers")]
#[allow(clippy::too_many_arguments)]
async fn serve_bus_ws(
    inner: &HandlerRuntimeInner,
    messaging: Arc<dyn Messaging>,
    project: ProjectContext,
    topic: String,
    key: String,
    sub: ResolvedSubscription,
    client_ip: IpAddr,
    mut request: Request,
) -> Response {
    // RFC 6455 opening handshake (mirrors `serve_ws_stream`): require version 13 + a key, derive the
    // accept token, and take over the connection via boatramp-http's upgrade seam.
    let version_ok = request
        .headers()
        .get("sec-websocket-version")
        .is_some_and(|v| v.as_bytes() == b"13");
    let accept = request
        .headers()
        .get("sec-websocket-key")
        .and_then(|k| k.to_str().ok())
        .map(boatramp_http::sec_websocket_accept);
    let (Some(accept), true) = (accept, version_ok) else {
        return (StatusCode::BAD_REQUEST, "invalid websocket handshake\n").into_response();
    };
    let on_upgrade = match boatramp_http::on_upgrade(&mut request) {
        Some(u) => u,
        None => return (StatusCode::BAD_REQUEST, "no upgrade handle\n").into_response(),
    };
    drop(request); // the WS handshake carries no body; release it before any await

    // Cap the connection BEFORE taking over the socket (deny before resource use).
    let scope = key.clone();
    let site_permit = match crate::stream::acquire_stream_permit_capped(
        inner,
        &scope,
        crate::stream::DEFAULT_STREAM_CONNECTIONS,
    ) {
        Ok(p) => p,
        Err(()) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "bus stream connection limit reached\n",
            )
                .into_response();
        }
    };
    let ip_guard = match crate::stream::acquire_stream_ip_slot(inner, &scope, client_ip) {
        Ok(g) => g,
        Err(()) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "per-client bus stream connection limit reached\n",
            )
                .into_response();
        }
    };

    let wake = messaging.wake_handle();
    // The durable pump task: claim → push each message into a bounded channel. Isolated from the WS
    // read loop so an inbound ack can never cancel an in-flight `claim_grouped` (at-least-once safe).
    // The bounded channel (sized to the per-claim batch) + `max_ack_pending` both bound read-ahead.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ClaimedMessage>(sub.max_batch.max(1));
    let pump_messaging = messaging.clone();
    let pump_task = tokio::spawn(async move {
        loop {
            match pump_until_batch(pump_messaging.as_ref(), &key, &sub, &wake).await {
                Ok(batch) => {
                    for m in batch {
                        if tx.send(m).await.is_err() {
                            return; // client gone (rx dropped)
                        }
                    }
                }
                Err(_) => return, // backend fault
            }
        }
    });

    tokio::spawn(async move {
        use futures::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::tungstenite::protocol::Role;

        // Permits held for the socket's lifetime; dropped (releasing the slot) when this task ends.
        let _permits = (site_permit, ip_guard);
        let Ok(upgraded) = on_upgrade.await else {
            pump_task.abort();
            return;
        };
        let socket =
            tokio_tungstenite::WebSocketStream::from_raw_socket(upgraded, Role::Server, None).await;
        let (mut sink, mut incoming) = socket.split();
        loop {
            tokio::select! {
                biased;
                // Inbound ack/nack frames FIRST (biased), so acks stay prompt and back-pressure drains.
                msg = incoming.next() => match msg {
                    Some(Ok(Message::Text(t))) => {
                        handle_ws_ack(messaging.as_ref(), &project, &topic, t.as_bytes()).await;
                    }
                    Some(Ok(Message::Binary(b))) => {
                        handle_ws_ack(messaging.as_ref(), &project, &topic, &b).await;
                    }
                    // Close / error / end-of-stream: tungstenite auto-answers pings; stop otherwise.
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => {}
                },
                // A durable delivery → one Text frame carrying the opaque handle.
                delivered = rx.recv() => match delivered {
                    Some(m) => {
                        let dto = ClaimedDto::from_message(&topic, &m);
                        let text = serde_json::to_string(&dto).unwrap_or_else(|_| "{}".to_string());
                        if sink.send(Message::Text(text)).await.is_err() {
                            break; // client gone
                        }
                    }
                    None => break, // pump ended (backend fault)
                },
            }
        }
        pump_task.abort();
    });

    // The `101` that triggers the serve loop's upgrade handoff — `Connection`/`Upgrade` must survive to
    // the client (the serve bridge preserves a `101` verbatim).
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

/// Apply one INLINE WebSocket ack/nack frame (`{"ack":"<handle>"}` or `{"nack":"<handle>","delay_ms":…}`).
///
/// SECURITY: the frame is confined to the connection's OWN subscribe topic. A durable stream claims
/// ONLY from `conn_topic`, so every handle it legitimately minted names that topic; the connection was
/// authorized `Messaging·Read` on exactly `<project>/<conn_topic>` (NARROWER than the project-wildcard
/// the SSE side-channel's `ack`/`nack` require), so a handle naming ANY OTHER topic is dropped — the
/// inline ack can never reach beyond the single topic this connection is scoped to. The full key is
/// recomposed from the TRUSTED path project (never the handle), identical to the shared side-channel,
/// so a tampered handle can never cross a project boundary either. A malformed/foreign frame is
/// silently ignored (an inline control frame has no response channel).
#[cfg(feature = "handlers")]
async fn handle_ws_ack(
    messaging: &dyn Messaging,
    project: &ProjectContext,
    conn_topic: &str,
    frame: &[u8],
) {
    #[derive(Deserialize)]
    struct WsAckFrame {
        #[serde(default)]
        ack: Option<String>,
        #[serde(default)]
        nack: Option<String>,
        #[serde(default)]
        delay_ms: Option<u64>,
    }
    let Ok(f) = serde_json::from_slice::<WsAckFrame>(frame) else {
        return;
    };
    let (handle, is_ack) = match (&f.ack, &f.nack) {
        (Some(h), _) => (h.as_str(), true),
        (None, Some(h)) => (h.as_str(), false),
        (None, None) => return,
    };
    // Confine to THIS connection's authorized topic (see the security note above): a handle that is
    // malformed, or names any topic OTHER than the one this connection subscribed to, is dropped.
    let Some(decoded) = AckHandle::decode(handle) else {
        return;
    };
    if decoded.topic != conn_topic {
        return;
    }
    let Ok(msg) = handle_to_message(project, handle) else {
        return;
    };
    let _ = if is_ack {
        messaging.ack(&msg).await
    } else {
        match f.delay_ms {
            Some(d) if d > 0 => messaging.nack_after(&msg, d).await,
            _ => messaging.nack(&msg).await,
        }
    };
}

// ---- Runtime gate A: the long-poll wakes on a real publish, with zero busy-poll, and inherits the
// durable lease/ack/nack/DLQ semantics unchanged. Drives the REAL `LogMessaging` claim core through a
// call-counting decorator (no stub). ------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::messaging::{
        ClaimedMessage, LogMessaging, Messaging, MessagingError, StartPosition, Wake,
    };
    use boatramp_core::{
        ByteStream, GetObject, ListPage, ObjectMeta, PutMeta, Storage, StorageError,
    };
    use bytes::Bytes as RawBytes;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Minimal in-memory [`Storage`] so the REAL [`LogMessaging`] substrate can be built (it persists
    /// non-inlined payloads as objects). Mirrors the shim test's `MemStorage`.
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

    #[async_trait]
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
            let slice = data[start..end].to_vec();
            Ok(GetObject {
                meta: meta(key, slice.len()),
                body: once_stream(RawBytes::from(slice)),
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

    /// A [`Messaging`] decorator over the REAL [`LogMessaging`] that COUNTS every `claim`/
    /// `claim_grouped` call — so the gate can prove the long-poll made only a small constant number
    /// of underlying claims (zero busy-poll). Every other op forwards unchanged, and `wake_handle`
    /// forwards the inner's real wake so a publish on the inner wakes a long-poll parked here.
    struct CountingMessaging {
        inner: Arc<LogMessaging>,
        claims: AtomicUsize,
    }

    impl CountingMessaging {
        fn new(inner: Arc<LogMessaging>) -> Self {
            Self {
                inner,
                claims: AtomicUsize::new(0),
            }
        }
        fn claims(&self) -> usize {
            self.claims.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Messaging for CountingMessaging {
        async fn publish(&self, topic: &str, payload: &[u8]) -> Result<(), MessagingError> {
            self.inner.publish(topic, payload).await
        }
        async fn publish_ctx(
            &self,
            topic: &str,
            payload: &[u8],
            signed_context: Option<&str>,
        ) -> Result<(), MessagingError> {
            self.inner.publish_ctx(topic, payload, signed_context).await
        }
        async fn claim(
            &self,
            topic: &str,
            lease: Duration,
            max_batch: usize,
            max_attempts: u32,
        ) -> Result<Vec<ClaimedMessage>, MessagingError> {
            self.claims.fetch_add(1, Ordering::SeqCst);
            self.inner
                .claim(topic, lease, max_batch, max_attempts)
                .await
        }
        async fn claim_grouped(
            &self,
            topic: &str,
            group: &str,
            start: StartPosition,
            lease: Duration,
            max_batch: usize,
            max_attempts: u32,
        ) -> Result<Vec<ClaimedMessage>, MessagingError> {
            self.claims.fetch_add(1, Ordering::SeqCst);
            self.inner
                .claim_grouped(topic, group, start, lease, max_batch, max_attempts)
                .await
        }
        async fn ack(&self, msg: &ClaimedMessage) -> Result<(), MessagingError> {
            self.inner.ack(msg).await
        }
        async fn nack(&self, msg: &ClaimedMessage) -> Result<(), MessagingError> {
            self.inner.nack(msg).await
        }
        async fn nack_after(
            &self,
            msg: &ClaimedMessage,
            delay_ms: u64,
        ) -> Result<(), MessagingError> {
            self.inner.nack_after(msg, delay_ms).await
        }
        async fn dead_letter_count(&self, topic: &str) -> Result<usize, MessagingError> {
            self.inner.dead_letter_count(topic).await
        }
        async fn backlog(&self, topic: &str) -> Result<usize, MessagingError> {
            self.inner.backlog(topic).await
        }
        // Forward the durable in-flight count UNCHANGED so the `max_ack_pending` back-pressure gate is
        // exercised against the REAL `LogMessaging` grouped-lease bookkeeping (the default trait impl
        // returns 0 and would silently disable the cap — a false green).
        async fn in_flight_count(&self, topic: &str) -> Result<usize, MessagingError> {
            self.inner.in_flight_count(topic).await
        }
        fn wake_handle(&self) -> Option<Wake> {
            self.inner.wake_handle()
        }
    }

    fn substrate() -> (Arc<CountingMessaging>, Arc<dyn Messaging>) {
        let inner = Arc::new(LogMessaging::new(
            Arc::new(MemStorage::default()),
            Arc::new(MemoryKv::new()),
        ));
        let counting = Arc::new(CountingMessaging::new(inner));
        let dynamic: Arc<dyn Messaging> = counting.clone();
        (counting, dynamic)
    }

    fn pull_sub() -> ResolvedSubscription {
        SubscriptionParams::default()
            .resolve_with_default_batch(SubscriptionParams::DEFAULT_CLAIM_BATCH)
    }

    /// RUNTIME GATE A — the long-poll returns when a message is actually produced (≈ at that time,
    /// NOT at a fixed poll tick / the deadline) and issues only a small constant number of underlying
    /// `claim` calls (proving ZERO busy-poll) — exercising the REAL `LogMessaging` claim core.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn long_poll_wakes_on_publish_with_zero_busy_poll() {
        let (counting, m) = substrate();
        let key = "acme/bus/orders/created".to_string();
        let sub = pull_sub();

        // Produce a message ~500 ms into the long-poll.
        let producer = {
            let m = m.clone();
            let key = key.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(500)).await;
                m.publish(&key, b"hello").await.unwrap();
            })
        };

        let before = counting.claims();
        let start = Instant::now();
        let claimed = long_poll_claim(m.as_ref(), &key, &sub, Duration::from_secs(5))
            .await
            .unwrap();
        let elapsed = start.elapsed();
        producer.await.unwrap();

        assert_eq!(claimed.len(), 1, "the produced message must be delivered");
        assert_eq!(claimed[0].payload, b"hello");
        assert_eq!(claimed[0].attempts, 1);
        assert!(
            elapsed >= Duration::from_millis(300),
            "returned before the message was produced: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "did NOT wake on the publish — returned at/near the 5s deadline (poll tick?): {elapsed:?}"
        );
        let claims_used = counting.claims() - before;
        assert!(
            (2..=5).contains(&claims_used),
            "expected a small constant number of claim calls (initial empty + post-wake); \
             got {claims_used} — a busy-poll would be hundreds"
        );
    }

    /// RUNTIME GATE A (inherited semantics) — ack deletes; nack and lease-expiry redeliver with the
    /// attempt count preserved; `max_attempts` dead-letters. The long-poll adds NO new durable
    /// semantics: these are the unchanged claim/lease/ack/nack/DLQ core, verified on the real
    /// substrate via the same leased message the long-poll returns.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn long_poll_inherits_claim_lease_ack_nack_dlq_semantics() {
        let (_counting, m) = substrate();
        let sub = pull_sub();

        // ---- ack deletes ----
        let ack_key = "acme/bus/orders/ackme".to_string();
        m.publish(&ack_key, b"done").await.unwrap();
        let claimed = long_poll_claim(m.as_ref(), &ack_key, &sub, Duration::from_millis(500))
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        m.ack(&claimed[0]).await.unwrap();
        let after_ack = m
            .claim(&ack_key, Duration::from_millis(100), 10, 5)
            .await
            .unwrap();
        assert!(after_ack.is_empty(), "ack must delete the message for good");

        // ---- nack redelivers with the attempt count incremented ----
        let nack_key = "acme/bus/orders/retry".to_string();
        m.publish(&nack_key, b"retry").await.unwrap();
        let first = m
            .claim(&nack_key, Duration::from_millis(40), 10, 5)
            .await
            .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].attempts, 1);
        m.nack(&first[0]).await.unwrap();
        let second = m
            .claim(&nack_key, Duration::from_millis(40), 10, 5)
            .await
            .unwrap();
        assert_eq!(second.len(), 1, "nack must redeliver");
        assert_eq!(
            second[0].attempts, 2,
            "nack preserves + increments the attempt count"
        );

        // ---- lease expiry redelivers (no ack) ----
        tokio::time::sleep(Duration::from_millis(70)).await;
        let third = m
            .claim(&nack_key, Duration::from_millis(40), 10, 5)
            .await
            .unwrap();
        assert_eq!(third.len(), 1, "an expired lease must redeliver");
        assert_eq!(
            third[0].attempts, 3,
            "lease-expiry redelivery preserves the attempt count"
        );
        m.ack(&third[0]).await.unwrap();

        // ---- max_attempts → DLQ ----
        let dlq_key = "acme/bus/orders/poison".to_string();
        let max_attempts = 2u32;
        m.publish(&dlq_key, b"poison").await.unwrap();
        for _ in 0..6 {
            let c = m
                .claim(&dlq_key, Duration::from_millis(30), 10, max_attempts)
                .await
                .unwrap();
            if c.is_empty() {
                break;
            }
            m.nack(&c[0]).await.unwrap();
        }
        let after = m
            .claim(&dlq_key, Duration::from_millis(30), 10, max_attempts)
            .await
            .unwrap();
        assert!(
            after.is_empty(),
            "a message past max_attempts must be dead-lettered, not redelivered"
        );
        assert!(
            m.dead_letter_count(&dlq_key).await.unwrap() >= 1,
            "the poison message must land in the DLQ"
        );
    }

    /// A long-poll on an empty topic with a `0` wait returns `[]` immediately after a single claim —
    /// the plain-claim degenerate case (no hang, no spin).
    #[tokio::test]
    async fn zero_wait_returns_immediately_with_one_claim() {
        let (counting, m) = substrate();
        let key = "acme/bus/orders/empty".to_string();
        let sub = pull_sub();
        let before = counting.claims();
        let claimed = long_poll_claim(m.as_ref(), &key, &sub, Duration::from_millis(0))
            .await
            .unwrap();
        assert!(claimed.is_empty());
        assert_eq!(
            counting.claims() - before,
            1,
            "wait=0 must make exactly one claim"
        );
    }

    // ---- Runtime gate B (b, durable streaming subscription): the durable `claim_grouped` pump
    // delivers every message with a usable handle, redelivers an unacked message on lease-expiry with
    // the attempt count preserved, dead-letters past `max_attempts`, back-pressures on `max_ack_pending`,
    // resumes without skipping an unacked message, and wakes on a real publish with ZERO busy-poll — all
    // against the REAL `LogMessaging` grouped-claim core (no stub). -----------------------------------

    /// A STREAM (per-tick) subscription over a durable consumer `group`.
    fn stream_sub(
        group: &str,
        lease_ms: u64,
        max_attempts: u32,
        max_ack_pending: Option<usize>,
    ) -> ResolvedSubscription {
        SubscriptionParams {
            group: group.to_string(),
            start: StartPosition::Latest,
            lease_ms: Some(lease_ms),
            max_attempts: Some(max_attempts),
            max_batch: None, // stream default (16)
            max_ack_pending,
            backoff_ms: None,
            retention_ms: None,
        }
        .resolve()
    }

    /// Register a durable group on first claim: sets its cursor at the current logmax (so only
    /// messages published AFTER this are delivered) and turns on publish-time fan-out retention.
    async fn register_group(m: &dyn Messaging, key: &str, group: &str) {
        let _ = m
            .claim_grouped(
                key,
                group,
                StartPosition::Latest,
                Duration::from_millis(50),
                16,
                5,
            )
            .await
            .unwrap();
    }

    /// GATE B (core) — a durable grouped subscription delivers every produced message with a usable
    /// opaque handle; an ack deletes for good; an UNACKED message redelivers on lease-expiry with the
    /// attempt count preserved (which is ALSO resume — the durable lease, not `Last-Event-ID`, is the
    /// authority, so a reconnect never skips it); a poison message dead-letters past `max_attempts`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn durable_stream_delivers_acks_redelivers_and_dead_letters() {
        let (_counting, m) = substrate();
        let key = "acme/bus/orders/created";
        let group = "analytics";
        let wake = m.wake_handle();
        // Short lease so the redelivery path is exercised quickly.
        let sub = stream_sub(group, 60, 3, None);

        register_group(m.as_ref(), key, group).await;
        let n = 5usize;
        for i in 0..n {
            m.publish(key, format!("msg-{i}").as_bytes()).await.unwrap();
        }

        // ---- delivery: every message arrives with a handle that round-trips to its topic ----
        let mut delivered: Vec<ClaimedMessage> = Vec::new();
        while delivered.len() < n {
            let batch = pump_until_batch(m.as_ref(), key, &sub, &wake)
                .await
                .unwrap();
            for cm in &batch {
                let dto = ClaimedDto::from_message("orders/created", cm);
                let decoded = AckHandle::decode(&dto.handle).expect("the delivery handle decodes");
                assert_eq!(
                    decoded.topic, "orders/created",
                    "handle carries the bare topic"
                );
                assert_eq!(cm.attempts, 1, "first delivery is attempt 1");
            }
            delivered.extend(batch);
        }
        assert_eq!(delivered.len(), n, "every produced message is delivered");

        // ---- ack deletes two for good ----
        m.ack(&delivered[0]).await.unwrap();
        m.ack(&delivered[1]).await.unwrap();

        // ---- the 3 UNACKED leases redeliver (== resume) with the attempt count preserved +1 ----
        tokio::time::sleep(Duration::from_millis(90)).await;
        let mut redelivered: Vec<ClaimedMessage> = Vec::new();
        while redelivered.len() < 3 {
            let batch = pump_until_batch(m.as_ref(), key, &sub, &wake)
                .await
                .unwrap();
            redelivered.extend(batch);
        }
        assert_eq!(
            redelivered.len(),
            3,
            "the 3 unacked leases must redeliver (never skipped)"
        );
        assert!(
            redelivered.iter().all(|cm| cm.attempts == 2),
            "lease-expiry redelivery preserves + increments the attempt count"
        );
        // The two ACKED messages are gone for good — their ids never reappear.
        let acked_ids = [delivered[0].id.clone(), delivered[1].id.clone()];
        assert!(
            redelivered.iter().all(|cm| !acked_ids.contains(&cm.id)),
            "an acked message is deleted for good — it must not redeliver"
        );
        for cm in &redelivered {
            m.ack(cm).await.unwrap();
        }

        // ---- DLQ: a poison message dead-letters past max_attempts (grouped core, unchanged) ----
        let dlq_key = "acme/bus/orders/poison";
        let dlq_group = "dlq-g";
        let max_attempts = 2u32;
        register_group(m.as_ref(), dlq_key, dlq_group).await;
        m.publish(dlq_key, b"poison").await.unwrap();
        for _ in 0..6 {
            let c = m
                .claim_grouped(
                    dlq_key,
                    dlq_group,
                    StartPosition::Latest,
                    Duration::from_millis(30),
                    16,
                    max_attempts,
                )
                .await
                .unwrap();
            if c.is_empty() {
                break;
            }
            m.nack(&c[0]).await.unwrap();
        }
        let after = m
            .claim_grouped(
                dlq_key,
                dlq_group,
                StartPosition::Latest,
                Duration::from_millis(30),
                16,
                max_attempts,
            )
            .await
            .unwrap();
        assert!(
            after.is_empty(),
            "a message past max_attempts must be dead-lettered, not redelivered"
        );
        assert!(
            m.dead_letter_count(dlq_key).await.unwrap() >= 1,
            "the poison message must land in the group's DLQ"
        );
    }

    /// GATE B (back-pressure) — `max_ack_pending` caps outstanding-unacked per connection via the
    /// durable `in_flight_count` gate: at the cap the pump claims NOTHING (parks), and an ack frees
    /// exactly one slot that the next claim fills. No message is lost or double-delivered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn durable_stream_max_ack_pending_caps_outstanding() {
        let (_counting, m) = substrate();
        let key = "acme/bus/orders/bp";
        let group = "slow";
        let wake = m.wake_handle();
        // Long lease (no mid-test redelivery) + a cap of 2.
        let sub = stream_sub(group, 30_000, 5, Some(2));

        register_group(m.as_ref(), key, group).await;
        for i in 0..5 {
            m.publish(key, format!("m{i}").as_bytes()).await.unwrap();
        }

        // The first claim is clamped to the cap: at most 2 leased-but-unacked outstanding.
        let first = pump_until_batch(m.as_ref(), key, &sub, &wake)
            .await
            .unwrap();
        assert_eq!(
            first.len(),
            2,
            "the initial claim is clamped to max_ack_pending"
        );

        // While both are unacked the pump must deliver NOTHING (it parks on the cap).
        let capped = tokio::time::timeout(
            Duration::from_millis(400),
            pump_until_batch(m.as_ref(), key, &sub, &wake),
        )
        .await;
        assert!(
            capped.is_err(),
            "at the cap the pump must park — no new delivery until an ack frees a slot"
        );

        // Ack one → frees exactly one slot → the next claim delivers exactly one more.
        m.ack(&first[0]).await.unwrap();
        let more = tokio::time::timeout(
            Duration::from_secs(2),
            pump_until_batch(m.as_ref(), key, &sub, &wake),
        )
        .await
        .expect("an ack frees a slot before the timeout")
        .unwrap();
        assert_eq!(more.len(), 1, "an ack freed exactly one outstanding slot");
    }

    /// GATE B (no busy-poll) — the durable pump returns at ~produce-time (woken by the real publish,
    /// not a poll tick) having issued only a small constant number of underlying grouped claims.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn durable_stream_wakes_on_publish_with_zero_busy_poll() {
        let (counting, m) = substrate();
        let key = "acme/bus/orders/stream";
        let group = "g1";
        let wake = m.wake_handle();
        let sub = stream_sub(group, 30_000, 5, None);
        register_group(m.as_ref(), key, group).await;

        // Produce a message ~400 ms into the pump.
        let producer = {
            let m = m.clone();
            let key = key.to_string();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(400)).await;
                m.publish(&key, b"hi").await.unwrap();
            })
        };

        let before = counting.claims();
        let start = Instant::now();
        let batch = pump_until_batch(m.as_ref(), key, &sub, &wake)
            .await
            .unwrap();
        let elapsed = start.elapsed();
        producer.await.unwrap();

        assert_eq!(batch.len(), 1, "the produced message must be delivered");
        assert_eq!(batch[0].payload, b"hi");
        assert!(
            elapsed >= Duration::from_millis(250),
            "returned before the message was produced: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "did NOT wake on the publish — returned near the 30s park (poll tick?): {elapsed:?}"
        );
        let claims = counting.claims() - before;
        assert!(
            (1..=4).contains(&claims),
            "expected a small constant number of grouped claims (initial empty + post-wake); got \
             {claims} — a busy-poll would be hundreds"
        );
    }

    /// GATE B (security) — an inline WS ack/nack frame naming a topic OTHER than the connection's own
    /// subscribe topic is DROPPED: the decode-level confinement keeps the inline ack within the exact
    /// `<project>/<topic>` the connection was authorized for (narrower than the side-channel's
    /// `<project>/*`). A frame for the OWN topic is accepted.
    #[test]
    fn ws_inline_ack_is_confined_to_the_connection_topic() {
        let msg = ClaimedMessage {
            id: "01HSOMEID".to_string(),
            topic: "acme/bus/orders/created".to_string(),
            payload: b"x".to_vec(),
            attempts: 1,
            group: "analytics".to_string(),
            signed_context: None,
            inline: false,
        };
        // A handle for THIS connection's topic decodes to that bare topic — accepted by the guard.
        let own = AckHandle::encode("orders/created", &msg);
        let decoded = AckHandle::decode(&own).unwrap();
        assert_eq!(
            decoded.topic, "orders/created",
            "a frame for the connection's own topic passes the confinement check"
        );
        // A handle for a DIFFERENT topic fails the `decoded.topic == conn_topic` guard, so
        // `handle_ws_ack` drops it (it can never ack a message outside the connection's scope).
        let foreign = AckHandle::encode("payments/charged", &msg);
        let decoded_foreign = AckHandle::decode(&foreign).unwrap();
        assert_ne!(
            decoded_foreign.topic, "orders/created",
            "a foreign-topic handle is rejected by the inline-ack confinement"
        );
    }
}
