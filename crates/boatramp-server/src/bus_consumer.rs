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

use std::time::{Duration, Instant};

use super::*;

use base64::Engine as _;
use boatramp_core::config::{ResolvedSubscription, StartPosition, SubscriptionParams};
use boatramp_core::messaging::{ClaimedMessage, Messaging};
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
                .map(|m| ClaimedDto {
                    id: m.id.clone(),
                    topic: topic.clone(),
                    attempts: m.attempts,
                    payload_b64: base64::engine::general_purpose::STANDARD.encode(&m.payload),
                    handle: AckHandle::encode(&topic, m),
                })
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
}
