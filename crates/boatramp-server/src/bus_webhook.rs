//! The project-bus **webhook sink** (PLAN-messaging-consumer-delivery, increment d): a host-run
//! pseudo-consumer that drains a project-bus topic and delivers each message as an outbound **signed
//! POST** to a sealed, SSRF-confined destination.
//!
//! Shaped exactly like the wasm consumer drainer ([`crate::handler_dispatch::dispatch_consumer_batch`])
//! — claim a batch under a lease, act per message, ack/nack — except the per-message action is an
//! HMAC-signed outbound POST (reusing the node-health webhook's SSRF floor, [`crate::health_alert`]):
//!   - the POST **is** the delivery; **HTTP 2xx ⇒ `ack`** (the message is deleted for good);
//!   - **non-2xx / timeout ⇒ `nack_after(backoff_ms × attempts)`** — the SAME linear backoff the wasm
//!     consumer uses (`handler_dispatch`), a crash-without-nack still redelivers on lease expiry;
//!   - **`max_attempts` ⇒ DLQ** — the core's attempt counting, unchanged.
//!
//! The webhook is a thin DELIVERY ADAPTER over the unchanged claim / lease / ack / nack / DLQ core —
//! no new durability primitive, no change to the wasm PUSH or the durable write path. The drain loop
//! REUSES the shared durable [`pump_until_batch`](crate::bus_consumer::pump_until_batch) core from
//! increment (b) — the `max_ack_pending` back-pressure, the zero-spin park-on-`Wake`, and the
//! redelivery/DLQ semantics all come for free.
//!
//! **One record, two registration paths** (owner decision): a runtime
//! `PUT`/`DELETE /api/projects/{proj}/bus/sinks/{name}` (`Messaging·Admin`-gated — the keystone maps
//! `sinks → Messaging·Admin` on `<project>`) persisted in the control-plane KV, AND the config-declared
//! `routing.webhook_sinks` block ([`boatramp_core::config::DeployConfig::webhook_sinks`]) activated on
//! deploy. Both converge on ONE [`WebhookSink`] + its ONE [`WebhookSink::validate`]; the drainer loop
//! ([`spawn_bus_webhook_drainer`]) drives BOTH sources.
//!
//! **Egress / SSRF confinement (SECURITY-critical, §4 — the interim floor).** A consumer-supplied
//! destination is an SSRF surface, confined in layers:
//!   - the destination is registered once + SEALED (`url_secret` names a `boatramp:<name>` project
//!     secret; the raw URL never rides a request body and is never logged — [`SealedWebhookUrl`] +
//!     the `without_url()` strip);
//!   - the SSRF floor runs at BOTH register-time ([`validate_sink_destination`]) AND delivery-time
//!     ([`deliver_webhook_message`]): [`ssrf_floored_resolve`]/[`ssrf_floored_post`] →
//!     `ssrf::resolve_pin` (https-only, userinfo-rejected, every resolved addr `is_global_ip`) +
//!     `ssrf::pinned_client` (pins the resolved addr, DNS-rebind choke);
//!   - the per-sink `egress_allow` (`host-glob:port`, empty ⇒ deny-all) the resolved destination MUST
//!     match, so a sink can't target `169.254.169.254` / RFC1918 / loopback (fails the allowlist AND
//!     `is_global_ip`);
//!   - **`allow_private` is operator-only, never consumer-settable** — [`WebhookSink`] carries no such
//!     field, so a sink can NEVER relax the floor; the `ssrf_bypass_active` mutation seam makes the
//!     gate go RED when armed, proving the floor is load-bearing.
//!
//! TODO(privsep egress broker): this ships on the INTERIM floor (the same floor the node-health
//! webhook relies on in production today). When the privsep egress-trust decision lands, the sink's
//! actual TCP connect should move BEHIND the privsep egress broker so the main process can't reach
//! arbitrary addresses at all (connect isolation) — a FOLLOW-UP, not this cut.

use std::collections::BTreeMap;
use std::time::Duration;

use super::*;

use boatramp_core::config::WebhookSink;
use boatramp_core::kv::KvStore;
use boatramp_core::messaging::{ClaimedMessage, Messaging};
use boatramp_core::project::{ProjectRef, validate_object_key};
use boatramp_core::secret_store::SecretStore;
use boatramp_core::webhook_sink::WebhookSinkStore;

use crate::health_alert::{
    SealedWebhookUrl, ssrf_bypass_active, ssrf_floored_post, ssrf_floored_resolve,
};
use crate::operator::bus_namespace;
use crate::project_scope::ProjectContext;

/// How often the drainer loop polls every registered sink for messages to deliver. A periodic drain
/// mirrors the wasm consumer model (the scheduler polls consumers on a tick); delivery latency is
/// bounded by one tick, with no busy-poll (an empty claim returns immediately and the loop parks on
/// the interval).
pub const WEBHOOK_DRAIN_TICK: Duration = Duration::from_millis(1000);

/// Per-delivery HTTP request timeout (ms). A slow/stalled sink past this is a non-2xx-equivalent →
/// nack-with-backoff, exactly like a 5xx.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(15);

/// Request headers carried on every signed webhook POST, so the receiver can verify the body and
/// dedupe/observe a redelivery.
const HEADER_MESSAGE_ID: &str = "X-Boatramp-Message-Id";
const HEADER_ATTEMPT: &str = "X-Boatramp-Message-Attempt";
const HEADER_TOPIC: &str = "X-Boatramp-Topic";
const HEADER_SIGNATURE: &str = "X-Boatramp-Signature";

// The KV-backed registry of runtime-registered sinks lives in
// [`boatramp_core::webhook_sink::WebhookSinkStore`] (alongside the other project-record stores); the
// config-declared sinks ride the deploy manifest. Both converge on the ONE [`WebhookSink`] record.

// ---- secret resolution + the signed, SSRF-floored delivery -------------------------------------

/// Resolve a sealed `boatramp:<name>` project-secret reference to its bytes. Fail-closed: a
/// non-`boatramp:` ref, a missing secret, or a store error all `Err` — never a plaintext fallback.
/// The scheme matches the node-health webhook's `resolve_webhook_url`, but scoped to the sink's
/// PROJECT (not the reserved `default`) so a project's sink resolves only its own tenant's secrets.
async fn resolve_sealed_ref(
    secret_store: &SecretStore,
    project: &str,
    reference: &str,
) -> Result<Vec<u8>, String> {
    let name = reference
        .trim()
        .strip_prefix(WebhookSink::SEALED_REF_PREFIX)
        .ok_or_else(|| {
            format!(
                "sink secret ref must be a sealed `{}<name>` reference",
                WebhookSink::SEALED_REF_PREFIX
            )
        })?;
    match secret_store.get(ProjectRef::new(project), name).await {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(format!(
            "sink secret {name:?} not found in the sealed store for project {project:?}"
        )),
        Err(e) => Err(format!("sink secret resolve failed: {e}")),
    }
}

/// Unseal a sink's destination URL into the redacting [`SealedWebhookUrl`] (never logged, never on a
/// request body).
async fn resolve_sink_url(
    secret_store: &SecretStore,
    project: &str,
    sink: &WebhookSink,
) -> Result<SealedWebhookUrl, String> {
    let bytes = resolve_sealed_ref(secret_store, project, &sink.url_secret).await?;
    let url =
        String::from_utf8(bytes).map_err(|_| "sink URL secret is not valid UTF-8".to_string())?;
    let url = url.trim();
    if url.is_empty() {
        return Err("sink URL secret is empty".to_string());
    }
    Ok(SealedWebhookUrl::seal(url.to_string()))
}

/// Lowercase-hex HMAC-SHA256 of `body` under `key` (the per-sink signing key).
fn hmac_sha256_hex(key: &[u8], body: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    // HMAC accepts a key of any length — `new_from_slice` is infallible for `Hmac`.
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// The register-time SSRF-floor DECISION for a sink: unseal its URL (and require its sign secret to
/// resolve, so a registered sink can actually sign), then run the resolved destination through the
/// floor + the per-sink `egress_allow` allowlist. Returns a redacted refusal (never the URL) if the
/// destination is not https / is userinfo-bearing / resolves non-global / is off the allowlist. Run at
/// REGISTER time so a sink pointed at `169.254.169.254` / RFC1918 / loopback is refused BEFORE it is
/// ever stored — the same floor delivery re-runs on every POST. Production flags: `allow_non_global` is
/// ONLY the mutation seam ([`ssrf_bypass_active`], `false` in a shipped build — a consumer has no
/// relaxation), and the live-gate loopback-http fixture is off.
pub(crate) async fn validate_sink_destination(
    secret_store: &SecretStore,
    project: &str,
    sink: &WebhookSink,
) -> Result<(), String> {
    let url = resolve_sink_url(secret_store, project, sink).await?;
    // The sign secret must resolve too (a sink that cannot sign is misconfigured).
    let _ = resolve_sealed_ref(secret_store, project, &sink.sign_secret).await?;
    ssrf_floored_resolve(&url, ssrf_bypass_active(), false, Some(&sink.egress_allow)).await?;
    Ok(())
}

/// Deliver ONE claimed message as a signed POST to the sink's destination — the per-message action of
/// the pseudo-consumer. Unseal the URL + the HMAC key, run the destination through the SHARED SSRF
/// floor + the per-sink `egress_allow` ([`ssrf_floored_post`]), and POST the RAW payload body signed
/// with the per-sink key and carrying the message id + attempt count. `Ok(())` iff the sink returns
/// HTTP 2xx (the caller acks); any non-2xx / timeout / floor-refusal is a redacted `Err` (the caller
/// nacks-with-backoff). `allow_loopback_http` is a live-gate fixture (`false` in all production wiring)
/// that lets the runtime gate reach a loopback mock sink.
pub(crate) async fn deliver_webhook_message(
    secret_store: &SecretStore,
    project: &str,
    sink: &WebhookSink,
    msg: &ClaimedMessage,
    allow_loopback_http: bool,
) -> Result<(), String> {
    let url = resolve_sink_url(secret_store, project, sink).await?;
    let sign_key = resolve_sealed_ref(secret_store, project, &sink.sign_secret).await?;
    let signature = hmac_sha256_hex(&sign_key, &msg.payload);

    // `allow_private` is operator-only and ABSENT from a sink record, so the only relaxation of the
    // floor is the mutation seam (`false` in a shipped build) — a consumer can NEVER widen it.
    let allow_non_global = ssrf_bypass_active();

    let body = msg.payload.clone();
    let id = msg.id.clone();
    let attempt = msg.attempts.to_string();
    let topic = sink.topic.clone();

    let resp = ssrf_floored_post(
        &url,
        allow_non_global,
        allow_loopback_http,
        Some(&sink.egress_allow),
        move |rb| {
            rb.header(HEADER_MESSAGE_ID, id)
                .header(HEADER_ATTEMPT, attempt)
                .header(HEADER_TOPIC, topic)
                .header(HEADER_SIGNATURE, signature)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(body)
                .timeout(DELIVERY_TIMEOUT)
        },
    )
    .await?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("webhook sink returned HTTP {}", resp.status()))
    }
}

// ---- the pseudo-consumer: pump a durable batch → deliver → ack / nack+backoff / DLQ ------------

/// Settle ONE delivered-or-failed message against the durable core: an HTTP-2xx `outcome` **acks** it
/// (deleted for good); any failure (non-2xx / timeout / floor-refusal) **nacks** it, held
/// `backoff_ms × attempts` — the SAME linear backoff the wasm consumer uses
/// ([`dispatch_consumer_batch`](crate::handler_dispatch)). The attempt count is preserved, so the core
/// dead-letters it at `max_attempts` (unchanged); a crash before this settle redelivers on lease expiry.
/// `outcome.err` is already redacted (never the sealed URL).
async fn settle_delivery(
    messaging: &dyn Messaging,
    sink: &WebhookSink,
    msg: &ClaimedMessage,
    backoff_ms: u64,
    outcome: Result<(), String>,
) {
    match outcome {
        Ok(()) => {
            if let Err(err) = messaging.ack(msg).await {
                tracing::warn!(
                    sink = %sink.name, id = %msg.id, %err,
                    "webhook sink ack failed; the message will redeliver on lease expiry"
                );
            }
        }
        Err(reason) => {
            let delay = backoff_ms.saturating_mul(u64::from(msg.attempts));
            let nack = if delay > 0 {
                messaging.nack_after(msg, delay).await
            } else {
                messaging.nack(msg).await
            };
            if let Err(e) = nack {
                tracing::warn!(sink = %sink.name, id = %msg.id, error = %e, "webhook sink nack failed");
            }
            tracing::debug!(
                sink = %sink.name, id = %msg.id, attempt = msg.attempts, %reason,
                "webhook sink delivery failed; nacked with backoff"
            );
        }
    }
}

/// Run ONE sink as a durable subscriber: a long-lived loop that reuses the shared, zero-spin
/// [`pump_until_batch`](crate::bus_consumer::pump_until_batch) core from increment (b) — the
/// `max_ack_pending` back-pressure (via the durable `in_flight_count`), the park-on-[`Wake`] (no
/// busy-poll), and the redelivery/DLQ semantics all come for free — then delivers each claimed message
/// as a signed, SSRF-confined POST and [`settle_delivery`]s it (ack on 2xx / nack+backoff otherwise).
/// A host-run background drainer, NOT a client connection, so it takes NO stream permits. Loops until
/// the task is aborted by the supervisor (a removed/changed sink); an in-flight delivery dropped by an
/// abort simply redelivers on lease expiry (at-least-once holds).
async fn run_webhook_sink(
    messaging: std::sync::Arc<dyn Messaging>,
    secret_store: std::sync::Arc<SecretStore>,
    project: String,
    sink: WebhookSink,
    allow_loopback_http: bool,
) {
    let key = bus_namespace(&ProjectRef::new(&project), &sink.topic);
    let sub = sink.subscription().resolve();
    let wake = messaging.wake_handle();
    loop {
        let batch = match crate::bus_consumer::pump_until_batch(
            messaging.as_ref(),
            &key,
            &sub,
            &wake,
        )
        .await
        {
            Ok(batch) => batch,
            Err(err) => {
                // A transient claim fault: back off a beat and retry (never a hot loop).
                tracing::warn!(sink = %sink.name, topic = %key, %err, "webhook sink claim failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        for msg in &batch {
            let outcome =
                deliver_webhook_message(&secret_store, &project, &sink, msg, allow_loopback_http)
                    .await;
            settle_delivery(messaging.as_ref(), &sink, msg, sub.backoff_ms, outcome).await;
        }
    }
}

// ---- the active-sink enumeration (BOTH registration paths) + the supervisor --------------------

/// Collect every ACTIVE sink across all projects, merging the two registration paths into the ONE
/// record type: the config-declared `routing.webhook_sinks` of each project's CURRENT deployments
/// (lower precedence) overlaid by the runtime-registered KV sinks (higher precedence — a runtime
/// `PUT` of the same name wins). Keyed by `(project, name)`.
async fn collect_active_sinks(
    kv: &std::sync::Arc<dyn KvStore>,
    deploy: &DeployStore,
) -> BTreeMap<(String, String), WebhookSink> {
    let store = WebhookSinkStore::new(kv.clone());
    let mut by_name: BTreeMap<(String, String), WebhookSink> = BTreeMap::new();
    let projects = match deploy.list_projects().await {
        Ok(p) => p,
        Err(err) => {
            tracing::warn!(%err, "webhook drainer: list projects failed");
            return by_name;
        }
    };
    for project in &projects {
        let proj = &project.name;
        let pref = ProjectRef::new(proj);
        // Config-declared sinks from every current deployment (first-seen wins across sites).
        if let Ok(sites) = deploy.list_sites(pref).await {
            for site in sites {
                if let Ok(Some(manifest)) = deploy.current_manifest(pref, &site).await {
                    for sink in manifest.config.webhook_sinks {
                        by_name
                            .entry((proj.clone(), sink.name.clone()))
                            .or_insert(sink);
                    }
                }
            }
        }
        // Runtime-registered sinks override config on a name collision.
        match store.list_project_sinks(proj).await {
            Ok(sinks) => {
                for sink in sinks {
                    by_name.insert((proj.clone(), sink.name.clone()), sink);
                }
            }
            Err(err) => {
                tracing::warn!(project = %proj, %err, "webhook drainer: list runtime sinks failed");
            }
        }
    }
    by_name
}

/// A content fingerprint of a sink record, so the supervisor restarts a per-sink subscriber only when
/// the sink's definition actually changed (not on every reconcile).
fn sink_fingerprint(sink: &WebhookSink) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    // The serialized record captures every field; hash its bytes.
    serde_json::to_vec(sink).unwrap_or_default().hash(&mut h);
    h.finish()
}

/// Spawn the **webhook-sink supervisor**: a periodic reconcile loop that owns ONE durable-subscriber
/// task ([`run_webhook_sink`]) per active sink (both registration paths), spawning a task for a newly
/// registered sink, aborting one for a removed sink, and restarting one whose record changed. Each
/// subscriber drains via the shared [`pump_until_batch`](crate::bus_consumer::pump_until_batch) — zero
/// busy-poll, wake-driven. NOT leader-gated: a webhook sink is a consumer and the durable
/// `claim_grouped` is leader-serialized, so every node may drain and at-least-once still holds (the wasm
/// consumer model). Returns the supervisor's `JoinHandle`; aborting it drops the owned per-sink tasks.
pub fn spawn_bus_webhook_drainer(
    messaging: std::sync::Arc<dyn Messaging>,
    secret_store: std::sync::Arc<SecretStore>,
    kv: std::sync::Arc<dyn KvStore>,
    deploy: DeployStore,
    tick: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // One running subscriber per active sink, with the record fingerprint it was started for.
        let mut running: BTreeMap<(String, String), (tokio::task::JoinHandle<()>, u64)> =
            BTreeMap::new();
        let mut interval = tokio::time::interval(tick);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let desired = collect_active_sinks(&kv, &deploy).await;

            // Stop subscribers whose sink was removed or whose record changed (abort → the in-flight
            // claim/delivery is dropped; its leased message redelivers on lease expiry). Also prune a
            // subscriber that has exited on its own (should not happen — the loop is infinite).
            running.retain(|key, (handle, fp)| {
                let keep = desired.get(key).is_some_and(|s| sink_fingerprint(s) == *fp)
                    && !handle.is_finished();
                if !keep {
                    handle.abort();
                }
                keep
            });

            // Start a subscriber for every desired sink not already running.
            for (key, sink) in &desired {
                if running.contains_key(key) {
                    continue;
                }
                let fp = sink_fingerprint(sink);
                let handle = tokio::spawn(run_webhook_sink(
                    messaging.clone(),
                    secret_store.clone(),
                    key.0.clone(),
                    sink.clone(),
                    // Production wiring never reaches a loopback-http mock.
                    false,
                ));
                running.insert(key.clone(), (handle, fp));
            }
        }
    })
}

// ---- the runtime registration API: PUT / DELETE .../bus/sinks/{name} ----------------------------

/// `PUT /api/projects/{proj}/bus/sinks/{name}` — register (create/replace) a webhook sink. Authorization
/// (`Messaging·Admin` on `<project>` — the keystone's `sinks` authz arm) is enforced by `require_auth`
/// BEFORE this handler. The project + sink name come from the TRUSTED path (never a client-supplied
/// body field), so a sink is structurally confined to the authorized project. The body is validated
/// (one shared [`WebhookSink::validate`]), the topic re-screened for traversal, and the destination run
/// through the register-time SSRF floor ([`validate_sink_destination`]) — a sink pointed at an
/// internal/metadata address is refused BEFORE it is ever stored.
#[cfg(feature = "handlers")]
pub(crate) async fn bus_sink_put(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<ProjectContext>,
    Path((_project_seg, name)): Path<(String, String)>,
    Json(mut sink): Json<WebhookSink>,
) -> Response {
    // The path name is authoritative (the body's `name` is overwritten, never trusted over the path).
    sink.name = name;
    if let Err(e) = sink.validate() {
        return (
            StatusCode::BAD_REQUEST,
            format!("invalid webhook sink: {e}\n"),
        )
            .into_response();
    }
    // Defense-in-depth: re-screen the topic for traversal / reserved namespace exactly as the
    // claim/ack path does.
    if let Err(e) = validate_object_key(&sink.topic) {
        return (StatusCode::BAD_REQUEST, format!("invalid topic: {e}\n")).into_response();
    }
    let Some(secret_store) = handlers.secret_store() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no [secrets] envelope configured — a webhook sink's sealed URL cannot be unsealed\n",
        )
            .into_response();
    };
    let Some(kv) = handlers.kv() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no control-plane store configured\n",
        )
            .into_response();
    };
    let project_name = project.as_ref().as_str().to_string();

    // Register-time SSRF floor: resolve the sealed URL + sign secret and run the destination through
    // the floor + the per-sink egress allowlist BEFORE storing. A refusal is a 400 (consumer error),
    // never a 5xx, and never echoes the sealed URL.
    if let Err(e) = validate_sink_destination(&secret_store, &project_name, &sink).await {
        return (
            StatusCode::BAD_REQUEST,
            format!("webhook sink destination refused: {e}\n"),
        )
            .into_response();
    }

    match WebhookSinkStore::new(kv).set(&project_name, &sink).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::warn!(project = %project_name, sink = %sink.name, error = %e, "webhook sink register failed");
            (
                StatusCode::BAD_GATEWAY,
                "failed to persist the webhook sink\n",
            )
                .into_response()
        }
    }
}

/// `DELETE /api/projects/{proj}/bus/sinks/{name}` — remove a webhook sink (idempotent; `404` when it
/// did not exist). Same `Messaging·Admin`-on-`<project>` authz + trusted-path project as the `PUT`.
#[cfg(feature = "handlers")]
pub(crate) async fn bus_sink_delete(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<ProjectContext>,
    Path((_project_seg, name)): Path<(String, String)>,
) -> Response {
    let Some(kv) = handlers.kv() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no control-plane store configured\n",
        )
            .into_response();
    };
    let project_name = project.as_ref().as_str().to_string();
    match WebhookSinkStore::new(kv).delete(&project_name, &name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such webhook sink\n").into_response(),
        Err(e) => {
            tracing::warn!(project = %project_name, sink = %name, error = %e, "webhook sink delete failed");
            (
                StatusCode::BAD_GATEWAY,
                "failed to delete the webhook sink\n",
            )
                .into_response()
        }
    }
}

// ---- Runtime gate D: the real claim core + the real signed SSRF-floored deliver path ------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::Mutex;

    use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::messaging::LogMessaging;
    use boatramp_core::{
        ByteStream, GetObject, ListPage, ObjectMeta, PutMeta, Storage, StorageError,
    };
    use bytes::Bytes as RawBytes;
    use futures::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ---- a minimal in-memory Storage so the REAL LogMessaging substrate can be built -----------
    #[derive(Default, Clone)]
    struct MemStorage {
        map: Arc<Mutex<std::collections::BTreeMap<String, Vec<u8>>>>,
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

    /// A reversible identity-ish envelope (XOR) so a "sealed" secret differs from the plaintext yet
    /// round-trips — lets the gate seal a real URL + HMAC key into a real `SecretStore`.
    struct XorEnvelope;
    #[async_trait::async_trait]
    impl KeyEnvelope for XorEnvelope {
        async fn wrap(&self, p: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(p.iter().map(|b| b ^ 0x5a).collect())
        }
        async fn unwrap(&self, w: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(w.iter().map(|b| b ^ 0x5a).collect())
        }
    }

    fn substrate() -> Arc<dyn Messaging> {
        Arc::new(LogMessaging::new(
            Arc::new(MemStorage::default()),
            Arc::new(MemoryKv::new()),
        ))
    }

    async fn secret_store_with(entries: &[(&str, &[u8])]) -> Arc<SecretStore> {
        let store = SecretStore::new(Arc::new(MemoryKv::new()), Arc::new(XorEnvelope));
        for (name, value) in entries {
            store
                .set(ProjectRef::new("acme"), name, value)
                .await
                .unwrap();
        }
        Arc::new(store)
    }

    /// A captured inbound request to the mock sink (for verifying the signature + headers).
    #[derive(Clone, Default)]
    struct CapturedReq {
        headers: std::collections::HashMap<String, String>,
        body: Vec<u8>,
    }

    /// A minimal loopback HTTP/1.1 mock sink returning a fixed status, capturing each request. Bound
    /// to the address `localhost` resolves to (so `resolve_pin`'s own lookup pins the SAME address),
    /// so the URL can carry a NAME (`http://localhost:<port>`) the per-sink `egress_allow` can match —
    /// an IP literal never matches the allowlist (names only).
    async fn spawn_mock_sink(status: u16) -> (u16, Arc<Mutex<Vec<CapturedReq>>>) {
        // Pin to whichever loopback address `localhost` resolves to first.
        let bind_ip = tokio::net::lookup_host(("localhost", 0))
            .await
            .expect("resolve localhost")
            .next()
            .expect("localhost resolves to at least one address")
            .ip();
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(bind_ip, 0))
            .await
            .expect("bind mock sink");
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(Mutex::new(Vec::<CapturedReq>::new()));
        let cap = captured.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let cap = cap.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    // Read until the end of the headers.
                    let header_end = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                        match sock.read(&mut tmp).await {
                            Ok(0) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                            Err(_) => return,
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    let mut headers = std::collections::HashMap::new();
                    let mut content_len = 0usize;
                    for line in head.lines().skip(1) {
                        if let Some((k, v)) = line.split_once(':') {
                            let k = k.trim().to_ascii_lowercase();
                            let v = v.trim().to_string();
                            if k == "content-length" {
                                content_len = v.parse().unwrap_or(0);
                            }
                            headers.insert(k, v);
                        }
                    }
                    let mut body = buf[header_end..].to_vec();
                    while body.len() < content_len {
                        match sock.read(&mut tmp).await {
                            Ok(0) => break,
                            Ok(n) => body.extend_from_slice(&tmp[..n]),
                            Err(_) => break,
                        }
                    }
                    cap.lock().unwrap().push(CapturedReq { headers, body });
                    let reason = if (200..300).contains(&status) {
                        "OK"
                    } else {
                        "ERR"
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });
        (port, captured)
    }

    fn sink_for(port: u16, backoff_ms: u64, max_attempts: u32) -> WebhookSink {
        WebhookSink {
            name: "fulfillment".into(),
            topic: "orders/created".into(),
            group: String::new(),
            url_secret: "boatramp:wh-url".into(),
            egress_allow: vec![format!("localhost:{port}")],
            sign_secret: "boatramp:wh-sign".into(),
            lease_ms: Some(10_000),
            max_attempts: Some(max_attempts),
            backoff_ms: Some(backoff_ms),
            max_ack_pending: None,
        }
    }

    /// ONE deterministic claim→deliver→settle pass — mirrors [`run_webhook_sink`]'s body but with a
    /// DIRECT `claim_grouped` instead of [`pump_until_batch`](crate::bus_consumer::pump_until_batch), so
    /// a backoff'd / empty topic returns at once rather than parking the test for up to `EMPTY_PARK`.
    /// (The shared pump's claim/park/back-pressure is driven end-to-end by `gate_d_runs_via_shared_pump`
    /// and `gate_d_max_ack_pending_backpressure` below.) Returns the number ACKED this pass.
    async fn deliver_and_settle_once(
        m: &dyn Messaging,
        ss: &SecretStore,
        project: &str,
        sink: &WebhookSink,
        allow_loopback_http: bool,
    ) -> usize {
        let key = bus_namespace(&ProjectRef::new(project), &sink.topic);
        let sub = sink.subscription().resolve();
        let claimed = m
            .claim_grouped(
                &key,
                &sub.group,
                sub.start,
                Duration::from_millis(sub.lease_ms),
                sub.max_batch,
                sub.max_attempts,
            )
            .await
            .unwrap();
        let mut acked = 0;
        for msg in &claimed {
            let outcome =
                deliver_webhook_message(ss, project, sink, msg, allow_loopback_http).await;
            let ok = outcome.is_ok();
            settle_delivery(m, sink, msg, sub.backoff_ms, outcome).await;
            if ok {
                acked += 1;
            }
        }
        acked
    }

    /// RUNTIME GATE D (2xx ⇒ ack + the signed body) — a produced message is delivered to a real
    /// loopback sink through the REAL claim core + the REAL signed, SSRF-floored POST path; an HTTP
    /// 2xx acks it (gone), and the sink receives the HMAC-SHA256 signature of the body + the
    /// message-id / attempt headers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gate_d_2xx_acks_and_signs() {
        let (port, captured) = spawn_mock_sink(200).await;
        let m = substrate();
        let secret_store = secret_store_with(&[
            ("wh-url", format!("http://localhost:{port}/hook").as_bytes()),
            ("wh-sign", b"topsecret-hmac-key"),
        ])
        .await;
        let sink = sink_for(port, 100, 5);
        let key = bus_namespace(&ProjectRef::new("acme"), &sink.topic);
        m.publish(&key, b"order-42").await.unwrap();

        let acked =
            deliver_and_settle_once(m.as_ref(), secret_store.as_ref(), "acme", &sink, true).await;
        assert_eq!(acked, 1, "a 2xx delivery must ack exactly one message");

        // The message is gone (acked for good).
        let after = m
            .claim(&key, Duration::from_millis(50), 10, 5)
            .await
            .unwrap();
        assert!(
            after.is_empty(),
            "a 2xx-delivered message must be acked (gone)"
        );

        // The sink received the signed body + headers.
        let reqs = captured.lock().unwrap().clone();
        assert_eq!(
            reqs.len(),
            1,
            "the sink must have received exactly one POST"
        );
        assert_eq!(
            reqs[0].body, b"order-42",
            "the raw payload is the POST body"
        );
        let expect_sig = hmac_sha256_hex(b"topsecret-hmac-key", b"order-42");
        assert_eq!(
            reqs[0].headers.get("x-boatramp-signature"),
            Some(&expect_sig),
            "the POST must carry the per-sink HMAC-SHA256 of the body"
        );
        assert_eq!(
            reqs[0]
                .headers
                .get("x-boatramp-message-attempt")
                .map(String::as_str),
            Some("1"),
            "the POST must carry the attempt count"
        );
        assert!(
            reqs[0].headers.contains_key("x-boatramp-message-id"),
            "the POST must carry the message id"
        );
    }

    /// RUNTIME GATE D (non-2xx ⇒ redeliver with `backoff_ms × attempts`, then DLQ) — a sink that
    /// returns 500 never acks; the message redelivers with the attempt count climbing and the linear
    /// backoff spacing it out, and past `max_attempts` it dead-letters (the core's job, inherited).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gate_d_non_2xx_redelivers_with_backoff_then_dlq() {
        let (port, _captured) = spawn_mock_sink(500).await;
        let m = substrate();
        let secret_store = secret_store_with(&[
            ("wh-url", format!("http://localhost:{port}/hook").as_bytes()),
            ("wh-sign", b"k"),
        ])
        .await;
        // Short lease + small backoff so the test is fast; max_attempts=3 → DLQ after the 3rd failure.
        // backoff_ms=20 ⇒ the attempt-N redelivery is held 20×N ms; sleeping 100ms (> the 20×3=60ms
        // max pre-DLQ backoff) between drains makes every redelivery claimable, so the run is
        // deterministic.
        let mut sink = sink_for(port, 20, 3);
        sink.lease_ms = Some(50);
        let key = bus_namespace(&ProjectRef::new("acme"), &sink.topic);
        m.publish(&key, b"poison").await.unwrap();

        // Attempt 1: deliver (500) → nack_after(20 × 1 = 20ms). Nothing acked.
        let acked =
            deliver_and_settle_once(m.as_ref(), secret_store.as_ref(), "acme", &sink, true).await;
        assert_eq!(acked, 0, "a 500 must not ack");
        // Immediately re-draining finds nothing: the backoff holds the message invisible (the nacked
        // message is still durably present — proving at-least-once — just not yet claimable).
        let acked_now =
            deliver_and_settle_once(m.as_ref(), secret_store.as_ref(), "acme", &sink, true).await;
        assert_eq!(
            acked_now, 0,
            "the backoff must hold the message invisible (no redelivery yet)"
        );

        // Drive it past max_attempts: each pass waits out the (growing) backoff, re-delivers (500),
        // nacks. 6 passes comfortably exceeds the 3 deliveries + the DLQ-triggering claim.
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            deliver_and_settle_once(m.as_ref(), secret_store.as_ref(), "acme", &sink, true).await;
        }

        // Past max_attempts the message is dead-lettered, never redelivered.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let after =
            deliver_and_settle_once(m.as_ref(), secret_store.as_ref(), "acme", &sink, true).await;
        assert_eq!(
            after, 0,
            "a message past max_attempts must not keep redelivering"
        );
        assert!(
            m.dead_letter_count(&key).await.unwrap() >= 1,
            "a message past max_attempts must land in the DLQ"
        );
    }

    /// RUNTIME GATE D (the shared pump, end-to-end) — the REAL per-sink subscriber loop
    /// ([`run_webhook_sink`], driving the shared [`pump_until_batch`](crate::bus_consumer::pump_until_batch)
    /// from increment (b)) delivers a published message as a signed POST and acks it on 2xx. Proves the
    /// drain loop is the shared pump, not a parallel hand-rolled claimer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gate_d_runs_via_shared_pump() {
        let (port, captured) = spawn_mock_sink(200).await;
        let m = substrate();
        let secret_store = secret_store_with(&[
            ("wh-url", format!("http://localhost:{port}/hook").as_bytes()),
            ("wh-sign", b"k"),
        ])
        .await;
        let sink = sink_for(port, 100, 5);
        let key = bus_namespace(&ProjectRef::new("acme"), &sink.topic);

        // Spawn the actual production subscriber loop, then produce a message.
        let task = tokio::spawn(run_webhook_sink(
            m.clone(),
            secret_store.clone(),
            "acme".into(),
            sink,
            true,
        ));
        m.publish(&key, b"via-pump").await.unwrap();

        // Wait (bounded) until the sink received the POST and the message was acked (gone).
        let mut delivered_and_acked = false;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let got_post = !captured.lock().unwrap().is_empty();
            if got_post && m.dead_letter_count(&key).await.unwrap() == 0 {
                // The pump owns the only in-flight lease; once the POST is captured the ack follows, so
                // a short grace then a fresh claim confirming empty proves the message is gone.
                tokio::time::sleep(Duration::from_millis(50)).await;
                if m.claim(&key, Duration::from_millis(20), 1, 5)
                    .await
                    .unwrap()
                    .is_empty()
                {
                    delivered_and_acked = true;
                    break;
                }
            }
        }
        task.abort();
        assert!(
            delivered_and_acked,
            "the shared-pump subscriber must deliver (signed POST) + ack the published message"
        );
        assert_eq!(captured.lock().unwrap()[0].body, b"via-pump");
    }

    /// RUNTIME GATE D (back-pressure via the shared pump's durable `in_flight_count`) — with
    /// `max_ack_pending` set, [`pump_until_batch`](crate::bus_consumer::pump_until_batch) claims NOTHING
    /// while the outstanding-unacked count is at the cap (it parks), and resumes once acks free a slot.
    /// Driven on the REAL `LogMessaging` (its real `in_flight_count`), so there is no decorator that
    /// could silently return 0 and false-green the gate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gate_d_max_ack_pending_backpressure() {
        let m = substrate();
        let key = "acme/bus/orders/created".to_string();
        let mut sink = sink_for(443, 0, 5);
        sink.max_ack_pending = Some(2);
        let sub = sink.subscription().resolve();
        let wake = m.wake_handle();

        for i in 0..3 {
            m.publish(&key, format!("m{i}").as_bytes()).await.unwrap();
        }
        // Lease 2 (no ack) on the SAME lane the pump claims → durable in_flight = 2 = the cap.
        let leased = m
            .claim_grouped(&key, &sub.group, sub.start, Duration::from_secs(30), 2, 5)
            .await
            .unwrap();
        assert_eq!(leased.len(), 2);

        // At the cap the pump must park (claim nothing) → the bounded wait elapses.
        let capped = tokio::time::timeout(
            Duration::from_millis(700),
            crate::bus_consumer::pump_until_batch(m.as_ref(), &key, &sub, &wake),
        )
        .await;
        assert!(
            capped.is_err(),
            "at the max_ack_pending cap the shared pump must claim nothing (parks)"
        );

        // Acking the two frees the cap → the pump delivers the remaining message.
        for msg in &leased {
            m.ack(msg).await.unwrap();
        }
        let batch = tokio::time::timeout(
            Duration::from_secs(3),
            crate::bus_consumer::pump_until_batch(m.as_ref(), &key, &sub, &wake),
        )
        .await
        .expect("the pump must return once the cap frees")
        .unwrap();
        assert!(
            !batch.is_empty(),
            "freeing the cap lets the shared pump claim the remaining message"
        );
    }

    /// RUNTIME GATE D (internal / metadata URL ⇒ REFUSED at BOTH register and delivery) — a sink
    /// pointed at the cloud-metadata endpoint, an RFC1918 address, or loopback is refused by the
    /// allowlist + the `is_global_ip` floor at register-time (`validate_sink_destination`) AND at
    /// delivery-time (`deliver_webhook_message`), with production flags (no loopback-http, no bypass).
    #[tokio::test]
    async fn gate_d_internal_url_refused_at_register_and_delivery() {
        let m = substrate();
        for target in [
            "https://169.254.169.254/latest/meta-data/", // cloud metadata (link-local IP)
            "https://10.1.2.3/hook",                     // RFC1918 (IP literal)
            "https://127.0.0.1/hook",                    // loopback (IP literal)
            "https://localhost/hook",                    // loopback by NAME (resolves non-global)
        ] {
            let secret_store =
                secret_store_with(&[("wh-url", target.as_bytes()), ("wh-sign", b"k")]).await;
            // A broad allowlist so the SSRF floor (not the allowlist) is what refuses the NAME case,
            // and both legs refuse the IP-literal cases (an IP literal never matches a glob anyway).
            let sink = WebhookSink {
                name: "exfil".into(),
                topic: "orders/created".into(),
                group: String::new(),
                url_secret: "boatramp:wh-url".into(),
                egress_allow: vec!["**:443".into(), "localhost:443".into()],
                sign_secret: "boatramp:wh-sign".into(),
                lease_ms: Some(10_000),
                max_attempts: Some(5),
                backoff_ms: Some(0),
                max_ack_pending: None,
            };

            // Register-time: REFUSED (production flags inside `validate_sink_destination`).
            let reg = validate_sink_destination(secret_store.as_ref(), "acme", &sink).await;
            assert!(
                reg.is_err(),
                "registering a sink pointed at {target:?} must be refused by the SSRF floor"
            );

            // Delivery-time: REFUSED too (production flags — `allow_loopback_http=false`).
            let key = bus_namespace(&ProjectRef::new("acme"), &sink.topic);
            m.publish(&key, b"secret").await.unwrap();
            let claimed = m.claim(&key, Duration::from_secs(5), 1, 5).await.unwrap();
            assert_eq!(claimed.len(), 1);
            let deliver = deliver_webhook_message(
                secret_store.as_ref(),
                "acme",
                &sink,
                &claimed[0],
                false, // production: no loopback-http fixture
            )
            .await;
            assert!(
                deliver.is_err(),
                "delivering to {target:?} must be refused by the SSRF floor at delivery-time"
            );
            // Never redelivers past its lease into this next assertion; clean the DLQ-irrelevant state.
            m.nack(&claimed[0]).await.ok();
        }
    }

    /// GATE D (the `ssrf_bypass_active` seam proves the `is_global_ip` floor is LOAD-BEARING) — with a
    /// NAME target the per-sink allowlist matches in both cases, so ONLY the floor flips the verdict:
    /// dormant it REFUSES a loopback-resolving name; armed (the bypass) it ADMITS it → the gate goes
    /// RED. Serialized against the health-alert mutation key (shared env var).
    #[tokio::test]
    #[serial_test::serial(health_alert_mutation)]
    async fn gate_d_ssrf_bypass_seam_proves_floor_load_bearing() {
        let secret_store =
            secret_store_with(&[("wh-url", b"https://localhost/hook"), ("wh-sign", b"k")]).await;
        let sink = WebhookSink {
            name: "probe".into(),
            topic: "orders/created".into(),
            group: String::new(),
            url_secret: "boatramp:wh-url".into(),
            egress_allow: vec!["localhost:443".into()], // the allowlist matches in BOTH cases
            sign_secret: "boatramp:wh-sign".into(),
            lease_ms: Some(10_000),
            max_attempts: Some(5),
            backoff_ms: Some(0),
            max_ack_pending: None,
        };

        // Dormant: the is_global_ip floor refuses the loopback-resolving NAME (allowlist matched).
        let dormant = validate_sink_destination(secret_store.as_ref(), "acme", &sink).await;
        assert!(
            dormant.is_err(),
            "the SSRF floor must refuse a loopback-resolving destination when the bypass is dormant"
        );

        // Armed: the bypass drops the is_global_ip floor → the SAME destination is now ADMITTED
        // (gate RED), proving the floor was the load-bearing check.
        // SAFETY: test-only env toggle, immediately cleared; serialized on this key.
        unsafe { std::env::set_var("BOATRAMP_HEALTHALERT_MUTATION", "ssrf_bypass") };
        let armed = validate_sink_destination(secret_store.as_ref(), "acme", &sink).await;
        unsafe { std::env::remove_var("BOATRAMP_HEALTHALERT_MUTATION") };
        assert!(
            armed.is_ok(),
            "the armed SSRF-bypass must admit the destination the floor otherwise refuses (gate RED)"
        );
    }

    /// The register-time + delivery-time allowlist is deny-all for an off-list destination even when
    /// it is a perfectly global, https host — the per-sink `egress_allow` is the explicit reach grant.
    #[tokio::test]
    async fn off_allowlist_destination_is_refused() {
        let secret_store = secret_store_with(&[
            ("wh-url", b"https://sink.example.com/hook"),
            ("wh-sign", b"k"),
        ])
        .await;
        let sink = WebhookSink {
            name: "mismatch".into(),
            topic: "t".into(),
            group: String::new(),
            url_secret: "boatramp:wh-url".into(),
            egress_allow: vec!["other.example.com:443".into()], // does NOT cover sink.example.com
            sign_secret: "boatramp:wh-sign".into(),
            lease_ms: None,
            max_attempts: None,
            backoff_ms: None,
            max_ack_pending: None,
        };
        let reg = validate_sink_destination(secret_store.as_ref(), "acme", &sink).await;
        assert!(
            reg.is_err(),
            "a destination not covered by egress_allow must be refused (deny-all off-list)"
        );
    }
}
