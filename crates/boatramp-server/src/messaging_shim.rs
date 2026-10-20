//! The compute **messaging-shim** (PLAN-compute-bindings) — the messaging analogue of the
//! [`sql_shim`](crate::sql_shim) / [`blob_shim`](crate::blob_shim), symmetric with them end to
//! end.
//!
//! An opaque compute workload (container / micro-VM) cannot import the `wasi:messaging`
//! host interface a handler uses. This shim gives it the *same* project-bus capability — both
//! halves, **publish AND consume** — over a plain HTTP wire, so an off-the-shelf HTTP client in
//! the guest meets a `wasi:messaging` handler on ONE project bus. One per-node listener, one
//! scoped bearer token, verb-prefixed routes:
//!
//! - `POST /publish/{*topic}` — body = payload → publishes to `{project}/bus/<topic>`, the exact
//!   keyspace a `wasi:messaging` producer that calls `publish("bus:<topic>", …)` reaches.
//! - `POST /claim/{*topic}`  — leases up to `?max` messages for `?lease_ms` (at-least-once,
//!   competing-consumer work queue — the trait's [`Messaging::claim`]); returns each payload +
//!   an opaque ack handle.
//! - `POST /ack`             — delete a claimed message for good ([`Messaging::ack`]).
//! - `POST /nack`            — redeliver it, immediately or after `?delay_ms`
//!   ([`Messaging::nack`] / [`Messaging::nack_after`]).
//!
//! All five run on the SAME [`Messaging`] substrate (`inner.messaging`) the host binding
//! resolves, so a native MX edge can `enqueue` a `DeliverJob` to `bus:deliver` AND a native
//! worker can drain it, exactly as a consumer *function* would. (The bus has no
//! visibility-extend primitive, so the shim exposes none — it never invents a semantic the
//! substrate lacks.)
//!
//! ## Isolation (mirrors the blob-shim's token→resolved-scope model)
//!
//! Requests authenticate with `Authorization: Bearer <token>`; the token maps to a
//! [`MessagingScope`] **already resolved for exactly one project bus** (the same
//! `{project}/bus/` prefix — `ProjectRef::qualified("bus")` — a `wasi:messaging` handler's
//! `bus:` publish lands under). The PROJECT is carried by the TOKEN's stored `bus_prefix`,
//! NEVER by a client-supplied or guessable field, so a workload is structurally incapable
//! of naming another project's bus. A `--bind messaging:<topic>` token is additionally
//! bound to one topic (cross-topic rejected); a bare `--bind messaging` token may name any
//! topic WITHIN the project bus, and every topic is screened ([`validate_object_key`]) so a
//! path-traversal topic can never escape the `{project}/bus/` prefix. The token is
//! boatramp-minted (HMAC over the per-node secret), instance-scoped, and rotatable (a fresh
//! per-node secret on restart re-derives it); the operator's substrate credentials never
//! enter the guest.
//!
//! ## Producer context (the one DOCUMENTED divergence from the guest producer)
//!
//! A `wasi:messaging` handler stamps a host-minted durable **signed-context** envelope (R1)
//! onto each message, sealed from its resolved own-tenant, so a consumer declaring
//! `sources: [signed_context]` resolves the producer. A native/compute workload has no
//! in-guest resolved tenant to seal, so the shim publishes as an **unscoped producer**
//! (`publish_ctx(key, data, None)` — identical to a plain `publish`). A consumer that
//! REQUIRES a signed context fails such a message closed, exactly as it does for a guest
//! producer with no resolved own-tenant (`publish_without_a_resolved_tenant_stamps_no_context`).
//! The shim deliberately does NOT reuse the handler path's `mint_producer_context` machinery
//! — that is a per-invocation, principal-derived seal with no native analogue, and inventing
//! one would be exactly the "new crypto" this work avoids.
//!
//! ## Scope grain (the SECOND documented divergence)
//!
//! The sql/blob shims treat the **workload name** as a site identity (per-site
//! `database`/`hblob/{site}/`). The project bus is **project-scoped**, not site-scoped
//! (`{project}/bus/…`, shared across every site + component in the project — that is the
//! whole point of `bus:`), so the messaging-shim scope keys on the PROJECT and the workload
//! name does not enter the bus prefix. The token derivation still mixes the workload (so two
//! workloads in one project mint distinct tokens), but the resolved keyspace is the project
//! bus.
//!
//! ## Network posture (listener bind)
//!
//! The listener binds the **host the operator names in `compute.messaging_shim_url`** — the
//! compute bridge-gateway IP / loopback that makes it reachable from the guests — via
//! [`crate::shim_bind_addr`], NEVER all interfaces on its own. This is a token-gated DATA
//! plane over the whole `{project}/bus/` namespace whose per-replica token is injected into
//! an often-untrusted guest env, so it MUST NOT be reachable off-node: operators point
//! `messaging_shim_url` at the bridge gateway (or loopback), never a public address. (An
//! explicit `0.0.0.0` in the URL is honored as the operator's own choice.)

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use boatramp_core::compute::{BindingKind, ComputeBinding, ComputeBindingResolver};
use boatramp_core::messaging::{ClaimedMessage, Messaging};
use boatramp_core::project::{ProjectRef, validate_object_key};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

/// A token-resolved messaging capability: the project bus [`Messaging`] substrate, the
/// topic prefix the token is confined to (`{project}/bus/` — host-stamped, never
/// client-supplied), and the one topic it may touch when the binding named one.
#[derive(Clone)]
struct MessagingScope {
    messaging: Arc<dyn Messaging>,
    /// `{project}/bus/` — the EXACT project-bus prefix a `wasi:messaging` producer's
    /// `bus:<topic>` publish is namespaced under (see `with_messaging`'s `bus_prefix`,
    /// `format!("{}/", project.qualified("bus"))`).
    bus_prefix: String,
    /// The one topic a `--bind messaging:<topic>` token is bound to, or `None` for a
    /// bus-wide `--bind messaging` token (which may name any topic WITHIN the project bus).
    topic: Option<String>,
}

/// The shim's token → resolved [`MessagingScope`] registry, shared with the HTTP handler.
///
/// The registry is keyed on `SHA-256(salt ∥ token)`, never the raw bearer token, so token
/// ADMISSION (the `HashMap` key compare) is timing-safe: a probe can at most learn a prefix of a
/// preimage-resistant hash of a 256-bit secret token, never the token itself (defense-in-depth
/// atop the already-unguessable HMAC token). Identical to the blob/sql shims' registries.
#[derive(Clone)]
pub struct MessagingShim {
    registry: Arc<RwLock<HashMap<[u8; 32], MessagingScope>>>,
    salt: [u8; 32],
}

impl Default for MessagingShim {
    fn default() -> Self {
        Self::new()
    }
}

impl MessagingShim {
    /// A fresh, empty shim with a per-instance random admission salt.
    pub fn new() -> Self {
        let mut salt = [0u8; 32];
        // A failed RNG only weakens the (defense-in-depth) salt to zero — admission stays timing-safe
        // because the key is still a preimage-resistant hash of a 256-bit secret token.
        let _ = getrandom::getrandom(&mut salt);
        Self {
            registry: Arc::new(RwLock::new(HashMap::new())),
            salt,
        }
    }

    /// The registry key for a bearer `token`: `SHA-256(salt ∥ token)`.
    fn key(&self, token: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.salt);
        hasher.update(token.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    /// Register a bearer `token` for an already-resolved, project-bus-scoped `scope`.
    /// Idempotent: re-registering the same token replaces the mapping.
    async fn register(&self, token: &str, scope: MessagingScope) {
        let key = self.key(token);
        self.registry.write().await.insert(key, scope);
    }

    /// Drop a token when its workload replica is torn down.
    async fn deregister(&self, token: &str) {
        let key = self.key(token);
        self.registry.write().await.remove(&key);
    }

    /// Resolve a presented bearer `token` to its [`MessagingScope`], or `None` for a missing
    /// or unknown/mismatched token (fail-closed authentication). The `admit_unmatched`
    /// mutation seam admits a missing/unknown token to SOME registered scope — exactly the
    /// breach the gate must catch; it is compiled out of every shipped build.
    async fn authenticate(&self, token: Option<&str>) -> Option<MessagingScope> {
        let reg = self.registry.read().await;
        if let Some(t) = token
            && let Some(scope) = reg.get(&self.key(t)).cloned()
        {
            return Some(scope);
        }
        if messaging_mutation().as_deref() == Some("admit_unmatched") {
            return reg.values().next().cloned();
        }
        None
    }

    /// The axum router — verb-prefixed so publish and the consume (claim/ack/nack) ops share
    /// ONE bind yet never collide with each other or with a freeform topic (the topic may
    /// contain `/`, e.g. `orders/created`; a topic literally named `claim` is published via
    /// `POST /publish/claim` and claimed via `POST /claim/claim` — the verb is always the first
    /// segment). Mount it on a node-internal listener (see [`spawn_messaging_shim`]).
    ///
    /// - `POST /publish/{*topic}` — body = payload (optional `?delay_ms`/`?ttl_ms`/`?priority`).
    /// - `POST /claim/{*topic}`   — lease up to `?max` msgs for `?lease_ms` (`?max_attempts`);
    ///   returns each payload + an opaque ack handle.
    /// - `POST /ack`              — body `{ "handle": … }`: delete the message for good.
    /// - `POST /nack`             — body `{ "handle": …, "delay_ms"?: … }`: redeliver (now, or
    ///   after a backoff).
    pub fn router(&self) -> Router {
        Router::new()
            .route("/publish/{*topic}", post(publish))
            .route("/claim/{*topic}", post(claim))
            .route("/ack", post(ack))
            .route("/nack", post(nack))
            .with_state(self.clone())
    }
}

/// Resolves a workload's `messaging` [`ComputeBinding`]s to a shim endpoint + credential
/// injected into the guest env. Holds the same [`Messaging`] substrate the `wasi:messaging`
/// host binding uses, the shim registry, the guest-reachable shim base URL, and a per-node
/// secret used to derive a token that is **deterministic** (recomputable at release /
/// re-register without persisting it) yet **unguessable** (keyed by the secret). The direct
/// analogue of [`crate::blob_shim::BlobShimResolver`].
pub struct MessagingShimResolver {
    messaging: Arc<dyn Messaging>,
    shim: MessagingShim,
    base_url: String,
    secret: [u8; 32],
}

impl MessagingShimResolver {
    /// `base_url` is the shim URL reachable from the guest; `secret` is a per-node random
    /// used only to key the token derivation.
    pub fn new(
        messaging: Arc<dyn Messaging>,
        shim: MessagingShim,
        base_url: String,
        secret: [u8; 32],
    ) -> Self {
        Self {
            messaging,
            shim,
            base_url,
            secret,
        }
    }

    /// A deterministic, unguessable bearer token for one `(project, workload, replica,
    /// binding)` — `HMAC-SHA256(secret, project ∥ workload ∥ name ∥ replica ∥ kind)`.
    /// Identical derivation to the blob/sql shims', so a messaging binding and a blob/sql
    /// binding on the same replica mint DISTINCT tokens (the `kind` byte differs).
    fn token(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        binding: &ComputeBinding,
    ) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).expect("hmac accepts any key len");
        for part in [
            project.as_bytes(),
            workload.as_bytes(),
            binding.name.as_bytes(),
        ] {
            mac.update(part);
            mac.update(&[0]);
        }
        mac.update(&replica.to_le_bytes());
        // A STABLE discriminant byte — never `format!("{:?}", kind)`, which would silently rotate
        // every live token if the enum were reordered/renamed.
        mac.update(&[binding.kind.stable_tag()]);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// The [`MessagingScope`] for a `messaging` binding on this `project`: the SAME substrate
    /// and `{project}/bus/` prefix the `wasi:messaging` host binding's `bus:` publish resolves.
    /// The workload does NOT enter the prefix (the bus is project-scoped, not site-scoped — see
    /// the module docs). A `--bind messaging:<topic>` additionally binds the one named topic;
    /// an invalid topic fails closed (`None` returned ⇒ the binding is skipped). Pure given the
    /// substrate, so the convention is unit-testable.
    fn scope(&self, project: &str, binding: &ComputeBinding) -> Option<MessagingScope> {
        // The topic, when named (`--bind messaging:<topic>`), must be a safe key — reject
        // traversal/control bytes at resolve time (fail closed), mirroring the blob shim's
        // resolve-time `validate_key_segment` choke point. A bus topic legitimately contains
        // `/` and `.` (`orders/created`, `concept.generate`), so the key screen (not the
        // single-segment screen) is the right one.
        let topic = if binding.name.is_empty() {
            None
        } else {
            if validate_object_key(&binding.name).is_err() {
                tracing::warn!(
                    %project, name = %binding.name,
                    "messaging binding: invalid topic; binding skipped"
                );
                return None;
            }
            Some(binding.name.clone())
        };
        // `{project}/bus/` — `ProjectRef::qualified("bus")` is `{project}/bus` for EVERY project
        // including the reserved `default` (`default/bus`, v0.31.0 Finding 8), matching the host
        // binding's `format!("{}/", project.qualified("bus"))`.
        let bus_prefix = format!("{}/", ProjectRef::new(project).qualified("bus"));
        Some(MessagingScope {
            messaging: self.messaging.clone(),
            bus_prefix,
            topic,
        })
    }
}

#[async_trait::async_trait]
impl ComputeBindingResolver for MessagingShimResolver {
    async fn resolve(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
    ) -> Vec<(String, String)> {
        let mut env = Vec::new();
        for binding in bindings {
            if binding.kind != BindingKind::Messaging {
                continue;
            }
            let Some(scope) = self.scope(project, binding) else {
                continue;
            };
            let token = self.token(project, workload, replica, binding);
            self.shim.register(&token, scope).await;
            let url_env = binding.url_env();
            env.push((url_env.clone(), self.base_url.clone()));
            env.push((format!("{url_env}_AUTH_TOKEN"), token));
        }
        env
    }

    async fn release(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
    ) {
        for binding in bindings {
            if binding.kind == BindingKind::Messaging {
                self.shim
                    .deregister(&self.token(project, workload, replica, binding))
                    .await;
            }
        }
    }
}

/// Activate the compute messaging-shim: bind its listener and build the resolver to hand the
/// compute reconcile. `shim_url` is the guest-reachable base URL (e.g. `http://10.0.0.1:8083`,
/// or the docker bridge gateway); the shim binds the **host:port the URL names** — the compute
/// bridge-gateway IP / loopback the operator configured — NOT all interfaces (see
/// [`crate::shim_bind_addr`] for the security rationale). Returns `None` — the feature stays
/// off — when there is no messaging substrate, no `shim_url`, or the host:port does not
/// resolve / bind. The direct analogue of [`crate::blob_shim::spawn_blob_shim`].
pub async fn spawn_messaging_shim(
    messaging: Option<Arc<dyn Messaging>>,
    shim_url: Option<String>,
) -> Option<Arc<dyn ComputeBindingResolver>> {
    let messaging = messaging?;
    let base_url = shim_url?;
    let Some(bind) = crate::shim_bind_addr(&base_url) else {
        tracing::warn!(%base_url, "compute.messaging_shim_url has no resolvable host:port; messaging bindings disabled");
        return None;
    };
    let mut secret = [0u8; 32];
    if getrandom::getrandom(&mut secret).is_err() {
        tracing::error!("getrandom failed; messaging bindings disabled");
        return None;
    }
    let shim = MessagingShim::new();
    let router = shim.router();
    match tokio::net::TcpListener::bind(bind).await {
        Ok(listener) => {
            // TCP_NODELAY: the shim serves small publish ACKs to the guest's `messaging`
            // binding over keep-alive; Nagle would add a ~40 ms delayed-ACK stall to each.
            // Mirrors the blob/sql shims. See `disable_nagle`.
            use axum::serve::ListenerExt;
            let listener = listener.tap_io(crate::disable_nagle);
            tokio::spawn(async move {
                if let Err(err) = axum::serve(listener, router).await {
                    tracing::error!(error = %err, "compute messaging-shim listener exited");
                }
            });
            tracing::info!(%bind, %base_url, "compute messaging-shim listening");
        }
        Err(err) => {
            tracing::warn!(%bind, error = %err, "compute messaging-shim bind failed; messaging bindings disabled");
            return None;
        }
    }
    Some(Arc::new(MessagingShimResolver::new(
        messaging, shim, base_url, secret,
    )))
}

// ---- the enforced authorization + key-composition decision -------------------

/// A fail-closed refusal from [`authorize`]. Distinct, greppable categories — never
/// collapsed — each mapped to a status by [`IntoResponse`].
#[derive(Debug)]
enum Denied {
    /// Missing or unknown/mismatched bearer token → 401.
    Unauthenticated,
    /// A topic-bound token named a DIFFERENT topic → 403.
    CrossTopic,
    /// The topic escapes its bus prefix (`..`/absolute/reserved/…) → 400.
    BadTopic(String),
}

impl IntoResponse for Denied {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                "missing or unknown bearer token\n",
            )
                .into_response(),
            Self::CrossTopic => (
                StatusCode::FORBIDDEN,
                "topic not permitted by this token's scope\n",
            )
                .into_response(),
            Self::BadTopic(e) => {
                (StatusCode::BAD_REQUEST, format!("invalid topic: {e}\n")).into_response()
            }
        }
    }
}

/// **THE single enforced authorization + key-composition decision** (mirrors the blob-shim's
/// `authorize`): the publish handler resolves its target through here, so the TESTED code is
/// the ENFORCED code. Given the token-resolved `scope` (`None` ⇒ the bearer was
/// missing/unknown) and the client-supplied `topic`, return the substrate plus the FINAL bus
/// key `{project}/bus/<topic>`, or a fail-closed [`Denied`].
///
/// The PROJECT is taken ONLY from `scope.bus_prefix` (token-bound), never from any client
/// field, so **cross-project is structurally impossible**. The three anti-hollow mutation
/// seams (test / `compute-messaging-shim-gate-mutation` only, compiled out of ships) each
/// neuter ONE enforced check so the CI gate proves it load-bearing: `allow_cross_topic`
/// drops the topic bind, `allow_traversal` drops the topic screen, and `admit_unmatched`
/// (in [`MessagingShim::authenticate`]) admits an unmatched token.
fn authorize(
    scope: Option<&MessagingScope>,
    topic: &str,
) -> Result<(Arc<dyn Messaging>, String), Denied> {
    // authentication: no resolved scope ⇒ fail closed.
    let scope = scope.ok_or(Denied::Unauthenticated)?;
    // cross-topic: a topic-bound token admits ONLY its topic. The project is already fixed by
    // `scope.bus_prefix`, so this is the only client-named dimension.
    if let Some(bound) = scope.topic.as_deref() {
        let permitted =
            bound == topic || messaging_mutation().as_deref() == Some("allow_cross_topic");
        if !permitted {
            return Err(Denied::CrossTopic);
        }
    }
    // traversal: screen the topic (rejects `..`/absolute/doubled-`/`/`\`/`*`/control bytes +
    // the reserved `.boatramp*` namespace) — the SAME screen the blob binding's key path runs,
    // so a traversal topic can never escape the `{project}/bus/` prefix.
    if messaging_mutation().as_deref() != Some("allow_traversal") {
        validate_object_key(topic).map_err(|e| Denied::BadTopic(e.to_string()))?;
    }
    // Compose under the TOKEN's bus prefix: `{project}/bus/<topic>` — the EXACT key a
    // `wasi:messaging` producer's `bus:<topic>` publish for this project reaches.
    Ok((
        scope.messaging.clone(),
        format!("{}{topic}", scope.bus_prefix),
    ))
}

/// Extract the `Authorization: Bearer <token>` value.
fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.trim().to_string())
}

/// Optional delivery-mode query params on a `POST /publish/{topic}`, mirroring the guest
/// producer's `publish_delayed` / `publish_with_ttl` / `publish_with_priority` verbs. At most
/// one is honored, in the precedence delay > ttl > priority; none ⇒ a plain `publish`.
#[derive(Debug, Default, Deserialize)]
struct PublishParams {
    /// Visibility delay in milliseconds (`publish_delayed`).
    #[serde(default)]
    delay_ms: Option<u64>,
    /// Time-to-live in milliseconds (`publish_with_ttl`).
    #[serde(default)]
    ttl_ms: Option<u64>,
    /// Priority 0–255 (`publish_with_priority`).
    #[serde(default)]
    priority: Option<u8>,
}

/// `POST /publish/{*topic}`: authenticate the bearer token to a resolved project-bus scope,
/// authorize the topic, and publish the request body to `{project}/bus/<topic>`. A native
/// producer is **unscoped** (no in-guest tenant to seal) — `signed_context` is `None`, so a
/// consumer requiring a signed context fails such a message closed, identical to a guest
/// producer with no resolved own-tenant (see the module docs).
async fn publish(
    State(shim): State<MessagingShim>,
    headers: HeaderMap,
    Path(topic): Path<String>,
    Query(params): Query<PublishParams>,
    body: Bytes,
) -> Response {
    let token = bearer(&headers);
    let scope = shim.authenticate(token.as_deref()).await;
    let (messaging, key) = match authorize(scope.as_ref(), &topic) {
        Ok(v) => v,
        Err(denied) => return denied.into_response(),
    };

    // At most one delivery mode, delay > ttl > priority; else a plain publish. Each maps 1:1
    // to the substrate's matching `publish_*_ctx` method the guest producer also calls.
    let result = if let Some(delay) = params.delay_ms {
        messaging
            .publish_delayed_ctx(&key, &body, std::time::Duration::from_millis(delay), None)
            .await
    } else if let Some(ttl) = params.ttl_ms {
        messaging
            .publish_with_ttl_ctx(&key, &body, std::time::Duration::from_millis(ttl), None)
            .await
    } else if let Some(priority) = params.priority {
        messaging
            .publish_with_priority_ctx(&key, &body, priority, None)
            .await
    } else {
        messaging.publish_ctx(&key, &body, None).await
    };

    match result {
        Ok(()) => (StatusCode::OK, topic).into_response(),
        Err(err) => {
            // A genuine substrate fault reaches ONLY the log with its real cause; the guest gets
            // a coarse, non-leaking reason — the same discipline the blob shim's `storage_fault`
            // enforces.
            tracing::warn!(key, error = %err, "compute messaging-shim publish fault");
            (StatusCode::BAD_GATEWAY, "messaging backend unavailable\n").into_response()
        }
    }
}

// ---- the consume half (claim / ack / nack) ----------------------------------

/// Default `claim` batch size (lease ONE message) when `?max` is absent.
const DEFAULT_CLAIM_MAX: usize = 1;
/// Hard cap on a single `claim`'s batch size — bounds the response body a buggy/greedy consumer
/// can pull in one call (the claim-side analogue of the publish `max_object_bytes`/batch caps).
const MAX_CLAIM_MAX: usize = 1024;
/// Default visibility lease (ms) when `?lease_ms` is absent — the window a claimed message stays
/// invisible before redelivery if not acked.
const DEFAULT_LEASE_MS: u64 = 30_000;
/// Default `max_attempts` (dead-letter after this many deliveries) when `?max_attempts` is absent.
const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Query params for `POST /claim/{topic}` — the [`Messaging::claim`] knobs. All optional;
/// absent ⇒ the defaults above. `max` is clamped to `[1, MAX_CLAIM_MAX]`.
#[derive(Debug, Default, Deserialize)]
struct ClaimParams {
    /// Max messages to lease in this claim (default 1, clamped to [`MAX_CLAIM_MAX`]).
    #[serde(default)]
    max: Option<usize>,
    /// Visibility lease in milliseconds (default [`DEFAULT_LEASE_MS`]).
    #[serde(default)]
    lease_ms: Option<u64>,
    /// Dead-letter threshold — deliveries before the message is quarantined (default
    /// [`DEFAULT_MAX_ATTEMPTS`]).
    #[serde(default)]
    max_attempts: Option<u32>,
}

/// One claimed message on the wire. `ClaimedMessage` is not `Serialize`, so this is a
/// shim-local DTO: the payload rides base64 and the `handle` is an opaque, self-contained
/// string the consumer presents back to `ack`/`nack`.
#[derive(Debug, Serialize)]
struct ClaimedDto {
    /// The substrate's unique, roughly time-ordered message id.
    id: String,
    /// The BARE topic the consumer claimed (not the full `{project}/bus/` key) — its own naming.
    topic: String,
    /// Delivery attempts so far, including this one (starts at 1).
    attempts: u32,
    /// Base64 (standard) of the message payload.
    payload_b64: String,
    /// Opaque ack/nack handle (see [`AckHandle`]).
    handle: String,
}

/// The `POST /claim/{topic}` response body.
#[derive(Debug, Serialize)]
struct ClaimResponse {
    messages: Vec<ClaimedDto>,
}

/// The opaque ack/nack **handle**: everything needed to faithfully reconstruct the
/// [`ClaimedMessage`] the trait's `ack`/`nack` identify a message by — base64url(JSON) of these
/// fields. It carries the BARE topic (re-authorized against the bearer's scope on every
/// ack/nack, so a tampered handle can never reach another project/topic) and the exact payload
/// (so `ack`'s inline byte-budget accounting is exact). It is NOT a bearer credential — the
/// `Authorization` token is the authority; a self-contained handle keeps the shim stateless (no
/// claimed-message map to GC or lose across a restart).
#[derive(Debug, Serialize, Deserialize)]
struct AckHandle {
    /// The substrate message id ([`ClaimedMessage::id`]).
    id: String,
    /// The BARE topic (re-authorized on ack/nack; the full key is recomposed from the scope).
    topic: String,
    /// The consumer group ([`ClaimedMessage::group`]) — `""` for the default work queue; `ack`/
    /// `nack` branch on it.
    group: String,
    /// Whether the payload was inlined in the index record ([`ClaimedMessage::inline`]) — `ack`
    /// skips the object-store delete + adjusts the inline byte budget when set.
    inline: bool,
    /// Delivery attempts ([`ClaimedMessage::attempts`]) — preserved across a nack.
    attempts: u32,
    /// Base64 (standard) of the payload, so the reconstructed message's `payload.len()` (the
    /// only field `ack` reads from the payload — the inline budget) is exact.
    payload_b64: String,
    /// The host-sealed signed-context envelope, if any ([`ClaimedMessage::signed_context`]).
    signed_context: Option<String>,
}

impl AckHandle {
    /// Encode a claimed message (keyed on the consumer's BARE `topic`) into its opaque wire
    /// handle.
    fn encode(bare_topic: &str, msg: &ClaimedMessage) -> String {
        let h = Self {
            id: msg.id.clone(),
            topic: bare_topic.to_string(),
            group: msg.group.clone(),
            inline: msg.inline,
            attempts: msg.attempts,
            payload_b64: base64::engine::general_purpose::STANDARD.encode(&msg.payload),
            signed_context: msg.signed_context.clone(),
        };
        let json = serde_json::to_vec(&h).expect("AckHandle serializes");
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    }

    /// Decode an opaque wire handle, or `None` when it is malformed (→ 400, never a panic).
    fn decode(handle: &str) -> Option<Self> {
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(handle)
            .ok()?;
        serde_json::from_slice(&json).ok()
    }

    /// Reconstruct the [`ClaimedMessage`] the trait acks/nacks, given the FULL namespaced topic
    /// key (recomposed from the re-authorized scope). The payload is decoded back to bytes so
    /// `ack`'s inline accounting is exact.
    fn into_message(self, full_key: String) -> ClaimedMessage {
        ClaimedMessage {
            id: self.id,
            topic: full_key,
            payload: base64::engine::general_purpose::STANDARD
                .decode(&self.payload_b64)
                .unwrap_or_default(),
            attempts: self.attempts,
            group: self.group,
            signed_context: self.signed_context,
            inline: self.inline,
        }
    }
}

/// `POST /claim/{*topic}`: authenticate + authorize the topic (the SAME scope gate publish uses
/// — cross-topic refused, traversal screened), then lease up to `?max` messages for `?lease_ms`
/// off `{project}/bus/<topic>` via [`Messaging::claim`] and return each payload + an ack handle.
async fn claim(
    State(shim): State<MessagingShim>,
    headers: HeaderMap,
    Path(topic): Path<String>,
    Query(params): Query<ClaimParams>,
) -> Response {
    let token = bearer(&headers);
    let scope = shim.authenticate(token.as_deref()).await;
    let (messaging, key) = match authorize(scope.as_ref(), &topic) {
        Ok(v) => v,
        Err(denied) => return denied.into_response(),
    };
    let max = params
        .max
        .unwrap_or(DEFAULT_CLAIM_MAX)
        .clamp(1, MAX_CLAIM_MAX);
    let lease = std::time::Duration::from_millis(params.lease_ms.unwrap_or(DEFAULT_LEASE_MS));
    let max_attempts = params.max_attempts.unwrap_or(DEFAULT_MAX_ATTEMPTS);

    match messaging.claim(&key, lease, max, max_attempts).await {
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
            tracing::warn!(key, error = %err, "compute messaging-shim claim fault");
            (StatusCode::BAD_GATEWAY, "messaging backend unavailable\n").into_response()
        }
    }
}

/// `POST /ack` body: the opaque handle from a prior claim.
#[derive(Debug, Deserialize)]
struct AckBody {
    handle: String,
}

/// `POST /nack` body: the handle, plus an optional redelivery backoff (ms) → [`Messaging::nack_after`].
#[derive(Debug, Deserialize)]
struct NackBody {
    handle: String,
    #[serde(default)]
    delay_ms: Option<u64>,
}

/// Decode the handle and RE-AUTHORIZE its bare topic against the presented bearer's scope — so
/// ack/nack enforce the IDENTICAL scope as publish/claim (a tampered or cross-topic handle is
/// refused), then recompose the full `{project}/bus/<topic>` key and reconstruct the message.
/// Returns the substrate + the reconstructed [`ClaimedMessage`], or a response (401/403/400).
async fn resolve_ack(
    shim: &MessagingShim,
    headers: &HeaderMap,
    handle: &str,
) -> Result<(Arc<dyn Messaging>, ClaimedMessage), Response> {
    let token = bearer(headers);
    let scope = shim.authenticate(token.as_deref()).await;
    let Some(decoded) = AckHandle::decode(handle) else {
        return Err((StatusCode::BAD_REQUEST, "malformed ack handle\n").into_response());
    };
    // The SAME enforced decision publish/claim run — the handle's bare topic must be within the
    // token's scope (cross-topic refused, traversal screened). The full key comes ONLY from the
    // scope's bus prefix, never the handle, so a tampered handle cannot reach another project.
    let (messaging, full_key) = authorize(scope.as_ref(), &decoded.topic)
        .map_err(axum::response::IntoResponse::into_response)?;
    Ok((messaging, decoded.into_message(full_key)))
}

/// `POST /ack`: delete a claimed message for good ([`Messaging::ack`]).
async fn ack(
    State(shim): State<MessagingShim>,
    headers: HeaderMap,
    Json(body): Json<AckBody>,
) -> Response {
    let (messaging, msg) = match resolve_ack(&shim, &headers, &body.handle).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    match messaging.ack(&msg).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            tracing::warn!(topic = %msg.topic, id = %msg.id, error = %err, "compute messaging-shim ack fault");
            (StatusCode::BAD_GATEWAY, "messaging backend unavailable\n").into_response()
        }
    }
}

/// `POST /nack`: redeliver a claimed message — immediately ([`Messaging::nack`]) or after a
/// `delay_ms` backoff ([`Messaging::nack_after`]). The attempt count is preserved, so it still
/// dead-letters after `max_attempts`.
async fn nack(
    State(shim): State<MessagingShim>,
    headers: HeaderMap,
    Json(body): Json<NackBody>,
) -> Response {
    let (messaging, msg) = match resolve_ack(&shim, &headers, &body.handle).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let result = match body.delay_ms {
        Some(delay) if delay > 0 => messaging.nack_after(&msg, delay).await,
        _ => messaging.nack(&msg).await,
    };
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            tracing::warn!(topic = %msg.topic, id = %msg.id, error = %err, "compute messaging-shim nack fault");
            (StatusCode::BAD_GATEWAY, "messaging backend unavailable\n").into_response()
        }
    }
}

/// The active compute-messaging-shim gate mutation (PLAN-compute-bindings anti-hollow gate),
/// or `None`. Present ONLY under `cfg(test)` (the in-crate gate) or the
/// `compute-messaging-shim-gate-mutation` feature; a shipped build has neither, so
/// [`authorize`] / [`MessagingShim::authenticate`] evaluate every check unconditionally and
/// this is a dead `None`. Each recognized value neuters ONE check so the CI gate can prove it
/// goes RED: `allow_cross_topic` (bypass the topic bind), `allow_traversal` (skip the topic
/// screen), `admit_unmatched` (admit a missing/unknown token). NOT a backdoor — it only reads
/// a test env var.
#[cfg(any(test, feature = "compute-messaging-shim-gate-mutation"))]
fn messaging_mutation() -> Option<String> {
    std::env::var("BOATRAMP_COMPUTEMESSAGING_MUTATION").ok()
}
#[cfg(not(any(test, feature = "compute-messaging-shim-gate-mutation")))]
#[inline]
fn messaging_mutation() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::messaging::{ClaimedMessage, LogMessaging, Messaging, MessagingError};
    use boatramp_core::{
        ByteStream, GetObject, ListPage, ObjectMeta, PutMeta, Storage, StorageError,
    };
    use bytes::Bytes as RawBytes;
    use futures::StreamExt as _;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::time::Duration;
    use tower::ServiceExt as _;

    /// A minimal in-memory [`Storage`] so the REAL [`LogMessaging`] substrate can be built for
    /// the round-trip proof (it persists message payloads as objects). Mirrors the blob-shim
    /// test's `MemStorage`.
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

    /// One recorded publish: `(topic, payload, signed_context)`.
    type Recorded = (String, Vec<u8>, Option<String>);

    /// A [`Messaging`] that records every `(topic, payload, signed_context)` it is asked to
    /// publish — enough to assert the wire → bus-key mapping + the unscoped-producer context
    /// without a durable substrate.
    #[derive(Default)]
    struct RecordingMessaging {
        published: Mutex<Vec<Recorded>>,
    }

    #[async_trait::async_trait]
    impl Messaging for RecordingMessaging {
        async fn publish(&self, topic: &str, payload: &[u8]) -> Result<(), MessagingError> {
            self.publish_ctx(topic, payload, None).await
        }
        async fn publish_ctx(
            &self,
            topic: &str,
            payload: &[u8],
            signed_context: Option<&str>,
        ) -> Result<(), MessagingError> {
            self.published.lock().unwrap().push((
                topic.to_string(),
                payload.to_vec(),
                signed_context.map(str::to_owned),
            ));
            Ok(())
        }
        async fn claim(
            &self,
            _: &str,
            _: Duration,
            _: usize,
            _: u32,
        ) -> Result<Vec<ClaimedMessage>, MessagingError> {
            Ok(Vec::new())
        }
        async fn ack(&self, _: &ClaimedMessage) -> Result<(), MessagingError> {
            Ok(())
        }
        async fn nack(&self, _: &ClaimedMessage) -> Result<(), MessagingError> {
            Ok(())
        }
    }

    /// Drive one request through the real router (the enforced HTTP path). The
    /// `content-type: application/json` header is set unconditionally — harmless for the
    /// `publish`/`claim` handlers (which read `Bytes` / no body) and required by the `ack`/`nack`
    /// `Json` extractors.
    async fn request(
        shim: &MessagingShim,
        path: &str,
        token: Option<&str>,
        body: &[u8],
    ) -> (StatusCode, Vec<u8>) {
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json");
        if let Some(t) = token {
            builder = builder.header("authorization", format!("Bearer {t}"));
        }
        let req = builder.body(Body::from(body.to_vec())).unwrap();
        let resp = shim.router().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec();
        (status, bytes)
    }

    /// Claim through the shim's real `POST /claim/{topic}` and decode the DTOs to
    /// `(payload, handle, attempts)` — the consumer's view.
    async fn claim_via_shim(
        shim: &MessagingShim,
        topic_and_query: &str,
        token: &str,
    ) -> (StatusCode, Vec<(Vec<u8>, String, u32)>) {
        let (status, body) =
            request(shim, &format!("/claim/{topic_and_query}"), Some(token), b"").await;
        if status != StatusCode::OK {
            return (status, Vec::new());
        }
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        let msgs = v["messages"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|m| {
                        let payload = base64::engine::general_purpose::STANDARD
                            .decode(m["payload_b64"].as_str().unwrap())
                            .unwrap();
                        let handle = m["handle"].as_str().unwrap().to_string();
                        let attempts = m["attempts"].as_u64().unwrap() as u32;
                        (payload, handle, attempts)
                    })
                    .collect()
            })
            .unwrap_or_default();
        (status, msgs)
    }

    /// Ack (or, with `delay_ms`, nack) a handle through the shim's real `POST /ack` / `/nack`.
    async fn ack_via_shim(shim: &MessagingShim, token: &str, handle: &str) -> StatusCode {
        let body = serde_json::json!({ "handle": handle });
        request(shim, "/ack", Some(token), body.to_string().as_bytes())
            .await
            .0
    }
    async fn nack_via_shim(shim: &MessagingShim, token: &str, handle: &str) -> StatusCode {
        let body = serde_json::json!({ "handle": handle });
        request(shim, "/nack", Some(token), body.to_string().as_bytes())
            .await
            .0
    }

    fn resolver(shim: &MessagingShim, messaging: Arc<dyn Messaging>) -> MessagingShimResolver {
        MessagingShimResolver::new(
            messaging,
            shim.clone(),
            "http://10.0.0.1:8083".to_string(),
            [9u8; 32],
        )
    }

    fn messaging_binding(name: &str) -> ComputeBinding {
        ComputeBinding {
            kind: BindingKind::Messaging,
            name: name.to_string(),
            url_env: None,
        }
    }

    fn token_of(env: &[(String, String)]) -> String {
        env.iter()
            .find(|(k, _)| k == "BOATRAMP_MESSAGING_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .expect("token env injected")
    }

    #[tokio::test]
    async fn resolver_injects_url_and_token_and_release_revokes() {
        let shim = MessagingShim::new();
        let backend = Arc::new(RecordingMessaging::default());
        let resolver = resolver(&shim, backend.clone());
        let bindings = vec![messaging_binding("deliver")];

        let env = resolver.resolve("default", "mx", 0, &bindings).await;
        let get = |k: &str| env.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        assert_eq!(
            get("BOATRAMP_MESSAGING_URL").as_deref(),
            Some("http://10.0.0.1:8083")
        );
        let token = token_of(&env);

        // Deterministic: resolving again mints the identical env (recomputable without persistence).
        assert_eq!(resolver.resolve("default", "mx", 0, &bindings).await, env);

        // The token now authorizes a publish to its bound topic …
        let (status, _) = request(&shim, "/publish/deliver", Some(&token), b"job").await;
        assert_eq!(status, StatusCode::OK);
        // … and release revokes it.
        resolver.release("default", "mx", 0, &bindings).await;
        let (status, _) = request(&shim, "/publish/deliver", Some(&token), b"job").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn named_project_qualifies_the_bus_prefix() {
        // A non-default project qualifies the bus: `acme/bus/<topic>`.
        let shim = MessagingShim::new();
        let backend = Arc::new(RecordingMessaging::default());
        let resolver = resolver(&shim, backend.clone());
        // Bare `--bind messaging` (bus-wide).
        let env = resolver
            .resolve("acme", "mx", 0, &[messaging_binding("")])
            .await;
        let token = token_of(&env);
        let (status, _) = request(&shim, "/publish/orders/created", Some(&token), b"evt").await;
        assert_eq!(status, StatusCode::OK);
        let published = backend.published.lock().unwrap();
        assert_eq!(
            published[0].0, "acme/bus/orders/created",
            "a named project publishes under {{project}}/bus/<topic>"
        );
        // An unscoped (native) producer stamps no signed context.
        assert_eq!(published[0].2, None);
    }

    #[tokio::test]
    async fn delivery_mode_query_param_routes_to_the_matching_verb() {
        // `?delay_ms=` routes to publish_delayed_ctx (the recording backend folds all publish_*
        // to one record via the trait defaults, so this proves the HTTP param is accepted + the
        // publish still lands on the right key).
        let shim = MessagingShim::new();
        let backend = Arc::new(RecordingMessaging::default());
        let resolver = resolver(&shim, backend.clone());
        let env = resolver
            .resolve("default", "mx", 0, &[messaging_binding("")])
            .await;
        let token = token_of(&env);
        let (status, _) = request(
            &shim,
            "/publish/deliver?delay_ms=60000",
            Some(&token),
            b"later",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            backend.published.lock().unwrap()[0].0,
            "default/bus/deliver"
        );
    }

    /// **CI mutation gate** (PLAN-compute-bindings anti-hollow, marker `COMPUTE MESSAGING-SHIM
    /// SCOPED OK`). Drives the ENFORCED [`authorize`] / [`MessagingShim::authenticate`] decision
    /// across the three security dimensions + proves the SHARED-BUS property by publishing through
    /// the shim into the REAL [`LogMessaging`] substrate and CLAIMING the message back off the exact
    /// `{project}/bus/<topic>` key a `wasi:messaging` consumer subscribes — a genuine round-trip,
    /// not a tautology. Prints the marker so the merge gate can assert it RAN. MUTATION-VERIFIED:
    /// the SAME test re-run under each `BOATRAMP_COMPUTEMESSAGING_MUTATION` neuters ONE check and
    /// MUST FAIL — `allow_cross_topic` (a token scoped to one topic reaches a different topic),
    /// `allow_traversal` (a `../` topic escapes the bus prefix), `admit_unmatched` (an
    /// unauthenticated/mismatched token is admitted).
    #[tokio::test]
    async fn compute_messaging_shim_scoped_gate() {
        let shim = MessagingShim::new();
        // The REAL project-bus substrate (durable at-least-once), so claiming back proves the
        // message is genuinely enqueued on the bus key a consumer drains.
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let messaging: Arc<dyn Messaging> = Arc::new(LogMessaging::new(storage, kv));
        let resolver = resolver(&shim, messaging.clone());

        // Topic-bound to `deliver` (`--bind messaging:deliver`); project default, so the bus
        // prefix is the two-segment `default/bus/` (v0.31.0 Finding 8).
        let env = resolver
            .resolve("default", "mx", 0, &[messaging_binding("deliver")])
            .await;
        let token = token_of(&env);
        let scope = shim
            .authenticate(Some(&token))
            .await
            .expect("scope registered");

        // A bus-wide (bare `--bind messaging`) scope, for the traversal checks below — a
        // topic-bound scope would trip the cross-topic check before the traversal screen ever
        // runs, so the screen needs a scope with no bound topic to reach it at all.
        let wide_env = resolver
            .resolve("default", "mx", 1, &[messaging_binding("")])
            .await;
        let wide_token = token_of(&wide_env);
        let wide_scope = shim
            .authenticate(Some(&wide_token))
            .await
            .expect("bus-wide scope registered");

        // ---- (iv) consume-side scope FIRST: a CLAIM and an ACK must enforce the SAME gate as
        // publish, through the REAL router (not a direct `authorize()`/`authenticate()` call) —
        // placed ahead of (i)-(iii) so that under EACH mutation value, the FIRST assertion the
        // test trips is a consume-path (claim/ack) one: the mutation loop's per-mutation failure
        // is thereby a direct demonstration that CLAIM/ACK — not just publish — go RED, rather
        // than an inference from a shared-function argument. ----------------------------------
        //
        // Cross-topic CLAIM: the `deliver`-bound token claiming a DIFFERENT topic is 403 (under
        // `allow_cross_topic` it would be admitted → 200 → this assert fails → gate RED).
        let (status, _) = claim_via_shim(&shim, "forbidden", &token).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a topic-bound token must be refused a CLAIM on a different topic"
        );
        // Cross-topic ACK: a handle minted for a topic OUTSIDE the token's scope is 403 at `/ack`
        // (same mutation sensitivity — the consume endpoints re-run `authorize`).
        let forged = AckHandle::encode(
            "forbidden",
            &ClaimedMessage {
                id: "x".into(),
                topic: "default/bus/forbidden".into(),
                payload: b"x".to_vec(),
                attempts: 1,
                group: String::new(),
                signed_context: None,
                inline: true,
            },
        );
        assert_eq!(
            ack_via_shim(&shim, &token, &forged).await,
            StatusCode::FORBIDDEN,
            "an ACK whose handle names a topic outside the token's scope must be refused"
        );
        // Traversal CLAIM: a bus-wide token claiming a `../` topic is 400 at `/claim` (under
        // `allow_traversal` the screen is skipped → 200 → this assert fails → gate RED).
        let (status, _) = claim_via_shim(&shim, "../escape", &wide_token).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a CLAIM on a traversal topic must be refused"
        );
        // Traversal ACK: a bus-wide token's handle naming a `../` topic is 400 at `/ack` (under
        // `allow_traversal` the screen is skipped → 204 → this assert fails → gate RED).
        let traversal = AckHandle::encode(
            "../escape",
            &ClaimedMessage {
                id: "y".into(),
                topic: "default/bus/../escape".into(),
                payload: b"y".to_vec(),
                attempts: 1,
                group: String::new(),
                signed_context: None,
                inline: true,
            },
        );
        assert_eq!(
            ack_via_shim(&shim, &wide_token, &traversal).await,
            StatusCode::BAD_REQUEST,
            "an ACK whose handle names a traversal topic must be refused"
        );
        // Unauthenticated/mismatched CLAIM: a missing or unknown bearer is 401 at `/claim` (under
        // `admit_unmatched` it would be admitted to SOME registered scope → 200 → this assert
        // fails → gate RED).
        let (status, _) = claim_via_shim(&shim, "deliver", "not-a-real-token").await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a CLAIM with an unknown/mismatched bearer token must not authenticate"
        );

        // ---- (i) cross-topic / cross-project confinement (direct `authorize()`, same decision
        // the publish handler calls) -----------------------------------------------------------
        // The token is bound to `deliver`; a different topic is refused …
        assert!(
            matches!(authorize(Some(&scope), "other"), Err(Denied::CrossTopic)),
            "a topic-bound token must refuse a DIFFERENT topic"
        );
        // … while its own topic composes the EXACT bus key, and the composed key ALWAYS begins
        // with the token's own (never client-named) bus prefix — so cross-PROJECT is impossible.
        let (_, key) = authorize(Some(&scope), "deliver").expect("own topic admitted");
        assert_eq!(key, "default/bus/deliver");
        assert!(key.starts_with(&scope.bus_prefix));

        // ---- (ii) path-traversal confinement (direct `authorize()`) -------------------------
        // The topic is the single addressable dimension, so the traversal screen is exercised on
        // the BUS-WIDE (bare `--bind messaging`) scope from above — a topic-bound scope would
        // trip the cross-topic check (i) before the screen. A bus-wide token still cannot escape
        // its `{project}/bus/` prefix: every topic is screened.
        for bad in ["../escape", "a/../../b", "/abs", ".boatramp-reserved"] {
            assert!(
                matches!(authorize(Some(&wide_scope), bad), Err(Denied::BadTopic(_))),
                "a traversal/reserved topic must be refused: {bad:?}"
            );
        }

        // ---- (iii) authentication (direct `authenticate()`) ----------------------------------
        assert!(
            shim.authenticate(None).await.is_none(),
            "a missing bearer token must not authenticate"
        );
        assert!(
            shim.authenticate(Some("not-a-real-token")).await.is_none(),
            "an unknown/mismatched bearer token must not authenticate"
        );

        // ---- SHARED-BUS positive round-trip, END TO END THROUGH THE SHIM ---------------
        // Publish → claim → ack → (second claim is empty); then publish → claim → nack →
        // (re-claim redelivers). Every hop goes through the real router, so tested == enforced,
        // and the REAL `LogMessaging` substrate proves the message is genuinely on the bus a
        // `wasi:messaging` consumer drains — not a tautology.
        let (status, _) = request(&shim, "/publish/deliver", Some(&token), b"DeliverJob-1").await;
        assert_eq!(status, StatusCode::OK);

        // Lease 0 ⇒ the message is immediately re-claimable, so the post-ack emptiness below is
        // explained ONLY by the ack having DELETED it (a no-op ack would leave a lease-0 message
        // re-claimable, failing the assert — the check is load-bearing, not a leased-hidden tautology).
        let (status, claimed) = claim_via_shim(&shim, "deliver?max=10&lease_ms=0", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            claimed.len(),
            1,
            "the shim-published message is claimable through the shim"
        );
        assert_eq!(
            claimed[0].0, b"DeliverJob-1",
            "claim returns the published payload"
        );
        assert_eq!(claimed[0].2, 1, "first delivery is attempt 1");

        // ACK it → a second claim sees NOTHING (acked, deleted for good — not redelivered).
        assert_eq!(
            ack_via_shim(&shim, &token, &claimed[0].1).await,
            StatusCode::NO_CONTENT
        );
        let (status, after_ack) = claim_via_shim(&shim, "deliver?lease_ms=0", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            after_ack.is_empty(),
            "an ACKed message must NOT be redelivered on a subsequent claim"
        );

        // NACK path: publish → claim → nack → re-claim REDELIVERS it (attempt charged again).
        let (status, _) = request(&shim, "/publish/deliver", Some(&token), b"DeliverJob-2").await;
        assert_eq!(status, StatusCode::OK);
        let (_, claimed2) = claim_via_shim(&shim, "deliver?lease_ms=30000", &token).await;
        assert_eq!(claimed2.len(), 1);
        assert_eq!(claimed2[0].0, b"DeliverJob-2");
        assert_eq!(
            nack_via_shim(&shim, &token, &claimed2[0].1).await,
            StatusCode::NO_CONTENT
        );
        let (_, redelivered) = claim_via_shim(&shim, "deliver?lease_ms=30000", &token).await;
        assert_eq!(
            redelivered.len(),
            1,
            "a NACKed message MUST be redelivered on a subsequent claim"
        );
        assert_eq!(redelivered[0].0, b"DeliverJob-2");
        assert_eq!(redelivered[0].2, 2, "redelivery charges a second attempt");

        println!("COMPUTE MESSAGING-SHIM SCOPED OK");
    }

    /// Security HIGH: the shim binds the HOST the `messaging_shim_url` names (bridge-gateway IP /
    /// loopback), NEVER widening to all interfaces on its own. (The bind helper is shared with the
    /// blob/sql shims — re-asserted here so the messaging shim's own posture is covered.)
    #[test]
    fn bind_addr_honors_configured_host_never_all_interfaces() {
        let a = crate::shim_bind_addr("http://127.0.0.1:8083/").expect("ip:port");
        assert_eq!(a.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
        assert_eq!(a.port(), 8083);
        assert!(!a.ip().is_unspecified(), "must not widen to all interfaces");
        assert!(crate::shim_bind_addr("http://").is_none());
    }
}
