//! The **external run front door** (PLAN-run-streaming P2): the authenticated control-plane HTTP
//! surface that lets a NON-GUEST client (an MCP app, a third-party GraphQL client — anything that is
//! not a wasm guest) START a run, ATTACH to its event stream (resumably), and CANCEL it. It is a thin
//! transport onto the transport-agnostic [`RunEngine`](crate::run_stream::RunEngine) P1 built — it adds
//! NO new durability or scope primitive, and reuses the SAME SSE/WS/permit machinery the project-bus
//! consumer surface ([`crate::bus_consumer`]) rides.
//!
//! # The three doors
//! - `POST /api/projects/{project}/runs` — **START.** Authorized by the caller's control-plane
//!   principal via the normal RBAC gate (`Project·Deploy` on the project — the invoke right, exactly
//!   like `/api/functions/{name}/invoke`), plus a host-resolved tenant (`run_grant_scope`, fail-closed
//!   under a multi-tenant posture — identical to P1's guest fence). It creates the run in the caller's
//!   tenant, dispatches a start-message (tagged with the `run_id`) to the target's bus topic (the
//!   existing publish seam — the target emits to the run via P1's `run.emit`), and returns
//!   `{ run_id, attach_token }`.
//! - `GET /api/projects/{project}/runs/{run_id}/events` — **ATTACH.** SSE (default) / WebSocket (on
//!   `Upgrade`) / long-poll (`?wait_ms=`), resumable by `?after_seq=` or `Last-Event-ID`. Authenticated
//!   by the RUN-SCOPED capability token (below), NOT a project RBAC right.
//! - `POST /api/projects/{project}/runs/{run_id}/cancel` — **CANCEL.** Same run-scoped-token auth;
//!   drives [`RunEngine::cancel`] (the terminal `cancelled`).
//!
//! # The run-scoped capability token (ATTACH/CANCEL auth)
//! START mints a [`boatramp_core::cose::KIND_RUN_CAP`] token (`mint_run_cap`) scoped to EXACTLY one
//! `{run_id, tenant-scope, rights ⊆ {attach, cancel}}`, fleet-signed, audience-bound to the project,
//! TTL-bound. It reuses boatramp's one COSE/CWT capability-token machinery — no new token format. An
//! external client presents it as `Authorization: Bearer <attach_token>`; ATTACH/CANCEL verify it
//! FAIL-CLOSED (fleet-signed against the trust root, not expired, audience == this project,
//! `br_kind == "run-cap"`, the carried `run_id` equals the path, the carried scope grants the needed
//! right), then build the run engine from the token's VERIFIED tenant scope — so a token for run A can
//! never attach run B, and a token minted under tenant X's scope composes X's key and so can never
//! reach tenant Y's run. These two routes are therefore UNGATED at the RBAC layer (they carry no
//! project right), exactly like the single-use `/api/cluster/join` / `/api/overlay/enroll` tokens —
//! see [`boatramp_core::authz::Right::required_for`].
//!
//! # Posture gate
//! The whole surface is behind the OFF-by-default node posture `allow_guest_run_streaming` (the SAME
//! gate as P1's guest door) AND the `run-streaming` cargo feature. With the posture off every door
//! returns `403` — zero runtime exposure. Minting the run-scoped token requires an ISSUING node (one
//! with a fleet signer); a non-issuing node returns `501` at START.
//!
//! # Security notes (P2 Security-review LOW/INFO items)
//!
//! **LOW-1 — the run-cap is a plain bearer, NOT channel-bound.** ATTACH/CANCEL verify only the
//! fleet SIGNATURE of the run-scoped token (`verify_run_cap`); they do NOT run the control-plane
//! middleware's proof-of-possession / `require_channel_bound_tokens` path (these two routes are
//! RBAC-ungated and self-verify the bearer). So a LEAKED `attach_token` grants attach + cancel on
//! that ONE run to anyone who holds it. **Blast radius is deliberately tight:** exactly one run
//! (`run_id` in the signed scope, matched to the path), under one tenant (the signed `scope` — never
//! cross-tenant), redeemable only at one project (the `aud`), for at most the mandatory TTL
//! ([`RUN_CAP_TTL_SECS`] = 3600s), and it can never be redeemed as any other token kind (the exact
//! `br_kind` check). It is never broad creds. **No revocation within the TTL** (INFO-3): a leaked
//! token is valid until it expires — bounded by the short TTL AND by the run itself being reclaimed
//! by the TTL/idle sweep (after which the token resolves to `NotFound`).
//!
//! *Assessment — cnf-binding the run-cap is a LARGER change, DEFERRED as an enable-time follow-up (we
//! did NOT implement it here, and we did NOT flip any posture):* binding the run-cap to the START
//! caller's holder key (a `cnf` claim + a per-request PoP, so a leaked token is useless without the
//! holder's private key) would require (a) plumbing the START caller's verified terminal holder key
//! out of `require_auth` into the mint, (b) stamping a `cnf` claim onto the run-cap, and (c) building
//! a PoP challenge/response verification ON these two RBAC-ungated routes (they today run NONE of the
//! middleware's PoP machinery), plus deciding its interaction with `require_channel_bound_tokens`.
//! That also changes the EXTERNAL-client contract — the whole point of the run-cap (D3) is a
//! run-scoped bearer for non-guest clients (MCP apps, third-party GraphQL) that we do not control and
//! that commonly present a plain HTTP bearer, not a DPoP-style PoP. So it is a design + Security-review
//! item to pin with the requester at enable time, not a clean drop-in here. The present mitigation is
//! the tight blast radius above (one run · short mandatory TTL · never cross-run/tenant/project) plus
//! the sweep that bounds the window a leaked token can reach anything.
//!
//! **INFO-2 — ghost-tenant START.** START authorizes the project invoke right + a host-resolved
//! tenant, but does not pre-verify the target agent EXISTS; a START for a non-existent target creates
//! an (orphan) run and publishes a start-message nobody consumes. This matches the project-bus
//! precedent (a publish to a topic with no consumer is accepted) and is RBAC-gated (only a principal
//! with the project invoke right can do it) — hygiene, not a breach.
//!
//! **INFO-4 — the orphan run from a non-existent target self-heals.** Such a run stays `Active` with
//! no emit and no attacher, so the IDLE/ABANDONED arm of the TTL sweep (see
//! [`crate::run_stream::sweep_runs`]) cancels + reclaims it after the idle TTL — no permanent leak.

#![cfg(feature = "run-streaming")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::*;

use base64::Engine as _;
use boatramp_core::cose::{RunCap, RunRight, mint_run_cap, verify_run_cap};
use boatramp_core::messaging::Messaging;
use boatramp_core::project::validate_object_key;
use boatramp_core::run::{RunEnvelope, RunError, RunEventKind, run_grant_scope};
use futures::StreamExt;
use futures::stream::BoxStream;

use crate::operator::{bus_namespace, messaging_or_unavailable};
use crate::project_scope::ProjectContext;
use crate::run_stream::{EngineAttach, RunEngine};

/// The run-scoped capability token's TTL (seconds). An attach token is good for one run's stream for
/// at most this long; a watcher that needs longer re-STARTs (or, later, refreshes). An hour comfortably
/// covers a long agent run + reconnects while keeping an offline-verified, un-revocable capability
/// short-lived. (The terminal/idle-run TTL sweep that must also be in before the posture is enabled is
/// a SEPARATE, deferred enable-precondition — see the PLAN.)
const RUN_CAP_TTL_SECS: u64 = 3600;

/// Upper bound on a long-poll `?wait_ms`: an attach long-poll hangs for AT MOST this long before
/// returning the envelopes it has (possibly none), so a client can never pin a connection forever.
const MAX_POLL_WAIT_MS: u64 = 60_000;

/// Max envelopes a single long-poll returns before yielding back to the client (bounded response).
const MAX_POLL_BATCH: usize = 256;

// ---- shared helpers --------------------------------------------------------------------------

/// The stable wire term for a run event kind (the SSE `event:` name + the DTO `kind`).
fn kind_str(kind: RunEventKind) -> &'static str {
    match kind {
        RunEventKind::Progress => "progress",
        RunEventKind::Result => "result",
        RunEventKind::Error => "error",
        RunEventKind::End => "end",
        RunEventKind::Cancelled => "cancelled",
    }
}

/// One run envelope framed for the external wire: the opaque guest payload rides base64 so it can
/// never break SSE framing or JSON, and `seq` is the resume cursor (the SSE `id:`).
#[derive(Serialize)]
struct RunEnvelopeDto {
    run_id: String,
    seq: u64,
    kind: &'static str,
    timestamp_ms: u64,
    /// Base64 (standard) of the opaque event payload.
    payload_b64: String,
}

impl RunEnvelopeDto {
    fn from_envelope(env: &RunEnvelope) -> Self {
        Self {
            run_id: env.run_id.clone(),
            seq: env.seq,
            kind: kind_str(env.kind),
            timestamp_ms: env.timestamp_ms,
            payload_b64: base64::engine::general_purpose::STANDARD.encode(&env.payload),
        }
    }
}

/// Map a host-internal [`RunError`] onto its fail-closed HTTP response. A non-existent run (the
/// cross-tenant / fabricated-id case, which surfaces as `NotFound` because the key does not exist
/// under the token's scope) is a flat `404` — never a cross-tenant touch, and no existence oracle
/// beyond what the already-authenticated token-holder could learn about its own run.
fn run_err_response(e: &RunError) -> Response {
    match e {
        RunError::NotFound => (StatusCode::NOT_FOUND, "run not found\n").into_response(),
        RunError::Invalid(m) => (
            StatusCode::BAD_REQUEST,
            format!("invalid run request: {m}\n"),
        )
            .into_response(),
        RunError::Terminal | RunError::Cancelled => {
            // A race against a concurrent terminal — the run already concluded; treat as success-ish
            // for cancel (idempotent) is handled by the engine, so reaching here is a genuine conflict.
            (StatusCode::CONFLICT, "run already concluded\n").into_response()
        }
        RunError::Backend(_) => {
            (StatusCode::BAD_GATEWAY, "run backend unavailable\n").into_response()
        }
    }
}

/// A flat `403` for every run-token auth failure (invalid / expired / wrong-project / wrong-run /
/// missing-right), deliberately NON-enumerable so the token surface is not an oracle.
fn run_token_forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        "run token invalid, expired, or not authorized for this run\n",
    )
        .into_response()
}

/// Extract the `Authorization: Bearer <token>` value, trimmed.
fn bearer_of(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// Posture gate: `403` when the node posture has `allow_guest_run_streaming` off (the default), so the
/// whole external surface has zero runtime exposure until an operator opts in (and the deferred
/// TTL-sweep enable-precondition is also in — never flip the posture before then).
fn posture_gate(posture: &boatramp_core::security::SecurityPosture) -> Option<Response> {
    if posture.allow_guest_run_streaming {
        None
    } else {
        Some(
            (
                StatusCode::FORBIDDEN,
                "run streaming is not enabled on this node (allow_guest_run_streaming is off)\n",
            )
                .into_response(),
        )
    }
}

/// Build a run engine fenced to `(project, scope)` over the node's durable messaging + control-plane
/// KV — the SAME construction `build_bindings` uses for the guest door, so the external door addresses
/// the IDENTICAL run keyspace (the bare project name, a sibling of `{project}/bus/…`).
fn engine_for(
    messaging: Arc<dyn Messaging>,
    inner: &HandlerRuntimeInner,
    project: &ProjectContext,
    scope: String,
) -> RunEngine {
    RunEngine::new(messaging, inner.kv.clone(), project.0.clone(), scope)
}

/// Verify the presented run-scoped token for `project` + `run_id`, requiring `need`. Returns the
/// verified [`RunCap`] (whose `scope` carries the tenancy fence to build the engine with), or a
/// fail-closed `403`/`501`. Shared by ATTACH and CANCEL.
fn authorize_run_token(
    headers: &HeaderMap,
    auth: &Auth,
    project: &ProjectContext,
    run_id: &str,
    need: RunRight,
) -> Result<RunCap, Response> {
    let Some(bearer) = bearer_of(headers) else {
        return Err((StatusCode::UNAUTHORIZED, "missing bearer token\n").into_response());
    };
    // The fleet trust root. A node with no root key cannot verify a run token — fail closed (501),
    // never fall open.
    let Some(public) = auth.public_key() else {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "this node has no trust root and cannot verify run tokens\n",
        )
            .into_response());
    };
    let now = boatramp_core::time::now_unix();
    // Fleet-signed, not expired, audience == this project, `br_kind == run-cap`, scope well-formed.
    let cap =
        verify_run_cap(&bearer, &public, now, &project.0).map_err(|_| run_token_forbidden())?;
    // Bound to EXACTLY this run: a token for run A can never be presented on run B's path.
    if cap.scope.run_id != run_id {
        return Err(run_token_forbidden());
    }
    // Carries the needed right (attach ≠ cancel): a token minted attach-only cannot cancel, etc.
    if !cap.scope.allows(need) {
        return Err(run_token_forbidden());
    }
    Ok(cap)
}

// ---- (1) START -------------------------------------------------------------------------------

/// `POST /api/projects/{project}/runs` body: the target handler/agent to invoke + its opaque input.
#[derive(Deserialize)]
pub(crate) struct RunStartBody {
    /// The target agent's **bus topic path** — the start is published to the target's
    /// `{project}/bus/<target>` topic, where a long-lived bus-consumer agent subscribes and emits to
    /// the run. INFO-1: this is a bus TOPIC PATH, not a single resource-name segment — a legitimate
    /// `bus:` topic is dotted/slashed (`concept.generate`, `orders/created`), so it is screened with
    /// [`validate_object_key`] (rejects traversal `..`, control bytes, `*`, and the reserved
    /// `.boatramp*` namespace — so a target can never escape the project bus or reach the sibling
    /// `{project}/.boatramp-run/…` run keyspace) rather than the strict single-segment
    /// `validate_resource_name` (which would wrongly reject those real bus topics). The confinement to
    /// `{project}/bus/<target>` is what keeps the target in-bounds; the screen is the traversal
    /// backstop.
    target: String,
    /// The opaque input handed to the target (carried verbatim in the start-message). Defaults to
    /// JSON `null` when omitted.
    #[serde(default)]
    input: serde_json::Value,
}

/// `POST /api/projects/{project}/runs` response: the created run id + the run-scoped attach token an
/// external client presents to ATTACH/CANCEL, with its absolute expiry (Unix seconds).
#[derive(Serialize)]
struct RunStartResponse {
    run_id: String,
    attach_token: String,
    expires_at: u64,
}

/// START a run (PLAN-run-streaming P2). Authorization (`Project·Deploy` — invoke rights on the target)
/// is enforced by `require_auth` BEFORE this handler (the project-scoped `runs` arm of
/// `Right::required_for`). Here we fail-closed on the posture + tenancy, create the run in the caller's
/// tenant (P1's `run_grant_scope` fence), dispatch the start to the target, and mint the run-scoped
/// attach token.
pub(crate) async fn run_start(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<ProjectContext>,
    Extension(posture): Extension<boatramp_core::security::SecurityPosture>,
    Extension(issuer): Extension<Issuer>,
    Json(body): Json<RunStartBody>,
) -> Response {
    if let Some(resp) = posture_gate(&posture) {
        return resp;
    }
    // Minting the run-scoped token needs an ISSUING node (a fleet signer). Check EARLY so a
    // non-issuing node 501s before any run is created (no orphaned run / start-message).
    let Some(signer) = issuer.0.clone() else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node has no root private key and cannot mint run tokens (the external run door \
             requires an issuing node)\n",
        )
            .into_response();
    };
    // Tenancy fence (P1 Security #2 + #5), IDENTICAL to the guest door: under a MULTI-TENANT posture
    // (`require_tenancy_declaration`) a run with no host-resolved own-tenant is REFUSED — otherwise
    // every untenanted external caller would collapse into the shared per-project `u` scope. The
    // external control-plane principal resolves NO firm-tenant on its own (a plain project token), so
    // `resolved_tenant` is `None` here: single-tenant/dev → the safe `u` scope; multi-tenant → refused.
    // (A richer host tenant resolution for the external door is a follow-up; the surface is posture-OFF
    // by default, so no behavior ships here.) Checked BEFORE any backend acquisition so the refusal is
    // cheap and cannot leak whether a backend is wired.
    let multi_tenant = posture.require_tenancy_declaration;
    let Some(scope) = run_grant_scope(multi_tenant, None) else {
        return (
            StatusCode::FORBIDDEN,
            "run refused: no resolved tenant under a multi-tenant posture (an untenanted run would \
             share the per-project scope across tenants)\n",
        )
            .into_response();
    };
    // Screen the target as a clean bus topic PATH BEFORE composing its key (INFO-1): `validate_object_key`
    // allows a real dotted/slashed `bus:` topic (`concept.generate`, `orders/created`) while rejecting
    // traversal (`..`), control bytes, `*`, and the reserved `.boatramp*` namespace — the SAME screen
    // the authenticated bus-consumer path runs on its topic. The start is then confined to
    // `{project}/bus/<target>`, so a screened target can never escape the project bus or reach the
    // sibling run keyspace.
    if body.target.is_empty() {
        return (StatusCode::BAD_REQUEST, "target must not be empty\n").into_response();
    }
    if let Err(e) = validate_object_key(&body.target) {
        return (StatusCode::BAD_REQUEST, format!("invalid target: {e}\n")).into_response();
    }
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m.clone(),
        Err(resp) => return resp,
    };
    let Some(inner) = handlers.inner.as_ref() else {
        return not_found();
    };

    let engine = engine_for(messaging.clone(), inner, &project, scope.clone());
    // Create the run (DROP-CANCEL ON by default — a dropped external watcher must not leave the target
    // burning compute). Minted id is unguessable + tenancy-fenced by the scope above.
    let run_id = match engine.create(true).await {
        Ok(id) => id,
        Err(e) => return run_err_response(&e),
    };

    // DISPATCH the start to the target over the existing publish seam: a start-message tagged with the
    // `run_id` on the target consumer's `{project}/bus/<target>` topic. The target (a long-lived
    // bus-consumer agent) emits to the run via P1's `run.emit` — this door never runs guest code.
    let topic_key = bus_namespace(&project.as_ref(), &body.target);
    let start_msg = serde_json::json!({
        "run_id": run_id,
        "target": body.target,
        "input": body.input,
    });
    let msg_bytes = match serde_json::to_vec(&start_msg) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not encode start message: {e}\n"),
            )
                .into_response();
        }
    };
    if let Err(err) = messaging.publish(&topic_key, &msg_bytes).await {
        tracing::warn!(key = %topic_key, error = %err, "run start dispatch publish fault");
        return (
            StatusCode::BAD_GATEWAY,
            "could not dispatch the run start to the target\n",
        )
            .into_response();
    }

    // Mint the run-scoped attach token: exactly `{run_id, scope, rights: attach|cancel}`, fleet-signed,
    // audience-bound to THIS project, TTL-bound. The scope it carries is the host-resolved tenant fence
    // above — ATTACH/CANCEL build their engine from it, never from the request.
    let now = boatramp_core::time::now_unix();
    let cap_scope = boatramp_core::cose::RunCapScope {
        run_id: run_id.clone(),
        scope,
        rights: vec![RunRight::Attach, RunRight::Cancel],
    };
    let attach_token =
        match mint_run_cap(&cap_scope, &project.0, RUN_CAP_TTL_SECS, now, &*signer).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "run-cap mint fault");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not mint the run attach token\n",
                )
                    .into_response();
            }
        };

    (
        StatusCode::CREATED,
        Json(RunStartResponse {
            run_id,
            attach_token,
            expires_at: now.saturating_add(RUN_CAP_TTL_SECS),
        }),
    )
        .into_response()
}

// ---- (2) ATTACH ------------------------------------------------------------------------------

/// Query params for `GET …/runs/{run_id}/events`. All optional.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct RunEventsQuery {
    /// Resume strictly AFTER this `seq` (lossless). Also accepted via the `Last-Event-ID` header;
    /// the query param wins when both are present.
    #[serde(default)]
    after_seq: Option<u64>,
    /// LONG-POLL mode: when present, return the envelopes available within `wait_ms` as a JSON batch
    /// (resumable via `after_seq`) instead of opening an SSE/WS stream. Clamped to [`MAX_POLL_WAIT_MS`].
    #[serde(default)]
    wait_ms: Option<u64>,
}

/// A drop guard that, when the attach is torn down, deletes the ephemeral consumer group this attach
/// opened and — for the SSE/WS transports, when the run armed DROP-CANCEL and NO terminal was
/// delivered — cancels the run (so a dropped external watcher stops the target). Long-poll does NOT
/// arm the cancel (a poll gap is not a disconnect). Mirrors the guest seam's `RunAttachStream`.
struct AttachGuard {
    engine: RunEngine,
    run_id: String,
    cancel_on_drop: bool,
    terminal_seen: Arc<AtomicBool>,
    cleanup: Option<Box<dyn FnOnce() -> futures::future::BoxFuture<'static, ()> + Send>>,
}

impl Drop for AttachGuard {
    fn drop(&mut self) {
        let cleanup = self.cleanup.take();
        let cancel = self.cancel_on_drop && !self.terminal_seen.load(Ordering::SeqCst);
        if cleanup.is_none() && !cancel {
            return;
        }
        let engine = self.engine.clone();
        let run_id = self.run_id.clone();
        tokio::spawn(async move {
            if let Some(c) = cleanup {
                c().await;
            }
            if cancel {
                let _ = engine.cancel(&run_id).await;
            }
        });
    }
}

/// ATTACH to a run's event stream (PLAN-run-streaming P2): SSE (default) / WebSocket (on `Upgrade`) /
/// long-poll (`?wait_ms`), resumable by `?after_seq` or `Last-Event-ID`. Authenticated by the
/// RUN-SCOPED capability token (NOT a project right — this route is ungated at the RBAC layer; see
/// `Right::required_for`). The engine is built from the TOKEN's verified tenant scope, so a token can
/// only ever reach its own run under its own tenant.
pub(crate) async fn run_events(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<ProjectContext>,
    Extension(posture): Extension<boatramp_core::security::SecurityPosture>,
    Extension(auth): Extension<Auth>,
    Path((_project_seg, run_id)): Path<(String, String)>,
    Query(q): Query<RunEventsQuery>,
    request: Request,
) -> Response {
    if let Some(resp) = posture_gate(&posture) {
        return resp;
    }
    let cap = match authorize_run_token(
        request.headers(),
        &auth,
        &project,
        &run_id,
        RunRight::Attach,
    ) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m.clone(),
        Err(resp) => return resp,
    };
    let Some(inner) = handlers.inner.as_ref() else {
        return not_found();
    };
    let client_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or(IpAddr::from([0u8, 0, 0, 0]));
    // Resume cursor: the `?after_seq` query wins, else the `Last-Event-ID` header (the SSE `id:` a
    // reconnecting EventSource echoes back) — lossless either way (the engine skips `seq ≤ after`).
    let after_seq = q.after_seq.or_else(|| {
        request
            .headers()
            .get("last-event-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
    });

    // The engine is fenced to the TOKEN's verified scope — the tenancy fence rides the signed token,
    // never the request. A token minted under tenant X composes X's key; run B under tenant Y is a
    // different key that does not exist ⇒ `NotFound`.
    let engine = engine_for(messaging, inner, &project, cap.scope.scope.clone());
    let attach = match engine.attach(&run_id, after_seq).await {
        Ok(a) => a,
        Err(e) => return run_err_response(&e),
    };

    if let Some(wait_ms) = q.wait_ms {
        return serve_run_longpoll(inner, engine, run_id, attach, client_ip, wait_ms).await;
    }
    if boatramp_http::is_upgrade_request(request.headers()) {
        return serve_run_ws(inner, engine, run_id, attach, client_ip, request).await;
    }
    serve_run_sse(inner, engine, run_id, attach, client_ip)
}

/// LONG-POLL: drain the envelopes available within `wait_ms` (bounded by [`MAX_POLL_BATCH`]) and
/// return them as a JSON batch with the next resume cursor. Does NOT arm drop-cancel (a poll gap is
/// not a watcher disconnect); the ephemeral attach group is still cleaned up on return.
///
/// LOW-2: acquires the SAME per-scope + per-IP stream permits SSE/WS do (keyed by `run:{run_id}`), so
/// concurrent long-polls — and the ephemeral-group churn each one opens on the holder's own run — are
/// bounded exactly like the streaming transports, rather than being an un-capped churn hole.
async fn serve_run_longpoll(
    inner: &HandlerRuntimeInner,
    engine: RunEngine,
    run_id: String,
    attach: EngineAttach,
    client_ip: IpAddr,
    wait_ms: u64,
) -> Response {
    #[derive(Serialize)]
    struct PollResponse {
        events: Vec<RunEnvelopeDto>,
        /// The resume cursor to pass as `?after_seq` on the next poll (`None` ⇒ nothing delivered).
        next_after_seq: Option<u64>,
        /// Whether a terminal envelope was delivered (the run has concluded — stop polling).
        done: bool,
    }

    // deny-before-resource-use: the per-scope + per-IP permits, keyed by the run topic (identical to
    // SSE/WS — one shared pool per run), acquired BEFORE opening the poll so a flood of long-polls on
    // one run is shed to 503 / 429 rather than opening unbounded ephemeral attach groups (LOW-2). Held
    // for the whole poll (released on return).
    let scope_key = format!("run:{run_id}");
    let _site_permit = match crate::stream::acquire_stream_permit_capped(
        inner,
        &scope_key,
        crate::stream::DEFAULT_STREAM_CONNECTIONS,
    ) {
        Ok(p) => p,
        Err(()) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "run stream connection limit reached\n",
            )
                .into_response();
        }
    };
    let _ip_guard = match crate::stream::acquire_stream_ip_slot(inner, &scope_key, client_ip) {
        Ok(g) => g,
        Err(()) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "per-client run stream connection limit reached\n",
            )
                .into_response();
        }
    };

    let EngineAttach {
        mut stream,
        cleanup,
        ..
    } = attach;
    // Clean up the ephemeral group on return; long-poll NEVER drop-cancels (cancel_on_drop = false).
    let _guard = AttachGuard {
        engine,
        run_id: run_id.clone(),
        cancel_on_drop: false,
        terminal_seen: Arc::new(AtomicBool::new(false)),
        cleanup,
    };

    let deadline = Duration::from_millis(wait_ms.min(MAX_POLL_WAIT_MS));
    let mut events = Vec::new();
    let mut next_after_seq = None;
    let mut done = false;
    loop {
        if events.len() >= MAX_POLL_BATCH {
            break;
        }
        match tokio::time::timeout(deadline, stream.next()).await {
            Ok(Some(Ok(env))) => {
                next_after_seq = Some(env.seq);
                if env.kind.is_terminal() {
                    done = true;
                }
                events.push(RunEnvelopeDto::from_envelope(&env));
                if done {
                    break;
                }
            }
            // Stream error → stop with what we have (the client re-polls from the cursor).
            Ok(Some(Err(_))) => break,
            // Stream ended (already-terminal fast path) → done.
            Ok(None) => {
                done = true;
                break;
            }
            // Wait deadline reached → return what we have (possibly empty); the client re-polls.
            Err(_) => break,
        }
    }
    Json(PollResponse {
        events,
        next_after_seq,
        done,
    })
    .into_response()
}

/// SSE: frame each run envelope as an SSE `event:` (the kind) with the `seq` as `id:` (for
/// `Last-Event-ID` resume) and the base64 payload DTO as `data:`. Ends after the terminal envelope.
/// On client disconnect before a terminal, the drop guard cancels the run if it armed drop-cancel.
fn serve_run_sse(
    inner: &HandlerRuntimeInner,
    engine: RunEngine,
    run_id: String,
    attach: EngineAttach,
    client_ip: IpAddr,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};

    // deny-before-resource-use: the per-scope + per-IP stream permits, keyed by the run topic so each
    // run is bounded independently and shares the configured-stream pools.
    let scope_key = format!("run:{run_id}");
    let site_permit = match crate::stream::acquire_stream_permit_capped(
        inner,
        &scope_key,
        crate::stream::DEFAULT_STREAM_CONNECTIONS,
    ) {
        Ok(p) => p,
        Err(()) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "run stream connection limit reached\n",
            )
                .into_response();
        }
    };
    let ip_guard = match crate::stream::acquire_stream_ip_slot(inner, &scope_key, client_ip) {
        Ok(g) => g,
        Err(()) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "per-client run stream connection limit reached\n",
            )
                .into_response();
        }
    };

    let EngineAttach {
        stream,
        drop_cancel_armed,
        cleanup,
    } = attach;
    let terminal_seen = Arc::new(AtomicBool::new(false));
    let guard = AttachGuard {
        engine,
        run_id,
        cancel_on_drop: drop_cancel_armed,
        terminal_seen: terminal_seen.clone(),
        cleanup,
    };

    struct SseState {
        stream: BoxStream<'static, Result<RunEnvelope, RunError>>,
        terminal_seen: Arc<AtomicBool>,
        _guard: AttachGuard,
        _site_permit: tokio::sync::OwnedSemaphorePermit,
        _ip_guard: crate::stream::IpStreamGuard,
    }
    let state = SseState {
        stream,
        terminal_seen,
        _guard: guard,
        _site_permit: site_permit,
        _ip_guard: ip_guard,
    };

    let body = futures::stream::unfold(state, |mut st| async move {
        match st.stream.next().await {
            Some(Ok(env)) => {
                if env.kind.is_terminal() {
                    // Mark terminal so the drop guard does NOT drop-cancel a run that ended cleanly.
                    st.terminal_seen.store(true, Ordering::SeqCst);
                }
                let dto = RunEnvelopeDto::from_envelope(&env);
                let data = serde_json::to_string(&dto).unwrap_or_else(|_| "{}".to_string());
                let event = Event::default()
                    .id(env.seq.to_string())
                    .event(kind_str(env.kind))
                    .data(data);
                Some((Ok::<_, std::convert::Infallible>(event), st))
            }
            // Stream error or end → close the SSE body (the terminal already ended it on the happy path).
            Some(Err(_)) | None => None,
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

/// WebSocket (RFC 6455): server→client, one Text [`RunEnvelopeDto`] JSON per envelope; closes after
/// the terminal. Mirrors the bus-consumer WS handshake + `boatramp_http` upgrade seam. The pump runs
/// as its own task feeding a bounded channel; the drop guard (held by the socket task) cancels the run
/// on disconnect-before-terminal when drop-cancel is armed.
async fn serve_run_ws(
    inner: &HandlerRuntimeInner,
    engine: RunEngine,
    run_id: String,
    attach: EngineAttach,
    client_ip: IpAddr,
    mut request: Request,
) -> Response {
    // RFC 6455 opening handshake (mirrors the bus-consumer WS): require version 13 + a key, derive the
    // accept token, take over the connection via boatramp-http's upgrade seam.
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
    drop(request);

    let scope_key = format!("run:{run_id}");
    let site_permit = match crate::stream::acquire_stream_permit_capped(
        inner,
        &scope_key,
        crate::stream::DEFAULT_STREAM_CONNECTIONS,
    ) {
        Ok(p) => p,
        Err(()) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "run stream connection limit reached\n",
            )
                .into_response();
        }
    };
    let ip_guard = match crate::stream::acquire_stream_ip_slot(inner, &scope_key, client_ip) {
        Ok(g) => g,
        Err(()) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "per-client run stream connection limit reached\n",
            )
                .into_response();
        }
    };

    let EngineAttach {
        mut stream,
        drop_cancel_armed,
        cleanup,
    } = attach;
    let terminal_seen = Arc::new(AtomicBool::new(false));
    let guard = AttachGuard {
        engine,
        run_id,
        cancel_on_drop: drop_cancel_armed,
        terminal_seen: terminal_seen.clone(),
        cleanup,
    };

    // The pump task: drive the engine stream → push each envelope into a bounded channel. Isolated so
    // the WS read loop (pings/close) never cancels an in-flight engine poll.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<RunEnvelope>(16);
    let pump_task = tokio::spawn(async move {
        // The guard lives with the pump task: when the socket task ends (client gone) it drops the rx,
        // the pump's `tx.send` fails, the pump returns, and the guard drops → cleanup + maybe cancel.
        let _guard = guard;
        while let Some(item) = stream.next().await {
            match item {
                Ok(env) => {
                    let terminal = env.kind.is_terminal();
                    if terminal {
                        terminal_seen.store(true, Ordering::SeqCst);
                    }
                    if tx.send(env).await.is_err() {
                        return; // client gone
                    }
                    if terminal {
                        return; // stream ends after the terminal
                    }
                }
                Err(_) => return,
            }
        }
    });

    tokio::spawn(async move {
        use futures::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::tungstenite::protocol::Role;

        let _permits = (site_permit, ip_guard);
        let Ok(upgraded) = on_upgrade.await else {
            pump_task.abort();
            return;
        };
        let socket =
            tokio_tungstenite::WebSocketStream::from_raw_socket(upgraded, Role::Server, None).await;
        let (mut sink, mut incoming) = socket.split();
        let mut ping = crate::stream::ws_ping_interval();
        let mut idle_deadline = crate::stream::ws_idle_deadline();
        loop {
            tokio::select! {
                biased;
                // Inbound frames (a pong, or a client close) are activity; a run WS is server→client
                // only, so any Text/Binary is ignored (never an ack channel like the bus WS).
                msg = incoming.next() => {
                    idle_deadline = crate::stream::ws_idle_deadline();
                    match msg {
                        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                        Some(Ok(_)) => {}
                    }
                },
                delivered = rx.recv() => match delivered {
                    Some(env) => {
                        let dto = RunEnvelopeDto::from_envelope(&env);
                        let text = serde_json::to_string(&dto).unwrap_or_else(|_| "{}".to_string());
                        let terminal = env.kind.is_terminal();
                        if sink.send(Message::Text(text)).await.is_err() {
                            break;
                        }
                        if terminal {
                            // Deliver the terminal, then close the socket cleanly.
                            let _ = sink.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    None => break, // pump ended
                },
                _ = ping.tick() => {
                    if tokio::time::Instant::now() >= idle_deadline {
                        break;
                    }
                    if sink.send(Message::Ping(Vec::new())).await.is_err() {
                        break;
                    }
                }
            }
        }
        pump_task.abort();
    });

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

// ---- (3) CANCEL ------------------------------------------------------------------------------

/// CANCEL a run (PLAN-run-streaming P2) → [`RunEngine::cancel`] (emits the terminal `cancelled`).
/// Authenticated by the run-scoped token carrying the `cancel` right (ungated at the RBAC layer).
pub(crate) async fn run_cancel(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(project): Extension<ProjectContext>,
    Extension(posture): Extension<boatramp_core::security::SecurityPosture>,
    Extension(auth): Extension<Auth>,
    Path((_project_seg, run_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    if let Some(resp) = posture_gate(&posture) {
        return resp;
    }
    let cap = match authorize_run_token(
        request.headers(),
        &auth,
        &project,
        &run_id,
        RunRight::Cancel,
    ) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let messaging = match messaging_or_unavailable(&handlers) {
        Ok(m) => m.clone(),
        Err(resp) => return resp,
    };
    let Some(inner) = handlers.inner.as_ref() else {
        return not_found();
    };
    let engine = engine_for(messaging, inner, &project, cap.scope.scope.clone());
    match engine.cancel(&run_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => run_err_response(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use boatramp_core::cose::{LocalSigner, RunCapScope, TokenAlg};
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::messaging::LogMessaging;
    use boatramp_core::run::RunEventKind;
    use boatramp_core::security::SecurityProfile;
    use boatramp_core::{
        ByteStream, GetObject, ListPage, ObjectMeta, PutMeta, Storage, StorageError,
    };
    use bytes::Bytes as RawBytes;

    use crate::auth::Auth;

    // A minimal in-memory `Storage` so the REAL `LogMessaging` durable substrate can be built —
    // mirrors the run-engine / bus-consumer test `MemStorage`.
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

    /// The test harness: a runtime wired to a REAL durable messaging + KV, a fleet signer + the
    /// matching trust-root `Auth`, and a single-tenant posture with run-streaming ON.
    struct Harness {
        rt: Arc<HandlerRuntime>,
        messaging: Arc<dyn Messaging>,
        kv: Arc<dyn KvStore>,
        auth: Auth,
        issuer: Issuer,
        posture: boatramp_core::security::SecurityPosture,
    }

    fn setup() -> Harness {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let mq_kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let messaging: Arc<dyn Messaging> = Arc::new(LogMessaging::new(storage.clone(), mq_kv));
        let engine =
            boatramp_handlers::HandlerEngine::new(boatramp_handlers::Limits::default(), 16)
                .unwrap();
        let rt = Arc::new(HandlerRuntime::new(
            engine,
            kv.clone(),
            storage,
            None,
            Some(messaging.clone()),
        ));
        let signer = LocalSigner::generate(TokenAlg::Ed25519);
        let public = signer.public_key();
        let auth = Auth::with_key(public, Arc::new(MemoryKv::new()));
        let issuer = Issuer(Some(Arc::new(signer)));
        let mut posture = SecurityProfile::SingleTenant.preset();
        posture.allow_guest_run_streaming = true;
        Harness {
            rt,
            messaging,
            kv,
            auth,
            issuer,
            posture,
        }
    }

    fn proj() -> ProjectContext {
        ProjectContext("acme".into())
    }

    async fn to_value(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn bearer_request(method: &str, token: &str) -> Request {
        Request::builder()
            .method(method)
            .uri("/")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    async fn start(h: &Harness) -> (String, String, u64) {
        let resp = run_start(
            Extension(h.rt.clone()),
            Extension(proj()),
            Extension(h.posture),
            Extension(h.issuer.clone()),
            Json(RunStartBody {
                target: "agent".into(),
                input: serde_json::json!({"q": "hi"}),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let v = to_value(resp).await;
        (
            v["run_id"].as_str().unwrap().to_string(),
            v["attach_token"].as_str().unwrap().to_string(),
            v["expires_at"].as_u64().unwrap(),
        )
    }

    /// The target-side engine for the single-tenant `u` scope — simulates the target agent emitting
    /// to the run (what the real guest `run.emit` binding does after it claims the start-message).
    fn target_engine(h: &Harness) -> RunEngine {
        RunEngine::new(
            h.messaging.clone(),
            h.kv.clone(),
            "acme".to_string(),
            "u".to_string(),
        )
    }

    /// END-TO-END: an external client STARTs (gets run_id + fleet-signed, TTL-bound attach_token), the
    /// target emits, the client ATTACHes with the token (long-poll) and sees the envelopes resumably,
    /// then CANCELs via the token.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_dispatch_attach_resume_and_cancel_end_to_end() {
        let h = setup();
        let now = boatramp_core::time::now_unix();
        let (run_id, token, expires_at) = start(&h).await;
        // The attach token is TTL-bound (≈ now + the cap TTL).
        assert!(expires_at > now && expires_at <= now + RUN_CAP_TTL_SECS + 2);
        // It is fleet-signed + scoped to EXACTLY this run (+ both rights), verifiable vs the trust root.
        let cap = verify_run_cap(&token, &h.auth.public_key().unwrap(), now, "acme").unwrap();
        assert_eq!(cap.scope.run_id, run_id);
        assert_eq!(cap.scope.scope, "u");
        assert!(cap.scope.allows(RunRight::Attach) && cap.scope.allows(RunRight::Cancel));

        // START dispatched a start-message tagged with the run_id to the target's bus topic.
        let key = bus_namespace(&proj().as_ref(), "agent");
        // Claim on the DEFAULT work-queue (empty group) — a published message is enqueued for the
        // first claimer regardless of when the group was created, so this sees the dispatched start.
        let claimed = h
            .messaging
            .claim_grouped(
                &key,
                "",
                boatramp_core::config::StartPosition::Earliest,
                Duration::from_secs(5),
                1,
                10,
            )
            .await
            .unwrap();
        assert_eq!(
            claimed.len(),
            1,
            "the start was dispatched to the target topic"
        );
        let msg: serde_json::Value = serde_json::from_slice(&claimed[0].payload).unwrap();
        assert_eq!(msg["run_id"].as_str().unwrap(), run_id);
        assert_eq!(msg["target"], "agent");

        // The target emits progress then a terminal result.
        let te = target_engine(&h);
        let p_seq = te
            .emit(&run_id, RunEventKind::Progress, b"working".to_vec())
            .await
            .unwrap();
        te.emit(&run_id, RunEventKind::Result, b"done".to_vec())
            .await
            .unwrap();

        // ATTACH via long-poll with the token: sees both envelopes, in order, done=true.
        let resp = run_events(
            Extension(h.rt.clone()),
            Extension(proj()),
            Extension(h.posture),
            Extension(h.auth.clone()),
            Path(("acme".into(), run_id.clone())),
            Query(RunEventsQuery {
                after_seq: None,
                wait_ms: Some(1000),
            }),
            bearer_request("GET", &token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = to_value(resp).await;
        let events = v["events"].as_array().unwrap();
        assert_eq!(events.len(), 2, "progress + result");
        assert_eq!(events[0]["kind"], "progress");
        assert_eq!(events[1]["kind"], "result");
        assert_eq!(v["done"], true);
        // The opaque payload rides base64, losslessly.
        let p0 = base64::engine::general_purpose::STANDARD
            .decode(events[0]["payload_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(p0, b"working");

        // RESUME strictly AFTER the progress seq: only the result (lossless, no gap).
        let resp = run_events(
            Extension(h.rt.clone()),
            Extension(proj()),
            Extension(h.posture),
            Extension(h.auth.clone()),
            Path(("acme".into(), run_id.clone())),
            Query(RunEventsQuery {
                after_seq: Some(p_seq),
                wait_ms: Some(1000),
            }),
            bearer_request("GET", &token),
        )
        .await;
        let v = to_value(resp).await;
        let events = v["events"].as_array().unwrap();
        assert_eq!(events.len(), 1, "resume sees only the un-consumed suffix");
        assert_eq!(events[0]["kind"], "result");

        // CANCEL a FRESH run via its token → 204, and the run is cancelled.
        let (run2, token2, _) = start(&h).await;
        let resp = run_cancel(
            Extension(h.rt.clone()),
            Extension(proj()),
            Extension(h.posture),
            Extension(h.auth.clone()),
            Path(("acme".into(), run2.clone())),
            bearer_request("POST", &token2),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            target_engine(&h).status(&run2).await.unwrap(),
            boatramp_core::run::RunStatus::Cancelled
        );
    }

    /// A run token for a DIFFERENT run, or one WITHOUT the needed right, is refused (403) — the door's
    /// run-id + right enforcement on top of the fleet-signature/audience checks.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn token_for_another_run_or_without_the_right_is_refused() {
        let h = setup();
        let (run_a, token_a, _) = start(&h).await;
        let (run_b, _token_b, _) = start(&h).await;

        // A's token presented on B's cancel path → 403 (bound to exactly run A).
        let resp = run_cancel(
            Extension(h.rt.clone()),
            Extension(proj()),
            Extension(h.posture),
            Extension(h.auth.clone()),
            Path(("acme".into(), run_b.clone())),
            bearer_request("POST", &token_a),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // ...and B is untouched (still active).
        assert_eq!(
            target_engine(&h).status(&run_b).await.unwrap(),
            boatramp_core::run::RunStatus::Active
        );

        // An ATTACH-only token cannot CANCEL run A → 403 (the right check).
        let now = boatramp_core::time::now_unix();
        let attach_only = mint_run_cap(
            &RunCapScope {
                run_id: run_a.clone(),
                scope: "u".into(),
                rights: vec![RunRight::Attach],
            },
            "acme",
            300,
            now,
            &*h.issuer.0.clone().unwrap(),
        )
        .await
        .unwrap();
        let resp = run_cancel(
            Extension(h.rt.clone()),
            Extension(proj()),
            Extension(h.posture),
            Extension(h.auth.clone()),
            Path(("acme".into(), run_a.clone())),
            bearer_request("POST", &attach_only),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            target_engine(&h).status(&run_a).await.unwrap(),
            boatramp_core::run::RunStatus::Active
        );
    }

    /// A token minted for a DIFFERENT tenant's scope can never reach this tenant's run: the door builds
    /// its engine from the TOKEN's verified scope, so a `t_other`-scoped token composes a key under
    /// `t_other` — the `u`-scoped run does not exist there ⇒ 404 (never a cross-tenant touch).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn token_for_another_tenant_scope_cannot_reach_the_run() {
        let h = setup();
        let (run_a, _token_a, _) = start(&h).await; // scope "u"
        // A well-formed, fleet-signed, audience-correct token for the SAME run id but a DIFFERENT
        // tenant scope. It verifies + matches the run id + carries cancel — but its scope fences it to
        // `t_other`, where the run does not exist.
        let now = boatramp_core::time::now_unix();
        let foreign = mint_run_cap(
            &RunCapScope {
                run_id: run_a.clone(),
                scope: "t_other".into(),
                rights: vec![RunRight::Attach, RunRight::Cancel],
            },
            "acme",
            300,
            now,
            &*h.issuer.0.clone().unwrap(),
        )
        .await
        .unwrap();
        let resp = run_cancel(
            Extension(h.rt.clone()),
            Extension(proj()),
            Extension(h.posture),
            Extension(h.auth.clone()),
            Path(("acme".into(), run_a.clone())),
            bearer_request("POST", &foreign),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // The real `u`-scoped run is untouched.
        assert_eq!(
            target_engine(&h).status(&run_a).await.unwrap(),
            boatramp_core::run::RunStatus::Active
        );
    }

    /// With the posture OFF (the default), every door returns 403 — zero runtime exposure.
    #[tokio::test]
    async fn posture_off_refuses_every_door() {
        let rt = Arc::new(HandlerRuntime::disabled());
        let posture = SecurityProfile::SingleTenant.preset(); // allow_guest_run_streaming stays false
        assert!(!posture.allow_guest_run_streaming);
        let signer = LocalSigner::generate(TokenAlg::Ed25519);
        let auth = Auth::with_key(signer.public_key(), Arc::new(MemoryKv::new()));
        let issuer = Issuer(Some(Arc::new(signer)));

        let resp = run_start(
            Extension(rt.clone()),
            Extension(proj()),
            Extension(posture),
            Extension(issuer),
            Json(RunStartBody {
                target: "agent".into(),
                input: serde_json::Value::Null,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let resp = run_cancel(
            Extension(rt),
            Extension(proj()),
            Extension(posture),
            Extension(auth),
            Path(("acme".into(), "r".into())),
            bearer_request("POST", "x"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// START under a MULTI-TENANT posture with no host-resolved tenant is REFUSED (403), identical to
    /// P1's guest fence — the untenanted run would share the per-project scope across tenants.
    #[tokio::test]
    async fn start_refused_untenanted_under_multi_tenant() {
        let rt = Arc::new(HandlerRuntime::disabled());
        let mut posture = SecurityProfile::MultiTenant.preset();
        posture.allow_guest_run_streaming = true;
        assert!(posture.require_tenancy_declaration);
        let signer = LocalSigner::generate(TokenAlg::Ed25519);
        let issuer = Issuer(Some(Arc::new(signer)));
        let resp = run_start(
            Extension(rt),
            Extension(proj()),
            Extension(posture),
            Extension(issuer),
            Json(RunStartBody {
                target: "agent".into(),
                input: serde_json::Value::Null,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// START on a NON-ISSUING node (no fleet signer) is refused 501 — the external door needs an
    /// issuing node to mint the run-scoped token.
    #[tokio::test]
    async fn start_requires_an_issuing_node() {
        let rt = Arc::new(HandlerRuntime::disabled());
        let mut posture = SecurityProfile::SingleTenant.preset();
        posture.allow_guest_run_streaming = true;
        let resp = run_start(
            Extension(rt),
            Extension(proj()),
            Extension(posture),
            Extension(Issuer(None)),
            Json(RunStartBody {
                target: "agent".into(),
                input: serde_json::Value::Null,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    /// LOW-2: the long-poll attach acquires the SAME per-scope + per-IP stream permits SSE/WS do, so a
    /// client already at the per-IP cap on a run is shed with 429 (bounding concurrent long-polls +
    /// the ephemeral-group churn each would open), and a released slot lets one through again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn longpoll_applies_the_per_ip_stream_cap() {
        let h = setup();
        let (run_id, token, _) = start(&h).await;
        let inner = h.rt.inner.as_ref().unwrap();
        let scope_key = format!("run:{run_id}");
        // Saturate the per-IP cap on this run's scope for the default client IP (0.0.0.0 — the value
        // the attach handler uses when the request carries no `ConnectInfo`, as in these unit calls).
        let ip = IpAddr::from([0u8, 0, 0, 0]);
        let mut held = Vec::new();
        for _ in 0..8 {
            held.push(
                crate::stream::acquire_stream_ip_slot(inner, &scope_key, ip)
                    .expect("under the cap"),
            );
        }
        let longpoll = |h: &Harness| {
            run_events(
                Extension(h.rt.clone()),
                Extension(proj()),
                Extension(h.posture),
                Extension(h.auth.clone()),
                Path(("acme".into(), run_id.clone())),
                Query(RunEventsQuery {
                    after_seq: None,
                    wait_ms: Some(50),
                }),
                bearer_request("GET", &token),
            )
        };
        // The next long-poll on the same run from the same IP is shed (the cap applies).
        assert_eq!(longpoll(&h).await.status(), StatusCode::TOO_MANY_REQUESTS);
        // Releasing a slot lets a long-poll through again (now under the cap).
        held.pop();
        assert_eq!(longpoll(&h).await.status(), StatusCode::OK);
    }
}
