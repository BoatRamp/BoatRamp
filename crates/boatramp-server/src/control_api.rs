//! The control-plane identity and cluster admin API: mint and revoke
//! control-plane tokens, run the bootstrap and cluster join/promote/revoke
//! membership dance, rotate the mesh signing key, and manage the Cedar authz
//! policy plus its root trust anchors. Always-on (`/api/tokens`,
//! `/api/cluster/*`, `/api/authz/*`, `/api/auth/whoami`). Pulls the serve
//! scope in via `use super::*`.

use super::*;

#[derive(Deserialize)]
pub(super) struct CreateTokenRequest {
    label: String,
    /// Role specs (`"<role>"` or `"<role>:<site>"`); at least one required.
    #[serde(default)]
    roles: Vec<String>,
    /// Optional TTL in seconds; omitted ⇒ no expiry.
    #[serde(default)]
    ttl_secs: Option<u64>,
    /// Optional holder public key (`"<alg>:<hex>"`) making the token
    /// **delegatable** (RFC 8747 `cnf`): the holder of the
    /// matching private key can mint narrowing delegation blocks offline. Absent ⇒
    /// a plain, non-delegatable token.
    #[serde(default)]
    holder_pubkey: Option<String>,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    /// The minted token (base64url `COSE_Sign1` CWT) — shown once, never stored.
    token: String,
    /// The revocation id (`cti`) — the `token rm` argument.
    id: String,
}

/// Reject a set of parsed roles if any target-scoped role carries a non-conforming
/// target (audit A8). A role scope is `<role>:<target>`, where `<target>` is a
/// `<project>` / `<project>/<site>` / `<project>/*`; each real segment must be a valid
/// slug. Global roles (no target) are always fine. Returns the offending target on the
/// first failure so the mint feeder can 400 with a precise reason — closing the
/// `publisher:${PROJECT}` ingress at issue time (the authz-match backstop closes it for
/// already-minted / offline tokens). Shared by [`create_token`] and [`bootstrap_token`].
fn validate_role_targets(
    roles: &[GrantedRole],
) -> Result<(), boatramp_core::project::InvalidResourceName> {
    for role in roles {
        if let Some(target) = &role.target {
            boatramp_core::project::validate_role_target(target)?;
        }
    }
    Ok(())
}

/// Mint a token carrying the requested roles and record its metadata. Needs the
/// token signer (the issuer); a verify-only node returns `501`. The token is
/// returned once and never stored — only its metadata is.
pub(super) async fn create_token(
    State(deploy): State<DeployStore>,
    Extension(issuer): Extension<Issuer>,
    Json(request): Json<CreateTokenRequest>,
) -> Response {
    let Some(signer) = issuer.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node has no root private key and cannot issue tokens\n",
        )
            .into_response();
    };
    let roles: Vec<GrantedRole> = request
        .roles
        .iter()
        .map(|s| GrantedRole::parse(s))
        .collect();
    if roles.is_empty() {
        return (StatusCode::BAD_REQUEST, "at least one role is required\n").into_response();
    }
    // A8: refuse a non-conforming role target at issue time (400), so a
    // `publisher:${PROJECT}` token is never minted in the first place.
    if let Err(err) = validate_role_targets(&roles) {
        return (StatusCode::BAD_REQUEST, format!("{err}\n")).into_response();
    }
    let now = now_unix();
    let claims = Claims {
        roles: roles.clone(),
        kind: cose::KIND_ROLE.to_string(),
        ttl_secs: request.ttl_secs,
        now_unix: now,
    };
    // A `holder_pubkey` makes the token delegatable (embeds the holder `cnf`).
    let holder = match &request.holder_pubkey {
        Some(hex) => match cose::TokenPublicKey::from_hex(hex) {
            Ok(pk) => Some(pk),
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("invalid holder key: {err}\n"),
                )
                    .into_response();
            }
        },
        None => None,
    };
    let minted = match &holder {
        Some(holder) => cose::mint_delegatable(&claims, holder, &*signer).await,
        None => cose::mint(&claims, &*signer).await,
    };
    let token = match minted {
        Ok(t) => t,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    // The revocation id is the token's `cti`; read it back by verifying the
    // just-minted token against our own public key (always valid, unexpired).
    let id = match cose::verify(&token, &signer.public_key(), now) {
        Ok(v) => v.cti,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    let meta = TokenMeta {
        version: boatramp_core::SCHEMA_VERSION,
        label: request.label,
        roles,
        created_at: now,
        expires_at: request.ttl_secs.map(|t| now.saturating_add(t)),
        revocation_id: id.clone(),
    };
    match deploy.put_token_meta(&meta).await {
        Ok(()) => (StatusCode::CREATED, Json(CreateTokenResponse { token, id })).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

#[derive(Deserialize)]
pub(super) struct BootstrapRequest {
    /// Roles for the first token. Defaults to `["admin"]` — the bootstrap token
    /// exists to configure the system (set policy, mint scoped tokens).
    #[serde(default)]
    pub(super) roles: Vec<String>,
    /// TTL in seconds; defaults to 1 h so an unused first token expires on its own.
    pub(super) ttl_secs: Option<u64>,
}

/// `POST /api/tokens/bootstrap` — mint the FIRST control-plane token by presenting
/// the operator-set, single-use **bootstrap secret** (as `Authorization: Bearer`),
/// not an admin token. RBAC-exempt at the router (`Right::required` → `None` for
/// exactly this path); this handler does the real verification. The token is
/// minted through the issuer (the root key never leaves the server), recorded as
/// [`TokenMeta`] (listable + revocable), and returned in the response — never
/// logged. `501` if bootstrap isn't enabled / this node can't issue; `401` on a
/// bad secret; `409` once the secret is spent (rotate it to re-bootstrap).
pub(super) async fn bootstrap_token(
    State(deploy): State<DeployStore>,
    Extension(issuer): Extension<Issuer>,
    Extension(gate): Extension<BootstrapGate>,
    headers: axum::http::HeaderMap,
    Json(request): Json<BootstrapRequest>,
) -> Response {
    let Some(inner) = gate.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "bootstrap is not enabled on this node (set a bootstrap secret)\n",
        )
            .into_response();
    };
    let Some(signer) = issuer.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node has no root private key and cannot issue tokens\n",
        )
            .into_response();
    };
    // The presented secret arrives as the bearer (so `require_auth`'s presence
    // check passes). Compare by SHA-256 — the hash also keys the single-use marker.
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if boatramp_core::deploy::sha256_hex(presented.as_bytes()) != inner.secret_hash {
        return (StatusCode::UNAUTHORIZED, "invalid bootstrap secret\n").into_response();
    }
    // Serialize check-and-spend; the persisted marker makes it single-use across
    // restarts. Rotating the secret yields a fresh hash → re-enabled (recovery).
    let _guard = inner.lock.lock().await;
    match deploy.bootstrap_consumed(&inner.secret_hash).await {
        Ok(true) => {
            return (
                StatusCode::CONFLICT,
                "bootstrap secret already used — rotate it to re-bootstrap\n",
            )
                .into_response();
        }
        Ok(false) => {}
        Err(err) => return deploy_error_response(err),
    }
    let roles: Vec<GrantedRole> = if request.roles.is_empty() {
        vec![GrantedRole::parse("admin")]
    } else {
        request
            .roles
            .iter()
            .map(|s| GrantedRole::parse(s))
            .collect()
    };
    // A8: refuse a non-conforming role target at issue time (400), even on the
    // bootstrap path — the first token must not smuggle a `publisher:${PROJECT}`.
    if let Err(err) = validate_role_targets(&roles) {
        return (StatusCode::BAD_REQUEST, format!("{err}\n")).into_response();
    }
    let now = now_unix();
    let ttl = request.ttl_secs.or(Some(3600));
    let claims = Claims {
        roles: roles.clone(),
        kind: cose::KIND_ROLE.to_string(),
        ttl_secs: ttl,
        now_unix: now,
    };
    let token = match cose::mint(&claims, &*signer).await {
        Ok(t) => t,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    let id = match cose::verify(&token, &signer.public_key(), now) {
        Ok(v) => v.cti,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    let meta = TokenMeta {
        version: boatramp_core::SCHEMA_VERSION,
        label: "bootstrap".to_string(),
        roles,
        created_at: now,
        expires_at: ttl.map(|t| now.saturating_add(t)),
        revocation_id: id.clone(),
    };
    if let Err(err) = deploy.put_token_meta(&meta).await {
        return deploy_error_response(err);
    }
    if let Err(err) = deploy.mark_bootstrap_consumed(&inner.secret_hash).await {
        return deploy_error_response(err);
    }
    tracing::warn!(cti = %id, "control-plane bootstrapped — first token minted via bootstrap secret");
    (StatusCode::CREATED, Json(CreateTokenResponse { token, id })).into_response()
}

#[derive(Deserialize)]
pub(super) struct JoinRequest {
    /// The single-use **bearer** mesh join token (base64url), from `cluster add`.
    pub(super) token: String,
    /// The joining node's own mesh public key (SPKI hex) — its self-derived
    /// identity. Not pre-authorized by the token; possession is proven below.
    pub(super) mesh_pubkey: String,
    /// A **possession proof**: an Ed25519 signature (hex) over
    /// `cose::join_challenge(jti, mesh_pubkey, proof_iat)`, proving the joiner
    /// controls `mesh_pubkey` — so a token + an observed key admits nothing.
    pub(super) possession_proof: String,
    /// The proof's issued-at (Unix seconds); must be fresh (anti-replay).
    pub(super) proof_iat: u64,
    /// The joiner's own mesh base URL (e.g. `https://10.0.0.4:7000`) so the leader
    /// can dial it for Raft replication. Advisory routing only — the mesh TLS
    /// re-authenticates every dial by key. Absent ⇒ the joiner isn't reachable by
    /// address (the leader still admits it, but can't replicate until it learns one).
    #[serde(default)]
    pub(super) advertise_addr: Option<String>,
}

#[derive(Serialize)]
struct JoinResponse {
    /// The cluster's current members as **root-signed** mesh-member assertions
    /// (base64url `COSE_Sign1`). The joiner verifies each against the root anchor
    /// before adding it to its trust set — so a malicious/stale seed can't inject a
    /// fabricated member (PLAN-cluster-join F3).
    members: Vec<String>,
    /// Advisory `node_id -> mesh URL` routing for the members, so the joiner can
    /// dial each one. Not signed (addressing is advisory; the mesh TLS
    /// re-authenticates by key), and only trusted for a `node_id` the joiner also
    /// verified via a root-signed member assertion above.
    #[serde(default)]
    member_addrs: std::collections::BTreeMap<u64, String>,
}

/// Admit a joining node presenting a mesh join token. Gated by
/// the token itself (`Right::required` returns `None` for this exact path), not
/// an admin bearer: the handler verifies the join token (signature + TTL),
/// confirms the presented `(node_id, pubkey)` is exactly the one the token
/// authorizes (a stolen token can't admit a different node/key), and hands the
/// verified claim to the cluster's [`MeshControl`] — which trusts the key
/// cluster-wide and adds membership, single-use enforced in the state machine.
/// `501` on a non-cluster node (no control hook) or a node without a root key.
pub(super) async fn cluster_join(
    Extension(auth): Extension<Auth>,
    Extension(mesh_control): Extension<MeshControlHandle>,
    Json(request): Json<JoinRequest>,
) -> Response {
    let Some(admitter) = mesh_control.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node is not a cluster node\n",
        )
            .into_response();
    };
    let Some(public) = auth.public_key() else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "join requires control-plane auth (no root key configured)\n",
        )
            .into_response();
    };
    let _ = public; // presence gates 501; verification tries the anchor set below.
    let now = now_unix();
    let jti = match auth.verify_join_token(&request.token, now).await {
        Ok(jti) => jti,
        Err(err) => {
            // A signature/framing failure is unauthenticated (401); an authentic
            // token that is expired or the wrong kind is forbidden (403).
            let code = match err {
                cose::TokenError::Invalid(_) => StatusCode::UNAUTHORIZED,
                _ => StatusCode::FORBIDDEN,
            };
            return (code, format!("invalid join token: {err}\n")).into_response();
        }
    };
    let Ok(proof) = hex::decode(request.possession_proof.trim()) else {
        return (StatusCode::BAD_REQUEST, "possession_proof must be hex\n").into_response();
    };
    // The cluster verifies the possession proof against the presented key + spends
    // the token, then vouches for its members with root-signed assertions.
    match admitter
        .admit(
            request.mesh_pubkey.trim(),
            &jti,
            &proof,
            request.proof_iat,
            now,
            request.advertise_addr.as_deref(),
        )
        .await
    {
        Ok(JoinOutcome::Admitted { members, addrs }) => (
            StatusCode::OK,
            Json(JoinResponse {
                members,
                member_addrs: addrs,
            }),
        )
            .into_response(),
        Ok(JoinOutcome::TokenSpent) => {
            (StatusCode::CONFLICT, "join token already spent\n").into_response()
        }
        Ok(JoinOutcome::ProofInvalid) => (
            StatusCode::FORBIDDEN,
            "join possession proof is missing, stale, or invalid\n",
        )
            .into_response(),
        Ok(JoinOutcome::Revoked) => (
            StatusCode::FORBIDDEN,
            "this mesh key is revoked; an explicit un-revoke is required before it can rejoin\n",
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("admit failed: {err}\n"),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct RotateKeyResponse {
    /// The node's new mesh public key (SPKI hex) after rotation.
    pubkey: String,
}

/// Rotate **this node's** mesh identity, make-before-break.
/// Admin-scoped (the deny-safe `Right::required` default for `/api/cluster/*`).
/// Node-local: only the node itself can mint + persist its private key, so this
/// rotates the key of the node whose API is hit. `501` on a non-cluster node.
pub(super) async fn cluster_rotate_key(
    Extension(mesh_control): Extension<MeshControlHandle>,
) -> Response {
    let Some(control) = mesh_control.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node is not a cluster node\n",
        )
            .into_response();
    };
    match control.rotate_key().await {
        Ok(pubkey) => (StatusCode::OK, Json(RotateKeyResponse { pubkey })).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("rotation failed: {err}\n"),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub(super) struct RevokeRequest {
    /// The node id to revoke from the mesh.
    node_id: u64,
}

/// Revoke a node from the mesh: delete its trust cluster-wide (so
/// it can no longer authenticate — the live verifier rejects it on reconnect) and
/// drop it from the quorum. Admin-scoped (the deny-safe `Right::required`
/// default). `501` on a non-cluster node.
pub(super) async fn cluster_revoke(
    Extension(mesh_control): Extension<MeshControlHandle>,
    Json(request): Json<RevokeRequest>,
) -> Response {
    let Some(control) = mesh_control.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node is not a cluster node\n",
        )
            .into_response();
    };
    match control.revoke(request.node_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("revocation failed: {err}\n"),
        )
            .into_response(),
    }
}

/// List the current Raft membership (`GET /api/cluster/members`) — voters +
/// learners with catch-up + leader flags. Admin-scoped (the deny-safe
/// `Right::required` default). `501` on a non-cluster node. The Kubernetes
/// operator reconciles this against the desired replica count.
pub(super) async fn cluster_members(
    Extension(mesh_control): Extension<MeshControlHandle>,
) -> Response {
    let Some(control) = mesh_control.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node is not a cluster node\n",
        )
            .into_response();
    };
    match control.members().await {
        Ok(members) => Json(members).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("listing membership failed: {err}\n"),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub(super) struct PromoteRequest {
    /// The node id (a caught-up learner) to promote to a voter.
    node_id: u64,
}

/// Promote a caught-up learner to a voter (`POST /api/cluster/promote`) — the
/// scale-up completion step the operator drives once a joined node has caught up.
/// Leader-only server-side (a no-op on a follower). Admin-scoped. `501` on a
/// non-cluster node.
pub(super) async fn cluster_promote(
    Extension(mesh_control): Extension<MeshControlHandle>,
    Json(request): Json<PromoteRequest>,
) -> Response {
    let Some(control) = mesh_control.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node is not a cluster node\n",
        )
            .into_response();
    };
    match control.promote(request.node_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("promotion failed: {err}\n"),
        )
            .into_response(),
    }
}

/// List issued-token metadata (id, label, roles, timestamps — never the token).
pub(super) async fn list_tokens(State(deploy): State<DeployStore>) -> Response {
    match deploy.list_token_meta().await {
        Ok(mut tokens) => {
            tokens.sort_by_key(|m| m.created_at);
            Json(tokens).into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Revoke a token by its revocation id or a unique id prefix.
pub(super) async fn revoke_token(
    State(deploy): State<DeployStore>,
    Path(id): Path<String>,
) -> Response {
    match deploy.revoke_token(&id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no matching token\n").into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Default mesh-join-token TTL when the request omits one (1 hour). A join is a
/// prompt operator action, so the admission window stays short.
const DEFAULT_JOIN_TOKEN_TTL_SECS: u64 = 3600;

#[derive(Deserialize, Default)]
pub(super) struct CreateJoinTokenRequest {
    /// Optional TTL in seconds; omitted ⇒ [`DEFAULT_JOIN_TOKEN_TTL_SECS`].
    #[serde(default)]
    pub(super) ttl_secs: Option<u64>,
}

#[derive(Serialize)]
struct CreateJoinTokenResponse {
    /// The minted join token, base64url — shown once, never stored.
    token: String,
    /// The token's expiry (Unix seconds).
    expires_at: u64,
}

/// Mint a **single-use bearer mesh join token** with a TTL. It is not bound to a
/// node/key (the operator can't know a not-yet-booted node's key); the joiner
/// proves possession of its own mesh key at redemption, and the `jti` is spent
/// single-use cluster-side. Needs the root private key (the issuer); a verify-only
/// node returns `501`. Admin-scoped (the deny-safe `Right::required` default gates
/// `/api/cluster/*`). Returned once, never stored.
pub(super) async fn create_join_token(
    Extension(issuer): Extension<Issuer>,
    Json(request): Json<CreateJoinTokenRequest>,
) -> Response {
    let Some(signer) = issuer.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node has no root private key and cannot issue join tokens\n",
        )
            .into_response();
    };
    let ttl = request.ttl_secs.unwrap_or(DEFAULT_JOIN_TOKEN_TTL_SECS);
    let now = now_unix();
    match cose::mint_join(ttl, now, &*signer).await {
        Ok(token) => (
            StatusCode::CREATED,
            Json(CreateJoinTokenResponse {
                token,
                expires_at: now.saturating_add(ttl),
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

/// Default lifetime of a minted overlay-dial capability (an overlay-dial cap MUST be time-bounded).
const DEFAULT_OVERLAY_DIAL_TTL_SECS: u64 = 3600;

/// Clamp a dial/publish request's requested TTL (Security MEDIUM-D): an absent request defaults to
/// [`DEFAULT_OVERLAY_DIAL_TTL_SECS`], and any requested value is capped at the server `max` — so a
/// caller cannot mint a near-immortal, irrevocable (offline-verified) dial OR publish capability
/// (both are offline-verified with no revocation, so the same TTL-bound applies).
fn clamp_dial_ttl(requested: Option<u64>, max: u64) -> u64 {
    requested.unwrap_or(DEFAULT_OVERLAY_DIAL_TTL_SECS).min(max)
}

/// Defense-in-depth (INFO-1, mirrors [`assert_kv_checkpoint_is_system_admin`]): re-derive that `POST
/// /api/overlay/dial` is gated `Overlay·Write` inside the handler, so a router/table refactor that
/// drops it from the authed group cannot silently open unauthenticated dial-capability minting.
fn assert_overlay_dial_is_overlay_write() -> Option<Response> {
    use boatramp_core::authz::{Action, Resource, Right};
    match Right::required("POST", "/api/overlay/dial") {
        Some(right)
            if right.resource == Resource::Overlay
                && right.target.is_none()
                && right.action == Action::Write =>
        {
            None
        }
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                "overlay dial requires Overlay·Write\n",
            )
                .into_response(),
        ),
    }
}

/// Defense-in-depth (mirrors [`assert_overlay_dial_is_overlay_write`]): re-derive that `POST
/// /api/overlay/expose` is gated `Overlay·Admin` INSIDE the handler, so a router/table refactor that
/// drops it (or weakens it to `Overlay·Write`, the dial tier) cannot silently let a dial-only
/// principal PUBLISH a service name — the strictly-higher bar is load-bearing (publishing claims a
/// name forward clients trust + pin).
fn assert_overlay_expose_is_overlay_admin() -> Option<Response> {
    use boatramp_core::authz::{Action, Resource, Right};
    match Right::required("POST", "/api/overlay/expose") {
        Some(right)
            if right.resource == Resource::Overlay
                && right.target.is_none()
                && right.action == Action::Admin =>
        {
            None
        }
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                "overlay expose (publish) requires Overlay·Admin\n",
            )
                .into_response(),
        ),
    }
}

/// Defense-in-depth (INFO-1): re-derive that `GET /api/overlay/services` is gated `Overlay·Read`.
fn assert_overlay_services_is_overlay_read() -> Option<Response> {
    use boatramp_core::authz::{Action, Resource, Right};
    match Right::required("GET", "/api/overlay/services") {
        Some(right)
            if right.resource == Resource::Overlay
                && right.target.is_none()
                && right.action == Action::Read =>
        {
            None
        }
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                "overlay service directory requires Overlay·Read\n",
            )
                .into_response(),
        ),
    }
}

/// The short, NON-enumerable 403 a flow-gate denial returns at the mint point (REQUIRED #6): it
/// names neither the deciding policies nor the evaluation diagnostics (those are an operator-only
/// oracle, surfaced ONLY on the `System·Admin`-gated `POST /api/overlay/policy/test`). The CLI
/// recognizes this body to show a distinct "RBAC OK but flow denied" message.
fn overlay_flow_denied() -> Response {
    (StatusCode::FORBIDDEN, "flow denied by policy\n").into_response()
}

/// The per-flow access gate shared by [`overlay_dial`] + [`overlay_expose`] (overlay follow-up #3).
/// Runs AFTER the RBAC assert + holder parse, BEFORE the mint. It:
/// 1. Builds the flow-policy `Overlay::Holder` principal: a verified, holder-bound `overlay-member`
///    credential (REQUIRED #3) contributes `role`/`scope`/`enrolled=true`; a key-only caller has
///    none of them (absent, default-deny safe). An invalid credential, or one whose `member_key`
///    is not THIS holder, is rejected **400** (never silently downgraded to key-only).
/// 2. Loads the flow policy through the fenced, four-state, fail-closed path ([`Auth::overlay_flow_policy`]).
/// 3. Evaluates — ALLOW (possibly shrinking the TTL) or DENY (403, non-enumerable).
///
/// Returns the TTL to mint with (`min(requested, policy_ttl_ceiling)` — the requested value was
/// already clamped to the server max, so this is the full `min(requested, ceiling, server_max)` of
/// REQUIRED #2a), or the error [`Response`] to return. The decision gates + bounds the TTL ONLY; it
/// never rewrites the capability's scope/holder/action/resource (REQUIRED #2b/#3c).
#[allow(clippy::too_many_arguments)]
async fn overlay_flow_gate(
    auth: &Auth,
    principal: Option<&crate::auth::VerifiedPrincipal>,
    holder: &cose::TokenPublicKey,
    member_cred: Option<&str>,
    action: boatramp_core::overlay_policy::FlowAction,
    service: &str,
    requested_ttl: u64,
    now: u64,
) -> Result<u64, Response> {
    use crate::auth::FlowPolicyLoad;
    use boatramp_core::overlay_policy::{Decision, FlowContext, HolderPrincipal};

    let holder_hex = holder.to_hex();
    // (1) Build the holder principal from an optional, holder-bound member credential.
    let holder_principal = match member_cred {
        None => HolderPrincipal::key_only(holder_hex.clone()),
        Some(cred) => {
            let verified = match auth.verify_overlay_member_token(cred, now).await {
                Ok(v) => v,
                // An INVALID credential (bad sig / expired / wrong-kind / unknown role) → 400:
                // reject loudly rather than silently falling back to a key-only principal.
                Err(err) => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("invalid overlay-member credential: {err}\n"),
                    )
                        .into_response());
                }
            };
            // REQUIRED #3b — bind `member_key == holder_pubkey`: a credential vouching for a
            // DIFFERENT key must not lend its role/scope to THIS holder. Canonicalize both sides
            // through `TokenPublicKey` so an encoding difference can't defeat the compare.
            let bound = cose::TokenPublicKey::from_hex(&verified.member_key)
                .map(|k| k.to_hex() == holder_hex)
                .unwrap_or(false);
            if !bound {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "overlay-member credential is not bound to this holder key \
                     (member_key != holder_pubkey)\n",
                )
                    .into_response());
            }
            HolderPrincipal {
                key: holder_hex.clone(),
                role: Some(verified.role.as_str().to_string()),
                scope: Some(verified.scope),
                enrolled: Some(true),
            }
        }
    };

    // (2) Load the flow policy (fenced + fail-closed four-state). A mint is a write, so pass
    // `is_write = true` to force a shared-mode read-through to the live store.
    match auth.overlay_flow_policy(true).await {
        // Feature off (absent / confirmed-empty) → allow at the requested TTL (preserve today's
        // behavior).
        FlowPolicyLoad::Off => Ok(requested_ttl),
        // Store unreachable → fail closed (deny). NEVER treated as absent→allow.
        FlowPolicyLoad::Unavailable => {
            tracing::warn!("overlay flow policy unreadable; denying the mint (fail-closed)");
            Err(overlay_flow_denied())
        }
        // Stored-but-corrupt → fail closed (deny-all).
        FlowPolicyLoad::Corrupt => {
            tracing::warn!("overlay flow policy is corrupt; denying the mint (fail-closed)");
            Err(overlay_flow_denied())
        }
        // (3) Present → evaluate.
        FlowPolicyLoad::Present(fp) => {
            let requestor = principal
                .map(|p| p.subject.clone())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "anonymous".to_string());
            let ctx = FlowContext {
                requestor,
                now,
                src_ip: None,
                ttl_requested: requested_ttl,
            };
            let outcome = fp.evaluate(&holder_principal, action, service, &ctx);
            match outcome.decision {
                Decision::Allow { ttl_ceiling } => {
                    // REQUIRED #2a — the policy only pulls the TTL DOWN; `requested_ttl` is already
                    // server-clamped, so this is `min(requested, ceiling, server_max)`.
                    Ok(ttl_ceiling
                        .map(|c| requested_ttl.min(c))
                        .unwrap_or(requested_ttl))
                }
                Decision::Deny => Err(overlay_flow_denied()),
            }
        }
    }
}

/// `POST /api/overlay/dial` request: resolve `service` + mint a dial capability bound to the
/// caller's overlay identity (`holder_pubkey`, `ed25519:<hex>`).
#[derive(Deserialize)]
pub(super) struct OverlayDialRequest {
    pub(super) service: String,
    pub(super) holder_pubkey: String,
    #[serde(default)]
    pub(super) ttl_secs: Option<u64>,
    /// An OPTIONAL root-signed `overlay-member` credential for the holder (overlay follow-up #3):
    /// when present it is verified + bound (`member_key == holder_pubkey`) and its role/scope
    /// populate the flow-policy `Overlay::Holder` principal. Absent ⇒ a key-only holder (no
    /// role/scope attributes → default-deny-safe against a role-gated flow permit).
    #[serde(default)]
    pub(super) overlay_member: Option<String>,
}

/// `POST /api/overlay/dial` response: the resolved topology + the minted capability.
#[derive(Serialize)]
struct OverlayDialResponse {
    relay: String,
    relay_id: String,
    egress_id: String,
    /// The relay's client-auth posture — the client uses it to choose its TLS posture when dialing.
    relay_client_auth: String,
    token: String,
    expires_at: u64,
}

/// One entry of `GET /api/overlay/services`.
#[derive(Serialize)]
struct OverlayServiceEntry {
    service: String,
    relay: String,
    relay_id: String,
    egress_id: String,
    client_auth: String,
}

/// Resolve a service to its overlay topology and mint a holder-bound dial capability for it, signed
/// by the node's root issuer (self-serve `boatramp forward svc/<name>`). The capability is still
/// holder-bound + scope-verified at the egress — this route gates WHO may obtain one (`Overlay·Write`).
pub(super) async fn overlay_dial(
    Extension(issuer): Extension<Issuer>,
    Extension(directory): Extension<OverlayDirectory>,
    Extension(auth): Extension<Auth>,
    principal: Option<Extension<crate::auth::VerifiedPrincipal>>,
    Json(request): Json<OverlayDialRequest>,
) -> Response {
    if let Some(forbidden) = assert_overlay_dial_is_overlay_write() {
        return forbidden;
    }
    let Some(signer) = issuer.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node has no root private key and cannot mint dial capabilities\n",
        )
            .into_response();
    };
    let now = now_unix();
    // Resolve over the MERGED directory (static `[overlay]` routes ∪ live reverse-ingress exposers):
    // a dial to an EXPOSED service resolves to a target whose `egress_id` is the holder-bound exposer
    // identity the relay verified AT REGISTRATION. A live exposer wins a name collision, so the
    // `egress_id` the client pins matches the peer it will actually reach.
    let Some(target) = directory.resolve_merged(&request.service, now).await else {
        return (
            StatusCode::NOT_FOUND,
            format!(
                "no overlay service `{}` in the directory\n",
                request.service
            ),
        )
            .into_response();
    };
    let holder = match cose::TokenPublicKey::from_hex(&request.holder_pubkey) {
        Ok(h) => h,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid holder_pubkey: {err}\n"),
            )
                .into_response();
        }
    };
    // INFO-2 — an overlay identity is ed25519-only; an es256 holder would yield a silently-unusable
    // cap (the overlay handshake can't present it), so reject it early with an actionable 400.
    if holder.alg() != cose::TokenAlg::Ed25519 {
        return (
            StatusCode::BAD_REQUEST,
            "holder_pubkey must be an ed25519 overlay identity (es256 keys cannot dial)\n",
        )
            .into_response();
    }
    // MEDIUM-D — clamp the requested lifetime to the server cap (an offline-verified dial cap has no
    // revocation, so an unbounded TTL is a standing risk).
    let clamped = clamp_dial_ttl(request.ttl_secs, directory.max_dial_ttl_secs());
    // Overlay follow-up #3 — the per-flow access gate, AFTER the RBAC `Overlay·Write` assert +
    // holder parse, BEFORE mint. It can only DENY or SHRINK the TTL; it never rewrites scope/holder
    // (the cap below is still bound to THIS holder + THIS one service). A 403 here is short + non-
    // enumerable (no policy diagnostics — REQUIRED #6).
    let ttl = match overlay_flow_gate(
        &auth,
        principal.as_ref().map(|Extension(p)| p),
        &holder,
        request.overlay_member.as_deref(),
        boatramp_core::overlay_policy::FlowAction::Dial,
        &request.service,
        clamped,
        now,
    )
    .await
    {
        Ok(ttl) => ttl,
        Err(resp) => return resp,
    };
    match cose::mint_overlay_dial(&holder, &request.service, ttl, now, &*signer).await {
        Ok(token) => (
            StatusCode::CREATED,
            Json(OverlayDialResponse {
                relay: target.relay.clone(),
                relay_id: target.relay_id.clone(),
                egress_id: target.egress_id.clone(),
                relay_client_auth: target.client_auth.clone(),
                token,
                expires_at: now.saturating_add(ttl),
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

/// `POST /api/overlay/expose` request: resolve this node's ingress relay topology + mint an
/// overlay-PUBLISH capability bound to the caller's overlay identity (`holder_pubkey`), so the
/// exposer can register `service` with the relay (self-serve `boatramp expose --server`).
#[derive(Deserialize)]
pub(super) struct OverlayExposeRequest {
    pub(super) service: String,
    pub(super) holder_pubkey: String,
    #[serde(default)]
    pub(super) ttl_secs: Option<u64>,
    /// An OPTIONAL root-signed `overlay-member` credential for the holder (overlay follow-up #3) —
    /// verified + bound to `holder_pubkey`, its role/scope populate the flow-policy principal.
    /// Absent ⇒ a key-only holder. Mirrors [`OverlayDialRequest::overlay_member`].
    #[serde(default)]
    pub(super) overlay_member: Option<String>,
}

/// `POST /api/overlay/expose` response: the ingress relay to dial OUT to + the minted publish
/// capability + the cluster trust root (the exposer verifies incoming forward clients against it).
/// The equivalent of an `ExposeTicket`'s fields, over an authenticated response.
#[derive(Serialize)]
struct OverlayExposeResponse {
    relay: String,
    relay_id: String,
    service: String,
    token: String,
    trust_root: String,
    /// The relay's client-auth posture — the exposer uses it to choose its TLS posture when dialing
    /// OUT (capability-only ⇒ present no client cert). Mirrors dial's `relay_client_auth`.
    relay_client_auth: String,
    expires_at: u64,
}

/// Resolve this node's ingress relay topology and mint a holder-bound overlay-PUBLISH capability for
/// `service`, signed by the node's root issuer (self-serve `boatramp expose --server`). Gated
/// `Overlay·Admin` — STRICTLY HIGHER than dial's `Overlay·Write` — because publishing CLAIMS a name
/// that cluster-side forward clients trust and pin; the relay still holder-binds + scope-verifies the
/// capability AT REGISTRATION, so this route gates WHO may obtain one.
pub(super) async fn overlay_expose(
    Extension(issuer): Extension<Issuer>,
    Extension(directory): Extension<OverlayDirectory>,
    Extension(auth): Extension<Auth>,
    principal: Option<Extension<crate::auth::VerifiedPrincipal>>,
    Json(request): Json<OverlayExposeRequest>,
) -> Response {
    if let Some(forbidden) = assert_overlay_expose_is_overlay_admin() {
        return forbidden;
    }
    let Some(signer) = issuer.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node has no root private key and cannot mint publish capabilities\n",
        )
            .into_response();
    };
    // The ingress relay an exposer dials OUT to (+ the cluster trust root). Present only when this
    // node runs an ingress relay accepting exposed services (`[overlay] accept_exposed`).
    let Some(relay) = directory.expose_relay() else {
        return (
            StatusCode::NOT_FOUND,
            "this node runs no overlay ingress relay accepting exposed services (set \
             `[overlay] accept_exposed = true` on a relay node)\n",
        )
            .into_response();
    };
    let holder = match cose::TokenPublicKey::from_hex(&request.holder_pubkey) {
        Ok(h) => h,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid holder_pubkey: {err}\n"),
            )
                .into_response();
        }
    };
    // INFO-2 (mirrors dial) — an overlay identity is ed25519-only; an es256 holder would yield a
    // silently-unusable cap (the registration handshake can't present it), so reject it early.
    if holder.alg() != cose::TokenAlg::Ed25519 {
        return (
            StatusCode::BAD_REQUEST,
            "holder_pubkey must be an ed25519 overlay identity (es256 keys cannot publish)\n",
        )
            .into_response();
    }
    // MEDIUM-D (mirrors dial) — clamp the requested lifetime to the server cap. An overlay-publish
    // cap is offline-verified (no revocation), and the relay bounds a parked registration by the
    // cap's expiry, so an unbounded TTL is the same standing risk as an unbounded dial cap.
    let clamped = clamp_dial_ttl(request.ttl_secs, directory.max_dial_ttl_secs());
    let now = now_unix();
    // Overlay follow-up #3 — the per-flow access gate (mirrors dial), AFTER the `Overlay·Admin`
    // assert + holder parse, BEFORE mint. Deny-or-shrink-TTL only; the minted publish cap stays
    // bound to THIS holder + THIS one service name. 403 is short + non-enumerable (REQUIRED #6).
    let ttl = match overlay_flow_gate(
        &auth,
        principal.as_ref().map(|Extension(p)| p),
        &holder,
        request.overlay_member.as_deref(),
        boatramp_core::overlay_policy::FlowAction::Expose,
        &request.service,
        clamped,
        now,
    )
    .await
    {
        Ok(ttl) => ttl,
        Err(resp) => return resp,
    };
    match cose::mint_overlay_publish(&holder, &request.service, ttl, now, &*signer).await {
        Ok(token) => (
            StatusCode::CREATED,
            Json(OverlayExposeResponse {
                relay: relay.relay.clone(),
                relay_id: relay.relay_id.clone(),
                service: request.service.clone(),
                token,
                trust_root: relay.trust_root.clone(),
                relay_client_auth: relay.client_auth.clone(),
                expires_at: now.saturating_add(ttl),
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

/// Length of a pairing rendezvous id (bytes). MUST match
/// `boatramp_overlay_proto::PAIR_RENDEZVOUS_ID_LEN` — `boatramp-server` deliberately carries no
/// overlay-transport dep, so the constant is mirrored here and the CLI's `PairCode::new` re-validates
/// the length when it assembles the `bropair1` code from this response (a mismatch fails loudly there).
const OVERLAY_PAIR_RENDEZVOUS_ID_LEN: usize = 16;

/// Default lifetime of a minted pairing rendezvous code when the request omits one (5 minutes): a
/// pairing code is a short-lived meeting credential — minutes, not the hours a dial cap lives.
const DEFAULT_OVERLAY_PAIR_CODE_TTL_SECS: u64 = 300;

/// Hard ceiling on a pairing rendezvous code's lifetime (10 minutes): the relay-blind rendezvous is
/// unauthenticated on the redeem side (the SAS backstops it), so a code must not stand open for long —
/// clamped well below the dial/publish/enroll server cap.
const MAX_OVERLAY_PAIR_CODE_TTL_SECS: u64 = 600;

/// Defense-in-depth (mirrors [`assert_overlay_expose_is_overlay_admin`]): re-derive that `POST
/// /api/overlay/pair-code` is gated `Overlay·Admin` INSIDE the handler, so a router/table refactor
/// that drops it (or weakens it to `Overlay·Write`) cannot silently let a non-admin mint a pairing
/// rendezvous code — minting one stands up a relay rendezvous slot keyed to this cluster's relay.
fn assert_overlay_pair_code_is_overlay_admin() -> Option<Response> {
    use boatramp_core::authz::{Action, Resource, Right};
    match Right::required("POST", "/api/overlay/pair-code") {
        Some(right)
            if right.resource == Resource::Overlay
                && right.target.is_none()
                && right.action == Action::Admin =>
        {
            None
        }
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                "overlay pair-code requires Overlay·Admin\n",
            )
                .into_response(),
        ),
    }
}

/// `POST /api/overlay/pair-code` request: mint a single-use, short-TTL pairing rendezvous code so two
/// peers that cannot direct-dial each other (both NAT'd) can meet THROUGH this cluster's ingress
/// relay. No role/scope — the redeeming peer is by design NOT membership-gated (the SAS backstops it);
/// the `Overlay·Admin` gate is on this MINT (who may stand up a rendezvous at the relay).
#[derive(Deserialize)]
pub(super) struct OverlayPairCodeRequest {
    /// Optional TTL in seconds; omitted ⇒ [`DEFAULT_OVERLAY_PAIR_CODE_TTL_SECS`], clamped to
    /// [`MAX_OVERLAY_PAIR_CODE_TTL_SECS`] (a pairing code is a minutes-long meeting credential).
    #[serde(default)]
    pub(super) ttl_secs: Option<u64>,
}

/// `POST /api/overlay/pair-code` response: the rendezvous id + the ingress relay to meet at. The CLI
/// assembles these into the copy-pasteable `bropair1…` code (`boatramp-server` carries no bech32 dep,
/// mirroring how the dial endpoint returns JSON the CLI packs into a `brfwd1…` ticket).
#[derive(Serialize)]
struct OverlayPairCodeResponse {
    /// The relay/ingress `host:port` both peers dial to meet.
    relay: String,
    /// The relay's overlay identity both peers pin (`ed25519:<hex>`).
    relay_id: String,
    /// The single-use rendezvous id (hex of [`OVERLAY_PAIR_RENDEZVOUS_ID_LEN`] bytes) — the relay's
    /// registry key both the park and the redeem present.
    rendezvous: String,
    /// The code's expiry (Unix seconds).
    expires_at: u64,
}

/// Mint a single-use pairing rendezvous code (self-serve `boatramp overlay pair-code`). Gated
/// `Overlay·Admin` — minting one stands up a relay rendezvous keyed to this cluster's ingress relay,
/// an owner-grade act (the same tier as `expose`/`invite`). `404` when this node runs no ingress relay
/// accepting rendezvous (`[overlay] accept_exposed`), mirroring `overlay_expose`. The code is NOT a
/// signed capability (so no root key is needed): its security is the short TTL + the relay's single-use
/// redemption + the relay-blind bridge + the out-of-band SAS — never a secret the relay verifies.
pub(super) async fn overlay_pair_code(
    Extension(directory): Extension<OverlayDirectory>,
    Json(request): Json<OverlayPairCodeRequest>,
) -> Response {
    if let Some(forbidden) = assert_overlay_pair_code_is_overlay_admin() {
        return forbidden;
    }
    // The ingress relay the peers meet at — the SAME relay `expose` dials OUT to. Present only when
    // this node runs an ingress relay (`[overlay] accept_exposed`); otherwise there is nowhere to meet.
    let Some(relay) = directory.expose_relay() else {
        return (
            StatusCode::NOT_FOUND,
            "this node runs no overlay ingress relay to host a pairing rendezvous (set \
             `[overlay] accept_exposed = true` on a relay node)\n",
        )
            .into_response();
    };
    let ttl = request
        .ttl_secs
        .unwrap_or(DEFAULT_OVERLAY_PAIR_CODE_TTL_SECS)
        .min(MAX_OVERLAY_PAIR_CODE_TTL_SECS);
    // The rendezvous id is high-entropy platform randomness — infeasible to guess, so the matching
    // park/redeem is the whole mechanism and the Overlay·Admin mint controls who may obtain one.
    let mut rendezvous = [0u8; OVERLAY_PAIR_RENDEZVOUS_ID_LEN];
    if getrandom::getrandom(&mut rendezvous).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to generate a pairing rendezvous id\n",
        )
            .into_response();
    }
    let now = now_unix();
    (
        StatusCode::CREATED,
        Json(OverlayPairCodeResponse {
            relay: relay.relay.clone(),
            relay_id: relay.relay_id.clone(),
            rendezvous: hex::encode(rendezvous),
            expires_at: now.saturating_add(ttl),
        }),
    )
        .into_response()
}

/// Default lifetime of a minted `overlay-enroll` invitation when the request omits one (1 hour) —
/// an enrollment invitation MUST be time-bounded (like the cluster join token), and a short
/// admission window bounds how long a leaked (unspent) invitation stays redeemable.
const DEFAULT_OVERLAY_ENROLL_TTL_SECS: u64 = DEFAULT_JOIN_TOKEN_TTL_SECS;

/// TTL on the root-signed `overlay-member` credential handed back on a successful enroll (24h): long
/// enough for the enrollee to adopt it, bounded because a membership credential MUST be time-bounded
/// (it is offline-verified with no revocation).
const DEFAULT_OVERLAY_MEMBER_TTL_SECS: u64 = 24 * 60 * 60;

/// Defense-in-depth (mirrors [`assert_overlay_expose_is_overlay_admin`]): re-derive that `POST
/// /api/overlay/invite` is gated `Overlay·Admin` INSIDE the handler, so a router/table refactor that
/// drops it (or weakens it to `Overlay·Write`, the dial tier) cannot silently let a non-admin mint an
/// enrollment invitation — which admits a NEW identity into the overlay trust set once redeemed.
fn assert_overlay_invite_is_overlay_admin() -> Option<Response> {
    use boatramp_core::authz::{Action, Resource, Right};
    match Right::required("POST", "/api/overlay/invite") {
        Some(right)
            if right.resource == Resource::Overlay
                && right.target.is_none()
                && right.action == Action::Admin =>
        {
            None
        }
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                "overlay invite requires Overlay·Admin\n",
            )
                .into_response(),
        ),
    }
}

/// `POST /api/overlay/invite` request: mint a single-use `overlay-enroll` invitation for a role +
/// scope (the online analog of `boatramp overlay invite`; the enrollment counterpart of
/// `/api/cluster/join-token`).
#[derive(Deserialize)]
pub(super) struct OverlayInviteRequest {
    /// The role the invitation grants once redeemed (`node` | `device` | `workload`).
    pub(super) role: String,
    /// The service scope the enrollee may dial/expose once enrolled (e.g. `svc/db`, or `*`).
    pub(super) scope: String,
    /// Optional TTL in seconds; omitted ⇒ [`DEFAULT_OVERLAY_ENROLL_TTL_SECS`], clamped to the
    /// server cap.
    #[serde(default)]
    pub(super) ttl_secs: Option<u64>,
}

/// `POST /api/overlay/invite` response: the minted invitation + its expiry (shown once).
#[derive(Serialize)]
struct OverlayInviteResponse {
    /// The minted `overlay-enroll` invitation (base64url COSE). A confidential **bearer** secret:
    /// whoever holds it (plus their own overlay key) can enroll until it is spent — deliver it over
    /// the authenticated control plane / the ticket, bounded by `exp` + single-use.
    token: String,
    /// The role it grants (echoed from the closed [`cose::OverlayMemberRole`] set).
    role: String,
    /// The scope it grants.
    scope: String,
    /// The invitation's expiry (Unix seconds).
    expires_at: u64,
}

/// Mint a single-use `overlay-enroll` invitation for `role` + `scope`, signed by the node's root
/// issuer. Gated `Overlay·Admin` (an owner-grade act: redeeming it admits a new identity into the
/// overlay trust set), TTL-clamped, `501` on a verify-only node (no root key). Mirrors
/// [`create_join_token`] + the `Overlay·Admin` gate of [`overlay_expose`].
pub(super) async fn overlay_invite(
    Extension(issuer): Extension<Issuer>,
    Extension(directory): Extension<OverlayDirectory>,
    Json(request): Json<OverlayInviteRequest>,
) -> Response {
    if let Some(forbidden) = assert_overlay_invite_is_overlay_admin() {
        return forbidden;
    }
    let Some(signer) = issuer.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node has no root private key and cannot mint overlay invitations\n",
        )
            .into_response();
    };
    let Some(role) = cose::OverlayMemberRole::parse(request.role.trim()) else {
        return (
            StatusCode::BAD_REQUEST,
            "role must be one of node|device|workload\n",
        )
            .into_response();
    };
    if request.scope.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "scope is required\n").into_response();
    }
    // Clamp to the same server cap a dial/publish cap uses: an `overlay-enroll` invitation is a
    // single-use, offline-verified bearer, so an unbounded TTL is the same standing risk (MEDIUM-D).
    let ttl = request
        .ttl_secs
        .unwrap_or(DEFAULT_OVERLAY_ENROLL_TTL_SECS)
        .min(directory.max_dial_ttl_secs());
    let now = now_unix();
    match cose::mint_overlay_enroll(role, request.scope.trim(), ttl, now, &*signer).await {
        Ok(token) => (
            StatusCode::CREATED,
            Json(OverlayInviteResponse {
                token,
                role: role.as_str().to_string(),
                scope: request.scope.trim().to_string(),
                expires_at: now.saturating_add(ttl),
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

/// `POST /api/overlay/enroll` request: redeem an `overlay-enroll` invitation + prove possession of
/// the enrolling overlay key. Token-gated like [`cluster_join`] (no RBAC right — the handler verifies
/// the invitation), so a stolen invitation + an observed key enrolls nothing.
#[derive(Deserialize)]
pub(super) struct OverlayEnrollRequest {
    /// The single-use **bearer** `overlay-enroll` invitation (base64url COSE), from `overlay invite`.
    pub(super) token: String,
    /// The enrolling overlay key (`ed25519:<hex>`) — the enrollee's self-derived identity. Not
    /// pre-named by the invitation; possession is proven below.
    pub(super) overlay_pubkey: String,
    /// A **possession proof**: an Ed25519 signature (hex) over
    /// `cose::join_challenge(jti, overlay_pubkey, proof_iat)`, proving the enrollee controls
    /// `overlay_pubkey` — so an invitation + an observed key admits nothing.
    pub(super) possession_proof: String,
    /// The proof's issued-at (Unix seconds); must be fresh (anti-replay).
    pub(super) proof_iat: u64,
}

/// `POST /api/overlay/enroll` response: the root-signed membership credential the enrollee adopts.
#[derive(Serialize)]
struct OverlayEnrollResponse {
    /// The root-signed `overlay-member` credential vouching the enrolled key is a member with the
    /// invitation's role + scope. The enrollee verifies it against the root anchor before trusting it.
    member: String,
    /// The role the membership grants.
    role: String,
    /// The scope the membership grants.
    scope: String,
    /// The credential's expiry (Unix seconds).
    expires_at: u64,
}

/// Redeem an `overlay-enroll` invitation: verify it (signature + mandatory `exp` + kind + closed
/// role) against the trust anchor, verify the enrollee's possession proof against the PRESENTED key,
/// then ADMIT — single-use spend the invitation's `jti`, bar a revoked key, and trust the key in the
/// relay's live set — and hand back a root-signed `overlay-member` credential. Token-gated (the
/// handler verifies the invitation). `501` on a node that runs no overlay relay accepting enrollments
/// or has no root key to vouch for the member. Mirrors [`cluster_join`].
pub(super) async fn overlay_enroll(
    Extension(auth): Extension<Auth>,
    Extension(issuer): Extension<Issuer>,
    Extension(enroll): Extension<OverlayEnrollHandle>,
    Json(request): Json<OverlayEnrollRequest>,
) -> Response {
    let Some(enroller) = enroll.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "this node runs no overlay relay accepting enrollments\n",
        )
            .into_response();
    };
    let Some(signer) = issuer.0 else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "enroll requires a root private key to vouch for the member (none configured)\n",
        )
            .into_response();
    };
    let now = now_unix();
    // (1) Verify the invitation against the anchor set (primary + rotation anchors). A
    // signature/framing failure is unauthenticated (401); an authentic but expired/wrong-kind
    // invitation is forbidden (403). Mirrors `cluster_join`'s token-verify classification.
    let verified = match auth.verify_overlay_enroll_token(&request.token, now).await {
        Ok(v) => v,
        Err(err) => {
            let code = match err {
                cose::TokenError::Invalid(_) => StatusCode::UNAUTHORIZED,
                _ => StatusCode::FORBIDDEN,
            };
            return (code, format!("invalid overlay-enroll invitation: {err}\n")).into_response();
        }
    };
    // (2) The enrolling key must be a valid ed25519 overlay identity (an es256 key cannot be an
    // overlay peer); reject early with an actionable 400 (mirrors dial/expose's ed25519-only gate).
    let member_pub = match cose::TokenPublicKey::from_hex(request.overlay_pubkey.trim()) {
        Ok(k) if k.alg() == cose::TokenAlg::Ed25519 => k,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "overlay_pubkey must be an ed25519 overlay identity\n",
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid overlay_pubkey: {err}\n"),
            )
                .into_response();
        }
    };
    let Ok(proof) = hex::decode(request.possession_proof.trim()) else {
        return (StatusCode::BAD_REQUEST, "possession_proof must be hex\n").into_response();
    };
    // (3) Admit: the impl verifies the possession proof against the presented key, then atomically
    // bars a revoked key / refuses a spent `jti` (single-use) / spends the `jti` + trusts the key in
    // the relay's live set.
    match enroller
        .admit(
            request.overlay_pubkey.trim(),
            &verified.jti,
            &proof,
            request.proof_iat,
            now,
        )
        .await
    {
        Ok(OverlayEnrollOutcome::Admitted) => {}
        Ok(OverlayEnrollOutcome::TokenSpent) => {
            return (
                StatusCode::CONFLICT,
                "overlay-enroll invitation already spent\n",
            )
                .into_response();
        }
        Ok(OverlayEnrollOutcome::ProofInvalid) => {
            return (
                StatusCode::FORBIDDEN,
                "overlay enrollment possession proof is missing, stale, or invalid\n",
            )
                .into_response();
        }
        Ok(OverlayEnrollOutcome::Revoked) => {
            return (
                StatusCode::FORBIDDEN,
                "this overlay key is barred from enrollment (revoked)\n",
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("overlay enroll failed: {err}\n"),
            )
                .into_response();
        }
    }
    // (4) Vouch for the enrolled member with a root-signed `overlay-member` credential (the enrollee
    // adopts it only after verifying it against the root anchor).
    match cose::mint_overlay_member(
        &member_pub,
        verified.role,
        &verified.scope,
        DEFAULT_OVERLAY_MEMBER_TTL_SECS,
        now,
        &*signer,
    )
    .await
    {
        Ok(member) => (
            StatusCode::CREATED,
            Json(OverlayEnrollResponse {
                member,
                role: verified.role.as_str().to_string(),
                scope: verified.scope.clone(),
                expires_at: now.saturating_add(DEFAULT_OVERLAY_MEMBER_TTL_SECS),
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

/// `GET /api/overlay/services` — list the overlay service directory (`Overlay·Read`).
pub(super) async fn overlay_services(
    Extension(directory): Extension<OverlayDirectory>,
) -> Response {
    if let Some(forbidden) = assert_overlay_services_is_overlay_read() {
        return forbidden;
    }
    // The MERGED directory (static `[overlay]` routes ∪ live reverse-ingress exposers) — so
    // `boatramp overlay ls` / `forward` discovery sees currently-published `expose` services too.
    let services: Vec<OverlayServiceEntry> = directory
        .list_merged(now_unix())
        .await
        .into_iter()
        .map(|(service, t)| OverlayServiceEntry {
            service,
            relay: t.relay,
            relay_id: t.relay_id,
            egress_id: t.egress_id,
            client_auth: t.client_auth,
        })
        .collect();
    Json(services).into_response()
}

/// A principal's own identity (`GET /api/auth/whoami`): the roles its token
/// grants. Gated only by holding a valid token (the handler verifies it).
#[derive(Serialize)]
struct WhoAmI {
    /// Whether control-plane auth is enabled on this node.
    auth_enabled: bool,
    /// The roles carried by the presented token.
    roles: Vec<GrantedRole>,
}

pub(super) async fn auth_whoami(Extension(auth): Extension<Auth>, headers: HeaderMap) -> Response {
    if auth.is_disabled() {
        // Auth disabled (dev): no identity to report.
        return Json(WhoAmI {
            auth_enabled: false,
            roles: Vec::new(),
        })
        .into_response();
    }
    let Some(bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return (StatusCode::UNAUTHORIZED, "missing bearer token\n").into_response();
    };
    // Full validation (signature + TTL + revocation + caveats), not a bare
    // signature check, so an expired/revoked token can't disclose its roles.
    match auth.verify_bearer_roles(bearer).await {
        Some(roles) => Json(WhoAmI {
            auth_enabled: true,
            roles,
        })
        .into_response(),
        None => (StatusCode::UNAUTHORIZED, "invalid token\n").into_response(),
    }
}

/// The running node's boatramp version (`GET /api/version`, `System·Read`).
#[derive(Serialize)]
struct NodeVersion {
    /// The exact package version of the binary serving this request (`CARGO_PKG_VERSION`, the
    /// workspace version all crates share — so it IS the boatramp release, e.g. `"0.7.3"`).
    version: &'static str,
}

/// The running node's boatramp version (`GET /api/version`). Gated at `system·read` by the auth
/// layer (`authz::Right::required` maps `/api/version` → `System·Read`), so it answers an operator's
/// "which build is actually deployed?" without exposing a release fingerprint to the public — there
/// is deliberately no unauthenticated version surface (no `Server:` header, no public `/version`).
/// A compile-time constant read: no state, no I/O. Shaped as an object so it can grow (e.g. build
/// metadata) without breaking a client. The `boatramp version --server` CLI consumes this.
pub(super) async fn node_version() -> Response {
    Json(NodeVersion {
        version: env!("CARGO_PKG_VERSION"),
    })
    .into_response()
}

/// The control-plane KV degraded state (`GET /api/kv-status`, v0.9.0 KV-recovery, C6). Gated at
/// `system·read` by the auth layer. Serves the BOOT-TIME `DEGRADED.json` snapshot (see
/// [`KvDegraded`](super::KvDegraded)): `{state:"ok"}` when clean, or `{state:"degraded", …}` with the
/// quarantined ids + loss window when a self-heal-on-open dropped a torn WAL tail this boot. Exposes
/// NO secrets. (When the store is DOWN, the recovery-mode listener serves its OWN `/api/kv-status`.)
pub(super) async fn kv_status(
    Extension(KvDegraded(marker)): Extension<super::KvDegraded>,
    Extension(super::KvCoord(coord)): Extension<super::KvCoord>,
) -> Response {
    match coord {
        // Pre-WS4 shape (cluster path / embedders that don't set the backend info): UNCHANGED, so
        // existing SlateDB behavior + its consumers are untouched.
        None => legacy_kv_status(marker),
        // WS4 backend-aware shape (Architect C7): top-level `state` stays (back-compat) + `backend` +
        // derived `coordination`, with the SlateDB recovery vocabulary nested under `durability`.
        Some(info) => backend_aware_kv_status(marker, info),
    }
}

/// The pre-WS4 SlateDB-flavored `kv-status` body (frontier/manifest at the root). Kept byte-identical
/// for the cluster path + any router built without [`KvStatusInfo`], so nothing that consumed the old
/// shape regresses.
fn legacy_kv_status(marker: Option<boatramp_core::kv::DegradedMarker>) -> Response {
    match marker {
        // v0.11.0 F2 manifest-rollback shape (UX C1/C2): lead with the lossless verdict and carry the
        // rollback fields + `frontier_source`/`last_durable_seq` (identical local-fs/S3).
        Some(m) if m.rolled_back_to_generation.is_some() => {
            let wal_tail_dropped = !m.quarantined_ids.is_empty();
            Json(serde_json::json!({
                "state": if wal_tail_dropped { "recovered" } else { "recovered_lossless" },
                "recovered_at": m.stamp,
                "frontier_source": m.frontier_source,
                "last_durable_seq": m.frontier,
                "rolled_back_to_generation": m.rolled_back_to_generation,
                "quarantined_manifest_ids": m.quarantined_manifest_ids,
                "quarantine_dir": m.quarantine_dir,
                // Reclaimable orphans are SPACE only, never loss (surfaced as a distinct field).
                "orphaned_nonacked_objects": m.orphaned_nonacked_objects,
                // Only present when the crash ALSO tore a WAL tail beyond the frontier (forensic-only).
                "quarantined_wal_ids": m.quarantined_ids,
                "loss_window": m.loss_window,
                "note": if wal_tail_dropped {
                    "RECOVERED by last-good-generation rollback; an ADDITIONAL torn WAL tail beyond the \
                     frontier was quarantined (FORENSIC-ONLY). Acknowledge with `boatramp kv status --ack`."
                } else {
                    "RECOVERED (lossless) by last-good-generation rollback — zero acked loss. Acknowledge \
                     with `boatramp kv status --ack` once reviewed."
                },
            }))
            .into_response()
        }
        Some(m) => Json(serde_json::json!({
            "state": "degraded",
            "self_healed_at": m.stamp,
            "frontier_source": m.frontier_source,
            "last_durable_seq": m.frontier,
            "quarantined_ids": m.quarantined_ids,
            "loss_window": m.loss_window,
            "quarantine_dir": m.quarantine_dir,
            "note": "The quarantined torn tail is FORENSIC-ONLY (no supported recovery of acked \
                     pairs). Acknowledge with `boatramp kv status --ack` once reviewed.",
        }))
        .into_response(),
        // A clean store opened from the latest manifest by definition; no boot snapshot ⇒ no seq known.
        None => Json(serde_json::json!({
            "state": "ok",
            "frontier_source": "manifest_latest",
            "last_durable_seq": serde_json::Value::Null,
        }))
        .into_response(),
    }
}

/// The WS4 backend-aware `kv-status` body (Architect C7): `state` stays at the root for back-compat;
/// `backend` and the DERIVED `coordination` describe the real backend (so SQL no longer inherits the
/// SlateDB `manifest_latest` vocabulary); the SlateDB recovery fields — when present — are nested
/// under `durability`, and a non-SlateDB backend reports its own durability model there.
fn backend_aware_kv_status(
    marker: Option<boatramp_core::kv::DegradedMarker>,
    info: super::KvStatusInfo,
) -> Response {
    let is_slatedb = info.backend_family == "slatedb";
    // `state` + the `durability` sub-object. SlateDB carries its recovery vocabulary; every other
    // backend's durability is the engine's own synchronous COMMIT (no manifest/frontier).
    let (state, durability) = if is_slatedb {
        slatedb_state_and_durability(&marker)
    } else {
        (
            "ok".to_string(),
            serde_json::json!({
                "model": "synchronous_commit",
                "note": "Crash recovery is the SQL engine's own (WAL + fsync); durability is the \
                         transaction COMMIT. There is no manifest/frontier/`.compactions` class here \
                         — the self-heal/recover/checkpoint surface does not apply to this backend.",
            }),
        )
    };
    Json(serde_json::json!({
        // Back-compat: the top-level `state` stays (a monitor keying on it keeps working).
        "state": state,
        "backend": {
            "family": info.backend_family,
            "dialect": info.backend_dialect,
            "writer_model": info.writer_model,
            "location": info.location,
            "connection": info.connection,
        },
        "coordination": {
            "mode": info.coordination_mode,
            "derived_from": info.coordination_derived_from,
            "control_plane_id": info.control_plane_id,
            "this_node": info.this_node,
            "members_seen": info.members_seen,
            // No Raft on the run()/shared path; the field is present (null) so a consumer can tell
            // "coordination exists but it is not Raft" from "unknown".
            "raft": serde_json::Value::Null,
        },
        "durability": durability,
    }))
    .into_response()
}

/// Derive the root `state` + the `durability` sub-object from a SlateDB degraded-state boot marker —
/// the SAME verdicts as [`legacy_kv_status`], with the frontier/manifest fields moved under
/// `durability` (the fields are unchanged, only re-homed).
fn slatedb_state_and_durability(
    marker: &Option<boatramp_core::kv::DegradedMarker>,
) -> (String, serde_json::Value) {
    match marker {
        Some(m) if m.rolled_back_to_generation.is_some() => {
            let wal_tail_dropped = !m.quarantined_ids.is_empty();
            let state = if wal_tail_dropped {
                "recovered"
            } else {
                "recovered_lossless"
            };
            (
                state.to_string(),
                serde_json::json!({
                    "recovered_at": m.stamp,
                    "frontier_source": m.frontier_source,
                    "last_durable_seq": m.frontier,
                    "rolled_back_to_generation": m.rolled_back_to_generation,
                    "quarantined_manifest_ids": m.quarantined_manifest_ids,
                    "quarantine_dir": m.quarantine_dir,
                    "orphaned_nonacked_objects": m.orphaned_nonacked_objects,
                    "quarantined_wal_ids": m.quarantined_ids,
                    "loss_window": m.loss_window,
                    "note": if wal_tail_dropped {
                        "RECOVERED by last-good-generation rollback; an ADDITIONAL torn WAL tail beyond \
                         the frontier was quarantined (FORENSIC-ONLY). Acknowledge with `boatramp kv \
                         status --ack`."
                    } else {
                        "RECOVERED (lossless) by last-good-generation rollback — zero acked loss. \
                         Acknowledge with `boatramp kv status --ack` once reviewed."
                    },
                }),
            )
        }
        Some(m) => (
            "degraded".to_string(),
            serde_json::json!({
                "self_healed_at": m.stamp,
                "frontier_source": m.frontier_source,
                "last_durable_seq": m.frontier,
                "quarantined_ids": m.quarantined_ids,
                "loss_window": m.loss_window,
                "quarantine_dir": m.quarantine_dir,
                "note": "The quarantined torn tail is FORENSIC-ONLY (no supported recovery of acked \
                         pairs). Acknowledge with `boatramp kv status --ack` once reviewed.",
            }),
        ),
        None => (
            "ok".to_string(),
            serde_json::json!({
                "frontier_source": "manifest_latest",
                "last_durable_seq": serde_json::Value::Null,
            }),
        ),
    }
}

/// Defense-in-depth (mirrors [`blob_drain`](super::blob_drain)): re-derive that `POST
/// /api/kv-checkpoint` is gated `System·Admin` inside the handler, so a routing/table regression
/// cannot silently downgrade a node-level mutating checkpoint to a project-scoped right.
fn assert_kv_checkpoint_is_system_admin() -> Option<Response> {
    use boatramp_core::authz::{Action, Resource, Right};
    match Right::required("POST", "/api/kv-checkpoint") {
        Some(right)
            if right.resource == Resource::System
                && right.target.is_none()
                && right.action == Action::Admin =>
        {
            None
        }
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                "kv checkpoint requires System·Admin\n",
            )
                .into_response(),
        ),
    }
}

/// On-demand LIVE checkpoint (`POST /api/kv-checkpoint`, `System·Admin`, v0.9.0 KV-recovery, #3):
/// advance the control-plane store's durable frontier NOW (freeze WAL→L0) WITHOUT stopping the
/// writer, so an operator can then snapshot a guaranteed-bootable volume of the running node. The
/// LIVE counterpart to the offline `boatramp kv checkpoint` + the automatic `[serve.kv]
/// checkpoint_interval` cadence. Idempotent + cheap when nothing has changed since the last checkpoint.
pub(super) async fn kv_checkpoint(State(deploy): State<DeployStore>) -> Response {
    if let Some(forbidden) = assert_kv_checkpoint_is_system_admin() {
        return forbidden;
    }
    match deploy.checkpoint().await {
        Ok(()) => (
            StatusCode::OK,
            "kv checkpoint: durable frontier advanced (WAL→L0); the store is a consistent, bootable \
             snapshot point — snapshot the volume now.\n",
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("kv checkpoint failed: {err}\n"),
        )
            .into_response(),
    }
}

/// Defense-in-depth (mirrors [`assert_kv_checkpoint_is_system_admin`]): re-derive that `path` is
/// gated `System·Admin` inside the handler, so a routing/table regression cannot silently downgrade a
/// node-global control-plane dump/restore to a project-scoped right. `what` names the op in the 403.
fn assert_kv_dump_is_system_admin(method: &str, path: &str, what: &str) -> Option<Response> {
    use boatramp_core::authz::{Action, Resource, Right};
    match Right::required(method, path) {
        Some(right)
            if right.resource == Resource::System
                && right.target.is_none()
                && right.action == Action::Admin =>
        {
            None
        }
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                format!("{what} requires System·Admin\n"),
            )
                .into_response(),
        ),
    }
}

/// Stream the control-plane KV as a PORTABLE dump (`GET /api/kv-export`, `System·Admin`, kv-sql WS7).
/// A LOGICAL dump of the CONTENT (`{key, value, version}` records minus the reserved `_cp/*` /
/// `_inval/*` coordination feeds), NOT the physical LSM/manifest — so a restore rebuilds a FRESH
/// clean store, immune to the torn-manifest / corrupt-`.compactions` classes. It is the WHOLE control
/// plane: SEALED secret ciphertext (sealing is pre-put — NO plaintext), plaintext config/RBAC, and
/// NEVER the envelope KEK (held separately; a restore needs it). Hence `System·Admin`, re-checked
/// defense-in-depth. OFFLINE/quiesced is the recommended posture (a live single-writer source races
/// concurrent writes); the SQL scan is itself a single MVCC-consistent read.
pub(super) async fn kv_export(State(deploy): State<DeployStore>) -> Response {
    if let Some(forbidden) = assert_kv_dump_is_system_admin("GET", "/api/kv-export", "kv export") {
        return forbidden;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match boatramp_core::kv_dump::export_to_bytes(deploy.kv().as_ref(), now).await {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"boatramp-kv-dump\"",
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("kv export failed: {err}\n"),
        )
            .into_response(),
    }
}

/// `POST /api/kv-import` query flags: `apply` executes (default = DRY-RUN plan), `force` overlays a
/// non-empty destination (default = REFUSE the commingle).
#[derive(Debug, Default, Deserialize)]
pub(super) struct KvImportQuery {
    #[serde(default)]
    apply: bool,
    #[serde(default)]
    force: bool,
}

/// Import a portable dump into the control-plane KV (`POST /api/kv-import`, `System·Admin`, kv-sql
/// WS7). DRY-RUN by default (returns the plan JSON); `?apply=true` executes then VERIFIES (re-reads
/// every key, compares bytes + count). REFUSES a non-empty destination — or one with an existing
/// control-plane identity — with **409** unless `?force=true` (never silently COMMINGLE two control
/// planes). A corrupt dump is **400**; a verify failure is **500**. The reserved `_cp/*` / `_inval/*`
/// feeds are never imported (they regenerate). `System·Admin`, re-checked defense-in-depth.
pub(super) async fn kv_import(
    State(deploy): State<DeployStore>,
    axum::extract::Query(q): axum::extract::Query<KvImportQuery>,
    body: axum::body::Bytes,
) -> Response {
    if let Some(forbidden) = assert_kv_dump_is_system_admin("POST", "/api/kv-import", "kv import") {
        return forbidden;
    }
    let decoded = match boatramp_core::kv_dump::decode_dump(&body) {
        Ok(d) => d,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("kv import: bad dump: {err}\n"),
            )
                .into_response();
        }
    };
    let kv = deploy.kv().as_ref();
    if !q.apply {
        return match boatramp_core::kv_dump::plan_import(kv, &decoded.entries, q.force).await {
            Ok(plan) => Json(serde_json::json!({
                "mode": "dry_run",
                "format_version": decoded.header.format_version,
                "created_at": decoded.header.created_at,
                "source_entries": plan.source_entries,
                "source_reserved_skipped": plan.source_reserved_skipped,
                "would_write": plan.would_write,
                "destination": {
                    "user_keys": plan.dest.user_keys,
                    "reserved_keys": plan.dest.reserved_keys,
                    "has_control_plane_id": plan.dest.has_control_plane_id,
                    "pristine": plan.dest.is_pristine(),
                },
                "would_refuse_commingle": plan.would_refuse_commingle,
            }))
            .into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("kv import plan failed: {err}\n"),
            )
                .into_response(),
        };
    }
    match boatramp_core::kv_dump::apply_import(kv, &decoded.entries, q.force).await {
        Ok(report) => Json(serde_json::json!({
            "mode": "applied",
            "written": report.written,
            "verified": report.verified,
        }))
        .into_response(),
        Err(boatramp_core::kv_dump::ImportError::Commingle(_)) => (
            StatusCode::CONFLICT,
            "kv import: refusing to import into a NON-EMPTY destination (or one with an existing \
             control-plane identity) — this would COMMINGLE two control planes. Re-send with \
             `?force=true` only to deliberately overlay it.\n",
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("kv import failed: {err}\n"),
        )
            .into_response(),
    }
}

/// Set the `ETag` header on a response to the quoted policy version, so a `GET` hands the operator
/// the version their next `PUT` echoes back as `If-Match` (optimistic concurrency).
fn set_policy_etag(resp: &mut Response, version: &boatramp_core::deploy::PolicyVersion) {
    if let Ok(val) = axum::http::HeaderValue::from_str(&format!("\"{}\"", version.as_str())) {
        resp.headers_mut().insert(axum::http::header::ETAG, val);
    }
}

/// Return the active RBAC policy (`authz/policy`), or the built-in default when
/// none is stored — so a `get` always shows the effective policy. The `ETag` header carries the
/// optimistic-concurrency version the operator echoes as `If-Match` on the next `PUT`.
pub(super) async fn get_authz_policy(State(deploy): State<DeployStore>) -> Response {
    match deploy.get_authz_policy_versioned().await {
        Ok((stored, version)) => {
            let policy = stored.unwrap_or_else(boatramp_core::authz::AuthzPolicy::default_policy);
            let mut resp = Json(policy).into_response();
            set_policy_etag(&mut resp, &version);
            resp
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Replace the RBAC policy with optimistic concurrency. Rejected (`400`) unless it compiles to a
/// valid Cedar policy set, so a bad policy can never be stored and brick the edge. When the request
/// carries an `If-Match` (the version from a prior `GET`'s `ETag`), the write wins only if the
/// stored policy still matches — a stale version → `409 Conflict` (the operator re-reads + retries),
/// closing the lost-grant/lost-revoke race when two operators edit on different nodes. With no
/// `If-Match` (or `If-Match: *`) the write CAS'es on the current value (still no blind clobber).
pub(super) async fn put_authz_policy(
    State(deploy): State<DeployStore>,
    headers: axum::http::HeaderMap,
    Json(policy): Json<boatramp_core::authz::AuthzPolicy>,
) -> Response {
    if let Err(err) = boatramp_core::cedar::CompiledCedar::compile(&policy) {
        return (StatusCode::BAD_REQUEST, format!("invalid policy: {err}\n")).into_response();
    }
    let if_match = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    let result = match if_match {
        Some(raw) if raw != "*" => {
            let expected = boatramp_core::deploy::PolicyVersion::from_header(raw);
            deploy.set_authz_policy_if_match(&expected, &policy).await
        }
        _ => match deploy.get_authz_policy_versioned().await {
            Ok((_current, version)) => deploy.set_authz_policy_if_match(&version, &policy).await,
            Err(err) => Err(err),
        },
    };
    match result {
        Ok(version) => {
            let mut resp = StatusCode::NO_CONTENT.into_response();
            set_policy_etag(&mut resp, &version);
            resp
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Defense-in-depth (mirrors [`assert_overlay_dial_is_overlay_write`]): re-derive that the overlay
/// flow-policy routes are gated **`System·Admin`** INSIDE each handler (overlay follow-up #3,
/// REQUIRED #6), so a router/table refactor cannot silently drop the gate down to an `Overlay·*`
/// tier — which would turn the policy-enumeration `GET`/`test` surfaces into a readable oracle, or
/// let a non-node-admin edit the gate.
fn assert_overlay_policy_is_system_admin(method: &str, path: &str) -> Option<Response> {
    use boatramp_core::authz::{Action, Resource, Right};
    match Right::required(method, path) {
        Some(right)
            if right.resource == Resource::System
                && right.target.is_none()
                && right.action == Action::Admin =>
        {
            None
        }
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                "overlay flow-policy administration requires System·Admin\n",
            )
                .into_response(),
        ),
    }
}

/// `PUT /api/overlay/policy` response: the new version + a one-time CLIFF warning when this PUT
/// stored the FIRST policy (the gate just went from OFF to default-deny).
#[derive(Serialize)]
struct OverlayPolicyPutResponse {
    /// The new optimistic-concurrency version (also returned as the `ETag`).
    version: String,
    /// Present only when this PUT turned the gate ON for the first time.
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
}

/// Return the stored overlay flow policy (Cedar TEXT), or an empty body when none is stored (the
/// gate is off). Gated `System·Admin`. The `ETag` carries the version for a subsequent `PUT`'s
/// `If-Match` (optimistic concurrency), exactly like the RBAC policy surface.
pub(super) async fn get_overlay_policy(State(deploy): State<DeployStore>) -> Response {
    if let Some(forbidden) = assert_overlay_policy_is_system_admin("GET", "/api/overlay/policy") {
        return forbidden;
    }
    match deploy.get_overlay_flow_policy_versioned().await {
        Ok((stored, version)) => {
            let body = stored
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default();
            let mut resp = (StatusCode::OK, body).into_response();
            set_policy_etag(&mut resp, &version);
            resp
        }
        Err(err) => deploy_error_response(err),
    }
}

/// Replace the overlay flow policy (Cedar TEXT body) with optimistic concurrency. **Validated on
/// PUT** (REQUIRED #5): the body must parse, pass the temporal screen (only a single `not_after`
/// upper bound), and type-check against the flow schema, or `400` with the error verbatim — so a
/// malformed/complex policy can never be stored. An EMPTY body turns the gate OFF (stored empty).
/// `If-Match` (the version from a prior `GET`'s `ETag`) makes the write conditional — a stale
/// version → `409`. Gated `System·Admin`. When this PUT stores the FIRST policy, the response
/// carries a CLIFF warning (the gate just became default-deny).
pub(super) async fn put_overlay_policy(
    State(deploy): State<DeployStore>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    if let Some(forbidden) = assert_overlay_policy_is_system_admin("PUT", "/api/overlay/policy") {
        return forbidden;
    }
    let bytes: Vec<u8> = if body.trim().is_empty() {
        // Empty ⇒ clear the policy (feature off). Stored as empty bytes; no compile.
        Vec::new()
    } else {
        // Validated-on-PUT: compile (parse + temporal screen + schema). 400 verbatim on failure.
        if let Err(err) = boatramp_core::overlay_policy::FlowPolicy::compile(&body) {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid overlay flow policy: {err}\n"),
            )
                .into_response();
        }
        body.into_bytes()
    };
    // Read the current value for the CLIFF-warning check + the no-If-Match CAS version.
    let (current, current_version) = match deploy.get_overlay_flow_policy_versioned().await {
        Ok(v) => v,
        Err(err) => return deploy_error_response(err),
    };
    let was_off = current
        .as_ref()
        .map(|c| c.iter().all(u8::is_ascii_whitespace))
        .unwrap_or(true);
    let first_policy = was_off && !bytes.is_empty();
    let if_match = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    let expected = match if_match {
        Some(raw) if raw != "*" => boatramp_core::deploy::PolicyVersion::from_header(raw),
        _ => current_version,
    };
    match deploy
        .set_overlay_flow_policy_if_match(&expected, &bytes)
        .await
    {
        Ok(version) => {
            let warning = first_policy.then(|| {
                "stored the FIRST overlay flow policy — the mint gate is now ON and DEFAULT-DENY \
                 within: every dial/expose mint NOT matched by a `permit` is denied. Preview with \
                 `POST /api/overlay/policy/test` before relying on it."
                    .to_string()
            });
            let mut resp = Json(OverlayPolicyPutResponse {
                version: version.as_str().to_string(),
                warning,
            })
            .into_response();
            set_policy_etag(&mut resp, &version);
            resp
        }
        Err(err) => deploy_error_response(err),
    }
}

/// `POST /api/overlay/policy/test` request: a dry-run scenario (NO mint). Evaluates against the
/// optional inline `policy` (pre-store preview) or, when omitted, the STORED policy.
#[derive(Deserialize)]
pub(super) struct OverlayPolicyTestRequest {
    /// Cedar policy text to evaluate against (pre-store preview); omit to use the stored policy.
    #[serde(default)]
    policy: Option<String>,
    /// The flow action to simulate: `dial` or `expose`.
    action: String,
    /// The target service name (the `Overlay::Service` uid).
    service: String,
    /// The holder key (the `Overlay::Holder` uid).
    holder: String,
    /// Optional holder attributes a bound member credential would supply (absent ⇒ key-only).
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    enrolled: Option<bool>,
    /// Optional `requestor` for the context (defaults to `test`).
    #[serde(default)]
    requestor: Option<String>,
    /// Optional `src_ip` for the context.
    #[serde(default)]
    src_ip: Option<String>,
    /// The requested TTL (seconds) to evaluate.
    ttl_requested: u64,
    /// Optional `now` (Unix seconds) for a `not_after` bound; defaults to the server clock.
    #[serde(default)]
    now: Option<u64>,
}

/// `POST /api/overlay/policy/test` response: the dry-run decision + the deciding policies +
/// diagnostics. Unlike the mint 403, this surface DOES expose the deciding policies/diagnostics —
/// it is `System·Admin`-only (the policy author), so it is not an oracle for a lesser principal.
#[derive(Serialize)]
struct OverlayPolicyTestResponse {
    /// `allow` or `deny`.
    decision: String,
    /// The policy-imposed TTL ceiling (seconds) on an allow, or `null` (no shrink / deny).
    ttl_ceiling: Option<u64>,
    /// The ids of the deciding policies (Cedar's `reason`).
    deciding_policies: Vec<String>,
    /// Evaluation diagnostics (errored conditions, etc.).
    diagnostics: Vec<String>,
    /// A human note about the policy posture (feature off / corrupt), when relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

/// Dry-run the flow gate (NO mint). Gated `System·Admin`. Resolves the policy (inline preview or
/// stored), builds the holder principal + context from the request, evaluates, and returns the
/// decision + deciding policies + diagnostics. Mirrors the live gate's four-state posture: feature
/// off ⇒ allow (ungated); corrupt stored policy ⇒ deny (fail-closed), both annotated in `note`.
pub(super) async fn test_overlay_policy(
    State(deploy): State<DeployStore>,
    Json(req): Json<OverlayPolicyTestRequest>,
) -> Response {
    if let Some(forbidden) =
        assert_overlay_policy_is_system_admin("POST", "/api/overlay/policy/test")
    {
        return forbidden;
    }
    use boatramp_core::overlay_policy::{
        Decision, FlowAction, FlowContext, FlowPolicy, HolderPrincipal,
    };
    let action = match req.action.as_str() {
        "dial" => FlowAction::Dial,
        "expose" => FlowAction::Expose,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                format!("action must be `dial` or `expose`, got `{other}`\n"),
            )
                .into_response();
        }
    };
    // Resolve the policy to evaluate: the inline preview, else the stored four-state.
    let fp = match &req.policy {
        Some(src) if !src.trim().is_empty() => match FlowPolicy::compile(src) {
            Ok(fp) => Some(fp),
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("invalid overlay flow policy: {err}\n"),
                )
                    .into_response();
            }
        },
        _ => match deploy.get_overlay_flow_policy_versioned().await {
            Ok((None, _)) => None,
            Ok((Some(b), _)) if b.iter().all(u8::is_ascii_whitespace) => None,
            Ok((Some(b), _)) => {
                match std::str::from_utf8(&b)
                    .ok()
                    .and_then(|s| FlowPolicy::compile(s).ok())
                {
                    Some(fp) => Some(fp),
                    None => {
                        // Corrupt stored policy — mirror the live gate's fail-closed deny-all.
                        return Json(OverlayPolicyTestResponse {
                            decision: "deny".into(),
                            ttl_ceiling: None,
                            deciding_policies: Vec::new(),
                            diagnostics: Vec::new(),
                            note: Some(
                                "stored flow policy is corrupt — the live gate fails closed \
                                 (deny-all)"
                                    .into(),
                            ),
                        })
                        .into_response();
                    }
                }
            }
            Err(err) => return deploy_error_response(err),
        },
    };
    let Some(fp) = fp else {
        // Feature off (no policy / empty) — the mint would be allowed ungated.
        return Json(OverlayPolicyTestResponse {
            decision: "allow".into(),
            ttl_ceiling: None,
            deciding_policies: Vec::new(),
            diagnostics: Vec::new(),
            note: Some(
                "no flow policy in effect (feature off) — the mint is allowed ungated".into(),
            ),
        })
        .into_response();
    };
    let principal = HolderPrincipal {
        key: req.holder.clone(),
        role: req.role.clone(),
        scope: req.scope.clone(),
        enrolled: req.enrolled,
    };
    let ctx = FlowContext {
        requestor: req.requestor.clone().unwrap_or_else(|| "test".to_string()),
        now: req.now.unwrap_or_else(now_unix),
        src_ip: req.src_ip.clone(),
        ttl_requested: req.ttl_requested,
    };
    let outcome = fp.evaluate(&principal, action, &req.service, &ctx);
    let (decision, ttl_ceiling) = match outcome.decision {
        Decision::Allow { ttl_ceiling } => ("allow", ttl_ceiling),
        Decision::Deny => ("deny", None),
    };
    Json(OverlayPolicyTestResponse {
        decision: decision.to_string(),
        ttl_ceiling,
        deciding_policies: outcome.deciding_policies,
        diagnostics: outcome.diagnostics,
        note: None,
    })
    .into_response()
}

/// The extra trusted root anchors (make-before-break rotation).
pub(super) async fn list_root_anchors(State(deploy): State<DeployStore>) -> Response {
    match deploy.list_root_anchors().await {
        Ok(anchors) => (StatusCode::OK, Json(anchors)).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

#[derive(Deserialize)]
pub(super) struct RootAnchorRequest {
    /// The `alg:hex`-encoded root public key to trust alongside the primary.
    pubkey: String,
}

/// Trust an additional root anchor — rejects anything that isn't a valid
/// `TokenPublicKey` so a malformed anchor can never be added.
pub(super) async fn add_root_anchor(
    State(deploy): State<DeployStore>,
    Json(req): Json<RootAnchorRequest>,
) -> Response {
    let pubkey = req.pubkey.trim();
    if cose::TokenPublicKey::from_hex(pubkey).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            "pubkey must be an alg:hex TokenPublicKey (e.g. es256:…)\n",
        )
            .into_response();
    }
    match deploy.add_root_anchor(pubkey).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Retire a root anchor (the old key, after a rotation propagates).
pub(super) async fn remove_root_anchor(
    State(deploy): State<DeployStore>,
    Path(pubkey): Path<String>,
) -> Response {
    match deploy.remove_root_anchor(pubkey.trim()).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

// ---- Project-scoped internal secret store (admin API) --------------------
//
// The `/api/projects/{proj}/secrets{,/{name}}` surface is rewritten by
// `project_scope` onto the global `/api/secrets{,/{name}}` handlers below, which
// read the tenant from the `ProjectContext` extension (the same shape as the
// site/function/compute handlers). Authorization is enforced upstream by
// `require_auth` against the *original* project-scoped path
// (`Secrets·Read`/`Secrets·Write`).
//
// The store seals every value with the `[secrets]` envelope; these handlers only
// ever set/list/delete **names + metadata** and NEVER return a value. There is no
// value-GET endpoint — a value leaves the store only into a guest at instantiation
// (the resolver), never over the API.

/// When no `[secrets]` key envelope is configured there is no sealed store, so
/// every secrets endpoint returns this clear `501` — never a panic or a `500`.
fn no_secret_store_response() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "no [secrets] key envelope configured; secrets require sealing at rest \
         (set [secrets] envelope = \"local\" or \"vault\" in boatramp.cfg)\n",
    )
        .into_response()
}

/// Map a [`SecretError`] to a response without disclosing backend internals: a
/// **client** error (invalid name, oversized value — the message is about the request)
/// returns `400` with that message; a **backend** error (a KV / envelope failure whose
/// detail could carry key shapes or a KMS endpoint) is logged server-side and returned
/// as a generic `500`.
fn secret_error_response(err: boatramp_core::secret_store::SecretError) -> Response {
    if err.is_conflict() {
        // An optimistic-concurrency conflict (a concurrent rotation/delete won the CAS). The
        // message is request-level and safe to surface; the caller re-reads and retries.
        (StatusCode::CONFLICT, format!("{err}\n")).into_response()
    } else if err.is_client_error() {
        (StatusCode::BAD_REQUEST, format!("{err}\n")).into_response()
    } else {
        tracing::warn!(%err, "secret store backend error");
        (StatusCode::INTERNAL_SERVER_ERROR, "secret store error\n").into_response()
    }
}

/// The secret store, injected as an extension by the node when a `[secrets]`
/// envelope is present. `None` ⇒ the endpoints fail closed with a clear `501`.
type SecretStoreExt = Option<Arc<boatramp_core::secret_store::SecretStore>>;

#[derive(Deserialize)]
pub(super) struct SetSecretRequest {
    /// The secret name (a KV key segment; validated inside the store).
    name: String,
    /// The plaintext value — sealed server-side; never stored in the clear,
    /// logged, or returned.
    value: String,
}

/// `POST /api/projects/{proj}/secrets` — seal `value` server-side under `name`
/// (rotation = POST an existing name) and return the value-free [`SecretMeta`] as
/// `201`. Never echoes the value. `501` when no envelope is configured; `400` on an
/// invalid name (rejected fail-closed inside the store).
pub(super) async fn set_secret(
    Extension(store): Extension<SecretStoreExt>,
    Extension(project): Extension<ProjectContext>,
    Json(request): Json<SetSecretRequest>,
) -> Response {
    let Some(store) = store else {
        return no_secret_store_response();
    };
    match store
        .set(project.as_ref(), &request.name, request.value.as_bytes())
        .await
    {
        Ok(meta) => (StatusCode::CREATED, Json(meta)).into_response(),
        Err(err) => secret_error_response(err),
    }
}

/// `GET /api/projects/{proj}/secrets` — list every secret's **name + metadata**
/// (sorted), never a value. `501` when no envelope is configured.
pub(super) async fn list_secrets(
    Extension(store): Extension<SecretStoreExt>,
    Extension(project): Extension<ProjectContext>,
) -> Response {
    let Some(store) = store else {
        return no_secret_store_response();
    };
    match store.list(project.as_ref()).await {
        Ok(metas) => Json(metas).into_response(),
        Err(err) => secret_error_response(err),
    }
}

/// `DELETE /api/projects/{proj}/secrets/{name}` — remove a secret; `204` if it
/// existed, `404` if not. `501` when no envelope is configured; `400` on an invalid
/// name.
pub(super) async fn delete_secret(
    Extension(store): Extension<SecretStoreExt>,
    Extension(project): Extension<ProjectContext>,
    Path(name): Path<String>,
) -> Response {
    let Some(store) = store else {
        return no_secret_store_response();
    };
    match store.delete(project.as_ref(), &name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no matching secret\n").into_response(),
        Err(err) => secret_error_response(err),
    }
}

// ---- Project-scoped PER-TENANT sealed secret store (admin API) -----------
//
// Task #493. The `/api/projects/{proj}/tenant-secrets/{tenant}{,/{name}}` surface is rewritten by
// `project_scope` onto the global `/api/tenant-secrets/{tenant}{,/{name}}` handlers below, which
// read the project from the `ProjectContext` extension. Authorization is enforced upstream by
// `require_auth` against the *original* project-scoped path (the dedicated `Resource::Secrets`
// mapping — Read to list, Write to mutate — NOT the deploy-grade publisher right; see
// `authz::Right::required`).
//
// Every value is sealed with the `[secrets]` envelope; these handlers set/list/delete NAMES +
// METADATA and NEVER return a value (there is no value-GET endpoint — a value leaves the store only
// into a guest at point-of-use via the `tenant-secrets` capability, never over the API). The
// `{tenant}` and `{name}` PATH segments are validated fail-closed INSIDE the store
// (`validate_resource_name` / `validate_name`), so a `..`/`/`-bearing segment is a `400` before it
// can reshape the key to a sibling tenant's — the guest read and this write compose byte-identical
// segments (Security HIGH-2).

/// The per-tenant secret store, injected as an extension by the node when a `[secrets]` envelope is
/// present. `None` ⇒ the endpoints fail closed with a clear `501` (`no_secret_store_response`).
type TenantSecretStoreExt = Option<Arc<boatramp_core::secret_store::TenantSecretStore>>;

#[derive(Deserialize)]
pub(super) struct SetTenantSecretRequest {
    /// The plaintext value — sealed server-side; never stored in the clear, logged, or returned.
    value: String,
}

/// `PUT /api/projects/{proj}/tenant-secrets/{tenant}/{name}` — seal `value` server-side under
/// `(project, tenant, name)` (rotation = PUT an existing name) and return the value-free
/// [`SecretMeta`] as `201`. Never echoes the value. `501` when no envelope is configured; `400` on
/// an invalid tenant/name segment (rejected fail-closed inside the store, before any write).
pub(super) async fn set_tenant_secret(
    Extension(store): Extension<TenantSecretStoreExt>,
    Extension(project): Extension<ProjectContext>,
    Path((tenant, name)): Path<(String, String)>,
    Json(request): Json<SetTenantSecretRequest>,
) -> Response {
    let Some(store) = store else {
        return no_secret_store_response();
    };
    match store
        .set(project.as_ref(), &tenant, &name, request.value.as_bytes())
        .await
    {
        Ok(meta) => (StatusCode::CREATED, Json(meta)).into_response(),
        Err(err) => secret_error_response(err),
    }
}

/// `GET /api/projects/{proj}/tenant-secrets/{tenant}` — list one tenant's secret **names +
/// metadata** (sorted), never a value, per-tenant (never project-wide → no cross-tenant name
/// oracle). `501` when no envelope; `400` on an invalid tenant segment.
pub(super) async fn list_tenant_secrets(
    Extension(store): Extension<TenantSecretStoreExt>,
    Extension(project): Extension<ProjectContext>,
    Path(tenant): Path<String>,
) -> Response {
    let Some(store) = store else {
        return no_secret_store_response();
    };
    match store.list(project.as_ref(), &tenant).await {
        Ok(metas) => Json(metas).into_response(),
        Err(err) => secret_error_response(err),
    }
}

/// `DELETE /api/projects/{proj}/tenant-secrets/{tenant}/{name}` — remove a secret; `204` if it
/// existed, `404` if not. `501` when no envelope; `400` on an invalid tenant/name segment.
pub(super) async fn delete_tenant_secret(
    Extension(store): Extension<TenantSecretStoreExt>,
    Extension(project): Extension<ProjectContext>,
    Path((tenant, name)): Path<(String, String)>,
) -> Response {
    let Some(store) = store else {
        return no_secret_store_response();
    };
    match store.delete(project.as_ref(), &tenant, &name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no matching secret\n").into_response(),
        Err(err) => secret_error_response(err),
    }
}

// ---- Project-scoped SMTP email profiles (admin API) ----------------------
//
// The `/api/projects/{proj}/email/profiles{,/{name}}` surface is rewritten by
// `project_scope` onto the global `/api/email/profiles{,/{name}}` handlers below,
// reading the tenant from the `ProjectContext`. Authorization is enforced upstream
// against the original project-scoped path with the same `Resource::Secrets` right
// as the secret store (email profiles are credential config).
//
// The store seals every profile's **password** with the `[secrets]` envelope; these
// handlers return only the **redacted** config (host/port/from/…, never the
// password). There is no password-GET endpoint — the password leaves the store only
// host-side, into the send binding at instantiation, never over the API.

/// When no `[secrets]` key envelope is configured there is no sealed store, so
/// every email-profile endpoint returns this clear `501` — never a panic or `500`.
fn no_email_store_response() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "no [secrets] key envelope configured; email profiles seal their SMTP \
         password at rest (set [secrets] envelope = \"local\" or \"vault\" in boatramp.cfg)\n",
    )
        .into_response()
}

/// Map an [`EmailProfileError`](boatramp_core::email_config::EmailProfileError) to a
/// response without disclosing backend internals: a client error (invalid name /
/// config) returns `400` with the message; a backend error is logged and returned
/// as a generic `500`.
fn email_error_response(err: boatramp_core::email_config::EmailProfileError) -> Response {
    if err.is_client_error() {
        (StatusCode::BAD_REQUEST, format!("{err}\n")).into_response()
    } else {
        tracing::warn!(%err, "email profile store backend error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "email profile store error\n",
        )
            .into_response()
    }
}

/// The email-profile store, injected as an extension by the node when a `[secrets]`
/// envelope is present. `None` ⇒ the endpoints fail closed with a clear `501`.
type EmailStoreExt = Option<Arc<boatramp_core::email_config::EmailProfileStore>>;

#[derive(Deserialize)]
pub(super) struct SetEmailProfileRequest {
    /// SMTP relay hostname. Required on create; **omit to keep** the stored value on update.
    #[serde(default)]
    host: Option<String>,
    /// SMTP relay port; omitted ⇒ kept (or, on create, the conventional port for `security`).
    #[serde(default)]
    port: Option<u16>,
    /// Transport security: `starttls` | `tls` | `plaintext`. Omitted ⇒ kept.
    #[serde(default)]
    security: Option<String>,
    /// SMTP AUTH username. Omitted ⇒ kept; use `clear_auth` to drop it.
    #[serde(default)]
    username: Option<String>,
    /// SMTP AUTH password — sealed server-side; never stored clear, logged, or returned.
    /// **Omitted ⇒ the stored password is kept** (so a host/from edit can't silently wipe
    /// auth); provide it only to rotate. `clear_auth` drops it.
    #[serde(default)]
    password: Option<String>,
    /// The default (and only permitted) `From` address. Required on create; omit to keep.
    #[serde(default)]
    from: Option<String>,
    /// Whether sends through this profile default to the durable spool. Omitted ⇒ kept.
    #[serde(default)]
    durable: Option<bool>,
    /// Drop the username + password entirely (an unauthenticated relay).
    #[serde(default)]
    clear_auth: bool,
}

/// `PUT /api/projects/{proj}/email/profiles/{name}` — create-or-**merge** a profile. Fields
/// present overwrite; fields omitted keep their stored value (the sealed password included, so
/// changing one parameter never re-transmits or wipes it); `clear_auth` drops the credentials.
/// Seals any supplied password server-side and returns the **redacted**
/// [`EmailProfileInfo`](boatramp_core::email_config::EmailProfileInfo) as `201`. On create,
/// host + from must be present. Never echoes the password. `501` with no envelope; `400` on an
/// invalid name/config.
pub(super) async fn set_email_profile(
    Extension(store): Extension<EmailStoreExt>,
    Extension(project): Extension<ProjectContext>,
    Path(name): Path<String>,
    Json(request): Json<SetEmailProfileRequest>,
) -> Response {
    let Some(store) = store else {
        return no_email_store_response();
    };
    let security = match &request.security {
        Some(s) => match s.parse::<boatramp_core::email_config::SmtpSecurity>() {
            Ok(s) => Some(s),
            Err(e) => return (StatusCode::BAD_REQUEST, format!("{e}\n")).into_response(),
        },
        None => None,
    };
    let patch = boatramp_core::email_config::EmailProfilePatch {
        host: request.host,
        port: request.port,
        security,
        username: request.username,
        password: request.password,
        from: request.from,
        durable: request.durable,
        clear_auth: request.clear_auth,
    };
    match store.patch(project.as_ref(), &name, &patch).await {
        Ok(info) => (StatusCode::CREATED, Json(info)).into_response(),
        Err(err) => email_error_response(err),
    }
}

/// `GET /api/projects/{proj}/email/profiles` — list every profile's **redacted**
/// config (sorted), never the password. `501` with no envelope.
pub(super) async fn list_email_profiles(
    Extension(store): Extension<EmailStoreExt>,
    Extension(project): Extension<ProjectContext>,
) -> Response {
    let Some(store) = store else {
        return no_email_store_response();
    };
    match store.list(project.as_ref()).await {
        Ok(infos) => Json(infos).into_response(),
        Err(err) => email_error_response(err),
    }
}

/// `GET /api/projects/{proj}/email/profiles/{name}` — one profile's **redacted**
/// config; `404` if absent. `501` with no envelope.
pub(super) async fn show_email_profile(
    Extension(store): Extension<EmailStoreExt>,
    Extension(project): Extension<ProjectContext>,
    Path(name): Path<String>,
) -> Response {
    let Some(store) = store else {
        return no_email_store_response();
    };
    match store.get_info(project.as_ref(), &name).await {
        Ok(Some(info)) => Json(info).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no matching email profile\n").into_response(),
        Err(err) => email_error_response(err),
    }
}

/// `DELETE /api/projects/{proj}/email/profiles/{name}` — remove a profile; `204` if
/// it existed, `404` if not. `501` with no envelope; `400` on an invalid name.
pub(super) async fn delete_email_profile(
    Extension(store): Extension<EmailStoreExt>,
    Extension(project): Extension<ProjectContext>,
    Path(name): Path<String>,
) -> Response {
    let Some(store) = store else {
        return no_email_store_response();
    };
    match store.delete(project.as_ref(), &name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no matching email profile\n").into_response(),
        Err(err) => email_error_response(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MEDIUM-D: an oversized (or unset) `ttl_secs` is clamped to the server cap; a value under the
    /// cap is honored verbatim. This is the exact decision `overlay_dial` applies before minting.
    #[test]
    fn dial_ttl_is_clamped_to_the_server_max() {
        let max = 24 * 60 * 60;
        // A near-immortal request is capped at the server max (the attack MEDIUM-D closes).
        assert_eq!(clamp_dial_ttl(Some(u64::MAX), max), max);
        assert_eq!(clamp_dial_ttl(Some(max + 1), max), max);
        // A request at/under the cap is honored.
        assert_eq!(clamp_dial_ttl(Some(60), max), 60);
        assert_eq!(clamp_dial_ttl(Some(max), max), max);
        // An absent ttl defaults, then is itself subject to the cap.
        assert_eq!(clamp_dial_ttl(None, max), DEFAULT_OVERLAY_DIAL_TTL_SECS);
        assert_eq!(clamp_dial_ttl(None, 60), 60);
    }

    /// INFO-1: the handler-level re-checks agree with the router `Right::required` table — so the
    /// defense-in-depth guard admits exactly the right the route is gated at, not a stale mismatch.
    #[test]
    fn overlay_handler_rechecks_match_the_route_table() {
        assert!(
            assert_overlay_dial_is_overlay_write().is_none(),
            "POST /api/overlay/dial must be gated Overlay·Write"
        );
        assert!(
            assert_overlay_services_is_overlay_read().is_none(),
            "GET /api/overlay/services must be gated Overlay·Read"
        );
        assert!(
            assert_overlay_invite_is_overlay_admin().is_none(),
            "POST /api/overlay/invite must be gated Overlay·Admin"
        );
        assert!(
            assert_overlay_pair_code_is_overlay_admin().is_none(),
            "POST /api/overlay/pair-code must be gated Overlay·Admin"
        );
    }

    /// `overlay_pair_code` is `404` on a node running no ingress relay (nowhere to meet) and `201`
    /// with an expose relay configured — returning the relay topology + a fresh rendezvous id, the
    /// TTL clamped to the short pairing ceiling. No root key is needed (the code is not signed).
    #[tokio::test]
    async fn overlay_pair_code_404_without_relay_and_201_with_relay() {
        // No ingress relay → 404 (nowhere to host the rendezvous).
        let resp = overlay_pair_code(
            Extension(OverlayDirectory::default()),
            Json(OverlayPairCodeRequest { ttl_secs: None }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // With an expose relay → 201, carrying the relay + a fresh rendezvous id.
        let directory = OverlayDirectory::default().with_expose_relay(Some(ExposeRelay {
            relay: "203.0.113.9:9100".into(),
            relay_id: "ed25519:aa".into(),
            trust_root: "ed25519:root".into(),
            client_auth: "capability-only".into(),
        }));
        let resp = overlay_pair_code(
            Extension(directory),
            Json(OverlayPairCodeRequest {
                ttl_secs: Some(u64::MAX), // clamped to the short pairing ceiling
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["relay"], "203.0.113.9:9100");
        assert_eq!(v["relay_id"], "ed25519:aa");
        // The rendezvous id is hex of the fixed-length nonce.
        let rvz = v["rendezvous"].as_str().unwrap();
        assert_eq!(rvz.len(), OVERLAY_PAIR_RENDEZVOUS_ID_LEN * 2);
        assert!(hex::decode(rvz).is_ok());
        // The TTL was clamped to the short pairing ceiling (not the 24h dial cap).
        let now = now_unix();
        let exp = v["expires_at"].as_u64().unwrap();
        assert!(
            exp <= now + MAX_OVERLAY_PAIR_CODE_TTL_SECS + 2,
            "pair-code TTL must be clamped to the short pairing ceiling"
        );
    }

    use boatramp_core::cose::{LocalSigner, OverlayMemberRole, Signer, TokenAlg};
    use boatramp_core::kv::{KvStore, MemoryKv};

    /// An `OverlayEnroll` stub returning a scripted outcome — so the enroll handler's
    /// outcome→HTTP-status mapping can be tested without the (binary-side) real trust-set admit.
    struct StubEnroll(OverlayEnrollOutcome);
    #[async_trait::async_trait]
    impl OverlayEnroll for StubEnroll {
        async fn admit(
            &self,
            _overlay_pubkey_hex: &str,
            _jti: &str,
            _possession_proof: &[u8],
            _proof_iat: u64,
            _now: u64,
        ) -> std::result::Result<OverlayEnrollOutcome, String> {
            Ok(self.0)
        }
    }

    fn mem_auth(root: &LocalSigner) -> Auth {
        let kv: std::sync::Arc<dyn KvStore> = std::sync::Arc::new(MemoryKv::new());
        Auth::with_key(root.public_key(), kv)
    }

    /// `overlay_invite` is `501` on a verify-only node (no root key) and `201` with a signer + a
    /// role in the closed set.
    #[tokio::test]
    async fn overlay_invite_501_without_root_and_201_with_signer() {
        // No root private key → 501 (mirrors `create_join_token`).
        let resp = overlay_invite(
            Extension(Issuer(None)),
            Extension(OverlayDirectory::default()),
            Json(OverlayInviteRequest {
                role: "device".into(),
                scope: "svc/db".into(),
                ttl_secs: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);

        // With a signer → 201.
        let root = LocalSigner::generate(TokenAlg::Ed25519);
        let resp = overlay_invite(
            Extension(Issuer(Some(std::sync::Arc::new(root)))),
            Extension(OverlayDirectory::default()),
            Json(OverlayInviteRequest {
                role: "device".into(),
                scope: "svc/db".into(),
                ttl_secs: Some(300),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // An unknown role → 400 (the closed role set is enforced at mint).
        let root = LocalSigner::generate(TokenAlg::Ed25519);
        let resp = overlay_invite(
            Extension(Issuer(Some(std::sync::Arc::new(root)))),
            Extension(OverlayDirectory::default()),
            Json(OverlayInviteRequest {
                role: "superuser".into(),
                scope: "svc/db".into(),
                ttl_secs: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// `overlay_enroll` returns `501` when the node runs no relay (no admit hook) or has no root key,
    /// and maps each admit outcome to its HTTP status (Admitted→201, Spent→409, ProofInvalid/Revoked
    /// →403) once a valid invitation + an ed25519 key clear the handler's token/key checks.
    #[tokio::test]
    async fn overlay_enroll_501s_and_outcome_status_mapping() {
        let root = LocalSigner::generate(TokenAlg::Ed25519);
        let now = now_unix();
        let token = cose::mint_overlay_enroll(OverlayMemberRole::Device, "svc/db", 300, now, &root)
            .await
            .unwrap();
        let overlay_pubkey = LocalSigner::generate(TokenAlg::Ed25519)
            .public_key()
            .to_hex();
        let req = || OverlayEnrollRequest {
            token: token.clone(),
            overlay_pubkey: overlay_pubkey.clone(),
            possession_proof: "00".into(), // the stub ignores it; hex must decode
            proof_iat: now,
        };

        // No relay admit hook → 501 (checked first, before anything else).
        let resp = overlay_enroll(
            Extension(Auth::disabled()),
            Extension(Issuer(None)),
            Extension(OverlayEnrollHandle(None)),
            Json(req()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);

        // A hook but no root key to vouch for the member → 501.
        let resp = overlay_enroll(
            Extension(Auth::disabled()),
            Extension(Issuer(None)),
            Extension(OverlayEnrollHandle(Some(std::sync::Arc::new(StubEnroll(
                OverlayEnrollOutcome::Admitted,
            ))))),
            Json(req()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);

        // Full valid setup (anchor + issuer), scripted outcomes → their statuses.
        let issuer = || {
            Issuer(Some(std::sync::Arc::new(LocalSigner::generate(
                TokenAlg::Ed25519,
            ))))
        };
        for (outcome, want) in [
            (OverlayEnrollOutcome::Admitted, StatusCode::CREATED),
            (OverlayEnrollOutcome::TokenSpent, StatusCode::CONFLICT),
            (OverlayEnrollOutcome::ProofInvalid, StatusCode::FORBIDDEN),
            (OverlayEnrollOutcome::Revoked, StatusCode::FORBIDDEN),
        ] {
            let resp = overlay_enroll(
                Extension(mem_auth(&root)),
                Extension(issuer()),
                Extension(OverlayEnrollHandle(Some(std::sync::Arc::new(StubEnroll(
                    outcome,
                ))))),
                Json(req()),
            )
            .await;
            assert_eq!(
                resp.status(),
                want,
                "outcome {outcome:?} must map to {want}"
            );
        }

        // An EXPIRED invitation is rejected at the token-verify step (before admit) → 403. The
        // handler reads its own `now_unix()`, so mint an ALREADY-expired invitation (ttl 0, issued in
        // the past) rather than racing the clock.
        let expired =
            cose::mint_overlay_enroll(OverlayMemberRole::Device, "svc/db", 0, now - 10, &root)
                .await
                .unwrap();
        let resp = overlay_enroll(
            Extension(mem_auth(&root)),
            Extension(issuer()),
            Extension(OverlayEnrollHandle(Some(std::sync::Arc::new(StubEnroll(
                OverlayEnrollOutcome::Admitted,
            ))))),
            Json(OverlayEnrollRequest {
                token: expired,
                overlay_pubkey: overlay_pubkey.clone(),
                possession_proof: "00".into(),
                proof_iat: now,
            }),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "an expired invitation must be rejected at the verify step"
        );

        // A non-ed25519 / malformed overlay_pubkey → 400 (before admit).
        let resp = overlay_enroll(
            Extension(mem_auth(&root)),
            Extension(issuer()),
            Extension(OverlayEnrollHandle(Some(std::sync::Arc::new(StubEnroll(
                OverlayEnrollOutcome::Admitted,
            ))))),
            Json(OverlayEnrollRequest {
                token: token.clone(),
                overlay_pubkey: "not-a-key".into(),
                possession_proof: "00".into(),
                proof_iat: now,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ===== Overlay follow-up #3: the per-flow access gate =====================================

    use boatramp_core::overlay_policy::FlowAction;
    use std::sync::Arc as StdArc;

    /// An `Auth` over a fresh in-memory KV, optionally pre-seeded with a stored flow policy.
    async fn auth_with_flow_policy(root: &LocalSigner, policy: Option<&str>) -> Auth {
        let kv: StdArc<dyn KvStore> = StdArc::new(MemoryKv::new());
        if let Some(p) = policy {
            kv.put(
                boatramp_core::authz::OVERLAY_FLOW_POLICY_KEY,
                p.as_bytes().to_vec(),
            )
            .await
            .unwrap();
        }
        Auth::with_key(root.public_key(), kv)
    }

    fn ed25519() -> LocalSigner {
        LocalSigner::generate(TokenAlg::Ed25519)
    }

    fn test_principal() -> crate::auth::VerifiedPrincipal {
        crate::auth::VerifiedPrincipal {
            subject: "tok-1".into(),
            roles: Vec::new(),
        }
    }

    async fn body_string(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).to_string()
    }

    /// MINT-GATE — ALLOW when no policy is stored (feature off): the requested TTL is returned
    /// untouched, preserving pre-feature behavior.
    #[tokio::test]
    async fn flow_gate_allows_when_policy_absent() {
        let root = ed25519();
        let auth = auth_with_flow_policy(&root, None).await;
        let holder = ed25519().public_key();
        let p = test_principal();
        let ttl = overlay_flow_gate(
            &auth,
            Some(&p),
            &holder,
            None,
            FlowAction::Dial,
            "svc/db",
            3600,
            now_unix(),
        )
        .await
        .expect("no policy → allow");
        assert_eq!(ttl, 3600, "feature off → allow at the requested ttl");
    }

    /// MINT-GATE — DENY (403, non-enumerable body) when a policy is stored and no `permit` matches.
    /// MUTATION-RED: if the Deny arm were turned into an allow, `unwrap_err` would panic.
    #[tokio::test]
    async fn flow_gate_denies_when_stored_and_no_permit() {
        let root = ed25519();
        // Permits only svc/other → svc/db is denied by default-deny.
        let auth = auth_with_flow_policy(
            &root,
            Some(r#"permit(principal, action, resource == Overlay::Service::"svc/other");"#),
        )
        .await;
        let holder = ed25519().public_key();
        let p = test_principal();
        let err = overlay_flow_gate(
            &auth,
            Some(&p),
            &holder,
            None,
            FlowAction::Dial,
            "svc/db",
            3600,
            now_unix(),
        )
        .await
        .expect_err("a stored policy with no matching permit must DENY");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
        // REQUIRED #6 — the 403 body is short + non-enumerable (no policy names / diagnostics).
        let body = body_string(err).await;
        assert_eq!(body.trim(), "flow denied by policy");
        assert!(
            !body.contains("svc/") && !body.contains("policy0"),
            "the mint 403 must not enumerate policy detail: {body:?}"
        );
    }

    /// MINT-GATE — ALLOW when a stored policy permits; the returned TTL is the requested one.
    #[tokio::test]
    async fn flow_gate_allows_when_stored_and_permit() {
        let root = ed25519();
        let auth = auth_with_flow_policy(&root, Some("permit(principal, action, resource);")).await;
        let holder = ed25519().public_key();
        let p = test_principal();
        let ttl = overlay_flow_gate(
            &auth,
            Some(&p),
            &holder,
            None,
            FlowAction::Dial,
            "svc/db",
            3600,
            now_unix(),
        )
        .await
        .expect("a matching permit → allow");
        assert_eq!(ttl, 3600);
    }

    /// REQUIRED #2a — TTL = min(requested, policy_ceiling): a policy that allows only ttl ≤ 300
    /// pulls a 3600s request DOWN to 300; a request already within the cap is honored as-is.
    #[tokio::test]
    async fn flow_gate_ttl_is_min_of_requested_and_policy_ceiling() {
        let root = ed25519();
        let auth = auth_with_flow_policy(
            &root,
            Some(r#"permit(principal, action, resource) when { context.ttl_requested <= 300 };"#),
        )
        .await;
        let holder = ed25519().public_key();
        let p = test_principal();
        let shrunk = overlay_flow_gate(
            &auth,
            Some(&p),
            &holder,
            None,
            FlowAction::Dial,
            "svc/db",
            3600,
            now_unix(),
        )
        .await
        .unwrap();
        assert_eq!(shrunk, 300, "the policy ceiling must pull the ttl DOWN");
        let within = overlay_flow_gate(
            &auth,
            Some(&p),
            &holder,
            None,
            FlowAction::Dial,
            "svc/db",
            120,
            now_unix(),
        )
        .await
        .unwrap();
        assert_eq!(
            within, 120,
            "a request within the cap is honored, never raised"
        );
    }

    /// HOLDER-BOUND — a member credential bound to the holder lends its role (a role-gated permit
    /// then matches); a key-only holder is default-deny-safe; a cred for a DIFFERENT key is 400;
    /// an invalid (foreign-signed) cred is 400 — never silently downgraded to key-only.
    #[tokio::test]
    async fn flow_gate_member_cred_bind_and_rejections() {
        let root = ed25519();
        let auth = auth_with_flow_policy(
            &root,
            Some(
                r#"permit(principal, action, resource) when { principal has role && principal.role == "node" };"#,
            ),
        )
        .await;
        let holder_signer = ed25519();
        let holder = holder_signer.public_key();
        let p = test_principal();
        let now = now_unix();

        // Bound cred (role node) → the role-gated permit matches → allow.
        let cred =
            cose::mint_overlay_member(&holder, OverlayMemberRole::Node, "svc/db", 300, now, &root)
                .await
                .unwrap();
        let ttl = overlay_flow_gate(
            &auth,
            Some(&p),
            &holder,
            Some(&cred),
            FlowAction::Dial,
            "svc/db",
            120,
            now,
        )
        .await
        .expect("a bound member cred lends its role → allow");
        assert_eq!(ttl, 120);

        // Key-only (no cred) → role ABSENT → default-deny-safe (403).
        let err = overlay_flow_gate(
            &auth,
            Some(&p),
            &holder,
            None,
            FlowAction::Dial,
            "svc/db",
            120,
            now,
        )
        .await
        .expect_err("a key-only holder must not satisfy a role-gated permit");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);

        // Cred for a DIFFERENT key → 400 (member_key != holder) — REQUIRED #3b.
        let other = ed25519().public_key();
        let cred_other =
            cose::mint_overlay_member(&other, OverlayMemberRole::Node, "svc/db", 300, now, &root)
                .await
                .unwrap();
        let err = overlay_flow_gate(
            &auth,
            Some(&p),
            &holder,
            Some(&cred_other),
            FlowAction::Dial,
            "svc/db",
            120,
            now,
        )
        .await
        .expect_err("a cred bound to a different key must be rejected");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);

        // Invalid cred (foreign signer) → 400, not silent key-only.
        let stranger = ed25519();
        let bad = cose::mint_overlay_member(
            &holder,
            OverlayMemberRole::Node,
            "svc/db",
            300,
            now,
            &stranger,
        )
        .await
        .unwrap();
        let err = overlay_flow_gate(
            &auth,
            Some(&p),
            &holder,
            Some(&bad),
            FlowAction::Dial,
            "svc/db",
            120,
            now,
        )
        .await
        .expect_err("an invalid member cred must be rejected (400), never silent key-only");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    /// FOUR-STATE (gate level) — a stored-but-corrupt policy fails CLOSED (403), never allow. (The
    /// read-error → Unavailable → deny case is exercised in `auth`'s four-state test with a failing
    /// KV; both corrupt and unreadable must deny.)
    #[tokio::test]
    async fn flow_gate_fails_closed_on_corrupt_policy() {
        let root = ed25519();
        let auth = auth_with_flow_policy(&root, Some("this is not a cedar policy")).await;
        let holder = ed25519().public_key();
        let p = test_principal();
        let err = overlay_flow_gate(
            &auth,
            Some(&p),
            &holder,
            None,
            FlowAction::Dial,
            "svc/db",
            300,
            now_unix(),
        )
        .await
        .expect_err("a corrupt stored policy must fail closed (deny)");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    /// A trivial storage for a KV-only `DeployStore` (the policy surfaces touch only the KV).
    struct NullStorage;
    #[async_trait::async_trait]
    impl boatramp_core::Storage for NullStorage {
        async fn get(
            &self,
            _: &str,
        ) -> std::result::Result<boatramp_core::GetObject, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn get_range(
            &self,
            _: &str,
            _: u64,
            _: Option<u64>,
        ) -> std::result::Result<boatramp_core::GetObject, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn put(
            &self,
            _: &str,
            _: boatramp_core::ByteStream,
            _: boatramp_core::PutMeta,
        ) -> std::result::Result<boatramp_core::ObjectMeta, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::unsupported("null"))
        }
        async fn head(
            &self,
            _: &str,
        ) -> std::result::Result<boatramp_core::ObjectMeta, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn delete(&self, _: &str) -> std::result::Result<(), boatramp_core::StorageError> {
            Ok(())
        }
        async fn list(
            &self,
            _: &str,
        ) -> std::result::Result<Vec<boatramp_core::ObjectMeta>, boatramp_core::StorageError>
        {
            Ok(Vec::new())
        }
    }

    fn deploy_store() -> DeployStore {
        DeployStore::new(StdArc::new(NullStorage), StdArc::new(MemoryKv::new()))
    }

    /// PUT HANDLER — validated-on-PUT (a malformed or recurring-temporal policy → 400), the first
    /// stored policy surfaces the default-deny CLIFF warning, and a GET round-trips the text.
    #[tokio::test]
    async fn put_overlay_policy_validates_warns_and_round_trips() {
        let deploy = deploy_store();

        // Malformed → 400 (validated on PUT), nothing stored.
        let resp = put_overlay_policy(
            State(deploy.clone()),
            axum::http::HeaderMap::new(),
            "not cedar".to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // A recurring/complex temporal condition → 400 (REQUIRED #5).
        let resp = put_overlay_policy(
            State(deploy.clone()),
            axum::http::HeaderMap::new(),
            r#"permit(principal, action, resource) when { context.now > 1000 };"#.to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // A valid FIRST policy → 200 + the cliff warning.
        let resp = put_overlay_policy(
            State(deploy.clone()),
            axum::http::HeaderMap::new(),
            "permit(principal, action, resource);".to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(
            body.contains("warning") && body.to_lowercase().contains("default-deny"),
            "the FIRST stored policy must surface the default-deny cliff warning: {body}"
        );

        // GET round-trips the stored text.
        let resp = get_overlay_policy(State(deploy.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text = body_string(resp).await;
        assert!(text.contains("permit(principal, action, resource);"));
    }

    /// TEST HANDLER — the dry-run reflects the stored policy (deny), accepts an inline preview
    /// policy, and NEVER mints. Also surfaces the feature-off note when no policy is stored.
    #[tokio::test]
    async fn test_overlay_policy_dry_run() {
        let deploy = deploy_store();
        let holder = ed25519().public_key().to_hex();

        // Feature off → allow (ungated), with a note.
        let resp = test_overlay_policy(
            State(deploy.clone()),
            Json(OverlayPolicyTestRequest {
                policy: None,
                action: "dial".into(),
                service: "svc/db".into(),
                holder: holder.clone(),
                role: None,
                scope: None,
                enrolled: None,
                requestor: None,
                src_ip: None,
                ttl_requested: 3600,
                now: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("\"allow\""));

        // Store a deny-shaped policy, then the dry-run reports deny with the deciding policy id.
        put_overlay_policy(
            State(deploy.clone()),
            axum::http::HeaderMap::new(),
            r#"permit(principal, action, resource == Overlay::Service::"svc/other");"#.to_string(),
        )
        .await;
        let resp = test_overlay_policy(
            State(deploy.clone()),
            Json(OverlayPolicyTestRequest {
                policy: None,
                action: "dial".into(),
                service: "svc/db".into(),
                holder,
                role: None,
                scope: None,
                enrolled: None,
                requestor: None,
                src_ip: None,
                ttl_requested: 3600,
                now: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("\"deny\""));
    }

    /// NARROW-ONLY (full handler) — with a `permit`-all policy + a resolvable directory, a dial
    /// mints a 201 whose capability is bound to THIS holder and scoped to THIS one service: the
    /// flow decision gates/bounds the TTL ONLY, it never rewrites scope/holder (REQUIRED #2b/#3c).
    #[tokio::test]
    async fn flow_gate_allow_mints_cap_with_unchanged_scope_and_holder() {
        let root = ed25519();
        let root_pub = root.public_key();
        let auth = auth_with_flow_policy(&root, Some("permit(principal, action, resource);")).await;
        let holder_hex = ed25519().public_key().to_hex();
        let directory = OverlayDirectory::from_entries([(
            "svc/db".to_string(),
            OverlayTarget {
                relay: "1.2.3.4:9100".into(),
                relay_id: "ed25519:aa".into(),
                egress_id: "ed25519:bb".into(),
                client_auth: "capability-only".into(),
            },
        )]);
        let resp = overlay_dial(
            Extension(Issuer(Some(StdArc::new(root)))),
            Extension(directory),
            Extension(auth),
            Some(Extension(test_principal())),
            Json(OverlayDialRequest {
                service: "svc/db".into(),
                holder_pubkey: holder_hex.clone(),
                ttl_secs: Some(120),
                overlay_member: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_string(resp).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let token = v["token"].as_str().expect("a minted token");
        let dial = cose::verify_overlay_dial(token, &root_pub, now_unix()).unwrap();
        assert_eq!(
            dial.scope, "svc/db",
            "the policy must NOT rewrite the cap's scope"
        );
        assert_eq!(
            dial.holder, holder_hex,
            "the policy must NOT rewrite the cap's holder"
        );
    }

    /// A deny policy at the full handler → 403 with the flow-denied body (end-to-end).
    #[tokio::test]
    async fn overlay_dial_denied_by_flow_policy_returns_403() {
        let root = ed25519();
        let auth = auth_with_flow_policy(
            &root,
            Some(r#"permit(principal, action, resource == Overlay::Service::"svc/other");"#),
        )
        .await;
        let holder_hex = ed25519().public_key().to_hex();
        let directory = OverlayDirectory::from_entries([(
            "svc/db".to_string(),
            OverlayTarget {
                relay: "1.2.3.4:9100".into(),
                relay_id: "ed25519:aa".into(),
                egress_id: "ed25519:bb".into(),
                client_auth: "capability-only".into(),
            },
        )]);
        let resp = overlay_dial(
            Extension(Issuer(Some(StdArc::new(root)))),
            Extension(directory),
            Extension(auth),
            Some(Extension(test_principal())),
            Json(OverlayDialRequest {
                service: "svc/db".into(),
                holder_pubkey: holder_hex,
                ttl_secs: Some(120),
                overlay_member: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_string(resp).await.trim(), "flow denied by policy");
    }

    /// SYSTEM·ADMIN gating — the three policy routes resolve to `System·Admin` (NOT an `Overlay·*`
    /// tier), and the in-handler tripwire agrees. A lesser `Overlay·*` right is a different
    /// resource, so it cannot satisfy the policy routes.
    #[test]
    fn overlay_policy_routes_are_system_admin_gated() {
        use boatramp_core::authz::{Action, Resource, Right};
        for (m, path) in [
            ("GET", "/api/overlay/policy"),
            ("PUT", "/api/overlay/policy"),
            ("POST", "/api/overlay/policy/test"),
        ] {
            let r = Right::required(m, path).expect("mapped");
            assert_eq!(r.resource, Resource::System, "{m} {path} resource");
            assert_eq!(r.target, None, "{m} {path} target");
            assert_eq!(r.action, Action::Admin, "{m} {path} action");
            assert!(
                assert_overlay_policy_is_system_admin(m, path).is_none(),
                "the in-handler tripwire must admit the System·Admin route {m} {path}"
            );
        }
        // The overlay dial/services tiers are a DIFFERENT resource (Overlay), so they cannot
        // satisfy the System·Admin policy routes — and vice versa (separate authority).
        assert_eq!(
            Right::required("POST", "/api/overlay/dial")
                .unwrap()
                .resource,
            Resource::Overlay
        );
        assert_eq!(
            Right::required("GET", "/api/overlay/services")
                .unwrap()
                .resource,
            Resource::Overlay
        );
    }
}
