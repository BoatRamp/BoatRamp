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
                    .into_response()
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
                .into_response()
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

/// Return the active RBAC policy (`authz/policy`), or the built-in default when
/// none is stored — so a `get` always shows the effective policy.
pub(super) async fn get_authz_policy(State(deploy): State<DeployStore>) -> Response {
    match deploy.get_authz_policy().await {
        Ok(Some(policy)) => Json(policy).into_response(),
        Ok(None) => Json(boatramp_core::authz::AuthzPolicy::default_policy()).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Replace the RBAC policy. Rejected (`400`) unless it compiles to a valid Cedar
/// policy set, so a bad policy can never be stored and brick the edge.
pub(super) async fn put_authz_policy(
    State(deploy): State<DeployStore>,
    Json(policy): Json<boatramp_core::authz::AuthzPolicy>,
) -> Response {
    if let Err(err) = boatramp_core::cedar::CompiledCedar::compile(&policy) {
        return (StatusCode::BAD_REQUEST, format!("invalid policy: {err}\n")).into_response();
    }
    match deploy.set_authz_policy(&policy).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
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
