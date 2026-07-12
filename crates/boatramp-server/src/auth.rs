//! Control-plane authorization for the publishing/management API.
//!
//! Every `/api/*` route is gated by the **COSE/CWT + Cedar** authorizer: the
//! request maps to a required [`Right`] (action × resource), the bearer token
//! (a `COSE_Sign1` CWT, RFC 8392/9052) is verified against the root public key,
//! checked against the KV revocation store, then decided by the Cedar policy
//! generated from the RBAC model. There are no legacy single-secret or opaque-KV
//! tokens — COSE is the one credential model (the OIDC→token exchange lives at
//! `/api/auth/exchange`). If no root key is configured, auth is **disabled**
//! (every request allowed — development only); public serving is never gated.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderName, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use boatramp_core::authz::{self, AuthzPolicy, Right};
use boatramp_core::cedar::CompiledCedar;
use boatramp_core::cose::{self, PopClaims, TokenError, TokenPublicKey, POP_MAX_BODY_HASH_BYTES};
use boatramp_core::kv::KvStore;

/// The header carrying a per-request proof-of-possession (base64url `COSE_Sign1`),
/// signed by the token's holder (`cnf`) key. Lower-case per HTTP/2 conventions.
const POP_HEADER: HeaderName = HeaderName::from_static("boatramp-pop");

use authz::ROOT_ANCHOR_PREFIX;

/// Control-plane auth configuration: the token trust anchor (root public key)
/// plus the KV that holds the RBAC policy (`authz/policy`) and revocation markers
/// (`authz/revoked/<id>`). `None` ⇒ auth disabled (development).
#[derive(Clone, Default)]
pub struct Auth {
    inner: Option<Arc<AuthInner>>,
}

struct AuthInner {
    public: TokenPublicKey,
    kv: Arc<dyn KvStore>,
    /// The fleet's canonical public origin (a PoP proof's required `aud`). `None`
    /// ⇒ a holder-bound token cannot be verified here (fails closed).
    pop_origin: Option<String>,
    /// Require **every** token to be holder-bound (`cnf`) and PoP-proven. A `cnf`
    /// token *always* requires a proof regardless of this knob; when `true`, a
    /// plain (non-`cnf`) token is additionally rejected.
    require_pop: bool,
    /// Node-local replay guard for PoP proof `jti`s (window-bounded).
    replay: PopReplayCache,
}

/// A node-local, window-bounded replay guard for PoP proof `jti`s. Bounds
/// **same-node** proof replay within the freshness window; there is deliberately
/// **no** cross-node cache (boatramp's `KvStore` has no atomic CAS outside Raft, so
/// a correct shared cache would cost a consensus round-trip per request). A
/// captured proof can therefore be replayed on a *different* node within the
/// ~`POP_WINDOW_SECS` window — an accepted, documented trade-off, bounded further
/// by the tight window + `ath` token binding + `cti` revocation.
#[derive(Clone, Default)]
struct PopReplayCache {
    seen: Arc<Mutex<HashMap<String, u64>>>,
}

impl PopReplayCache {
    fn new() -> Self {
        Self {
            seen: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record `jti` as seen at `now`; returns `false` if it was already seen within
    /// its validity window (a replay), `true` if fresh. Prunes expired entries on
    /// each call so the map stays bounded by the in-flight proof count.
    fn check_and_insert(&self, jti: &str, now: u64) -> bool {
        let ttl = cose::POP_WINDOW_SECS + cose::POP_SKEW_SECS;
        let expiry = now.saturating_add(ttl);
        let mut seen = self.seen.lock().expect("pop replay cache mutex poisoned");
        seen.retain(|_, exp| *exp > now);
        if seen.contains_key(jti) {
            return false;
        }
        seen.insert(jti.to_string(), expiry);
        true
    }
}

impl Auth {
    /// No authentication (development default).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Enable token auth: verify tokens against the root public key `public`, and
    /// read the RBAC policy + revocation markers from `kv` (front it with the
    /// shared `CachedKv` so policy reads are cheap and ride cache invalidation).
    pub fn with_key(public: TokenPublicKey, kv: Arc<dyn KvStore>) -> Self {
        Self {
            inner: Some(Arc::new(AuthInner {
                public,
                kv,
                pop_origin: None,
                require_pop: false,
                replay: PopReplayCache::new(),
            })),
        }
    }

    /// Configure per-request proof-of-possession enforcement (DPoP): the fleet's
    /// canonical origin a proof must bind (`pop_origin`, the proof `aud`) and
    /// whether **every** token must be holder-bound (`require_pop`). A no-op when
    /// auth is disabled. A holder-bound (`cnf`) token always requires a valid proof
    /// regardless of `require_pop`.
    pub fn with_pop(self, pop_origin: Option<String>, require_pop: bool) -> Self {
        match self.inner {
            Some(inner) => Self {
                inner: Some(Arc::new(AuthInner {
                    public: inner.public.clone(),
                    kv: inner.kv.clone(),
                    pop_origin,
                    require_pop,
                    replay: PopReplayCache::new(),
                })),
            },
            None => Self { inner: None },
        }
    }

    /// Whether no authentication is configured.
    pub fn is_disabled(&self) -> bool {
        self.inner.is_none()
    }

    /// The root public key (verification trust anchor), when auth is enabled —
    /// so a self-service handler like `whoami` can verify the presented token.
    pub fn public_key(&self) -> Option<TokenPublicKey> {
        self.inner.as_ref().map(|i| i.public.clone())
    }

    /// The "any valid token" gate (protected previews): a token that is
    /// authentic, unexpired, and not revoked — no RBAC right required. Returns
    /// `false` when auth is disabled (no tokens exist to present).
    pub async fn verify_bearer(&self, bearer: &str) -> bool {
        let Some(inner) = &self.inner else {
            return false;
        };
        let Ok(verified) = inner.verify_credential_any(bearer, now_unix()).await else {
            return false;
        };
        !inner.is_revoked(&verified.cti).await
    }

    /// Like [`verify_bearer`](Self::verify_bearer), but returns the token's
    /// granted roles on success. `whoami` uses this so it reports an identity
    /// only for a token that is authentic, **unexpired, and unrevoked** — not for
    /// any signature-valid blob. `None` when auth is disabled or any
    /// check fails.
    pub async fn verify_bearer_roles(&self, bearer: &str) -> Option<Vec<authz::GrantedRole>> {
        let inner = self.inner.as_ref()?;
        let verified = inner
            .verify_credential_any(bearer, now_unix())
            .await
            .ok()?;
        if inner.is_revoked(&verified.cti).await {
            return None;
        }
        Some(verified.roles)
    }

    /// Authorize an API request, or reject it. Callers guard on
    /// [`Auth::is_disabled`] first (a disabled auth allows everything). `pop_proof`
    /// is the presented `Boatramp-PoP` header (if any); `body_hash` is the hex
    /// SHA-256 of the (buffered) request body for a write, or `None`.
    async fn authorize(
        &self,
        bearer: &str,
        method: &str,
        path: &str,
        pop_proof: Option<&str>,
        body_hash: Option<String>,
    ) -> Result<(), Reject> {
        let inner = self
            .inner
            .as_ref()
            .expect("authorize called on disabled auth");
        // Endpoints not gated by a right (the OIDC→token exchange) authenticate
        // by other means; the router still requires *some* bearer to reach here.
        let Some(required) = Right::required(method, path) else {
            return Ok(());
        };
        let now = now_unix();
        let verified = inner
            .verify_credential_any(bearer, now)
            .await
            .map_err(Reject::from_token_err)?;
        if inner.is_revoked(&verified.cti).await {
            return Err(Reject::forbidden("token revoked\n"));
        }
        // Proof-of-possession (DPoP): a holder-bound (`cnf`) credential MUST carry a
        // valid per-request proof — always, regardless of the posture knob (RFC 9449:
        // a `cnf` token is presented with a proof or not at all). Never silently
        // accept it as a plain bearer (the anti-downgrade invariant). The
        // `require_pop` knob additionally forbids a non-`cnf` token fleet-wide.
        match &verified.leaf_cnf {
            Some(leaf_cnf) => {
                inner.verify_pop(leaf_cnf, pop_proof, method, path, bearer, body_hash, now)?;
            }
            None if inner.require_pop => {
                return Err(Reject::unauthorized(
                    "proof-of-possession required: present a holder-bound (cnf) token\n",
                ));
            }
            None => {}
        }
        // Delegation caveats can only *subtract* from the root's authority: enforce
        // them before consulting the RBAC policy.
        if !verified.caveats.allows(&required, now) {
            return Err(Reject::forbidden(
                "token not authorized for this resource\n",
            ));
        }
        let policy = inner.policy().await;
        if policy.authorize(&verified.roles, &required) {
            Ok(())
        } else {
            Err(Reject::forbidden(
                "token not authorized for this resource\n",
            ))
        }
    }
}

impl AuthInner {
    /// Whether the token's revocation id (`cti`) is marked revoked in the KV.
    async fn is_revoked(&self, cti: &str) -> bool {
        matches!(self.kv.get(&authz::revoked_key(cti)).await, Ok(Some(_)))
    }

    /// Verify a credential against the primary anchor, then — only on failure —
    /// the replicated **rotation anchor set** (`auth/root/*`). This makes a
    /// `auth rotate-root` make-before-break: both the old and new root keys are
    /// trusted during the overlap, so no node ever rejects a valid token. The
    /// replicated set is consulted only when the primary key doesn't verify (the
    /// rare overlap case), so the common path stays a single in-memory check.
    async fn verify_credential_any(
        &self,
        bearer: &str,
        now: u64,
    ) -> Result<cose::VerifiedChain, TokenError> {
        match cose::verify_credential(bearer, &self.public, now) {
            Ok(v) => Ok(v),
            Err(primary_err) => {
                for anchor in self.rotation_anchors().await {
                    if let Ok(v) = cose::verify_credential(bearer, &anchor, now) {
                        return Ok(v);
                    }
                }
                Err(primary_err)
            }
        }
    }

    /// The replicated rotation anchors — extra root public keys added by
    /// `auth rotate-root` (`auth/root/{es256:hex}`), trusted alongside the primary.
    async fn rotation_anchors(&self) -> Vec<TokenPublicKey> {
        self.kv
            .list_prefix(ROOT_ANCHOR_PREFIX)
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(|k| k.strip_prefix(ROOT_ANCHOR_PREFIX))
            .filter_map(|hex| TokenPublicKey::from_hex(hex).ok())
            .collect()
    }

    /// Require + verify a per-request PoP proof for a holder-bound credential.
    /// Binds the proof to `htm` (method) + `htp` (canonicalized path) + a
    /// **config-set** `aud` (never a forwarded header) + `ath` (the presented
    /// token) + `bh` (the body hash on writes), verified against the credential's
    /// terminal (`leaf`) `cnf` — then a node-local replay check on the proof `jti`.
    #[allow(clippy::too_many_arguments)]
    fn verify_pop(
        &self,
        leaf_cnf: &str,
        proof: Option<&str>,
        method: &str,
        path: &str,
        bearer: &str,
        body_hash: Option<String>,
        now: u64,
    ) -> Result<(), Reject> {
        let Some(proof) = proof else {
            return Err(Reject::unauthorized(
                "missing proof-of-possession (Boatramp-PoP header)\n",
            ));
        };
        // The origin a proof must bind is operator config, never a request header.
        // A `cnf` token is unusable against a server that hasn't set `pop_origin`
        // (its proof cannot be verified) — fail closed, and say so in the log.
        let Some(aud) = self.pop_origin.clone() else {
            tracing::warn!(
                "a holder-bound (cnf) token was presented but `pop_origin` is not \
                 configured; rejecting — set [serve] pop_origin in boatramp.cfg"
            );
            return Err(Reject::unauthorized(
                "proof-of-possession not configured on this server\n",
            ));
        };
        let holder = TokenPublicKey::from_hex(leaf_cnf)
            .map_err(|_| Reject::unauthorized("invalid holder key\n"))?;
        let expected = PopClaims {
            htm: method.to_string(),
            htp: cose::canon_pop_path(path),
            aud,
            ath: cose::pop_sha256_hex(bearer.as_bytes()),
            bh: body_hash,
        };
        let jti = cose::verify_pop(proof, &holder, now, &expected).map_err(|err| match err {
            TokenError::Expired => Reject::unauthorized("proof-of-possession expired\n"),
            _ => Reject::unauthorized("invalid proof-of-possession\n"),
        })?;
        if !self.replay.check_and_insert(&jti, now) {
            return Err(Reject::unauthorized("proof-of-possession replayed\n"));
        }
        Ok(())
    }

    /// Load + compile the RBAC policy from `authz/policy` into a Cedar authorizer,
    /// falling back to the built-in default when absent, unreadable, or
    /// uncompilable (a malformed stored policy must never brick the control plane
    /// — it is logged and the default used).
    async fn policy(&self) -> CompiledCedar {
        let stored = match self.kv.get(authz::POLICY_KEY).await {
            Ok(Some(bytes)) => match serde_json::from_slice::<AuthzPolicy>(&bytes) {
                Ok(p) => Some(p),
                Err(err) => {
                    tracing::warn!(%err, "authz/policy is malformed; using the default policy");
                    None
                }
            },
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(%err, "could not read authz/policy; using the default policy");
                None
            }
        };
        let policy = stored.unwrap_or_else(AuthzPolicy::default_policy);
        match CompiledCedar::compile(&policy) {
            Ok(c) => c,
            Err(err) => {
                tracing::warn!(%err, "authz/policy failed to compile; using the default policy");
                CompiledCedar::compile(&AuthzPolicy::default_policy())
                    .expect("the default policy always compiles")
            }
        }
    }
}

/// A rejected request: the HTTP status + a short body.
struct Reject {
    status: StatusCode,
    body: &'static str,
}

impl Reject {
    fn unauthorized(body: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            body,
        }
    }
    fn forbidden(body: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            body,
        }
    }
    /// Map a token verification failure to a response. An *expired* token is a 401
    /// so a client re-authenticates (re-exchanges); any other verification failure
    /// (bad signature, malformed, wrong algorithm) is also a 401.
    fn from_token_err(err: TokenError) -> Self {
        match err {
            TokenError::Expired => Reject::unauthorized("token expired\n"),
            _ => Reject::unauthorized("invalid token\n"),
        }
    }
}

/// Axum middleware enforcing control-plane auth on the routes it wraps.
pub async fn require_auth(State(auth): State<Auth>, request: Request, next: Next) -> Response {
    if auth.is_disabled() {
        return next.run(request).await;
    }
    let Some(bearer) = bearer_token(&request) else {
        return (StatusCode::UNAUTHORIZED, "missing bearer token\n").into_response();
    };
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let pop_proof = pop_header(&request);

    // On a write, bind the request body into the PoP proof: buffer it (up to a
    // bound) so a hash can be committed to, then hand the buffered bytes
    // downstream. Larger/streamed bodies (blob uploads) pass through unbuffered and
    // are not body-bound. The hash is computed unconditionally for small write
    // bodies; `authorize` only consults it when the token is holder-bound.
    let is_write = !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE");
    let (request, body_hash) = if is_write {
        match buffer_body_for_pop(request).await {
            Ok(pair) => pair,
            Err(response) => return response,
        }
    } else {
        (request, None)
    };

    match auth
        .authorize(&bearer, &method, &path, pop_proof.as_deref(), body_hash)
        .await
    {
        Ok(()) => next.run(request).await,
        Err(reject) => (reject.status, reject.body).into_response(),
    }
}

/// Buffer a write request's body (when its declared length fits the PoP hash
/// bound) so the auth layer can bind its hash, reconstructing the request from the
/// buffered bytes. Bodies with no `Content-Length` or one over the bound stream
/// through untouched and are not body-bound (documented gap). Returns the
/// (possibly reconstructed) request and the body hash (`None` for an empty or
/// unbuffered body).
async fn buffer_body_for_pop(request: Request) -> Result<(Request, Option<String>), Response> {
    let within_bound = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|len| len <= POP_MAX_BODY_HASH_BYTES);
    if !within_bound {
        return Ok((request, None));
    }
    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, POP_MAX_BODY_HASH_BYTES).await {
        Ok(bytes) => bytes,
        // A body that exceeds the bound despite its declared length (or a broken
        // stream) — reject rather than silently drop the body binding.
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, "could not read request body\n").into_response())
        }
    };
    let body_hash = if bytes.is_empty() {
        None
    } else {
        Some(cose::pop_sha256_hex(&bytes))
    };
    Ok((Request::from_parts(parts, Body::from(bytes)), body_hash))
}

fn bearer_token(request: &Request) -> Option<String> {
    let value = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    value.strip_prefix("Bearer ").map(str::to_string)
}

/// The presented per-request PoP proof (the `Boatramp-PoP` header), if any.
fn pop_header(request: &Request) -> Option<String> {
    request
        .headers()
        .get(&POP_HEADER)?
        .to_str()
        .ok()
        .map(str::to_string)
}

/// The current Unix time in seconds (for token TTL evaluation).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::authz::GrantedRole;
    use boatramp_core::cose::{Claims, LocalSigner, Signer, TokenAlg};
    use boatramp_core::kv::MemoryKv;

    const ORIGIN: &str = "https://cp.example.com";
    // A gated GET path (System·Read) an `admin` token is authorized for — reaches
    // the full pipeline (unlike the ungated `/api/auth/exchange`).
    const PATH: &str = "/api/sites";

    fn holder() -> LocalSigner {
        LocalSigner::generate(TokenAlg::Es256)
    }

    fn admin_claims(now: u64) -> Claims {
        Claims {
            roles: vec![GrantedRole::global("admin")],
            kind: "role".into(),
            ttl_secs: Some(3600),
            now_unix: now,
        }
    }

    /// An `Auth` over a fresh in-memory KV (default policy) with `pop_origin`
    /// configured to [`ORIGIN`] and the given `require_pop`.
    fn auth_with(root: &LocalSigner, require_pop: bool) -> Auth {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        Auth::with_key(root.public_key(), kv).with_pop(Some(ORIGIN.to_string()), require_pop)
    }

    /// Mint a PoP proof for `token` bound to the given facts.
    async fn proof(
        holder: &LocalSigner,
        token: &str,
        htm: &str,
        path: &str,
        aud: &str,
        bh: Option<String>,
        now: u64,
    ) -> String {
        cose::mint_pop(
            &PopClaims {
                htm: htm.to_string(),
                htp: cose::canon_pop_path(path),
                aud: aud.to_string(),
                ath: cose::pop_sha256_hex(token.as_bytes()),
                bh,
            },
            holder,
            now,
        )
        .await
        .unwrap()
    }

    /// Make-before-break root rotation: a token signed by a **new** root verifies
    /// only once that key is trusted as a rotation anchor (`auth/root/*`), while
    /// the **primary** root's tokens keep verifying throughout — so there is no
    /// window where a valid token is rejected. Retiring the anchor reverses it.
    #[tokio::test]
    async fn rotation_anchor_is_make_before_break() {
        use boatramp_core::kv::KvStore;
        let primary = holder();
        let new_root = holder();
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let auth = Auth::with_key(primary.public_key(), kv.clone());
        let now = now_unix();

        let new_token = cose::mint(&admin_claims(now), &new_root).await.unwrap();
        // Before rotation: only the primary is trusted, so the new key's token fails.
        assert!(!auth.verify_bearer(&new_token).await);

        // Trust the new key as a rotation anchor (make-before-break).
        let anchor = authz::root_anchor_key(&new_root.public_key().to_hex());
        kv.put(&anchor, Vec::new()).await.unwrap();
        assert!(auth.verify_bearer(&new_token).await, "new-root token now verifies");
        // The primary's tokens verify the whole time.
        let primary_token = cose::mint(&admin_claims(now), &primary).await.unwrap();
        assert!(auth.verify_bearer(&primary_token).await);

        // Retire the old/new anchor → its tokens stop verifying again.
        kv.delete(&anchor).await.unwrap();
        assert!(!auth.verify_bearer(&new_token).await);
        assert!(auth.verify_bearer(&primary_token).await, "primary still valid");
    }

    #[tokio::test]
    async fn plain_bearer_is_authorized_without_a_proof() {
        let root = holder();
        let auth = auth_with(&root, false);
        let now = now_unix();
        let token = cose::mint(&admin_claims(now), &root).await.unwrap();
        // A non-holder-bound token needs no proof when `require_pop` is off.
        assert!(auth.authorize(&token, "GET", PATH, None, None).await.is_ok());
    }

    #[tokio::test]
    async fn cnf_token_requires_a_valid_proof() {
        let root = holder();
        let h = holder();
        let auth = auth_with(&root, false);
        let now = now_unix();
        let token = cose::mint_delegatable(&admin_claims(now), &h.public_key(), &root)
            .await
            .unwrap();

        // No proof → rejected (no silent bearer downgrade), with a 401.
        let rej = auth
            .authorize(&token, "GET", PATH, None, None)
            .await
            .unwrap_err();
        assert_eq!(rej.status, StatusCode::UNAUTHORIZED);

        // A valid proof (bound to the request + config origin + this token) → ok.
        let p = proof(&h, &token, "GET", PATH, ORIGIN, None, now).await;
        assert!(auth
            .authorize(&token, "GET", PATH, Some(&p), None)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn proof_bound_to_the_wrong_facts_is_rejected() {
        let root = holder();
        let h = holder();
        let auth = auth_with(&root, false);
        let now = now_unix();
        let token = cose::mint_delegatable(&admin_claims(now), &h.public_key(), &root)
            .await
            .unwrap();
        let body = cose::pop_sha256_hex(b"the-real-body");

        // Wrong method: proof says PUT, request is GET.
        let wrong_method = proof(&h, &token, "PUT", PATH, ORIGIN, None, now).await;
        assert!(auth
            .authorize(&token, "GET", PATH, Some(&wrong_method), None)
            .await
            .is_err());

        // Wrong path.
        let wrong_path = proof(&h, &token, "GET", "/api/certs", ORIGIN, None, now).await;
        assert!(auth
            .authorize(&token, "GET", PATH, Some(&wrong_path), None)
            .await
            .is_err());

        // Wrong origin (a captured proof relayed to a different fleet).
        let wrong_aud = proof(&h, &token, "GET", PATH, "https://evil.example.com", None, now).await;
        assert!(auth
            .authorize(&token, "GET", PATH, Some(&wrong_aud), None)
            .await
            .is_err());

        // Wrong token (proof paired with a different access token's `ath`).
        let other = cose::mint_delegatable(&admin_claims(now), &h.public_key(), &root)
            .await
            .unwrap();
        let wrong_ath = proof(&h, &other, "GET", PATH, ORIGIN, None, now).await;
        assert!(auth
            .authorize(&token, "GET", PATH, Some(&wrong_ath), None)
            .await
            .is_err());

        // Wrong body: proof binds one body, the request carries another.
        let bound = proof(
            &h,
            &token,
            "PUT",
            PATH,
            ORIGIN,
            Some(body.clone()),
            now,
        )
        .await;
        let tampered = cose::pop_sha256_hex(b"a-different-body");
        assert!(auth
            .authorize(&token, "PUT", PATH, Some(&bound), Some(tampered))
            .await
            .is_err());
        // ...but the matching body authorizes.
        assert!(auth
            .authorize(&token, "PUT", PATH, Some(&bound), Some(body))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn require_pop_forbids_a_plain_bearer_fleetwide() {
        let root = holder();
        let h = holder();
        let auth = auth_with(&root, true); // require_pop on
        let now = now_unix();

        // A plain (non-cnf) token is rejected fleet-wide.
        let plain = cose::mint(&admin_claims(now), &root).await.unwrap();
        let rej = auth
            .authorize(&plain, "GET", PATH, None, None)
            .await
            .unwrap_err();
        assert_eq!(rej.status, StatusCode::UNAUTHORIZED);

        // A holder-bound token with a valid proof still works.
        let token = cose::mint_delegatable(&admin_claims(now), &h.public_key(), &root)
            .await
            .unwrap();
        let p = proof(&h, &token, "GET", PATH, ORIGIN, None, now).await;
        assert!(auth
            .authorize(&token, "GET", PATH, Some(&p), None)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn aud_comes_from_config_never_a_request_header() {
        // The proof binds the server's *configured* origin; a proof bound to any
        // other value (what a spoofed `X-Forwarded-Host` might inject) fails —
        // `authorize` never reads a request header for `aud`, so this is structural.
        let root = holder();
        let h = holder();
        let now = now_unix();
        let token = cose::mint_delegatable(&admin_claims(now), &h.public_key(), &root)
            .await
            .unwrap();

        let auth = auth_with(&root, false); // pop_origin = ORIGIN
        let good = proof(&h, &token, "GET", PATH, ORIGIN, None, now).await;
        assert!(auth
            .authorize(&token, "GET", PATH, Some(&good), None)
            .await
            .is_ok());

        // With no origin configured, a `cnf` token can't be verified → fail closed.
        let unset: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let auth_unset = Auth::with_key(root.public_key(), unset).with_pop(None, false);
        assert!(auth_unset
            .authorize(&token, "GET", PATH, Some(&good), None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn proof_verifies_against_the_leaf_cnf_not_the_root() {
        // root (cnf = h1) → delegation block signed by h1 (cnf = h2). The proof must
        // be signed by the *leaf* holder (h2); the intermediate/root holder (h1) is
        // rejected even though it signed a chain block.
        let root = holder();
        let h1 = holder();
        let h2 = holder();
        let now = now_unix();
        let base = cose::mint_delegatable(&admin_claims(now), &h1.public_key(), &root)
            .await
            .unwrap();
        let chain = cose::attenuate(
            &base,
            &h1,
            &Default::default(),
            Some(&h2.public_key()),
            now,
        )
        .await
        .unwrap();

        let auth = auth_with(&root, false);
        // Leaf holder (h2) → authorized.
        let leaf_proof = proof(&h2, &chain, "GET", PATH, ORIGIN, None, now).await;
        assert!(auth
            .authorize(&chain, "GET", PATH, Some(&leaf_proof), None)
            .await
            .is_ok());
        // Intermediate holder (h1) → rejected.
        let stale_proof = proof(&h1, &chain, "GET", PATH, ORIGIN, None, now).await;
        assert!(auth
            .authorize(&chain, "GET", PATH, Some(&stale_proof), None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_proof_cannot_be_replayed_on_the_same_node() {
        let root = holder();
        let h = holder();
        let auth = auth_with(&root, false);
        let now = now_unix();
        let token = cose::mint_delegatable(&admin_claims(now), &h.public_key(), &root)
            .await
            .unwrap();
        let p = proof(&h, &token, "GET", PATH, ORIGIN, None, now).await;

        // First use succeeds; the same proof (same `jti`) is then a replay → 401.
        assert!(auth
            .authorize(&token, "GET", PATH, Some(&p), None)
            .await
            .is_ok());
        let rej = auth
            .authorize(&token, "GET", PATH, Some(&p), None)
            .await
            .unwrap_err();
        assert_eq!(rej.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn buffer_body_hashes_small_writes_and_streams_large_ones() {
        // A small declared body is buffered, hashed, and reconstructed intact.
        let payload = b"{\"config\":true}".to_vec();
        let req = Request::builder()
            .method("PUT")
            .uri(PATH)
            .header(header::CONTENT_LENGTH, payload.len())
            .body(Body::from(payload.clone()))
            .unwrap();
        let (rebuilt, hash) = buffer_body_for_pop(req).await.unwrap();
        assert_eq!(hash, Some(cose::pop_sha256_hex(&payload)));
        let echoed = axum::body::to_bytes(rebuilt.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(echoed.as_ref(), payload.as_slice());

        // A body whose declared length exceeds the bound is not buffered/hashed.
        let big = Request::builder()
            .method("PUT")
            .uri(PATH)
            .header(header::CONTENT_LENGTH, POP_MAX_BODY_HASH_BYTES + 1)
            .body(Body::empty())
            .unwrap();
        let (_, hash) = buffer_body_for_pop(big).await.unwrap();
        assert_eq!(hash, None);

        // An empty write body binds no hash.
        let empty = Request::builder()
            .method("DELETE")
            .uri(PATH)
            .header(header::CONTENT_LENGTH, 0)
            .body(Body::empty())
            .unwrap();
        let (_, hash) = buffer_body_for_pop(empty).await.unwrap();
        assert_eq!(hash, None);
    }
}
