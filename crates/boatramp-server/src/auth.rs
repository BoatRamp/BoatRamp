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

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use boatramp_core::authz::{self, AuthzPolicy, Right};
use boatramp_core::cedar::CompiledCedar;
use boatramp_core::cose::{self, TokenError, TokenPublicKey};
use boatramp_core::kv::KvStore;

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
            inner: Some(Arc::new(AuthInner { public, kv })),
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
        let Ok(verified) = cose::verify_credential(bearer, &inner.public, now_unix()) else {
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
        let verified = cose::verify_credential(bearer, &inner.public, now_unix()).ok()?;
        if inner.is_revoked(&verified.cti).await {
            return None;
        }
        Some(verified.roles)
    }

    /// Authorize an API request, or reject it. Callers guard on
    /// [`Auth::is_disabled`] first (a disabled auth allows everything).
    async fn authorize(&self, bearer: &str, method: &str, path: &str) -> Result<(), Reject> {
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
        let verified =
            cose::verify_credential(bearer, &inner.public, now).map_err(Reject::from_token_err)?;
        if inner.is_revoked(&verified.cti).await {
            return Err(Reject::forbidden("token revoked\n"));
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
    match auth.authorize(&bearer, &method, &path).await {
        Ok(()) => next.run(request).await,
        Err(reject) => (reject.status, reject.body).into_response(),
    }
}

fn bearer_token(request: &Request) -> Option<String> {
    let value = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    value.strip_prefix("Bearer ").map(str::to_string)
}

/// The current Unix time in seconds (for token TTL evaluation).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
