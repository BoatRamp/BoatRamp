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

use boatramp_core::time::now_unix;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderName, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use boatramp_core::authz::{self, Action, AuthzPolicy, Resource, Right};
use boatramp_core::cache_coherence::AuthzFence;
use boatramp_core::cedar::CompiledCedar;
use boatramp_core::cose::{self, POP_MAX_BODY_HASH_BYTES, PopClaims, TokenError, TokenPublicKey};
use boatramp_core::kv::{KvError, KvStore};
use boatramp_core::tenancy::PrincipalKind;

/// The header carrying a per-request proof-of-possession (base64url `COSE_Sign1`),
/// signed by the token's holder (`cnf`) key. Lower-case per HTTP/2 conventions.
const POP_HEADER: HeaderName = HeaderName::from_static("boatramp-pop");

use authz::ROOT_ANCHOR_PREFIX;

/// Whether the MF-3 fence mutation seam is armed — the shared-mode authz read then IGNORES the
/// fence and always serves from the local cache, so a missed invalidation keeps being honored and
/// `shared_stale_authz_fence_denies_on_missed_invalidation` goes RED (proving the fence read-through
/// is load-bearing). ALWAYS `false` in a shipped build: the env check compiles in ONLY under
/// `cfg(test)` (this crate's own gates) or the `shared-mode-gate-mutation` feature (a downstream
/// test lane). Shares the one `BOATRAMP_KVSQL_MUTATION` env var, mirroring the WS1–4 seams.
///
/// `pub(crate)` so the GraphQL registry fence ([`crate::graphql_cache`]) reuses the SAME seam — the
/// `remove_authz_fence` mutation drives BOTH the authz-policy read and the registry read back onto
/// the stale cache, so the policy gate AND the registry gate go RED under the one seam.
pub(crate) fn authz_fence_removed() -> bool {
    #[cfg(any(test, feature = "shared-mode-gate-mutation"))]
    {
        std::env::var("BOATRAMP_KVSQL_MUTATION").as_deref() == Ok("remove_authz_fence")
    }
    #[cfg(not(any(test, feature = "shared-mode-gate-mutation")))]
    {
        false
    }
}

/// Whether the MF-4 fail-closed mutation seam is armed — a shared-mode authz read ERROR then reverts
/// to the pre-MF-4 FAIL-OPEN behavior (an unreachable store reads as "not revoked" / falls to the
/// looser default policy), so `shared_fail_closed_on_db_unreachable` goes RED (proving the
/// fail-closed branch is load-bearing). Same gating as [`authz_fence_removed`].
fn authz_fail_open_reverted() -> bool {
    #[cfg(any(test, feature = "shared-mode-gate-mutation"))]
    {
        std::env::var("BOATRAMP_KVSQL_MUTATION").as_deref() == Ok("revert_authz_fail_open")
    }
    #[cfg(not(any(test, feature = "shared-mode-gate-mutation")))]
    {
        false
    }
}

/// Whether `method` is a control-plane WRITE (mutating). Mirrors the `is_write` classification in
/// [`require_auth`] — in shared mode a write's authz decision ALWAYS reads through to the live store
/// (never trusts the cache), so a tightened policy / revoked grant is confirmed before the write and
/// a partition sheds the write (503) rather than letting a stale-authorized mutation proceed.
fn is_write_method(method: &str) -> bool {
    !matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

/// The classification of a bearer presented to a session-channel gate
/// ([`Auth::classify_channel_bearer`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelBearer {
    /// A valid, unrevoked, plain (non-`cnf`) bearer — admit the channel.
    Valid,
    /// A valid, unrevoked, but holder-bound (`cnf`) token — reject: a channel can't
    /// carry a per-request PoP proof for its downstream in-process calls.
    HolderBound,
    /// Missing, malformed, unverifiable, expired, or revoked.
    Invalid,
}

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
    /// **Shared-mode (multi-writer) authz guard** (MF-3 stale-authz fence + MF-4 fail-closed).
    /// `None` in single-writer / Raft mode — the authz reads use `kv` directly and a read error is
    /// best-effort (today's behavior, UNCHANGED). `Some` in multi-writer `shared` mode — the fence
    /// routes authz reads cache-vs-read-through, control-plane WRITES always read through, and a
    /// store-unreachable read error FAILS CLOSED (deny / shed 503). See [`SharedAuthz`].
    shared: Option<SharedAuthz>,
}

/// The shared-mode authz guard carried by [`AuthInner`] in multi-writer mode (MF-3 + MF-4). Built by
/// the node bootstrap ONLY when the control-plane KV backend declares
/// [`WriterModel::MultiWriter`](boatramp_core::kv::WriterModel); single-writer deployments never
/// construct one, so their authz path is byte-for-byte unchanged.
#[derive(Clone)]
struct SharedAuthz {
    /// The UNCACHED backing control-plane store — the authoritative source the fence reads the authz
    /// keyspace THROUGH when it cannot trust the cache (`AuthInner::kv` is the `CachedKv` fast path;
    /// this is its inner store). A read error here is a genuine partition signal → fail closed.
    backing: Arc<dyn KvStore>,
    /// The MF-3 currency fence, shared (by `Arc`) with the cache poller: the poller trips it when a
    /// poll cannot reach the store; the authorizer confirms it after a successful read-through.
    fence: Arc<AuthzFence>,
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
                shared: None,
            })),
        }
    }

    /// Enable the **multi-writer `shared`-mode authz guard** (MF-3 stale-authz fence + MF-4
    /// fail-closed). `backing` is the UNCACHED control-plane store (the `CachedKv`'s inner store)
    /// the fence reads the authz keyspace through when it cannot trust the cache; `fence` is the
    /// [`AuthzFence`] shared with the cache poller. A no-op when auth is disabled. Call it ONLY for a
    /// multi-writer backend; a single-writer / Raft node must NOT (its authz path stays unchanged).
    /// Builder-style and order-independent — [`with_pop`](Self::with_pop) preserves it.
    pub fn with_shared_authz(self, backing: Arc<dyn KvStore>, fence: Arc<AuthzFence>) -> Self {
        match self.inner {
            Some(inner) => Self {
                inner: Some(Arc::new(AuthInner {
                    public: inner.public.clone(),
                    kv: inner.kv.clone(),
                    pop_origin: inner.pop_origin.clone(),
                    require_pop: inner.require_pop,
                    replay: inner.replay.clone(),
                    shared: Some(SharedAuthz { backing, fence }),
                })),
            },
            None => Self { inner: None },
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
                    shared: inner.shared.clone(),
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
        !inner.is_revoked_or_unreadable(&verified.cti).await
    }

    /// Classify a bearer for a session-channel gate (the HTTP `/mcp` endpoint): a
    /// channel authenticates once, then re-authorizes each operation per call, so it
    /// needs a valid **plain** bearer. A holder-bound (`cnf`) token can't produce a
    /// per-request PoP proof for the in-process calls, so it's reported distinctly
    /// (the gate rejects it with a clear message rather than letting every tool call
    /// fail an opaque PoP check).
    pub async fn classify_channel_bearer(&self, bearer: &str) -> ChannelBearer {
        let Some(inner) = &self.inner else {
            return ChannelBearer::Invalid;
        };
        let Ok(verified) = inner.verify_credential_any(bearer, now_unix()).await else {
            return ChannelBearer::Invalid;
        };
        if inner.is_revoked_or_unreadable(&verified.cti).await {
            return ChannelBearer::Invalid;
        }
        if verified.leaf_cnf.is_some() {
            return ChannelBearer::HolderBound;
        }
        ChannelBearer::Valid
    }

    /// Verify a mesh **join token** against the primary root, then — on failure —
    /// the replicated rotation anchor set, returning its single-use `jti`. Because
    /// the anchor set is operator-managed (`auth rotate-root`), a cluster can mint
    /// join tokens with a **distinct mesh-admission key** trusted alongside (not
    /// instead of) the admin-token root — narrowing the admission blast radius
    /// (F8) without a separate signer config or imposing KMS. `Err` when auth is
    /// disabled or the token verifies under no trusted anchor.
    pub async fn verify_join_token(&self, token: &str, now: u64) -> Result<String, TokenError> {
        let Some(inner) = self.inner.as_ref() else {
            return Err(TokenError::Invalid("auth disabled".into()));
        };
        match cose::verify_join(token, &inner.public, now) {
            Ok(jti) => Ok(jti),
            Err(primary_err) => {
                for anchor in inner.rotation_anchors().await {
                    if let Ok(jti) = cose::verify_join(token, &anchor, now) {
                        return Ok(jti);
                    }
                }
                Err(primary_err)
            }
        }
    }

    /// Like [`verify_bearer`](Self::verify_bearer), but returns the token's
    /// granted roles on success. `whoami` uses this so it reports an identity
    /// only for a token that is authentic, **unexpired, and unrevoked** — not for
    /// any signature-valid blob. `None` when auth is disabled or any
    /// check fails.
    pub async fn verify_bearer_roles(&self, bearer: &str) -> Option<Vec<authz::GrantedRole>> {
        let inner = self.inner.as_ref()?;
        let verified = inner.verify_credential_any(bearer, now_unix()).await.ok()?;
        if inner.is_revoked_or_unreadable(&verified.cti).await {
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
    ) -> Result<PrincipalKind, Reject> {
        let inner = self
            .inner
            .as_ref()
            .expect("authorize called on disabled auth");
        // Endpoints not gated by a right (the OIDC→token exchange) authenticate
        // by other means; the router still requires *some* bearer to reach here.
        let Some(required) = Right::required(method, path) else {
            return Ok(PrincipalKind::Tenant);
        };
        let now = now_unix();
        // A control-plane WRITE confirms its authz against the live store (never a stale cache) in
        // shared mode, and a partitioned node sheds the write (503) — there is no leader to absorb it.
        let is_write = is_write_method(method);
        let verified = inner
            .verify_credential_any(bearer, now)
            .await
            .map_err(Reject::from_token_err)?;
        // MF-4 — revocation fails CLOSED in shared mode: `Ok(true)` is revoked; `Ok(false)` is a
        // clean absence (honor the token); `Err` is a store-unreachable partition → SHED (deny /
        // 503), never silently treat an unreadable marker as "not revoked" (the pre-MF-4 hole).
        match inner.revocation(&verified.cti, is_write).await {
            Ok(true) => return Err(Reject::forbidden("token revoked\n")),
            Ok(false) => {}
            Err(_) if inner.fail_closed() && !authz_fail_open_reverted() => {
                return Err(Reject::shed());
            }
            Err(err) => {
                // Single-writer / local mode (a genuine local-store fault, not a routine partition),
                // OR the `revert_authz_fail_open` mutation: preserve the pre-MF-4 fail-OPEN behavior
                // (treat as not revoked) — this is what keeps a single-node deployment UNCHANGED.
                tracing::warn!(%err, "could not read token revocation marker; treating as not revoked");
            }
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
        // MF-3/MF-4 — the policy read is fenced + fails CLOSED in shared mode: a cached policy older
        // than the fence bound `T` (or any write) reads THROUGH to the live store; a store-unreachable
        // `Err` SHEDS (deny / 503) rather than falling to the looser built-in default (privilege
        // escalation). `Ok` still brick-guards a malformed/uncompilable stored policy to the default.
        let (policy, compiled) = match inner.policy(is_write).await {
            Ok(pc) => pc,
            Err(_) => return Err(Reject::shed()),
        };
        // Normalize legacy grants (a pre-0.2.0 `publisher:blog` reads as the `default`
        // project) so a site name minted before the project re-keying still authorizes
        // its now project-qualified route.
        let roles = policy.normalize_grants(&verified.roles);
        if !compiled.authorize(&roles, &required) {
            return Err(Reject::forbidden(
                "token not authorized for this resource\n",
            ));
        }
        // PLAN-system-principal P2 — derive the deployer's CLASS from the SAME verified, normalized
        // grants and the SAME compiled policy that just authorized the request: a token that
        // satisfies the node-global `System·Admin` right (`Resource::System`, no project scope,
        // `Action::Admin`) is the SYSTEM class; anything else is a `Tenant`-class deployer. This is a
        // pure read of already-verified authority — no second credential, no new trust. The caller
        // stashes it as a request extension so the deploy handler can capture it onto `DeployMeta`.
        // MUTATION SEAM (gate `deploy_class_any_is_system`): classify EVERY authorized deployer as
        // System, dropping the exact `System·Admin` predicate — so a project-scoped admin's
        // `run_as: deployer` cron would fire as system. Compiled out of shipped builds; the gate then
        // goes RED (a non-System·Admin deployer must classify as Tenant).
        if sysprincipal_mutation().as_deref() == Some("deploy_class_any_is_system") {
            return Ok(PrincipalKind::System);
        }
        let system_admin = Right::new(Resource::System, None, Action::Admin);
        let kind = if compiled.authorize(&roles, &system_admin) {
            PrincipalKind::System
        } else {
            PrincipalKind::Tenant
        };
        Ok(kind)
    }
}

/// The active system-principal anti-hollow mutation (`BOATRAMP_SYSPRINCIPAL_MUTATION`), or `None`.
/// Present ONLY under `cfg(test)` or the `system-principal-gate-mutation` feature; a shipped build has
/// neither, so the deploy-class derivation keys ONLY on the exact `System·Admin` right and this is a
/// dead `None`.
#[cfg(any(test, feature = "system-principal-gate-mutation"))]
fn sysprincipal_mutation() -> Option<String> {
    std::env::var("BOATRAMP_SYSPRINCIPAL_MUTATION").ok()
}
#[cfg(not(any(test, feature = "system-principal-gate-mutation")))]
#[inline]
fn sysprincipal_mutation() -> Option<String> {
    None
}

impl AuthInner {
    /// The store an authz-keyspace read uses, and whether it is a fence-forced READ-THROUGH
    /// (shared-mode only). Single-writer: always `kv` — today's behavior. Shared mode: the UNCACHED
    /// `backing` when this is a control-plane WRITE (a mutating authz decision never trusts the
    /// cache) OR the MF-3 fence is not current (cache trust lapsed past `T`, or the poller tripped it
    /// on an unreachable store); otherwise the local cache (the NOTIFY fast path).
    fn authz_read_store(&self, is_write: bool) -> (&Arc<dyn KvStore>, bool) {
        match &self.shared {
            None => (&self.kv, false),
            Some(s) => {
                if authz_fence_removed() {
                    // MUTATION (remove_authz_fence): ignore the fence → always serve the local cache,
                    // so a missed invalidation keeps being honored (the fence gate goes RED).
                    (&self.kv, false)
                } else if is_write || !s.fence.is_current() {
                    (&s.backing, true)
                } else {
                    (&self.kv, false)
                }
            }
        }
    }

    /// Whether this node is in shared (multi-writer) mode, where an authz read error is a routine
    /// partition that must FAIL CLOSED (MF-4). Single-writer / Raft returns `false` (UNCHANGED): a
    /// local read error there is a genuine, rare fault, not a routine partition, and Raft replication
    /// keeps every node's applied state current — so the pre-MF-4 best-effort semantics are retained.
    fn fail_closed(&self) -> bool {
        self.shared.is_some()
    }

    /// Whether the token's revocation id (`cti`) is marked revoked. `Ok(true)` = revoked; `Ok(false)`
    /// = a clean absence (`CachedKv` never caches an absent key, so a freshly-written revoke is seen
    /// at once — revocation is fresh by construction); `Err` = the store was UNREACHABLE, so the
    /// caller fails CLOSED in shared mode (MF-4).
    async fn revocation(&self, cti: &str, is_write: bool) -> Result<bool, KvError> {
        let (store, _) = self.authz_read_store(is_write);
        store
            .get(&authz::revoked_key(cti))
            .await
            .map(|v| v.is_some())
    }

    /// Revocation check for the non-`authorize` bearer gates (`verify_bearer`, the MCP channel
    /// classifier, `whoami`), which have no 503 channel. Returns `true` (reject the bearer) when the
    /// token is revoked OR — in shared mode — the marker is UNREACHABLE (fail closed, MF-4), and
    /// `false` otherwise. Single-writer preserves the pre-MF-4 behavior (an error reads as not
    /// revoked); the `revert_authz_fail_open` mutation forces that fail-OPEN path even in shared mode.
    async fn is_revoked_or_unreadable(&self, cti: &str) -> bool {
        match self.revocation(cti, false).await {
            Ok(revoked) => revoked,
            Err(_) => self.fail_closed() && !authz_fail_open_reverted(),
        }
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
        // Route through the fence (shared mode) so a lapsed cache reads the anchor set through to the
        // live store. On a read error the set is empty → a token signed only by a rotation anchor
        // fails verification → DENIED, which is the fail-closed-safe direction (never falsely admits).
        let (store, _) = self.authz_read_store(false);
        store
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
    /// — it is logged and the default used). Returns the raw [`AuthzPolicy`] too, so
    /// the caller can [`normalize_grants`](AuthzPolicy::normalize_grants) (legacy
    /// bare-site grants → the `default` project) with the same policy the authorizer
    /// compiled from.
    async fn policy(&self, is_write: bool) -> Result<(AuthzPolicy, CompiledCedar), KvError> {
        let (store, via_read_through) = self.authz_read_store(is_write);
        let stored = match store.get(authz::POLICY_KEY).await {
            Ok(Some(bytes)) => match serde_json::from_slice::<AuthzPolicy>(&bytes) {
                Ok(p) => Some(p),
                Err(err) => {
                    // Brick-guard (KEPT): a corrupt STORED policy must never wedge the control plane
                    // — it is logged and the default used. Only the UNREACHABLE case fails closed.
                    tracing::warn!(%err, "authz/policy is malformed; using the default policy");
                    None
                }
            },
            Ok(None) => None,
            Err(err) => {
                // MF-4 — a store-unreachable read FAILS CLOSED in shared mode: return the error so
                // `authorize` sheds (503) instead of falling to the LOOSER built-in default (which
                // would be a privilege escalation during a partition). Single-writer / local mode —
                // or the `revert_authz_fail_open` mutation — keeps the pre-MF-4 default-on-error path.
                if self.fail_closed() && !authz_fail_open_reverted() {
                    return Err(err);
                }
                tracing::warn!(%err, "could not read authz/policy; using the default policy");
                None
            }
        };
        // MF-3 — a SUCCESSFUL read-through of the authz keyspace against the live store re-confirms
        // the fence for the bound `T` (so subsequent reads may ride the cache fast path again).
        if via_read_through && let Some(s) = &self.shared {
            s.fence.confirm();
        }
        let policy = stored.unwrap_or_else(AuthzPolicy::default_policy);
        match CompiledCedar::compile(&policy) {
            Ok(c) => Ok((policy, c)),
            Err(err) => {
                tracing::warn!(%err, "authz/policy failed to compile; using the default policy");
                let default = AuthzPolicy::default_policy();
                let compiled =
                    CompiledCedar::compile(&default).expect("the default policy always compiles");
                Ok((default, compiled))
            }
        }
    }
}

/// How long a shed (503) control-plane request should wait before retrying, in seconds. Mirrors the
/// managed-dependency readiness gate's `Retry-After` (`scheduler.rs` `sql_starting_response`).
const SHED_RETRY_AFTER_SECS: u32 = 2;

/// A rejected request: the HTTP status, a short body, and an optional `Retry-After` (for a shed 503).
struct Reject {
    status: StatusCode,
    body: &'static str,
    /// `Some(secs)` → attach a `Retry-After` header (a retryable shed); `None` → a plain rejection.
    retry_after: Option<u32>,
}

impl Reject {
    fn unauthorized(body: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            body,
            retry_after: None,
        }
    }
    fn forbidden(body: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            body,
            retry_after: None,
        }
    }
    /// MF-3/MF-4 **shed**: the shared control-plane store is unreachable, so the node can neither
    /// confirm authz currency nor absorb a write (there is no leader). Return a retryable `503` with
    /// `Retry-After` — a client re-polls rather than being silently stale-authorized or 500'd. This
    /// is the fail-closed outcome for a revoked-token check, a tightened-policy decision, AND a new
    /// control-plane write during a partition.
    fn shed() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: "control plane store unreachable; retry shortly\n",
            retry_after: Some(SHED_RETRY_AFTER_SECS),
        }
    }
    /// Map a token verification failure to a response. An *expired* token is a 401
    /// so a client re-authenticates (re-exchanges); any other verification failure
    /// (bad signature, malformed, wrong algorithm) is also a 401.
    fn from_token_err(err: TokenError) -> Self {
        match err {
            TokenError::Expired => Self::unauthorized("token expired\n"),
            _ => Self::unauthorized("invalid token\n"),
        }
    }

    /// Build the HTTP response, attaching `Retry-After` for a shed.
    fn into_response(self) -> Response {
        match self.retry_after {
            Some(secs) => {
                let mut headers = axum::http::HeaderMap::new();
                if let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string()) {
                    headers.insert(header::RETRY_AFTER, v);
                }
                (self.status, headers, self.body).into_response()
            }
            None => (self.status, self.body).into_response(),
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
    // Authorize (and PoP-bind) the path the client actually sent: for a project-scoped
    // request the `project_scope` layer rewrote the URI to its global form but stashed
    // the original `/api/projects/<proj>/…` path here, so `Right::required` still sees
    // the project-qualified path and enforces the project-scoped right.
    let path = match request.extensions().get::<crate::OriginalPath>() {
        Some(original) => original.0.clone(),
        None => request.uri().path().to_owned(),
    };
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
        Ok(kind) => {
            // PLAN-system-principal P2: stash the SERVER-DERIVED deployer class as a request extension
            // for the deploy handler to capture onto `DeployMeta`. A client can neither set nor read
            // it (it is computed here from the verified rights, after authorization passed).
            let mut request = request;
            request.extensions_mut().insert(VerifiedDeployClass(kind));
            next.run(request).await
        }
        Err(reject) => reject.into_response(),
    }
}

/// The verified deployer's principal class (PLAN-system-principal P2), derived in [`require_auth`]
/// from the authorized token's rights and carried as a request extension so a deploy handler can
/// record it on [`boatramp_core::deploy::DeployMeta`]. SERVER-DERIVED and server-only — never
/// client-settable. Absent when auth is disabled (dev), so a deploy then captures no class.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedDeployClass(pub PrincipalKind);

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
            return Err((StatusCode::BAD_REQUEST, "could not read request body\n").into_response());
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
        assert!(
            auth.verify_bearer(&new_token).await,
            "new-root token now verifies"
        );
        // The primary's tokens verify the whole time.
        let primary_token = cose::mint(&admin_claims(now), &primary).await.unwrap();
        assert!(auth.verify_bearer(&primary_token).await);

        // Retire the old/new anchor → its tokens stop verifying again.
        kv.delete(&anchor).await.unwrap();
        assert!(!auth.verify_bearer(&new_token).await);
        assert!(
            auth.verify_bearer(&primary_token).await,
            "primary still valid"
        );
    }

    #[tokio::test]
    async fn deploy_class_is_system_only_for_a_global_system_admin() {
        // PLAN-system-principal P2: `authorize` returns the deployer CLASS, derived from the SAME
        // verified, normalized grants. A global `admin` (⇒ the node-global System·Admin right) is the
        // System class; a project-scoped admin authorizes its own project but is NOT system.
        let root = holder();
        let auth = auth_with(&root, false);
        let now = now_unix();

        let admin = cose::mint(&admin_claims(now), &root).await.unwrap();
        assert_eq!(
            auth.authorize(&admin, "GET", PATH, None, None).await.ok(),
            Some(PrincipalKind::System),
            "a global System·Admin deployer is captured as the system class"
        );

        // An `operator` holds node-level System·Read (so it authorizes this gated GET) but NOT the
        // node-global System·Admin — a non-system deployer. A scoped `admin` would NOT work here: the
        // default policy's `admin` role carries an unguarded (AnyTarget) System·Admin permit, so the
        // grant's scope attribute does not restrict it — holding `admin` at all IS system.
        let operator = cose::mint(
            &Claims {
                roles: vec![GrantedRole::global("operator")],
                kind: "role".into(),
                ttl_secs: Some(3600),
                now_unix: now,
            },
            &root,
        )
        .await
        .unwrap();
        assert_eq!(
            auth.authorize(&operator, "GET", PATH, None, None)
                .await
                .ok(),
            Some(PrincipalKind::Tenant),
            "an operator (System·Read, not System·Admin) is NOT the system class"
        );
        // CI anti-hollow marker (grepped by the mutation gate): reached ONLY when the operator
        // classified as Tenant. `BOATRAMP_SYSPRINCIPAL_MUTATION=deploy_class_any_is_system` classifies
        // every authorized deployer as System → the operator assertion goes RED before this line.
        println!("SYSTEM PRINCIPAL DEPLOY-CLASS OK");
    }

    #[tokio::test]
    async fn plain_bearer_is_authorized_without_a_proof() {
        let root = holder();
        let auth = auth_with(&root, false);
        let now = now_unix();
        let token = cose::mint(&admin_claims(now), &root).await.unwrap();
        // A non-holder-bound token needs no proof when `require_pop` is off.
        assert!(
            auth.authorize(&token, "GET", PATH, None, None)
                .await
                .is_ok()
        );
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
        assert!(
            auth.authorize(&token, "GET", PATH, Some(&p), None)
                .await
                .is_ok()
        );
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
        assert!(
            auth.authorize(&token, "GET", PATH, Some(&wrong_method), None)
                .await
                .is_err()
        );

        // Wrong path.
        let wrong_path = proof(&h, &token, "GET", "/api/certs", ORIGIN, None, now).await;
        assert!(
            auth.authorize(&token, "GET", PATH, Some(&wrong_path), None)
                .await
                .is_err()
        );

        // Wrong origin (a captured proof relayed to a different fleet).
        let wrong_aud = proof(
            &h,
            &token,
            "GET",
            PATH,
            "https://evil.example.com",
            None,
            now,
        )
        .await;
        assert!(
            auth.authorize(&token, "GET", PATH, Some(&wrong_aud), None)
                .await
                .is_err()
        );

        // Wrong token (proof paired with a different access token's `ath`).
        let other = cose::mint_delegatable(&admin_claims(now), &h.public_key(), &root)
            .await
            .unwrap();
        let wrong_ath = proof(&h, &other, "GET", PATH, ORIGIN, None, now).await;
        assert!(
            auth.authorize(&token, "GET", PATH, Some(&wrong_ath), None)
                .await
                .is_err()
        );

        // Wrong body: proof binds one body, the request carries another.
        let bound = proof(&h, &token, "PUT", PATH, ORIGIN, Some(body.clone()), now).await;
        let tampered = cose::pop_sha256_hex(b"a-different-body");
        assert!(
            auth.authorize(&token, "PUT", PATH, Some(&bound), Some(tampered))
                .await
                .is_err()
        );
        // ...but the matching body authorizes.
        assert!(
            auth.authorize(&token, "PUT", PATH, Some(&bound), Some(body))
                .await
                .is_ok()
        );
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
        assert!(
            auth.authorize(&token, "GET", PATH, Some(&p), None)
                .await
                .is_ok()
        );
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
        assert!(
            auth.authorize(&token, "GET", PATH, Some(&good), None)
                .await
                .is_ok()
        );

        // With no origin configured, a `cnf` token can't be verified → fail closed.
        let unset: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let auth_unset = Auth::with_key(root.public_key(), unset).with_pop(None, false);
        assert!(
            auth_unset
                .authorize(&token, "GET", PATH, Some(&good), None)
                .await
                .is_err()
        );
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
        let chain = cose::attenuate(&base, &h1, &Default::default(), Some(&h2.public_key()), now)
            .await
            .unwrap();

        let auth = auth_with(&root, false);
        // Leaf holder (h2) → authorized.
        let leaf_proof = proof(&h2, &chain, "GET", PATH, ORIGIN, None, now).await;
        assert!(
            auth.authorize(&chain, "GET", PATH, Some(&leaf_proof), None)
                .await
                .is_ok()
        );
        // Intermediate holder (h1) → rejected.
        let stale_proof = proof(&h1, &chain, "GET", PATH, ORIGIN, None, now).await;
        assert!(
            auth.authorize(&chain, "GET", PATH, Some(&stale_proof), None)
                .await
                .is_err()
        );
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
        assert!(
            auth.authorize(&token, "GET", PATH, Some(&p), None)
                .await
                .is_ok()
        );
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

    // ===== MF-3 (stale-authz fence) + MF-4 (fail-closed) shared-mode authz gates =================
    //
    // These model the multi-writer topology backend-agnostically (node B's local cache vs the
    // authoritative shared store), exactly as the WS1–4 core gates model it over `MemoryKv`. Each
    // clean gate asserts the SECURE behavior with the mutation seam UNARMED; a paired `mutation_*`
    // test ARMS the seam (`BOATRAMP_KVSQL_MUTATION`) and asserts the INSECURE behavior — so the CI
    // mutation loop runs the clean gate with the env set and sees it go RED. The live-Postgres twins
    // (same properties over a real multi-writer `SqlKv`) are in `pg_shared_authz_gates`.

    use boatramp_core::cache_coherence::AuthzFence;
    use std::time::Duration;

    /// A `KvStore` whose every op ERRORS — a faithful stand-in for "the shared control-plane DB is
    /// unreachable" (a severed pool). The MF-4 fail-closed gate reads through it.
    struct FailingKv;
    #[async_trait::async_trait]
    impl KvStore for FailingKv {
        async fn get(&self, _k: &str) -> Result<Option<Vec<u8>>, KvError> {
            Err(KvError::backend("db unreachable (test)"))
        }
        async fn put(&self, _k: &str, _v: Vec<u8>) -> Result<(), KvError> {
            Err(KvError::backend("db unreachable (test)"))
        }
        async fn delete(&self, _k: &str) -> Result<(), KvError> {
            Err(KvError::backend("db unreachable (test)"))
        }
        async fn list_prefix(&self, _p: &str) -> Result<Vec<String>, KvError> {
            Err(KvError::backend("db unreachable (test)"))
        }
    }

    /// A `KvStore` that ERRORS only for the authz POLICY key and is empty-but-reachable otherwise —
    /// models "revocation reads fine, the policy read can't reach the DB", so the fail-closed gate
    /// can exercise the policy path distinctly from revocation.
    struct PolicyUnreachableKv;
    #[async_trait::async_trait]
    impl KvStore for PolicyUnreachableKv {
        async fn get(&self, k: &str) -> Result<Option<Vec<u8>>, KvError> {
            if k == authz::POLICY_KEY {
                Err(KvError::backend("policy db unreachable (test)"))
            } else {
                Ok(None) // not revoked; no anchors
            }
        }
        async fn put(&self, _k: &str, _v: Vec<u8>) -> Result<(), KvError> {
            Ok(())
        }
        async fn delete(&self, _k: &str) -> Result<(), KvError> {
            Ok(())
        }
        async fn list_prefix(&self, _p: &str) -> Result<Vec<String>, KvError> {
            Ok(Vec::new())
        }
    }

    /// A plain (non-`cnf`) admin token — needs no PoP proof, so the gates exercise the authz decision.
    async fn admin_token(root: &LocalSigner) -> String {
        cose::mint(&admin_claims(now_unix()), root).await.unwrap()
    }

    /// The `cti` (revocation id) of a token, for seeding a revoke marker.
    fn token_cti(root: &LocalSigner, token: &str) -> String {
        cose::verify_credential(token, &root.public_key(), now_unix())
            .unwrap()
            .cti
    }

    /// Build a shared-mode `Auth` over a local cache + an uncached backing + a fence (MF-3/MF-4).
    fn shared_auth(
        root: &LocalSigner,
        cached: Arc<dyn KvStore>,
        backing: Arc<dyn KvStore>,
        fence: Arc<AuthzFence>,
    ) -> Auth {
        Auth::with_key(root.public_key(), cached)
            .with_pop(Some(ORIGIN.to_string()), false)
            .with_shared_authz(backing, fence)
    }

    /// A VALID but empty policy (compiles, grants nobody) — the "tightened" policy that denies an
    /// `admin` token the right the permissive default grants it.
    fn tightened_policy_bytes() -> Vec<u8> {
        let mut tight = AuthzPolicy::default_policy();
        tight.roles.clear();
        serde_json::to_vec(&tight).unwrap()
    }

    fn default_policy_bytes() -> Vec<u8> {
        serde_json::to_vec(&AuthzPolicy::default_policy()).unwrap()
    }

    /// GATE (MF-3) — a tightened/revoked grant on node A with the NOTIFY publish SUPPRESSED is
    /// DENIED on node B within the fence bound `T` (via read-through), not after the 300s backstop.
    /// B's cache holds the old permissive policy; the authoritative store has the tightened one; the
    /// fence (unable to confirm currency) forces the read-through that enforces the tightening.
    /// RED under `remove_authz_fence` (B keeps serving the stale permissive policy → allows).
    #[tokio::test]
    #[serial_test::serial(shared_authz_env)]
    async fn shared_stale_authz_fence_denies_on_missed_invalidation() {
        let root = holder();
        let token = admin_token(&root).await;

        let cached: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        cached
            .put(authz::POLICY_KEY, default_policy_bytes())
            .await
            .unwrap(); // B's stale cache: admin still allowed
        let backing: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        backing
            .put(authz::POLICY_KEY, tightened_policy_bytes())
            .await
            .unwrap(); // A tightened it; publish suppressed

        let fence = Arc::new(AuthzFence::new(Duration::from_secs(30)));
        fence.trip(); // B cannot confirm currency within T → must read through
        let auth = shared_auth(&root, cached, backing, fence);

        let rej = auth
            .authorize(&token, "GET", PATH, None, None)
            .await
            .unwrap_err();
        assert_eq!(
            rej.status,
            StatusCode::FORBIDDEN,
            "the fence read-through enforces the tightened policy — B denies within T"
        );
    }

    /// The `remove_authz_fence` MUTATION makes MF-3 RED: B ignores the fence, serves the stale
    /// permissive policy from cache, and ALLOWS the request the tightened policy would deny.
    #[tokio::test]
    #[serial_test::serial(shared_authz_env)]
    async fn mutation_remove_authz_fence_serves_stale() {
        // SAFETY: single-threaded within this #[serial] test; cleared before returning.
        unsafe { std::env::set_var("BOATRAMP_KVSQL_MUTATION", "remove_authz_fence") };
        let root = holder();
        let token = admin_token(&root).await;
        let cached: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        cached
            .put(authz::POLICY_KEY, default_policy_bytes())
            .await
            .unwrap();
        let backing: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        backing
            .put(authz::POLICY_KEY, tightened_policy_bytes())
            .await
            .unwrap();
        let fence = Arc::new(AuthzFence::new(Duration::from_secs(30)));
        fence.trip();
        let auth = shared_auth(&root, cached, backing, fence);
        let allowed = auth
            .authorize(&token, "GET", PATH, None, None)
            .await
            .is_ok();
        unsafe { std::env::remove_var("BOATRAMP_KVSQL_MUTATION") };
        assert!(
            allowed,
            "mutation: the fence is ignored, the stale permissive policy is served → the gate is RED"
        );
    }

    /// GATE (MF-3, symmetric) — a token REVOKED on node A with the NOTIFY publish SUPPRESSED is
    /// denied on node B without NOTIFY: B's cache has a stale "not revoked" negative, the shared
    /// store has the revoke marker, and the fence forces the read-through that sees it.
    /// RED under `remove_authz_fence` (B serves the stale negative → honors the revoked token).
    #[tokio::test]
    #[serial_test::serial(shared_authz_env)]
    async fn shared_revoked_token_denied_across_nodes_without_notify() {
        let root = holder();
        let token = admin_token(&root).await;
        let cti = token_cti(&root, &token);

        let cached: Arc<dyn KvStore> = Arc::new(MemoryKv::new()); // stale: no marker
        let backing: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        backing
            .put(&authz::revoked_key(&cti), Vec::new())
            .await
            .unwrap(); // A revoked it; publish suppressed

        let fence = Arc::new(AuthzFence::new(Duration::from_secs(30)));
        fence.trip();
        let auth = shared_auth(&root, cached, backing, fence);
        let rej = auth
            .authorize(&token, "GET", PATH, None, None)
            .await
            .unwrap_err();
        assert_eq!(
            rej.status,
            StatusCode::FORBIDDEN,
            "the revoke is seen via the fence read-through, without NOTIFY"
        );
    }

    #[tokio::test]
    #[serial_test::serial(shared_authz_env)]
    async fn mutation_remove_authz_fence_honors_revoked_token() {
        unsafe { std::env::set_var("BOATRAMP_KVSQL_MUTATION", "remove_authz_fence") };
        let root = holder();
        let token = admin_token(&root).await;
        let cti = token_cti(&root, &token);
        let cached: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let backing: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        backing
            .put(&authz::revoked_key(&cti), Vec::new())
            .await
            .unwrap();
        let fence = Arc::new(AuthzFence::new(Duration::from_secs(30)));
        fence.trip();
        let auth = shared_auth(&root, cached, backing, fence);
        let allowed = auth
            .authorize(&token, "GET", PATH, None, None)
            .await
            .is_ok();
        unsafe { std::env::remove_var("BOATRAMP_KVSQL_MUTATION") };
        assert!(
            allowed,
            "mutation: the stale 'not revoked' negative is served → the revoked token is honored (RED)"
        );
    }

    /// GATE (MF-4) — with the shared DB unreachable, a shared-mode node FAILS CLOSED: (a) a revoked
    /// check sheds (REJECTED, not honored), (b) a policy decision sheds (DENIED, not default-allow),
    /// (c) a new control-plane WRITE sheds 503 + `Retry-After`. RED under `revert_authz_fail_open`.
    #[tokio::test]
    #[serial_test::serial(shared_authz_env)]
    async fn shared_fail_closed_on_db_unreachable() {
        let root = holder();
        let token = admin_token(&root).await;
        let fence = Arc::new(AuthzFence::new(Duration::from_secs(30)));
        fence.trip();

        // (a) the revoked-token check against an unreachable store → shed (not honored).
        let failing: Arc<dyn KvStore> = Arc::new(FailingKv);
        let auth = shared_auth(&root, failing.clone(), failing.clone(), fence.clone());
        let rej = auth
            .authorize(&token, "GET", PATH, None, None)
            .await
            .unwrap_err();
        assert_eq!(
            rej.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "(a) revoked-check unreachable ⇒ SHED, never silently honor"
        );

        // (b) a policy decision when only the policy read is unreachable → shed (not default-allow).
        let polfail: Arc<dyn KvStore> = Arc::new(PolicyUnreachableKv);
        let auth_b = shared_auth(&root, polfail.clone(), polfail, fence.clone());
        let rej_b = auth_b
            .authorize(&token, "GET", PATH, None, None)
            .await
            .unwrap_err();
        assert_eq!(
            rej_b.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "(b) policy unreachable ⇒ SHED, never fall to the looser default"
        );

        // (c) a new control-plane WRITE during the partition → 503 + Retry-After.
        let rej_w = auth
            .authorize(&token, "PUT", "/api/authz/policy", None, None)
            .await
            .unwrap_err();
        assert_eq!(rej_w.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            rej_w.retry_after,
            Some(SHED_RETRY_AFTER_SECS),
            "(c) a shed write carries Retry-After (mirrors the managed-dep readiness gate)"
        );
    }

    #[tokio::test]
    #[serial_test::serial(shared_authz_env)]
    async fn mutation_revert_authz_fail_open_honors_unreachable() {
        unsafe { std::env::set_var("BOATRAMP_KVSQL_MUTATION", "revert_authz_fail_open") };
        let root = holder();
        let token = admin_token(&root).await;
        let fence = Arc::new(AuthzFence::new(Duration::from_secs(30)));
        fence.trip();
        let failing: Arc<dyn KvStore> = Arc::new(FailingKv);
        let auth = shared_auth(&root, failing.clone(), failing, fence);
        let allowed = auth
            .authorize(&token, "GET", PATH, None, None)
            .await
            .is_ok();
        unsafe { std::env::remove_var("BOATRAMP_KVSQL_MUTATION") };
        assert!(
            allowed,
            "mutation: an unreachable store reads as not-revoked + default policy → honored (RED)"
        );
    }

    /// SINGLE-WRITER PRESERVED — with NO shared guard, a local read error keeps the pre-MF-4
    /// semantics: NOT a 503 shed. Revocation reads as not-revoked and policy falls to the default,
    /// so a valid admin token is still authorized (today's single-node behavior, unchanged).
    #[tokio::test]
    async fn local_mode_authz_read_error_does_not_shed() {
        let root = holder();
        let token = admin_token(&root).await;
        let failing: Arc<dyn KvStore> = Arc::new(FailingKv);
        let auth =
            Auth::with_key(root.public_key(), failing).with_pop(Some(ORIGIN.to_string()), false);
        assert!(
            auth.authorize(&token, "GET", PATH, None, None)
                .await
                .is_ok(),
            "single-writer must NOT 503 on a local read error (unchanged semantics)"
        );
    }
}

/// MF-3/MF-4 live-Postgres twins — the SAME fence + fail-closed properties over a REAL multi-writer
/// `SqlKv`, so node B's read-through / shed is exercised against a real shared primary. Env-gated on
/// `BOATRAMP_TEST_PG_URL`; skips CLEANLY when unset. Mirrors the WS2/WS4 live harness; `#[serial]`
/// because the shared `kv` tables are reset per test. Compiled only with `--features sql-postgres`.
#[cfg(all(test, feature = "sql-postgres"))]
mod pg_shared_authz_gates {
    use super::*;
    use boatramp_core::cache_coherence::AuthzFence;
    use boatramp_core::cose::{Claims, LocalSigner, Signer, TokenAlg};
    use boatramp_core::kv::MemoryKv;
    use boatramp_storage::SqlKv;
    use serial_test::serial;
    use std::time::Duration;

    const ORIGIN: &str = "https://cp.example.com";
    const PATH: &str = "/api/sites";

    async fn fresh_pg() -> Option<Arc<dyn KvStore>> {
        let Ok(url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
            eprintln!("skip pg shared-authz gate: BOATRAMP_TEST_PG_URL unset");
            return None;
        };
        let kv = SqlKv::open_postgres(url, Some(8))
            .await
            .expect("open Postgres SqlKv");
        // Clean slate: clear the control-plane keyspace used by these gates.
        for key in kv.list_prefix("authz/").await.unwrap() {
            kv.delete(&key).await.unwrap();
        }
        Some(Arc::new(kv) as Arc<dyn KvStore>)
    }

    fn root() -> LocalSigner {
        LocalSigner::generate(TokenAlg::Es256)
    }

    async fn admin_token(root: &LocalSigner) -> String {
        let now = boatramp_core::time::now_unix();
        let claims = Claims {
            roles: vec![authz::GrantedRole::global("admin")],
            kind: "role".into(),
            ttl_secs: Some(3600),
            now_unix: now,
        };
        cose::mint(&claims, root).await.unwrap()
    }

    fn shared_auth(
        root: &LocalSigner,
        cached: Arc<dyn KvStore>,
        backing: Arc<dyn KvStore>,
        fence: Arc<AuthzFence>,
    ) -> Auth {
        Auth::with_key(root.public_key(), cached)
            .with_pop(Some(ORIGIN.to_string()), false)
            .with_shared_authz(backing, fence)
    }

    fn tightened_policy_bytes() -> Vec<u8> {
        let mut tight = AuthzPolicy::default_policy();
        tight.roles.clear();
        serde_json::to_vec(&tight).unwrap()
    }

    /// LIVE MF-3 — node A tightens the policy on a REAL shared Postgres (NOTIFY suppressed); node B,
    /// whose cache holds the old permissive policy, DENIES via the fence read-through to the primary.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial(shared_authz_env)]
    async fn pg_shared_stale_authz_fence_denies_on_missed_invalidation() {
        let Some(shared) = fresh_pg().await else {
            return;
        };
        let root = root();
        let token = admin_token(&root).await;

        // A writes the tightened policy to the real shared primary.
        shared
            .put(authz::POLICY_KEY, tightened_policy_bytes())
            .await
            .unwrap();
        // B's local cache still holds the permissive default (publish suppressed → never invalidated).
        let cached: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        cached
            .put(
                authz::POLICY_KEY,
                serde_json::to_vec(&AuthzPolicy::default_policy()).unwrap(),
            )
            .await
            .unwrap();

        let fence = Arc::new(AuthzFence::new(Duration::from_secs(30)));
        fence.trip();
        let auth = shared_auth(&root, cached, shared, fence);
        let rej = auth
            .authorize(&token, "GET", PATH, None, None)
            .await
            .unwrap_err();
        assert_eq!(rej.status, StatusCode::FORBIDDEN);
        println!(
            "SERVER PG STALE-AUTHZ FENCE OK [postgres]: node B denied a tightened policy via \
             read-through to the real shared primary (no NOTIFY)."
        );
    }

    /// LIVE MF-3 (symmetric) — a token revoked on the real shared primary (NOTIFY suppressed) is
    /// denied on node B via the fence read-through, despite B's stale "not revoked" cache.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial(shared_authz_env)]
    async fn pg_shared_revoked_token_denied_across_nodes_without_notify() {
        let Some(shared) = fresh_pg().await else {
            return;
        };
        let root = root();
        let token = admin_token(&root).await;
        let cti =
            cose::verify_credential(&token, &root.public_key(), boatramp_core::time::now_unix())
                .unwrap()
                .cti;
        shared
            .put(&authz::revoked_key(&cti), Vec::new())
            .await
            .unwrap();
        let cached: Arc<dyn KvStore> = Arc::new(MemoryKv::new()); // stale: no marker
        let fence = Arc::new(AuthzFence::new(Duration::from_secs(30)));
        fence.trip();
        let auth = shared_auth(&root, cached, shared, fence);
        let rej = auth
            .authorize(&token, "GET", PATH, None, None)
            .await
            .unwrap_err();
        assert_eq!(rej.status, StatusCode::FORBIDDEN);
        println!("SERVER PG REVOKED-ACROSS-NODES OK [postgres]");
    }

    // MF-4 fail-closed is backend-agnostic — "a read returns `Err` ⇒ shed 503" — so its gate runs
    // over the deterministic `FailingKv` in the parent `tests` module (a severed pool returns `Err`
    // exactly as `FailingKv` does). These live twins cover the real-PG dimension that matters most:
    // node B's fence read-through / revoke visibility against a REAL shared primary.
}
