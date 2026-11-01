//! The privsep **authority-API grammar framework** + the **verifiable end-principal CONTEXT
//! primitive (F3)** (privsep Phase 1 — WS-E; design `PLAN-privsep-phase1.md` §3.2 the `Link` trait,
//! §3.4 the authority-API grammar — the mandatory-Security-review deliverable). **SECURITY-CRITICAL —
//! this is the surface a dropped crown-jewel instance exposes to a (possibly RCE'd) frontend.**
//!
//! ## What this ships (framework + context primitive ONLY — the concrete grammars are Phase 2)
//!
//! §3.4 is explicit: Phase 1 ships the grammar *framework* and PINS its load-bearing primitive — the
//! **context argument (F3)** — because the whole model's containment rests on it, so its shape cannot
//! wait. The concrete per-capability grammars (`seal`/`unseal`/`mint_token`/`sign_image`/
//! `mint_dial_cap`) drop in **Phase 2**, each taken through its own Security review. This module
//! therefore ships:
//!
//! 1. A **typed authority-call envelope** over the existing bounded [`LinkEndpoint::send_frame`] /
//!    [`LinkEndpoint::recv_frame`] byte frames: an [`AuthorityLink::call`] carrying an
//!    [`AuthorityCall`] (a context + a bounded request) and returning an [`AuthorityResponse`]. The
//!    request enum admits ONLY bounded operations returning RESULTS — **there is no variant that
//!    returns a key, seed, or KEK**. The TYPE SYSTEM, not a runtime check, forecloses the exfiltration
//!    op (design §3.4.3). Phase 1 ships a single no-op [`AuthorityRequest::Ping`] that proves the
//!    round-trip; the clean typed SEAMS for the Phase-2 grammars are [`AuthorityRequest`] /
//!    [`AuthorityResponse`] (add op + result variants) and [`AuthorityHandler`] (the per-capability
//!    dispatch).
//! 2. The **context primitive (F3)**: [`AuthorityContext`] — the request's OWN authenticated COSE/CWT
//!    bearer token, relayed VERBATIM by the caller and **RE-VALIDATED by the receiving instance
//!    against the PUBLIC trust root on every call** ([`ContextVerifier::verify_context`]). It is a
//!    verifiable CREDENTIAL, NEVER a caller-asserted id.
//! 3. **Audit + rate-limit hooks keyed on the VERIFIED principal** — framework seams
//!    ([`AuthorityAudit`], [`AuthorityRateLimiter`]), not full impls.
//!
//! ## The context primitive (F3) — why a CREDENTIAL, not an id
//!
//! A frontend RCE **IS** the authorized caller on the link: the link's peer identity (the root-wired
//! fd topology on `local`, the dial-cap holder on `tcp`/`overlay`) attests only *which instance* is
//! calling — it is necessary, but it is NOT the authorization. If the context were a tenant/project/
//! site id the frontend merely ASSERTS, a compromised frontend would just assert any tenant and the
//! split would buy nothing. Only a credential the attacker cannot forge — signed by a key the frontend
//! does NOT hold, and RE-VERIFIED downstream against the public trust root — actually names the end
//! principal. So [`AuthorityContext`] carries the request's own signed bearer token and has **no field
//! in which to assert an id**: the only path to a principal is [`ContextVerifier::verify_context`],
//! which re-runs the control-plane verifier. Re-validation needs only the PUBLIC trust root / issuer
//! JWKS (non-secret), so a split `secrets.sealer` instance holding NO `token.signer` can still carry
//! the verifier — a public verifying key is not a secret and widens no exposure (design clarification 4).
//!
//! ## How this relates to [`crate::privsep_unseal`]
//!
//! Both are typed, per-link grammars riding the same bounded [`LinkEndpoint`] frames — but their
//! authorization models are DIFFERENT, deliberately, and they must not be conflated:
//!
//! - **`privsep_unseal`** is the signer-unlock's NARROW instance-to-instance unseal: a `token.signer`
//!   asks the `secrets.sealer` to unseal its OWN sealed key once at boot. It is **instance-authorized**
//!   via the ROOT-WIRED per-link allowlist (the root alone knows the topology and tells the sealer
//!   exactly which single key each link may unseal). Its `UnsealResponse::Unsealed` DOES return key
//!   bytes — correctly, because the whole point is to hand the signer its own key, and the containment
//!   is the allowlist, not the response type.
//! - **WS-E (this module)** is the GENERAL authority-API the Phase-2 capability grammars use to serve
//!   END-PRINCIPAL requests relayed by a frontend. It is **end-principal-authorized** via the verified
//!   [`AuthorityContext`] credential, and its response type admits **NO key-bearing variant at all** —
//!   the ops return bounded RESULTS (a sealed blob, a minted token, a signature), never the key/seed/
//!   KEK. A frontend relaying end-principal requests must never be able to say "give me the key"; the
//!   type system forecloses it.
//!
//! In short: unseal = *the signer bootstrapping its own key, gated by the root*; the authority-API =
//! *the signer serving bounded operations for a re-validated end principal, returning only results*.
//!
//! **Linux-only in Phase 1 (like the sandbox + the link).** The grammar types + the context verifier
//! are platform-independent pure logic (so they unit-test on this darwin dev host); only the parts that
//! touch [`LinkEndpoint`] ([`AuthorityLink`]'s impl + [`serve_authority`]) are `cfg(unix)`, exactly as
//! in [`crate::privsep_unseal`]. The full fork+spawn+sandbox composition stays gated Linux-only by the
//! fail-closed sandbox install.

use serde::{Deserialize, Serialize};

use boatramp_core::cose::{self, TokenError, TokenPublicKey, VerifiedToken};

#[cfg(unix)]
use crate::privsep_link::LinkEndpoint;

// =============================================================================
// 1. The typed authority-call envelope (exfiltration foreclosed by the type system)
// =============================================================================

/// One bounded authority operation a caller may request over the link. **The request enum admits ONLY
/// bounded operations returning RESULTS — there is NO variant that returns, or could be redeemed for, a
/// key / seed / KEK** (design §3.4.3). Phase 1 ships just the no-op round-trip proof; each Phase-2
/// capability grammar adds its own variant HERE (e.g. `Seal { ciphertext_in: … }`, `MintToken {
/// authorized_claims: … }`, `SignImage { digest: …, authorized_repo: … }`), each a request for ONE
/// bounded operation whose [`AuthorityResponse`] carries the RESULT, never the key. Adding a variant is
/// an explicit, Security-reviewed addition — the review gates on "does this op, or its result variant,
/// hand back key material?" (the answer must be no).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityRequest {
    /// The Phase-1 no-op: a liveness / round-trip probe that proves the typed envelope **and** the
    /// context re-validation work end-to-end. It materializes no authority and reads nothing from the
    /// principal — a correct `Pong` means only that the relayed context verified against the trust root
    /// and the frame round-tripped. Phase 2 replaces this as the exemplar with the concrete ops.
    Ping {
        /// An opaque caller nonce echoed back in [`AuthorityResponse::Pong`] (a round-trip witness).
        nonce: u64,
    },
}

impl AuthorityRequest {
    /// A short, non-secret op name for the audit record + the log (never echoes arguments).
    #[must_use]
    pub fn op_name(&self) -> &'static str {
        match self {
            Self::Ping { .. } => "ping",
        }
    }
}

/// The reply to an [`AuthorityRequest`]. **Every variant is either a bounded RESULT or a fail-closed
/// refusal carrying only a non-secret reason — NO variant carries a key, seed, or KEK** (unlike
/// [`crate::privsep_unseal::UnsealResponse::Unsealed`], which intentionally does; see the module doc on
/// how the two grammars differ). This is the type-level exfiltration foreclosure the Security review
/// gates on: a Phase-2 result variant returns the *output* of a bounded operation (a sealed blob, a
/// minted token, a signature) — never the signing/sealing key itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityResponse {
    /// The round-trip proof: the context re-validated and the [`AuthorityRequest::Ping`] nonce is
    /// echoed. Carries no authority and no bytes.
    Pong {
        /// The echoed caller nonce.
        nonce: u64,
    },
    /// A fail-closed refusal — the context was absent / unverifiable / expired, the operation was not
    /// permitted for the verified principal, or a rate-limit tripped. Carries a **non-secret reason
    /// only**, and NEVER any bytes. Mirrors [`crate::privsep_unseal::UnsealResponse::Refused`].
    Refused {
        /// A non-secret reason for the caller + the log (never echoes key material or the token).
        reason: String,
    },
}

/// The wire envelope sent frame-by-frame over the link: a [`AuthorityContext`] (the verifiable
/// end-principal credential) PAIRED with the [`AuthorityRequest`]. Pairing them in one struct makes it
/// **structurally impossible to send a request without a context** — there is no `call` path that omits
/// the credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityCall {
    /// The relayed end-principal credential, re-validated by the receiver before any dispatch.
    pub context: AuthorityContext,
    /// The bounded operation requested.
    pub request: AuthorityRequest,
}

/// A transport-level failure of an authority call — the §3.2 `LinkError`. Application-level refusals are
/// NOT errors here: they ride back as [`AuthorityResponse::Refused`] (the context/authorization outcome
/// is part of the typed reply, exactly as in [`crate::privsep_unseal`]). This error is only for a link
/// that could not carry the call at all (EOF, framing, oversize) or a codec failure.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityError {
    /// The link transport failed (EOF, framing, oversize — from [`LinkEndpoint`]).
    #[error("privsep authority link: {0}")]
    Link(String),
    /// Serializing the call / deserializing the response failed.
    #[error("privsep authority codec: {0}")]
    Codec(String),
}

/// The transport-independent authority-call seam (design §3.2 — the `Link` trait's `call`). Phase 1
/// implements it for the `local` [`LinkEndpoint`]; the `tcp` / `overlay` transports implement the SAME
/// trait in later phases so instance code calls an authority identically regardless of transport.
///
/// `call` is BLOCKING here (the `local` [`LinkEndpoint`] frame I/O is blocking and a control/authority
/// call is request/response, not per-request-hot — design §3.1); a caller bridging into Tokio runs it on
/// a dedicated thread / `spawn_blocking`, exactly as [`crate::privsep_unseal::request_unseal`] is used.
/// (The design sketches `async fn call`; the async signature is realized when the networked transports
/// land — the local transport is blocking and does not need it.)
pub trait AuthorityLink {
    /// Relay one bounded `request` under `context` (the end-principal credential) and return the typed
    /// reply. Never ships key material — the reply type forecloses it. A transport/codec failure is an
    /// [`AuthorityError`]; an authorization refusal is an `Ok(`[`AuthorityResponse::Refused`]`)`.
    fn call(
        &self,
        context: &AuthorityContext,
        request: &AuthorityRequest,
    ) -> Result<AuthorityResponse, AuthorityError>;
}

#[cfg(unix)]
impl AuthorityLink for LinkEndpoint {
    fn call(
        &self,
        context: &AuthorityContext,
        request: &AuthorityRequest,
    ) -> Result<AuthorityResponse, AuthorityError> {
        let call = AuthorityCall {
            context: context.clone(),
            request: request.clone(),
        };
        let bytes = serde_json::to_vec(&call).map_err(|e| AuthorityError::Codec(e.to_string()))?;
        self.send_frame(&bytes)
            .map_err(|e| AuthorityError::Link(e.to_string()))?;
        let reply = self
            .recv_frame()
            .map_err(|e| AuthorityError::Link(e.to_string()))?;
        serde_json::from_slice(&reply).map_err(|e| AuthorityError::Codec(e.to_string()))
    }
}

// =============================================================================
// 2. The context primitive (F3) — a verifiable end-principal CREDENTIAL
// =============================================================================

/// The **context argument (F3)** carried on every authority call: the request's OWN authenticated
/// COSE/CWT bearer token (base64url), relayed VERBATIM by the caller. It is a verifiable CREDENTIAL,
/// **never a caller-asserted id** — note there is deliberately NO `tenant` / `project` / `principal`
/// field here: the only field is the signed token, so a compromised caller has nowhere to assert an
/// identity it cannot prove. The receiver turns it into a principal ONLY by re-validating it against the
/// public trust root ([`ContextVerifier::verify_context`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityContext {
    /// The request's own signed end-principal bearer token (base64url `COSE_Sign1` CWT), as the request
    /// presented it. Opaque on the wire; meaningful only once re-verified against the trust root.
    pub token: String,
}

impl AuthorityContext {
    /// Wrap a relayed bearer token as the call context.
    #[must_use]
    pub fn from_token(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

/// Why a relayed [`AuthorityContext`] was refused — the fail-closed outcome of re-validation. Carries
/// only non-secret reasons; it becomes an [`AuthorityResponse::Refused`] on the wire and a `tracing`
/// warning on the receiver. Fail-closed in every arm: no principal, no partial, no bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextRejection {
    /// No credential was relayed at all (an empty token) — the moral equivalent of asserting an id
    /// with nothing to back it. Refused.
    Absent,
    /// The token is not authentic against the trust root (a forged/tampered/wrong-algorithm/malformed
    /// signature, or a token signed by a key the frontend forged). Refused.
    Unverifiable(String),
    /// The token is authentic but past its `exp`. Refused (the Phase-2 grammar additionally TIGHTENS
    /// the observable-token-replay window — see [`ContextVerifier::verify_context`]).
    Expired,
    /// The token is authentic and unexpired but its claims are wrong for an authority call (e.g. a
    /// kind the grammar does not accept). Refused.
    Claims(String),
}

impl ContextRejection {
    /// A non-secret reason string for the refusal response + the log (never echoes the token).
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Absent => "authority context absent (no end-principal credential relayed)".into(),
            Self::Unverifiable(e) => format!("authority context unverifiable: {e}"),
            Self::Expired => "authority context expired".into(),
            Self::Claims(e) => format!("authority context claims rejected: {e}"),
        }
    }
}

/// A RE-VALIDATED end principal — the output of [`ContextVerifier::verify_context`]. It wraps the
/// [`VerifiedToken`] the control-plane verifier produced, so downstream (Phase-2) grammar handlers read
/// the principal's authority ONLY from a credential the receiver itself re-verified against the trust
/// root, never from a caller-asserted field.
#[derive(Debug, Clone)]
pub struct VerifiedPrincipal {
    token: VerifiedToken,
}

impl VerifiedPrincipal {
    /// The re-verified token (roles, kind, `cti`, `exp`, `cnf`) — the raw credential a Phase-2 handler
    /// inspects for its own scope checks (e.g. "is this principal authorized for THIS ciphertext's
    /// scope?" before any crypto).
    #[must_use]
    pub fn token(&self) -> &VerifiedToken {
        &self.token
    }

    /// A stable, **credential-derived** identity for audit + rate-limit keying — the kind tag plus the
    /// canonical (sorted) set of granted roles. Derived SOLELY from the re-verified token, NEVER from a
    /// caller-asserted field or the calling instance (design §3.4.2). Phase 1 keys the framework hooks
    /// on this; a Phase-2 concrete grammar MAY refine the key to a finer principal claim (e.g. a tenant
    /// / `sub`) carried in the same verified token — the load-bearing invariant is only that it is
    /// credential-derived.
    #[must_use]
    pub fn principal_id(&self) -> String {
        let mut roles: Vec<String> = self
            .token
            .roles
            .iter()
            .map(|r| match &r.target {
                Some(t) => format!("{}@{}", r.name, t),
                None => r.name.clone(),
            })
            .collect();
        roles.sort();
        format!("{}|{}", self.token.kind, roles.join(","))
    }
}

/// The receiver-side context verifier: holds the PUBLIC control-plane trust root and re-validates every
/// relayed [`AuthorityContext`] against it. Built from a [`TokenPublicKey`] — a NON-SECRET verifying key
/// — so an instance holding no signer (e.g. a `secrets.sealer` without `token.signer`) can still carry
/// it, widening no exposure (design clarification 4).
///
/// **Missing verifier ⇒ refuse (fail-closed, by construction).** [`serve_authority`] requires a
/// `&ContextVerifier`, so an instance that holds no trust root cannot build one and therefore cannot
/// stand up an authority server at all — there is no code path that serves authority calls without a
/// verifier.
#[derive(Clone)]
pub struct ContextVerifier {
    /// The control-plane trust anchor (`auth_root_public_key`) — public, non-secret.
    trust_root: TokenPublicKey,
}

impl ContextVerifier {
    /// Build from the public control-plane trust root.
    #[must_use]
    pub fn new(trust_root: TokenPublicKey) -> Self {
        Self { trust_root }
    }

    /// RE-VALIDATE the relayed `context` against the public trust root at `now_unix`, returning the
    /// VERIFIED principal or a fail-closed [`ContextRejection`]. This is the F3 crux: the receiver does
    /// NOT trust the caller's relay — it re-runs the same control-plane verifier
    /// ([`cose::verify`](boatramp_core::cose::verify), the function that authenticates a client's own
    /// presented bearer/role token into a verified principal) against the trust root on EVERY call. An
    /// absent, forged, or expired token refuses — no principal, no dispatch, no bytes.
    ///
    /// **Phase-2 anti-replay watch-item (F3; NOT a Phase-1 blocker).** The Phase-1 primitive is right,
    /// but a frontend RCE can REPLAY any end-principal token it OBSERVES transiting the frontend to the
    /// receiver until that token EXPIRES — so the attacker is bounded to the principals whose tokens
    /// transit the frontend, within each token's lifetime, but not instantly to zero. Phase 1 binds the
    /// context correctly (a token it never saw it cannot forge); Phase 2's concrete grammar must
    /// additionally TIGHTEN the observable-token window: short token lifetimes, PoP / `cnf`-binding
    /// (bind the token to a key the frontend does not hold, defeating bare replay), and/or per-call
    /// anti-replay nonces. Named here so Phase 2 does not miss it.
    pub fn verify_context(
        &self,
        context: &AuthorityContext,
        now_unix: u64,
    ) -> Result<VerifiedPrincipal, ContextRejection> {
        // An empty token is "assert an id with nothing behind it" — refuse before touching the verifier.
        if context.token.is_empty() {
            return Err(ContextRejection::Absent);
        }
        // Re-validate against the PUBLIC trust root — the reused control-plane bearer verifier. We do
        // NOT reinvent verification; `cose::verify` checks the COSE signature (algorithm pinned to the
        // trust root's) and the expiry, then yields the verified principal (its granted roles + kind).
        match cose::verify(&context.token, &self.trust_root, now_unix) {
            Ok(token) => Ok(VerifiedPrincipal { token }),
            Err(TokenError::Expired) => Err(ContextRejection::Expired),
            Err(e @ (TokenError::Invalid(_) | TokenError::Key(_))) => {
                // Not authentic (bad signature / framing / wrong algorithm) — the presenter is
                // unauthenticated. A plaintext asserted id lands here too: it is not a signed token.
                Err(ContextRejection::Unverifiable(e.to_string()))
            }
            Err(e @ TokenError::Claims(_)) => {
                // Authentic but the claims are wrong for an authority call.
                Err(ContextRejection::Claims(e.to_string()))
            }
            // Build/Signer errors are mint-side; on the verify path they are not expected, but map
            // them fail-closed to Unverifiable rather than leaking a different outcome.
            Err(e) => Err(ContextRejection::Unverifiable(e.to_string())),
        }
    }
}

// =============================================================================
// 3. Framework hooks keyed on the VERIFIED principal (audit + rate-limit)
// =============================================================================

/// One append-only authority-audit record, keyed on the VERIFIED principal (never the calling instance
/// or an asserted field). Carries only non-secret fields: the credential-derived principal id, the op
/// name, and the outcome. It NEVER carries the token, arguments, or any bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityAuditEntry {
    /// The credential-derived principal id ([`VerifiedPrincipal::principal_id`]).
    pub principal_id: String,
    /// The requested op ([`AuthorityRequest::op_name`]).
    pub op: &'static str,
    /// The call outcome.
    pub outcome: AuthorityOutcome,
}

/// The outcome of a context-verified authority call, for the audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityOutcome {
    /// The op ran and returned a result.
    Served,
    /// The verified principal tripped the rate-limit (throttle / abuse-detection, F9).
    RateLimited,
}

/// The **append-only, RECEIVER-SIDE audit sink** (design §3.4.2 / F9). It is **write-only from the
/// caller's view** — the trait exposes only [`record`](AuthorityAudit::record), no read — so a
/// compromised caller cannot read or tamper the record of what it asked. The sink lives on the
/// receiving (authority-holding) instance. Phase 1 ships the seam + a `tracing` default; a Phase-2
/// grammar can back it with a durable append-only store.
///
/// Implementations MUST NOT return any data to the caller from `record` (append-only) and MUST key on
/// the verified `principal_id` carried in the entry (never on a caller-asserted field).
pub trait AuthorityAudit: Send + Sync {
    /// Append one record. Infallible from the caller's view (a sink that cannot persist logs its own
    /// failure; it never signals back to the authority caller — append-only, write-only).
    fn record(&self, entry: &AuthorityAuditEntry);
}

/// The default audit sink: append-only to the `tracing` log on the receiving instance. Receiver-side
/// and write-only — the authority caller sees nothing of it.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingAudit;

impl AuthorityAudit for TracingAudit {
    fn record(&self, entry: &AuthorityAuditEntry) {
        tracing::info!(
            principal = %entry.principal_id,
            op = entry.op,
            outcome = ?entry.outcome,
            "[privsep] authority call audited"
        );
    }
}

/// The rate-limit decision for one verified principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// The call may proceed.
    Allow,
    /// The call is throttled (the per-principal or global cap tripped).
    Throttled,
}

/// The per-verified-principal (+ global) rate-limit hook (design §3.4 / F9). **Rate-limit is
/// THROTTLE / abuse-detection, NOT containment** — the containment is the context-binding; a
/// correctly-bound grammar is already safe without it. It caps blast *rate* and surfaces an anomaly.
/// Keyed on the VERIFIED `principal_id` (never the calling instance or an asserted field). Phase 1
/// ships the seam + an [`Unlimited`] default; a Phase-2 grammar wires a real token-bucket.
pub trait AuthorityRateLimiter: Send + Sync {
    /// Check-and-consume one unit for `principal_id` (an implementation also enforces its own global
    /// cap). Returns whether the call may proceed.
    fn check(&self, principal_id: &str) -> RateLimitDecision;
}

/// The default limiter: never throttles (the containment is the context-binding, not the rate-limit —
/// F9). A hardened composition swaps in a real token-bucket; the seam is unchanged.
#[derive(Debug, Default, Clone, Copy)]
pub struct Unlimited;

impl AuthorityRateLimiter for Unlimited {
    fn check(&self, _principal_id: &str) -> RateLimitDecision {
        RateLimitDecision::Allow
    }
}

// =============================================================================
// The per-capability dispatch seam + the receiver-side serve loop
// =============================================================================

/// The per-capability authority dispatch (the Phase-2 grammar seam). An implementation handles ONE
/// bounded, already-context-verified request and returns a bounded [`AuthorityResponse`]. Phase 1 ships
/// [`PingHandler`]; each Phase-2 capability (`secrets.sealer`, `token.signer`, …) implements this with
/// its concrete grammar, re-checking the verified `principal`'s scope BEFORE any crypto and returning
/// only RESULTS (the response type forecloses returning a key).
///
/// Async because the Phase-2 ops (seal/mint/sign) are async crypto, exactly like
/// [`crate::privsep_unseal::SealedKeyResolver`].
#[async_trait::async_trait]
pub trait AuthorityHandler: Send + Sync {
    /// Handle one request for a RE-VALIDATED `principal`. Never returns key material. An op the handler
    /// does not permit for this principal returns [`AuthorityResponse::Refused`] (no bytes).
    async fn handle(
        &self,
        principal: &VerifiedPrincipal,
        request: AuthorityRequest,
    ) -> AuthorityResponse;
}

/// The Phase-1 no-op handler: answers [`AuthorityRequest::Ping`] with a matching
/// [`AuthorityResponse::Pong`]. It reads nothing from the principal — a correct `Pong` proves only that
/// the relayed context re-validated (that check ran before dispatch) and the frame round-tripped. The
/// exemplar the Phase-2 handlers replace.
#[derive(Debug, Default, Clone, Copy)]
pub struct PingHandler;

#[async_trait::async_trait]
impl AuthorityHandler for PingHandler {
    async fn handle(
        &self,
        _principal: &VerifiedPrincipal,
        request: AuthorityRequest,
    ) -> AuthorityResponse {
        match request {
            AuthorityRequest::Ping { nonce } => AuthorityResponse::Pong { nonce },
        }
    }
}

/// Serve authority calls from ONE peer over `link`, re-validating every call's context against the
/// trust root (fail-closed) before dispatch. The receiver-side crux, mirroring
/// [`crate::privsep_unseal::serve_unseal`]'s shape:
///
/// 1. receive one bounded, typed [`AuthorityCall`] (fail-closed on oversize / framing in `recv_frame`);
/// 2. RE-VALIDATE its [`AuthorityContext`] against the trust root ([`ContextVerifier::verify_context`]);
///    a rejection ⇒ reply [`AuthorityResponse::Refused`] (no bytes), LOG, keep serving — a compromised
///    frontend relaying a forged/absent/expired credential reaches no authority;
/// 3. check the per-verified-principal rate-limit (throttle / abuse-detection, F9) — a trip ⇒ audit
///    `RateLimited` + reply `Refused`, keep serving;
/// 4. else dispatch to the per-capability `handler`, AUDIT the outcome keyed on the verified principal,
///    and reply with the handler's bounded result.
///
/// Loops until the peer closes the link (EOF) — a clean EOF is the normal end. Async (the handler is
/// async); the caller drives it on the instance's runtime (the blocking link I/O is fine on a dedicated
/// serve task, as in `serve_unseal`). `link_name` is for the log only.
///
/// A context rejection is LOGGED (there is no verified principal to key an audit entry on) but NOT
/// written to the principal-keyed audit sink — the sink records only context-VERIFIED calls, which is
/// precisely "keyed on the verified principal" (design §3.4.2).
#[cfg(unix)]
pub async fn serve_authority(
    link_name: &str,
    link: &LinkEndpoint,
    verifier: &ContextVerifier,
    limiter: &dyn AuthorityRateLimiter,
    audit: &dyn AuthorityAudit,
    handler: &dyn AuthorityHandler,
    now_unix: impl Fn() -> u64,
) -> Result<(), String> {
    loop {
        // (1) Receive one bounded, typed call (fail-closed on oversize / framing, in `recv_frame`).
        let frame = match link.recv_frame() {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::debug!(link = %link_name, "[privsep] authority: peer closed the link (EOF)");
                return Ok(());
            }
            Err(e) => return Err(format!("recv on link {link_name:?}: {e}")),
        };
        let call: AuthorityCall = match serde_json::from_slice(&frame) {
            Ok(c) => c,
            Err(e) => {
                // A malformed call is a protocol fault — refuse + keep serving (fail-closed).
                tracing::warn!(link = %link_name, error = %e, "[privsep] authority: malformed call — refusing");
                send_response(
                    link,
                    &AuthorityResponse::Refused {
                        reason: "malformed authority call".to_string(),
                    },
                )?;
                continue;
            }
        };
        let op = call.request.op_name();

        // (2) RE-VALIDATE the context against the trust root — the F3 crux. A rejection reaches no
        // authority: refused, logged, no principal-keyed audit entry (there is no verified principal).
        let principal = match verifier.verify_context(&call.context, now_unix()) {
            Ok(p) => p,
            Err(rejection) => {
                tracing::warn!(
                    link = %link_name,
                    op,
                    reason = %rejection.reason(),
                    "[privsep] authority REFUSED: context did not re-validate against the trust root (fail-closed)"
                );
                send_response(
                    link,
                    &AuthorityResponse::Refused {
                        reason: rejection.reason(),
                    },
                )?;
                continue;
            }
        };
        let principal_id = principal.principal_id();

        // (3) Per-verified-principal rate-limit (throttle / abuse-detection, NOT containment — F9).
        if limiter.check(&principal_id) == RateLimitDecision::Throttled {
            audit.record(&AuthorityAuditEntry {
                principal_id: principal_id.clone(),
                op,
                outcome: AuthorityOutcome::RateLimited,
            });
            tracing::warn!(link = %link_name, principal = %principal_id, op, "[privsep] authority throttled");
            send_response(
                link,
                &AuthorityResponse::Refused {
                    reason: "rate-limited".to_string(),
                },
            )?;
            continue;
        }

        // (4) Dispatch to the per-capability handler; audit (keyed on the verified principal) + reply.
        let response = handler.handle(&principal, call.request).await;
        audit.record(&AuthorityAuditEntry {
            principal_id,
            op,
            outcome: AuthorityOutcome::Served,
        });
        send_response(link, &response)?;
    }
}

/// Serialize + send one [`AuthorityResponse`] frame. Unlike `privsep_unseal`'s `send_response`, the
/// buffer needs no zeroizing — an [`AuthorityResponse`] never carries key material (the type forecloses
/// it), only a nonce or a non-secret reason.
#[cfg(unix)]
fn send_response(link: &LinkEndpoint, resp: &AuthorityResponse) -> Result<(), String> {
    let bytes =
        serde_json::to_vec(resp).map_err(|e| format!("encoding authority response: {e}"))?;
    link.send_frame(&bytes)
        .map_err(|e| format!("sending authority response: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::cose::{Claims, LocalSigner, Signer, TokenAlg};

    // ---- helpers: a real signer + minted bearer tokens, backend-agnostic ----

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build a current-thread runtime")
    }

    /// Mint a valid role bearer token (`br_kind = "role"`) with `ttl` seconds from `now`.
    fn mint_token(signer: &LocalSigner, now: u64, ttl: Option<u64>) -> String {
        let claims = Claims {
            roles: Vec::new(),
            kind: boatramp_core::cose::KIND_ROLE.to_string(),
            ttl_secs: ttl,
            now_unix: now,
        };
        runtime()
            .block_on(cose::mint(&claims, signer))
            .expect("mint")
    }

    // ---- the typed envelope forecloses key exfiltration (structural assertion) ----

    /// The response type admits NO key-bearing variant: exhaustive match proves the only data a reply
    /// can carry is a `u64` nonce or a non-secret `String` reason. A future (Phase-2) variant that
    /// broke this would fail to compile this exhaustive match without being reviewed — the guard.
    #[test]
    fn response_admits_no_key_material() {
        for resp in [
            AuthorityResponse::Pong { nonce: 7 },
            AuthorityResponse::Refused { reason: "x".into() },
        ] {
            match resp {
                // A nonce is not key material; a reason is a non-secret string. There is deliberately
                // no `Unsealed { key }` / `Minted { … }`-with-key / `Kek { … }` arm here, unlike
                // `privsep_unseal::UnsealResponse`. Phase-2 result variants return the OUTPUT of a
                // bounded op (a sealed blob / a token / a signature), never the key — reviewed on add.
                AuthorityResponse::Pong { nonce: _ } => {}
                AuthorityResponse::Refused { reason: _ } => {}
            }
        }
    }

    // ---- context re-validation (the F3 crux) ----

    #[test]
    fn valid_token_verifies_to_a_principal() {
        let now = 1_000;
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let verifier = ContextVerifier::new(signer.public_key());
        let ctx = AuthorityContext::from_token(mint_token(&signer, now, Some(300)));
        let principal = verifier
            .verify_context(&ctx, now + 1)
            .expect("a valid relayed bearer re-validates to a principal");
        assert_eq!(principal.token().kind, boatramp_core::cose::KIND_ROLE);
    }

    #[test]
    fn forged_token_is_rejected_fail_closed() {
        // A token minted by a DIFFERENT key (what a frontend RCE that lacks the trust-root private key
        // can at best produce) does not verify against the real trust root.
        let now = 1_000;
        let real = LocalSigner::generate(TokenAlg::Es256);
        let attacker = LocalSigner::generate(TokenAlg::Es256);
        let verifier = ContextVerifier::new(real.public_key());
        let ctx = AuthorityContext::from_token(mint_token(&attacker, now, Some(300)));
        let err = verifier.verify_context(&ctx, now + 1).unwrap_err();
        assert!(
            matches!(err, ContextRejection::Unverifiable(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn absent_token_is_rejected_fail_closed() {
        let verifier = ContextVerifier::new(LocalSigner::generate(TokenAlg::Es256).public_key());
        let err = verifier
            .verify_context(&AuthorityContext::from_token(""), 1_000)
            .unwrap_err();
        assert_eq!(err, ContextRejection::Absent);
    }

    #[test]
    fn expired_token_is_rejected_fail_closed() {
        let now = 1_000;
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let verifier = ContextVerifier::new(signer.public_key());
        let ctx = AuthorityContext::from_token(mint_token(&signer, now, Some(60)));
        // Verify well past `exp`.
        let err = verifier.verify_context(&ctx, now + 61).unwrap_err();
        assert_eq!(err, ContextRejection::Expired);
    }

    #[test]
    fn asserted_id_without_credential_is_rejected() {
        // An attacker ASSERTS a tenant id as the "context" — but `AuthorityContext` has no id field;
        // the only field is the token, and a plaintext id is not a signed token, so it is unverifiable.
        // This is the whole F3 point: an asserted id buys nothing.
        let verifier = ContextVerifier::new(LocalSigner::generate(TokenAlg::Es256).public_key());
        let ctx = AuthorityContext::from_token("tenant-acme"); // a bare asserted id, not a credential
        let err = verifier.verify_context(&ctx, 1_000).unwrap_err();
        assert!(
            matches!(err, ContextRejection::Unverifiable(_)),
            "got {err:?}"
        );
    }

    // ---- audit sink: append-only + receiver-side, keyed on the verified principal ----

    /// A receiver-side collecting sink for the harness. The append-only CALLER-FACING contract is the
    /// `AuthorityAudit` trait (write-only — only `record`); `drain` is a test-only inspection that is
    /// NOT part of that trait, so a caller still cannot read the record.
    #[derive(Default)]
    struct CollectingAudit(std::sync::Mutex<Vec<AuthorityAuditEntry>>);
    impl AuthorityAudit for CollectingAudit {
        fn record(&self, entry: &AuthorityAuditEntry) {
            self.0.lock().unwrap().push(entry.clone());
        }
    }
    impl CollectingAudit {
        fn drain(&self) -> Vec<AuthorityAuditEntry> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    #[test]
    fn audit_entry_keys_on_the_verified_principal() {
        let now = 1_000;
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let verifier = ContextVerifier::new(signer.public_key());
        let ctx = AuthorityContext::from_token(mint_token(&signer, now, Some(300)));
        let principal = verifier.verify_context(&ctx, now + 1).unwrap();
        // The audit key is the credential-derived principal id, never a caller-asserted field.
        let audit = CollectingAudit::default();
        audit.record(&AuthorityAuditEntry {
            principal_id: principal.principal_id(),
            op: AuthorityRequest::Ping { nonce: 1 }.op_name(),
            outcome: AuthorityOutcome::Served,
        });
        let entries = audit.drain();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].principal_id, principal.principal_id());
        assert_eq!(entries[0].op, "ping");
    }

    // ---- rate-limit keys on the verified principal ----

    /// A limiter that throttles exactly the principals it was told to, by their verified id.
    struct DenyPrincipals(std::collections::BTreeSet<String>);
    impl AuthorityRateLimiter for DenyPrincipals {
        fn check(&self, principal_id: &str) -> RateLimitDecision {
            if self.0.contains(principal_id) {
                RateLimitDecision::Throttled
            } else {
                RateLimitDecision::Allow
            }
        }
    }

    #[test]
    fn rate_limit_keys_on_the_verified_principal() {
        let now = 1_000;
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let verifier = ContextVerifier::new(signer.public_key());
        let principal = verifier
            .verify_context(
                &AuthorityContext::from_token(mint_token(&signer, now, Some(300))),
                now + 1,
            )
            .unwrap();
        let id = principal.principal_id();
        // The limiter decision is taken on the VERIFIED principal id.
        let mut denied = std::collections::BTreeSet::new();
        denied.insert(id.clone());
        assert_eq!(
            DenyPrincipals(denied).check(&id),
            RateLimitDecision::Throttled
        );
        assert_eq!(
            DenyPrincipals(std::collections::BTreeSet::new()).check(&id),
            RateLimitDecision::Allow
        );
        assert_eq!(Unlimited.check(&id), RateLimitDecision::Allow);
    }

    // ---- end-to-end over a real socketpair (unix) ----

    #[cfg(unix)]
    mod unix {
        use super::*;

        #[test]
        fn ping_round_trips_under_a_valid_context() {
            let now = 1_000;
            let signer = LocalSigner::generate(TokenAlg::Es256);
            let trust_root = signer.public_key();
            let ctx = AuthorityContext::from_token(mint_token(&signer, now, Some(300)));

            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = std::thread::spawn(move || {
                runtime().block_on(async {
                    serve_authority(
                        "to-signer",
                        &server_end,
                        &ContextVerifier::new(trust_root),
                        &Unlimited,
                        &TracingAudit,
                        &PingHandler,
                        || 1_001,
                    )
                    .await
                })
            });

            let resp = client_end
                .call(&ctx, &AuthorityRequest::Ping { nonce: 42 })
                .expect("the call round-trips");
            assert_eq!(resp, AuthorityResponse::Pong { nonce: 42 });

            drop(client_end); // EOF → the serve loop returns Ok
            server.join().unwrap().expect("serve ends cleanly on EOF");
        }

        #[test]
        fn forged_context_is_refused_no_pong() {
            // A compromised frontend relays a token it forged with a key it holds (not the trust root):
            // the receiver re-validates and REFUSES — no `Pong`, and it keeps serving.
            let now = 1_000;
            let real = LocalSigner::generate(TokenAlg::Es256);
            let attacker = LocalSigner::generate(TokenAlg::Es256);
            let trust_root = real.public_key();
            let good_ctx = AuthorityContext::from_token(mint_token(&real, now, Some(300)));
            let forged_ctx = AuthorityContext::from_token(mint_token(&attacker, now, Some(300)));

            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = std::thread::spawn(move || {
                runtime().block_on(async {
                    serve_authority(
                        "to-signer",
                        &server_end,
                        &ContextVerifier::new(trust_root),
                        &Unlimited,
                        &TracingAudit,
                        &PingHandler,
                        || 1_001,
                    )
                    .await
                })
            });

            // The forged context is refused (no bytes, no pong) ...
            let resp = client_end
                .call(&forged_ctx, &AuthorityRequest::Ping { nonce: 1 })
                .expect("the link still carries the call");
            assert!(
                matches!(resp, AuthorityResponse::Refused { .. }),
                "got {resp:?}"
            );
            // ... and the server keeps serving: a valid context on the same link still succeeds.
            let resp = client_end
                .call(&good_ctx, &AuthorityRequest::Ping { nonce: 2 })
                .expect("still serving");
            assert_eq!(resp, AuthorityResponse::Pong { nonce: 2 });

            drop(client_end);
            server.join().unwrap().expect("clean end");
        }

        #[test]
        fn throttled_principal_is_refused_and_audited() {
            let now = 1_000;
            let signer = LocalSigner::generate(TokenAlg::Es256);
            let trust_root = signer.public_key();
            let ctx = AuthorityContext::from_token(mint_token(&signer, now, Some(300)));
            // Pre-compute the principal id the limiter must deny.
            let denied_id = ContextVerifier::new(signer.public_key())
                .verify_context(&ctx, now + 1)
                .unwrap()
                .principal_id();

            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = std::thread::spawn(move || {
                let mut deny = std::collections::BTreeSet::new();
                deny.insert(denied_id);
                let limiter = DenyPrincipals(deny);
                let audit = CollectingAudit::default();
                let outcome = runtime().block_on(async {
                    serve_authority(
                        "to-signer",
                        &server_end,
                        &ContextVerifier::new(trust_root),
                        &limiter,
                        &audit,
                        &PingHandler,
                        || 1_001,
                    )
                    .await
                });
                (outcome, audit.drain())
            });

            let resp = client_end
                .call(&ctx, &AuthorityRequest::Ping { nonce: 9 })
                .expect("the link carries the call");
            assert!(
                matches!(resp, AuthorityResponse::Refused { .. }),
                "got {resp:?}"
            );

            drop(client_end);
            let (outcome, entries) = server.join().unwrap();
            outcome.expect("clean end");
            // The throttle was audited, keyed on the verified principal.
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].outcome, AuthorityOutcome::RateLimited);
            assert_eq!(entries[0].op, "ping");
        }
    }
}
