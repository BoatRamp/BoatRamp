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
//! touch [`LinkEndpoint`] ([`AuthorityLink`]'s impl + [`AuthorityServe::serve`]) are `cfg(unix)`, exactly as
//! in [`crate::privsep_unseal`]. The full fork+spawn+sandbox composition stays gated Linux-only by the
//! fail-closed sandbox install.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use boatramp_core::authz::GrantedRole;
use boatramp_core::cose::{self, Claims, Signer, TokenError, TokenPublicKey, VerifiedToken};
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::privsep::HostAuthority;

#[cfg(unix)]
use crate::privsep_link::LinkEndpoint;

/// The default anti-replay freshness bound (design §3.4 watch-item mechanism (a)): an authority
/// context token OLDER than this (by its `iat`) is refused even when its `exp` is further out. It
/// shrinks the observable-token-replay window a frontend RCE could exploit — the attacker is bounded
/// to tokens that transited the frontend within this many seconds, not within the full token TTL.
/// Short on purpose; a control/authority call is not latency-sensitive (design §3.1), so a tight
/// bound costs nothing and a legitimate relayed token is always fresh.
pub const DEFAULT_CONTEXT_MAX_AGE_SECS: u64 = 120;

/// Clock skew tolerated for a context token stamped slightly in the future (mirrors
/// [`cose::POP_SKEW_SECS`](boatramp_core::cose::POP_SKEW_SECS)). A token whose `iat` is more than this
/// far ahead of the receiver's clock is refused as not-yet-valid (fail-closed).
pub const CONTEXT_CLOCK_SKEW_SECS: u64 = 30;

/// The default per-link read deadline for an IN-PROGRESS authority frame (slowloris defense). The
/// idle wait between calls is unbounded (an authority link sits idle between infrequent calls); this
/// only bounds the time to finish reading a frame once a peer has started sending one.
pub const DEFAULT_LINK_READ_DEADLINE: Duration = Duration::from_secs(30);

/// The default global in-flight cap for authority-call handler executions across one instance's
/// authority links (design §2 serve concurrency cap): a flood across many links cannot run unbounded
/// concurrent crypto. Generous — authority calls are infrequent.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 64;

/// The default replay-cache capacity: the maximum number of live `(cti, nonce)` witnesses tracked at
/// once. Reached only under a flood (each entry TTL-evicts after the freshness bound); at capacity the
/// cache fail-closes a new call rather than evicting an unexpired witness (which would reopen a replay
/// window).
pub const DEFAULT_REPLAY_CACHE_CAPACITY: usize = 65_536;

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
    /// and the frame round-tripped. Needs no held authority (`required_authority` ⇒ `None`).
    Ping {
        /// An opaque caller witness echoed back in [`AuthorityResponse::Pong`] (round-trip proof).
        /// Distinct from the per-call anti-replay [`AuthorityCall::nonce`]: this one is application
        /// data the handler echoes, not the replay-cache key.
        witness: u64,
    },
    /// **`secrets.sealer` grammar (Phase 2 Wave 1):** seal `plaintext` under the VERIFIED end
    /// principal's scope. The handler tags the sealed blob with the principal's credential-derived
    /// scope so a later [`Unseal`](Self::Unseal) can refuse a ciphertext outside that scope BEFORE any
    /// crypto. Returns [`AuthorityResponse::Sealed`] (a scope-tagged blob — a RESULT, never the KEK).
    /// Served only by an instance holding [`HostAuthority::SecretsSealer`].
    Seal {
        /// The bytes to seal (bounded by the link frame size). Held zeroizing by the handler.
        plaintext: Vec<u8>,
    },
    /// **`secrets.sealer` grammar:** unseal a scope-tagged blob produced by [`Seal`](Self::Seal). The
    /// handler reads the blob's cleartext scope tag and REFUSES — before touching the KEK — if it is
    /// not the verified principal's own scope (so a frontend RCE relaying one principal's credential
    /// can never unseal another principal's ciphertext). Returns [`AuthorityResponse::Unsealed`] (the
    /// unsealed plaintext — the operation's RESULT, scoped to the principal, never the KEK).
    Unseal {
        /// The scope-tagged sealed blob to unseal.
        sealed: Vec<u8>,
    },
    /// **`token.signer` grammar (Phase 2 Wave 1):** mint a control-plane token bearing ONLY claims the
    /// VERIFIED principal is authorized for. The handler derives the authorized role set from the
    /// re-validated principal and refuses (`Refused`) if `requested_roles` is not a SUBSET of it — the
    /// load-bearing scope check (a caller can only mint ≤ its own proven authority, never arbitrary
    /// claims). Returns [`AuthorityResponse::Minted`] (the token — a RESULT; the signing key is
    /// type-foreclosed from ever being returned). Served only by a [`HostAuthority::TokenSigner`].
    MintToken {
        /// The roles the caller asks to have minted. Honored ONLY as a subset of the verified
        /// principal's own roles; any role not held by the principal makes the whole call `Refused`.
        requested_roles: Vec<GrantedRole>,
        /// The requested token lifetime (seconds). Clamped to [`MAX_MINTED_TOKEN_TTL_SECS`].
        ttl_secs: u64,
    },
}

/// The hard ceiling on a minted token's TTL (seconds). The signer clamps a `MintToken` request to
/// this so a compromised caller cannot mint a long-lived token off a short-lived context (the context
/// is itself freshness-bounded — see [`ContextVerifier`]). One hour is ample for a serving token.
pub const MAX_MINTED_TOKEN_TTL_SECS: u64 = 3600;

impl AuthorityRequest {
    /// A short, non-secret op name for the audit record + the log (never echoes arguments).
    #[must_use]
    pub fn op_name(&self) -> &'static str {
        match self {
            Self::Ping { .. } => "ping",
            Self::Seal { .. } => "seal",
            Self::Unseal { .. } => "unseal",
            Self::MintToken { .. } => "mint_token",
        }
    }

    /// The host authority an instance MUST hold to serve this request — the registry dispatch key
    /// (design §3.4 per-capability grammar). `None` for the authority-free liveness [`Ping`](Self::Ping).
    /// A request whose required authority is not registered on the serving instance is `Refused`
    /// (fail-closed, never a wrong-handler dispatch).
    #[must_use]
    pub fn required_authority(&self) -> Option<HostAuthority> {
        match self {
            Self::Ping { .. } => None,
            Self::Seal { .. } | Self::Unseal { .. } => Some(HostAuthority::SecretsSealer),
            Self::MintToken { .. } => Some(HostAuthority::TokenSigner),
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
    /// The round-trip proof: the context re-validated and the [`AuthorityRequest::Ping`] witness is
    /// echoed. Carries no authority and no bytes.
    Pong {
        /// The echoed caller witness.
        witness: u64,
    },
    /// The RESULT of a [`AuthorityRequest::Seal`]: the scope-tagged sealed blob. **This is the
    /// OUTPUT of a bounded op, NOT a key** — it is ciphertext the sealer produced, tagged with the
    /// verified principal's scope; the KEK that sealed it is never representable here.
    Sealed {
        /// The scope-tagged sealed blob (opaque ciphertext).
        sealed: Vec<u8>,
    },
    /// The RESULT of a [`AuthorityRequest::Unseal`]: the unsealed plaintext, scoped to the verified
    /// principal (the sealer refused any ciphertext outside that scope BEFORE decrypting). **This is
    /// the tenant/principal's OWN data — the op's output — NOT the sealing KEK** (which is
    /// type-foreclosed). Held zeroizing on the wire (the transient copy is wiped after the send),
    /// exactly as [`crate::privsep_unseal`] wipes its plaintext.
    Unsealed {
        /// The unsealed plaintext (the principal's own data).
        plaintext: Vec<u8>,
    },
    /// The RESULT of a [`AuthorityRequest::MintToken`]: the minted control-plane token (base64url).
    /// **This is a freshly-minted, scope-attenuated token — the op's output — NOT the signing key**,
    /// which no variant can carry (the type-level exfiltration foreclosure).
    Minted {
        /// The minted token (base64url `COSE_Sign1` CWT).
        token: String,
    },
    /// A fail-closed refusal — the context was absent / unverifiable / expired / stale, the call was
    /// a replay, the operation was not permitted for the verified principal, or a rate-limit tripped.
    /// Carries a **non-secret reason only**, and NEVER any bytes. Mirrors
    /// [`crate::privsep_unseal::UnsealResponse::Refused`].
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
    /// A fresh per-call anti-replay NONCE (design §3.4 watch-item mechanism (b)). The caller mints a
    /// CSPRNG value per call ([`AuthorityLink::call`] does this); the receiver records `(cti, nonce)`
    /// in a bounded, TTL-evicting [`ReplayCache`] and REFUSES a reused pair — so a captured call frame
    /// cannot be replayed verbatim, while a legitimate second call under the same token (a fresh
    /// nonce) still proceeds. The nonce is NOT signed, so it does not bind the request to the token;
    /// it suppresses exact-duplicate replays within the freshness window (the window itself is bounded
    /// by [`ContextVerifier`]'s max-age). See the module doc on why PoP (c) is the stronger, flagged
    /// follow-on.
    pub nonce: u128,
    /// The bounded operation requested.
    pub request: AuthorityRequest,
}

/// A fresh 128-bit CSPRNG anti-replay nonce for one [`AuthorityCall`]. The OS CSPRNG is treated as
/// fail-stop (same posture as [`cose`]'s `cti` generation + [`cose::LocalSigner::generate`]): a
/// predictable nonce would weaken the replay cache, so there is no silent fallback to a weak source.
#[must_use]
pub fn fresh_nonce() -> u128 {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("system CSPRNG for an authority-call anti-replay nonce");
    u128::from_le_bytes(b)
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
            nonce: fresh_nonce(),
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
    /// The token is authentic but past its `exp`. Refused.
    Expired,
    /// The token is authentic and unexpired but FAILS THE TIGHTENED FRESHNESS BOUND (design §3.4
    /// watch-item mechanism (a)): its `iat` is older than the verifier's short max-age, or it has no
    /// `iat` to freshness-bound (fail-closed), or it is stamped implausibly far in the future (beyond
    /// the tolerated clock skew). Refused — this shrinks the observable-token-replay window below the
    /// token's own TTL.
    Stale(String),
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
            Self::Stale(e) => format!("authority context stale (freshness bound): {e}"),
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
/// **Missing verifier ⇒ refuse (fail-closed, by construction).** [`AuthorityServe`] requires a
/// `&ContextVerifier`, so an instance that holds no trust root cannot build one and therefore cannot
/// stand up an authority server at all — there is no code path that serves authority calls without a
/// verifier.
#[derive(Clone)]
pub struct ContextVerifier {
    /// The control-plane trust anchor (`auth_root_public_key`) — public, non-secret.
    trust_root: TokenPublicKey,
    /// The tightened freshness bound (design §3.4 watch-item (a)): reject a token whose `iat` is
    /// older than this, even when `exp` is further out.
    max_age_secs: u64,
    /// Tolerated clock skew for a token stamped slightly in the future.
    skew_secs: u64,
}

impl ContextVerifier {
    /// Build from the public control-plane trust root, with the [`DEFAULT_CONTEXT_MAX_AGE_SECS`]
    /// freshness bound + [`CONTEXT_CLOCK_SKEW_SECS`] skew.
    #[must_use]
    pub fn new(trust_root: TokenPublicKey) -> Self {
        Self {
            trust_root,
            max_age_secs: DEFAULT_CONTEXT_MAX_AGE_SECS,
            skew_secs: CONTEXT_CLOCK_SKEW_SECS,
        }
    }

    /// Override the freshness max-age (seconds) — a hardened composition can tighten it further. A
    /// zero max-age means "only a token stamped this exact second" (effectively single-tick); the
    /// default [`DEFAULT_CONTEXT_MAX_AGE_SECS`] is the intended production value.
    #[must_use]
    pub fn with_max_age_secs(mut self, max_age_secs: u64) -> Self {
        self.max_age_secs = max_age_secs;
        self
    }

    /// RE-VALIDATE the relayed `context` against the public trust root at `now_unix`, returning the
    /// VERIFIED principal or a fail-closed [`ContextRejection`]. This is the F3 crux: the receiver does
    /// NOT trust the caller's relay — it re-runs the same control-plane verifier
    /// ([`cose::verify`](boatramp_core::cose::verify), the function that authenticates a client's own
    /// presented bearer/role token into a verified principal) against the trust root on EVERY call. An
    /// absent, forged, or expired token refuses — no principal, no dispatch, no bytes.
    ///
    /// **Anti-replay (Phase-2 Wave 1, §3.4 watch-item).** A frontend RCE can REPLAY any end-principal
    /// token it OBSERVES transiting the frontend. This verifier TIGHTENS that window with mechanism (a)
    /// — a freshness bound on `iat` ([`max_age_secs`](Self::with_max_age_secs)) that refuses a token
    /// older than the bound even when its `exp` is further out — complemented by the per-call
    /// [`ReplayCache`] (mechanism (b)) in the serve loop. Mechanism (c) (PoP / `cnf`-binding), which
    /// would also defeat an ACTIVE principal's NEW-call forgery within the window (which (a)+(b) do
    /// not), is a documented wiring-gate precondition (see [`AuthorityServe`]).
    ///
    /// **LOW-1 revocation residual (documented, inherent to the secret-blind split).** This verifier
    /// checks signature + `exp` + freshness, NOT KV revocation (`cti` lookup) — it is IO-free and the
    /// isolated crown jewel is deliberately control-plane-KV-blind. So a token REVOKED but still within
    /// its freshness window is accepted. The freshness bound shrinks that residual to `max_age_secs`;
    /// closing it fully would require handing the crown jewel a revocation feed (a bigger coupling).
    /// Named so a reviewer sees it is a conscious bound, not an oversight.
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
        let token = match cose::verify(&context.token, &self.trust_root, now_unix) {
            Ok(token) => token,
            Err(TokenError::Expired) => return Err(ContextRejection::Expired),
            Err(e @ (TokenError::Invalid(_) | TokenError::Key(_))) => {
                // Not authentic (bad signature / framing / wrong algorithm) — the presenter is
                // unauthenticated. A plaintext asserted id lands here too: it is not a signed token.
                return Err(ContextRejection::Unverifiable(e.to_string()));
            }
            Err(e @ TokenError::Claims(_)) => {
                // Authentic but the claims are wrong for an authority call.
                return Err(ContextRejection::Claims(e.to_string()));
            }
            // Build/Signer errors are mint-side; on the verify path they are not expected, but map
            // them fail-closed to Unverifiable rather than leaking a different outcome.
            Err(e) => return Err(ContextRejection::Unverifiable(e.to_string())),
        };

        // KIND PIN (MEDIUM-2): an authority context is an END-PRINCIPAL control-plane ROLE bearer only.
        // `cose::verify` authenticates ANY trust-root-signed token carrying a roles claim — a join /
        // cluster-write / mesh-member / overlay / context-family token would otherwise be honored as an
        // end-principal context. Pin the kind to `KIND_ROLE` and refuse every other family (fail-closed,
        // domain separation — a non-role token is not an end-principal authority).
        if token.kind != cose::KIND_ROLE {
            return Err(ContextRejection::Claims(format!(
                "authority context must be a '{}' token, got '{}'",
                cose::KIND_ROLE,
                token.kind
            )));
        }

        // TIGHTENED FRESHNESS BOUND (mechanism (a)). The signature + `exp` are good; now bound how OLD
        // the token may be, independent of its (possibly generous) `exp`. A frontend RCE can only
        // replay a token it OBSERVED; capping the age shrinks that window to `max_age_secs` rather than
        // the full token TTL. Fail-closed on a token with no `iat` (it cannot be freshness-bounded) and
        // on one stamped implausibly in the future (beyond tolerated skew).
        let iat = token.iat.ok_or_else(|| {
            ContextRejection::Stale("token carries no iat to freshness-bound".to_string())
        })?;
        if iat > now_unix.saturating_add(self.skew_secs) {
            return Err(ContextRejection::Stale(format!(
                "iat {iat} is more than {}s ahead of now {now_unix}",
                self.skew_secs
            )));
        }
        let age = now_unix.saturating_sub(iat);
        if age > self.max_age_secs {
            return Err(ContextRejection::Stale(format!(
                "token age {age}s exceeds the {}s max-age",
                self.max_age_secs
            )));
        }
        Ok(VerifiedPrincipal { token })
    }
}

// =============================================================================
// 2b. The per-call anti-replay cache (mechanism (b))
// =============================================================================

/// The outcome of recording one call's `(cti, nonce)` witness in the [`ReplayCache`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDecision {
    /// A FRESH `(cti, nonce)` — recorded; the call may proceed.
    Fresh,
    /// The exact `(cti, nonce)` was already seen within the freshness window — a verbatim REPLAY.
    /// Refused fail-closed.
    Replay,
    /// The cache is at capacity with unexpired witnesses — refuse fail-closed rather than evict a
    /// live witness (which would reopen a replay window). A flood cannot buy an attacker a replay.
    Saturated,
}

/// The **per-call anti-replay cache** (design §3.4 watch-item mechanism (b)): a bounded, TTL-evicting
/// set of `(cti, nonce)` witnesses the receiver has already served. Keying on the token's `cti`
/// scopes the nonce namespace to the specific token (two different tokens never collide), and lets a
/// witness be evicted once the token is older than the freshness bound (after which the token itself
/// is refused as [`ContextRejection::Stale`], so remembering its nonces buys nothing).
///
/// **Property + honest bound.** This suppresses the VERBATIM replay of a captured call frame (same
/// token, same nonce) and the duplicate side-effect of a frontend re-sending one call. It does NOT,
/// on its own, stop a frontend RCE from crafting a NEW call (fresh nonce) under an observed token
/// within the freshness window — the nonce is not signed, so nothing binds it to the token. That
/// residual is what PoP / `cnf`-binding (mechanism (c)) closes; it is flagged, not implemented here
/// (see the module doc). Mechanisms (a)+(b) together bound the replay window tightly; (c) would close
/// it to the holder-of-`cnf` only.
///
/// Thread-safe (an instance serves authority calls on several link tasks sharing one cache).
pub struct ReplayCache {
    seen: Mutex<HashMap<(String, u128), u64>>,
    ttl_secs: u64,
    capacity: usize,
}

impl ReplayCache {
    /// Build a cache whose witnesses live `ttl_secs` (set this to the verifier's freshness max-age)
    /// and whose size is capped at `capacity` live witnesses.
    #[must_use]
    pub fn new(ttl_secs: u64, capacity: usize) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            ttl_secs,
            capacity,
        }
    }

    /// A cache sized to the defaults ([`DEFAULT_CONTEXT_MAX_AGE_SECS`] TTL,
    /// [`DEFAULT_REPLAY_CACHE_CAPACITY`] entries).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_CONTEXT_MAX_AGE_SECS, DEFAULT_REPLAY_CACHE_CAPACITY)
    }

    /// Check-and-record `(cti, nonce)` at `now_unix`. Evicts expired witnesses first; then returns
    /// [`ReplayDecision::Replay`] if the pair is already live, [`ReplayDecision::Saturated`] if the
    /// cache is full of live witnesses (fail-closed — no eviction of a live witness to make room),
    /// else records the pair and returns [`ReplayDecision::Fresh`].
    pub fn check_and_record(&self, cti: &str, nonce: u128, now_unix: u64) -> ReplayDecision {
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // TTL-evict: drop every witness older than the freshness window.
        let ttl = self.ttl_secs;
        seen.retain(|_, &mut first_seen| now_unix.saturating_sub(first_seen) <= ttl);
        let key = (cti.to_string(), nonce);
        if seen.contains_key(&key) {
            return ReplayDecision::Replay;
        }
        if seen.len() >= self.capacity {
            // Full of UNEXPIRED witnesses: refuse rather than evict a live one (evicting would let an
            // attacker flood the cache to drop a victim's witness, then replay it).
            return ReplayDecision::Saturated;
        }
        seen.insert(key, now_unix);
        ReplayDecision::Fresh
    }

    /// The number of live witnesses (test/observability).
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether the cache currently holds no witnesses.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    /// The call was a verbatim `(cti, nonce)` REPLAY (or the replay cache was saturated) and was
    /// refused before dispatch — audited keyed on the verified principal (the signature verified; the
    /// call did not proceed).
    Replayed,
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
/// bounded, already-context-verified request and returns a bounded [`AuthorityResponse`]. Each
/// capability (`secrets.sealer` ⇒ [`SealerHandler`], `token.signer` ⇒ [`SignerHandler`], …) implements
/// this with its concrete grammar, re-checking the verified `principal`'s scope BEFORE any crypto and
/// returning only RESULTS (the response type forecloses returning a key).
///
/// **Per-handler KIND-GATING (mandatory).** A handler accepts ONLY its own request kinds; any other
/// kind returns [`AuthorityResponse::Refused`] — never a panic, never a wrong-handler action. This is
/// defense-in-depth beneath the [`AuthorityRegistry`] (which already routes by
/// [`AuthorityRequest::required_authority`]): even a misrouted request cannot make a handler act
/// outside its grammar.
///
/// Async because the ops (seal/unseal/mint) are async crypto, exactly like
/// [`crate::privsep_unseal::SealedKeyResolver`]. `now_unix` is the receiver's clock at the call — the
/// SAME value the serve loop used to re-validate the context, so a handler (e.g. the signer) stamps a
/// consistent time.
#[async_trait::async_trait]
pub trait AuthorityHandler: Send + Sync {
    /// Handle one request for a RE-VALIDATED `principal`. Never returns key material. An op the handler
    /// does not permit for this principal — or a kind it does not serve — returns
    /// [`AuthorityResponse::Refused`] (no bytes).
    async fn handle(
        &self,
        principal: &VerifiedPrincipal,
        request: AuthorityRequest,
        now_unix: u64,
    ) -> AuthorityResponse;
}

/// The authority-free liveness handler: answers [`AuthorityRequest::Ping`] with a matching
/// [`AuthorityResponse::Pong`]. It reads nothing from the principal — a correct `Pong` proves only that
/// the relayed context re-validated (that check ran before dispatch) and the frame round-tripped.
/// Kind-gates: anything but `Ping` is `Refused`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PingHandler;

#[async_trait::async_trait]
impl AuthorityHandler for PingHandler {
    async fn handle(
        &self,
        _principal: &VerifiedPrincipal,
        request: AuthorityRequest,
        _now_unix: u64,
    ) -> AuthorityResponse {
        match request {
            AuthorityRequest::Ping { witness } => AuthorityResponse::Pong { witness },
            other => refused_wrong_kind("ping", &other),
        }
    }
}

/// A uniform kind-gating refusal (no panic, no wrong-handler action; non-secret).
fn refused_wrong_kind(handler: &str, got: &AuthorityRequest) -> AuthorityResponse {
    AuthorityResponse::Refused {
        reason: format!(
            "the {handler} grammar does not serve the {:?} op",
            got.op_name()
        ),
    }
}

// =============================================================================
// The `secrets.sealer` grammar (Phase 2 Wave 1): seal / unseal, context-bound
// =============================================================================

/// The cleartext + inner shape of a scope-tagged sealed blob. The `scope` is carried BOTH as cleartext
/// (so an [`AuthorityRequest::Unseal`] can refuse an out-of-scope blob BEFORE touching the KEK) AND
/// inside the AEAD-sealed `ciphertext` (so a tampered cleartext scope is caught AFTER decrypt, before
/// any plaintext is returned).
#[derive(Serialize, Deserialize)]
struct SealedBlob {
    /// The verified principal's credential-derived scope this blob is bound to (cleartext tag).
    scope: String,
    /// `envelope.wrap(`[`SealedInner`]`)` — the KEK-sealed, scope-bound plaintext.
    ciphertext: Vec<u8>,
}

/// The inner, AEAD-sealed payload: the scope (re-bound under the seal) + the plaintext.
#[derive(Serialize, Deserialize)]
struct SealedInner {
    scope: String,
    plaintext: Vec<u8>,
}

/// The **`secrets.sealer` serving grammar** (design §3.4 exemplar): a context-bound `seal`/`unseal`
/// for tenant-scoped SERVING requests relayed by a frontend. It re-checks the VERIFIED end principal's
/// scope and refuses an `unseal` of a ciphertext outside that scope BEFORE any crypto.
///
/// **Separation from the Phase-1 bootstrap unseal ([`crate::privsep_unseal`]).** This is a DIFFERENT,
/// deliberately-separate grammar. The bootstrap path is the root-wired, name-allowlisted
/// sealer→signer key unseal that runs once at instance boot with NO end-principal context (it IS
/// instance bootstrap; its containment is the root-wired allowlist). THIS grammar is end-principal
/// authorized (the re-validated [`AuthorityContext`]) and serves tenant-scoped seal/unseal during
/// serving. Both live on the sealer, both fail-closed, and they never share a link or a code path.
pub struct SealerHandler {
    /// The `[secrets]` KEK envelope the `secrets.sealer` holds (never reachable over any link).
    envelope: Arc<dyn KeyEnvelope>,
}

impl SealerHandler {
    /// Build from the sealer's `[secrets]` KEK envelope.
    #[must_use]
    pub fn new(envelope: Arc<dyn KeyEnvelope>) -> Self {
        Self { envelope }
    }

    async fn seal(&self, principal: &VerifiedPrincipal, plaintext: Vec<u8>) -> AuthorityResponse {
        // HIGH-1: the seal scope is the principal's STABLE IDENTITY, never role-shape. No
        // uniquely-identifying claim ⇒ no scope ⇒ seal NOTHING (fail-closed), so a sealed blob can
        // never be bound to a non-identity and later unsealed by a different principal.
        let Some(scope) = scope_of(principal) else {
            return refused_no_identity("seal");
        };
        let plaintext = Zeroizing::new(plaintext);
        let inner = SealedInner {
            scope: scope.clone(),
            plaintext: plaintext.to_vec(),
        };
        // The serialized inner carries the plaintext — hold it zeroizing until it is sealed.
        let inner_bytes = match serde_json::to_vec(&inner) {
            Ok(b) => Zeroizing::new(b),
            Err(e) => return refused_internal("seal encode", &e.to_string()),
        };
        match self.envelope.wrap(&inner_bytes).await {
            Ok(ciphertext) => {
                let blob = SealedBlob { scope, ciphertext };
                match serde_json::to_vec(&blob) {
                    Ok(sealed) => AuthorityResponse::Sealed { sealed },
                    Err(e) => refused_internal("seal blob encode", &e.to_string()),
                }
            }
            Err(e) => refused_internal("seal", &e.to_string()),
        }
    }

    async fn unseal(&self, principal: &VerifiedPrincipal, sealed: Vec<u8>) -> AuthorityResponse {
        // HIGH-1: no uniquely-identifying claim ⇒ no scope ⇒ unseal NOTHING (fail-closed). A
        // targetless/global/role-only token can never unseal — it names no principal.
        let Some(scope) = scope_of(principal) else {
            return refused_no_identity("unseal");
        };
        let blob: SealedBlob = match serde_json::from_slice(&sealed) {
            Ok(b) => b,
            Err(_) => {
                return AuthorityResponse::Refused {
                    reason: "unseal: malformed sealed blob".to_string(),
                };
            }
        };
        // THE CONTAINMENT (design §3.4): refuse a ciphertext whose cleartext scope is not this
        // principal's own — BEFORE touching the KEK. A frontend RCE relaying principal P's credential
        // can never reach a blob tagged for a different principal.
        if blob.scope != scope {
            tracing::warn!(
                principal = %scope,
                "[privsep] sealer REFUSED unseal: blob scope is not the verified principal's (pre-crypto, fail-closed)"
            );
            return AuthorityResponse::Refused {
                reason: "unseal refused: ciphertext is outside the verified principal's scope"
                    .to_string(),
            };
        }
        // Allowlisted by scope — now decrypt.
        let inner_bytes = match self.envelope.unwrap(&blob.ciphertext).await {
            Ok(b) => Zeroizing::new(b),
            Err(e) => return refused_internal("unseal", &e.to_string()),
        };
        let inner: SealedInner = match serde_json::from_slice(&inner_bytes) {
            Ok(i) => i,
            Err(e) => return refused_internal("unseal decode", &e.to_string()),
        };
        // Defense-in-depth: the AEAD-bound inner scope is authoritative — catch a tampered CLEARTEXT
        // scope (an attacker that swapped `blob.scope` to pass the pre-crypto check). No bytes returned.
        let mut plaintext = Zeroizing::new(inner.plaintext);
        if inner.scope != scope {
            zeroize::Zeroize::zeroize(&mut *plaintext);
            tracing::warn!(
                "[privsep] sealer REFUSED unseal: sealed inner scope mismatch (tamper) — no bytes"
            );
            return AuthorityResponse::Refused {
                reason: "unseal refused: sealed scope does not match the verified principal"
                    .to_string(),
            };
        }
        AuthorityResponse::Unsealed {
            plaintext: plaintext.to_vec(),
        }
    }
}

#[async_trait::async_trait]
impl AuthorityHandler for SealerHandler {
    async fn handle(
        &self,
        principal: &VerifiedPrincipal,
        request: AuthorityRequest,
        _now_unix: u64,
    ) -> AuthorityResponse {
        match request {
            AuthorityRequest::Seal { plaintext } => self.seal(principal, plaintext).await,
            AuthorityRequest::Unseal { sealed } => self.unseal(principal, sealed).await,
            other => refused_wrong_kind("secrets.sealer", &other),
        }
    }
}

// =============================================================================
// The `token.signer` grammar (Phase 2 Wave 1): mint_token, authority-attenuated
// =============================================================================

/// The **`token.signer` serving grammar** (design §3.4 exemplar): mint a control-plane token bearing
/// ONLY claims the VERIFIED principal is authorized for. The signing key is held here and NEVER
/// representable in a response (type-foreclosed). The load-bearing scope check is the authorized-claims
/// derivation: the handler mints only roles that are a SUBSET of the re-validated principal's own
/// roles — a caller can mint ≤ its proven authority, never arbitrary caller-supplied claims.
pub struct SignerHandler {
    /// The control-plane auth-root signer the `token.signer` holds (never reachable over any link).
    signer: Arc<dyn Signer>,
    /// The context freshness max-age the serving verifier enforces — the minted token's TTL is bound
    /// to the context's REMAINING freshness so a short-lived observed context cannot be converted into
    /// a durable credential (MEDIUM-1). Should match the paired [`ContextVerifier`]'s `max_age_secs`.
    context_max_age_secs: u64,
}

impl SignerHandler {
    /// Build from the signer's unlocked control-plane signer + the context freshness max-age (pass the
    /// paired [`ContextVerifier`]'s `max_age_secs`; the default is [`DEFAULT_CONTEXT_MAX_AGE_SECS`]).
    #[must_use]
    pub fn new(signer: Arc<dyn Signer>, context_max_age_secs: u64) -> Self {
        Self {
            signer,
            context_max_age_secs,
        }
    }

    async fn mint_token(
        &self,
        principal: &VerifiedPrincipal,
        requested_roles: Vec<GrantedRole>,
        ttl_secs: u64,
        now_unix: u64,
    ) -> AuthorityResponse {
        // THE SCOPE CHECK (design §5): every requested role MUST be one the verified principal holds.
        // The authorized set is read SOLELY from the re-validated credential, never from a caller
        // field. Any role the principal does not hold refuses the WHOLE call (no partial mint).
        let authorized = &principal.token().roles;
        if let Some(bad) = requested_roles.iter().find(|r| !authorized.contains(r)) {
            tracing::warn!(
                principal = %principal.principal_id(),
                role = %bad.name,
                "[privsep] signer REFUSED mint_token: a requested role is not held by the verified principal (fail-closed)"
            );
            return AuthorityResponse::Refused {
                reason: "mint_token refused: a requested role exceeds the verified principal's authority"
                    .to_string(),
            };
        }
        // MEDIUM-1: bind the minted TTL to the context's REMAINING freshness so an observed short-lived
        // context cannot be amplified into a durable control-plane token. Remaining freshness =
        // max_age - age (by iat; verify_context guarantees iat is present on a verified context), also
        // bounded by the context's own `exp`. A context with no freshness left mints nothing.
        let remaining = match principal.token().iat {
            Some(iat) => self
                .context_max_age_secs
                .saturating_sub(now_unix.saturating_sub(iat)),
            // Defensive: a verified context always has iat (verify_context refuses otherwise); treat a
            // missing one as no freshness (fail-closed).
            None => 0,
        };
        let remaining = match principal.token().exp {
            Some(exp) => remaining.min(exp.saturating_sub(now_unix)),
            None => remaining,
        };
        let ttl = ttl_secs.min(MAX_MINTED_TOKEN_TTL_SECS).min(remaining);
        if ttl == 0 {
            tracing::warn!(
                principal = %principal.principal_id(),
                "[privsep] signer REFUSED mint_token: the context has no remaining freshness to bind a usable token (fail-closed)"
            );
            return AuthorityResponse::Refused {
                reason: "mint_token refused: the authority context has no remaining freshness"
                    .to_string(),
            };
        }
        let claims = Claims {
            roles: requested_roles,
            kind: cose::KIND_ROLE.to_string(),
            ttl_secs: Some(ttl),
            now_unix,
        };
        match cose::mint(&claims, self.signer.as_ref()).await {
            Ok(token) => AuthorityResponse::Minted { token },
            // A mint failure is non-secret; never echo the signer error verbatim (it is key-side).
            Err(_) => AuthorityResponse::Refused {
                reason: "mint_token failed at the signer".to_string(),
            },
        }
    }
}

#[async_trait::async_trait]
impl AuthorityHandler for SignerHandler {
    async fn handle(
        &self,
        principal: &VerifiedPrincipal,
        request: AuthorityRequest,
        now_unix: u64,
    ) -> AuthorityResponse {
        match request {
            AuthorityRequest::MintToken {
                requested_roles,
                ttl_secs,
            } => {
                self.mint_token(principal, requested_roles, ttl_secs, now_unix)
                    .await
            }
            other => refused_wrong_kind("token.signer", &other),
        }
    }
}

/// The per-principal seal/unseal SCOPE — the verified principal's **stable IDENTITY**, read SOLELY
/// from the re-verified token, or `None` when the token carries no uniquely-identifying claim (**then
/// the sealer fails closed — seals/unseals NOTHING**). This is the HIGH-1 fix: the scope is keyed on
/// the credential's stable SUBJECT identity, **NEVER on its role-SHAPE** ([`VerifiedPrincipal::principal_id`],
/// which two distinct principals sharing a (kind, roles) set collapse into — the original flaw), and
/// NEVER on the per-TOKEN `cti` (which a re-mint changes, so it is not a per-principal id either).
///
/// A uniquely-identifying claim means the standard CWT **subject** (`sub`). The verified principal's
/// granted `target`s (the tenant/site a scoped role binds to) are folded in so a given subject's scope
/// is additionally tenant-shaped, but the load-bearing uniqueness is the subject — a token with no
/// subject (every token the CURRENT issuance path mints — see [`VerifiedToken::subject`]) returns
/// `None` and seals/unseals nothing.
///
/// **SCOPED + STOPPED (reported to the lead).** Making the sealer grammar FUNCTIONAL (not just safe)
/// requires the issuance path to mint a mandatory per-principal `sub` into end-principal role tokens —
/// a cross-cutting change AND a seal-GRANULARITY model choice (per-identity `sub` vs per-tenant). Until
/// the owner settles it + the claim lands, this fails closed (correct + inert; no serve-link is wired).
fn scope_of(principal: &VerifiedPrincipal) -> Option<String> {
    let tok = principal.token();
    // The uniquely-identifying part: the stable CWT subject. Absent (or empty) ⇒ no identity ⇒ None.
    let subject = tok.subject.as_deref().filter(|s| !s.is_empty())?;
    // Fold in the granted tenant/target set (defense-in-depth tenant shaping); a targetless (global)
    // role contributes none, so the scope is the subject alone (still a valid per-principal identity).
    let mut targets: Vec<&str> = tok
        .roles
        .iter()
        .filter_map(|r| r.target.as_deref())
        .collect();
    targets.sort_unstable();
    targets.dedup();
    Some(format!("sub={subject}|targets={}", targets.join(",")))
}

/// A fail-closed refusal when an authority op needs a per-principal identity the context does not carry
/// (HIGH-1). Non-secret; no bytes.
fn refused_no_identity(op: &str) -> AuthorityResponse {
    tracing::warn!(
        op,
        "[privsep] sealer REFUSED: the verified context carries no uniquely-identifying principal \
         subject — no identity, no scope (fail-closed)"
    );
    AuthorityResponse::Refused {
        reason: format!(
            "{op} refused: the authority context carries no uniquely-identifying principal subject"
        ),
    }
}

/// A non-secret internal-failure refusal (never echoes crypto/key error text to the caller).
fn refused_internal(op: &str, detail: &str) -> AuthorityResponse {
    // The detail goes to the receiver-side log only, never into the caller-facing reason.
    tracing::warn!(
        op,
        detail,
        "[privsep] authority op failed internally (fail-closed, no bytes)"
    );
    AuthorityResponse::Refused {
        reason: format!("{op} failed"),
    }
}

// =============================================================================
// The per-capability registry + the hardened receiver-side serve loop
// =============================================================================

/// The per-capability handler REGISTRY (design §3.4 / task #3): routes a context-verified request to
/// the handler for its [`AuthorityRequest::required_authority`], keyed on the [`HostAuthority`] the
/// serving instance holds. A Wave-2 grammar (`image.signer` / `overlay.dial-signer` / `s3ingress.root`
/// / `cluster.join-signer`) plugs in by [`register`](Self::register)ing a handler under its authority —
/// WITHOUT touching the serve loop. A request whose required authority is not registered here is
/// `Refused` (fail-closed, no wrong-handler dispatch); the authority-free [`AuthorityRequest::Ping`] is
/// always answered (liveness).
#[derive(Default)]
pub struct AuthorityRegistry {
    handlers: HashMap<HostAuthority, Arc<dyn AuthorityHandler>>,
}

impl AuthorityRegistry {
    /// An empty registry (serves only `Ping`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `handler` as the grammar for `authority`. A second registration for the same authority
    /// replaces the first (the composition holds one handler per authority per instance).
    pub fn register(&mut self, authority: HostAuthority, handler: Arc<dyn AuthorityHandler>) {
        self.handlers.insert(authority, handler);
    }

    /// Whether any capability handler is registered (an instance with none stands up no authority
    /// server beyond liveness).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// The authorities this registry serves (sorted; for the log).
    #[must_use]
    pub fn served(&self) -> Vec<HostAuthority> {
        let mut v: Vec<HostAuthority> = self.handlers.keys().copied().collect();
        v.sort();
        v
    }
}

#[async_trait::async_trait]
impl AuthorityHandler for AuthorityRegistry {
    async fn handle(
        &self,
        principal: &VerifiedPrincipal,
        request: AuthorityRequest,
        now_unix: u64,
    ) -> AuthorityResponse {
        match request.required_authority() {
            // Liveness needs no held authority.
            None => PingHandler.handle(principal, request, now_unix).await,
            Some(authority) => match self.handlers.get(&authority) {
                Some(h) => h.handle(principal, request, now_unix).await,
                // The serving instance does not hold this authority — fail-closed, no dispatch.
                None => AuthorityResponse::Refused {
                    reason: format!(
                        "this instance does not serve the {} authority",
                        authority.tag()
                    ),
                },
            },
        }
    }
}

/// The hardened receiver-side authority serve (design §2 / §3.4 / task #2). Bundles the fail-closed
/// deps so the serve loop takes a single, reviewable shape:
/// - `verifier` — re-validates every call's context against the public trust root (F3), now also with
///   the tightened freshness bound;
/// - `replay` — the per-call `(cti, nonce)` anti-replay cache (mechanism (b));
/// - `limiter` — the per-verified-principal rate-limit (throttle / abuse-detection, F9);
/// - `audit` — the append-only, receiver-side, principal-keyed sink;
/// - `handler` — the per-capability dispatch (usually an [`AuthorityRegistry`]);
/// - `max_in_flight` — a GLOBAL concurrency cap across all of the instance's authority-serve links
///   (a flood cannot run unbounded concurrent crypto);
/// - `read_deadline` — bounds an IN-PROGRESS frame read (slowloris defense); the idle wait between
///   calls stays unbounded.
///
/// ## WIRING-GATE PRECONDITIONS (TRACKED — do NOT ship a real frontend→signer serve-link without these)
///
/// This serve is inert in every current composition (no serve-link is designated — see
/// `boatramp::privsep::compute_authority_serve_links`). BEFORE any composition designates a REAL
/// relay→crown-jewel authority-serve link, ALL of these are HARD preconditions:
/// 1. **HIGH-1 per-principal identity.** A mandatory per-principal `sub` claim must be minted into
///    end-principal role tokens (today [`scope_of`] fails closed because none exists), and the owner
///    must settle the seal-GRANULARITY model (per-identity `sub` vs per-tenant). Until then the sealer
///    grammar seals/unseals NOTHING.
/// 2. **(c) PoP / `cnf`-binding.** (a)+(b) tighten the replay window but do NOT stop an ACTIVE
///    principal's NEW-call forgery within it (the nonce is unsigned); `cnf`-binding closes that
///    residual. Needs the originating client to sign an authority-call challenge the frontend relays —
///    a token-format + guest-SDK change. **Additionally, a machine-minted token output (`mint_token`)
///    must itself be PoP-bound AND NOT re-redeemable as a mint context** — this closes the mint→mint
///    refresh chain (a minted token relayed back as a fresh context to mint again) that the per-call
///    TTL clamp (MEDIUM-1) alone does not.
/// 3. **Real limiter + durable audit (LOW-3 / INFO).** Swap the default [`Unlimited`] limiter for a
///    token-bucket and [`TracingAudit`] for a durable append-only sink.
/// 4. **Per-link PURPOSE marker.** The composition model needs an explicit per-link purpose so a
///    listener-FRONTEND→signer authority link can be designated WITHOUT colliding with the
///    link-shape-identical client-fd splice (why `compute_authority_serve_links` conservatively
///    excludes the listener-peer shape today).
///
/// The **LOW-1 revocation residual** (a revoked-but-fresh token is accepted within the freshness
/// window — inherent to the control-plane-KV-blind crown-jewel split) is documented on
/// [`ContextVerifier::verify_context`].
pub struct AuthorityServe<'a> {
    /// The context verifier (public trust root + freshness bound).
    pub verifier: &'a ContextVerifier,
    /// The per-call anti-replay cache.
    pub replay: &'a ReplayCache,
    /// The per-principal rate-limit.
    pub limiter: &'a dyn AuthorityRateLimiter,
    /// The append-only principal-keyed audit sink.
    pub audit: &'a dyn AuthorityAudit,
    /// The per-capability dispatch.
    pub handler: &'a dyn AuthorityHandler,
    /// The global in-flight handler-execution cap.
    pub max_in_flight: &'a tokio::sync::Semaphore,
    /// The per-in-progress-frame read deadline.
    pub read_deadline: Duration,
}

#[cfg(unix)]
impl AuthorityServe<'_> {
    /// Serve authority calls from ONE peer over `link`, re-validating every call's context against the
    /// trust root (fail-closed) before dispatch. Per call:
    ///
    /// 1. receive one bounded, typed [`AuthorityCall`] (fail-closed on oversize / framing / a
    ///    mid-frame stall via the read deadline);
    /// 2. RE-VALIDATE its [`AuthorityContext`] (signature + `exp` + the tightened freshness bound);
    ///    a rejection ⇒ `Refused` (no bytes), LOG, keep serving;
    /// 3. check the per-call anti-replay cache — a verbatim replay / saturation ⇒ audit `Replayed` +
    ///    `Refused`, keep serving;
    /// 4. check the per-verified-principal rate-limit — a trip ⇒ audit `RateLimited` + `Refused`;
    /// 5. else acquire a global in-flight permit, dispatch to the per-capability handler, AUDIT the
    ///    outcome keyed on the verified principal, and reply with the handler's bounded result.
    ///
    /// Loops until the peer closes the link (EOF). `link_name` is for the log only. A context
    /// rejection is LOGGED but NOT written to the principal-keyed sink (there is no verified principal
    /// to key it on); a replay/throttle IS audited (the signature verified — there is a principal).
    pub async fn serve(
        &self,
        link_name: &str,
        link: &LinkEndpoint,
        now_unix: impl Fn() -> u64,
    ) -> Result<(), String> {
        loop {
            // (1) Receive one bounded, typed call. A mid-frame stall trips the read deadline
            // (slowloris) ⇒ end this peer's serve fail-closed; a clean EOF is the normal end.
            let frame = match link.recv_frame_within(self.read_deadline) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    tracing::debug!(link = %link_name, "[privsep] authority: peer closed the link (EOF)");
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    tracing::warn!(link = %link_name, "[privsep] authority: read deadline exceeded mid-frame — dropping the peer (fail-closed)");
                    return Ok(());
                }
                Err(e) => return Err(format!("recv on link {link_name:?}: {e}")),
            };
            let call: AuthorityCall = match serde_json::from_slice(&frame) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(link = %link_name, error = %e, "[privsep] authority: malformed call — refusing");
                    self.send(
                        link,
                        &AuthorityResponse::Refused {
                            reason: "malformed authority call".to_string(),
                        },
                    )?;
                    continue;
                }
            };
            let op = call.request.op_name();
            let now = now_unix();

            // (2) RE-VALIDATE the context (signature + exp + freshness). A rejection reaches no
            // authority: refused, logged, no principal-keyed audit (there is no verified principal).
            let principal = match self.verifier.verify_context(&call.context, now) {
                Ok(p) => p,
                Err(rejection) => {
                    tracing::warn!(
                        link = %link_name, op, reason = %rejection.reason(),
                        "[privsep] authority REFUSED: context did not re-validate (fail-closed)"
                    );
                    self.send(
                        link,
                        &AuthorityResponse::Refused {
                            reason: rejection.reason(),
                        },
                    )?;
                    continue;
                }
            };
            let principal_id = principal.principal_id();
            let cti = principal.token().cti.clone();

            // (3) Anti-replay: a verbatim (cti, nonce) replay — or cache saturation — is refused
            // before any work (audited, keyed on the verified principal).
            match self.replay.check_and_record(&cti, call.nonce, now) {
                ReplayDecision::Fresh => {}
                ReplayDecision::Replay | ReplayDecision::Saturated => {
                    self.audit.record(&AuthorityAuditEntry {
                        principal_id: principal_id.clone(),
                        op,
                        outcome: AuthorityOutcome::Replayed,
                    });
                    tracing::warn!(link = %link_name, principal = %principal_id, op, "[privsep] authority REFUSED: anti-replay (duplicate nonce or cache saturated)");
                    self.send(
                        link,
                        &AuthorityResponse::Refused {
                            reason: "anti-replay: duplicate or cache-saturated call".to_string(),
                        },
                    )?;
                    continue;
                }
            }

            // (4) Per-verified-principal rate-limit (throttle / abuse-detection, NOT containment — F9).
            if self.limiter.check(&principal_id) == RateLimitDecision::Throttled {
                self.audit.record(&AuthorityAuditEntry {
                    principal_id: principal_id.clone(),
                    op,
                    outcome: AuthorityOutcome::RateLimited,
                });
                tracing::warn!(link = %link_name, principal = %principal_id, op, "[privsep] authority throttled");
                self.send(
                    link,
                    &AuthorityResponse::Refused {
                        reason: "rate-limited".to_string(),
                    },
                )?;
                continue;
            }

            // (5) Acquire a global in-flight permit (concurrency cap), dispatch, audit, reply.
            let permit = match self.max_in_flight.acquire().await {
                Ok(p) => p,
                Err(_) => {
                    // The semaphore was closed (shutdown) — stop serving fail-closed.
                    return Ok(());
                }
            };
            let mut response = self.handler.handle(&principal, call.request, now).await;
            drop(permit);
            self.audit.record(&AuthorityAuditEntry {
                principal_id,
                op,
                outcome: AuthorityOutcome::Served,
            });
            let send = self.send(link, &response);
            // Wipe the transient plaintext copy an `Unsealed` result carries (hygiene, like
            // `privsep_unseal`) regardless of the send outcome.
            if let AuthorityResponse::Unsealed { plaintext } = &mut response {
                zeroize::Zeroize::zeroize(plaintext);
            }
            send?;
        }
    }

    /// Serialize + send one [`AuthorityResponse`] frame. The serialized buffer is held zeroizing
    /// because a result variant (an `Unsealed` plaintext) can carry principal data; the transient wire
    /// copy is wiped after the send. (No variant can carry the signer's key/KEK/seed — the type
    /// forecloses it — so this guards principal data, not key material.)
    fn send(&self, link: &LinkEndpoint, resp: &AuthorityResponse) -> Result<(), String> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(resp).map_err(|e| format!("encoding authority response: {e}"))?,
        );
        link.send_frame(&bytes)
            .map_err(|e| format!("sending authority response: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::cose::{Claims, LocalSigner, Signer, TokenAlg};

    use crate::envelope::LocalKek;

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

    /// Mint a valid role bearer token carrying `roles`, `ttl` seconds from `now`.
    fn mint_token_roles(
        signer: &LocalSigner,
        now: u64,
        ttl: Option<u64>,
        roles: Vec<GrantedRole>,
    ) -> String {
        let claims = Claims {
            roles,
            kind: boatramp_core::cose::KIND_ROLE.to_string(),
            ttl_secs: ttl,
            now_unix: now,
        };
        runtime()
            .block_on(cose::mint(&claims, signer))
            .expect("mint")
    }

    fn role(name: &str) -> GrantedRole {
        GrantedRole {
            name: name.to_string(),
            target: None,
        }
    }

    // ---- the typed envelope forecloses KEY exfiltration (the compile tripwire) ----

    /// **The no-key-variant invariant (task #3).** An exhaustive match over every response variant is
    /// the compile tripwire: a Phase-2+ variant cannot be added without a reviewer consciously handling
    /// it HERE, where the review question is "does this variant hand back the instance's OWN key / KEK /
    /// seed?" The answer must stay NO. The result variants below return the OUTPUT of a bounded op (a
    /// sealed blob, an unsealed principal plaintext, a minted token) — never the sealing/signing key,
    /// unlike `privsep_unseal::UnsealResponse::Unsealed` (which deliberately returns the signer's own
    /// key, gated by the root-wired allowlist, a different grammar).
    #[test]
    fn response_admits_no_key_material() {
        for resp in [
            AuthorityResponse::Pong { witness: 7 },
            AuthorityResponse::Sealed { sealed: vec![1] },
            AuthorityResponse::Unsealed { plaintext: vec![2] },
            AuthorityResponse::Minted { token: "t".into() },
            AuthorityResponse::Refused { reason: "x".into() },
        ] {
            match resp {
                // Each arm affirms: a bounded-op RESULT, never the instance's key/KEK/seed.
                AuthorityResponse::Pong { witness: _ } => {} // round-trip witness only
                AuthorityResponse::Sealed { sealed: _ } => {} // ciphertext (not the KEK)
                AuthorityResponse::Unsealed { plaintext: _ } => {} // principal data (not the KEK)
                AuthorityResponse::Minted { token: _ } => {} // a token (not the signing key)
                AuthorityResponse::Refused { reason: _ } => {} // a non-secret reason, no bytes
            }
        }
    }

    // ---- anti-replay (a): the tightened freshness bound ----

    #[test]
    fn stale_but_unexpired_token_is_rejected() {
        // A token with a GENEROUS exp but an OLD iat is refused by the freshness bound — the point of
        // mechanism (a): it shrinks the replay window below the token's own (long) TTL.
        let now = 1_000_000;
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let verifier = ContextVerifier::new(signer.public_key());
        // exp is an hour out, but we verify LONG after iat (well past the max-age, before exp).
        let ctx = AuthorityContext::from_token(mint_token(&signer, now, Some(3_600)));
        let err = verifier
            .verify_context(&ctx, now + DEFAULT_CONTEXT_MAX_AGE_SECS + 1)
            .unwrap_err();
        assert!(matches!(err, ContextRejection::Stale(_)), "got {err:?}");
        // The SAME token within the max-age still verifies (the bound is age, not exp).
        assert!(verifier.verify_context(&ctx, now + 1).is_ok());
    }

    #[test]
    fn future_dated_token_beyond_skew_is_rejected() {
        let now = 1_000_000;
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let verifier = ContextVerifier::new(signer.public_key());
        // iat stamped in the future; verify at an EARLIER now, more than the skew behind iat.
        let ctx = AuthorityContext::from_token(mint_token(&signer, now, Some(3_600)));
        let err = verifier
            .verify_context(&ctx, now - CONTEXT_CLOCK_SKEW_SECS - 1)
            .unwrap_err();
        assert!(matches!(err, ContextRejection::Stale(_)), "got {err:?}");
    }

    // ---- anti-replay (b): the per-call nonce cache ----

    #[test]
    fn replay_cache_detects_a_duplicate_and_ttl_evicts() {
        let cache = ReplayCache::new(100, 1024);
        assert_eq!(
            cache.check_and_record("cti-a", 1, 1_000),
            ReplayDecision::Fresh
        );
        // Same (cti, nonce) again within the TTL → a verbatim replay.
        assert_eq!(
            cache.check_and_record("cti-a", 1, 1_050),
            ReplayDecision::Replay
        );
        // A fresh nonce under the same token is fine (a legitimate second call).
        assert_eq!(
            cache.check_and_record("cti-a", 2, 1_050),
            ReplayDecision::Fresh
        );
        // After the TTL, the original witness is evicted so the nonce is accepted again (the token
        // itself would be stale by then, refused upstream).
        assert_eq!(
            cache.check_and_record("cti-a", 1, 1_000 + 101),
            ReplayDecision::Fresh
        );
    }

    #[test]
    fn replay_cache_saturates_fail_closed() {
        // A tiny cache full of UNEXPIRED witnesses refuses a new call rather than evicting a live one.
        let cache = ReplayCache::new(1_000, 2);
        assert_eq!(cache.check_and_record("c", 1, 10), ReplayDecision::Fresh);
        assert_eq!(cache.check_and_record("c", 2, 10), ReplayDecision::Fresh);
        assert_eq!(
            cache.check_and_record("c", 3, 10),
            ReplayDecision::Saturated
        );
        // A repeat of an already-seen pair is still a Replay (checked before the capacity gate).
        assert_eq!(cache.check_and_record("c", 1, 10), ReplayDecision::Replay);
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
            op: AuthorityRequest::Ping { witness: 1 }.op_name(),
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

    // ---- the secrets.sealer grammar: context-bound seal/unseal, per-IDENTITY scope (HIGH-1) ----

    /// A verified principal built straight from a real minted role token — carries NO subject (the
    /// current issuance path mints none), so the sealer fails closed for it. Used for the fail-closed
    /// and kind-gating tests.
    fn principal_for(signer: &LocalSigner, now: u64, roles: Vec<GrantedRole>) -> VerifiedPrincipal {
        let verifier = ContextVerifier::new(signer.public_key());
        verifier
            .verify_context(
                &AuthorityContext::from_token(mint_token_roles(signer, now, Some(300), roles)),
                now + 1,
            )
            .expect("verify")
    }

    /// A verified principal with a chosen STABLE subject identity + roles, constructed directly
    /// (bypassing the wire) to simulate what `verify_context` WILL yield once the issuance path mints a
    /// `sub` into role tokens — the only way to exercise per-identity seal scoping today, since
    /// `cose::mint` cannot set a subject. `iat`/`exp` are set generous so freshness is not the subject.
    fn principal_with_subject(
        subject: &str,
        roles: Vec<GrantedRole>,
        iat: u64,
        exp: u64,
    ) -> VerifiedPrincipal {
        VerifiedPrincipal {
            token: VerifiedToken {
                roles,
                kind: boatramp_core::cose::KIND_ROLE.to_string(),
                subject: Some(subject.to_string()),
                cti: "test-cti".to_string(),
                iat: Some(iat),
                exp: Some(exp),
                cnf: None,
            },
        }
    }

    #[test]
    fn seal_then_unseal_round_trips_for_the_same_identity() {
        let now = 1_000;
        let kek = Arc::new(LocalKek::from_bytes([7u8; 32])) as Arc<dyn KeyEnvelope>;
        let handler = SealerHandler::new(kek);
        let principal = principal_with_subject("alice", vec![role("admin")], now, now + 1_000_000);

        let sealed = runtime().block_on(handler.handle(
            &principal,
            AuthorityRequest::Seal {
                plaintext: b"a tenant secret".to_vec(),
            },
            now,
        ));
        let AuthorityResponse::Sealed { sealed } = sealed else {
            panic!("expected Sealed, got {sealed:?}");
        };
        let out = runtime().block_on(handler.handle(
            &principal,
            AuthorityRequest::Unseal { sealed },
            now,
        ));
        assert_eq!(
            out,
            AuthorityResponse::Unsealed {
                plaintext: b"a tenant secret".to_vec()
            }
        );
    }

    /// HIGH-1 REGRESSION: two principals with IDENTICAL role-shape but DIFFERENT subject identity must
    /// NOT share a seal scope — B cannot unseal A's blob even though their role-shape (principal_id) is
    /// identical. This is the exact flaw the review found (scope keyed on role-shape, not identity).
    #[test]
    fn unseal_refused_across_identities_with_identical_role_shape() {
        let now = 1_000;
        let kek = Arc::new(LocalKek::from_bytes([7u8; 32])) as Arc<dyn KeyEnvelope>;
        let handler = SealerHandler::new(kek);
        let a = principal_with_subject("alice", vec![role("admin")], now, now + 1_000_000);
        let b = principal_with_subject("bob", vec![role("admin")], now, now + 1_000_000);
        // Identical role-SHAPE (the old scope key) — yet DIFFERENT principals.
        assert_eq!(a.principal_id(), b.principal_id());
        let AuthorityResponse::Sealed { sealed } = runtime().block_on(handler.handle(
            &a,
            AuthorityRequest::Seal {
                plaintext: b"A's secret".to_vec(),
            },
            now,
        )) else {
            panic!("seal");
        };
        let out = runtime().block_on(handler.handle(&b, AuthorityRequest::Unseal { sealed }, now));
        assert!(
            matches!(out, AuthorityResponse::Refused { .. }),
            "B must NOT unseal A's blob despite identical role-shape, got {out:?}"
        );
    }

    /// A context with no uniquely-identifying subject (every token the current issuance path mints)
    /// can seal NOTHING and unseal NOTHING — fail-closed, no identity ⇒ no scope.
    #[test]
    fn seal_and_unseal_fail_closed_without_a_subject() {
        let now = 1_000;
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let kek = Arc::new(LocalKek::from_bytes([7u8; 32])) as Arc<dyn KeyEnvelope>;
        let handler = SealerHandler::new(kek);
        let p = principal_for(&signer, now, vec![role("admin")]); // real token ⇒ subject None
        assert!(p.token().subject.is_none());
        let seal = runtime().block_on(handler.handle(
            &p,
            AuthorityRequest::Seal {
                plaintext: b"x".to_vec(),
            },
            now,
        ));
        assert!(
            matches!(seal, AuthorityResponse::Refused { .. }),
            "seal: {seal:?}"
        );
        let unseal = runtime().block_on(handler.handle(
            &p,
            AuthorityRequest::Unseal {
                sealed: b"{}".to_vec(),
            },
            now,
        ));
        assert!(
            matches!(unseal, AuthorityResponse::Refused { .. }),
            "unseal: {unseal:?}"
        );
    }

    #[test]
    fn sealer_kind_gates_a_mint_request() {
        let now = 1_000;
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let kek = Arc::new(LocalKek::from_bytes([7u8; 32])) as Arc<dyn KeyEnvelope>;
        let handler = SealerHandler::new(kek);
        let p = principal_for(&signer, now, vec![role("admin")]);
        // A mint_token sent to the SEALER (wrong kind) is Refused, never actioned, never a panic.
        let out = runtime().block_on(handler.handle(
            &p,
            AuthorityRequest::MintToken {
                requested_roles: vec![role("admin")],
                ttl_secs: 60,
            },
            now,
        ));
        assert!(
            matches!(out, AuthorityResponse::Refused { .. }),
            "got {out:?}"
        );
    }

    // ---- MEDIUM-2: the authority context must be a role token ----

    #[test]
    fn context_pins_kind_to_role() {
        // A non-KIND_ROLE token (a mesh join token), validly signed by the trust root, is REFUSED as
        // an authority context (domain separation) — only an end-principal role bearer is accepted.
        let now = 1_000;
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let verifier = ContextVerifier::new(signer.public_key());
        let join = runtime()
            .block_on(cose::mint_join(300, now, &signer))
            .expect("mint a join token");
        let err = verifier
            .verify_context(&AuthorityContext::from_token(join), now + 1)
            .unwrap_err();
        assert!(matches!(err, ContextRejection::Claims(_)), "got {err:?}");
    }

    // ---- the token.signer grammar: mint ≤ the verified principal's own authority ----

    /// Read the signer handler's public key (test helper — the handler never exposes the key itself).
    fn handler_signer_public(h: &SignerHandler) -> TokenPublicKey {
        h.signer.public_key()
    }

    #[test]
    fn mint_token_mints_only_a_subset_of_authorized_roles() {
        let now = 1_000;
        let root = LocalSigner::generate(TokenAlg::Es256);
        let handler = SignerHandler::new(
            Arc::new(LocalSigner::generate(TokenAlg::Es256)),
            DEFAULT_CONTEXT_MAX_AGE_SECS,
        );
        // The principal holds admin + viewer; it mints a token bearing ONLY viewer (a subset).
        let p = principal_for(&root, now, vec![role("admin"), role("viewer")]);
        let out = runtime().block_on(handler.handle(
            &p,
            AuthorityRequest::MintToken {
                requested_roles: vec![role("viewer")],
                ttl_secs: 60,
            },
            now,
        ));
        let AuthorityResponse::Minted { token } = out else {
            panic!("expected Minted, got {out:?}");
        };
        // The minted token is a real token the signer's own key verifies, bearing exactly `viewer`.
        let verified = cose::verify(&token, &handler_signer_public(&handler), now + 1).unwrap();
        assert_eq!(verified.roles, vec![role("viewer")]);
    }

    /// MEDIUM-1: the minted token's TTL is bound to the context's REMAINING freshness, so an observed
    /// near-stale context cannot be amplified into a durable 1h credential.
    #[test]
    fn mint_token_ttl_clamped_to_remaining_context_freshness() {
        let max_age = 120;
        let iat = 1_000;
        let now = iat + 110; // age 110 ⇒ only 10s of freshness remain
        let handler = SignerHandler::new(Arc::new(LocalSigner::generate(TokenAlg::Es256)), max_age);
        // A subject-bearing principal with a far-off exp, so the freshness bound (not exp) governs.
        let p = principal_with_subject("alice", vec![role("admin")], iat, iat + 1_000_000);
        let out = runtime().block_on(handler.handle(
            &p,
            AuthorityRequest::MintToken {
                requested_roles: vec![role("admin")],
                ttl_secs: 3_600, // asks for an hour...
            },
            now,
        ));
        let AuthorityResponse::Minted { token } = out else {
            panic!("expected Minted, got {out:?}");
        };
        // ...but gets at most the 10s of remaining freshness: exp == now + 10.
        let verified = cose::verify(&token, &handler_signer_public(&handler), now + 1).unwrap();
        assert_eq!(
            verified.exp,
            Some(now + 10),
            "TTL must clamp to remaining freshness"
        );
    }

    #[test]
    fn mint_token_refused_when_a_requested_role_exceeds_the_principal() {
        let now = 1_000;
        let root = LocalSigner::generate(TokenAlg::Es256);
        let handler = SignerHandler::new(
            Arc::new(LocalSigner::generate(TokenAlg::Es256)),
            DEFAULT_CONTEXT_MAX_AGE_SECS,
        );
        // The principal holds ONLY viewer; asking to mint admin (which it does not hold) is Refused.
        let p = principal_for(&root, now, vec![role("viewer")]);
        let out = runtime().block_on(handler.handle(
            &p,
            AuthorityRequest::MintToken {
                requested_roles: vec![role("admin")],
                ttl_secs: 60,
            },
            now,
        ));
        assert!(
            matches!(out, AuthorityResponse::Refused { .. }),
            "got {out:?}"
        );
    }

    #[test]
    fn signer_kind_gates_a_seal_request() {
        let now = 1_000;
        let root = LocalSigner::generate(TokenAlg::Es256);
        let handler = SignerHandler::new(
            Arc::new(LocalSigner::generate(TokenAlg::Es256)),
            DEFAULT_CONTEXT_MAX_AGE_SECS,
        );
        let p = principal_for(&root, now, vec![role("admin")]);
        let out = runtime().block_on(handler.handle(
            &p,
            AuthorityRequest::Seal {
                plaintext: b"x".to_vec(),
            },
            now,
        ));
        assert!(
            matches!(out, AuthorityResponse::Refused { .. }),
            "got {out:?}"
        );
    }

    // ---- the registry routes by required authority + refuses an unheld one ----

    #[test]
    fn registry_routes_by_authority_and_refuses_an_unregistered_one() {
        let now = 1_000;
        // A subject-bearing principal so the Seal route actually seals (per-identity scope).
        let p = principal_with_subject("alice", vec![role("admin")], now, now + 1_000_000);
        // A registry holding ONLY the sealer.
        let kek = Arc::new(LocalKek::from_bytes([7u8; 32])) as Arc<dyn KeyEnvelope>;
        let mut reg = AuthorityRegistry::new();
        reg.register(
            HostAuthority::SecretsSealer,
            Arc::new(SealerHandler::new(kek)),
        );
        // A Seal routes to the sealer (served).
        let out = runtime().block_on(reg.handle(
            &p,
            AuthorityRequest::Seal {
                plaintext: b"x".to_vec(),
            },
            now,
        ));
        assert!(
            matches!(out, AuthorityResponse::Sealed { .. }),
            "got {out:?}"
        );
        // A MintToken (needs token.signer, NOT registered here) is Refused — no wrong-handler dispatch.
        let out = runtime().block_on(reg.handle(
            &p,
            AuthorityRequest::MintToken {
                requested_roles: vec![role("admin")],
                ttl_secs: 60,
            },
            now,
        ));
        assert!(
            matches!(out, AuthorityResponse::Refused { .. }),
            "got {out:?}"
        );
        // Ping (authority-free liveness) is always answered.
        let out = runtime().block_on(reg.handle(&p, AuthorityRequest::Ping { witness: 5 }, now));
        assert_eq!(out, AuthorityResponse::Pong { witness: 5 });
    }

    // ---- end-to-end over a real socketpair (unix) ----

    #[cfg(unix)]
    mod unix {
        use super::*;

        /// Spawn an [`AuthorityServe`] loop on `end` with the given deps + a fixed `now` clock, on a
        /// dedicated thread (the link I/O is blocking). The caller keeps an `Arc<CollectingAudit>`
        /// clone to inspect after the join.
        fn spawn_server(
            end: LinkEndpoint,
            verifier: ContextVerifier,
            handler: Arc<dyn AuthorityHandler>,
            limiter: Arc<dyn AuthorityRateLimiter>,
            audit: Arc<CollectingAudit>,
            now: u64,
        ) -> std::thread::JoinHandle<Result<(), String>> {
            std::thread::spawn(move || {
                let replay = ReplayCache::with_defaults();
                let sem = tokio::sync::Semaphore::new(DEFAULT_MAX_IN_FLIGHT);
                let serve = AuthorityServe {
                    verifier: &verifier,
                    replay: &replay,
                    limiter: limiter.as_ref(),
                    audit: audit.as_ref(),
                    handler: handler.as_ref(),
                    max_in_flight: &sem,
                    read_deadline: Duration::from_secs(5),
                };
                runtime().block_on(serve.serve("to-signer", &end, || now))
            })
        }

        #[test]
        fn ping_round_trips_under_a_valid_context() {
            let now = 1_000;
            let signer = LocalSigner::generate(TokenAlg::Es256);
            let ctx = AuthorityContext::from_token(mint_token(&signer, now, Some(300)));
            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = spawn_server(
                server_end,
                ContextVerifier::new(signer.public_key()),
                Arc::new(PingHandler),
                Arc::new(Unlimited),
                Arc::new(CollectingAudit::default()),
                now + 1,
            );
            let resp = client_end
                .call(&ctx, &AuthorityRequest::Ping { witness: 42 })
                .expect("the call round-trips");
            assert_eq!(resp, AuthorityResponse::Pong { witness: 42 });
            drop(client_end); // EOF → the serve loop returns Ok
            server.join().unwrap().expect("serve ends cleanly on EOF");
        }

        #[test]
        fn grammar_round_trips_and_a_replayed_call_is_refused() {
            // The WS-E grammar over a real socketpair, with a RELAYED real token (which carries no
            // subject today): the sealer seal FAILS CLOSED (HIGH-1 — no identity ⇒ no scope); the
            // signer mint_token works (roles-based); then a VERBATIM replay of a captured call frame
            // (same context, same nonce) is refused by the anti-replay cache.
            let now = 2_000;
            let root = LocalSigner::generate(TokenAlg::Es256);
            let trust_root = root.public_key();
            let kek = Arc::new(LocalKek::from_bytes([9u8; 32])) as Arc<dyn KeyEnvelope>;
            // The signer handler's own key is the trust root here (so a minted token verifies).
            let signer_key = Arc::new(LocalSigner::from_private_hex(&root.private_hex()).unwrap());
            let mut reg = AuthorityRegistry::new();
            reg.register(
                HostAuthority::SecretsSealer,
                Arc::new(SealerHandler::new(kek)),
            );
            reg.register(
                HostAuthority::TokenSigner,
                Arc::new(SignerHandler::new(signer_key, DEFAULT_CONTEXT_MAX_AGE_SECS)),
            );

            let ctx = AuthorityContext::from_token(mint_token_roles(
                &root,
                now,
                Some(300),
                vec![role("admin")],
            ));
            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = spawn_server(
                server_end,
                ContextVerifier::new(trust_root.clone()),
                Arc::new(reg),
                Arc::new(Unlimited),
                Arc::new(CollectingAudit::default()),
                now + 1,
            );

            // seal FAILS CLOSED over the wire: a relayed real token carries no subject (HIGH-1).
            let sealed = client_end
                .call(
                    &ctx,
                    &AuthorityRequest::Seal {
                        plaintext: b"serving secret".to_vec(),
                    },
                )
                .expect("seal call carried");
            assert!(
                matches!(sealed, AuthorityResponse::Refused { .. }),
                "a subjectless relayed context must seal nothing (fail-closed), got {sealed:?}"
            );

            // mint_token works (roles-based, not identity-scoped): the principal holds admin, mints
            // admin (a subset of itself), TTL bound to the context's remaining freshness.
            let minted = client_end
                .call(
                    &ctx,
                    &AuthorityRequest::MintToken {
                        requested_roles: vec![role("admin")],
                        ttl_secs: 60,
                    },
                )
                .expect("mint call");
            let AuthorityResponse::Minted { token } = minted else {
                panic!("expected Minted, got {minted:?}");
            };
            assert_eq!(
                cose::verify(&token, &trust_root, now + 2).unwrap().roles,
                vec![role("admin")]
            );

            // Now a VERBATIM REPLAY: send the identical call frame (same context + same nonce) twice.
            let call = AuthorityCall {
                context: ctx.clone(),
                nonce: 0xDEAD_BEEF,
                request: AuthorityRequest::Ping { witness: 1 },
            };
            let frame = serde_json::to_vec(&call).unwrap();
            client_end.send_frame(&frame).unwrap();
            let first: AuthorityResponse =
                serde_json::from_slice(&client_end.recv_frame().unwrap()).unwrap();
            assert_eq!(first, AuthorityResponse::Pong { witness: 1 });
            client_end.send_frame(&frame).unwrap(); // the SAME frame again — a replay
            let second: AuthorityResponse =
                serde_json::from_slice(&client_end.recv_frame().unwrap()).unwrap();
            assert!(
                matches!(second, AuthorityResponse::Refused { .. }),
                "replay must be refused, got {second:?}"
            );

            drop(client_end);
            server.join().unwrap().expect("clean end");
        }

        #[test]
        fn forged_context_is_refused_no_pong() {
            // A compromised frontend relays a token it forged with a key it holds (not the trust root):
            // the receiver re-validates and REFUSES — no `Pong`, and it keeps serving.
            let now = 1_000;
            let real = LocalSigner::generate(TokenAlg::Es256);
            let attacker = LocalSigner::generate(TokenAlg::Es256);
            let good_ctx = AuthorityContext::from_token(mint_token(&real, now, Some(300)));
            let forged_ctx = AuthorityContext::from_token(mint_token(&attacker, now, Some(300)));

            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = spawn_server(
                server_end,
                ContextVerifier::new(real.public_key()),
                Arc::new(PingHandler),
                Arc::new(Unlimited),
                Arc::new(CollectingAudit::default()),
                now + 1,
            );

            // The forged context is refused (no bytes, no pong) ...
            let resp = client_end
                .call(&forged_ctx, &AuthorityRequest::Ping { witness: 1 })
                .expect("the link still carries the call");
            assert!(
                matches!(resp, AuthorityResponse::Refused { .. }),
                "got {resp:?}"
            );
            // ... and the server keeps serving: a valid context on the same link still succeeds.
            let resp = client_end
                .call(&good_ctx, &AuthorityRequest::Ping { witness: 2 })
                .expect("still serving");
            assert_eq!(resp, AuthorityResponse::Pong { witness: 2 });

            drop(client_end);
            server.join().unwrap().expect("clean end");
        }

        #[test]
        fn throttled_principal_is_refused_and_audited() {
            let now = 1_000;
            let signer = LocalSigner::generate(TokenAlg::Es256);
            let ctx = AuthorityContext::from_token(mint_token(&signer, now, Some(300)));
            // Pre-compute the principal id the limiter must deny.
            let denied_id = ContextVerifier::new(signer.public_key())
                .verify_context(&ctx, now + 1)
                .unwrap()
                .principal_id();
            let mut deny = std::collections::BTreeSet::new();
            deny.insert(denied_id);

            let audit = Arc::new(CollectingAudit::default());
            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = spawn_server(
                server_end,
                ContextVerifier::new(signer.public_key()),
                Arc::new(PingHandler),
                Arc::new(DenyPrincipals(deny)),
                audit.clone(),
                now + 1,
            );

            let resp = client_end
                .call(&ctx, &AuthorityRequest::Ping { witness: 9 })
                .expect("the link carries the call");
            assert!(
                matches!(resp, AuthorityResponse::Refused { .. }),
                "got {resp:?}"
            );

            drop(client_end);
            server.join().unwrap().expect("clean end");
            // The throttle was audited, keyed on the verified principal.
            let entries = audit.drain();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].outcome, AuthorityOutcome::RateLimited);
            assert_eq!(entries[0].op, "ping");
        }
    }
}
