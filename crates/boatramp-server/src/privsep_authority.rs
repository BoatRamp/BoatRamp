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
//!    [`LinkEndpoint::recv_frame`] byte frames: an [`AuthorityLink::relay`] carrying an
//!    [`AuthorityCall`] (a context + nonce + per-call PoP + a bounded request) and returning an
//!    [`AuthorityResponse`]. The
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
//! 3. **Audit + rate-limit hooks keyed on the VERIFIED principal** — the trait seams
//!    ([`AuthorityAudit`], [`AuthorityRateLimiter`]) plus BOTH a default ([`TracingAudit`] /
//!    [`Unlimited`]) and a production impl ([`DurableAudit`] / [`TokenBucketLimiter`]).
//!
//! ## Phase-2 authority-serve HARDENING (this pass)
//!
//! On top of the Wave-1 grammars, this module now carries the wiring-gate containment preconditions:
//! - **Per-call proof-of-possession (mechanism (c)).** Every authority call carries an
//!   [`AuthorityCall::pop`] the ORIGINATING principal signs with its holder (`cnf`) key;
//!   [`ContextVerifier::verify_call`] REQUIRES and re-verifies it against the context token's own `cnf`,
//!   bound to the exact call. This defeats the active-principal new-call forgery the Wave-1 freshness
//!   bound + nonce cache alone do not — a compromised frontend, lacking the holder key, can at most
//!   replay an exact observed call (which the nonce cache catches). The host REFUSES fail-closed a
//!   context with no `cnf` or a call with no valid PoP. See the cross-repo guest-SDK follow-on on
//!   [`AuthorityServe`].
//! - **Mint→mint closure.** A `mint_token` output is `cnf`-bound (so it is itself PoP-bound) AND marked
//!   `br_authz_issued`, so the verifier refuses it if relayed back as a context ([`cose::mint_authority_output`]).
//! - **Durable audit + real limiter** — [`DurableAudit`] + [`TokenBucketLimiter`].
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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use boatramp_core::authz::GrantedRole;
use boatramp_core::cose::{
    self, AuthorityPopBinding, Claims, Signer, TokenError, TokenPublicKey, VerifiedToken,
};
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
/// end-principal credential), a per-call nonce, a per-call **proof-of-possession**, and the
/// [`AuthorityRequest`]. Bundling them in one struct makes it **structurally impossible to send a
/// request without a context AND a possession proof** — there is no relay path that omits either.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityCall {
    /// The relayed end-principal credential, re-validated by the receiver before any dispatch.
    pub context: AuthorityContext,
    /// A fresh per-call anti-replay NONCE (design §3.4 watch-item mechanism (b)). The ORIGINATING
    /// principal mints a CSPRNG value per call ([`AuthorityCall::signed`] does this) and BINDS it into
    /// the PoP (`pop`); the receiver records `(cti, nonce)` in a bounded, TTL-evicting [`ReplayCache`]
    /// and REFUSES a reused pair — so a captured call frame cannot be replayed verbatim. Unlike Wave-1
    /// (where the nonce was unsigned), the nonce is now bound by the PoP to the token + holder key, so
    /// a frontend RCE cannot swap it on an observed proof: mechanisms (a)+(b)+(c) together contain both
    /// the verbatim replay AND the active-principal new-call forgery.
    pub nonce: u128,
    /// The per-call **authority-call proof-of-possession** (design §3.4 watch-item mechanism (c)),
    /// base64url. The ORIGINATING end principal signs it with its holder (`cnf`) key over
    /// (`op`, context token, `nonce`, serialized `request`); the receiver re-verifies it against the
    /// context token's own `cnf` ([`ContextVerifier::verify_call`]). Because the holder key is one the
    /// relaying frontend does NOT hold, a valid proof can only originate from the real principal — a
    /// compromised frontend can at most replay an exact observed call (caught by the nonce cache) and
    /// can NEVER forge a new authority call under an observed context. A call whose `pop` is
    /// absent / unverifiable / bound to a different call is refused fail-closed.
    pub pop: String,
    /// The bounded operation requested.
    pub request: AuthorityRequest,
}

/// The canonical serialized request bytes bound into the authority-call PoP. BOTH the originator
/// ([`AuthorityCall::signed`]) and the receiver ([`ContextVerifier::verify_call`]) run this over the
/// same [`AuthorityRequest`] value, so the PoP's request binding compares identically — a receiver
/// re-serializes the request it deserialized from the frame and gets the originator's bytes back. (The
/// guest-SDK half, in another repo, MUST serialize the request with this same codec; see the module
/// doc's cross-repo follow-on.)
#[must_use]
pub fn request_pop_bytes(request: &AuthorityRequest) -> Vec<u8> {
    // serde_json over our bounded enum is deterministic (declaration-order fields, order-preserving
    // arrays, no maps) and round-trip stable, so mint and verify agree on the bound bytes.
    serde_json::to_vec(request).unwrap_or_default()
}

impl AuthorityCall {
    /// Build a PoP-SIGNED authority call: pick a fresh anti-replay nonce, then sign an authority-call
    /// proof-of-possession over (`op`, context token, nonce, request) with the end principal's holder
    /// (`cnf`) key. **This is the ORIGINATING end principal's operation** (e.g. the guest SDK) — the
    /// frontend that relays the call never runs it, because it does not hold the holder key. The
    /// resulting call is what the frontend relays verbatim with [`AuthorityLink::relay`].
    pub async fn signed(
        context: AuthorityContext,
        request: AuthorityRequest,
        holder: &dyn Signer,
        now_unix: u64,
    ) -> Result<Self, AuthorityError> {
        let nonce = fresh_nonce();
        let req_bytes = request_pop_bytes(&request);
        let binding = AuthorityPopBinding {
            op: request.op_name(),
            context_token: &context.token,
            nonce,
            request_bytes: &req_bytes,
        };
        let pop = cose::mint_authority_pop(&binding, holder, now_unix)
            .await
            .map_err(|e| AuthorityError::Codec(format!("minting authority-call PoP: {e}")))?;
        Ok(Self {
            context,
            nonce,
            pop,
            request,
        })
    }
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
    /// RELAY one already-[`signed`](AuthorityCall::signed) authority call and return the typed reply.
    /// The relay (a frontend) forwards the originator's call verbatim — it does NOT mint the context or
    /// the PoP (it holds neither the issuer key nor the holder key). Never ships key material — the
    /// reply type forecloses it. A transport/codec failure is an [`AuthorityError`]; an authorization
    /// refusal (bad/absent/replayed context or PoP) rides back as `Ok(`[`AuthorityResponse::Refused`]`)`.
    fn relay(&self, call: &AuthorityCall) -> Result<AuthorityResponse, AuthorityError>;
}

#[cfg(unix)]
impl AuthorityLink for LinkEndpoint {
    fn relay(&self, call: &AuthorityCall) -> Result<AuthorityResponse, AuthorityError> {
        let bytes = serde_json::to_vec(call).map_err(|e| AuthorityError::Codec(e.to_string()))?;
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
    /// The token is itself an AUTHORITY-API OUTPUT (it carries the `br_authz_issued` marker — see
    /// [`cose::mint_authority_output`]). An output can NEVER be relayed back as a fresh authority
    /// context: this closes the mint→mint refresh chain (and any re-redemption of an output). Refused.
    AuthorityIssued,
    /// The token is authentic but carries NO holder key (`cnf`), so no per-call proof-of-possession can
    /// bind to it — an authority context MUST be holder-bound (mechanism (c)). Refused fail-closed (a
    /// bare bearer context, replayable by whoever observes it, is exactly what PoP-binding forecloses).
    NoHolderBinding,
    /// No per-call proof-of-possession was relayed with the call (an empty `pop`). The host refuses a
    /// context lacking a valid PoP (fail-closed). Refused.
    MissingPop,
    /// A PoP was relayed but it did not verify against the context token's `cnf`, was stale/future, or
    /// was bound to a DIFFERENT call (a different op / context / nonce / request) — i.e. anything other
    /// than a fresh proof minted by the real holder for THIS exact call. This is the mechanism-(c)
    /// refusal that defeats an active principal's new-call forgery under an observed context. Refused.
    PopUnverifiable(String),
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
            Self::AuthorityIssued => {
                "authority context rejected: a machine-minted authority-API output is not \
                 re-redeemable as a context"
                    .into()
            }
            Self::NoHolderBinding => {
                "authority context rejected: the token carries no holder key (cnf) to bind a \
                 proof-of-possession"
                    .into()
            }
            Self::MissingPop => {
                "authority context rejected: no per-call proof-of-possession was relayed".into()
            }
            Self::PopUnverifiable(e) => format!("authority-call proof-of-possession rejected: {e}"),
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

    /// RE-VALIDATE the relayed `context` TOKEN against the public trust root at `now_unix`, returning
    /// the VERIFIED principal or a fail-closed [`ContextRejection`]. This is the F3 crux: the receiver
    /// does NOT trust the caller's relay — it re-runs the same control-plane verifier
    /// ([`cose::verify`](boatramp_core::cose::verify), the function that authenticates a client's own
    /// presented bearer/role token into a verified principal) against the trust root on EVERY call. An
    /// absent, forged, or expired token refuses — no principal, no dispatch, no bytes.
    ///
    /// **This is the TOKEN step only — it does NOT check the per-call PoP.** The serve path calls
    /// [`verify_call`](Self::verify_call), which runs this PLUS the mechanism-(c) proof-of-possession
    /// check. This method is `pub` for the token-level checks a consumer may want in isolation, but an
    /// authority serve MUST go through [`verify_call`](Self::verify_call) so a context lacking a valid
    /// PoP is refused fail-closed.
    ///
    /// **Anti-replay (Phase-2 Wave 1 + hardening, §3.4 watch-item).** A frontend RCE can REPLAY any
    /// end-principal token it OBSERVES transiting the frontend. The defense is three mechanisms:
    /// (a) a freshness bound on `iat` ([`max_age_secs`](Self::with_max_age_secs)) HERE, refusing a token
    /// older than the bound even when its `exp` is further out; (b) the per-call [`ReplayCache`] in the
    /// serve loop, refusing a verbatim `(cti, nonce)` replay; and (c) the PoP / `cnf`-binding in
    /// [`verify_call`](Self::verify_call), which defeats an ACTIVE principal's NEW-call forgery within
    /// the window that (a)+(b) alone do not. This method also enforces two structural preconditions for
    /// (c): the context must be holder-bound ([`ContextRejection::NoHolderBinding`] if it carries no
    /// `cnf`) and must NOT be a machine-minted authority output ([`ContextRejection::AuthorityIssued`],
    /// closing the mint→mint refresh chain).
    ///
    /// **Revocation is a SEPARATE serve-loop step (WS-E residual #3), not done HERE.** This verifier
    /// stays IO-free — signature + `exp` + freshness only — because the isolated crown jewel is
    /// deliberately control-plane-KV-blind (it cannot do the platform's live `authz/revoked/<cti>` KV
    /// lookup without re-coupling to the KV). Revocation within the freshness window is instead handled
    /// by the serve loop's [`RevocationCheck`] (a KV-blind FEED — see [`FileRevocationList`]), keyed on
    /// the verified `cti`/`subject`. So the former "revoked-but-fresh token is accepted" residual is
    /// closed by that feed; the freshness bound here remains the fallback that bounds any feed-delivery
    /// staleness.
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

        // MINT→MINT CLOSURE: refuse a token that is itself a machine-minted AUTHORITY-API OUTPUT. The
        // signer's `mint_token` stamps `br_authz_issued` on its result (and binds it to the principal's
        // `cnf`); an output relayed BACK as a fresh context to mint again would extend the chain beyond
        // the originating context's freshness — the per-call TTL clamp alone does not stop it. Refusing
        // the marker here closes the refresh chain at the verifier (and any re-redemption of an output).
        if token.authority_issued {
            return Err(ContextRejection::AuthorityIssued);
        }

        // HOLDER-BINDING PRECONDITION (mechanism (c)). An authority context MUST declare a holder key
        // (`cnf`) so the per-call proof-of-possession can bind to a key the frontend does NOT hold. A
        // bare (non-`cnf`) bearer context is replayable by whoever observes it — exactly what PoP
        // forecloses — so refuse it here (fail-closed). `verify_call` relies on this to parse the cnf.
        if token.cnf.is_none() {
            return Err(ContextRejection::NoHolderBinding);
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

    /// RE-VALIDATE a whole [`AuthorityCall`] — its context token ([`verify_context`](Self::verify_context))
    /// AND its per-call **proof-of-possession** (mechanism (c)) — at `now_unix`, returning the VERIFIED
    /// principal or a fail-closed [`ContextRejection`]. **This is the method the serve loop uses; it is
    /// the host's fail-closed refusal of a context lacking a valid PoP.**
    ///
    /// After the token re-validates (which also guarantees a `cnf` is present and the token is not an
    /// authority output), this:
    /// 1. refuses a call with no PoP relayed ([`ContextRejection::MissingPop`]);
    /// 2. parses the context token's own `cnf` into the holder public key (the key the frontend does
    ///    NOT hold);
    /// 3. re-verifies the relayed PoP against that holder key, bound to THIS exact call — the op, the
    ///    context token, the per-call nonce, and the serialized request ([`request_pop_bytes`]). A proof
    ///    that is absent / stale / signed by a different key / bound to a different call is refused
    ///    ([`ContextRejection::PopUnverifiable`]).
    ///
    /// Because a valid proof can only be produced by the real holder, a compromised frontend can at most
    /// REPLAY an exact observed call (which the serve loop's [`ReplayCache`] then catches on the bound
    /// nonce) and can NEVER forge a new authority call under an observed context.
    pub fn verify_call(
        &self,
        call: &AuthorityCall,
        now_unix: u64,
    ) -> Result<VerifiedPrincipal, ContextRejection> {
        // (token) re-validate the context token first — this also enforces cnf-present + not-an-output.
        let principal = self.verify_context(&call.context, now_unix)?;

        // (c.1) a PoP MUST be relayed — fail-closed on an absent one.
        if call.pop.is_empty() {
            return Err(ContextRejection::MissingPop);
        }

        // (c.2) the holder key is the context token's OWN `cnf` (verify_context guaranteed it present).
        let cnf = principal
            .token()
            .cnf
            .as_deref()
            .ok_or(ContextRejection::NoHolderBinding)?;
        let holder = TokenPublicKey::from_hex(cnf)
            .map_err(|e| ContextRejection::PopUnverifiable(format!("malformed holder key: {e}")))?;

        // (c.3) re-verify the PoP against the holder, bound to THIS exact call.
        let req_bytes = request_pop_bytes(&call.request);
        let binding = AuthorityPopBinding {
            op: call.request.op_name(),
            context_token: &call.context.token,
            nonce: call.nonce,
            request_bytes: &req_bytes,
        };
        cose::verify_authority_pop(&call.pop, &holder, now_unix, &binding)
            .map_err(|e| ContextRejection::PopUnverifiable(e.to_string()))?;

        Ok(principal)
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
/// token, same nonce) and the duplicate side-effect of a frontend re-sending one call. On its own it
/// does NOT stop a frontend RCE from crafting a NEW call (fresh nonce) under an observed token within
/// the freshness window. That residual is now closed by PoP / `cnf`-binding (mechanism (c)) in
/// [`ContextVerifier::verify_call`]: the PoP binds the nonce to the token + holder key, so the only
/// call a frontend can get past (c) is one whose exact `(cti, nonce)` it observed — which this cache
/// then refuses. Mechanisms (a)+(b)+(c) together contain both the verbatim replay AND the
/// active-principal new-call forgery.
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
    /// The verified principal was REVOKED — the token's `cti`/`subject` was on the revocation feed, or
    /// the configured feed was UNAVAILABLE (fail-closed) — so the call was refused before dispatch
    /// (WS-E residual #3). Audited keyed on the verified principal (the signature verified).
    Revoked,
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

/// The **durable, append-only, write-only authority-audit sink** (wiring-gate precondition #3 / F9) —
/// the production replacement for [`TracingAudit`]. It appends one JSON-lines record per call to a file
/// held on the RECEIVING (authority-holding) instance, keyed on the VERIFIED `principal_id`:
///
/// - **Append-only.** The file is opened with `O_APPEND`, and each record is a single line written with
///   one `write_all` under a mutex — records are only ever added, never rewritten; a crash mid-write
///   leaves whole prior lines intact (a partial last line is detectable + ignorable by a reader).
/// - **Write-only from the caller's view.** Like the trait, the sink exposes no read path to the
///   authority caller — a compromised frontend can neither read nor tamper the record of what it asked.
///   The file lives in the crown jewel's own state subtree (the composition must grant it WRITE and
///   deny the relay any access — a sandbox-profile concern of the wiring composition).
/// - **Never signals the caller.** A persist failure is logged on the receiver (`tracing::error`) and
///   swallowed — `record` is infallible from the caller's view, so an audit outage never leaks back as
///   a distinguishable authority-call outcome.
///
/// Durability note: records are flushed to the OS on each write (no userspace buffering is held across
/// calls); an `fsync`-per-record is deliberately NOT done (authority calls are infrequent but a per-call
/// fsync is still a needless stall, and the OS page cache already survives a process crash — only a
/// machine crash loses the tail, an accepted bound for a throttle/forensic log, not a containment).
pub struct DurableAudit {
    /// The append-handle, behind a mutex so concurrent link tasks serialize their whole-line writes.
    file: Mutex<std::fs::File>,
    /// The path, for the self-logged failure message only (never written into a record).
    path: std::path::PathBuf,
}

impl DurableAudit {
    /// Open (creating if absent, creating parent dirs as needed) the append-only audit file at `path`.
    /// Fails closed: if the file cannot be opened the authority serve MUST NOT stand up (an audit the
    /// caller could evade is not an audit), so the error is returned to the stand-up, not swallowed.
    pub fn open(path: impl Into<std::path::PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            file: Mutex::new(file),
            path,
        })
    }
}

impl AuthorityAudit for DurableAudit {
    fn record(&self, entry: &AuthorityAuditEntry) {
        use std::io::Write as _;
        // One JSON object per line: the credential-derived principal id, the op, the outcome, and a
        // receiver-side wall-clock stamp. NON-SECRET only (the entry type forecloses bytes/token/args).
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Hand-built JSON over three non-secret, control-character-free fields (principal_id is a
        // credential-derived `kind|roles` string; op + outcome are &'static tags) — no injection vector.
        let line = format!(
            "{{\"ts\":{stamp},\"principal\":{:?},\"op\":{:?},\"outcome\":{:?}}}\n",
            entry.principal_id,
            entry.op,
            format!("{:?}", entry.outcome),
        );
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(e) = file.write_all(line.as_bytes()) {
            // Log on the receiver + swallow — never signal the authority caller (append-only, write-only).
            tracing::error!(
                path = %self.path.display(), error = %e,
                "[privsep] durable authority audit: append failed (record dropped; caller not signaled)"
            );
        }
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

/// A token-bucket quota: at most `capacity` tokens, refilled at `refill_per_sec` tokens/second. One
/// token is consumed per authority call. `capacity` is the burst allowance; `refill_per_sec` is the
/// sustained rate.
#[derive(Debug, Clone, Copy)]
pub struct RateQuota {
    /// The maximum (burst) token count.
    pub capacity: f64,
    /// The sustained refill rate, tokens per second.
    pub refill_per_sec: f64,
}

/// One token bucket (continuous refill via a monotonic clock).
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: std::time::Instant,
}

impl Bucket {
    fn full(q: RateQuota, now: std::time::Instant) -> Self {
        Self {
            tokens: q.capacity,
            last: now,
        }
    }
    /// Refill for the elapsed time, then try to take one token. Returns whether a token was taken.
    fn refill_and_take(&mut self, q: RateQuota, now: std::time::Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * q.refill_per_sec).min(q.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
    /// Whether the bucket is (approximately) full — an idle bucket safe to evict (a fresh one is full
    /// too, so dropping it loses no accrued debt).
    fn is_full(&self, q: RateQuota, now: std::time::Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        (self.tokens + elapsed * q.refill_per_sec) >= q.capacity
    }
}

/// The **real per-verified-principal + global token-bucket rate limiter** (wiring-gate precondition
/// #3 / F9) — the production replacement for [`Unlimited`]. A call is allowed only if BOTH the
/// per-principal bucket AND the global bucket have a token; a token is consumed from each only when
/// both allow (so a throttled principal never drains the global bucket). Keyed on the VERIFIED
/// `principal_id` (never the calling instance or an asserted field).
///
/// **Throttle, NOT containment (F9).** The containment is the context-binding + PoP; this caps blast
/// *rate* and surfaces an anomaly. The per-principal map is bounded (`max_tracked`): when full, idle
/// (refilled-to-capacity) buckets are pruned, and if the map is still full a brand-new principal is
/// throttled — a flood of distinct principals cannot grow memory unbounded (fail-closed under flood,
/// matching the replay cache).
pub struct TokenBucketLimiter {
    inner: KeyedRateBuckets,
}

/// The shared **per-key + global token-bucket** core (consolidated, not mirrored — the one
/// parameterized path behind BOTH the post-verify [`TokenBucketLimiter`] (keyed on the VERIFIED
/// principal) AND the pre-verify [`SourceBucketThrottle`] (keyed on the cheap link/source). A unit is
/// admitted only if BOTH the per-key bucket AND the global bucket have a token; a token is consumed
/// from each only when both allow (so a throttled key never drains the global bucket). The per-key map
/// is bounded (`max_tracked`): when full, idle (refilled-to-capacity) buckets are pruned, and if it is
/// still full a brand-new key is throttled — a flood of distinct keys cannot grow memory unbounded
/// (fail-closed under flood, matching the replay cache).
struct KeyedRateBuckets {
    per_key: RateQuota,
    state: Mutex<KeyedRateState>,
    max_tracked: usize,
}

struct KeyedRateState {
    global: Bucket,
    global_quota: RateQuota,
    keys: HashMap<String, Bucket>,
}

/// The default per-principal token-bucket capacity (burst) — generous, as authority calls are infrequent.
pub const DEFAULT_RATE_PER_PRINCIPAL_BURST: f64 = 60.0;
/// The default per-principal sustained refill rate (tokens/sec).
pub const DEFAULT_RATE_PER_PRINCIPAL_PER_SEC: f64 = 1.0;
/// The default GLOBAL token-bucket capacity (burst) across all principals on the instance.
pub const DEFAULT_RATE_GLOBAL_BURST: f64 = 600.0;
/// The default GLOBAL sustained refill rate (tokens/sec).
pub const DEFAULT_RATE_GLOBAL_PER_SEC: f64 = 50.0;
/// The default cap on distinct principals tracked at once (bounds the limiter's memory).
pub const DEFAULT_RATE_MAX_TRACKED: usize = 65_536;

impl KeyedRateBuckets {
    /// Build with explicit per-key + global quotas and a tracking-table bound.
    fn new(per_key: RateQuota, global: RateQuota, max_tracked: usize) -> Self {
        Self {
            per_key,
            state: Mutex::new(KeyedRateState {
                global: Bucket::full(global, std::time::Instant::now()),
                global_quota: global,
                keys: HashMap::new(),
            }),
            max_tracked,
        }
    }

    /// Check-and-consume one unit for `key`. `true` ⇒ admitted (a token taken from BOTH the global and
    /// the per-key bucket); `false` ⇒ throttled (no token taken anywhere). Fail-closed under flood.
    fn try_admit(&self, key: &str) -> bool {
        let now = std::time::Instant::now();
        let per_key = self.per_key;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // The global bucket first (peek by refilling; only consume if the per-key bucket also allows).
        let global_quota = state.global_quota;
        let mut global = state.global;
        let global_elapsed = now.saturating_duration_since(global.last).as_secs_f64();
        let global_tokens = (global.tokens + global_elapsed * global_quota.refill_per_sec)
            .min(global_quota.capacity);
        if global_tokens < 1.0 {
            // Even refilled, the global bucket is empty: throttle (do not touch the per-key bucket).
            global.tokens = global_tokens;
            global.last = now;
            state.global = global;
            return false;
        }

        // Bound the tracking table: if full and this key is new, prune idle (full) buckets.
        if state.keys.len() >= self.max_tracked && !state.keys.contains_key(key) {
            state.keys.retain(|_, b| !b.is_full(per_key, now));
            if state.keys.len() >= self.max_tracked {
                // Still full of ACTIVE buckets — a genuine many-key flood. Fail-closed (throttle)
                // rather than grow unbounded or evict an active (debt-carrying) bucket.
                return false;
            }
        }

        let bucket = state
            .keys
            .entry(key.to_string())
            .or_insert_with(|| Bucket::full(per_key, now));
        if bucket.refill_and_take(per_key, now) {
            // The per-key bucket allowed — now actually consume the global token too.
            global.tokens = global_tokens - 1.0;
            global.last = now;
            state.global = global;
            true
        } else {
            // The per-key bucket is throttled — leave the global bucket untouched.
            false
        }
    }
}

impl TokenBucketLimiter {
    /// Build with explicit per-principal + global quotas and a tracking-table bound.
    #[must_use]
    pub fn new(per_principal: RateQuota, global: RateQuota, max_tracked: usize) -> Self {
        Self {
            inner: KeyedRateBuckets::new(per_principal, global, max_tracked),
        }
    }

    /// Build with the documented defaults.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(
            RateQuota {
                capacity: DEFAULT_RATE_PER_PRINCIPAL_BURST,
                refill_per_sec: DEFAULT_RATE_PER_PRINCIPAL_PER_SEC,
            },
            RateQuota {
                capacity: DEFAULT_RATE_GLOBAL_BURST,
                refill_per_sec: DEFAULT_RATE_GLOBAL_PER_SEC,
            },
            DEFAULT_RATE_MAX_TRACKED,
        )
    }
}

impl AuthorityRateLimiter for TokenBucketLimiter {
    fn check(&self, principal_id: &str) -> RateLimitDecision {
        if self.inner.try_admit(principal_id) {
            RateLimitDecision::Allow
        } else {
            RateLimitDecision::Throttled
        }
    }
}

// =============================================================================
// 3c. The PRE-VERIFY flood throttle (WS-E residual #2) — cheap, BEFORE the signature verify
// =============================================================================

/// The pre-verify throttle decision for one cheap SOURCE key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreVerifyDecision {
    /// The call may proceed to the (expensive) context re-validation.
    Proceed,
    /// The source has exceeded its pre-verify budget — refuse WITHOUT running the expensive verify.
    Throttled,
}

/// The **pre-verify flood throttle** (design §3.4 / WS-E residual #2). A forged [`AuthorityContext`] is
/// rejected by [`ContextVerifier::verify_call`] — but that re-runs `cose::verify` (an asymmetric
/// signature check), which is EXPENSIVE, so a flood of forged calls on a link is a CPU-exhaustion DoS.
/// This hook is consulted on a CHEAP attribute — the link/SOURCE the call arrived on — BEFORE any
/// deserialization or signature verification, so a forged-context flood is bounded to a cheap
/// refusal-rate and cannot burn the receiver's CPU on `cose::verify`.
///
/// **It NEVER weakens the real verification.** A call that passes this throttle still goes through the
/// full [`ContextVerifier::verify_call`]; this only ever refuses EXTRA load pre-verify. It is keyed on
/// the source (the *calling instance / link*), NOT the end principal — the principal is unknown until
/// after verification, which is the whole point. The post-verify per-principal
/// [`AuthorityRateLimiter`] is the orthogonal second layer.
///
/// For the `local` transport the source key is the link name (one root-wired socketpair = one peer).
/// For the networked transports (later) the source is the peer address / dial-cap holder.
pub trait PreVerifyThrottle: Send + Sync {
    /// Check-and-consume one unit for the cheap `source` key, BEFORE any expensive verify. Returns
    /// whether the call may proceed to re-validation.
    fn check(&self, source: &str) -> PreVerifyDecision;
}

/// The default pre-verify throttle: never throttles (for tests + compositions that rely solely on the
/// post-verify limiter). A production composition swaps in [`SourceBucketThrottle`].
#[derive(Debug, Default, Clone, Copy)]
pub struct UnthrottledPreVerify;

impl PreVerifyThrottle for UnthrottledPreVerify {
    fn check(&self, _source: &str) -> PreVerifyDecision {
        PreVerifyDecision::Proceed
    }
}

/// The default per-SOURCE pre-verify burst — the number of back-to-back calls one link may present
/// before the expensive verify is rate-gated. Larger than the per-principal burst: a single source
/// (e.g. a listener frontend) may legitimately relay calls for MANY principals.
pub const DEFAULT_PREVERIFY_PER_SOURCE_BURST: f64 = 200.0;
/// The default per-source sustained pre-verify rate (calls/sec admitted to verification).
pub const DEFAULT_PREVERIFY_PER_SOURCE_PER_SEC: f64 = 50.0;
/// The default GLOBAL pre-verify burst across all of the instance's authority-serve links.
pub const DEFAULT_PREVERIFY_GLOBAL_BURST: f64 = 2_000.0;
/// The default GLOBAL sustained pre-verify rate (calls/sec admitted to verification).
pub const DEFAULT_PREVERIFY_GLOBAL_PER_SEC: f64 = 500.0;
/// The default cap on distinct sources tracked at once (bounds the throttle's memory).
pub const DEFAULT_PREVERIFY_MAX_TRACKED: usize = 4_096;

/// The **real per-source + global pre-verify token-bucket throttle** (WS-E residual #2) — the
/// production [`PreVerifyThrottle`]. It rides the SAME consolidated [`KeyedRateBuckets`] core as
/// [`TokenBucketLimiter`] (keyed on the source instead of the principal), so a per-source flood is
/// gated AND a total flood across links is globally capped, both before any `cose::verify`. Shared
/// across an instance's authority-serve link threads (one instance, cloned in).
pub struct SourceBucketThrottle {
    inner: KeyedRateBuckets,
}

impl SourceBucketThrottle {
    /// Build with explicit per-source + global quotas and a tracking-table bound.
    #[must_use]
    pub fn new(per_source: RateQuota, global: RateQuota, max_tracked: usize) -> Self {
        Self {
            inner: KeyedRateBuckets::new(per_source, global, max_tracked),
        }
    }

    /// Build with the documented defaults.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(
            RateQuota {
                capacity: DEFAULT_PREVERIFY_PER_SOURCE_BURST,
                refill_per_sec: DEFAULT_PREVERIFY_PER_SOURCE_PER_SEC,
            },
            RateQuota {
                capacity: DEFAULT_PREVERIFY_GLOBAL_BURST,
                refill_per_sec: DEFAULT_PREVERIFY_GLOBAL_PER_SEC,
            },
            DEFAULT_PREVERIFY_MAX_TRACKED,
        )
    }
}

impl PreVerifyThrottle for SourceBucketThrottle {
    fn check(&self, source: &str) -> PreVerifyDecision {
        if self.inner.try_admit(source) {
            PreVerifyDecision::Proceed
        } else {
            PreVerifyDecision::Throttled
        }
    }
}

// =============================================================================
// 3d. The revocation check (WS-E residual #3) — refuse a revoked principal within its freshness window
// =============================================================================

/// The revocation status of a verified principal, consulted on every authority call (WS-E residual #3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationState {
    /// Not revoked — the call may proceed.
    Active,
    /// The principal's token is REVOKED (its `cti` or `subject` is on the revocation feed) — refuse.
    Revoked,
    /// The configured revocation feed could not be consulted (unreadable / malformed) — refuse
    /// FAIL-CLOSED. A crown jewel that cannot consult its revocation signal must not serve, else a
    /// revoked principal would slip through.
    Unavailable,
}

/// The **revocation check** (WS-E residual #3). [`ContextVerifier`] checks signature + `exp` + freshness
/// but NOT revocation — the isolated crown jewel is deliberately control-plane-KV-BLIND (it holds no
/// `backend.kv`), so it cannot do the platform's live `authz/revoked/<cti>` KV lookup
/// ([`boatramp_server::auth`]) without re-coupling to the KV and collapsing the secret-blind split. This
/// hook lets a revoked principal be refused EVEN WITHIN its freshness window, via a signal the crown
/// jewel can consult WITHOUT opening the KV.
///
/// Keyed on the VERIFIED principal's credential — its `cti` (per-token revocation, the platform's unit)
/// and/or `subject` (per-principal revocation) — never a caller-asserted field.
///
/// **Fail-closed:** a configured feed that cannot be consulted returns [`RevocationState::Unavailable`],
/// which the serve loop refuses (an un-consultable revocation signal must not fail open).
pub trait RevocationCheck: Send + Sync {
    /// The revocation status of `principal` at call time.
    fn status(&self, principal: &VerifiedPrincipal) -> RevocationState;
}

/// The default revocation check: every principal is [`RevocationState::Active`] (NO revocation signal).
/// This is the documented Phase-1 residual made EXPLICIT — a composition that wires no feed accepts a
/// revoked-but-fresh token until it ages out of the freshness window. The mechanism to close it is
/// [`FileRevocationList`]; the DEFAULT serve wiring uses the file feed at a conventional path, so a
/// composition only lands on `NoRevocation` by choosing it.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoRevocation;

impl RevocationCheck for NoRevocation {
    fn status(&self, _principal: &VerifiedPrincipal) -> RevocationState {
        RevocationState::Active
    }
}

/// The on-disk revocation feed shape: a set of revoked token ids (`cti`, hex) and/or revoked principal
/// subjects (`sub`). Both optional; an empty / omitted array revokes nothing.
#[derive(Debug, Default, Deserialize)]
struct RevocationFeed {
    #[serde(default)]
    cti: Vec<String>,
    #[serde(default)]
    subject: Vec<String>,
}

/// The last successfully-loaded feed state (behind the cache mutex).
enum FeedState {
    /// The feed file was absent at the last stat — NO revocations (matches the platform's
    /// `authz/revoked/<cti>` absent ⇒ not-revoked semantics).
    Absent,
    /// The feed was loaded at modification time `mtime` with these revoked sets.
    Present {
        mtime: Option<std::time::SystemTime>,
        cti: HashSet<String>,
        subject: HashSet<String>,
    },
}

/// A **file-backed revocation feed** (WS-E residual #3) the KV-blind crown jewel can consult without
/// opening the control-plane KV. The authoritative revocation state is the platform's
/// `authz/revoked/<cti>` KV markers; this file is a **projection** of them, DELIVERED into the crown
/// jewel's OWN Landlock-granted state subtree out-of-band (who projects it + the cadence is the owner/
/// ops design — flagged for Security; the delivery MUST be atomic, e.g. write-then-rename, so a reader
/// never sees a half-written feed). The crown jewel only READS it — it never touches the KV, so the
/// secret-blind split holds.
///
/// Semantics, mirroring the platform's revocation model:
/// - **File absent** ⇒ [`RevocationState::Active`] (no revocations — exactly as an absent
///   `authz/revoked/<cti>` marker reads as not-revoked).
/// - **File present + readable + parseable** ⇒ a token whose `cti` or `subject` is listed is
///   [`RevocationState::Revoked`]; otherwise [`RevocationState::Active`].
/// - **File present but unreadable / malformed** ⇒ [`RevocationState::Unavailable`] (fail-closed — a
///   configured-but-unconsultable feed must refuse, never fail open).
///
/// The feed is cached and reloaded only when its mtime changes (a `stat` per call; authority calls are
/// infrequent and pre-verify-throttled). **Staleness bound (flagged):** a revocation propagates no
/// faster than the feed is re-delivered, so within the freshness window a revoked token is refused only
/// once the feed carries it; past the freshness window it is refused anyway (stale). The feed cadence is
/// thus the revocation-latency knob the owner/ops set.
pub struct FileRevocationList {
    path: std::path::PathBuf,
    cache: Mutex<FeedState>,
}

impl FileRevocationList {
    /// A feed read from `path` (the crown jewel's own granted subtree). Opening is lazy (per-call stat);
    /// construction never fails — an absent file is simply "no revocations" until one is delivered.
    #[must_use]
    pub fn at(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            cache: Mutex::new(FeedState::Absent),
        }
    }

    /// Parse the feed file into its revoked sets.
    fn load(path: &std::path::Path) -> std::io::Result<(HashSet<String>, HashSet<String>)> {
        let bytes = std::fs::read(path)?;
        let feed: RevocationFeed = serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok((
            feed.cti.into_iter().collect(),
            feed.subject.into_iter().collect(),
        ))
    }
}

impl RevocationCheck for FileRevocationList {
    fn status(&self, principal: &VerifiedPrincipal) -> RevocationState {
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Refresh: stat the feed; reload on first use / mtime change; fail-closed on a read/parse error.
        match std::fs::metadata(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                *cache = FeedState::Absent;
            }
            Err(e) => {
                // A stat error other than "absent" (e.g. a permission error on a configured feed) is a
                // consultation failure — fail-closed, and do NOT cache it (retry next call).
                tracing::warn!(path = %self.path.display(), error = %e, "[privsep] revocation feed stat failed — refusing fail-closed");
                return RevocationState::Unavailable;
            }
            Ok(meta) => {
                let mtime = meta.modified().ok();
                let need_reload =
                    !matches!(&*cache, FeedState::Present { mtime: m, .. } if *m == mtime);
                if need_reload {
                    match Self::load(&self.path) {
                        Ok((cti, subject)) => {
                            *cache = FeedState::Present {
                                mtime,
                                cti,
                                subject,
                            };
                        }
                        Err(e) => {
                            // Readable-stat but unreadable/malformed content — fail-closed, uncached.
                            tracing::warn!(path = %self.path.display(), error = %e, "[privsep] revocation feed unreadable/malformed — refusing fail-closed");
                            return RevocationState::Unavailable;
                        }
                    }
                }
            }
        }
        match &*cache {
            FeedState::Absent => RevocationState::Active,
            FeedState::Present { cti, subject, .. } => {
                let tok = principal.token();
                if cti.contains(tok.cti.as_str()) {
                    return RevocationState::Revoked;
                }
                if let Some(sub) = tok.subject.as_deref()
                    && subject.contains(sub)
                {
                    return RevocationState::Revoked;
                }
                RevocationState::Active
            }
        }
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

    /// Whether this handler is PERMITTED to serve the request kinds that require `authority` (WS-E
    /// residual #4 — kind-gating COMPLETION). The [`AuthorityRegistry`] VERIFIES at registration that a
    /// handler registered under authority `A` declares `permits_authority(A)` — a composition that
    /// registers a handler under an authority it does not serve is refused FAIL-CLOSED, at composition,
    /// before any call ([`AuthorityRegistry::register`]). Combined with each handler's own internal
    /// kind-gate (every `handle` arm but its grammar's returns [`refused_wrong_kind`]), this makes the
    /// kind-gate STRUCTURAL rather than convention: a handler can never be ROUTED a request kind outside
    /// its declared grant (the registry dispatches by [`AuthorityRequest::required_authority`] to a
    /// handler that has declared it serves exactly that authority), and even a hand-constructed
    /// misdispatch is caught by the internal kind-gate. There is deliberately NO default impl — a NEW
    /// capability handler MUST consciously declare its grant here, itself a review tripwire.
    fn permits_authority(&self, authority: HostAuthority) -> bool;
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

    /// The liveness handler holds NO authority: it serves only the authority-FREE
    /// [`AuthorityRequest::Ping`] (routed via the registry's `None` arm, never registered under any
    /// [`HostAuthority`]). So it permits no held authority — it must never be registered as a capability
    /// handler (the registry's `register` would refuse it).
    fn permits_authority(&self, _authority: HostAuthority) -> bool {
        false
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

    /// The sealer serves ONLY the `secrets.sealer` grammar (seal/unseal) — never any other authority's
    /// kinds.
    fn permits_authority(&self, authority: HostAuthority) -> bool {
        matches!(authority, HostAuthority::SecretsSealer)
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
        // PoP-BIND THE OUTPUT (wiring-gate precondition). The minted token is holder-bound (`cnf`) to
        // the SAME key the originating principal holds — read from the verified context's own `cnf`
        // (which `verify_call` guaranteed present). So the output is itself proof-of-possession-bound,
        // not a bare-replayable bearer; AND `mint_authority_output` stamps it `br_authz_issued`, so the
        // context verifier refuses it if it is ever relayed back as a fresh context — closing the
        // mint→mint refresh chain. If the principal somehow carries no `cnf` (it never should past
        // `verify_call`, but a handler can be invoked directly), fail closed rather than mint an
        // unbindable output.
        let Some(cnf) = principal.token().cnf.as_deref() else {
            tracing::warn!(
                principal = %principal.principal_id(),
                "[privsep] signer REFUSED mint_token: the verified context carries no holder key (cnf) to PoP-bind the output (fail-closed)"
            );
            return AuthorityResponse::Refused {
                reason:
                    "mint_token refused: the authority context carries no holder key to bind the \
                         minted output"
                        .to_string(),
            };
        };
        let holder = match TokenPublicKey::from_hex(cnf) {
            Ok(h) => h,
            Err(_) => {
                tracing::warn!(
                    principal = %principal.principal_id(),
                    "[privsep] signer REFUSED mint_token: the verified context holder key (cnf) is malformed (fail-closed)"
                );
                return AuthorityResponse::Refused {
                    reason: "mint_token refused: the authority context holder key is malformed"
                        .to_string(),
                };
            }
        };
        let claims = Claims {
            roles: requested_roles,
            kind: cose::KIND_ROLE.to_string(),
            ttl_secs: Some(ttl),
            now_unix,
        };
        match cose::mint_authority_output(&claims, &holder, self.signer.as_ref()).await {
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

    /// The signer serves ONLY the `token.signer` grammar (mint_token) — never any other authority's
    /// kinds.
    fn permits_authority(&self, authority: HostAuthority) -> bool {
        matches!(authority, HostAuthority::TokenSigner)
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

    /// Register `handler` as the grammar for `authority` — **CHECKED fail-closed (WS-E residual #4).**
    /// The handler MUST declare it [`permits_authority`](AuthorityHandler::permits_authority)`(authority)`;
    /// a handler registered under an authority it does not serve (a composition bug that would otherwise
    /// let a request kind be routed to the wrong grammar, caught only by the handler's internal kind-gate
    /// as defense-in-depth) is REFUSED here, at composition, before any call. A second registration for
    /// the same authority replaces the first (the composition holds one handler per authority per
    /// instance). The stand-up propagates the error → the instance exits → `FailNodeClosed`.
    pub fn register(
        &mut self,
        authority: HostAuthority,
        handler: Arc<dyn AuthorityHandler>,
    ) -> Result<(), String> {
        if !handler.permits_authority(authority) {
            return Err(format!(
                "refusing to register an authority handler under the {} authority it does not \
                 permit (kind-gating completion, WS-E residual #4): a handler serves ONLY its own \
                 declared authority's request kinds",
                authority.tag()
            ));
        }
        self.handlers.insert(authority, handler);
        Ok(())
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

    /// The registry (a composite handler) permits `authority` iff it holds a registered handler that
    /// itself permits it — tautological post-[`register`](Self::register) (register refuses a mismatch),
    /// but keeps the composite consistent with the trait contract. The registry is never itself
    /// registered inside another registry; this exists for trait-completeness.
    fn permits_authority(&self, authority: HostAuthority) -> bool {
        self.handlers
            .get(&authority)
            .is_some_and(|h| h.permits_authority(authority))
    }
}

/// The hardened receiver-side authority serve (design §2 / §3.4 / task #2). Bundles the fail-closed
/// deps so the serve loop takes a single, reviewable shape:
/// - `verifier` — re-validates every call's context against the public trust root (F3), now also with
///   the tightened freshness bound;
/// - `pre_verify` — the CHEAP pre-verify flood throttle keyed on the link/source (WS-E residual #2),
///   consulted BEFORE `cose::verify` so a forged-context flood cannot exhaust CPU;
/// - `replay` — the per-call `(cti, nonce)` anti-replay cache (mechanism (b));
/// - `revocation` — the revocation check (WS-E residual #3), refusing a revoked principal (by
///   `cti`/`subject`) even within its freshness window, fail-closed on an unavailable feed;
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
/// `boatramp::privsep::compute_authority_serve_links`) AND code-fail-closed at stand-up (the gate
/// `boatramp::privsep::check_authority_serve_preconditions` refuses until BOTH a PoP/cnf verifier is
/// configured AND the link is purpose-marked). This Phase-2 HARDENING pass builds the containment
/// preconditions; the remaining ones are the composition/config + owner items:
/// 1. **HIGH-1 per-principal identity (open — owner + issuance).** A mandatory per-principal `sub` claim
///    must be minted into end-principal role tokens (today [`scope_of`] fails closed because none
///    exists), and the owner must settle the seal-GRANULARITY model (per-identity `sub` vs per-tenant).
///    Until then the sealer grammar seals/unseals NOTHING.
/// 2. **(c) PoP / `cnf`-binding (BUILT — host side).** [`ContextVerifier::verify_call`] now REQUIRES and
///    verifies a per-call authority-call proof-of-possession ([`AuthorityCall::pop`]) against the
///    context token's own `cnf`, bound to (op, context token, nonce, request) — defeating both the
///    verbatim replay and the ACTIVE-principal new-call forgery that (a)+(b) alone do not. A context
///    lacking a `cnf`, or a call lacking a valid PoP, is refused fail-closed. A machine-minted
///    `mint_token` output is itself PoP-bound (`cnf` = the principal's holder key) AND marked
///    `br_authz_issued`, so it is refused if relayed back as a context — closing the mint→mint refresh
///    chain. **Cross-repo FOLLOW-ON (guest SDK, `boatramp-uchron-shim`):** the ORIGINATING client must
///    (i) hold a holder key and present end-principal role tokens that are `cnf`-bound to it, and
///    (ii) sign each authority call's PoP ([`AuthorityCall::signed`] is the reference impl) and thread
///    it through the frontend relay ([`AuthorityLink::relay`] forwards it verbatim). Until the issuance
///    path mints `cnf`-bound end-principal tokens, the host fails closed (a non-`cnf` context is
///    [`ContextRejection::NoHolderBinding`]) — correct + inert.
/// 3. **Real limiter + durable audit (BUILT).** [`TokenBucketLimiter`] (per-principal + global) replaces
///    [`Unlimited`]; [`DurableAudit`] (append-only, write-only, principal-keyed JSONL) replaces
///    [`TracingAudit`]. The composition's stand-up wires these in (its sandbox profile must grant the
///    crown jewel WRITE to the audit path and deny the relay any access).
/// 4. **Per-link PURPOSE marker (open — composition model, sibling lane).** The composition needs an
///    explicit per-link purpose so a listener-FRONTEND→signer authority link can be designated WITHOUT
///    colliding with the link-shape-identical client-fd splice (why `compute_authority_serve_links`
///    conservatively excludes the listener-peer shape today).
///
/// The stand-up gate opens only when BOTH a PoP/cnf verifier is configured (precondition 2's host side
/// is now present) AND the link is purpose-marked (precondition 4) — so the serve stays inert until
/// both land. The former **LOW-1 revocation residual** (a revoked-but-fresh token accepted within the
/// freshness window) is now addressed by the serve loop's [`RevocationCheck`] (`revocation`) — a
/// KV-blind feed keyed on the verified `cti`/`subject` ([`FileRevocationList`]); its delivery cadence
/// (who projects the control-plane `authz/revoked/<cti>` markers into the crown jewel's feed) is the
/// owner/ops design flagged for Security.
pub struct AuthorityServe<'a> {
    /// The context verifier (public trust root + freshness bound).
    pub verifier: &'a ContextVerifier,
    /// The CHEAP pre-verify flood throttle (WS-E residual #2) — consulted on the link/source BEFORE
    /// any deserialization or signature verification, so a forged-context flood cannot burn CPU on
    /// `cose::verify`. Never weakens the real verify (it only ever refuses extra load pre-verify).
    pub pre_verify: &'a dyn PreVerifyThrottle,
    /// The per-call anti-replay cache.
    pub replay: &'a ReplayCache,
    /// The revocation check (WS-E residual #3) — refuses a revoked principal even within its freshness
    /// window, consulted on the VERIFIED principal's `cti`/`subject` without opening the KV.
    pub revocation: &'a dyn RevocationCheck,
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
    /// 2. PRE-VERIFY flood throttle (residual #2) keyed on the cheap source — a throttled source ⇒
    ///    `Refused` WITHOUT running the expensive `cose::verify`, LOG, keep serving;
    /// 3. RE-VALIDATE its [`AuthorityContext`] (signature + `exp` + the tightened freshness bound) AND
    ///    its per-call PoP; a rejection ⇒ `Refused` (no bytes), LOG, keep serving;
    /// 4. check the per-call anti-replay cache — a verbatim replay / saturation ⇒ audit `Replayed` +
    ///    `Refused`, keep serving;
    /// 5. check revocation (residual #3) — a revoked principal / unavailable feed ⇒ audit `Revoked` +
    ///    `Refused` (fail-closed), keep serving;
    /// 6. check the per-verified-principal rate-limit — a trip ⇒ audit `RateLimited` + `Refused`;
    /// 7. else acquire a global in-flight permit, dispatch to the per-capability handler, AUDIT the
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

            // (1b) PRE-VERIFY FLOOD THROTTLE (WS-E residual #2). Keyed on the CHEAP source (the link),
            // consulted BEFORE deserialization + the expensive `cose::verify`, so a forged-context flood
            // cannot exhaust CPU on signature verification. Fail-closed: a throttled source is refused
            // here (a cheap, non-secret refusal — there is no verified principal yet, so this is LOGGED
            // but not principal-keyed-audited, mirroring a context rejection). This never weakens the
            // real verify — a frame that passes still goes through the full `verify_call` below.
            if self.pre_verify.check(link_name) == PreVerifyDecision::Throttled {
                tracing::warn!(link = %link_name, "[privsep] authority REFUSED pre-verify: source flood throttle tripped (no cose::verify run)");
                self.send(
                    link,
                    &AuthorityResponse::Refused {
                        reason: "pre-verify throttle: source call rate exceeded".to_string(),
                    },
                )?;
                continue;
            }

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

            // (2) RE-VALIDATE the whole call: the context (signature + exp + freshness + cnf-present +
            // not-an-output) AND the per-call proof-of-possession (mechanism (c)). A rejection reaches
            // no authority: refused, logged, no principal-keyed audit (there is no verified principal).
            let principal = match self.verifier.verify_call(&call, now) {
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

            // (3b) REVOCATION (WS-E residual #3): refuse a revoked principal even within its freshness
            // window. Keyed on the verified `cti`/`subject`, consulted WITHOUT opening the KV. A
            // configured-but-unconsultable feed is `Unavailable` ⇒ refuse FAIL-CLOSED (an
            // un-consultable revocation signal must not fail open). Audited keyed on the verified
            // principal (the signature verified; the call did not proceed).
            match self.revocation.status(&principal) {
                RevocationState::Active => {}
                state @ (RevocationState::Revoked | RevocationState::Unavailable) => {
                    self.audit.record(&AuthorityAuditEntry {
                        principal_id: principal_id.clone(),
                        op,
                        outcome: AuthorityOutcome::Revoked,
                    });
                    tracing::warn!(link = %link_name, principal = %principal_id, op, ?state, "[privsep] authority REFUSED: principal revoked (or revocation feed unavailable — fail-closed)");
                    let reason = match state {
                        RevocationState::Revoked => "revoked: the principal is revoked",
                        _ => "revocation feed unavailable (fail-closed)",
                    };
                    self.send(
                        link,
                        &AuthorityResponse::Refused {
                            reason: reason.to_string(),
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

    /// Mint a valid, `cnf`-BOUND role bearer token (`br_kind = "role"`) with `ttl` seconds from `now`,
    /// holder-bound to `holder` (the key a per-call PoP must verify against). This is the realistic
    /// Phase-3 authority-context shape: an authority context MUST carry a `cnf`.
    fn mint_ctx(
        signer: &LocalSigner,
        holder: &TokenPublicKey,
        now: u64,
        ttl: Option<u64>,
    ) -> String {
        mint_ctx_roles(signer, holder, now, ttl, Vec::new())
    }

    /// Mint a `cnf`-bound role token carrying `roles`.
    fn mint_ctx_roles(
        signer: &LocalSigner,
        holder: &TokenPublicKey,
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
            .block_on(cose::mint_delegatable(&claims, holder, signer))
            .expect("mint")
    }

    /// A `cnf`-bound role token for the verify_context-only / principal-shape tests that do NOT exercise
    /// the per-call PoP (a throwaway holder is embedded — the private half is never needed here).
    fn mint_token(signer: &LocalSigner, now: u64, ttl: Option<u64>) -> String {
        let holder = LocalSigner::generate(TokenAlg::Es256).public_key();
        mint_ctx(signer, &holder, now, ttl)
    }

    /// As [`mint_token`] but carrying `roles` (throwaway holder — no PoP exercised).
    fn mint_token_roles(
        signer: &LocalSigner,
        now: u64,
        ttl: Option<u64>,
        roles: Vec<GrantedRole>,
    ) -> String {
        let holder = LocalSigner::generate(TokenAlg::Es256).public_key();
        mint_ctx_roles(signer, &holder, now, ttl, roles)
    }

    /// Build a fully PoP-SIGNED call as the ORIGINATING principal would — a `cnf`-bound context (holder
    /// `holder`) plus a per-call PoP signed by that holder. The reference for what the guest SDK emits.
    fn signed_call(
        root: &LocalSigner,
        holder: &LocalSigner,
        now: u64,
        ttl: Option<u64>,
        roles: Vec<GrantedRole>,
        request: AuthorityRequest,
    ) -> AuthorityCall {
        let ctx = AuthorityContext::from_token(mint_ctx_roles(
            root,
            &holder.public_key(),
            now,
            ttl,
            roles,
        ));
        runtime()
            .block_on(AuthorityCall::signed(ctx, request, holder, now))
            .expect("sign the authority call")
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

    // ---- mechanism (c): the per-call proof-of-possession binding ----

    #[test]
    fn cnf_less_context_is_refused_no_holder_binding() {
        // A valid, trust-root-signed role token that is NOT cnf-bound (the ordinary non-delegatable
        // mint) cannot be an authority context — there is no holder key to bind a PoP to. Refused.
        let now = 1_000;
        let root = LocalSigner::generate(TokenAlg::Es256);
        let verifier = ContextVerifier::new(root.public_key());
        let claims = Claims {
            roles: Vec::new(),
            kind: boatramp_core::cose::KIND_ROLE.to_string(),
            ttl_secs: Some(300),
            now_unix: now,
        };
        let plain = runtime().block_on(cose::mint(&claims, &root)).unwrap();
        let err = verifier
            .verify_context(&AuthorityContext::from_token(plain), now + 1)
            .unwrap_err();
        assert_eq!(err, ContextRejection::NoHolderBinding);
    }

    #[test]
    fn pop_less_call_is_refused() {
        // verify_call with an empty PoP is refused fail-closed (MissingPop), even on an otherwise valid
        // cnf-bound context.
        let now = 1_000;
        let root = LocalSigner::generate(TokenAlg::Es256);
        let holder = LocalSigner::generate(TokenAlg::Es256);
        let verifier = ContextVerifier::new(root.public_key());
        let call = AuthorityCall {
            context: AuthorityContext::from_token(mint_ctx(
                &root,
                &holder.public_key(),
                now,
                Some(300),
            )),
            nonce: fresh_nonce(),
            pop: String::new(),
            request: AuthorityRequest::Ping { witness: 1 },
        };
        assert_eq!(
            verifier.verify_call(&call, now + 1).unwrap_err(),
            ContextRejection::MissingPop
        );
    }

    #[test]
    fn valid_signed_call_verifies_and_wrong_holder_pop_is_refused() {
        // A PoP signed by the context's OWN holder verifies; a PoP signed by a DIFFERENT key (what a
        // frontend lacking the holder private key can at best produce) does not.
        let now = 1_000;
        let root = LocalSigner::generate(TokenAlg::Es256);
        let holder = LocalSigner::generate(TokenAlg::Es256);
        let verifier = ContextVerifier::new(root.public_key());

        let good = signed_call(
            &root,
            &holder,
            now,
            Some(300),
            Vec::new(),
            AuthorityRequest::Ping { witness: 1 },
        );
        assert!(verifier.verify_call(&good, now + 1).is_ok());

        // Same context, but a PoP signed by an IMPOSTOR key (not the context's cnf).
        let impostor = LocalSigner::generate(TokenAlg::Es256);
        let req = AuthorityRequest::Ping { witness: 1 };
        let req_bytes = request_pop_bytes(&req);
        let binding = AuthorityPopBinding {
            op: req.op_name(),
            context_token: &good.context.token,
            nonce: good.nonce,
            request_bytes: &req_bytes,
        };
        let bad_pop = runtime()
            .block_on(cose::mint_authority_pop(&binding, &impostor, now))
            .unwrap();
        let bad = AuthorityCall {
            pop: bad_pop,
            ..good.clone()
        };
        assert!(matches!(
            verifier.verify_call(&bad, now + 1).unwrap_err(),
            ContextRejection::PopUnverifiable(_)
        ));
    }

    #[test]
    fn pop_bound_to_a_different_request_is_refused() {
        // THE ACTIVE-PRINCIPAL FORGERY the nonce alone does not stop: a frontend observes a valid
        // (context, PoP) for op A and tries to pair it with a DIFFERENT request B. The PoP is bound to
        // the exact request, so swapping it is refused (PopUnverifiable).
        let now = 1_000;
        let root = LocalSigner::generate(TokenAlg::Es256);
        let holder = LocalSigner::generate(TokenAlg::Es256);
        let verifier = ContextVerifier::new(root.public_key());

        // A proof minted for a benign Ping...
        let benign = signed_call(
            &root,
            &holder,
            now,
            Some(300),
            vec![role("admin")],
            AuthorityRequest::Ping { witness: 1 },
        );
        // ...re-paired with a privileged MintToken request (same context, same nonce, same PoP).
        let swapped = AuthorityCall {
            request: AuthorityRequest::MintToken {
                requested_roles: vec![role("admin")],
                ttl_secs: 60,
            },
            ..benign.clone()
        };
        assert!(matches!(
            verifier.verify_call(&swapped, now + 1).unwrap_err(),
            ContextRejection::PopUnverifiable(_)
        ));
    }

    #[test]
    fn mint_output_is_not_re_redeemable_as_a_context() {
        // Close the mint→mint refresh chain: an output minted by the signer grammar carries the
        // br_authz_issued marker and so is REFUSED if relayed back as a fresh authority context.
        let now = 1_000;
        let root = LocalSigner::generate(TokenAlg::Es256);
        // The signer's key is the trust root, so a minted output verifies against the context verifier.
        let signer_key = Arc::new(LocalSigner::from_private_hex(&root.private_hex()).unwrap());
        let handler = SignerHandler::new(signer_key, DEFAULT_CONTEXT_MAX_AGE_SECS);
        // A subject-bearing, cnf-bound principal mints an output bound to its holder.
        let holder = LocalSigner::generate(TokenAlg::Es256);
        let mut principal =
            principal_with_subject("alice", vec![role("admin")], now, now + 1_000_000);
        principal.token.cnf = Some(holder.public_key().to_hex());

        let out = runtime().block_on(handler.handle(
            &principal,
            AuthorityRequest::MintToken {
                requested_roles: vec![role("admin")],
                ttl_secs: 60,
            },
            now,
        ));
        let AuthorityResponse::Minted { token } = out else {
            panic!("expected Minted, got {out:?}");
        };
        // The output verifies as a token AND is marked authority-issued.
        let v = cose::verify(&token, &root.public_key(), now + 1).unwrap();
        assert!(v.authority_issued);

        // Relaying it BACK as a fresh authority context is refused (AuthorityIssued).
        let verifier = ContextVerifier::new(root.public_key());
        let err = verifier
            .verify_context(&AuthorityContext::from_token(token), now + 1)
            .unwrap_err();
        assert_eq!(err, ContextRejection::AuthorityIssued);
    }

    // ---- durable audit sink (task #2): append-only, write-only, principal-keyed ----

    #[test]
    fn durable_audit_appends_one_line_per_record() {
        let dir = std::env::temp_dir().join(format!("privsep-audit-{}", fresh_nonce()));
        let path = dir.join("authority-audit.jsonl");
        let audit = DurableAudit::open(&path).expect("open durable audit");
        audit.record(&AuthorityAuditEntry {
            principal_id: "role|admin".to_string(),
            op: "mint_token",
            outcome: AuthorityOutcome::Served,
        });
        audit.record(&AuthorityAuditEntry {
            principal_id: "role|viewer".to_string(),
            op: "ping",
            outcome: AuthorityOutcome::RateLimited,
        });
        let body = std::fs::read_to_string(&path).expect("read back");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "append-only: one line per record");
        assert!(lines[0].contains("\"op\":\"mint_token\"") && lines[0].contains("role|admin"));
        assert!(lines[1].contains("RateLimited") && lines[1].contains("role|viewer"));
        // Re-opening appends (never truncates) — the durable property.
        drop(audit);
        let audit2 = DurableAudit::open(&path).expect("re-open");
        audit2.record(&AuthorityAuditEntry {
            principal_id: "role|admin".to_string(),
            op: "ping",
            outcome: AuthorityOutcome::Replayed,
        });
        let body = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(body.lines().count(), 3, "re-open appends, never truncates");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- token-bucket rate limiter (task #3): per-principal + global ----

    #[test]
    fn token_bucket_throttles_a_principal_past_its_burst() {
        // A tiny per-principal bucket (capacity 3, no refill) allows exactly 3 then throttles; a
        // DIFFERENT principal is unaffected (per-principal keying).
        let limiter = TokenBucketLimiter::new(
            RateQuota {
                capacity: 3.0,
                refill_per_sec: 0.0,
            },
            RateQuota {
                capacity: 1_000.0,
                refill_per_sec: 0.0,
            },
            1_024,
        );
        for _ in 0..3 {
            assert_eq!(limiter.check("alice"), RateLimitDecision::Allow);
        }
        assert_eq!(limiter.check("alice"), RateLimitDecision::Throttled);
        // A different principal still has its own full bucket.
        assert_eq!(limiter.check("bob"), RateLimitDecision::Allow);
    }

    #[test]
    fn token_bucket_global_cap_throttles_across_principals() {
        // A global cap of 2 (no refill) throttles the 3rd call even across DISTINCT principals, and a
        // throttled call does not consume a principal's own tokens needlessly.
        let limiter = TokenBucketLimiter::new(
            RateQuota {
                capacity: 100.0,
                refill_per_sec: 0.0,
            },
            RateQuota {
                capacity: 2.0,
                refill_per_sec: 0.0,
            },
            1_024,
        );
        assert_eq!(limiter.check("alice"), RateLimitDecision::Allow);
        assert_eq!(limiter.check("bob"), RateLimitDecision::Allow);
        // Global bucket is now empty → everyone is throttled regardless of per-principal headroom.
        assert_eq!(limiter.check("carol"), RateLimitDecision::Throttled);
        assert_eq!(limiter.check("alice"), RateLimitDecision::Throttled);
    }

    // ---- WS-E residual #2: the pre-verify flood throttle (keyed on the cheap source) ----

    #[test]
    fn pre_verify_throttle_gates_per_source() {
        // Per-source burst of 2, no refill: a source gets 2 then is throttled; a DIFFERENT source has
        // its own independent bucket.
        let t = SourceBucketThrottle::new(
            RateQuota {
                capacity: 2.0,
                refill_per_sec: 0.0,
            },
            RateQuota {
                capacity: 1_000.0,
                refill_per_sec: 0.0,
            },
            16,
        );
        assert_eq!(t.check("link-a"), PreVerifyDecision::Proceed);
        assert_eq!(t.check("link-a"), PreVerifyDecision::Proceed);
        assert_eq!(t.check("link-a"), PreVerifyDecision::Throttled);
        // A different source is unaffected by link-a's flood.
        assert_eq!(t.check("link-b"), PreVerifyDecision::Proceed);
    }

    #[test]
    fn pre_verify_throttle_global_cap_bounds_total_verify_load() {
        // A global cap of 2 (no refill) bounds TOTAL admitted-to-verify load across DISTINCT sources —
        // so a flood spread across many links cannot exhaust CPU on cose::verify.
        let t = SourceBucketThrottle::new(
            RateQuota {
                capacity: 100.0,
                refill_per_sec: 0.0,
            },
            RateQuota {
                capacity: 2.0,
                refill_per_sec: 0.0,
            },
            16,
        );
        assert_eq!(t.check("link-a"), PreVerifyDecision::Proceed);
        assert_eq!(t.check("link-b"), PreVerifyDecision::Proceed);
        assert_eq!(t.check("link-c"), PreVerifyDecision::Throttled);
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

    /// A test revocation check with a fixed state (residual #3 serve-loop tests).
    struct FixedRevocation(RevocationState);
    impl RevocationCheck for FixedRevocation {
        fn status(&self, _principal: &VerifiedPrincipal) -> RevocationState {
            self.0
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
        // A holder key so an authority-output mint (which binds the output to the principal's `cnf`)
        // has one to bind to — the realistic shape of a verify_call'd principal.
        let holder = LocalSigner::generate(TokenAlg::Es256).public_key().to_hex();
        VerifiedPrincipal {
            token: VerifiedToken {
                roles,
                kind: boatramp_core::cose::KIND_ROLE.to_string(),
                subject: Some(subject.to_string()),
                cti: "test-cti".to_string(),
                iat: Some(iat),
                exp: Some(exp),
                cnf: Some(holder),
                authority_issued: false,
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
        )
        .unwrap();
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

    // ---- WS-E residual #4: registration is kind-gated (a handler can't serve a foreign authority) ----

    #[test]
    fn register_refuses_a_handler_under_an_authority_it_does_not_serve() {
        // A SealerHandler registered under the token.signer authority is a composition bug: the sealer
        // serves no token.signer kind. The CHECKED register refuses it fail-closed, at composition.
        let kek = Arc::new(LocalKek::from_bytes([3u8; 32])) as Arc<dyn KeyEnvelope>;
        let mut reg = AuthorityRegistry::new();
        let err = reg
            .register(
                HostAuthority::TokenSigner,
                Arc::new(SealerHandler::new(kek)),
            )
            .unwrap_err();
        assert!(err.contains("does not"), "got {err}");
        // And the correct registration is accepted.
        let kek2 = Arc::new(LocalKek::from_bytes([3u8; 32])) as Arc<dyn KeyEnvelope>;
        reg.register(
            HostAuthority::SecretsSealer,
            Arc::new(SealerHandler::new(kek2)),
        )
        .expect("the sealer registers under its own authority");
    }

    #[test]
    fn handlers_permit_only_their_own_authority() {
        let kek = Arc::new(LocalKek::from_bytes([4u8; 32])) as Arc<dyn KeyEnvelope>;
        let sealer = SealerHandler::new(kek);
        assert!(sealer.permits_authority(HostAuthority::SecretsSealer));
        assert!(!sealer.permits_authority(HostAuthority::TokenSigner));
        let signer = SignerHandler::new(
            Arc::new(LocalSigner::generate(TokenAlg::Es256)),
            DEFAULT_CONTEXT_MAX_AGE_SECS,
        );
        assert!(signer.permits_authority(HostAuthority::TokenSigner));
        assert!(!signer.permits_authority(HostAuthority::SecretsSealer));
        // The liveness handler holds no authority — it must never register as a capability handler.
        assert!(!PingHandler.permits_authority(HostAuthority::SecretsSealer));
    }

    // ---- WS-E residual #3: the revocation check (KV-blind, file-feed, fail-closed) ----

    #[test]
    fn no_revocation_is_always_active() {
        let p = principal_with_subject("alice", vec![role("admin")], 1_000, 2_000);
        assert_eq!(NoRevocation.status(&p), RevocationState::Active);
    }

    #[test]
    fn file_revocation_missing_feed_is_active() {
        // An absent feed ⇒ no revocations (matches `authz/revoked/<cti>` absent ⇒ not-revoked).
        let path = std::env::temp_dir().join(format!("privsep-revoke-{}.json", fresh_nonce()));
        let feed = FileRevocationList::at(&path);
        let p = principal_with_subject("alice", vec![role("admin")], 1_000, 2_000);
        assert_eq!(feed.status(&p), RevocationState::Active);
    }

    #[test]
    fn file_revocation_picks_up_a_delivered_cti_feed() {
        // Absent → Active; then DELIVER a feed revoking the principal's cti → Revoked (reload on the
        // absent→present transition, no mtime-granularity dependence).
        let dir = std::env::temp_dir().join(format!("privsep-revoke-{}", fresh_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("revoked.json");
        let feed = FileRevocationList::at(&path);
        // `principal_with_subject` builds a principal whose cti is "test-cti".
        let p = principal_with_subject("alice", vec![role("admin")], 1_000, 2_000);
        assert_eq!(feed.status(&p), RevocationState::Active, "no feed yet");
        std::fs::write(&path, br#"{"cti":["test-cti"]}"#).unwrap();
        assert_eq!(
            feed.status(&p),
            RevocationState::Revoked,
            "delivered feed revoking the cti"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_revocation_revokes_by_subject() {
        let dir = std::env::temp_dir().join(format!("privsep-revoke-{}", fresh_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("revoked.json");
        std::fs::write(&path, br#"{"subject":["alice"]}"#).unwrap();
        let feed = FileRevocationList::at(&path);
        let alice = principal_with_subject("alice", vec![role("admin")], 1_000, 2_000);
        let bob = principal_with_subject("bob", vec![role("admin")], 1_000, 2_000);
        assert_eq!(feed.status(&alice), RevocationState::Revoked);
        assert_eq!(
            feed.status(&bob),
            RevocationState::Active,
            "a different subject is not revoked"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_revocation_malformed_feed_is_unavailable_fail_closed() {
        // A present-but-unparseable feed is a consultation failure ⇒ Unavailable (fail-closed), NOT a
        // silent Active — an un-consultable revocation signal must never fail open.
        let dir = std::env::temp_dir().join(format!("privsep-revoke-{}", fresh_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("revoked.json");
        std::fs::write(&path, b"this is not json").unwrap();
        let feed = FileRevocationList::at(&path);
        let p = principal_with_subject("alice", vec![role("admin")], 1_000, 2_000);
        assert_eq!(feed.status(&p), RevocationState::Unavailable);
        let _ = std::fs::remove_dir_all(&dir);
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
            spawn_server_full(
                end,
                verifier,
                handler,
                limiter,
                Arc::new(UnthrottledPreVerify),
                Arc::new(NoRevocation),
                audit,
                now,
            )
        }

        /// As [`spawn_server`] but with an explicit pre-verify throttle (WS-E residual #2).
        fn spawn_server_throttled(
            end: LinkEndpoint,
            verifier: ContextVerifier,
            handler: Arc<dyn AuthorityHandler>,
            limiter: Arc<dyn AuthorityRateLimiter>,
            pre_verify: Arc<dyn PreVerifyThrottle>,
            audit: Arc<CollectingAudit>,
            now: u64,
        ) -> std::thread::JoinHandle<Result<(), String>> {
            spawn_server_full(
                end,
                verifier,
                handler,
                limiter,
                pre_verify,
                Arc::new(NoRevocation),
                audit,
                now,
            )
        }

        /// As [`spawn_server`] but with explicit pre-verify throttle AND revocation check (residuals
        /// #2/#3).
        #[allow(clippy::too_many_arguments)]
        fn spawn_server_full(
            end: LinkEndpoint,
            verifier: ContextVerifier,
            handler: Arc<dyn AuthorityHandler>,
            limiter: Arc<dyn AuthorityRateLimiter>,
            pre_verify: Arc<dyn PreVerifyThrottle>,
            revocation: Arc<dyn RevocationCheck>,
            audit: Arc<CollectingAudit>,
            now: u64,
        ) -> std::thread::JoinHandle<Result<(), String>> {
            std::thread::spawn(move || {
                let replay = ReplayCache::with_defaults();
                let sem = tokio::sync::Semaphore::new(DEFAULT_MAX_IN_FLIGHT);
                let serve = AuthorityServe {
                    verifier: &verifier,
                    pre_verify: pre_verify.as_ref(),
                    replay: &replay,
                    revocation: revocation.as_ref(),
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
        fn ping_round_trips_under_a_valid_signed_context() {
            let now = 1_000;
            let root = LocalSigner::generate(TokenAlg::Es256);
            let holder = LocalSigner::generate(TokenAlg::Es256);
            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = spawn_server(
                server_end,
                ContextVerifier::new(root.public_key()),
                Arc::new(PingHandler),
                Arc::new(Unlimited),
                Arc::new(CollectingAudit::default()),
                now + 1,
            );
            // The ORIGINATING principal signs the call with its holder key; the frontend relays it.
            let call = signed_call(
                &root,
                &holder,
                now,
                Some(300),
                Vec::new(),
                AuthorityRequest::Ping { witness: 42 },
            );
            let resp = client_end.relay(&call).expect("the call round-trips");
            assert_eq!(resp, AuthorityResponse::Pong { witness: 42 });
            drop(client_end); // EOF → the serve loop returns Ok
            server.join().unwrap().expect("serve ends cleanly on EOF");
        }

        #[test]
        fn grammar_round_trips_and_a_replayed_call_is_refused() {
            // The WS-E grammar over a real socketpair, with a PoP-SIGNED relayed call: the sealer seal
            // FAILS CLOSED (HIGH-1 — no subject ⇒ no scope); the signer mint_token works (roles-based)
            // and its output is cnf-bound + authority-issued; then a VERBATIM replay of a captured call
            // frame (same context, same nonce, same PoP) is refused by the anti-replay cache.
            let now = 2_000;
            let root = LocalSigner::generate(TokenAlg::Es256);
            let holder = LocalSigner::generate(TokenAlg::Es256);
            let trust_root = root.public_key();
            let kek = Arc::new(LocalKek::from_bytes([9u8; 32])) as Arc<dyn KeyEnvelope>;
            // The signer handler's own key is the trust root here (so a minted token verifies).
            let signer_key = Arc::new(LocalSigner::from_private_hex(&root.private_hex()).unwrap());
            let mut reg = AuthorityRegistry::new();
            reg.register(
                HostAuthority::SecretsSealer,
                Arc::new(SealerHandler::new(kek)),
            )
            .unwrap();
            reg.register(
                HostAuthority::TokenSigner,
                Arc::new(SignerHandler::new(signer_key, DEFAULT_CONTEXT_MAX_AGE_SECS)),
            )
            .unwrap();

            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = spawn_server(
                server_end,
                ContextVerifier::new(trust_root.clone()),
                Arc::new(reg),
                Arc::new(Unlimited),
                Arc::new(CollectingAudit::default()),
                now + 1,
            );

            // seal FAILS CLOSED over the wire: a relayed token carries no subject (HIGH-1).
            let seal = signed_call(
                &root,
                &holder,
                now,
                Some(300),
                vec![role("admin")],
                AuthorityRequest::Seal {
                    plaintext: b"serving secret".to_vec(),
                },
            );
            let sealed = client_end.relay(&seal).expect("seal call carried");
            assert!(
                matches!(sealed, AuthorityResponse::Refused { .. }),
                "a subjectless relayed context must seal nothing (fail-closed), got {sealed:?}"
            );

            // mint_token works (roles-based, not identity-scoped): the principal holds admin, mints
            // admin (a subset of itself); the output is cnf-bound to the holder + authority-issued.
            let mint = signed_call(
                &root,
                &holder,
                now,
                Some(300),
                vec![role("admin")],
                AuthorityRequest::MintToken {
                    requested_roles: vec![role("admin")],
                    ttl_secs: 60,
                },
            );
            let minted = client_end.relay(&mint).expect("mint call");
            let AuthorityResponse::Minted { token } = minted else {
                panic!("expected Minted, got {minted:?}");
            };
            let v = cose::verify(&token, &trust_root, now + 2).unwrap();
            assert_eq!(v.roles, vec![role("admin")]);
            assert!(v.authority_issued, "the output must be authority-issued");
            assert_eq!(
                v.cnf.as_deref(),
                Some(holder.public_key().to_hex().as_str()),
                "the output must be cnf-bound to the principal's holder"
            );

            // Now a VERBATIM REPLAY: send the identical signed call frame twice. The first is served;
            // the second is refused by the (cti, nonce) anti-replay cache even though the PoP re-verifies.
            let ping = signed_call(
                &root,
                &holder,
                now,
                Some(300),
                vec![role("admin")],
                AuthorityRequest::Ping { witness: 1 },
            );
            let frame = serde_json::to_vec(&ping).unwrap();
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
        fn pop_less_call_is_refused_over_the_wire() {
            // A relayed call with NO proof-of-possession (empty `pop`) is refused fail-closed — the host
            // refuses a context lacking a valid PoP (mechanism (c) is mandatory). A fresh valid call on
            // the same link still succeeds (the server keeps serving).
            let now = 1_000;
            let root = LocalSigner::generate(TokenAlg::Es256);
            let holder = LocalSigner::generate(TokenAlg::Es256);
            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = spawn_server(
                server_end,
                ContextVerifier::new(root.public_key()),
                Arc::new(PingHandler),
                Arc::new(Unlimited),
                Arc::new(CollectingAudit::default()),
                now + 1,
            );
            // A cnf-bound context but a STRIPPED PoP (what a frontend that observed only the token, not a
            // per-call proof, could at best present).
            let no_pop = AuthorityCall {
                context: AuthorityContext::from_token(mint_ctx(
                    &root,
                    &holder.public_key(),
                    now,
                    Some(300),
                )),
                nonce: fresh_nonce(),
                pop: String::new(),
                request: AuthorityRequest::Ping { witness: 7 },
            };
            let resp = client_end
                .relay(&no_pop)
                .expect("the link carries the call");
            assert!(
                matches!(resp, AuthorityResponse::Refused { .. }),
                "a PoP-less call must be refused, got {resp:?}"
            );
            let good = signed_call(
                &root,
                &holder,
                now,
                Some(300),
                Vec::new(),
                AuthorityRequest::Ping { witness: 8 },
            );
            assert_eq!(
                client_end.relay(&good).expect("still serving"),
                AuthorityResponse::Pong { witness: 8 }
            );
            drop(client_end);
            server.join().unwrap().expect("clean end");
        }

        #[test]
        fn forged_context_is_refused_no_pong() {
            // A compromised frontend relays a (self-signed-PoP) call whose CONTEXT token it forged with a
            // key it holds (not the trust root): the receiver re-validates the token and REFUSES before
            // the PoP even matters — no `Pong`, and it keeps serving.
            let now = 1_000;
            let real = LocalSigner::generate(TokenAlg::Es256);
            let attacker = LocalSigner::generate(TokenAlg::Es256);
            let holder = LocalSigner::generate(TokenAlg::Es256);
            // The attacker can produce a self-consistent call (its own forged context + a matching PoP),
            // but the context does not verify against the REAL trust root.
            let forged = signed_call(
                &attacker,
                &holder,
                now,
                Some(300),
                Vec::new(),
                AuthorityRequest::Ping { witness: 1 },
            );
            let good = signed_call(
                &real,
                &holder,
                now,
                Some(300),
                Vec::new(),
                AuthorityRequest::Ping { witness: 2 },
            );

            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = spawn_server(
                server_end,
                ContextVerifier::new(real.public_key()),
                Arc::new(PingHandler),
                Arc::new(Unlimited),
                Arc::new(CollectingAudit::default()),
                now + 1,
            );

            let resp = client_end
                .relay(&forged)
                .expect("the link still carries the call");
            assert!(
                matches!(resp, AuthorityResponse::Refused { .. }),
                "got {resp:?}"
            );
            let resp = client_end.relay(&good).expect("still serving");
            assert_eq!(resp, AuthorityResponse::Pong { witness: 2 });

            drop(client_end);
            server.join().unwrap().expect("clean end");
        }

        #[test]
        fn throttled_principal_is_refused_and_audited() {
            let now = 1_000;
            let root = LocalSigner::generate(TokenAlg::Es256);
            let holder = LocalSigner::generate(TokenAlg::Es256);
            let call = signed_call(
                &root,
                &holder,
                now,
                Some(300),
                Vec::new(),
                AuthorityRequest::Ping { witness: 9 },
            );
            // Pre-compute the principal id the limiter must deny (verify_context yields the same id).
            let denied_id = ContextVerifier::new(root.public_key())
                .verify_context(&call.context, now + 1)
                .unwrap()
                .principal_id();
            let mut deny = std::collections::BTreeSet::new();
            deny.insert(denied_id);

            let audit = Arc::new(CollectingAudit::default());
            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = spawn_server(
                server_end,
                ContextVerifier::new(root.public_key()),
                Arc::new(PingHandler),
                Arc::new(DenyPrincipals(deny)),
                audit.clone(),
                now + 1,
            );

            let resp = client_end.relay(&call).expect("the link carries the call");
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

        #[test]
        fn pre_verify_throttle_refuses_before_the_expensive_verify() {
            // WS-E residual #2: the pre-verify throttle short-circuits BEFORE cose::verify. A per-source
            // burst of 1 admits the first (valid) call; a SECOND call — a FORGED context the real trust
            // root would reject at verify — is refused with the PRE-VERIFY reason, proving the throttle
            // ran and `cose::verify` did NOT (a verified rejection would carry the "unverifiable" reason).
            let now = 1_000;
            let real = LocalSigner::generate(TokenAlg::Es256);
            let attacker = LocalSigner::generate(TokenAlg::Es256);
            let holder = LocalSigner::generate(TokenAlg::Es256);
            // Per-source budget of exactly ONE admission to verify; global ample.
            let throttle = Arc::new(SourceBucketThrottle::new(
                RateQuota {
                    capacity: 1.0,
                    refill_per_sec: 0.0,
                },
                RateQuota {
                    capacity: 1_000.0,
                    refill_per_sec: 0.0,
                },
                16,
            ));
            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = spawn_server_throttled(
                server_end,
                ContextVerifier::new(real.public_key()),
                Arc::new(PingHandler),
                Arc::new(Unlimited),
                throttle,
                Arc::new(CollectingAudit::default()),
                now + 1,
            );

            // First call (valid) consumes the single source token and is served.
            let good = signed_call(
                &real,
                &holder,
                now,
                Some(300),
                Vec::new(),
                AuthorityRequest::Ping { witness: 1 },
            );
            assert_eq!(
                client_end.relay(&good).expect("carried"),
                AuthorityResponse::Pong { witness: 1 }
            );

            // Second call: a FORGED context. If it reached verify it would be refused as unverifiable;
            // instead the pre-verify throttle (now out of source tokens) refuses it WITHOUT verifying.
            let forged = signed_call(
                &attacker,
                &holder,
                now,
                Some(300),
                Vec::new(),
                AuthorityRequest::Ping { witness: 2 },
            );
            let resp = client_end.relay(&forged).expect("carried");
            match resp {
                AuthorityResponse::Refused { reason } => assert!(
                    reason.contains("pre-verify throttle"),
                    "expected a pre-verify refusal (verify skipped), got reason: {reason}"
                ),
                other => panic!("expected Refused, got {other:?}"),
            }

            drop(client_end);
            server.join().unwrap().expect("clean end");
        }

        #[test]
        fn revoked_principal_is_refused_and_audited() {
            // WS-E residual #3: a principal the revocation feed marks revoked is refused AFTER the
            // context + PoP verify (so it is a verified principal) and BEFORE dispatch, audited `Revoked`.
            let now = 1_000;
            let root = LocalSigner::generate(TokenAlg::Es256);
            let holder = LocalSigner::generate(TokenAlg::Es256);
            let call = signed_call(
                &root,
                &holder,
                now,
                Some(300),
                Vec::new(),
                AuthorityRequest::Ping { witness: 9 },
            );
            let audit = Arc::new(CollectingAudit::default());
            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = spawn_server_full(
                server_end,
                ContextVerifier::new(root.public_key()),
                Arc::new(PingHandler),
                Arc::new(Unlimited),
                Arc::new(UnthrottledPreVerify),
                Arc::new(FixedRevocation(RevocationState::Revoked)),
                audit.clone(),
                now + 1,
            );
            let resp = client_end.relay(&call).expect("carried");
            match resp {
                AuthorityResponse::Refused { reason } => {
                    assert!(reason.contains("revoked"), "got reason: {reason}");
                }
                other => panic!("expected Refused, got {other:?}"),
            }
            drop(client_end);
            server.join().unwrap().expect("clean end");
            let entries = audit.drain();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].outcome, AuthorityOutcome::Revoked);
        }

        #[test]
        fn unavailable_revocation_feed_fails_closed_over_the_wire() {
            // A configured-but-unconsultable feed (Unavailable) refuses the call fail-closed.
            let now = 1_000;
            let root = LocalSigner::generate(TokenAlg::Es256);
            let holder = LocalSigner::generate(TokenAlg::Es256);
            let call = signed_call(
                &root,
                &holder,
                now,
                Some(300),
                Vec::new(),
                AuthorityRequest::Ping { witness: 3 },
            );
            let audit = Arc::new(CollectingAudit::default());
            let (server_end, client_end) = LinkEndpoint::socketpair().unwrap();
            let server = spawn_server_full(
                server_end,
                ContextVerifier::new(root.public_key()),
                Arc::new(PingHandler),
                Arc::new(Unlimited),
                Arc::new(UnthrottledPreVerify),
                Arc::new(FixedRevocation(RevocationState::Unavailable)),
                audit.clone(),
                now + 1,
            );
            let resp = client_end.relay(&call).expect("carried");
            assert!(
                matches!(resp, AuthorityResponse::Refused { .. }),
                "an unavailable revocation feed must refuse fail-closed, got {resp:?}"
            );
            drop(client_end);
            server.join().unwrap().expect("clean end");
            assert_eq!(audit.drain()[0].outcome, AuthorityOutcome::Revoked);
        }
    }
}
