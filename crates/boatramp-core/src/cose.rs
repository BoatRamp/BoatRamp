//! COSE/CWT control-plane tokens + a pluggable [`Signer`] (authz migration).
//!
//! A control-plane token is a `COSE_Sign1` (RFC 9052) over a CWT claim set
//! (RFC 8392): the boatramp roles (`br_roles`), a kind tag (`br_kind`, domain
//! separation), a TTL (`exp`), and a random revocation id (`cti`). Signing goes
//! through the [`Signer`] trait so the root key can be a local key, an HSM
//! (PKCS#11), or a cloud KMS — **verification needs only the public key**, so the
//! hot per-request path is offline. Algorithms are **ES256 (default) + Ed25519**,
//! pinned on verify to defeat algorithm confusion.
//!
//! A *delegatable* token additionally declares a holder key (RFC 8747 `cnf`); the
//! holder can [`attenuate`] it fully offline into a chain of `COSE_Sign1` blocks
//! that only *narrow* authority (restrict-only [`Caveats`]). [`verify_credential`]
//! walks such a chain — each block verified under its parent's `cnf` (proof of
//! possession), caveats intersected, `not_after` folded into the effective `exp`,
//! and roles taken from the **root only** (the anti-escalation invariant).

// `CborValue` (the CBOR value model) and `ClaimsSet` (the CWT claim-set) are the
// foreign types this module's API speaks; `pub use` re-exports them through
// boatramp-core::cose for consumers that only depend on boatramp-core (U8–U10, #6),
// while they remain usable internally under the same names.
pub use ciborium::value::Value as CborValue;
pub use coset::cwt::ClaimsSet;
use coset::cwt::{ClaimsSetBuilder, Timestamp};

use boatramp_types::authz::GrantedRole;

// The generic COSE_Sign1/CWT engine lives in `boatramp-cwt`. These re-exports keep
// boatramp-core's public API byte-for-byte: `boatramp_core::cose::{TokenError,
// Signer, LocalSigner, TokenPublicKey, TokenAlg, MAX_CHAIN_*, p256_der_sig_to_raw}`
// resolve exactly as before, now pointing at the shared engine. The newest-first
// key-selection helpers (`peek_*`, U8–U10, #5) surface here too.
pub use boatramp_cwt::{
    LocalSigner, MAX_CHAIN_BYTES, MAX_CHAIN_DEPTH, NarrowingCaveats, Signer, TokenAlg, TokenError,
    TokenPublicKey, p256_der_sig_to_raw, peek_protected_kid, peek_unverified_claims,
};
// Low-level engine helpers this module's boatramp-specific mint/verify functions
// call (private, as they were before the extraction).
use boatramp_cwt::{check_exp, claim_cti, random_cti, sign_claims, text_claim, verify_envelope};

/// Text claim key for the boatramp role set (an array of `[name]` / `[name,target]`).
const CLAIM_ROLES: &str = "br_roles";
/// Text claim key for the token kind (`role` / `join` / `cluster-write` / …).
const CLAIM_KIND: &str = "br_kind";
/// Text claim key for a mesh join token's node id (a CBOR integer).
const CLAIM_NODE: &str = "br_node";
/// Text claim key for a mesh join token's bound mesh public key (SPKI hex).
const CLAIM_PUBKEY: &str = "br_pubkey";
/// Text claim key for an anonymous session cookie's session id (R3, PLAN-tenancy-principal).
const CLAIM_SID: &str = "br_sid";
/// Text claim key for a durable signed-context envelope's carried own-tenant value (R1).
const CLAIM_CTX: &str = "br_ctx";
/// Text claim key for a durable signed-context envelope's carried caller **persona/role** (the async
/// -lane RBAC propagation, PLAN-async-persona). A SINGLE bounded text value (never an array/set) —
/// the host-verified value of the producer bearer's operator-configured `token_persona_claim`, sealed
/// into the SAME `COSE_Sign1` as `br_ctx` so it is bound to the same signature/expiry/tenant. Read
/// back by [`verify_context_full`]; a hostile/corrupt/oversized/non-text value is dropped (persona
/// `None`), never a panic. Absent when no persona was configured (unchanged for every existing
/// producer).
const CLAIM_PERSONA: &str = "br_persona";
/// Text claim key for a signed-context envelope's **principal class** (a
/// `cron-system-principal` request). Present (value [`SCOPE_KIND_SYSTEM`]) ONLY on a SYSTEM seal — a
/// no-tenant platform/super-admin principal. A tenant seal omits it entirely (so existing seals are
/// byte-unchanged). It is a POSITIVE, signed marker: a system principal is recognised ONLY by this
/// claim's presence, NEVER by the mere absence of `br_ctx` (that still rejects, preserving the
/// malformity check). Sealed into the SAME `COSE_Sign1` as the other claims, so the class is
/// signature-bound and unforgeable; a system seal carries NO `br_ctx` (the two are mutually exclusive —
/// a seal with both is rejected as a contradiction).
const CLAIM_SCOPE_KIND: &str = "br_scope_kind";
/// The public-subset name a target-capability envelope grants (5c) — binds the capability to a
/// specific declared `PublicSubset`, so a capability minted for one subset can't reach another.
const CLAIM_PUB: &str = "br_pub";
/// An **opaque, app-authored context** map a target-capability carries (PLAN-delegable-capabilities):
/// integrity-protected by the fleet signature, **never interpreted by the host**, and surfaced back to
/// the issuing guest so it can apply its own within-tenant filter (e.g. a per-client `sub`). The host
/// treats every key/value as an opaque string.
const CLAIM_APP: &str = "br_app";
/// Text claim key for the **S3-ingress upload scope** ([`KIND_S3_SESSION`]) — a CBOR map holding the
/// host-stamped `{project, site, container, key|prefix, perms, constraints}`. The full scope lives in
/// the SIGNED payload so a client can never widen it (the URL/headers are never consulted for scope).
const CLAIM_S3: &str = "br_s3";
/// Text claim key for an overlay-dial capability's authorized dial scope (boatramp overlay fabric):
/// the in-cluster service/target the holder may dial (`"*"` = any within the issuer's authority).
/// The scope lives in the SIGNED payload, so a client can never widen it.
const CLAIM_OVERLAY_SCOPE: &str = "br_ovscope";
/// Text claim key for an overlay enrollment/member role (boatramp overlay fabric): a single scalar
/// member-role string ([`OverlayMemberRole`] — `node`/`device`/`workload`), carried in the SIGNED
/// payload of an [`KIND_OVERLAY_ENROLL`] invitation or an [`KIND_OVERLAY_MEMBER`] credential. The set
/// is CLOSED: a token whose `br_ovrole` is any other value is rejected on verify (fail-closed), so a
/// corrupt/unknown role never degrades to a weaker-but-accepted one.
const CLAIM_OVERLAY_ROLE: &str = "br_ovrole";

/// Bounds on the opaque app-context (R6): a capability may carry at most this many entries, and its
/// keys+values may total at most this many bytes. Enforced at mint so a guest can't inflate a token.
const MAX_APP_CONTEXT_ENTRIES: usize = 16;
const MAX_APP_CONTEXT_BYTES: usize = 4096;

/// Tight bound on the sealed `br_persona` value (bytes). A persona is a single RBAC role name (an
/// enum on the trusting app's side, e.g. `Integration`/`Staff`), so a small cap suffices; a value
/// longer than this on a verified envelope is treated as corrupt/hostile and dropped (persona
/// `None`), never truncated (a truncated role could match a different role). Enforced at BOTH mint
/// (refuse) and verify (drop) — defense in depth, mirroring the app-context bounds.
const MAX_PERSONA_LEN: usize = 128;

/// Token kind: an RBAC role-bearing control-plane token (the `/api/*` bearer).
pub const KIND_ROLE: &str = "role";
/// Token kind: a single-use mesh join token.
pub const KIND_JOIN: &str = "join";
/// Token kind: a mesh client-write capability.
pub const KIND_CLUSTER_WRITE: &str = "cluster-write";
/// Token kind: a delegation (attenuation) block within a presented chain.
pub const KIND_DELEGATION: &str = "delegation";
/// Token kind: a bootstrap-TLS identity attestation — the root key vouching that
/// a given control-plane RPK TLS public key is this fleet's (`--tls rpk`).
pub const KIND_BOOTSTRAP_TLS: &str = "bootstrap-tls";
/// Token kind: a **per-request proof-of-possession** (DPoP-style), signed by a
/// token's holder (`cnf`) key to bind one request to that holder — so a leaked
/// bearer token alone can't be replayed.
pub const KIND_POP: &str = "pop";
/// Token kind: a **cluster mesh-member assertion** — the root key vouching that a
/// given mesh public key (`br_pubkey`) belongs to node `br_node` of this cluster.
/// A joiner adopts each returned member into its trust set only after verifying
/// this against the root anchor, so a malicious seed cannot inject a fabricated
/// member (dynamic-join trust bootstrap; see PLAN-cluster-join F3).
pub const KIND_MESH_MEMBER: &str = "mesh-member";
/// Token kind: a host-issued **anonymous session cookie** (R3, PLAN-tenancy-principal). Binds a
/// CSPRNG session id (`br_sid`) with `iat`/`exp`, signed by the fleet's `Signer` trust root — no app
/// JWKS, no JS. Verified (signature + expiry) at each resolution; a client-forged/unsigned `sid`
/// fails verification. Isolation is structural (the `Session` scope-fact binds a disjoint column),
/// so the cookie only ever names the actor's own anonymous rows.
pub const KIND_SESSION: &str = "session";
/// Token kind: a host-issued **durable signed-context** envelope (R1, PLAN-tenancy-principal D6) —
/// the producer's resolved own-tenant fact, stamped by the host onto a durable message / cron
/// materialization / async invoke so the async lane (which has no inbound request) still resolves a
/// verified "own" tenant. Signed by the fleet `Signer`; verified (signature + expiry + kind) when
/// the consumer/drain resolves it. Guest-blind: the guest never names the tenant — the host stamps
/// it from the producer's principal, and a forged/absent envelope fails closed.
pub const KIND_CONTEXT: &str = "context";
/// The one accepted value of [`CLAIM_SCOPE_KIND`]: a SYSTEM (no-tenant) principal. Any other value of
/// the scope-kind claim is rejected (fail-closed — an unknown/typo'd kind never degrades to a tenant
/// seal). A tenant seal omits the claim altogether.
const SCOPE_KIND_SYSTEM: &str = "system";
/// Token kind: a host-signed **target capability** envelope (R4/D8 5c, PLAN-tenancy-principal) — the
/// AUTHENTICATED target source. Names a SECOND tenant `B` (`br_ctx`) and the public subset it grants
/// (`br_pub`), scoped to an `aud`ience (the project permitted to redeem it) with `iat`/`exp`/`cti`,
/// signed by the fleet `Signer`. A caller presenting it (as a bearer) resolves a target scope for
/// `B`, exactly like the routed-domain source, but proven by signature rather than by the terminating
/// domain — so an off-domain / API caller can be granted read (or, with the route's write grant,
/// write) access to `B`'s public subset. Verified (signature + expiry + kind + audience) at bind; a
/// forged/expired/wrong-audience envelope fails closed. Distinct from `handle` (which is read-only,
/// unauthenticated, and world-public only).
pub const KIND_CAPABILITY: &str = "capability";
/// Token kind: a host-issued **S3-ingress session token** (PLAN-blob-s3-ingress). It IS the
/// `session_token` of a temporary S3 credential: a `COSE_Sign1` CWT carrying the FULL host-stamped
/// upload scope (`br_s3` — project/site/container, the single key or prefix, the permitted S3
/// operations, and the enforced constraints), a **mandatory** `exp`, and a `cti`. Signed by the fleet
/// `Signer` trust root and client-opaque; the local S3 face verifies it (signature + expiry + kind)
/// on every request and authorizes the concrete PUT/multipart call against the carried scope — the
/// scope is NEVER taken from the URL or a client header, so cross-container/cross-project access is
/// structurally impossible. **Domain-separated**: it can never be redeemed as a role/capability/
/// context/session token, and none of those can be redeemed as an S3 session (the `br_kind` check is
/// exact on both mint and verify).
pub const KIND_S3_SESSION: &str = "s3-session";
/// Token kind: an **overlay-dial capability** (boatramp overlay fabric) — a holder-key-bound,
/// offline-verifiable CWT authorizing the holder identity to dial a scoped in-cluster service over
/// the overlay. A relay/egress verifies it (signature + expiry + `br_kind == "overlay-dial"`) and
/// checks `cnf` against the dialing peer's TLS/E2EE-proven identity, with NO control-plane
/// round-trip. Domain-separated: the exact `br_kind` check means it can never be redeemed as any
/// other token kind, nor they as it.
pub const KIND_OVERLAY_DIAL: &str = "overlay-dial";
/// Token kind: an **overlay-publish capability** (boatramp overlay fabric) — the structural mirror of
/// [`KIND_OVERLAY_DIAL`] for the reverse-ingress (`boatramp expose`) direction. A holder-key-bound,
/// offline-verifiable CWT authorizing the holder identity to PUBLISH a local service into the cluster
/// overlay under an exact service name (`br_ovscope`), so a cluster-side `boatramp forward` reaches
/// it. A relay verifies it (signature + expiry + `br_kind == "overlay-publish"`) and binds `cnf` to
/// the registering exposer's E2EE-proven identity AT REGISTRATION — the exposer is terminal, so the
/// relay is the holder-binding authority (there is no downstream party to defer to). Domain-separated:
/// the exact `br_kind` check means an overlay-dial capability can never be redeemed to publish, nor an
/// overlay-publish capability to dial.
pub const KIND_OVERLAY_PUBLISH: &str = "overlay-publish";
/// Token kind: an **overlay enrollment invitation** (boatramp overlay fabric, enrollment & pairing) —
/// a single-use, root-signed `COSE_Sign1` CWT that invites a NOT-YET-KNOWN member key into the
/// overlay with a declared role (`br_ovrole`) and service scope (`br_ovscope`). It is the exact
/// structural analogue of the cluster [`KIND_JOIN`] token: TTL'd via a **mandatory** `exp`, spent
/// single-use via its `cti`/`jti`, and — deliberately — **NOT** holder-bound (no `cnf`), because the
/// enrollee's overlay key is unknown at mint time (contrast [`KIND_OVERLAY_DIAL`], which IS `cnf`-
/// bound). At redemption the enrollee presents its overlay key AND a possession proof (an Ed25519
/// signature over [`join_challenge`] naming this `jti` + that key), exactly as a cluster joiner does,
/// so a token alone (without the overlay private key) enrolls nothing. Domain-separated: the exact
/// `br_kind` check means an enroll invitation can never be redeemed as a join / dial / publish /
/// member token, nor any of those as an enroll invitation.
pub const KIND_OVERLAY_ENROLL: &str = "overlay-enroll";
/// Token kind: an **overlay membership credential** (boatramp overlay fabric, enrollment & pairing) —
/// the root key vouching, offline-verifiably, that a given overlay key (`br_pubkey`) is an ENROLLED
/// member with role `br_ovrole` and scope `br_ovscope`. It is the exact structural analogue of the
/// cluster [`KIND_MESH_MEMBER`] assertion: a joiner adopts the vouched key into its trust set only
/// after verifying this against the root anchor (signature + `exp` + `br_kind == "overlay-member"`),
/// so a malicious seed cannot inject a fabricated member. Unlike a dial/publish capability it is NOT
/// `cnf`-bound (it is a third-party-verifiable statement ABOUT a key, not a per-request possession
/// capability the holder proves); the member's key is the VOUCHED `br_pubkey`. Domain-separated by the
/// exact `br_kind` check from every other token kind.
pub const KIND_OVERLAY_MEMBER: &str = "overlay-member";

/// PoP claim: the bound HTTP method (upper-case).
const CLAIM_HTM: &str = "htm";
/// PoP claim: the bound request path (canonicalized; not the full URL — the host
/// is not trustworthy behind a proxy, so the *origin* is bound via `aud` instead).
const CLAIM_HTP: &str = "htp";
/// PoP claim: hex SHA-256 of the presented access token — binds the proof to that
/// specific token (a stolen proof can't be paired with a different token).
const CLAIM_ATH: &str = "ath";
/// PoP claim: hex SHA-256 of the request body — present on write requests with a
/// body (so a captured proof can't authorize a swapped payload).
const CLAIM_BH: &str = "bh";

/// How long a PoP proof stays fresh, in seconds. Tight on purpose: it bounds
/// replay without a (CAS-less, expensive) fleet-wide `jti` cache.
pub const POP_WINDOW_SECS: u64 = 60;
/// Clock skew tolerated for a proof minted slightly in the future, in seconds.
pub const POP_SKEW_SECS: u64 = 30;
/// The largest request body bound by a PoP `bh` hash. Both the client (which
/// signs) and the server (which buffers + verifies) key the body binding off
/// `body length ≤ this`, so they always agree on whether a proof carries a `bh`.
/// Control-plane payloads are far smaller; larger bodies (blob/tarball uploads)
/// stream through unbound (a documented gap — those carry their own content hash).
pub const POP_MAX_BODY_HASH_BYTES: usize = 1024 * 1024;

/// Text claim key for the holder key (the holder's public key `"<alg>:<hex>"`): the
/// key that may mint the next delegation block. Present only on a *delegatable*
/// token / block.
///
/// **RFC-8747 flag (U8–U10, #7):** the holder is carried as this bare private-use
/// *text* claim, NOT as a structured RFC-8747 `cnf` claim (CWT claim key 8, a map
/// whose member — `COSE_Key` / `kid` / `jwk` — states the confirmation method).
/// Moving to the RFC-8747 form would **change the wire bytes** of every delegatable
/// token (`mint_delegatable`, every `attenuate` block, every `cnf`-bound overlay
/// capability) and break verification of all existing boatramp tokens — so it is
/// **not changed here** (STOP-and-flag, per the task's compatibility rule). A
/// future migration is additive: mint both forms during an overlap, read the
/// RFC-8747 `cnf` first and fall back to this text claim, then retire the text
/// claim once all issuers/verifiers are upgraded (a release-gated wire change).
const CLAIM_CNF: &str = "br_cnf";
/// Text claim key for a delegation block's narrowing caveats (a CBOR map).
const CLAIM_CAVEATS: &str = "br_caveats";

/// Restrict-only caveats a delegation block adds. Every field can only *narrow*
/// the credential's authority; the chain walk intersects them (the tightest wins).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Caveats {
    /// Restrict to a single site: the request's target must equal this (which also
    /// denies non-site resources, whose target term is `*`).
    pub only_site: Option<String>,
    /// Restrict to read operations only.
    pub read_only: bool,
    /// Shorten the lifetime (folded into the effective `exp` during the walk).
    pub not_after: Option<u64>,
    /// Set when two blocks pin *different* `only_site`s — an empty intersection
    /// that authorizes nothing (checked in [`Caveats::allows`]).
    impossible: bool,
}

impl Caveats {
    /// Build a caveat set from the restrict-only fields (the `impossible` flag is
    /// derived only during the chain walk, so it starts clear).
    pub fn restrict(only_site: Option<String>, read_only: bool, not_after: Option<u64>) -> Self {
        Self {
            only_site,
            read_only,
            not_after,
            impossible: false,
        }
    }

    /// Whether these caveats restrict anything.
    pub fn is_empty(&self) -> bool {
        self.only_site.is_none() && !self.read_only && self.not_after.is_none() && !self.impossible
    }

    /// Tighten `self` by intersecting with `other` (the deeper block). Each field
    /// takes the more restrictive value; disjoint `only_site`s make it impossible.
    fn tighten(&mut self, other: &Self) {
        self.read_only |= other.read_only;
        self.impossible |= other.impossible;
        match (self.only_site.as_deref(), other.only_site.as_deref()) {
            (None, Some(s)) => self.only_site = Some(s.to_string()),
            (Some(a), Some(b)) if a != b => self.impossible = true,
            _ => {}
        }
        self.not_after = match (self.not_after, other.not_after) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, None) => a,
            (None, b) => b,
        };
    }

    /// Whether these caveats permit `required` at `now_unix`. Applied *after* the
    /// role/Cedar decision — caveats can only subtract. `not_after` is enforced via
    /// the effective `exp`, so it is not re-checked here.
    pub fn allows(&self, required: &crate::authz::Right, _now_unix: u64) -> bool {
        if self.impossible {
            return false;
        }
        if self.read_only && required.action != crate::authz::Action::Read {
            return false;
        }
        if let Some(site) = &self.only_site
            && required.target_term() != site
        {
            return false;
        }
        true
    }
}

/// boatramp's [`Caveats`] is the first [`NarrowingCaveats`] impl: the engine drives
/// the delegation chain-walk over it, and — crucially — the engine VERIFIES that
/// [`meet`](NarrowingCaveats::meet) only narrows (see
/// [`is_narrower_or_equal`](NarrowingCaveats::is_narrower_or_equal)). boatramp's
/// `meet` is the existing [`tighten`](Caveats::tighten) intersection (a true
/// greatest-lower-bound), so the engine's monotonicity check is always satisfied
/// here and the mint/verify behavior is byte-for-byte unchanged.
impl NarrowingCaveats for Caveats {
    const KIND_CLAIM: &'static str = CLAIM_KIND;
    const CNF_CLAIM: &'static str = CLAIM_CNF;
    const CAVEATS_CLAIM: &'static str = CLAIM_CAVEATS;
    const DELEGATION_KIND: &'static str = KIND_DELEGATION;

    /// Greatest-lower-bound = the existing restrict-only [`tighten`](Self::tighten)
    /// intersection (the tightest field wins; disjoint `only_site`s → impossible).
    fn meet(&self, deeper: &Self) -> Self {
        let mut out = self.clone();
        out.tighten(deeper);
        out
    }

    /// `self ⊑ other`: `self`'s permitted set ⊆ `other`'s (self restricts at least
    /// as much). `impossible` is the lattice bottom (narrowest). Consistent with
    /// [`meet`](Self::meet): `self.meet(b)` is always `⊑` both `self` and `b`, so
    /// the engine's narrowing check never trips for a faithful boatramp chain.
    fn is_narrower_or_equal(&self, other: &Self) -> bool {
        if self.impossible {
            return true; // bottom ⊑ everything
        }
        if other.impossible {
            return false; // only bottom ⊑ bottom
        }
        // read_only: if `other` forbids writes, `self` must too.
        if other.read_only && !self.read_only {
            return false;
        }
        // only_site: `self`'s allowed-site set ⊆ `other`'s.
        match (self.only_site.as_deref(), other.only_site.as_deref()) {
            (_, None) => {}                    // other allows any site
            (Some(s), Some(o)) if s == o => {} // same single site
            (_, Some(_)) => return false,      // other pins a site self doesn't match
        }
        // not_after: `self` must bound the lifetime at least as tightly (sooner).
        match (self.not_after, other.not_after) {
            (_, None) => {}                    // other has no bound
            (Some(s), Some(o)) if s <= o => {} // self sooner-or-equal
            (_, Some(_)) => return false,      // self later / unbounded vs other's bound
        }
        true
    }

    /// Encode as a CBOR map with only the present fields.
    fn to_cbor(&self) -> CborValue {
        let mut map = Vec::new();
        if let Some(site) = &self.only_site {
            map.push((
                CborValue::Text("only_site".into()),
                CborValue::Text(site.clone()),
            ));
        }
        if self.read_only {
            map.push((CborValue::Text("read_only".into()), CborValue::Bool(true)));
        }
        if let Some(na) = self.not_after {
            map.push((
                CborValue::Text("not_after".into()),
                CborValue::Integer(na.into()),
            ));
        }
        CborValue::Map(map)
    }

    /// Decode from the CBOR produced by [`to_cbor`](NarrowingCaveats::to_cbor).
    /// **Fallible (U8–U10, #3):** an unknown restriction key — or a known key with
    /// the wrong CBOR type — **refuses** the token with a reason, fail-closed,
    /// rather than silently dropping a narrowing the verifier can't interpret
    /// (which could *widen* authority). Never panics on a hostile token.
    fn from_cbor(value: &CborValue) -> Result<Self, TokenError> {
        let mut caveats = Self::default();
        let CborValue::Map(entries) = value else {
            return Err(TokenError::Claims("caveats must be a CBOR map".into()));
        };
        for (k, v) in entries {
            let CborValue::Text(key) = k else {
                return Err(TokenError::Claims("caveat key must be text".into()));
            };
            match key.as_str() {
                "only_site" => match v {
                    CborValue::Text(s) => caveats.only_site = Some(s.clone()),
                    _ => return Err(TokenError::Claims("only_site caveat must be text".into())),
                },
                "read_only" => match v {
                    CborValue::Bool(b) => caveats.read_only = *b,
                    _ => return Err(TokenError::Claims("read_only caveat must be a bool".into())),
                },
                "not_after" => match v {
                    CborValue::Integer(i) => {
                        caveats.not_after = Some(u64::try_from(*i).map_err(|_| {
                            TokenError::Claims("not_after caveat out of range".into())
                        })?);
                    }
                    _ => {
                        return Err(TokenError::Claims(
                            "not_after caveat must be an integer".into(),
                        ));
                    }
                },
                // An UNKNOWN restriction key is refused with a reason: a verifier that
                // cannot interpret a caveat must not silently honor the rest (it might
                // be a narrowing that would otherwise be dropped). Fail-closed.
                other => {
                    return Err(TokenError::Claims(format!(
                        "unknown caveat restriction {other:?}"
                    )));
                }
            }
        }
        Ok(caveats)
    }

    /// Fold `not_after` into the block's `exp` so the standard expiry check (min
    /// across the chain) enforces it.
    fn not_after(&self) -> Option<u64> {
        self.not_after
    }
}

/// The inputs to mint a token.
pub struct Claims {
    /// The granted roles carried by the token.
    pub roles: Vec<GrantedRole>,
    /// The token kind, for domain separation (`role` / `join` / `cluster-write`).
    pub kind: String,
    /// TTL in seconds from `now_unix`; `None` ⇒ no expiry.
    pub ttl_secs: Option<u64>,
    /// The issuing time (Unix seconds) — stamps `iat` and the `exp` base.
    pub now_unix: u64,
}

/// A verified token's claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    /// The granted roles (authority claims).
    pub roles: Vec<GrantedRole>,
    /// The token kind.
    pub kind: String,
    /// The revocation id (hex of `cti`) — looked up in the KV revocation store.
    pub cti: String,
    /// The expiry (Unix seconds), if any.
    pub exp: Option<u64>,
    /// The holder key `"<alg>:<hex>"` (RFC 8747 `cnf`), when this token is
    /// *delegatable* — the key allowed to mint the next chain block.
    pub cnf: Option<String>,
}

/// Mint a signed `COSE_Sign1` CWT for role `claims`, returning the base64url token.
pub async fn mint(claims: &Claims, signer: &dyn Signer) -> Result<String, TokenError> {
    mint_inner(claims, None, signer).await
}

/// Mint a **delegatable** role token: like [`mint`] but declaring a holder key
/// (`cnf`), so the holder can later mint narrowing delegation blocks off it.
/// The holder's private key stays with the holder (it may itself be an
/// HSM/KMS key); only its public half is embedded.
pub async fn mint_delegatable(
    claims: &Claims,
    holder: &TokenPublicKey,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    mint_inner(claims, Some(holder), signer).await
}

async fn mint_inner(
    claims: &Claims,
    holder: Option<&TokenPublicKey>,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    let mut builder = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(claims.now_unix as i64))
        .cwt_id(random_cti()?)
        .text_claim(CLAIM_ROLES.to_string(), roles_to_cbor(&claims.roles))
        .text_claim(CLAIM_KIND.to_string(), CborValue::Text(claims.kind.clone()));
    if let Some(holder) = holder {
        builder = builder.text_claim(CLAIM_CNF.to_string(), CborValue::Text(holder.to_hex()));
    }
    if let Some(ttl) = claims.ttl_secs {
        builder = builder.expiration_time(Timestamp::WholeSeconds(
            claims.now_unix.saturating_add(ttl) as i64,
        ));
    }
    sign_claims(builder.build(), signer).await
}

/// Mint a **single-use bearer mesh join token**: a `COSE_Sign1` CWT with
/// `br_kind = "join"` (domain separation from role tokens), a short TTL (`exp`),
/// and a single-use handle (`cti` = `jti`). It is **not** bound to a specific node
/// or key — the operator can't know a not-yet-booted node's mesh key. At redemption
/// the joiner presents its mesh pubkey **and a possession proof** (an Ed25519
/// signature over a challenge naming this `jti`), which the cluster verifies before
/// admitting; so a token alone (without the mesh private key) admits nothing, and
/// its `jti` is spent single-use. Minted where the root key lives; shown once.
pub async fn mint_join(
    ttl_secs: u64,
    now_unix: u64,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    let claims = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .expiration_time(Timestamp::WholeSeconds(
            now_unix.saturating_add(ttl_secs) as i64
        ))
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_JOIN.to_string()),
        )
        .build();
    sign_claims(claims, signer).await
}

/// Mint a **bootstrap-TLS identity attestation**: a `COSE_Sign1` CWT signed by
/// the root key binding a control-plane RPK TLS public key (`br_pubkey`, SPKI
/// hex) with `br_kind = "bootstrap-tls"` and a validity window (`iat`/`exp`). A
/// `--tls rpk` client that trusts only the root public key fetches this,
/// verifies the root signature + window, and pins the attested TLS key — so an
/// operator pins one anchor (the root key) for the whole fleet, and TLS-identity
/// rotation needs no client change (a fresh attestation is re-minted + re-served).
pub async fn mint_attestation(
    tls_pubkey_hex: &str,
    ttl_secs: u64,
    now_unix: u64,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    let claims = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .expiration_time(Timestamp::WholeSeconds(
            now_unix.saturating_add(ttl_secs) as i64
        ))
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_BOOTSTRAP_TLS.to_string()),
        )
        .text_claim(
            CLAIM_PUBKEY.to_string(),
            CborValue::Text(tls_pubkey_hex.to_string()),
        )
        .build();
    sign_claims(claims, signer).await
}

/// Verify a bootstrap-TLS attestation against the root `public` at `now_unix`:
/// signature + alg pin + TTL + `br_kind = "bootstrap-tls"`, returning the
/// attested control-plane TLS public key (SPKI hex). A role/join token presented
/// here is rejected on the kind check (domain separation).
pub fn verify_attestation(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<String, TokenError> {
    let claims = verify_envelope(token, public)?;
    check_exp(&claims, now_unix)?;
    let mut kind = String::new();
    let mut pubkey_hex: Option<String> = None;
    for (name, value) in &claims.rest {
        if let coset::cwt::ClaimName::Text(t) = name {
            match t.as_str() {
                CLAIM_KIND => {
                    if let CborValue::Text(k) = value {
                        kind = k.clone();
                    }
                }
                CLAIM_PUBKEY => {
                    if let CborValue::Text(k) = value {
                        pubkey_hex = Some(k.clone());
                    }
                }
                _ => {}
            }
        }
    }
    if kind != KIND_BOOTSTRAP_TLS {
        return Err(TokenError::Claims("not a bootstrap-tls attestation".into()));
    }
    pubkey_hex.ok_or_else(|| TokenError::Claims("attestation has no pubkey".into()))
}

/// A verified cluster mesh-member assertion: the root key's binding of a mesh
/// public key to a node id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberAssertion {
    /// The node id (label) the assertion vouches for.
    pub node_id: u64,
    /// The node's mesh public key (SPKI hex) — the identity a joiner adds to trust.
    pub pubkey_hex: String,
}

/// Mint a **cluster mesh-member assertion**: a `COSE_Sign1` CWT signed by the root
/// key binding `(node_id, mesh_pubkey)` with `br_kind = "mesh-member"` and a TTL.
/// The join response returns one per current member so a joiner can verify each
/// against the root anchor before trusting it — a malicious/stale seed cannot then
/// inject or fabricate a member (PLAN-cluster-join F3).
pub async fn mint_member_assertion(
    node_id: u64,
    mesh_pubkey_hex: &str,
    ttl_secs: u64,
    now_unix: u64,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    let claims = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .expiration_time(Timestamp::WholeSeconds(
            now_unix.saturating_add(ttl_secs) as i64
        ))
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_MESH_MEMBER.to_string()),
        )
        .text_claim(CLAIM_NODE.to_string(), CborValue::from(node_id))
        .text_claim(
            CLAIM_PUBKEY.to_string(),
            CborValue::Text(mesh_pubkey_hex.to_string()),
        )
        .build();
    sign_claims(claims, signer).await
}

/// Verify a mesh-member assertion against the root `public` at `now_unix`:
/// signature + alg pin + TTL + `br_kind = "mesh-member"`, returning the vouched
/// `(node_id, mesh_pubkey)`. A token of any other kind is rejected (domain
/// separation) — so a role/join/attestation token can't pose as a member.
pub fn verify_member_assertion(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<MemberAssertion, TokenError> {
    let claims = verify_envelope(token, public)?;
    check_exp(&claims, now_unix)?;
    let mut kind = String::new();
    let mut node_id: Option<u64> = None;
    let mut pubkey_hex: Option<String> = None;
    for (name, value) in &claims.rest {
        if let coset::cwt::ClaimName::Text(t) = name {
            match t.as_str() {
                CLAIM_KIND => {
                    if let CborValue::Text(k) = value {
                        kind = k.clone();
                    }
                }
                CLAIM_NODE => {
                    if let CborValue::Integer(i) = value {
                        node_id = u64::try_from(*i).ok();
                    }
                }
                CLAIM_PUBKEY => {
                    if let CborValue::Text(k) = value {
                        pubkey_hex = Some(k.clone());
                    }
                }
                _ => {}
            }
        }
    }
    if kind != KIND_MESH_MEMBER {
        return Err(TokenError::Claims("not a mesh-member assertion".into()));
    }
    Ok(MemberAssertion {
        node_id: node_id
            .ok_or_else(|| TokenError::Claims("member assertion has no node".into()))?,
        pubkey_hex: pubkey_hex
            .ok_or_else(|| TokenError::Claims("member assertion has no pubkey".into()))?,
    })
}

/// Verify a base64url `COSE_Sign1` CWT against `public` at `now_unix`: checks the
/// signature (algorithm pinned to `public`'s), then `exp`. Revocation is the
/// caller's job (look up `cti` in the KV store) — kept out of this IO-free fn.
pub fn verify(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<VerifiedToken, TokenError> {
    let claims = verify_envelope(token, public)?;
    let exp = check_exp(&claims, now_unix)?;
    let token = role_token(&claims, exp)?;
    // 8(b) — domain separation: `verify` is the ROLE path, so it accepts ONLY a
    // `br_kind == KIND_ROLE` token, symmetric with every sibling verifier (each
    // rejects on `br_kind != its own kind`). A join / session / s3-session /
    // overlay / cluster-write / capability / context token — or another
    // vocabulary's token — is refused here rather than returned for the caller to
    // re-check. A non-role token with its own role grants (e.g. a `cluster-write`
    // capability) has a dedicated kind-checked verifier ([`verify_cluster_write`]).
    if token.kind != KIND_ROLE {
        return Err(TokenError::Claims("not a role token".into()));
    }
    Ok(token)
}

/// Verify a **cluster-write capability** ([`KIND_CLUSTER_WRITE`]) against `public`
/// at `now_unix`: signature + alg pin + `exp` + an exact `br_kind` check, returning
/// its role set. The kind-checked sibling of [`verify`] for the mesh client-write
/// gate — so a `cluster-write` capability is verified as exactly that, and a role /
/// join / any-other-kind token presented in its place is rejected (domain
/// separation). The caller still checks the returned roles for `cluster-write`.
pub fn verify_cluster_write(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<VerifiedToken, TokenError> {
    let claims = verify_envelope(token, public)?;
    let exp = check_exp(&claims, now_unix)?;
    let token = role_token(&claims, exp)?;
    if token.kind != KIND_CLUSTER_WRITE {
        return Err(TokenError::Claims("not a cluster-write capability".into()));
    }
    Ok(token)
}

/// Assemble a [`VerifiedToken`] from an already-verified claim set (shared by
/// [`verify`] and the delegation chain root).
fn role_token(claims: &ClaimsSet, exp: Option<u64>) -> Result<VerifiedToken, TokenError> {
    let cti = claim_cti(claims)?;
    let mut roles = Vec::new();
    let mut kind = String::new();
    for (name, value) in &claims.rest {
        if let coset::cwt::ClaimName::Text(t) = name {
            match t.as_str() {
                CLAIM_ROLES => roles = cbor_to_roles(value),
                CLAIM_KIND => {
                    if let CborValue::Text(k) = value {
                        kind = k.clone();
                    }
                }
                _ => {}
            }
        }
    }
    Ok(VerifiedToken {
        roles,
        kind,
        cti,
        exp,
        cnf: claim_cnf(claims),
    })
}

/// Verify a base64url **bearer** mesh join token: signature + alg pin + TTL +
/// `br_kind = "join"`. Returns its single-use handle (`jti` = `cti`). IO-free: the
/// caller must still, at admission, (a) verify the joiner's **possession proof**
/// against the mesh key it presents ([`join_challenge`] + `verify_signature`) and
/// (b) reject a `jti` already recorded as spent or revoked. A role token presented
/// here is rejected on the kind check ([`TokenError::Claims`]).
pub fn verify_join(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<String, TokenError> {
    let claims = verify_envelope(token, public)?;
    let jti = claim_cti(&claims)?;
    check_exp(&claims, now_unix)?;
    let kind = claims
        .rest
        .iter()
        .find_map(|(name, value)| match (name, value) {
            (coset::cwt::ClaimName::Text(t), CborValue::Text(k)) if t == CLAIM_KIND => {
                Some(k.clone())
            }
            _ => None,
        });
    if kind.as_deref() != Some(KIND_JOIN) {
        return Err(TokenError::Claims("not a mesh join token".into()));
    }
    Ok(jti)
}

/// Mint a host-issued **anonymous session cookie** (R3): a `COSE_Sign1` CWT with
/// `br_kind = "session"`, the CSPRNG `sid` bound in the signed payload (`br_sid`), `iat = now`, and
/// `exp = now + ttl_secs`. Signed by the fleet `Signer` trust root — no app JWKS. The returned
/// base64url string is the cookie value (`HttpOnly; Secure; SameSite=Lax` set by the serving path).
/// Verified with [`verify_session`]; a client-forged/unsigned `sid` never verifies.
pub async fn mint_session(
    sid: &str,
    ttl_secs: u64,
    now_unix: u64,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    let claims = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .expiration_time(Timestamp::WholeSeconds(
            now_unix.saturating_add(ttl_secs) as i64
        ))
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_SESSION.to_string()),
        )
        .text_claim(CLAIM_SID.to_string(), CborValue::Text(sid.to_string()))
        .build();
    sign_claims(claims, signer).await
}

/// Verify a host-issued session cookie against the fleet public key at `now_unix`: checks the COSE
/// signature, the expiry, and `br_kind == "session"`, then returns the bound `sid`. Any tampering
/// (a client-chosen `sid`, an altered/expired payload) fails closed — the caller then mints a fresh
/// cookie. Stateless: no server-side session table for the identity itself (isolation is structural
/// via the disjoint `Session` column, not a stored label).
pub fn verify_session(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<String, TokenError> {
    let claims = verify_envelope(token, public)?;
    check_exp(&claims, now_unix)?;
    let mut kind = None;
    let mut sid = None;
    for (name, value) in &claims.rest {
        if let (coset::cwt::ClaimName::Text(t), CborValue::Text(v)) = (name, value) {
            match t.as_str() {
                CLAIM_KIND => kind = Some(v.clone()),
                CLAIM_SID => sid = Some(v.clone()),
                _ => {}
            }
        }
    }
    if kind.as_deref() != Some(KIND_SESSION) {
        return Err(TokenError::Claims("not a session cookie".into()));
    }
    sid.ok_or_else(|| TokenError::Claims("session cookie has no sid".into()))
}

/// The verified contents of an overlay-dial capability ([`verify_overlay_dial`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOverlayDial {
    /// The holder key (`cnf`, `"<alg>:<hex>"`) the dialing peer must prove possession of — the
    /// caller checks it equals the peer's TLS/E2EE-proven overlay identity.
    pub holder: String,
    /// The dial scope this capability authorizes (a service/target, or `"*"`).
    pub scope: String,
}

/// Mint an **overlay-dial capability** (`br_kind = "overlay-dial"`): a holder-key-bound,
/// offline-verifiable `COSE_Sign1` CWT authorizing `holder` to dial `scope` over the overlay fabric,
/// signed by the fleet `Signer` trust root with `iat = now`, `exp = now + ttl_secs`, and a `cti`.
/// A relay/egress authorizes a dial from it with [`verify_overlay_dial`] plus a holder-key check
/// against the dialing peer's proven identity — no control-plane round-trip. The holder's private
/// key never leaves the holder; only its public half (`cnf`) is embedded.
pub async fn mint_overlay_dial(
    holder: &TokenPublicKey,
    scope: &str,
    ttl_secs: u64,
    now_unix: u64,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    let claims = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .expiration_time(Timestamp::WholeSeconds(
            now_unix.saturating_add(ttl_secs) as i64
        ))
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_OVERLAY_DIAL.to_string()),
        )
        .text_claim(CLAIM_CNF.to_string(), CborValue::Text(holder.to_hex()))
        .text_claim(
            CLAIM_OVERLAY_SCOPE.to_string(),
            CborValue::Text(scope.to_string()),
        )
        .build();
    sign_claims(claims, signer).await
}

/// Verify an overlay-dial capability against the fleet public key at `now_unix`: checks the COSE
/// signature, the expiry, and `br_kind == "overlay-dial"`, returning the bound holder key and
/// scope. Fail-closed: a forged/unsigned/expired/wrong-kind token never verifies. The caller MUST
/// additionally confirm the returned `holder` equals the dialing peer's proven identity (holder
/// binding) before honoring the dial.
pub fn verify_overlay_dial(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<VerifiedOverlayDial, TokenError> {
    let claims = verify_envelope(token, public)?;
    // An overlay-dial capability MUST be time-bounded (LOW-3): a token with no `exp` is refused
    // rather than treated as immortal — an unbounded dial capability is never acceptable.
    if check_exp(&claims, now_unix)?.is_none() {
        return Err(TokenError::Claims(
            "overlay-dial capability has no expiry".into(),
        ));
    }
    let mut kind = None;
    let mut holder = None;
    let mut scope = None;
    for (name, value) in &claims.rest {
        if let (coset::cwt::ClaimName::Text(t), CborValue::Text(v)) = (name, value) {
            match t.as_str() {
                CLAIM_KIND => kind = Some(v.clone()),
                CLAIM_CNF => holder = Some(v.clone()),
                CLAIM_OVERLAY_SCOPE => scope = Some(v.clone()),
                _ => {}
            }
        }
    }
    if kind.as_deref() != Some(KIND_OVERLAY_DIAL) {
        return Err(TokenError::Claims("not an overlay-dial capability".into()));
    }
    let holder =
        holder.ok_or_else(|| TokenError::Claims("overlay-dial capability has no holder".into()))?;
    let scope =
        scope.ok_or_else(|| TokenError::Claims("overlay-dial capability has no scope".into()))?;
    Ok(VerifiedOverlayDial { holder, scope })
}

/// The verified contents of an overlay-publish capability ([`verify_overlay_publish`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOverlayPublish {
    /// The holder key (`cnf`, `"<alg>:<hex>"`) the registering exposer must prove possession of — the
    /// relay checks it equals the exposer's E2EE-proven overlay identity AT REGISTRATION.
    pub holder: String,
    /// The EXACT service name this capability authorizes the holder to publish as (no wildcard — a
    /// publish capability names one concrete service). The relay enforces `scope == service`.
    pub scope: String,
    /// The capability's expiry (Unix seconds) — always present (an overlay-publish capability MUST be
    /// time-bounded). The relay uses it to bound a parked registration's lifetime.
    pub exp: u64,
}

/// Mint an **overlay-publish capability** (`br_kind = "overlay-publish"`): an exact structural mirror
/// of [`mint_overlay_dial`] for the reverse-ingress direction. A holder-key-bound, offline-verifiable
/// `COSE_Sign1` CWT authorizing `holder` to publish the local service `scope` into the overlay, signed
/// by the fleet `Signer` trust root with `iat = now`, `exp = now + ttl_secs`, and a `cti`. A relay
/// authorizes a registration from it with [`verify_overlay_publish`] plus a holder-key check against
/// the registering exposer's E2EE-proven identity — no control-plane round-trip. The holder's private
/// key never leaves the holder; only its public half (`cnf`) is embedded.
pub async fn mint_overlay_publish(
    holder: &TokenPublicKey,
    scope: &str,
    ttl_secs: u64,
    now_unix: u64,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    let claims = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .expiration_time(Timestamp::WholeSeconds(
            now_unix.saturating_add(ttl_secs) as i64
        ))
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_OVERLAY_PUBLISH.to_string()),
        )
        .text_claim(CLAIM_CNF.to_string(), CborValue::Text(holder.to_hex()))
        .text_claim(
            CLAIM_OVERLAY_SCOPE.to_string(),
            CborValue::Text(scope.to_string()),
        )
        .build();
    sign_claims(claims, signer).await
}

/// Verify an overlay-publish capability against the fleet public key at `now_unix`: checks the COSE
/// signature, the **mandatory** expiry, and `br_kind == "overlay-publish"`, returning the bound holder
/// key, scope, and expiry. Fail-closed: a forged/unsigned/expired/wrong-kind token never verifies, and
/// an overlay-DIAL token (or any other kind) presented here is rejected (domain separation). The caller
/// MUST additionally confirm the returned `holder` equals the registering exposer's E2EE-proven identity
/// (holder binding) and that `scope` equals the service being registered before honoring it.
pub fn verify_overlay_publish(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<VerifiedOverlayPublish, TokenError> {
    let claims = verify_envelope(token, public)?;
    // An overlay-publish capability MUST be time-bounded (as overlay-dial is): a token with no `exp`
    // is refused rather than treated as immortal — an unbounded publish capability is never acceptable.
    let exp = check_exp(&claims, now_unix)?
        .ok_or_else(|| TokenError::Claims("overlay-publish capability has no expiry".into()))?;
    let mut kind = None;
    let mut holder = None;
    let mut scope = None;
    for (name, value) in &claims.rest {
        if let (coset::cwt::ClaimName::Text(t), CborValue::Text(v)) = (name, value) {
            match t.as_str() {
                CLAIM_KIND => kind = Some(v.clone()),
                CLAIM_CNF => holder = Some(v.clone()),
                CLAIM_OVERLAY_SCOPE => scope = Some(v.clone()),
                _ => {}
            }
        }
    }
    if kind.as_deref() != Some(KIND_OVERLAY_PUBLISH) {
        return Err(TokenError::Claims(
            "not an overlay-publish capability".into(),
        ));
    }
    let holder = holder
        .ok_or_else(|| TokenError::Claims("overlay-publish capability has no holder".into()))?;
    let scope = scope
        .ok_or_else(|| TokenError::Claims("overlay-publish capability has no scope".into()))?;
    Ok(VerifiedOverlayPublish { holder, scope, exp })
}

/// Token kind: an **overlay-pairing-park capability** (overlay pairing PARK per-relay operator
/// config) — the structural mirror of [`KIND_OVERLAY_PUBLISH`] for the AUTHENTICATED pairing-park
/// mode: a relay operator may choose to require a parking accepter to present one of these and prove
/// possession, exactly as `register_exposer` requires an overlay-publish capability. A relay in OPEN
/// mode (the default) never checks for one. Unlike an overlay-publish capability this carries no
/// `scope` (a pairing park authorizes the holder to park, full stop — there is no service name to
/// bind it to); only the holder-binding carries over. The exact `br_kind` check means an
/// overlay-publish/-dial/any other capability can never be redeemed as a pairing-park capability, nor
/// the reverse.
pub const KIND_OVERLAY_PAIRING_PARK: &str = "overlay-pairing-park";

/// The verified contents of an overlay-pairing-park capability ([`verify_overlay_pairing_park`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOverlayPairingPark {
    /// The holder key (`cnf`, `"<alg>:<hex>"`) the parking accepter must prove possession of — the
    /// relay checks it equals the accepter's E2EE-proven overlay identity AT PARK TIME, exactly the
    /// holder-binding [`verify_overlay_publish`]'s caller applies at registration.
    pub holder: String,
    /// The capability's expiry (Unix seconds) — always present (an overlay-pairing-park capability
    /// MUST be time-bounded, like every other overlay capability).
    pub exp: u64,
}

/// Mint an **overlay-pairing-park capability** (`br_kind = "overlay-pairing-park"`): a holder-key-
/// bound, offline-verifiable `COSE_Sign1` CWT authorizing `holder` — the pairing ACCEPTER's overlay
/// identity — to PARK a rendezvous at a relay whose operator has opted into AUTHENTICATED pairing-park
/// (the owner's per-relay choice; OPEN mode, the default, never checks this), signed by the fleet
/// `Signer` trust root with `iat = now`, `exp = now + ttl_secs`, and a `cti`. A relay in authenticated
/// mode authorizes a park from it with [`verify_overlay_pairing_park`] plus a holder-key check against
/// the parking peer's E2EE-proven identity — no control-plane round-trip, mirroring
/// [`mint_overlay_publish`]/`register_exposer`. The holder's private key never leaves the holder; only
/// its public half (`cnf`) is embedded.
pub async fn mint_overlay_pairing_park(
    holder: &TokenPublicKey,
    ttl_secs: u64,
    now_unix: u64,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    let claims = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .expiration_time(Timestamp::WholeSeconds(
            now_unix.saturating_add(ttl_secs) as i64
        ))
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_OVERLAY_PAIRING_PARK.to_string()),
        )
        .text_claim(CLAIM_CNF.to_string(), CborValue::Text(holder.to_hex()))
        .build();
    sign_claims(claims, signer).await
}

/// Verify an overlay-pairing-park capability against the fleet public key at `now_unix`: checks the
/// COSE signature, the **mandatory** expiry, and `br_kind == "overlay-pairing-park"`, returning the
/// bound holder key + expiry. Fail-closed: a forged/unsigned/expired/wrong-kind token never verifies,
/// and an overlay-publish/-dial/any other kind presented here is rejected (domain separation). The
/// caller MUST additionally confirm the returned `holder` equals the parking peer's E2EE-proven
/// identity (holder binding) before honoring the park — exactly as `register_exposer` does for an
/// overlay-publish capability.
pub fn verify_overlay_pairing_park(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<VerifiedOverlayPairingPark, TokenError> {
    let claims = verify_envelope(token, public)?;
    // An overlay-pairing-park capability MUST be time-bounded (as publish/dial are): a token with no
    // `exp` is refused rather than treated as immortal.
    let exp = check_exp(&claims, now_unix)?.ok_or_else(|| {
        TokenError::Claims("overlay-pairing-park capability has no expiry".into())
    })?;
    let mut kind = None;
    let mut holder = None;
    for (name, value) in &claims.rest {
        if let (coset::cwt::ClaimName::Text(t), CborValue::Text(v)) = (name, value) {
            match t.as_str() {
                CLAIM_KIND => kind = Some(v.clone()),
                CLAIM_CNF => holder = Some(v.clone()),
                _ => {}
            }
        }
    }
    if kind.as_deref() != Some(KIND_OVERLAY_PAIRING_PARK) {
        return Err(TokenError::Claims(
            "not an overlay-pairing-park capability".into(),
        ));
    }
    let holder = holder.ok_or_else(|| {
        TokenError::Claims("overlay-pairing-park capability has no holder".into())
    })?;
    Ok(VerifiedOverlayPairingPark { holder, exp })
}

/// A member's role in the boatramp overlay fabric — a **closed** scalar set carried by both an
/// enrollment invitation ([`KIND_OVERLAY_ENROLL`]) and a membership credential ([`KIND_OVERLAY_MEMBER`]).
/// Representing it as an enum (rather than a bare string) makes an invalid role unrepresentable at mint
/// and lets verify reject an unknown/typo'd value fail-closed — a corrupt role never degrades to a
/// weaker-but-accepted one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayMemberRole {
    /// A full overlay node (relay/egress-capable peer).
    Node,
    /// An end-user device (laptop/phone paired into the overlay).
    Device,
    /// A workload/service identity enrolled into the overlay.
    Workload,
}

impl OverlayMemberRole {
    /// The wire string stored in `br_ovrole` (stable; part of the signed payload).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Device => "device",
            Self::Workload => "workload",
        }
    }

    /// Parse the `br_ovrole` wire string; `None` for any value outside the closed set (the verifier
    /// turns that into a fail-closed [`TokenError::Claims`]).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "node" => Some(Self::Node),
            "device" => Some(Self::Device),
            "workload" => Some(Self::Workload),
            _ => None,
        }
    }
}

/// The verified contents of an overlay enrollment invitation ([`verify_overlay_enroll`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOverlayEnroll {
    /// The single-use handle (`jti` = `cti`, hex): the control plane spends it once, so a replayed
    /// invitation enrolls nothing. Mirrors [`verify_join`]'s returned `jti`.
    pub jti: String,
    /// The role this invitation grants the enrollee once redeemed.
    pub role: OverlayMemberRole,
    /// The service scope the enrollee may dial/expose once enrolled (`"*"` = any within the issuer's
    /// authority).
    pub scope: String,
    /// The invitation's expiry (Unix seconds) — always present (an enrollment invitation MUST be
    /// time-bounded, like the cluster join token and the overlay-dial capability).
    pub exp: u64,
}

/// Mint an **overlay enrollment invitation** (`br_kind = "overlay-enroll"`): a single-use, root-signed
/// `COSE_Sign1` CWT inviting a not-yet-known member key into the overlay with `role` + `scope`, a
/// **mandatory** `exp` (`now + ttl_secs`), and a single-use `cti`/`jti`. Modeled exactly on
/// [`mint_join`]: it is **not** holder-bound (no `cnf`) because the enrollee's overlay key is unknown
/// at mint time — at redemption the enrollee presents its key plus a possession proof over
/// [`join_challenge`] naming this `jti`. Minted where the root key lives; shown once.
pub async fn mint_overlay_enroll(
    role: OverlayMemberRole,
    scope: &str,
    ttl_secs: u64,
    now_unix: u64,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    let claims = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .expiration_time(Timestamp::WholeSeconds(
            now_unix.saturating_add(ttl_secs) as i64
        ))
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_OVERLAY_ENROLL.to_string()),
        )
        .text_claim(
            CLAIM_OVERLAY_ROLE.to_string(),
            CborValue::Text(role.as_str().to_string()),
        )
        .text_claim(
            CLAIM_OVERLAY_SCOPE.to_string(),
            CborValue::Text(scope.to_string()),
        )
        .build();
    sign_claims(claims, signer).await
}

/// Verify an overlay enrollment invitation against the fleet public key at `now_unix`: checks the COSE
/// signature, the **mandatory** expiry, `br_kind == "overlay-enroll"`, and a role in the closed
/// [`OverlayMemberRole`] set, returning the single-use `jti`, role, scope, and expiry. Fail-closed: a
/// forged/unsigned/expired/wrong-kind/unknown-role token never verifies, and a join / dial / publish /
/// member token presented here is rejected on the kind check (domain separation). IO-free: the caller
/// must still spend the `jti` single-use and verify the enrollee's possession proof
/// ([`join_challenge`] + [`TokenPublicKey::verify`]) at admission.
pub fn verify_overlay_enroll(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<VerifiedOverlayEnroll, TokenError> {
    let claims = verify_envelope(token, public)?;
    let jti = claim_cti(&claims)?;
    // An enrollment invitation MUST be time-bounded (as the join token and overlay capabilities are):
    // a token with no `exp` is refused rather than treated as immortal.
    let exp = check_exp(&claims, now_unix)?
        .ok_or_else(|| TokenError::Claims("overlay-enroll invitation has no expiry".into()))?;
    let mut kind = None;
    let mut role = None;
    let mut scope = None;
    for (name, value) in &claims.rest {
        if let (coset::cwt::ClaimName::Text(t), CborValue::Text(v)) = (name, value) {
            match t.as_str() {
                CLAIM_KIND => kind = Some(v.clone()),
                CLAIM_OVERLAY_ROLE => role = Some(v.clone()),
                CLAIM_OVERLAY_SCOPE => scope = Some(v.clone()),
                _ => {}
            }
        }
    }
    if kind.as_deref() != Some(KIND_OVERLAY_ENROLL) {
        return Err(TokenError::Claims(
            "not an overlay-enroll invitation".into(),
        ));
    }
    let role = role
        .ok_or_else(|| TokenError::Claims("overlay-enroll invitation has no role".into()))
        .and_then(|r| {
            OverlayMemberRole::parse(&r).ok_or_else(|| {
                TokenError::Claims("overlay-enroll invitation has an unknown role".into())
            })
        })?;
    let scope =
        scope.ok_or_else(|| TokenError::Claims("overlay-enroll invitation has no scope".into()))?;
    Ok(VerifiedOverlayEnroll {
        jti,
        role,
        scope,
        exp,
    })
}

/// The verified contents of an overlay membership credential ([`verify_overlay_member`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOverlayMember {
    /// The member's overlay key (`"<alg>:<hex>"`, from `br_pubkey`) the trust anchor vouches is an
    /// enrolled member — a joiner compares it to the peer's TLS/E2EE-proven identity before trusting.
    pub member_key: String,
    /// The role the trust anchor vouches this member holds.
    pub role: OverlayMemberRole,
    /// The service scope this member is enrolled for.
    pub scope: String,
    /// The credential's expiry (Unix seconds) — always present (a membership credential MUST be
    /// time-bounded).
    pub exp: u64,
}

/// Mint an **overlay membership credential** (`br_kind = "overlay-member"`): a root-signed `COSE_Sign1`
/// CWT vouching that `member`'s overlay key is an enrolled member with `role` + `scope`, with a
/// **mandatory** `exp` (`now + ttl_secs`) and a `cti`. Modeled exactly on [`mint_member_assertion`]:
/// the member's key is carried as the VOUCHED `br_pubkey` (NOT a `cnf` possession binding — this is a
/// third-party-verifiable statement about a key). A joiner adopts the vouched key only after verifying
/// this against the root anchor with [`verify_overlay_member`]. The member's private key never leaves
/// the member; only its public half is embedded.
pub async fn mint_overlay_member(
    member: &TokenPublicKey,
    role: OverlayMemberRole,
    scope: &str,
    ttl_secs: u64,
    now_unix: u64,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    let claims = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .expiration_time(Timestamp::WholeSeconds(
            now_unix.saturating_add(ttl_secs) as i64
        ))
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_OVERLAY_MEMBER.to_string()),
        )
        .text_claim(CLAIM_PUBKEY.to_string(), CborValue::Text(member.to_hex()))
        .text_claim(
            CLAIM_OVERLAY_ROLE.to_string(),
            CborValue::Text(role.as_str().to_string()),
        )
        .text_claim(
            CLAIM_OVERLAY_SCOPE.to_string(),
            CborValue::Text(scope.to_string()),
        )
        .build();
    sign_claims(claims, signer).await
}

/// Verify an overlay membership credential against the fleet public key at `now_unix`: checks the COSE
/// signature, the **mandatory** expiry, `br_kind == "overlay-member"`, and a role in the closed
/// [`OverlayMemberRole`] set, returning the vouched member key, role, scope, and expiry. Fail-closed:
/// a forged/unsigned/expired/wrong-kind/unknown-role token never verifies, and a token of any other
/// kind (join / dial / publish / enroll / mesh-member) presented here is rejected (domain separation).
pub fn verify_overlay_member(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<VerifiedOverlayMember, TokenError> {
    let claims = verify_envelope(token, public)?;
    let exp = check_exp(&claims, now_unix)?
        .ok_or_else(|| TokenError::Claims("overlay-member credential has no expiry".into()))?;
    let mut kind = None;
    let mut member_key = None;
    let mut role = None;
    let mut scope = None;
    for (name, value) in &claims.rest {
        if let (coset::cwt::ClaimName::Text(t), CborValue::Text(v)) = (name, value) {
            match t.as_str() {
                CLAIM_KIND => kind = Some(v.clone()),
                CLAIM_PUBKEY => member_key = Some(v.clone()),
                CLAIM_OVERLAY_ROLE => role = Some(v.clone()),
                CLAIM_OVERLAY_SCOPE => scope = Some(v.clone()),
                _ => {}
            }
        }
    }
    if kind.as_deref() != Some(KIND_OVERLAY_MEMBER) {
        return Err(TokenError::Claims(
            "not an overlay-member credential".into(),
        ));
    }
    let member_key = member_key
        .ok_or_else(|| TokenError::Claims("overlay-member credential has no member key".into()))?;
    let role = role
        .ok_or_else(|| TokenError::Claims("overlay-member credential has no role".into()))
        .and_then(|r| {
            OverlayMemberRole::parse(&r).ok_or_else(|| {
                TokenError::Claims("overlay-member credential has an unknown role".into())
            })
        })?;
    let scope =
        scope.ok_or_else(|| TokenError::Claims("overlay-member credential has no scope".into()))?;
    Ok(VerifiedOverlayMember {
        member_key,
        role,
        scope,
        exp,
    })
}

/// The fully-verified contents of a durable signed-context envelope (R1 + async-lane persona,
/// PLAN-async-persona): the host-sealed own-tenant AND (optionally) the host-verified caller persona,
/// both bound to the SAME `COSE_Sign1` signature/expiry. Returned by [`verify_context_full`]; the
/// tenant-only [`verify_context`] projects out just [`VerifiedContext::tenant`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContext {
    /// The principal CLASS this seal carries (a `cron-system-principal` request): `Tenant` for an
    /// ordinary own-tenant seal (`br_ctx` present, no scope-kind claim), `System` for a no-tenant
    /// platform/super-admin seal (a positive `br_scope_kind=system` claim, no `br_ctx`). The class is
    /// signature-bound and recognised ONLY by the positive marker — never by a missing tenant.
    pub kind: crate::tenancy::PrincipalKind,
    /// The producer's host-sealed own-tenant (`br_ctx`). `Some` for a `Tenant` seal (the value every
    /// existing caller reads); **`None` for a `System` seal** (a system principal has no tenant). The
    /// tenant-only [`verify_context`] maps a `System` seal (tenant `None`) to an `Err`, so its 13
    /// callers' `.ok()` yields `None` and a `{tenant}`-templated bind-verify quarantines fail-closed.
    pub tenant: Option<String>,
    /// The producer bearer's host-verified persona/role (`br_persona`), sealed only when the operator
    /// configured `token_persona_claim` at seal time. `None` when no persona was sealed OR when the
    /// carried value was corrupt/oversized/non-text (dropped fail-closed — the async-lane `role(…)`
    /// guard then refuses, unchanged from before this feature). A single scalar, never a set.
    pub persona: Option<String>,
}

/// Mint a **durable signed-context** envelope (R1): a `COSE_Sign1` CWT with `br_kind = "context"`,
/// the producer's resolved own-tenant value bound as `br_ctx`, `iat = now`, `exp = now + ttl_secs`,
/// signed by the fleet `Signer`. The host stamps this onto a durable message / cron / async invoke
/// so the async lane resolves a verified "own" tenant. Verified with [`verify_context`]; a
/// forged/unsigned tenant never verifies (the guest never names the tenant — the host does).
///
/// When `persona` is `Some`, a single bounded `br_persona` text claim (the host-verified caller
/// role from the producer bearer's operator-configured `token_persona_claim`) is sealed into the
/// SAME claim set — bound to the same signature/expiry/tenant — for the async-lane `role(…)`
/// propagation (PLAN-async-persona). A value longer than [`MAX_PERSONA_LEN`] is refused at mint
/// (`TokenError::Claims`) rather than truncated. `None` seals no persona (unchanged for every
/// existing producer). Read back via [`verify_context_full`].
pub async fn mint_context(
    tenant: &str,
    persona: Option<&str>,
    ttl_secs: u64,
    now_unix: u64,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    let mut builder = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .expiration_time(Timestamp::WholeSeconds(
            now_unix.saturating_add(ttl_secs) as i64
        ))
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_CONTEXT.to_string()),
        )
        .text_claim(CLAIM_CTX.to_string(), CborValue::Text(tenant.to_string()));
    // A single, bounded persona value only. Refuse (never truncate) an over-length value — a
    // truncated role name could collide with a different role on the trusting side (Security C5).
    if let Some(persona) = persona {
        if persona.len() > MAX_PERSONA_LEN {
            return Err(TokenError::Claims(format!(
                "context persona exceeds {MAX_PERSONA_LEN} bytes"
            )));
        }
        builder = builder.text_claim(
            CLAIM_PERSONA.to_string(),
            CborValue::Text(persona.to_string()),
        );
    }
    sign_claims(builder.build(), signer).await
}

/// Mint a **SYSTEM** signed-context envelope (a `cron-system-principal` request): a `COSE_Sign1` CWT
/// with `br_kind = "context"` and a positive `br_scope_kind = "system"` claim, and — deliberately —
/// **no `br_ctx`** (a system principal has no tenant). Signed by the fleet `Signer`. The async lane
/// resolves this to a [`PrincipalKind::System`](crate::tenancy::PrincipalKind) principal (base/`IS
/// NULL`-only, `app.principal_kind='system'`), NOT a tenant. `persona` rides the SAME envelope exactly
/// as [`mint_context`]. The class is recognised ONLY by the signed `br_scope_kind` claim — so a
/// stripped/forged envelope cannot be promoted to system by merely lacking a tenant. Used ONLY where a
/// VERIFIED system source is established (a node-config cron, a `System·Admin` deploy capture, a
/// `system_when` token match on an exactly-named issuer); it is never reachable from guest input.
pub async fn mint_system_context(
    persona: Option<&str>,
    ttl_secs: u64,
    now_unix: u64,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    let mut builder = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .expiration_time(Timestamp::WholeSeconds(
            now_unix.saturating_add(ttl_secs) as i64
        ))
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_CONTEXT.to_string()),
        )
        .text_claim(
            CLAIM_SCOPE_KIND.to_string(),
            CborValue::Text(SCOPE_KIND_SYSTEM.to_string()),
        );
    if let Some(persona) = persona {
        if persona.len() > MAX_PERSONA_LEN {
            return Err(TokenError::Claims(format!(
                "context persona exceeds {MAX_PERSONA_LEN} bytes"
            )));
        }
        builder = builder.text_claim(
            CLAIM_PERSONA.to_string(),
            CborValue::Text(persona.to_string()),
        );
    }
    sign_claims(builder.build(), signer).await
}

/// Shared inner verify for a durable signed-context envelope: checks the COSE signature, the expiry,
/// and `br_kind == "context"`, then returns the carried tenant + (optionally) the bounded persona.
/// Both [`verify_context`] (tenant-only) and [`verify_context_full`] project from this so the
/// verify/expiry/kind checks are identical. The persona is read defensively — a single bounded text
/// claim, else dropped (never a panic on a hostile/corrupt token), mirroring `cbor_to_app_context`.
/// The active system-principal anti-hollow mutation (`BOATRAMP_SYSPRINCIPAL_MUTATION`), or `None`.
/// Present ONLY under `cfg(test)` or the `system-principal-gate-mutation` feature; a shipped build has
/// neither, so [`verify_context_inner`] recognizes System ONLY by the positive signed marker and this
/// is a dead `None`.
#[cfg(any(test, feature = "system-principal-gate-mutation"))]
fn sysseal_mutation() -> Option<String> {
    std::env::var("BOATRAMP_SYSPRINCIPAL_MUTATION").ok()
}
#[cfg(not(any(test, feature = "system-principal-gate-mutation")))]
#[inline]
fn sysseal_mutation() -> Option<String> {
    None
}

fn verify_context_inner(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<VerifiedContext, TokenError> {
    let claims = verify_envelope(token, public)?;
    check_exp(&claims, now_unix)?;
    let mut kind = None;
    let mut ctx = None;
    let mut scope_kind = None;
    let mut persona = None;
    for (name, value) in &claims.rest {
        if let (coset::cwt::ClaimName::Text(t), CborValue::Text(v)) = (name, value) {
            match t.as_str() {
                CLAIM_KIND => kind = Some(v.clone()),
                CLAIM_CTX => ctx = Some(v.clone()),
                CLAIM_SCOPE_KIND => scope_kind = Some(v.clone()),
                // Bounded, non-panicking: accept the persona ONLY if it is a single text value within
                // the cap. A non-text or oversized value is silently dropped (persona `None`) — a
                // corrupt/hostile envelope must never truncate a role or panic (Security C5).
                CLAIM_PERSONA if v.len() <= MAX_PERSONA_LEN => persona = Some(v.clone()),
                _ => {}
            }
        }
    }
    if kind.as_deref() != Some(KIND_CONTEXT) {
        return Err(TokenError::Claims("not a signed-context envelope".into()));
    }
    // POSITIVE-marker class precedence (Security S4 / Backend #2), fail-closed at every fork:
    //   br_scope_kind=system  ⇒ System, and `br_ctx` MUST be absent (a seal with both is a
    //                            contradiction → reject; a system principal has no tenant).
    //   br_scope_kind=<other> ⇒ reject (unknown kind — never degrade to a tenant seal).
    //   no scope-kind + br_ctx ⇒ Tenant (the ordinary seal; unchanged).
    //   no scope-kind + no ctx ⇒ reject (preserves the pre-feature malformity check — a system
    //                            principal is NEVER inferred from a missing tenant).
    match scope_kind.as_deref() {
        Some(SCOPE_KIND_SYSTEM) => {
            if ctx.is_some() {
                return Err(TokenError::Claims(
                    "system signed-context must carry no tenant (br_ctx present)".into(),
                ));
            }
            Ok(VerifiedContext {
                kind: crate::tenancy::PrincipalKind::System,
                tenant: None,
                persona,
            })
        }
        Some(other) => Err(TokenError::Claims(format!(
            "signed context has an unknown scope kind: {other}"
        ))),
        None => {
            // MUTATION SEAM (gate `infer_system_from_missing_tenant`): promote a seal with NO positive
            // marker and NO tenant to System — provenance by ABSENCE, the exact landmine this
            // precedence forbids. Compiled out of shipped builds; the gate then goes RED (a
            // markerless/tenantless seal must be REJECTED, never classed System).
            if ctx.is_none()
                && sysseal_mutation().as_deref() == Some("infer_system_from_missing_tenant")
            {
                return Ok(VerifiedContext {
                    kind: crate::tenancy::PrincipalKind::System,
                    tenant: None,
                    persona,
                });
            }
            let tenant =
                ctx.ok_or_else(|| TokenError::Claims("signed context has no tenant".into()))?;
            Ok(VerifiedContext {
                kind: crate::tenancy::PrincipalKind::Tenant,
                tenant: Some(tenant),
                persona,
            })
        }
    }
}

/// Verify a durable signed-context envelope against the fleet public key at `now_unix`: checks the
/// COSE signature, the expiry, and `br_kind == "context"`, then returns the carried own-tenant
/// value. Any tampering (a forged tenant, an altered/expired envelope, a wrong kind) fails closed —
/// the async consumer then resolves no `SignedContext` fact and an "own" op fails closed. The
/// (8+) tenant-only callers keep this signature; a consumer needing the persona uses
/// [`verify_context_full`].
pub fn verify_context(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<String, TokenError> {
    // A SYSTEM seal has no tenant ⇒ `Err` here, so the 13 tenant-only callers' `.ok()` yields `None`
    // (no `SignedContext` tenant fact; a `{tenant}`-templated bind-verify quarantines fail-closed). A
    // system principal is usable only via the class-aware [`verify_context_full`].
    verify_context_inner(token, public, now_unix)?
        .tenant
        .ok_or_else(|| {
            TokenError::Claims("signed context is a system principal (no tenant)".into())
        })
}

/// Verify a durable signed-context envelope and return BOTH the sealed own-tenant and the
/// host-verified caller persona (PLAN-async-persona). Same signature/expiry/kind checks as
/// [`verify_context`] — the persona rides in the SAME envelope, so it is bound to the same verified
/// tenant (no separate expiry, no cross-tenant persona). `persona` is `None` when none was sealed
/// or the carried value was corrupt/oversized/non-text (dropped fail-closed).
pub fn verify_context_full(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<VerifiedContext, TokenError> {
    verify_context_inner(token, public, now_unix)
}

/// The grant a verified [`KIND_CAPABILITY`] envelope carries: the target tenant `B` and the public
/// subset name it is scoped to (R4/D8 5c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGrant {
    /// The target tenant `B` (`br_ctx`) the bearer may reach.
    pub tenant: String,
    /// The public-subset name (`br_pub`) the capability is scoped to — must match the route's
    /// declared `public` at bind (a capability for one subset can't be redeemed for another).
    pub public: String,
    /// The **opaque app-authored context** (`br_app`) the issuer attached — host-carried with
    /// integrity, **never interpreted by the host**, surfaced back to the issuing guest for its own
    /// within-tenant filtering (e.g. a per-client `sub`). Empty when the capability carried none.
    pub context: std::collections::BTreeMap<String, String>,
}

/// Encode an opaque app-context map as a CBOR text→text map (deterministic key order). Only present
/// when non-empty. The host never reads the values — this is app-authored, app-read data.
fn app_context_to_cbor(context: &std::collections::BTreeMap<String, String>) -> CborValue {
    CborValue::Map(
        context
            .iter()
            .map(|(k, v)| (CborValue::Text(k.clone()), CborValue::Text(v.clone())))
            .collect(),
    )
}

/// Decode the app-context from the CBOR produced by [`app_context_to_cbor`]; non-text or malformed
/// entries are ignored (never a panic on a hostile token). Bounded on decode too (defense in depth).
fn cbor_to_app_context(value: &CborValue) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let CborValue::Map(entries) = value else {
        return out;
    };
    for (k, v) in entries.iter().take(MAX_APP_CONTEXT_ENTRIES) {
        if let (CborValue::Text(k), CborValue::Text(v)) = (k, v) {
            out.insert(k.clone(), v.clone());
        }
    }
    out
}

/// Total serialized size (keys + values) of an app-context, for the [`MAX_APP_CONTEXT_BYTES`] bound.
fn app_context_bytes(context: &std::collections::BTreeMap<String, String>) -> usize {
    context.iter().map(|(k, v)| k.len() + v.len()).sum()
}

/// Mint a host-signed **target capability** envelope (5c): `br_kind = "capability"`, the target tenant
/// bound as `br_ctx`, the granted public-subset name as `br_pub`, the redeeming project as `aud`,
/// `iat = now`, `exp = now + ttl_secs`, a random `cti`, signed by the fleet `Signer`. Presented as a
/// bearer, it authenticates target access to `B`'s public subset for the named audience only.
/// Verified with [`verify_capability`]; a forged/expired/wrong-audience envelope never verifies.
pub async fn mint_capability(
    target_tenant: &str,
    audience: &str,
    public_subset: &str,
    app_context: &std::collections::BTreeMap<String, String>,
    ttl_secs: u64,
    now_unix: u64,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    // R6: the opaque app-context is bounded so a guest can't inflate a token. Enforced at mint.
    if app_context.len() > MAX_APP_CONTEXT_ENTRIES {
        return Err(TokenError::Claims(format!(
            "capability app-context has {} entries (max {MAX_APP_CONTEXT_ENTRIES})",
            app_context.len()
        )));
    }
    if app_context_bytes(app_context) > MAX_APP_CONTEXT_BYTES {
        return Err(TokenError::Claims(format!(
            "capability app-context exceeds {MAX_APP_CONTEXT_BYTES} bytes"
        )));
    }
    let mut builder = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .audience(audience.to_string())
        .expiration_time(Timestamp::WholeSeconds(
            now_unix.saturating_add(ttl_secs) as i64
        ))
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_CAPABILITY.to_string()),
        )
        .text_claim(
            CLAIM_CTX.to_string(),
            CborValue::Text(target_tenant.to_string()),
        )
        .text_claim(
            CLAIM_PUB.to_string(),
            CborValue::Text(public_subset.to_string()),
        );
    // Only carry the app-context claim when the issuer attached one.
    if !app_context.is_empty() {
        builder = builder.text_claim(CLAIM_APP.to_string(), app_context_to_cbor(app_context));
    }
    sign_claims(builder.build(), signer).await
}

/// Verify a target-capability envelope against the fleet public key at `now_unix`, requiring the
/// carried audience to equal `expected_audience` (the redeeming project). Checks the COSE signature,
/// the expiry, `br_kind == "capability"`, and the audience, then returns the [`CapabilityGrant`]
/// (`B` + the granted public-subset name). Any tampering — a forged tenant, an altered/expired
/// envelope, a wrong kind, or a **different audience** (a capability minted for project X presented at
/// project Y) — fails closed; the bind then resolves no target fact and the route fails closed.
pub fn verify_capability(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
    expected_audience: &str,
) -> Result<CapabilityGrant, TokenError> {
    let claims = verify_envelope(token, public)?;
    // A capability crosses the tenant boundary, so its expiry is a HARD verify-side invariant (R5):
    // an `exp`-less capability would never expire. `check_exp` treats an absent `exp` as "no expiry"
    // (fine for other kinds), so require its presence here — regardless of who minted the token.
    if check_exp(&claims, now_unix)?.is_none() {
        return Err(TokenError::Claims(
            "capability has no expiry (exp is mandatory for a target capability)".into(),
        ));
    }
    // Audience binding: a capability is redeemable ONLY at the project it names — never replayed
    // across projects. Absent or mismatched audience fails closed.
    if claims.audience.as_deref() != Some(expected_audience) {
        return Err(TokenError::Claims(
            "capability audience does not match this project".into(),
        ));
    }
    let mut kind = None;
    let mut ctx = None;
    let mut pubname = None;
    let mut context = std::collections::BTreeMap::new();
    for (name, value) in &claims.rest {
        let coset::cwt::ClaimName::Text(t) = name else {
            continue;
        };
        match (t.as_str(), value) {
            (CLAIM_KIND, CborValue::Text(v)) => kind = Some(v.clone()),
            (CLAIM_CTX, CborValue::Text(v)) => ctx = Some(v.clone()),
            (CLAIM_PUB, CborValue::Text(v)) => pubname = Some(v.clone()),
            // The opaque app-context — decoded verbatim, never interpreted by the host.
            (CLAIM_APP, m @ CborValue::Map(_)) => context = cbor_to_app_context(m),
            _ => {}
        }
    }
    if kind.as_deref() != Some(KIND_CAPABILITY) {
        return Err(TokenError::Claims("not a capability envelope".into()));
    }
    Ok(CapabilityGrant {
        tenant: ctx.ok_or_else(|| TokenError::Claims("capability has no target tenant".into()))?,
        public: pubname
            .ok_or_else(|| TokenError::Claims("capability has no public subset".into()))?,
        context,
    })
}

// ---- S3-ingress session token (PLAN-blob-s3-ingress) ----------------------------------------
//
// The `session_token` of a temporary S3 credential. Domain-separated from every other token kind:
// a role/capability/context/session token can never be redeemed here (the exact `br_kind` check), and
// an S3 session can never be redeemed as any of those (their verifiers reject its kind).

/// A single permitted S3 operation an [`S3SessionScope`] grants. Deliberately a small, explicit set
/// (write/multipart only by default) — an ingress credential is never a read/list/delete surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum S3Perm {
    /// Single-shot `PutObject`.
    Put,
    /// The multipart quartet (`CreateMultipartUpload` / `UploadPart` / `CompleteMultipartUpload` /
    /// `AbortMultipartUpload`) — resumable/large uploads.
    Multipart,
}

impl S3Perm {
    /// The stable wire term (CBOR + greppable).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Put => "put",
            Self::Multipart => "multipart",
        }
    }

    /// Parse a wire term back; unknown ⇒ `None` (dropped on decode, never a panic).
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "put" => Some(Self::Put),
            "multipart" => Some(Self::Multipart),
            _ => None,
        }
    }
}

/// What an [`S3SessionScope`] is bound to: exactly ONE object key, or a key prefix. Caller-chosen-key
/// (UGC) creds bind a single key; bulk-agent creds bind a prefix. Both are host-composed under
/// `hblob/{project-qualified-site}/{container}/` and screened by `validate_object_key` before the
/// scope is minted (M2 re-screens at the face; here it is carried opaquely).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3Target {
    /// A single object key the credential may write (create-only unless content-addressed).
    Key(String),
    /// A key prefix the credential may write under (a bulk credential).
    Prefix(String),
}

impl S3Target {
    /// The CBOR discriminant term.
    fn tag(&self) -> &'static str {
        match self {
            Self::Key(_) => "key",
            Self::Prefix(_) => "prefix",
        }
    }
    /// The bound key/prefix string.
    fn value(&self) -> &str {
        match self {
            Self::Key(k) | Self::Prefix(k) => k,
        }
    }
}

/// The **enforced** constraints stamped into an [`S3SessionScope`]. On the local S3 face these are
/// hard fail-closed checks (M2); the credential's `enforced`-vs-`advisory` contract (M3) reflects that
/// a cloud store may not honor all of them, where content-addressing is the mandatory fallback.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct S3Constraints {
    /// Max object size in bytes (`None` ⇒ unbounded here; the per-container ceiling still applies).
    pub max_bytes: Option<u64>,
    /// Required `Content-Type` (exact or a `type/*` family — matched at the face); `None` ⇒ any.
    pub content_type: Option<String>,
    /// Require the object key to equal `sha256(bytes)` (content-addressing) — the strong,
    /// cross-cloud, replay-inert enforcement.
    pub require_sha256: bool,
    /// Refuse to overwrite an existing key (create-only, `If-None-Match: *`-style). UGC creds default
    /// to this; overwrite is safe only for content-addressed keys (same bytes ⇒ same key).
    pub create_only: bool,
}

/// The full host-stamped upload scope an [`KIND_S3_SESSION`] token carries. Project + site are
/// resolved by the HOST from the minting principal's own scope (never guest/client-supplied), so a
/// credential is structurally confined to its origin tenant; container/target/perms/constraints are
/// the (clamped) request shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3SessionScope {
    /// The owning project (host-resolved).
    pub project: String,
    /// The owning site (host-resolved).
    pub site: String,
    /// The blob container (a single validated segment).
    pub container: String,
    /// The single key or prefix the credential may write.
    pub target: S3Target,
    /// The permitted S3 operations (a non-empty set; write/multipart only).
    pub perms: Vec<S3Perm>,
    /// The enforced upload constraints.
    pub constraints: S3Constraints,
}

impl S3SessionScope {
    /// Encode as a deterministic CBOR map for the signed payload. Only present constraint fields are
    /// written (a compact, stable token). Perms are sorted+deduped so the encoding is canonical.
    fn to_cbor(&self) -> CborValue {
        let mut perms: Vec<S3Perm> = self.perms.clone();
        perms.sort_unstable();
        perms.dedup();
        let mut constraints: Vec<(CborValue, CborValue)> = Vec::new();
        if let Some(mb) = self.constraints.max_bytes {
            constraints.push((
                CborValue::Text("max_bytes".into()),
                CborValue::Integer(mb.into()),
            ));
        }
        if let Some(ct) = &self.constraints.content_type {
            constraints.push((
                CborValue::Text("content_type".into()),
                CborValue::Text(ct.clone()),
            ));
        }
        if self.constraints.require_sha256 {
            constraints.push((
                CborValue::Text("require_sha256".into()),
                CborValue::Bool(true),
            ));
        }
        if self.constraints.create_only {
            constraints.push((CborValue::Text("create_only".into()), CborValue::Bool(true)));
        }
        CborValue::Map(vec![
            (
                CborValue::Text("project".into()),
                CborValue::Text(self.project.clone()),
            ),
            (
                CborValue::Text("site".into()),
                CborValue::Text(self.site.clone()),
            ),
            (
                CborValue::Text("container".into()),
                CborValue::Text(self.container.clone()),
            ),
            (
                CborValue::Text(self.target.tag().into()),
                CborValue::Text(self.target.value().to_string()),
            ),
            (
                CborValue::Text("perms".into()),
                CborValue::Array(
                    perms
                        .iter()
                        .map(|p| CborValue::Text(p.as_str().into()))
                        .collect(),
                ),
            ),
            (
                CborValue::Text("constraints".into()),
                CborValue::Map(constraints),
            ),
        ])
    }

    /// Decode from the CBOR produced by [`to_cbor`](Self::to_cbor). Fails closed (`None`) on a missing
    /// required field, an empty perm set, or both/neither of `key`/`prefix` — a hostile/garbled scope
    /// never yields a usable (and therefore never a widened) grant. Unknown keys are ignored.
    fn from_cbor(value: &CborValue) -> Option<Self> {
        let CborValue::Map(entries) = value else {
            return None;
        };
        let mut project = None;
        let mut site = None;
        let mut container = None;
        let mut key = None;
        let mut prefix = None;
        let mut perms: Vec<S3Perm> = Vec::new();
        let mut constraints = S3Constraints::default();
        for (k, v) in entries {
            let CborValue::Text(name) = k else { continue };
            match (name.as_str(), v) {
                ("project", CborValue::Text(s)) => project = Some(s.clone()),
                ("site", CborValue::Text(s)) => site = Some(s.clone()),
                ("container", CborValue::Text(s)) => container = Some(s.clone()),
                ("key", CborValue::Text(s)) => key = Some(s.clone()),
                ("prefix", CborValue::Text(s)) => prefix = Some(s.clone()),
                ("perms", CborValue::Array(items)) => {
                    for item in items {
                        if let CborValue::Text(p) = item
                            && let Some(perm) = S3Perm::from_str(p)
                        {
                            perms.push(perm);
                        }
                    }
                }
                ("constraints", CborValue::Map(cs)) => {
                    for (ck, cv) in cs {
                        let CborValue::Text(cname) = ck else { continue };
                        match (cname.as_str(), cv) {
                            ("max_bytes", CborValue::Integer(i)) => {
                                constraints.max_bytes = u64::try_from(*i).ok();
                            }
                            ("content_type", CborValue::Text(s)) => {
                                constraints.content_type = Some(s.clone());
                            }
                            ("require_sha256", CborValue::Bool(b)) => {
                                constraints.require_sha256 = *b;
                            }
                            ("create_only", CborValue::Bool(b)) => constraints.create_only = *b,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        // Exactly one of key/prefix must be present (never both, never neither).
        let target = match (key, prefix) {
            (Some(k), None) => S3Target::Key(k),
            (None, Some(p)) => S3Target::Prefix(p),
            _ => return None,
        };
        perms.sort_unstable();
        perms.dedup();
        if perms.is_empty() {
            return None;
        }
        Some(Self {
            project: project?,
            site: site?,
            container: container?,
            target,
            perms,
            constraints,
        })
    }
}

/// A verified S3-ingress session token: the carried [`S3SessionScope`], its revocation id (`cti`, for
/// the opt-in revocation check), and its effective expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Session {
    /// The host-stamped upload scope this credential authorizes.
    pub scope: S3SessionScope,
    /// The revocation id (hex of `cti`) — looked up in `authz/revoked/<cti>` only for long-TTL creds
    /// that opt into revocation (off by default; the common path is stateless).
    pub cti: String,
    /// The (mandatory) expiry, Unix seconds.
    pub exp: u64,
}

/// Mint an S3-ingress **session token** ([`KIND_S3_SESSION`]): a `COSE_Sign1` CWT carrying the full
/// host-stamped `scope` as `br_s3`, `iat = now`, a mandatory `exp = now + ttl_secs`, and a random
/// `cti`, signed by the fleet `Signer`. Returns the base64url token — the `session_token` field of the
/// temporary credential handed to the client. Verified with [`verify_s3_session`]; a forged/expired/
/// wrong-kind token never verifies, and the scope can only be READ from the signed payload (never
/// widened by the client).
pub async fn mint_s3_session(
    scope: &S3SessionScope,
    ttl_secs: u64,
    now_unix: u64,
    signer: &dyn Signer,
) -> Result<String, TokenError> {
    let claims = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .expiration_time(Timestamp::WholeSeconds(
            now_unix.saturating_add(ttl_secs) as i64
        ))
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_S3_SESSION.to_string()),
        )
        .text_claim(CLAIM_S3.to_string(), scope.to_cbor())
        .build();
    sign_claims(claims, signer).await
}

/// Verify an S3-ingress session token against the fleet public key at `now_unix`: checks the COSE
/// signature (algorithm pinned), the **mandatory** expiry, and `br_kind == "s3-session"` (domain
/// separation — a role/capability/context/session token presented here is rejected), then decodes the
/// carried [`S3SessionScope`]. Any tampering — a forged/altered scope, an absent/expired `exp`, a wrong
/// kind, a malformed scope (missing field / empty perms / both-or-neither key/prefix) — fails closed;
/// the local S3 face then returns a uniform 403 with NO which-check-failed detail (revocation, if the
/// caller opts in, is a separate `authz/revoked/<cti>` lookup on the returned `cti`).
pub fn verify_s3_session(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<S3Session, TokenError> {
    let claims = verify_envelope(token, public)?;
    let cti = claim_cti(&claims)?;
    // An S3 credential is short-lived by construction, so `exp` is a HARD invariant: an `exp`-less
    // token would never expire. `check_exp` treats an absent `exp` as "no expiry" (fine for other
    // kinds), so require its presence here regardless of who minted the token.
    let exp = check_exp(&claims, now_unix)?
        .ok_or_else(|| TokenError::Claims("s3-session has no expiry (exp is mandatory)".into()))?;
    let mut kind = None;
    let mut scope = None;
    for (name, value) in &claims.rest {
        let coset::cwt::ClaimName::Text(t) = name else {
            continue;
        };
        match (t.as_str(), value) {
            (CLAIM_KIND, CborValue::Text(k)) => kind = Some(k.clone()),
            (CLAIM_S3, m @ CborValue::Map(_)) => scope = S3SessionScope::from_cbor(m),
            _ => {}
        }
    }
    if kind.as_deref() != Some(KIND_S3_SESSION) {
        return Err(TokenError::Claims("not an s3-session token".into()));
    }
    let scope =
        scope.ok_or_else(|| TokenError::Claims("s3-session scope is missing/malformed".into()))?;
    Ok(S3Session { scope, cti, exp })
}

/// The canonical bytes a joiner signs with its mesh private key to **prove
/// possession** of the key it presents when redeeming join token `jti`. Bound to
/// the token (`jti`), the presented key (`mesh_pubkey_hex`), and a fresh timestamp
/// (`proof_iat`) — so the proof can't be replayed for a different token, key, or
/// (stale) time. Built identically on both sides (a strict compare, no ambiguity).
pub fn join_challenge(jti: &str, mesh_pubkey_hex: &str, proof_iat: u64) -> Vec<u8> {
    format!("boatramp-mesh-join/v1\n{jti}\n{mesh_pubkey_hex}\n{proof_iat}").into_bytes()
}

/// A verified delegation credential: the **root's** roles + revocation id, the
/// *effective* expiry (the tightest across the root and every block's
/// `not_after`), and the intersected [`Caveats`]. A plain (non-delegated) token
/// verifies to this too — with empty caveats and a single block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    /// The roles the credential grants — always the **root's** (children add none).
    pub roles: Vec<GrantedRole>,
    /// The root token kind (`role`, typically).
    pub kind: String,
    /// The root's revocation id (`cti`, hex): revoking it revokes the whole chain.
    pub cti: String,
    /// The effective expiry (Unix seconds) — the min across the chain, if any.
    pub exp: Option<u64>,
    /// The intersected narrowing caveats to enforce at authorization time.
    pub caveats: Caveats,
    /// The **terminal** holder key (`cnf`) of the presented credential — the leaf
    /// delegate's key, or the token's own for a plain token; `None` for a
    /// non-holder-bound token. A per-request PoP proof must verify against *this*
    /// key (not the root's), so channel/replay binding follows delegation.
    pub leaf_cnf: Option<String>,
}

impl VerifiedChain {
    /// Whether this presented chain ends in a **sealed** leaf: a terminal block
    /// naming **no** next holder (`leaf_cnf == None`), or naming the **root's own
    /// verifying key**. A sealed leaf has no un-presented narrowing beyond what is
    /// shown, so a prefix ending there cannot be a truncation of a longer chain.
    /// See [`verify_presented`] (uchron RFC-009 §7, C1). Delegates to the generic
    /// engine's single source of truth so the rule stays identical everywhere.
    pub fn leaf_is_sealed(&self, root_public: &TokenPublicKey) -> bool {
        boatramp_cwt::leaf_cnf_is_sealed(self.leaf_cnf.as_deref(), root_public)
    }

    /// Whether the credential's effective [`exp`](Self::exp) is past `now_unix`.
    /// Pairs with [`verify_credential_unexpired`] so a caller on a non-wall clock
    /// can separate "authentic" from "expired" (U8–U10, #2).
    pub fn is_expired_at(&self, now_unix: u64) -> bool {
        matches!(self.exp, Some(exp) if now_unix > exp)
    }
}

/// Project a generic engine [`CredentialChain`](boatramp_cwt::CredentialChain) over
/// [`Caveats`] into boatramp's [`VerifiedChain`] (roles/kind from the verified root).
fn project_chain(
    chain: boatramp_cwt::CredentialChain<Caveats>,
) -> Result<VerifiedChain, TokenError> {
    let root = role_token(&chain.root_claims, chain.exp)?;
    // 8(b) / M1 — domain separation on the CHAIN/role-gate path. This is the single
    // choke point for [`verify_credential`] (RBAC authz), [`verify_presented`]
    // (whoami + the preview "any valid token" gate), and [`verify_credential_unexpired`],
    // so the root-kind check belongs here, symmetric with [`verify`]. Without it, a
    // sealed, root-signed non-role credential — notably the per-node `cluster-write`
    // capability (`kind = cluster-write`, no `cnf` ⇒ sealed, non-expiring) — would be
    // accepted as a valid ROLE credential at every control-plane role gate (C1 can't
    // reject it: it's sealed), letting a captured capability view protected previews
    // and disclose its role at whoami. A legit role token / delegation chain carries
    // root `kind = KIND_ROLE` (delegation blocks are KIND_DELEGATION, but only the
    // ROOT claims are read here); every other kind has its own verifier, and the
    // mesh-write gate uses [`verify_cluster_write`], not this path.
    if root.kind != KIND_ROLE {
        return Err(TokenError::Claims("not a role token".into()));
    }
    Ok(VerifiedChain {
        roles: root.roles,
        kind: root.kind,
        cti: chain.cti,
        exp: chain.exp,
        caveats: chain.caveats,
        leaf_cnf: chain.leaf_cnf,
    })
}

/// Append a **restrict-only** delegation block to a credential, signed by the
/// holder key the previous block declared (`cnf`). Fully offline/client-side (no
/// root key): the holder proves possession by signing, and can only *narrow* via
/// `caveats`. `next_holder` (optional) is the key permitted to attenuate further.
///
/// The result is `base64url(CBOR array [root, …, child])`. The caller must present
/// this whole credential; revocation still keys off the root `cti`.
pub async fn attenuate(
    credential: &str,
    holder_signer: &dyn Signer,
    caveats: &Caveats,
    next_holder: Option<&TokenPublicKey>,
    now_unix: u64,
) -> Result<String, TokenError> {
    // Thin layer over the generic engine: boatramp's `Caveats` is the first
    // `NarrowingCaveats` impl, so block framing (kind/caveats/cnf claims, the
    // `not_after`→`exp` fold) is identical to the pre-extraction code.
    boatramp_cwt::attenuate(credential, holder_signer, caveats, next_holder, now_unix).await
}

/// Verify a presented credential — a plain token *or* a delegation chain — against
/// the root public key at `now_unix`. Walks the chain (each block under its
/// parent's `cnf`, PoP-style), intersects caveats, folds `not_after` into the
/// effective `exp`, and returns the **root's** roles + `cti`. Resource bounds
/// ([`MAX_CHAIN_BYTES`]/[`MAX_CHAIN_DEPTH`]) are enforced *before* any signature
/// verification. Revocation (root `cti`) stays the caller's job.
pub fn verify_credential(
    credential: &str,
    root_public: &TokenPublicKey,
    now_unix: u64,
) -> Result<VerifiedChain, TokenError> {
    // The generic engine walks the chain (signatures, PoP `cnf` binding, the
    // engine-VERIFIED monotonic narrowing of `Caveats`, min-folded expiry) and
    // returns the verified ROOT claim set — authority is read from the root alone.
    // This layer projects boatramp's roles/kind from that root, so the result is
    // byte-for-byte the pre-extraction `VerifiedChain`.
    let chain = boatramp_cwt::verify_credential::<Caveats>(credential, root_public, now_unix)?;
    project_chain(chain)
}

/// Verify a **presented** credential for a gate with **no per-request proof of
/// possession** (the protected-preview gate, `whoami`): exactly
/// [`verify_credential`], but additionally **requires a sealed leaf**
/// ([`VerifiedChain::leaf_is_sealed`]). This closes the chain-prefix **truncation**
/// escalation (uchron RFC-009 §7, C1): a holder of an *intermediate* `cnf` key
/// could otherwise strip the trailing narrowing blocks and present the shorter
/// prefix to recover the parent's un-narrowed authority. A PoP-capable path keeps
/// [`verify_credential`] + a per-request proof against
/// [`leaf_cnf`](VerifiedChain::leaf_cnf) instead (the complementary half of the
/// sealed-or-PoP rule). Thin layer over [`boatramp_cwt::verify_presented`].
pub fn verify_presented(
    credential: &str,
    root_public: &TokenPublicKey,
    now_unix: u64,
) -> Result<VerifiedChain, TokenError> {
    let chain = boatramp_cwt::verify_presented::<Caveats>(credential, root_public, now_unix)?;
    project_chain(chain)
}

/// Like [`verify_credential`], but **does not enforce expiry** — it proves
/// authenticity (signatures, PoP `cnf` binding, the engine-verified monotone
/// narrowing) and returns the chain with its min-folded
/// [`exp`](VerifiedChain::exp) for the caller to check against its own clock
/// ([`VerifiedChain::is_expired_at`]). Surfaces the engine's authentic-vs-expired
/// separation (U8–U10, #2). Thin layer over [`boatramp_cwt::verify_credential_unexpired`].
pub fn verify_credential_unexpired(
    credential: &str,
    root_public: &TokenPublicKey,
) -> Result<VerifiedChain, TokenError> {
    let chain = boatramp_cwt::verify_credential_unexpired::<Caveats>(credential, root_public)?;
    project_chain(chain)
}

/// The bound facts of a per-request **proof-of-possession** (DPoP-style). The
/// client signs these with the token's holder (`cnf`) key; the server rebuilds
/// them from the actual request + its configured origin and verifies the proof
/// against the credential's [`leaf_cnf`](VerifiedChain::leaf_cnf).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopClaims {
    /// HTTP method, upper-case (`GET`, `PUT`, …).
    pub htm: String,
    /// Request path, canonicalized by [`canon_pop_path`].
    pub htp: String,
    /// The fleet's configured canonical origin (e.g. `https://cp.example.com`).
    /// Bound so a captured proof can't be relayed to a different origin — compared
    /// to the server's *config*, never to a `Host`/`X-Forwarded-*` header.
    pub aud: String,
    /// Hex SHA-256 of the presented access token.
    pub ath: String,
    /// Hex SHA-256 of the request body — `Some` on write requests with a body.
    pub bh: Option<String>,
}

/// Canonicalize a request path for PoP binding: exactly one leading slash, no
/// trailing slash (except root). Applied identically on both sides so the compare
/// can't silently mismatch (availability) or be loosened into a bypass.
pub fn canon_pop_path(path: &str) -> String {
    let trimmed = path.trim().trim_start_matches('/').trim_end_matches('/');
    format!("/{trimmed}")
}

/// Hex SHA-256 of `bytes` — the encoding used for the `ath`/`bh` PoP bindings.
pub fn pop_sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Mint a per-request PoP proof (a `br_kind = "pop"` `COSE_Sign1`), signed by the
/// holder key, binding `claims` to this request. `now_unix` stamps `iat`
/// (freshness) and a random `jti` (`cti`) is added. Returned base64url.
pub async fn mint_pop(
    claims: &PopClaims,
    holder: &dyn Signer,
    now_unix: u64,
) -> Result<String, TokenError> {
    let mut builder = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .audience(claims.aud.clone())
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_POP.to_string()),
        )
        .text_claim(CLAIM_HTM.to_string(), CborValue::Text(claims.htm.clone()))
        .text_claim(CLAIM_HTP.to_string(), CborValue::Text(claims.htp.clone()))
        .text_claim(CLAIM_ATH.to_string(), CborValue::Text(claims.ath.clone()));
    if let Some(bh) = &claims.bh {
        builder = builder.text_claim(CLAIM_BH.to_string(), CborValue::Text(bh.clone()));
    }
    sign_claims(builder.build(), holder).await
}

/// Verify a per-request PoP proof against `holder_public` (the credential's
/// [`leaf_cnf`](VerifiedChain::leaf_cnf)) at `now_unix`: signature + alg pin +
/// `br_kind = "pop"` + freshness (`iat` within [`POP_WINDOW_SECS`], not
/// [`POP_SKEW_SECS`] in the future) + every bound fact (`htm`/`htp`/`aud`/`ath`,
/// and `bh` — which must match, present-or-absent, the server's `expected.bh`).
/// On success returns the proof's `jti` (its `cti`, hex) so the caller can run a
/// node-local replay check. IO-free; the replay check itself is the caller's job.
pub fn verify_pop(
    proof: &str,
    holder_public: &TokenPublicKey,
    now_unix: u64,
    expected: &PopClaims,
) -> Result<String, TokenError> {
    let claims = verify_envelope(proof, holder_public)?;

    let kind = text_claim(&claims, CLAIM_KIND).and_then(|v| match v {
        CborValue::Text(t) => Some(t.as_str()),
        _ => None,
    });
    if kind != Some(KIND_POP) {
        return Err(TokenError::Claims("not a PoP proof".into()));
    }

    let iat = match claims.issued_at {
        Some(Timestamp::WholeSeconds(s)) => s.max(0) as u64,
        _ => return Err(TokenError::Claims("PoP proof has no iat".into())),
    };
    if iat > now_unix.saturating_add(POP_SKEW_SECS)
        || now_unix.saturating_sub(iat) > POP_WINDOW_SECS
    {
        return Err(TokenError::Expired);
    }

    let text = |name| {
        text_claim(&claims, name).and_then(|v| match v {
            CborValue::Text(t) => Some(t.clone()),
            _ => None,
        })
    };
    if text(CLAIM_HTM).as_deref() != Some(expected.htm.as_str())
        || text(CLAIM_HTP).as_deref() != Some(expected.htp.as_str())
        || claims.audience.as_deref() != Some(expected.aud.as_str())
        || text(CLAIM_ATH).as_deref() != Some(expected.ath.as_str())
    {
        return Err(TokenError::Claims(
            "PoP proof does not match the request".into(),
        ));
    }
    // The body binding must match present-or-absent: a proof binding a body on a
    // bodiless request (or vice versa) is rejected.
    if text(CLAIM_BH) != expected.bh {
        return Err(TokenError::Claims("PoP proof body-hash mismatch".into()));
    }
    // The proof's `jti` (its `cti`) — the caller's replay handle.
    claim_cti(&claims)
}

/// Read the holder-key (`cnf`) claim, if present.
fn claim_cnf(claims: &ClaimsSet) -> Option<String> {
    text_claim(claims, CLAIM_CNF).and_then(|v| match v {
        CborValue::Text(t) => Some(t.clone()),
        _ => None,
    })
}

/// Encode roles as a CBOR array of `[name]` (global) / `[name, target]` (scoped).
fn roles_to_cbor(roles: &[GrantedRole]) -> CborValue {
    CborValue::Array(
        roles
            .iter()
            .map(|r| match &r.target {
                Some(t) => CborValue::Array(vec![
                    CborValue::Text(r.name.clone()),
                    CborValue::Text(t.clone()),
                ]),
                None => CborValue::Array(vec![CborValue::Text(r.name.clone())]),
            })
            .collect(),
    )
}

/// Decode roles from the CBOR produced by [`roles_to_cbor`]; unparsable entries
/// are dropped (never a panic on a hostile token).
fn cbor_to_roles(value: &CborValue) -> Vec<GrantedRole> {
    let CborValue::Array(items) = value else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        let CborValue::Array(parts) = item else {
            continue;
        };
        match parts.as_slice() {
            [CborValue::Text(name)] => out.push(GrantedRole::global(name)),
            [CborValue::Text(name), CborValue::Text(target)] => {
                out.push(GrantedRole::scoped(name, target));
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    // Low-level engine helpers used only by these tests (crafting raw chains /
    // malformed blocks). They were private helpers in this module before the
    // `boatramp-cwt` extraction; the production code above no longer calls them.
    use base64::Engine as _;
    use boatramp_cwt::{decode_credential, encode_chain, sign_claims_bytes};

    const NOW: u64 = 1_700_000_000;

    fn claims() -> Claims {
        Claims {
            roles: vec![
                GrantedRole::global("admin"),
                GrantedRole::scoped("publisher", "blog"),
            ],
            kind: "role".into(),
            ttl_secs: Some(3600),
            now_unix: NOW,
        }
    }

    async fn round_trip(alg: TokenAlg) {
        let signer = LocalSigner::generate(alg);
        let public = signer.public_key();
        assert_eq!(public.alg(), alg);

        let token = mint(&claims(), &signer).await.unwrap();
        let v = verify(&token, &public, NOW + 60).unwrap();
        assert_eq!(v.kind, "role");
        assert_eq!(v.roles.len(), 2);
        assert_eq!(v.roles[0], GrantedRole::global("admin"));
        assert_eq!(v.roles[1], GrantedRole::scoped("publisher", "blog"));
        assert!(!v.cti.is_empty());
        assert_eq!(v.exp, Some(NOW + 3600));
    }

    #[tokio::test]
    async fn es256_round_trips() {
        round_trip(TokenAlg::Es256).await;
    }

    #[tokio::test]
    async fn ed25519_round_trips() {
        round_trip(TokenAlg::Ed25519).await;
    }

    #[tokio::test]
    async fn session_cookie_round_trips_and_rejects_tamper_expiry_and_kind() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let pubkey = signer.public_key();
        // Mint at t=1000, ttl 3600 ⇒ exp 4600. Round-trip returns the bound sid within the window.
        let cookie = mint_session("sid-abc", 3600, 1000, &signer).await.unwrap();
        assert_eq!(verify_session(&cookie, &pubkey, 1000).unwrap(), "sid-abc");
        assert_eq!(verify_session(&cookie, &pubkey, 4000).unwrap(), "sid-abc");
        // Expired past the window ⇒ refused.
        assert!(verify_session(&cookie, &pubkey, 5000).is_err());
        // A stranger's key can't verify (the cookie is signed by the fleet root) — fixation via an
        // unsigned/forged sid fails here.
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        assert!(verify_session(&cookie, &stranger.public_key(), 1000).is_err());
        // Domain separation: a join token (same signer, wrong `br_kind`) is NOT a session cookie.
        let join = mint_join(3600, 1000, &signer).await.unwrap();
        assert!(verify_session(&join, &pubkey, 1000).is_err());
    }

    #[tokio::test]
    async fn signed_context_round_trips_and_is_domain_separated() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let pubkey = signer.public_key();
        // Mint at t=1000, ttl 300 ⇒ exp 1300. Round-trip returns the carried tenant within the window.
        let ctx = mint_context("acme", None, 300, 1000, &signer)
            .await
            .unwrap();
        assert_eq!(verify_context(&ctx, &pubkey, 1000).unwrap(), "acme");
        assert_eq!(verify_context(&ctx, &pubkey, 1200).unwrap(), "acme");
        // Expired ⇒ refused (a stale replayed envelope drops out; the async op fails closed).
        assert!(verify_context(&ctx, &pubkey, 2000).is_err());
        // A stranger's key can't verify (a forged tenant fails the signature).
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        assert!(verify_context(&ctx, &stranger.public_key(), 1000).is_err());
        // Cross-kind confusion: a session cookie is NOT a signed context, and vice-versa.
        let cookie = mint_session("sid-1", 300, 1000, &signer).await.unwrap();
        assert!(verify_context(&cookie, &pubkey, 1000).is_err());
        assert!(verify_session(&ctx, &pubkey, 1000).is_err());
    }

    #[tokio::test]
    async fn signed_context_persona_round_trips_and_is_bound_to_the_same_envelope() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let pubkey = signer.public_key();
        // No persona configured ⇒ the envelope seals none (unchanged for every existing producer).
        let plain = mint_context("acme", None, 300, 1000, &signer)
            .await
            .unwrap();
        let v = verify_context_full(&plain, &pubkey, 1000).unwrap();
        assert_eq!(v.tenant.as_deref(), Some("acme"));
        assert_eq!(v.persona, None, "no persona sealed when none configured");
        // With a persona: both the tenant and the persona round-trip, bound to the SAME envelope.
        let sealed = mint_context("acme", Some("Integration"), 300, 1000, &signer)
            .await
            .unwrap();
        let v = verify_context_full(&sealed, &pubkey, 1000).unwrap();
        assert_eq!(v.tenant.as_deref(), Some("acme"));
        assert_eq!(v.persona.as_deref(), Some("Integration"));
        // The tenant-only `verify_context` projects out just the tenant (the 8+ existing callers).
        assert_eq!(verify_context(&sealed, &pubkey, 1000).unwrap(), "acme");
        // The persona shares the envelope's TTL: past exp ⇒ the whole envelope fails closed (the
        // async-lane `role(…)` then refuses — same as the tenant today).
        assert!(verify_context_full(&sealed, &pubkey, 2000).is_err());
        // A forged persona fails the signature (a stranger's key never verifies).
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        assert!(verify_context_full(&sealed, &stranger.public_key(), 1000).is_err());
        // Bound (non-panicking): an over-length persona is REFUSED at mint (never truncated — a
        // truncated role could collide with a different role).
        let too_long = "x".repeat(MAX_PERSONA_LEN + 1);
        assert!(
            mint_context("acme", Some(&too_long), 300, 1000, &signer)
                .await
                .is_err()
        );
        // At the cap it seals fine.
        let at_cap = "y".repeat(MAX_PERSONA_LEN);
        let ok = mint_context("acme", Some(&at_cap), 300, 1000, &signer)
            .await
            .unwrap();
        assert_eq!(
            verify_context_full(&ok, &pubkey, 1000).unwrap().persona,
            Some(at_cap)
        );
    }

    /// A `cron-system-principal` request — a SYSTEM signed-context is classed `System`, carries NO
    /// tenant, and is recognised ONLY by a POSITIVE signed `br_scope_kind=system` marker (never by a
    /// missing tenant). The reject forks are the load-bearing security property.
    #[tokio::test]
    async fn system_signed_context_is_positive_marker_only_and_tenant_free() {
        use crate::tenancy::PrincipalKind;
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let pubkey = signer.public_key();

        // A SYSTEM seal: classed System, NO tenant, persona rides the same envelope.
        let sys = mint_system_context(Some("super_admin"), 300, 1000, &signer)
            .await
            .unwrap();
        let v = verify_context_full(&sys, &pubkey, 1000).unwrap();
        assert_eq!(v.kind, PrincipalKind::System);
        assert_eq!(v.tenant, None, "a system principal has no tenant");
        assert_eq!(v.persona.as_deref(), Some("super_admin"));
        // The tenant-only verify maps a system seal to Err ⇒ its callers' `.ok()` yields None.
        assert!(verify_context(&sys, &pubkey, 1000).is_err());
        // Same signature/expiry discipline as a tenant seal (forged key / expired ⇒ fail closed).
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        assert!(verify_context_full(&sys, &stranger.public_key(), 1000).is_err());
        assert!(verify_context_full(&sys, &pubkey, 2000).is_err());

        // A TENANT seal stays Tenant with the tenant present (the ordinary path, unchanged).
        let ten = mint_context("acme", None, 300, 1000, &signer)
            .await
            .unwrap();
        let v = verify_context_full(&ten, &pubkey, 1000).unwrap();
        assert_eq!(v.kind, PrincipalKind::Tenant);
        assert_eq!(v.tenant.as_deref(), Some("acme"));

        // POSITIVE-marker precedence — a system principal is NEVER inferred from a missing tenant.
        // Mint context seals with arbitrary (ctx, scope_kind) claims to exercise every reject fork.
        async fn mint_raw(
            ctx: Option<&str>,
            scope_kind: Option<&str>,
            signer: &dyn Signer,
        ) -> String {
            let mut b = ClaimsSetBuilder::new()
                .issued_at(Timestamp::WholeSeconds(1000))
                .cwt_id(random_cti().unwrap())
                .expiration_time(Timestamp::WholeSeconds(1300))
                .text_claim(
                    CLAIM_KIND.to_string(),
                    CborValue::Text(KIND_CONTEXT.to_string()),
                );
            if let Some(c) = ctx {
                b = b.text_claim(CLAIM_CTX.to_string(), CborValue::Text(c.to_string()));
            }
            if let Some(sk) = scope_kind {
                b = b.text_claim(
                    CLAIM_SCOPE_KIND.to_string(),
                    CborValue::Text(sk.to_string()),
                );
            }
            sign_claims(b.build(), signer).await.unwrap()
        }
        // both a tenant AND system kind ⇒ contradiction ⇒ REJECT.
        let both = mint_raw(Some("acme"), Some("system"), &signer).await;
        assert!(
            verify_context_full(&both, &pubkey, 1000).is_err(),
            "a seal with both a tenant and the system marker must be rejected"
        );
        // neither a tenant NOR a system marker ⇒ REJECT (pre-feature malformity check preserved).
        let neither = mint_raw(None, None, &signer).await;
        assert!(
            verify_context_full(&neither, &pubkey, 1000).is_err(),
            "a seal with no tenant and no system marker must be rejected (never inferred as system)"
        );
        // an UNKNOWN scope kind ⇒ REJECT (fail-closed, never degrade to a tenant seal).
        let unknown = mint_raw(Some("acme"), Some("wizard"), &signer).await;
        assert!(
            verify_context_full(&unknown, &pubkey, 1000).is_err(),
            "an unknown scope kind must be rejected"
        );
        // CI anti-hollow marker (grepped by the mutation gate): reached ONLY when every reject fork
        // above held. `BOATRAMP_SYSPRINCIPAL_MUTATION=infer_system_from_missing_tenant` promotes the
        // markerless/tenantless seal to System, turning the `neither` assertion RED before this line.
        println!("SYSTEM PRINCIPAL SEAL OK");
    }

    #[tokio::test]
    async fn capability_round_trips_and_is_audience_and_kind_bound() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let pubkey = signer.public_key();
        // Mint a capability granting target tenant B's `storefront` subset, redeemable at project
        // `shop`, ttl 300 ⇒ exp 1300.
        let cap = mint_capability(
            "tenant_B",
            "shop",
            "storefront",
            &Default::default(),
            300,
            1000,
            &signer,
        )
        .await
        .unwrap();
        // Round-trip at the right audience returns B + the granted subset name; no app-context ⇒ empty.
        let grant = verify_capability(&cap, &pubkey, 1000, "shop").unwrap();
        assert_eq!(grant.tenant, "tenant_B");
        assert_eq!(grant.public, "storefront");
        assert!(grant.context.is_empty(), "no app-context was minted");
        // Audience binding: presented at a DIFFERENT project ⇒ refused (no cross-project replay).
        assert!(verify_capability(&cap, &pubkey, 1000, "other-project").is_err());
        // Expired ⇒ refused.
        assert!(verify_capability(&cap, &pubkey, 2000, "shop").is_err());
        // A stranger's key can't verify (a forged target tenant fails the signature).
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        assert!(verify_capability(&cap, &stranger.public_key(), 1000, "shop").is_err());
        // Cross-kind confusion: a signed context is NOT a capability, and a capability is NOT a
        // context (so a capability can never be redeemed as an own-tenant fact and vice-versa).
        let ctx = mint_context("tenant_B", None, 300, 1000, &signer)
            .await
            .unwrap();
        assert!(verify_capability(&ctx, &pubkey, 1000, "shop").is_err());
        assert!(verify_context(&cap, &pubkey, 1000).is_err());
    }

    #[tokio::test]
    async fn capability_carries_opaque_app_context_round_trip_and_is_bounded() {
        use std::collections::BTreeMap;
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let pubkey = signer.public_key();
        // The issuer (a guest) attaches an opaque per-client context; the host carries it verbatim.
        let ctx: BTreeMap<String, String> = BTreeMap::from([
            ("sub".into(), "client-42".into()),
            ("plan".into(), "pro".into()),
        ]);
        let cap = mint_capability("tenant_B", "shop", "storefront", &ctx, 300, 1000, &signer)
            .await
            .unwrap();
        // The verified grant surfaces the app-context verbatim (host never interprets it) alongside B.
        let grant = verify_capability(&cap, &pubkey, 1000, "shop").unwrap();
        assert_eq!(grant.tenant, "tenant_B");
        assert_eq!(
            grant.context.get("sub").map(String::as_str),
            Some("client-42")
        );
        assert_eq!(grant.context.get("plan").map(String::as_str), Some("pro"));
        // The context is integrity-protected: a stranger's key can't verify (so it can't be forged).
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        assert!(verify_capability(&cap, &stranger.public_key(), 1000, "shop").is_err());

        // R6 bounds are enforced at mint: too many entries, or too many bytes, are refused.
        let too_many: BTreeMap<String, String> = (0..MAX_APP_CONTEXT_ENTRIES + 1)
            .map(|i| (format!("k{i}"), "v".to_string()))
            .collect();
        assert!(
            mint_capability(
                "tenant_B",
                "shop",
                "storefront",
                &too_many,
                300,
                1000,
                &signer
            )
            .await
            .is_err(),
            "over-many app-context entries must be refused"
        );
        let too_big: BTreeMap<String, String> =
            BTreeMap::from([("big".into(), "x".repeat(MAX_APP_CONTEXT_BYTES + 1))]);
        assert!(
            mint_capability(
                "tenant_B",
                "shop",
                "storefront",
                &too_big,
                300,
                1000,
                &signer
            )
            .await
            .is_err(),
            "over-large app-context must be refused"
        );
    }

    #[tokio::test]
    async fn capability_app_context_cannot_shadow_reserved_claims() {
        use std::collections::BTreeMap;
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let pubkey = signer.public_key();
        // A hostile issuer names app-context keys identical to the reserved top-level claims. They are
        // nested under `br_app`, so they can NEVER shadow the real tenant/subset/kind/audience — the
        // grant's tenant/public/audience are unaffected and the keys appear ONLY inside grant.context.
        let evil: BTreeMap<String, String> = BTreeMap::from([
            ("br_ctx".into(), "tenant_EVIL".into()),
            ("br_pub".into(), "admin".into()),
            ("br_kind".into(), "role".into()),
            ("aud".into(), "other-project".into()),
        ]);
        let cap = mint_capability("tenant_B", "shop", "storefront", &evil, 300, 1000, &signer)
            .await
            .unwrap();
        let grant = verify_capability(&cap, &pubkey, 1000, "shop").unwrap();
        // The real target facts win; the shadow keys did not leak into them.
        assert_eq!(grant.tenant, "tenant_B");
        assert_eq!(grant.public, "storefront");
        // The shadow values are confined to the opaque app-context.
        assert_eq!(
            grant.context.get("br_ctx").map(String::as_str),
            Some("tenant_EVIL")
        );
        assert_eq!(
            grant.context.get("aud").map(String::as_str),
            Some("other-project")
        );
        // And the token still only redeems at its real audience.
        assert!(verify_capability(&cap, &pubkey, 1000, "other-project").is_err());
    }

    #[tokio::test]
    async fn a_capability_with_no_expiry_is_refused() {
        // Belt-and-suspenders on R5: even a fleet-signed capability that somehow carried no `exp`
        // (a future minter / a bug) must be refused at verify — an unexpiring cross-tenant bearer is
        // never acceptable. Forge one by signing a capability-shaped ClaimsSet WITHOUT exp.
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let pubkey = signer.public_key();
        let claims = ClaimsSetBuilder::new()
            .issued_at(Timestamp::WholeSeconds(1000))
            .cwt_id(random_cti().unwrap())
            .audience("shop".to_string())
            .text_claim(
                CLAIM_KIND.to_string(),
                CborValue::Text(KIND_CAPABILITY.to_string()),
            )
            .text_claim(
                CLAIM_CTX.to_string(),
                CborValue::Text("tenant_B".to_string()),
            )
            .text_claim(
                CLAIM_PUB.to_string(),
                CborValue::Text("storefront".to_string()),
            )
            .build();
        let token = sign_claims(claims, &signer).await.unwrap();
        assert!(
            verify_capability(&token, &pubkey, 1000, "shop").is_err(),
            "an exp-less capability must be refused (R5 enforced at verify)"
        );
    }

    #[tokio::test]
    async fn expiry_is_enforced() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let token = mint(&claims(), &signer).await.unwrap();
        assert!(verify(&token, &signer.public_key(), NOW + 50).is_ok());
        assert!(matches!(
            verify(&token, &signer.public_key(), NOW + 4000),
            Err(TokenError::Expired)
        ));
    }

    #[tokio::test]
    async fn wrong_key_and_tamper_are_rejected() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let token = mint(&claims(), &signer).await.unwrap();

        // A different key can't verify.
        let other = LocalSigner::generate(TokenAlg::Es256);
        assert!(verify(&token, &other.public_key(), NOW).is_err());

        // Flipping a byte in the token breaks it.
        let mut raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&token)
            .unwrap();
        *raw.last_mut().unwrap() ^= 0x01;
        let tampered = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        assert!(verify(&tampered, &signer.public_key(), NOW).is_err());
    }

    #[tokio::test]
    async fn algorithm_confusion_is_rejected() {
        // A token signed ES256 must not verify against an Ed25519 key (and vice
        // versa) — the header alg is pinned to the key's alg.
        let es = LocalSigner::generate(TokenAlg::Es256);
        let token = mint(&claims(), &es).await.unwrap();
        let ed_key = LocalSigner::generate(TokenAlg::Ed25519).public_key();
        // (U8–U10, #1) The algorithm-pin failure now has a dedicated typed variant,
        // so algorithm confusion is detected by variant, not error text.
        assert!(matches!(
            verify(&token, &ed_key, NOW),
            Err(TokenError::AlgMismatch)
        ));
    }

    /// Negative-path hardening for the ES256 migration: a truncated signature, a tampered payload
    /// (distinct from the signature), and malformed/out-of-range raw signatures must ALL be rejected
    /// fail-closed. A migration that silently weakened verification (e.g. accepting a short or
    /// all-zero signature) would light this up.
    #[tokio::test]
    async fn es256_rejects_truncated_tampered_and_malformed_signatures() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let pubkey = signer.public_key();
        let token = mint(&claims(), &signer).await.unwrap();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&token)
            .unwrap();

        // (a) Truncating the trailing ES256 signature → rejected (never silently accepted).
        for cut in [1usize, 8, 32, 64] {
            let mut t = raw.clone();
            t.truncate(t.len() - cut);
            let tok = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&t);
            assert!(
                verify(&tok, &pubkey, NOW).is_err(),
                "a signature truncated by {cut} bytes must be rejected"
            );
        }

        // (b) Tampering a PAYLOAD byte (not the signature): the signed `ToBeSigned` no longer matches
        // the signature. The flipped byte sits in the middle third — past the 2-byte tag + protected
        // header and before the trailing 64-byte signature — so this exercises payload integrity, not
        // the separate signature-tamper case already covered above.
        let mut tp = raw.clone();
        let idx = raw.len() / 3;
        tp[idx] ^= 0x01;
        let tok = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&tp);
        assert!(
            verify(&tok, &pubkey, NOW).is_err(),
            "a tampered payload byte must be rejected"
        );

        // (c) The low-level verifier rejects malformed / out-of-range raw signatures fail-closed —
        // never a panic, never an accept.
        let tbs = b"boatramp es256 verify fixture";
        assert!(pubkey.verify(tbs, &[]).is_err(), "empty signature");
        assert!(
            pubkey.verify(tbs, &[0u8; 10]).is_err(),
            "too-short signature"
        );
        assert!(
            pubkey.verify(tbs, &[0u8; 64]).is_err(),
            "all-zero r||s is not a valid signature"
        );
        assert!(
            pubkey.verify(tbs, &[0xffu8; 64]).is_err(),
            "out-of-range r||s is not a valid signature"
        );
        assert!(
            pubkey.verify(tbs, &[0u8; 100]).is_err(),
            "over-long signature"
        );
    }

    /// Wire-compatibility KAT for the p256 0.13 → 0.14 migration. The vector below (public key +
    /// role token) was minted by the PRE-migration p256 0.13 ecosystem from the fixed private scalar
    /// `0x42…42` (captured once via a throwaway `dump_old_wire_vector` test at the parent commit).
    /// ES256/COSE is a stable on-the-wire standard and this change is API-only, so:
    ///   * the compressed-SEC1 public-key encoding (the config trust anchor) must be byte-identical, and
    ///   * a token signed by p256 0.13 must still verify under p256 0.14 (ECDSA verification is a
    ///     cross-implementation standard — there is no version-specific encoding).
    ///
    /// If verification had been weakened or the key/signature encoding changed, this test fails.
    #[test]
    fn es256_wire_compatible_with_p256_0_13_ecosystem() {
        const OLD_PRIV: &str =
            "es256:4242424242424242424242424242424242424242424242424242424242424242";
        const OLD_PUB: &str =
            "es256:033ad3861a95621392516bb593ef05583ed2e5866f5cb6260a3017237fd89b90af";
        const OLD_TOKEN: &str = "0oRDoQEmoFhNpQQaZVP_EAYaZVPxAAdQF2ifvu6xifOH1SWoT0-ezmhicl9yb2xlc4KBZWFkbWlugmlwdWJsaXNoZXJkYmxvZ2dicl9raW5kZHJvbGVYQKxi52ekr8mjJnEgRyNxqRL9wCpRyudVRDhP2jQRqHbTdlLd_EjE3pnFrJ_0iqqbyavNiuX0DSFGevuxB6Rnsk0";

        // 1) Key encoding unchanged: the same scalar re-loaded under p256 0.14 yields the same
        //    compressed-SEC1 trust anchor the old code wrote.
        let signer = LocalSigner::from_private_hex(OLD_PRIV).unwrap();
        assert_eq!(
            signer.public_key().to_hex(),
            OLD_PUB,
            "compressed-SEC1 public-key encoding must be byte-identical across the migration"
        );

        // 2) The old-ecosystem public key parses (the `from_sec1_bytes` path) and round-trips.
        let public = TokenPublicKey::from_hex(OLD_PUB).unwrap();
        assert_eq!(public.to_hex(), OLD_PUB);

        // 3) The old (p256 0.13) token verifies under the new (p256 0.14) verifier with the exact
        //    expected claims — the core old→new interop guarantee.
        let v = verify(OLD_TOKEN, &public, NOW + 60).unwrap();
        assert_eq!(v.kind, "role");
        assert_eq!(
            v.roles,
            vec![
                GrantedRole::global("admin"),
                GrantedRole::scoped("publisher", "blog"),
            ]
        );
        assert_eq!(v.exp, Some(NOW + 3600));

        // 4) It also verifies against the key re-derived from the private scalar (same identity).
        verify(OLD_TOKEN, &signer.public_key(), NOW + 60).unwrap();

        // 5) The verifier is genuinely live on the old token: past `exp` it is rejected (not a no-op
        //    accept), and a stranger key is rejected.
        assert!(matches!(
            verify(OLD_TOKEN, &public, NOW + 4000),
            Err(TokenError::Expired)
        ));
        let stranger = LocalSigner::generate(TokenAlg::Es256).public_key();
        assert!(verify(OLD_TOKEN, &stranger, NOW + 60).is_err());
    }

    #[tokio::test]
    async fn bearer_join_token_round_trips_and_yields_a_single_use_jti() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let public = signer.public_key();
        let token = mint_join(3600, NOW, &signer).await.unwrap();

        let jti = verify_join(&token, &public, NOW + 60).unwrap();
        assert!(!jti.is_empty(), "the jti is the single-use handle");
        // Stable across re-verification (the cluster spends it once).
        assert_eq!(verify_join(&token, &public, NOW + 60).unwrap(), jti);
    }

    #[tokio::test]
    async fn join_challenge_binds_the_token_key_and_time() {
        // Distinct tokens/keys/times give distinct challenges (no cross-replay).
        let a = join_challenge("jti-1", "aa01", 100);
        assert_eq!(a, join_challenge("jti-1", "aa01", 100));
        assert_ne!(a, join_challenge("jti-2", "aa01", 100));
        assert_ne!(a, join_challenge("jti-1", "bb02", 100));
        assert_ne!(a, join_challenge("jti-1", "aa01", 101));
    }

    #[tokio::test]
    async fn join_token_expires_and_rejects_foreign_key() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let token = mint_join(100, NOW, &signer).await.unwrap();
        assert!(verify_join(&token, &signer.public_key(), NOW + 50).is_ok());
        assert!(matches!(
            verify_join(&token, &signer.public_key(), NOW + 200),
            Err(TokenError::Expired)
        ));
        // A different root key can't verify it.
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        assert!(matches!(
            verify_join(&token, &stranger.public_key(), NOW),
            Err(TokenError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn attestation_round_trips_and_rejects_tamper_expiry_and_kind() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let public = root.public_key();
        let tls_spki = "302a300506032b6570032100deadbeefdeadbeefdeadbeefdeadbeef";

        // Round-trip: the attested TLS key comes back.
        let att = mint_attestation(tls_spki, 3600, NOW, &root).await.unwrap();
        assert_eq!(
            verify_attestation(&att, &public, NOW + 60).unwrap(),
            tls_spki
        );

        // Past the validity window → rejected.
        assert!(matches!(
            verify_attestation(&att, &public, NOW + 4000),
            Err(TokenError::Expired)
        ));

        // A different (non-root) key can't verify it.
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        assert!(verify_attestation(&att, &stranger.public_key(), NOW).is_err());

        // A join token (same signer) is not accepted as an attestation — the
        // `br_kind` domain separation rejects it.
        let join = mint_join(3600, NOW, &root).await.unwrap();
        assert!(matches!(
            verify_attestation(&join, &public, NOW + 60),
            Err(TokenError::Claims(_))
        ));
    }

    #[tokio::test]
    async fn member_assertion_round_trips_and_rejects_tamper_expiry_and_kind() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let public = root.public_key();
        let mesh_spki = "302a300506032b6570032100feedface00000000feedface00000000";

        // Round-trip: the vouched (node, key) comes back.
        let m = mint_member_assertion(42, mesh_spki, 3600, NOW, &root)
            .await
            .unwrap();
        let got = verify_member_assertion(&m, &public, NOW + 60).unwrap();
        assert_eq!(got.node_id, 42);
        assert_eq!(got.pubkey_hex, mesh_spki);

        // Expired → rejected.
        assert!(matches!(
            verify_member_assertion(&m, &public, NOW + 4000),
            Err(TokenError::Expired)
        ));
        // Not the root key → rejected (only the root anchor vouches for members).
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        assert!(verify_member_assertion(&m, &stranger.public_key(), NOW).is_err());
        // A bootstrap-TLS attestation is not a member assertion (domain separation).
        let att = mint_attestation(mesh_spki, 3600, NOW, &root).await.unwrap();
        assert!(matches!(
            verify_member_assertion(&att, &public, NOW + 60),
            Err(TokenError::Claims(_))
        ));
    }

    #[tokio::test]
    async fn kind_domain_separation_between_role_and_join_tokens() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let public = signer.public_key();

        // A role token presented as a join token is rejected on the kind check.
        let role = mint(&claims(), &signer).await.unwrap();
        assert!(matches!(
            verify_join(&role, &public, NOW),
            Err(TokenError::Claims(_))
        ));

        // 8(b): the ROLE verifier refuses a join token outright (domain
        // separation) — it is not returned for the caller to re-check its kind.
        let join = mint_join(3600, NOW, &signer).await.unwrap();
        assert!(matches!(
            verify(&join, &public, NOW),
            Err(TokenError::Claims(_))
        ));
    }

    #[test]
    fn p256_der_signature_converts_to_raw() {
        // Sign a message, then check the DER→raw conversion equals the native raw
        // form — the transform every DER-returning KMS (AWS/GCP) relies on.
        use p256::ecdsa::signature::Signer as _;
        use p256::elliptic_curve::Generate as _;
        let sk = p256::ecdsa::SigningKey::generate();
        let sig: p256::ecdsa::Signature = sk.sign(b"boatramp cose kms");
        let der = sig.to_der();
        let raw = super::p256_der_sig_to_raw(der.as_bytes()).unwrap();
        assert_eq!(raw.len(), 64, "raw r||s is fixed 64 bytes");
        assert_eq!(
            raw,
            sig.to_bytes().to_vec(),
            "DER→raw matches the native raw sig"
        );

        // A token whose signature we round-tripped through DER still verifies —
        // proves a KMS-style DER sig is accepted once normalized.
        let public = TokenPublicKey::Es256(*sk.verifying_key());
        public.verify(b"boatramp cose kms", &raw).unwrap();
    }

    #[test]
    fn es256_public_key_parses_from_spki_der_and_pem() {
        // A KMS `GetPublicKey` returns SPKI DER/PEM; parsing it must yield the same
        // key the raw-hex path yields.
        use p256::pkcs8::{EncodePublicKey as _, LineEnding};
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let TokenPublicKey::Es256(vk) = signer.public_key() else {
            unreachable!("generated ES256")
        };
        let der = vk.to_public_key_der().unwrap();
        let pem = vk.to_public_key_pem(LineEnding::LF).unwrap();

        let want = signer.public_key().to_hex();
        assert_eq!(
            TokenPublicKey::es256_from_spki_der(der.as_bytes())
                .unwrap()
                .to_hex(),
            want
        );
        assert_eq!(
            TokenPublicKey::es256_from_spki_pem(&pem).unwrap().to_hex(),
            want
        );
    }

    // ---- Offline delegation ------------------------------------------------

    async fn delegatable_root(
        signer: &LocalSigner,
        holder: &TokenPublicKey,
        roles: Vec<GrantedRole>,
    ) -> String {
        let claims = Claims {
            roles,
            kind: KIND_ROLE.into(),
            ttl_secs: Some(3600),
            now_unix: NOW,
        };
        mint_delegatable(&claims, holder, signer).await.unwrap()
    }

    #[tokio::test]
    async fn delegation_narrows_via_caveats() {
        use crate::authz::{Action, Resource, Right};
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let holder = LocalSigner::generate(TokenAlg::Es256);
        let token = delegatable_root(
            &root,
            &holder.public_key(),
            vec![GrantedRole::global("admin")],
        )
        .await;

        let caveats = Caveats {
            read_only: true,
            only_site: Some("blog".into()),
            ..Default::default()
        };
        let chain = attenuate(&token, &holder, &caveats, None, NOW)
            .await
            .unwrap();

        let v = verify_credential(&chain, &root_pub, NOW + 60).unwrap();
        // Roles are unchanged — the child only narrows.
        assert_eq!(v.roles, vec![GrantedRole::global("admin")]);
        assert!(v.caveats.read_only);
        assert_eq!(v.caveats.only_site.as_deref(), Some("blog"));

        let read_blog = Right::new(Resource::Site, Some("blog".into()), Action::Read);
        let write_blog = Right::new(Resource::Site, Some("blog".into()), Action::Write);
        let read_shop = Right::new(Resource::Site, Some("shop".into()), Action::Read);
        assert!(v.caveats.allows(&read_blog, NOW + 60));
        assert!(
            !v.caveats.allows(&write_blog, NOW + 60),
            "read_only blocks writes"
        );
        assert!(
            !v.caveats.allows(&read_shop, NOW + 60),
            "only_site blocks other sites"
        );

        // A plain (non-delegated) token verifies to empty caveats.
        let plain = verify_credential(&token, &root_pub, NOW + 60).unwrap();
        assert!(plain.caveats.is_empty());
        assert_eq!(plain.roles, vec![GrantedRole::global("admin")]);
    }

    #[tokio::test]
    async fn verified_chain_exposes_the_leaf_cnf() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let holder = LocalSigner::generate(TokenAlg::Es256);

        // A delegatable token's leaf_cnf is its own holder key.
        let token = delegatable_root(
            &root,
            &holder.public_key(),
            vec![GrantedRole::global("admin")],
        )
        .await;
        assert_eq!(
            verify_credential(&token, &root_pub, NOW).unwrap().leaf_cnf,
            Some(holder.public_key().to_hex())
        );

        // A plain (non-delegatable) token has no leaf_cnf.
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let plain = mint(&claims(), &signer).await.unwrap();
        assert_eq!(
            verify_credential(&plain, &signer.public_key(), NOW)
                .unwrap()
                .leaf_cnf,
            None
        );

        // A delegated chain's leaf_cnf is the *last* delegate's key, not the root's.
        let d2 = LocalSigner::generate(TokenAlg::Es256);
        let chain = attenuate(
            &token,
            &holder,
            &Caveats::default(),
            Some(&d2.public_key()),
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(
            verify_credential(&chain, &root_pub, NOW).unwrap().leaf_cnf,
            Some(d2.public_key().to_hex())
        );
    }

    #[tokio::test]
    async fn pop_proof_binds_the_request_and_rejects_mismatch() {
        let holder = LocalSigner::generate(TokenAlg::Es256);
        let public = holder.public_key();
        let ath = pop_sha256_hex(b"the-access-token-string");
        let want = PopClaims {
            htm: "PUT".into(),
            htp: canon_pop_path("/api/sites/x/config/"),
            aud: "https://cp.example.com".into(),
            ath: ath.clone(),
            bh: Some(pop_sha256_hex(b"{\"body\":1}")),
        };
        assert_eq!(want.htp, "/api/sites/x/config"); // canonicalized

        let proof = mint_pop(&want, &holder, NOW).await.unwrap();
        assert!(verify_pop(&proof, &public, NOW + 5, &want).is_ok());

        // Wrong holder key → rejected.
        let other = LocalSigner::generate(TokenAlg::Es256);
        assert!(verify_pop(&proof, &other.public_key(), NOW + 5, &want).is_err());

        // Past the freshness window / too far in the future → Expired.
        assert!(matches!(
            verify_pop(&proof, &public, NOW + POP_WINDOW_SECS + 5, &want),
            Err(TokenError::Expired)
        ));
        assert!(matches!(
            verify_pop(&proof, &public, NOW - POP_SKEW_SECS - 5, &want),
            Err(TokenError::Expired)
        ));

        // Each bound fact mismatch (incl. body present-vs-absent) → rejected.
        for bad in [
            PopClaims {
                htm: "GET".into(),
                ..want.clone()
            },
            PopClaims {
                htp: "/api/sites/y/config".into(),
                ..want.clone()
            },
            PopClaims {
                aud: "https://evil.example.com".into(),
                ..want.clone()
            },
            PopClaims {
                ath: pop_sha256_hex(b"other-token"),
                ..want.clone()
            },
            PopClaims {
                bh: Some(pop_sha256_hex(b"swapped")),
                ..want.clone()
            },
            PopClaims {
                bh: None,
                ..want.clone()
            },
        ] {
            assert!(
                verify_pop(&proof, &public, NOW + 5, &bad).is_err(),
                "must reject {bad:?}"
            );
        }

        // A role token is not a PoP proof (br_kind domain separation).
        let role = mint(&claims(), &holder).await.unwrap();
        assert!(matches!(
            verify_pop(&role, &public, NOW, &want),
            Err(TokenError::Claims(_))
        ));
    }

    #[tokio::test]
    async fn delegation_block_cannot_add_roles() {
        // The anti-escalation linchpin: a block that carries a `br_roles` claim
        // granting itself admin MUST NOT widen the credential — verify never reads
        // a block's roles.
        let root = LocalSigner::generate(TokenAlg::Es256);
        let holder = LocalSigner::generate(TokenAlg::Es256);
        let token = delegatable_root(
            &root,
            &holder.public_key(),
            vec![GrantedRole::scoped("viewer", "blog")],
        )
        .await;

        // Forge a block, signed by the *legitimate* holder, that injects admin.
        let evil = ClaimsSetBuilder::new()
            .cwt_id(random_cti().unwrap())
            .text_claim(
                CLAIM_KIND.to_string(),
                CborValue::Text(KIND_DELEGATION.to_string()),
            )
            .text_claim(
                CLAIM_ROLES.to_string(),
                roles_to_cbor(&[GrantedRole::global("admin")]),
            )
            .build();
        let evil_block = sign_claims_bytes(evil, &holder).await.unwrap();
        let mut blocks = decode_credential(&token).unwrap();
        blocks.push(evil_block);
        let chain = encode_chain(blocks).unwrap();

        let v = verify_credential(&chain, &root.public_key(), NOW).unwrap();
        assert_eq!(
            v.roles,
            vec![GrantedRole::scoped("viewer", "blog")],
            "an injected role in a delegation block must be ignored"
        );
    }

    #[tokio::test]
    async fn delegation_shortens_expiry() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let holder = LocalSigner::generate(TokenAlg::Es256);
        let token = delegatable_root(
            &root,
            &holder.public_key(),
            vec![GrantedRole::global("admin")],
        )
        .await;
        let caveats = Caveats {
            not_after: Some(NOW + 100),
            ..Default::default()
        };
        let chain = attenuate(&token, &holder, &caveats, None, NOW)
            .await
            .unwrap();
        assert!(verify_credential(&chain, &root.public_key(), NOW + 50).is_ok());
        assert!(matches!(
            verify_credential(&chain, &root.public_key(), NOW + 200),
            Err(TokenError::Expired)
        ));
    }

    #[tokio::test]
    async fn delegation_requires_the_declared_holder_key() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let holder = LocalSigner::generate(TokenAlg::Es256);
        let token = delegatable_root(
            &root,
            &holder.public_key(),
            vec![GrantedRole::global("admin")],
        )
        .await;

        // A block signed by a key other than the declared holder must not verify.
        let impostor = LocalSigner::generate(TokenAlg::Es256);
        let forged = attenuate(
            &token,
            &impostor,
            &Caveats {
                read_only: true,
                ..Default::default()
            },
            None,
            NOW,
        )
        .await
        .unwrap();
        assert!(matches!(
            verify_credential(&forged, &root.public_key(), NOW),
            Err(TokenError::Invalid(_))
        ));

        // A non-delegatable token (no `cnf`) cannot be extended at all.
        let plain = mint(&claims(), &root).await.unwrap();
        let bad = attenuate(
            &plain,
            &holder,
            &Caveats {
                read_only: true,
                ..Default::default()
            },
            None,
            NOW,
        )
        .await
        .unwrap();
        assert!(matches!(
            verify_credential(&bad, &root.public_key(), NOW),
            Err(TokenError::Claims(_))
        ));
    }

    #[tokio::test]
    async fn disjoint_site_caveats_authorize_nothing() {
        use crate::authz::{Action, Resource, Right};
        let root = LocalSigner::generate(TokenAlg::Es256);
        let h1 = LocalSigner::generate(TokenAlg::Es256);
        let h2 = LocalSigner::generate(TokenAlg::Es256);
        let token =
            delegatable_root(&root, &h1.public_key(), vec![GrantedRole::global("admin")]).await;
        // blog, delegatable to h2; then shop → an empty intersection.
        let c1 = attenuate(
            &token,
            &h1,
            &Caveats {
                only_site: Some("blog".into()),
                ..Default::default()
            },
            Some(&h2.public_key()),
            NOW,
        )
        .await
        .unwrap();
        let c2 = attenuate(
            &c1,
            &h2,
            &Caveats {
                only_site: Some("shop".into()),
                ..Default::default()
            },
            None,
            NOW,
        )
        .await
        .unwrap();
        let v = verify_credential(&c2, &root.public_key(), NOW).unwrap();
        assert!(!v.caveats.allows(
            &Right::new(Resource::Site, Some("blog".into()), Action::Read),
            NOW
        ));
        assert!(!v.caveats.allows(
            &Right::new(Resource::Site, Some("shop".into()), Action::Read),
            NOW
        ));
    }

    #[tokio::test]
    async fn chain_depth_and_size_bounds_are_enforced() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let pk = root.public_key();
        // Depth: a chain with more than MAX_CHAIN_DEPTH blocks is refused before
        // any block is verified (dummy blocks suffice).
        let one = decode_credential(&mint(&claims(), &root).await.unwrap())
            .unwrap()
            .pop()
            .unwrap();
        let deep = encode_chain(vec![one; MAX_CHAIN_DEPTH + 1]).unwrap();
        assert!(matches!(
            verify_credential(&deep, &pk, NOW),
            Err(TokenError::Bounds(_))
        ));

        // Size: a credential larger than MAX_CHAIN_BYTES is refused before parsing.
        let big = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(vec![0x80u8; MAX_CHAIN_BYTES + 1]);
        assert!(matches!(
            verify_credential(&big, &pk, NOW),
            Err(TokenError::Bounds(_))
        ));
    }

    #[test]
    fn keys_round_trip_through_hex() {
        for alg in [TokenAlg::Es256, TokenAlg::Ed25519] {
            let signer = LocalSigner::generate(alg);
            let priv_hex = signer.private_hex();
            let pub_hex = signer.public_key().to_hex();
            let restored = LocalSigner::from_private_hex(&priv_hex).unwrap();
            assert_eq!(restored.public_key().to_hex(), pub_hex);
            assert_eq!(
                TokenPublicKey::from_hex(&pub_hex).unwrap().to_hex(),
                pub_hex
            );
        }
    }

    // ---- S3-ingress session token (KIND_S3_SESSION) --------------------------------------------

    fn s3_scope_key() -> S3SessionScope {
        S3SessionScope {
            project: "acme".into(),
            site: "blog".into(),
            container: "uploads".into(),
            target: S3Target::Key("avatars/u1/pic.jpg".into()),
            perms: vec![S3Perm::Put],
            constraints: S3Constraints {
                max_bytes: Some(5 * 1024 * 1024),
                content_type: Some("image/*".into()),
                require_sha256: false,
                create_only: true,
            },
        }
    }

    fn s3_scope_prefix() -> S3SessionScope {
        S3SessionScope {
            project: "acme".into(),
            site: "blog".into(),
            container: "bulk".into(),
            target: S3Target::Prefix("ingest/2026/".into()),
            perms: vec![S3Perm::Put, S3Perm::Multipart],
            constraints: S3Constraints {
                max_bytes: None,
                content_type: None,
                require_sha256: true,
                create_only: false,
            },
        }
    }

    #[tokio::test]
    async fn s3_session_round_trips_the_full_scope() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let public = signer.public_key();
        for scope in [s3_scope_key(), s3_scope_prefix()] {
            let token = mint_s3_session(&scope, 300, NOW, &signer).await.unwrap();
            let v = verify_s3_session(&token, &public, NOW + 60).unwrap();
            assert_eq!(
                v.scope, scope,
                "the verified scope must equal what was minted"
            );
            assert_eq!(v.exp, NOW + 300);
            assert!(!v.cti.is_empty());
        }
    }

    #[tokio::test]
    async fn s3_session_is_domain_separated_from_every_other_kind() {
        // An S3 session must NOT verify as any other token kind, and no other kind may verify as an
        // S3 session — the exact `br_kind` check on both sides is the whole isolation guarantee.
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let public = signer.public_key();

        // (a) An S3-session token cannot be redeemed as a role / capability / context / session /
        //     join token. Since 8(b), the role verifier `verify()` enforces `br_kind == KIND_ROLE`,
        //     so it REFUSES the s3-session outright (the strongest domain separation); every
        //     strongly-typed verifier likewise rejects it via its own exact-kind check.
        let s3 = mint_s3_session(&s3_scope_key(), 300, NOW, &signer)
            .await
            .unwrap();
        assert!(
            matches!(verify(&s3, &public, NOW + 1), Err(TokenError::Claims(_))),
            "an s3-session must be refused by the role verifier (domain separation)"
        );
        assert!(verify_capability(&s3, &public, NOW + 1, "acme").is_err());
        assert!(verify_context(&s3, &public, NOW + 1).is_err());
        assert!(verify_session(&s3, &public, NOW + 1).is_err());
        assert!(verify_join(&s3, &public, NOW + 1).is_err());

        // (b) A role token, a session cookie, a signed-context envelope, and a capability all fail
        //     the s3-session kind check.
        let role = mint(&claims(), &signer).await.unwrap();
        assert!(matches!(
            verify_s3_session(&role, &public, NOW + 1),
            Err(TokenError::Claims(_)),
        ));
        let sess = mint_session("sid-1", 300, NOW, &signer).await.unwrap();
        assert!(matches!(
            verify_s3_session(&sess, &public, NOW + 1),
            Err(TokenError::Claims(_)),
        ));
        let ctx = mint_context("tenant-a", None, 300, NOW, &signer)
            .await
            .unwrap();
        assert!(matches!(
            verify_s3_session(&ctx, &public, NOW + 1),
            Err(TokenError::Claims(_)),
        ));
        let cap = mint_capability(
            "tenant-b",
            "acme",
            "public",
            &std::collections::BTreeMap::new(),
            300,
            NOW,
            &signer,
        )
        .await
        .unwrap();
        assert!(matches!(
            verify_s3_session(&cap, &public, NOW + 1),
            Err(TokenError::Claims(_)),
        ));
    }

    #[tokio::test]
    async fn s3_session_rejects_expired_and_a_foreign_signer() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let public = signer.public_key();
        let token = mint_s3_session(&s3_scope_key(), 300, NOW, &signer)
            .await
            .unwrap();

        // Expired (verifying past `exp`) fails closed.
        assert!(matches!(
            verify_s3_session(&token, &public, NOW + 301),
            Err(TokenError::Expired),
        ));

        // A different fleet key cannot verify it (signature check).
        let stranger = LocalSigner::generate(TokenAlg::Es256).public_key();
        assert!(matches!(
            verify_s3_session(&token, &stranger, NOW + 1),
            Err(TokenError::Invalid(_)),
        ));
    }

    #[tokio::test]
    async fn s3_session_requires_a_mandatory_exp() {
        // Hand-build a KIND_S3_SESSION claim set with NO expiry; verify must refuse it (an expiry is
        // mandatory for an ingress credential, regardless of who minted the token).
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let public = signer.public_key();
        let claims = ClaimsSetBuilder::new()
            .issued_at(Timestamp::WholeSeconds(NOW as i64))
            .cwt_id(random_cti().unwrap())
            .text_claim(
                CLAIM_KIND.to_string(),
                CborValue::Text(KIND_S3_SESSION.to_string()),
            )
            .text_claim(CLAIM_S3.to_string(), s3_scope_key().to_cbor())
            .build();
        let token = sign_claims(claims, &signer).await.unwrap();
        assert!(matches!(
            verify_s3_session(&token, &public, NOW + 1),
            Err(TokenError::Claims(_)),
        ));
    }

    #[test]
    fn s3_scope_from_cbor_fails_closed_on_malformed_shapes() {
        // A garbled scope must never decode to a usable (widened) grant.
        // Both key AND prefix present ⇒ None.
        let both = CborValue::Map(vec![
            (
                CborValue::Text("project".into()),
                CborValue::Text("p".into()),
            ),
            (CborValue::Text("site".into()), CborValue::Text("s".into())),
            (
                CborValue::Text("container".into()),
                CborValue::Text("c".into()),
            ),
            (CborValue::Text("key".into()), CborValue::Text("k".into())),
            (
                CborValue::Text("prefix".into()),
                CborValue::Text("pre/".into()),
            ),
            (
                CborValue::Text("perms".into()),
                CborValue::Array(vec![CborValue::Text("put".into())]),
            ),
            (
                CborValue::Text("constraints".into()),
                CborValue::Map(vec![]),
            ),
        ]);
        assert!(S3SessionScope::from_cbor(&both).is_none());

        // Neither key nor prefix ⇒ None.
        let neither = CborValue::Map(vec![
            (
                CborValue::Text("project".into()),
                CborValue::Text("p".into()),
            ),
            (CborValue::Text("site".into()), CborValue::Text("s".into())),
            (
                CborValue::Text("container".into()),
                CborValue::Text("c".into()),
            ),
            (
                CborValue::Text("perms".into()),
                CborValue::Array(vec![CborValue::Text("put".into())]),
            ),
            (
                CborValue::Text("constraints".into()),
                CborValue::Map(vec![]),
            ),
        ]);
        assert!(S3SessionScope::from_cbor(&neither).is_none());

        // Empty perm set ⇒ None (an ingress cred that authorizes nothing is refused, not "allow").
        let no_perms = CborValue::Map(vec![
            (
                CborValue::Text("project".into()),
                CborValue::Text("p".into()),
            ),
            (CborValue::Text("site".into()), CborValue::Text("s".into())),
            (
                CborValue::Text("container".into()),
                CborValue::Text("c".into()),
            ),
            (CborValue::Text("key".into()), CborValue::Text("k".into())),
            (CborValue::Text("perms".into()), CborValue::Array(vec![])),
            (
                CborValue::Text("constraints".into()),
                CborValue::Map(vec![]),
            ),
        ]);
        assert!(S3SessionScope::from_cbor(&no_perms).is_none());

        // Missing a required field (no container) ⇒ None.
        let missing = CborValue::Map(vec![
            (
                CborValue::Text("project".into()),
                CborValue::Text("p".into()),
            ),
            (CborValue::Text("site".into()), CborValue::Text("s".into())),
            (CborValue::Text("key".into()), CborValue::Text("k".into())),
            (
                CborValue::Text("perms".into()),
                CborValue::Array(vec![CborValue::Text("put".into())]),
            ),
            (
                CborValue::Text("constraints".into()),
                CborValue::Map(vec![]),
            ),
        ]);
        assert!(S3SessionScope::from_cbor(&missing).is_none());
    }

    #[tokio::test]
    async fn s3_session_scope_is_tamper_evident() {
        // Flipping a byte of the signed token (which contains the scope) breaks the signature — a
        // client cannot edit the carried scope to widen its container/key/perms.
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let public = signer.public_key();
        let token = mint_s3_session(&s3_scope_key(), 300, NOW, &signer)
            .await
            .unwrap();
        let mut raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&token)
            .unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0x01;
        let tampered = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw);
        assert!(verify_s3_session(&tampered, &public, NOW + 1).is_err());
    }

    #[tokio::test]
    async fn overlay_dial_round_trips_and_requires_an_expiry() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let holder = LocalSigner::generate(TokenAlg::Es256);
        let holder_pub = holder.public_key();

        // A properly-minted capability (exp = now + ttl) verifies and carries holder + scope.
        let good = mint_overlay_dial(&holder_pub, "svc/db", 300, NOW, &root)
            .await
            .unwrap();
        let v = verify_overlay_dial(&good, &root_pub, NOW).unwrap();
        assert_eq!(v.holder, holder_pub.to_hex());
        assert_eq!(v.scope, "svc/db");

        // A token with NO `exp` claim — otherwise identical and correctly signed — is REFUSED
        // (LOW-3): an overlay-dial capability is never treated as immortal.
        let no_exp = ClaimsSetBuilder::new()
            .issued_at(Timestamp::WholeSeconds(NOW as i64))
            .cwt_id(random_cti().unwrap())
            .text_claim(
                CLAIM_KIND.to_string(),
                CborValue::Text(KIND_OVERLAY_DIAL.to_string()),
            )
            .text_claim(CLAIM_CNF.to_string(), CborValue::Text(holder_pub.to_hex()))
            .text_claim(
                CLAIM_OVERLAY_SCOPE.to_string(),
                CborValue::Text("svc/db".to_string()),
            )
            .build();
        let no_exp = sign_claims(no_exp, &root).await.unwrap();
        assert!(
            matches!(
                verify_overlay_dial(&no_exp, &root_pub, NOW),
                Err(TokenError::Claims(_))
            ),
            "an overlay-dial capability with no expiry must be refused"
        );
    }

    #[tokio::test]
    async fn overlay_publish_round_trips_and_requires_an_expiry() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let holder = LocalSigner::generate(TokenAlg::Ed25519);
        let holder_pub = holder.public_key();

        // A properly-minted capability (exp = now + ttl) verifies and carries holder + scope + exp.
        let good = mint_overlay_publish(&holder_pub, "svc/db", 300, NOW, &root)
            .await
            .unwrap();
        let v = verify_overlay_publish(&good, &root_pub, NOW).unwrap();
        assert_eq!(v.holder, holder_pub.to_hex());
        assert_eq!(v.scope, "svc/db");
        assert_eq!(v.exp, NOW + 300);

        // A token with NO `exp` claim — otherwise identical and correctly signed — is REFUSED: an
        // overlay-publish capability is never treated as immortal.
        let no_exp = ClaimsSetBuilder::new()
            .issued_at(Timestamp::WholeSeconds(NOW as i64))
            .cwt_id(random_cti().unwrap())
            .text_claim(
                CLAIM_KIND.to_string(),
                CborValue::Text(KIND_OVERLAY_PUBLISH.to_string()),
            )
            .text_claim(CLAIM_CNF.to_string(), CborValue::Text(holder_pub.to_hex()))
            .text_claim(
                CLAIM_OVERLAY_SCOPE.to_string(),
                CborValue::Text("svc/db".to_string()),
            )
            .build();
        let no_exp = sign_claims(no_exp, &root).await.unwrap();
        assert!(
            matches!(
                verify_overlay_publish(&no_exp, &root_pub, NOW),
                Err(TokenError::Claims(_))
            ),
            "an overlay-publish capability with no expiry must be refused"
        );
    }

    #[tokio::test]
    async fn overlay_publish_rejects_a_wrong_trust_root_and_an_expired_token() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let impostor = LocalSigner::generate(TokenAlg::Es256);
        let holder = LocalSigner::generate(TokenAlg::Ed25519);
        let holder_pub = holder.public_key();
        let token = mint_overlay_publish(&holder_pub, "svc/db", 300, NOW, &root)
            .await
            .unwrap();

        // Verified against the WRONG root → the signature check fails.
        assert!(
            verify_overlay_publish(&token, &impostor.public_key(), NOW).is_err(),
            "a publish capability from a different trust root must be refused"
        );
        // Evaluated past expiry → refused.
        assert!(
            verify_overlay_publish(&token, &root.public_key(), NOW + 600).is_err(),
            "an expired publish capability must be refused"
        );
    }

    /// Domain separation (the load-bearing `br_kind` check): an overlay-DIAL token never verifies as a
    /// publish capability, and an overlay-PUBLISH token never verifies as a dial capability — so a
    /// capability minted for one direction can never be redeemed for the other.
    #[tokio::test]
    async fn overlay_publish_and_dial_are_domain_separated() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let holder = LocalSigner::generate(TokenAlg::Ed25519);
        let holder_pub = holder.public_key();

        let dial = mint_overlay_dial(&holder_pub, "svc/db", 300, NOW, &root)
            .await
            .unwrap();
        let publish = mint_overlay_publish(&holder_pub, "svc/db", 300, NOW, &root)
            .await
            .unwrap();

        assert!(
            matches!(
                verify_overlay_publish(&dial, &root_pub, NOW),
                Err(TokenError::Claims(_))
            ),
            "an overlay-dial token must not verify as an overlay-publish capability"
        );
        assert!(
            matches!(
                verify_overlay_dial(&publish, &root_pub, NOW),
                Err(TokenError::Claims(_))
            ),
            "an overlay-publish token must not verify as an overlay-dial capability"
        );
    }

    #[tokio::test]
    async fn overlay_pairing_park_round_trips_and_requires_an_expiry() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let holder = LocalSigner::generate(TokenAlg::Ed25519);
        let holder_pub = holder.public_key();

        // A properly-minted capability (exp = now + ttl) verifies and carries holder + exp.
        let good = mint_overlay_pairing_park(&holder_pub, 300, NOW, &root)
            .await
            .unwrap();
        let v = verify_overlay_pairing_park(&good, &root_pub, NOW).unwrap();
        assert_eq!(v.holder, holder_pub.to_hex());
        assert_eq!(v.exp, NOW + 300);

        // A token with NO `exp` claim — otherwise identical and correctly signed — is REFUSED: an
        // overlay-pairing-park capability is never treated as immortal.
        let no_exp = ClaimsSetBuilder::new()
            .issued_at(Timestamp::WholeSeconds(NOW as i64))
            .cwt_id(random_cti().unwrap())
            .text_claim(
                CLAIM_KIND.to_string(),
                CborValue::Text(KIND_OVERLAY_PAIRING_PARK.to_string()),
            )
            .text_claim(CLAIM_CNF.to_string(), CborValue::Text(holder_pub.to_hex()))
            .build();
        let no_exp = sign_claims(no_exp, &root).await.unwrap();
        assert!(
            matches!(
                verify_overlay_pairing_park(&no_exp, &root_pub, NOW),
                Err(TokenError::Claims(_))
            ),
            "an overlay-pairing-park capability with no expiry must be refused"
        );
    }

    #[tokio::test]
    async fn overlay_pairing_park_rejects_a_wrong_trust_root_and_an_expired_token() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let impostor = LocalSigner::generate(TokenAlg::Es256);
        let holder = LocalSigner::generate(TokenAlg::Ed25519);
        let holder_pub = holder.public_key();
        let token = mint_overlay_pairing_park(&holder_pub, 300, NOW, &root)
            .await
            .unwrap();

        // Verified against the WRONG root → the signature check fails.
        assert!(
            verify_overlay_pairing_park(&token, &impostor.public_key(), NOW).is_err(),
            "a pairing-park capability from a different trust root must be refused"
        );
        // Evaluated past expiry → refused.
        assert!(
            verify_overlay_pairing_park(&token, &root.public_key(), NOW + 600).is_err(),
            "an expired pairing-park capability must be refused"
        );
    }

    /// Domain separation (the load-bearing `br_kind` check), BOTH ways: an overlay-PUBLISH/-DIAL token
    /// never verifies as a pairing-park capability, and a pairing-park capability never verifies as a
    /// publish/dial capability — so a capability minted for one purpose can never be redeemed as
    /// another.
    #[tokio::test]
    async fn overlay_pairing_park_is_domain_separated_from_publish_and_dial() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let holder = LocalSigner::generate(TokenAlg::Ed25519);
        let holder_pub = holder.public_key();

        let dial = mint_overlay_dial(&holder_pub, "svc/db", 300, NOW, &root)
            .await
            .unwrap();
        let publish = mint_overlay_publish(&holder_pub, "svc/db", 300, NOW, &root)
            .await
            .unwrap();
        let park = mint_overlay_pairing_park(&holder_pub, 300, NOW, &root)
            .await
            .unwrap();

        assert!(
            matches!(
                verify_overlay_pairing_park(&dial, &root_pub, NOW),
                Err(TokenError::Claims(_))
            ),
            "an overlay-dial token must not verify as a pairing-park capability"
        );
        assert!(
            matches!(
                verify_overlay_pairing_park(&publish, &root_pub, NOW),
                Err(TokenError::Claims(_))
            ),
            "an overlay-publish token must not verify as a pairing-park capability"
        );
        assert!(
            matches!(
                verify_overlay_dial(&park, &root_pub, NOW),
                Err(TokenError::Claims(_))
            ),
            "a pairing-park token must not verify as an overlay-dial capability"
        );
        assert!(
            matches!(
                verify_overlay_publish(&park, &root_pub, NOW),
                Err(TokenError::Claims(_))
            ),
            "a pairing-park token must not verify as an overlay-publish capability"
        );
    }

    // --- overlay enrollment & pairing: enroll invitation + membership credential ----------------

    #[tokio::test]
    async fn overlay_enroll_round_trips_and_requires_an_expiry() {
        let root = LocalSigner::generate(TokenAlg::Ed25519);
        let root_pub = root.public_key();

        // A properly-minted invitation (exp = now + ttl) verifies and carries role + scope + a
        // single-use jti; it is deliberately NOT holder-bound (no cnf), like the cluster join token.
        let good = mint_overlay_enroll(OverlayMemberRole::Device, "svc/db", 300, NOW, &root)
            .await
            .unwrap();
        let v = verify_overlay_enroll(&good, &root_pub, NOW).unwrap();
        assert_eq!(v.role, OverlayMemberRole::Device);
        assert_eq!(v.scope, "svc/db");
        assert_eq!(v.exp, NOW + 300);
        assert!(!v.jti.is_empty(), "the jti is the single-use handle");
        // Stable across re-verification (the control plane spends it once).
        assert_eq!(
            verify_overlay_enroll(&good, &root_pub, NOW).unwrap().jti,
            v.jti
        );

        // A token with NO `exp` claim — otherwise identical and correctly signed — is REFUSED: an
        // enrollment invitation is never treated as immortal.
        let no_exp = ClaimsSetBuilder::new()
            .issued_at(Timestamp::WholeSeconds(NOW as i64))
            .cwt_id(random_cti().unwrap())
            .text_claim(
                CLAIM_KIND.to_string(),
                CborValue::Text(KIND_OVERLAY_ENROLL.to_string()),
            )
            .text_claim(
                CLAIM_OVERLAY_ROLE.to_string(),
                CborValue::Text("device".to_string()),
            )
            .text_claim(
                CLAIM_OVERLAY_SCOPE.to_string(),
                CborValue::Text("svc/db".to_string()),
            )
            .build();
        let no_exp = sign_claims(no_exp, &root).await.unwrap();
        assert!(
            matches!(
                verify_overlay_enroll(&no_exp, &root_pub, NOW),
                Err(TokenError::Claims(_))
            ),
            "an overlay-enroll invitation with no expiry must be refused"
        );
    }

    #[tokio::test]
    async fn overlay_enroll_rejects_an_unknown_role_fail_closed() {
        // Only the root signs an invitation, but an unknown/typo'd role is still refused rather than
        // silently accepted — the role set is closed (defense in depth).
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let bogus = ClaimsSetBuilder::new()
            .issued_at(Timestamp::WholeSeconds(NOW as i64))
            .cwt_id(random_cti().unwrap())
            .expiration_time(Timestamp::WholeSeconds((NOW + 300) as i64))
            .text_claim(
                CLAIM_KIND.to_string(),
                CborValue::Text(KIND_OVERLAY_ENROLL.to_string()),
            )
            .text_claim(
                CLAIM_OVERLAY_ROLE.to_string(),
                CborValue::Text("admin".to_string()),
            )
            .text_claim(
                CLAIM_OVERLAY_SCOPE.to_string(),
                CborValue::Text("*".to_string()),
            )
            .build();
        let bogus = sign_claims(bogus, &root).await.unwrap();
        assert!(matches!(
            verify_overlay_enroll(&bogus, &root_pub, NOW),
            Err(TokenError::Claims(_))
        ));
    }

    #[tokio::test]
    async fn overlay_member_round_trips_and_requires_an_expiry() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let member = LocalSigner::generate(TokenAlg::Ed25519);
        let member_pub = member.public_key();

        // Round-trip: the vouched (member key, role, scope, exp) comes back.
        let m = mint_overlay_member(
            &member_pub,
            OverlayMemberRole::Node,
            "svc/*",
            3600,
            NOW,
            &root,
        )
        .await
        .unwrap();
        let v = verify_overlay_member(&m, &root_pub, NOW + 60).unwrap();
        assert_eq!(v.member_key, member_pub.to_hex());
        assert_eq!(v.role, OverlayMemberRole::Node);
        assert_eq!(v.scope, "svc/*");
        assert_eq!(v.exp, NOW + 3600);

        // A token with NO `exp` — otherwise identical and correctly signed — is REFUSED.
        let no_exp = ClaimsSetBuilder::new()
            .issued_at(Timestamp::WholeSeconds(NOW as i64))
            .cwt_id(random_cti().unwrap())
            .text_claim(
                CLAIM_KIND.to_string(),
                CborValue::Text(KIND_OVERLAY_MEMBER.to_string()),
            )
            .text_claim(
                CLAIM_PUBKEY.to_string(),
                CborValue::Text(member_pub.to_hex()),
            )
            .text_claim(
                CLAIM_OVERLAY_ROLE.to_string(),
                CborValue::Text("node".to_string()),
            )
            .text_claim(
                CLAIM_OVERLAY_SCOPE.to_string(),
                CborValue::Text("svc/*".to_string()),
            )
            .build();
        let no_exp = sign_claims(no_exp, &root).await.unwrap();
        assert!(matches!(
            verify_overlay_member(&no_exp, &root_pub, NOW),
            Err(TokenError::Claims(_))
        ));
    }

    #[tokio::test]
    async fn overlay_enroll_and_member_reject_a_wrong_root_and_an_expired_token() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let impostor = LocalSigner::generate(TokenAlg::Es256);
        let member = LocalSigner::generate(TokenAlg::Ed25519);
        let member_pub = member.public_key();

        let enroll = mint_overlay_enroll(OverlayMemberRole::Workload, "svc/db", 300, NOW, &root)
            .await
            .unwrap();
        let memtok = mint_overlay_member(
            &member_pub,
            OverlayMemberRole::Workload,
            "svc/db",
            300,
            NOW,
            &root,
        )
        .await
        .unwrap();

        // Verified against the WRONG root → the signature check fails.
        assert!(
            matches!(
                verify_overlay_enroll(&enroll, &impostor.public_key(), NOW),
                Err(TokenError::Invalid(_))
            ),
            "an enroll invitation from a different trust root must be refused"
        );
        assert!(
            matches!(
                verify_overlay_member(&memtok, &impostor.public_key(), NOW),
                Err(TokenError::Invalid(_))
            ),
            "a membership credential from a different trust root must be refused"
        );

        // Evaluated past expiry → refused.
        assert!(matches!(
            verify_overlay_enroll(&enroll, &root.public_key(), NOW + 600),
            Err(TokenError::Expired)
        ));
        assert!(matches!(
            verify_overlay_member(&memtok, &root.public_key(), NOW + 600),
            Err(TokenError::Expired)
        ));
    }

    /// The load-bearing domain separation (the `br_kind` check), BOTH ways: an overlay-enroll /
    /// overlay-member token is rejected by every OTHER kind's verifier, and an enroll/member verifier
    /// rejects every other kind — so a token minted for one purpose can never be redeemed as another.
    #[tokio::test]
    async fn overlay_enroll_and_member_are_domain_separated_from_every_other_kind() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let holder = LocalSigner::generate(TokenAlg::Ed25519);
        let holder_pub = holder.public_key();

        let enroll = mint_overlay_enroll(OverlayMemberRole::Device, "svc/db", 300, NOW, &root)
            .await
            .unwrap();
        let member = mint_overlay_member(
            &holder_pub,
            OverlayMemberRole::Device,
            "svc/db",
            300,
            NOW,
            &root,
        )
        .await
        .unwrap();
        let join = mint_join(300, NOW, &root).await.unwrap();
        let dial = mint_overlay_dial(&holder_pub, "svc/db", 300, NOW, &root)
            .await
            .unwrap();
        let publish = mint_overlay_publish(&holder_pub, "svc/db", 300, NOW, &root)
            .await
            .unwrap();

        // An enroll / member token is rejected by join / dial / publish verifiers (the `br_kind`
        // check). verify_join does NOT enforce exp-presence, so a wrong-kind token yields Claims.
        for (label, tok) in [("enroll", &enroll), ("member", &member)] {
            assert!(
                matches!(verify_join(tok, &root_pub, NOW), Err(TokenError::Claims(_))),
                "{label} must not verify as a join token"
            );
            assert!(
                matches!(
                    verify_overlay_dial(tok, &root_pub, NOW),
                    Err(TokenError::Claims(_))
                ),
                "{label} must not verify as an overlay-dial capability"
            );
            assert!(
                matches!(
                    verify_overlay_publish(tok, &root_pub, NOW),
                    Err(TokenError::Claims(_))
                ),
                "{label} must not verify as an overlay-publish capability"
            );
        }

        // And the reverse: a join / dial / publish token is rejected by the enroll AND member
        // verifiers.
        for (label, tok) in [("join", &join), ("dial", &dial), ("publish", &publish)] {
            assert!(
                matches!(
                    verify_overlay_enroll(tok, &root_pub, NOW),
                    Err(TokenError::Claims(_))
                ),
                "{label} must not verify as an overlay-enroll invitation"
            );
            assert!(
                matches!(
                    verify_overlay_member(tok, &root_pub, NOW),
                    Err(TokenError::Claims(_))
                ),
                "{label} must not verify as an overlay-member credential"
            );
        }

        // enroll and member are also separated from EACH OTHER.
        assert!(
            matches!(
                verify_overlay_member(&enroll, &root_pub, NOW),
                Err(TokenError::Claims(_))
            ),
            "an enroll invitation must not verify as a membership credential"
        );
        assert!(
            matches!(
                verify_overlay_enroll(&member, &root_pub, NOW),
                Err(TokenError::Claims(_))
            ),
            "a membership credential must not verify as an enroll invitation"
        );
    }

    /// The enrollee's possession proof REUSES [`join_challenge`] verbatim (no new challenge
    /// primitive): the enrollee signs `join_challenge(enroll_jti, overlay_key_hex, iat)` with its
    /// overlay key, and the control plane verifies it against the presented key — exactly as a cluster
    /// joiner proves possession of its mesh key.
    #[tokio::test]
    async fn overlay_enroll_possession_proof_reuses_join_challenge() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let enrollee = LocalSigner::generate(TokenAlg::Ed25519);
        let enrollee_pub = enrollee.public_key();

        let enroll = mint_overlay_enroll(OverlayMemberRole::Device, "svc/db", 300, NOW, &root)
            .await
            .unwrap();
        let v = verify_overlay_enroll(&enroll, &root_pub, NOW).unwrap();

        // Enrollee proves possession of its overlay key over the SAME challenge primitive.
        let proof_iat = NOW + 1;
        let challenge = join_challenge(&v.jti, &enrollee_pub.to_hex(), proof_iat);
        let sig = enrollee.sign(&challenge).await.unwrap();
        assert!(
            enrollee_pub.verify(&challenge, &sig).is_ok(),
            "a valid possession proof over join_challenge verifies"
        );
        // A proof naming a DIFFERENT jti does not verify against this challenge (no cross-replay).
        let other = join_challenge("different-jti", &enrollee_pub.to_hex(), proof_iat);
        assert!(enrollee_pub.verify(&other, &sig).is_err());
    }

    // ---- C1: sealed presentation (chain-prefix truncation) -----------------

    /// Reproduce-first exploit witness + fix with boatramp's REAL vocabulary
    /// (roles + `Caveats`): a holder of an intermediate `cnf` key strips the
    /// trailing narrowing block and presents the root prefix to recover the parent's
    /// un-narrowed (WRITE) authority — `verify_credential` accepts it; the fix
    /// `verify_presented` refuses it (unsealed leaf), yet still verifies + narrows a
    /// legitimately-sealed chain. (uchron RFC-009 §7, C1.)
    #[tokio::test]
    async fn verify_presented_refuses_a_truncated_prefix_and_accepts_a_sealed_narrowed_chain() {
        use crate::authz::{Action, Resource, Right};
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let h1 = LocalSigner::generate(TokenAlg::Es256); // the intermediate holder
        let h2 = LocalSigner::generate(TokenAlg::Es256); // the narrowed delegate

        // root(cnf = h1) → block1(read-only + only-site=blog, cnf = h2)
        let token =
            delegatable_root(&root, &h1.public_key(), vec![GrantedRole::global("admin")]).await;
        let narrow = Caveats {
            read_only: true,
            only_site: Some("blog".into()),
            ..Default::default()
        };
        let full = attenuate(&token, &h1, &narrow, Some(&h2.public_key()), NOW)
            .await
            .unwrap();
        let write_blog = Right::new(Resource::Site, Some("blog".into()), Action::Write);

        // The legitimate full chain enforces the narrowing (no writes).
        let v_full = verify_credential(&full, &root_pub, NOW).unwrap();
        assert!(!v_full.caveats.allows(&write_blog, NOW));

        // WITNESS: strip block1, present the root prefix. Its leaf `cnf` (h1) is a key
        // the stripper holds, so `verify_credential` accepts it and the caveat is GONE.
        let stripped = verify_credential(&token, &root_pub, NOW).unwrap();
        assert!(
            stripped.caveats.is_empty(),
            "WITNESS: the narrowing vanished — authority recovered"
        );
        assert!(
            stripped.caveats.allows(&write_blog, NOW),
            "WITNESS: the stripped prefix regains WRITE the chain forbade"
        );
        assert!(
            !stripped.leaf_is_sealed(&root_pub),
            "the prefix is unsealed"
        );

        // FIX: `verify_presented` refuses the truncated prefix (unsealed leaf = h1)...
        assert!(matches!(
            verify_presented(&token, &root_pub, NOW),
            Err(TokenError::Unsealed(_))
        ));
        // ...and the full onward-delegatable chain (leaf = h2) presented without a PoP.
        assert!(matches!(
            verify_presented(&full, &root_pub, NOW),
            Err(TokenError::Unsealed(_))
        ));

        // A SEALED narrowed chain (next_holder = None) verifies AND still narrows.
        let sealed = attenuate(&token, &h1, &narrow, None, NOW).await.unwrap();
        let vs = verify_presented(&sealed, &root_pub, NOW).expect("a sealed chain verifies");
        assert!(vs.leaf_is_sealed(&root_pub));
        assert_eq!(vs.leaf_cnf, None);
        assert_eq!(vs.roles, vec![GrantedRole::global("admin")]);
        assert!(vs.caveats.allows(
            &Right::new(Resource::Site, Some("blog".into()), Action::Read),
            NOW
        ));
        assert!(
            !vs.caveats.allows(&write_blog, NOW),
            "the sealed chain still forbids writes"
        );

        // A plain (non-delegatable) role token is sealed too.
        let plain = mint(&claims(), &root).await.unwrap();
        assert!(
            verify_presented(&plain, &root_pub, NOW)
                .unwrap()
                .leaf_is_sealed(&root_pub)
        );
    }

    /// A terminal block naming the ROOT's own key is a sealed endpoint (issuer
    /// re-root): a client never holds the root signing key.
    #[tokio::test]
    async fn verify_presented_treats_a_root_keyed_leaf_as_sealed() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let h1 = LocalSigner::generate(TokenAlg::Es256);
        let token =
            delegatable_root(&root, &h1.public_key(), vec![GrantedRole::global("admin")]).await;
        let chain = attenuate(
            &token,
            &h1,
            &Caveats {
                read_only: true,
                ..Default::default()
            },
            Some(&root_pub),
            NOW,
        )
        .await
        .unwrap();
        let v = verify_presented(&chain, &root_pub, NOW)
            .expect("a leaf naming the root key is a sealed endpoint");
        assert_eq!(v.leaf_cnf, Some(root_pub.to_hex()));
        assert!(v.leaf_is_sealed(&root_pub));
    }

    // ---- 8(b): the role verifier requires its kind -------------------------

    /// `verify` (the role path) accepts ONLY `br_kind == KIND_ROLE`; a join token,
    /// and a `cluster-write` capability, are refused. The `cluster-write` kind has a
    /// dedicated verifier that accepts it and rejects a role token (domain separation).
    #[tokio::test]
    async fn verify_requires_the_role_kind_and_cluster_write_has_its_own() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let public = signer.public_key();

        let role = mint(&claims(), &signer).await.unwrap();
        assert!(verify(&role, &public, NOW).is_ok());

        let join = mint_join(3600, NOW, &signer).await.unwrap();
        assert!(matches!(
            verify(&join, &public, NOW),
            Err(TokenError::Claims(_))
        ));

        let cw = mint(
            &Claims {
                roles: vec![GrantedRole::global("cluster-write")],
                kind: KIND_CLUSTER_WRITE.to_string(),
                ttl_secs: Some(3600),
                now_unix: NOW,
            },
            &signer,
        )
        .await
        .unwrap();
        // The role verifier refuses the cluster-write kind...
        assert!(matches!(
            verify(&cw, &public, NOW),
            Err(TokenError::Claims(_))
        ));
        // ...its kind-checked sibling accepts it and returns the grant...
        let v = verify_cluster_write(&cw, &public, NOW).unwrap();
        assert!(v.roles.iter().any(|r| r.name == "cluster-write"));
        // ...and the sibling refuses a role token (reverse domain separation).
        assert!(matches!(
            verify_cluster_write(&role, &public, NOW),
            Err(TokenError::Claims(_))
        ));
    }

    /// M1 — the CHAIN/role-gate path (`verify_credential`/`verify_presented`/
    /// `verify_credential_unexpired`, all via `project_chain`, which feeds RBAC,
    /// whoami, and the preview gate) must enforce the root kind too, not only
    /// `cose::verify`. A per-node `cluster-write` capability (kind=cluster-write,
    /// roles=[cluster-write], NO cnf ⇒ SEALED and non-expiring, root-signed) must
    /// NOT be accepted as a role credential at those gates — C1 can't reject it
    /// (it's sealed), so only the kind check does. **Mutation-proof:** removing the
    /// `project_chain` kind check makes these entry points ACCEPT the capability and
    /// disclose its role, reddening this test.
    #[tokio::test]
    async fn the_chain_path_refuses_a_non_role_root() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let public = signer.public_key();

        // The per-node cluster-write capability: non-role kind, sealed (no cnf),
        // non-expiring — exactly the shape `build_mesh_write_gate` mints.
        let cw = mint(
            &Claims {
                roles: vec![GrantedRole::global("cluster-write")],
                kind: KIND_CLUSTER_WRITE.to_string(),
                ttl_secs: None,
                now_unix: NOW,
            },
            &signer,
        )
        .await
        .unwrap();
        // It is sealed (so C1's verify_presented would not reject it on sealing)...
        assert!(
            verify_credential(&cw, &public, NOW)
                .err()
                .is_some_and(|e| matches!(e, TokenError::Claims(_))),
            "the chain path must refuse a non-role (cluster-write) root"
        );
        // ...yet every project_chain entry point refuses it on the kind check.
        assert!(matches!(
            verify_presented(&cw, &public, NOW),
            Err(TokenError::Claims(_))
        ));
        assert!(matches!(
            verify_credential_unexpired(&cw, &public),
            Err(TokenError::Claims(_))
        ));

        // No legitimate flow breaks: a real role token still verifies through the
        // chain path, and the mesh-write gate accepts the capability via its OWN
        // verifier (`verify_cluster_write`, which never routes through project_chain).
        let role = mint(&claims(), &signer).await.unwrap();
        assert!(verify_credential(&role, &public, NOW).is_ok());
        assert!(verify_presented(&role, &public, NOW).is_ok());
        assert!(
            verify_cluster_write(&cw, &public, NOW)
                .unwrap()
                .roles
                .iter()
                .any(|r| r.name == "cluster-write"),
            "the mesh-write gate still accepts the cluster-write capability"
        );
    }

    // ---- Ergonomics (U8–U10) at the boatramp layer -------------------------

    /// (#3) A delegation block carrying an UNKNOWN caveat restriction key refuses the
    /// whole credential with a reason, fail-closed — never a silent deny-all/drop.
    #[tokio::test]
    async fn an_unknown_caveat_key_refuses_the_credential_with_a_reason() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let h1 = LocalSigner::generate(TokenAlg::Es256);
        let token =
            delegatable_root(&root, &h1.public_key(), vec![GrantedRole::global("admin")]).await;
        // Hand-craft a delegation block whose caveats map carries an unknown key.
        let bad = CborValue::Map(vec![(
            CborValue::Text("wormhole".into()),
            CborValue::Bool(true),
        )]);
        let claims = ClaimsSetBuilder::new()
            .cwt_id(random_cti().unwrap())
            .text_claim(
                CLAIM_KIND.to_string(),
                CborValue::Text(KIND_DELEGATION.to_string()),
            )
            .text_claim(CLAIM_CAVEATS.to_string(), bad)
            .build();
        let block = sign_claims_bytes(claims, &h1).await.unwrap();
        let mut blocks = decode_credential(&token).unwrap();
        blocks.push(block);
        let chain = encode_chain(blocks).unwrap();
        let err = verify_credential(&chain, &root_pub, NOW).unwrap_err();
        assert!(
            matches!(&err, TokenError::Claims(m) if m.contains("unknown caveat")),
            "an unknown caveat key must refuse with a reason, got {err:?}"
        );
    }

    /// (#4) A deeper block that tries to EXTEND the lifetime (a looser `not_after`
    /// than in force) narrows nothing and is reported as `Widened`, instead of being
    /// silently absorbed. A block that further shortens is accepted.
    #[tokio::test]
    async fn a_block_that_extends_the_lifetime_is_reported_as_widening() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let h1 = LocalSigner::generate(TokenAlg::Es256);
        let h2 = LocalSigner::generate(TokenAlg::Es256);
        let token =
            delegatable_root(&root, &h1.public_key(), vec![GrantedRole::global("admin")]).await;
        let c1 = attenuate(
            &token,
            &h1,
            &Caveats {
                not_after: Some(NOW + 100),
                ..Default::default()
            },
            Some(&h2.public_key()),
            NOW,
        )
        .await
        .unwrap();
        // block2 names a LATER not_after (NOW+500): it narrows nothing → Widened.
        let c2 = attenuate(
            &c1,
            &h2,
            &Caveats {
                not_after: Some(NOW + 500),
                ..Default::default()
            },
            None,
            NOW,
        )
        .await
        .unwrap();
        assert!(matches!(
            verify_credential(&c2, &root_pub, NOW),
            Err(TokenError::Widened(_))
        ));
        // Control: a block that FURTHER shortens (NOW+50) is accepted.
        let c2b = attenuate(
            &c1,
            &h2,
            &Caveats {
                not_after: Some(NOW + 50),
                ..Default::default()
            },
            None,
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(
            verify_credential(&c2b, &root_pub, NOW).unwrap().exp,
            Some(NOW + 50)
        );
    }

    /// (#2) Authenticity and expiry are separate outcomes:
    /// `verify_credential_unexpired` returns an AUTHENTIC chain (roles + caveats
    /// intact) past its `exp`, carrying the effective expiry, while the enforcing
    /// `verify_credential` returns `Expired`.
    #[tokio::test]
    async fn unexpired_verify_returns_an_authentic_expired_chain() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let h1 = LocalSigner::generate(TokenAlg::Es256);
        let token =
            delegatable_root(&root, &h1.public_key(), vec![GrantedRole::global("admin")]).await;
        let narrowed = attenuate(
            &token,
            &h1,
            &Caveats {
                read_only: true,
                not_after: Some(NOW + 100),
                ..Default::default()
            },
            None,
            NOW,
        )
        .await
        .unwrap();

        assert!(matches!(
            verify_credential(&narrowed, &root_pub, NOW + 500),
            Err(TokenError::Expired)
        ));
        let v = verify_credential_unexpired(&narrowed, &root_pub).unwrap();
        assert_eq!(v.roles, vec![GrantedRole::global("admin")]);
        assert!(v.caveats.read_only);
        assert_eq!(v.exp, Some(NOW + 100));
        assert!(v.is_expired_at(NOW + 500));
        assert!(!v.is_expired_at(NOW + 50));
    }

    /// (#8) A root that self-restricts (carries a caveats claim) now has it read as
    /// the initial accumulator rather than silently ignored — fail-safe, since a
    /// root caveat can only subtract.
    #[tokio::test]
    async fn a_self_restricting_root_is_honored() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let caveats = Caveats {
            read_only: true,
            ..Default::default()
        };
        let claims = ClaimsSetBuilder::new()
            .issued_at(Timestamp::WholeSeconds(NOW as i64))
            .cwt_id(random_cti().unwrap())
            .text_claim(
                CLAIM_ROLES.to_string(),
                roles_to_cbor(&[GrantedRole::global("admin")]),
            )
            .text_claim(
                CLAIM_KIND.to_string(),
                CborValue::Text(KIND_ROLE.to_string()),
            )
            .text_claim(
                CLAIM_CAVEATS.to_string(),
                NarrowingCaveats::to_cbor(&caveats),
            )
            .build();
        let token = sign_claims(claims, &root).await.unwrap();
        let v = verify_credential(&token, &root_pub, NOW).unwrap();
        assert!(
            v.caveats.read_only,
            "a self-restricting root's caveats are honored, not ignored"
        );
        assert_eq!(v.roles, vec![GrantedRole::global("admin")]);
    }

    /// (#5, #6) The newest-first key-selection helpers and the foreign-type
    /// re-exports resolve through `boatramp_core::cose`.
    #[test]
    fn peek_helpers_and_foreign_types_are_reexported() {
        let _peek: fn(&str) -> Option<Vec<u8>> = crate::cose::peek_protected_kid;
        let _peek_claims: fn(&str) -> Result<crate::cose::ClaimsSet, TokenError> =
            crate::cose::peek_unverified_claims;
        let _v: crate::cose::CborValue = crate::cose::CborValue::Bool(true);
        let _c: crate::cose::ClaimsSet = ClaimsSetBuilder::new().build();
    }
}
