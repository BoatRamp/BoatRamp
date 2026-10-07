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

use async_trait::async_trait;
use base64::Engine as _;
use ciborium::value::Value as CborValue;
use coset::cwt::{ClaimsSet, ClaimsSetBuilder, Timestamp};
use coset::{
    Algorithm as CoseAlg, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder,
    TaggedCborSerializable, iana,
};

use boatramp_types::authz::GrantedRole;

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
/// Text claim key for a signed-context envelope's **principal class** (construens
/// `cron-system-principal`). Present (value [`SCOPE_KIND_SYSTEM`]) ONLY on a SYSTEM seal — a
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

/// Text claim key for the holder key (RFC 8747 `cnf`, here the holder's public key
/// `"<alg>:<hex>"`): the key that may mint the next delegation block. Present only
/// on a *delegatable* token / block.
const CLAIM_CNF: &str = "br_cnf";
/// Text claim key for a delegation block's narrowing caveats (a CBOR map).
const CLAIM_CAVEATS: &str = "br_caveats";

/// Max blocks in a presented delegation chain — a resource bound checked *before*
/// any signature verification.
pub const MAX_CHAIN_DEPTH: usize = 8;
/// Max serialized bytes of a presented delegation chain — bounded before parsing.
pub const MAX_CHAIN_BYTES: usize = 8 * 1024;

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

    /// Decode from the CBOR produced by [`to_cbor`](Self::to_cbor); unknown/ill-typed
    /// entries are ignored (never a panic on a hostile token).
    fn from_cbor(value: &CborValue) -> Self {
        let mut caveats = Self::default();
        let CborValue::Map(entries) = value else {
            return caveats;
        };
        for (k, v) in entries {
            let CborValue::Text(key) = k else { continue };
            match (key.as_str(), v) {
                ("only_site", CborValue::Text(s)) => caveats.only_site = Some(s.clone()),
                ("read_only", CborValue::Bool(b)) => caveats.read_only = *b,
                ("not_after", CborValue::Integer(i)) => {
                    caveats.not_after = u64::try_from(*i).ok();
                }
                _ => {}
            }
        }
        caveats
    }
}

/// The token signing algorithm. **ES256 is the portable default** (every HSM/KMS
/// can sign it); Ed25519 is offered for AWS/Vault/local deployments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenAlg {
    /// ECDSA P-256 with SHA-256 (COSE `ES256`).
    Es256,
    /// Ed25519 (COSE `EdDSA`).
    Ed25519,
}

impl TokenAlg {
    fn iana(self) -> iana::Algorithm {
        match self {
            Self::Es256 => iana::Algorithm::ES256,
            Self::Ed25519 => iana::Algorithm::EdDSA,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Es256 => "es256",
            Self::Ed25519 => "ed25519",
        }
    }
}

/// A failure minting or verifying a control-plane token.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// Key material failed to parse/load.
    #[error("token key: {0}")]
    Key(String),
    /// Building/serializing the token failed.
    #[error("token build: {0}")]
    Build(String),
    /// The signer (local/HSM/KMS) failed to produce a signature.
    #[error("token signer: {0}")]
    Signer(String),
    /// The token is not authentic / malformed / wrong algorithm (a signature or
    /// framing failure — the presenter is unauthenticated).
    #[error("token invalid: {0}")]
    Invalid(String),
    /// The token is authentic but its claims are wrong for the use (e.g. a role
    /// token presented as a join token, or a missing claim) — authenticated but
    /// not authorized for this operation.
    #[error("token claims: {0}")]
    Claims(String),
    /// The token is past its `exp`.
    #[error("token expired")]
    Expired,
}

/// Mints tokens by signing the COSE `ToBeSigned` bytes. Async so a remote KMS
/// (an HTTP round-trip) fits the same seam as a local key. Verification does not
/// use this — it needs only the [`TokenPublicKey`].
#[async_trait]
pub trait Signer: Send + Sync {
    /// The algorithm this signer produces.
    fn alg(&self) -> TokenAlg;
    /// The public key that verifies this signer's tokens (the config trust anchor).
    fn public_key(&self) -> TokenPublicKey;
    /// Sign the COSE `ToBeSigned` bytes, returning the raw fixed-size signature
    /// (ES256 = 64-byte `r‖s`; Ed25519 = 64 bytes).
    async fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, TokenError>;
}

/// An in-process signing key (the default / test backend). External backends
/// (Vault, PKCS#11, KMS) live in `boatramp-server`.
pub enum LocalSigner {
    /// ES256 (P-256) key.
    Es256(p256::ecdsa::SigningKey),
    /// Ed25519 key.
    Ed25519(ed25519_dalek::SigningKey),
}

impl LocalSigner {
    /// Generate a fresh key for `alg`.
    pub fn generate(alg: TokenAlg) -> Self {
        match alg {
            TokenAlg::Es256 => Self::Es256(p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)),
            TokenAlg::Ed25519 => {
                Self::Ed25519(ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng))
            }
        }
    }

    /// Load from an `"<alg>:<hex>"` private key (32-byte scalar/seed), as written
    /// by [`private_hex`](Self::private_hex).
    pub fn from_private_hex(spec: &str) -> Result<Self, TokenError> {
        let (alg, raw) = split_tagged(spec)?;
        match alg {
            TokenAlg::Es256 => Ok(Self::Es256(
                p256::ecdsa::SigningKey::from_slice(&raw)
                    .map_err(|e| TokenError::Key(format!("es256 private key: {e}")))?,
            )),
            TokenAlg::Ed25519 => {
                let bytes: [u8; 32] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| TokenError::Key("ed25519 private key must be 32 bytes".into()))?;
                Ok(Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(&bytes)))
            }
        }
    }

    /// The private key as `"<alg>:<hex>"` (store securely; shown once).
    pub fn private_hex(&self) -> String {
        match self {
            Self::Es256(sk) => format!("es256:{}", hex::encode(sk.to_bytes())),
            Self::Ed25519(sk) => format!("ed25519:{}", hex::encode(sk.to_bytes())),
        }
    }
}

#[async_trait]
impl Signer for LocalSigner {
    fn alg(&self) -> TokenAlg {
        match self {
            Self::Es256(_) => TokenAlg::Es256,
            Self::Ed25519(_) => TokenAlg::Ed25519,
        }
    }

    fn public_key(&self) -> TokenPublicKey {
        match self {
            Self::Es256(sk) => TokenPublicKey::Es256(*sk.verifying_key()),
            Self::Ed25519(sk) => TokenPublicKey::Ed25519(sk.verifying_key()),
        }
    }

    async fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, TokenError> {
        match self {
            Self::Es256(sk) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = sk
                    .try_sign(tbs)
                    .map_err(|e| TokenError::Signer(e.to_string()))?;
                Ok(sig.to_bytes().to_vec())
            }
            Self::Ed25519(sk) => {
                use ed25519_dalek::Signer as _;
                let sig = sk
                    .try_sign(tbs)
                    .map_err(|e| TokenError::Signer(e.to_string()))?;
                Ok(sig.to_bytes().to_vec())
            }
        }
    }
}

/// The public key that verifies a token — the config trust anchor on every node.
#[derive(Clone, Debug)]
pub enum TokenPublicKey {
    /// ES256 (P-256) verifying key.
    Es256(p256::ecdsa::VerifyingKey),
    /// Ed25519 verifying key.
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl TokenPublicKey {
    /// This key's algorithm.
    pub fn alg(&self) -> TokenAlg {
        match self {
            Self::Es256(_) => TokenAlg::Es256,
            Self::Ed25519(_) => TokenAlg::Ed25519,
        }
    }

    /// `"<alg>:<hex>"` — ES256 is the 33-byte compressed SEC1 point, Ed25519 the
    /// 32-byte key. This is the config trust anchor (`auth_root_public_key`).
    pub fn to_hex(&self) -> String {
        match self {
            Self::Es256(vk) => {
                format!(
                    "es256:{}",
                    hex::encode(vk.to_encoded_point(true).as_bytes())
                )
            }
            Self::Ed25519(vk) => format!("ed25519:{}", hex::encode(vk.as_bytes())),
        }
    }

    /// Parse an ES256 (P-256) public key from X.509 `SubjectPublicKeyInfo` DER —
    /// the form cloud KMS `GetPublicKey` returns. Ed25519 is not offered here
    /// (GCP/Azure KMS can't sign it, and AWS KMS only signs ECDSA).
    pub fn es256_from_spki_der(der: &[u8]) -> Result<Self, TokenError> {
        use p256::pkcs8::DecodePublicKey as _;
        p256::ecdsa::VerifyingKey::from_public_key_der(der)
            .map(TokenPublicKey::Es256)
            .map_err(|e| TokenError::Key(format!("es256 SPKI DER: {e}")))
    }

    /// Parse an ES256 public key from a PEM `SubjectPublicKeyInfo` block — the form
    /// Vault Transit + GCP Cloud KMS return.
    pub fn es256_from_spki_pem(pem: &str) -> Result<Self, TokenError> {
        use p256::pkcs8::DecodePublicKey as _;
        p256::ecdsa::VerifyingKey::from_public_key_pem(pem)
            .map(TokenPublicKey::Es256)
            .map_err(|e| TokenError::Key(format!("es256 SPKI PEM: {e}")))
    }

    /// Parse an `"<alg>:<hex>"` public key.
    pub fn from_hex(spec: &str) -> Result<Self, TokenError> {
        let (alg, raw) = split_tagged(spec)?;
        match alg {
            TokenAlg::Es256 => Ok(Self::Es256(
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw)
                    .map_err(|e| TokenError::Key(format!("es256 public key: {e}")))?,
            )),
            TokenAlg::Ed25519 => {
                let bytes: [u8; 32] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| TokenError::Key("ed25519 public key must be 32 bytes".into()))?;
                Ok(Self::Ed25519(
                    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                        .map_err(|e| TokenError::Key(format!("ed25519 public key: {e}")))?,
                ))
            }
        }
    }

    /// Verify a raw signature over `tbs`. Anti-malleability: ES256 uses the fixed
    /// `r‖s` form, Ed25519 uses `verify_strict`. Public so other subsystems (e.g.
    /// the kernel-trust check) can verify a detached signature with the same
    /// pinned-algorithm primitives.
    pub fn verify(&self, tbs: &[u8], sig: &[u8]) -> Result<(), TokenError> {
        match self {
            Self::Es256(vk) => {
                use p256::ecdsa::signature::Verifier as _;
                let sig = p256::ecdsa::Signature::from_slice(sig)
                    .map_err(|e| TokenError::Invalid(format!("es256 signature: {e}")))?;
                vk.verify(tbs, &sig)
                    .map_err(|_| TokenError::Invalid("signature verification failed".into()))
            }
            Self::Ed25519(vk) => {
                let sig = ed25519_dalek::Signature::from_slice(sig)
                    .map_err(|e| TokenError::Invalid(format!("ed25519 signature: {e}")))?;
                vk.verify_strict(tbs, &sig)
                    .map_err(|_| TokenError::Invalid("signature verification failed".into()))
            }
        }
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

/// A random 16-byte revocation/single-use id (`cti`).
fn random_cti() -> Result<Vec<u8>, TokenError> {
    let mut cti = [0u8; 16];
    getrandom::getrandom(&mut cti).map_err(|e| TokenError::Build(format!("rng: {e}")))?;
    Ok(cti.to_vec())
}

/// Wrap a CWT claim set in a signed `COSE_Sign1` and base64url-encode it. The
/// protected header carries the signer's algorithm; the canonical `ToBeSigned`
/// bytes are what gets signed (never hand-rolled).
async fn sign_claims(claims: ClaimsSet, signer: &dyn Signer) -> Result<String, TokenError> {
    let bytes = sign_claims_bytes(claims, signer).await?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Sign a claim set into the tagged `COSE_Sign1` bytes (the raw block form used
/// inside a delegation chain, and the pre-base64 form of a plain token).
async fn sign_claims_bytes(claims: ClaimsSet, signer: &dyn Signer) -> Result<Vec<u8>, TokenError> {
    let payload = claims
        .to_vec()
        .map_err(|e| TokenError::Build(e.to_string()))?;
    let header = HeaderBuilder::new().algorithm(signer.alg().iana()).build();
    let mut sign1 = CoseSign1Builder::new()
        .protected(header)
        .payload(payload)
        .build();
    let tbs = sign1.tbs_data(&[]);
    sign1.signature = signer.sign(&tbs).await?;
    sign1
        .to_tagged_vec()
        .map_err(|e| TokenError::Build(e.to_string()))
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
    role_token(&claims, exp)
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

/// The fully-verified contents of a durable signed-context envelope (R1 + async-lane persona,
/// PLAN-async-persona): the host-sealed own-tenant AND (optionally) the host-verified caller persona,
/// both bound to the SAME `COSE_Sign1` signature/expiry. Returned by [`verify_context_full`]; the
/// tenant-only [`verify_context`] projects out just [`VerifiedContext::tenant`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContext {
    /// The principal CLASS this seal carries (construens `cron-system-principal`): `Tenant` for an
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

/// Mint a **SYSTEM** signed-context envelope (construens `cron-system-principal`): a `COSE_Sign1` CWT
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
    let mut blocks = decode_credential(credential)?;
    let mut builder = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .text_claim(
            CLAIM_KIND.to_string(),
            CborValue::Text(KIND_DELEGATION.to_string()),
        )
        .text_claim(CLAIM_CAVEATS.to_string(), caveats.to_cbor());
    if let Some(holder) = next_holder {
        builder = builder.text_claim(CLAIM_CNF.to_string(), CborValue::Text(holder.to_hex()));
    }
    // Fold `not_after` into `exp` so the standard expiry check enforces it.
    if let Some(na) = caveats.not_after {
        builder = builder.expiration_time(Timestamp::WholeSeconds(na as i64));
    }
    // A block carries NO roles: children can only narrow (the anti-escalation
    // invariant — verify never reads a block's roles).
    blocks.push(sign_claims_bytes(builder.build(), holder_signer).await?);
    encode_chain(blocks)
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
    let blocks = decode_credential(credential)?;
    let (root_bytes, children) = blocks
        .split_first()
        .ok_or_else(|| TokenError::Invalid("empty credential".into()))?;

    let root_claims = verify_envelope_bytes(root_bytes, root_public)?;
    let root = role_token(&root_claims, check_exp(&root_claims, now_unix)?)?;

    let mut effective_exp = root.exp;
    let mut caveats = Caveats::default();
    let mut parent_cnf = root.cnf.clone();

    for block in children {
        // Each block must be signed by the key the parent declared (`cnf`) — proof
        // of possession. A parent that declared no holder key can't be extended.
        let holder_hex = parent_cnf
            .take()
            .ok_or_else(|| TokenError::Claims("delegation past a non-delegatable block".into()))?;
        let holder = TokenPublicKey::from_hex(&holder_hex)
            .map_err(|e| TokenError::Claims(format!("holder key: {e}")))?;
        let claims = verify_envelope_bytes(block, &holder)?;

        // Domain separation: a role token can't masquerade as a delegation block.
        let kind = text_claim(&claims, CLAIM_KIND).and_then(|v| match v {
            CborValue::Text(t) => Some(t.as_str()),
            _ => None,
        });
        if kind != Some(KIND_DELEGATION) {
            return Err(TokenError::Claims("not a delegation block".into()));
        }
        // Anti-escalation: a block's roles are never read — only its caveats narrow.
        let block_caveats = text_claim(&claims, CLAIM_CAVEATS)
            .map(Caveats::from_cbor)
            .unwrap_or_default();
        caveats.tighten(&block_caveats);
        effective_exp = min_opt(effective_exp, check_exp(&claims, now_unix)?);
        parent_cnf = claim_cnf(&claims);
    }

    Ok(VerifiedChain {
        roles: root.roles,
        kind: root.kind,
        cti: root.cti,
        exp: effective_exp,
        caveats,
        // After the walk, `parent_cnf` holds the terminal block's declared holder
        // key (or the root's, for a plain token) — the leaf a PoP proof binds to.
        leaf_cnf: parent_cnf,
    })
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

/// Decode a presented credential into its ordered blocks (raw tagged
/// `COSE_Sign1` bytes). A plain token is a bare `COSE_Sign1` (one block); a chain
/// is a CBOR array of byte strings. Enforces the size/depth bounds *before* any
/// verification, so a hostile credential can't force unbounded work.
fn decode_credential(credential: &str) -> Result<Vec<Vec<u8>>, TokenError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(credential.trim())
        .map_err(|e| TokenError::Invalid(format!("base64: {e}")))?;
    if bytes.len() > MAX_CHAIN_BYTES {
        return Err(TokenError::Invalid("credential exceeds size bound".into()));
    }
    // CBOR major type 4 (0b100_xxxxx) is an array (a chain); a tagged COSE_Sign1
    // is major type 6 (tag). Peek before parsing.
    let is_array = matches!(bytes.first(), Some(b) if (b >> 5) == 4);
    if !is_array {
        return Ok(vec![bytes]);
    }
    let value: CborValue =
        ciborium::from_reader(&bytes[..]).map_err(|e| TokenError::Invalid(e.to_string()))?;
    let CborValue::Array(items) = value else {
        return Err(TokenError::Invalid("malformed credential".into()));
    };
    if items.is_empty() || items.len() > MAX_CHAIN_DEPTH {
        return Err(TokenError::Invalid(
            "credential chain length out of bounds".into(),
        ));
    }
    items
        .into_iter()
        .map(|item| match item {
            CborValue::Bytes(b) => Ok(b),
            _ => Err(TokenError::Invalid("malformed chain block".into())),
        })
        .collect()
}

/// Encode ordered blocks as `base64url(CBOR array of byte strings)`.
fn encode_chain(blocks: Vec<Vec<u8>>) -> Result<String, TokenError> {
    let array = CborValue::Array(blocks.into_iter().map(CborValue::Bytes).collect());
    let mut buf = Vec::new();
    ciborium::into_writer(&array, &mut buf).map_err(|e| TokenError::Build(e.to_string()))?;
    if buf.len() > MAX_CHAIN_BYTES {
        return Err(TokenError::Build(
            "delegation chain exceeds size bound".into(),
        ));
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

/// The tighter of two optional expiries (treating `None` as "no bound").
fn min_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) => Some(x),
        (None, b) => b,
    }
}

/// Decode + signature-verify a base64url `COSE_Sign1` CWT against `public`,
/// returning its claim set. Pins the algorithm to the *key's* algorithm (never
/// trusting the attacker-controlled protected header) to defeat algorithm
/// confusion. All failures here are authenticity/framing failures
/// ([`TokenError::Invalid`]).
fn verify_envelope(token: &str, public: &TokenPublicKey) -> Result<ClaimsSet, TokenError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token.trim())
        .map_err(|e| TokenError::Invalid(format!("base64: {e}")))?;
    verify_envelope_bytes(&bytes, public)
}

/// Verify the tagged `COSE_Sign1` bytes of one block against `public`, returning
/// its claim set. The shared core of [`verify`] and the delegation chain walk.
fn verify_envelope_bytes(bytes: &[u8], public: &TokenPublicKey) -> Result<ClaimsSet, TokenError> {
    let sign1 =
        CoseSign1::from_tagged_slice(bytes).map_err(|e| TokenError::Invalid(e.to_string()))?;

    let want = CoseAlg::Assigned(public.alg().iana());
    if sign1.protected.header.alg.as_ref() != Some(&want) {
        return Err(TokenError::Invalid("algorithm mismatch".into()));
    }
    sign1.verify_signature(&[], |sig, tbs| public.verify(tbs, sig))?;

    let payload = sign1
        .payload
        .as_ref()
        .ok_or_else(|| TokenError::Invalid("no payload".into()))?;
    ClaimsSet::from_slice(payload).map_err(|e| TokenError::Invalid(e.to_string()))
}

/// Read the holder-key (`cnf`) claim, if present.
fn claim_cnf(claims: &ClaimsSet) -> Option<String> {
    text_claim(claims, CLAIM_CNF).and_then(|v| match v {
        CborValue::Text(t) => Some(t.clone()),
        _ => None,
    })
}

/// Look up a text-keyed private-use claim by name.
fn text_claim<'a>(claims: &'a ClaimsSet, name: &str) -> Option<&'a CborValue> {
    claims.rest.iter().find_map(|(k, v)| match k {
        coset::cwt::ClaimName::Text(t) if t == name => Some(v),
        _ => None,
    })
}

/// The token's revocation id (`cti`, hex). A token with no `cti` is malformed.
fn claim_cti(claims: &ClaimsSet) -> Result<String, TokenError> {
    claims
        .cwt_id
        .as_ref()
        .map(hex::encode)
        .ok_or_else(|| TokenError::Invalid("no cti".into()))
}

/// Read the `exp` claim and enforce it against `now_unix`. Returns the expiry (if
/// any); [`TokenError::Expired`] when past it.
fn check_exp(claims: &ClaimsSet, now_unix: u64) -> Result<Option<u64>, TokenError> {
    let exp = match claims.expiration_time {
        Some(Timestamp::WholeSeconds(s)) => Some(s.max(0) as u64),
        _ => None,
    };
    if let Some(exp) = exp
        && now_unix > exp
    {
        return Err(TokenError::Expired);
    }
    Ok(exp)
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

/// Convert a DER-encoded ECDSA/P-256 signature to the raw fixed 64-byte `r‖s`
/// COSE form. AWS KMS and GCP Cloud KMS return ECDSA signatures DER-encoded;
/// Vault (with `marshaling_algorithm=jws`), Azure Key Vault, and PKCS#11
/// (`CKM_ECDSA`) already return the raw form. Ed25519 signatures are always raw.
pub fn p256_der_sig_to_raw(der: &[u8]) -> Result<Vec<u8>, TokenError> {
    p256::ecdsa::Signature::from_der(der)
        .map(|sig| sig.to_bytes().to_vec())
        .map_err(|e| TokenError::Invalid(format!("es256 DER signature: {e}")))
}

/// Split an `"<alg>:<hex>"` spec into `(alg, bytes)`.
fn split_tagged(spec: &str) -> Result<(TokenAlg, Vec<u8>), TokenError> {
    let (tag, hex_str) = spec
        .trim()
        .split_once(':')
        .ok_or_else(|| TokenError::Key("expected \"<alg>:<hex>\"".into()))?;
    let alg = match tag {
        t if t == TokenAlg::Es256.label() => TokenAlg::Es256,
        t if t == TokenAlg::Ed25519.label() => TokenAlg::Ed25519,
        other => {
            return Err(TokenError::Key(format!(
                "unknown token algorithm {other:?}"
            )));
        }
    };
    let bytes = hex::decode(hex_str).map_err(|e| TokenError::Key(format!("hex: {e}")))?;
    Ok((alg, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// construens `cron-system-principal` — a SYSTEM signed-context is classed `System`, carries NO
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
        assert!(matches!(
            verify(&token, &ed_key, NOW),
            Err(TokenError::Invalid(_))
        ));
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

        // A join token verified as a role token carries kind="join" and no roles,
        // so the RBAC layer grants it nothing.
        let join = mint_join(3600, NOW, &signer).await.unwrap();
        let v = verify(&join, &public, NOW).unwrap();
        assert_eq!(v.kind, KIND_JOIN);
        assert!(v.roles.is_empty());
    }

    #[test]
    fn p256_der_signature_converts_to_raw() {
        // Sign a message, then check the DER→raw conversion equals the native raw
        // form — the transform every DER-returning KMS (AWS/GCP) relies on.
        use p256::ecdsa::signature::Signer as _;
        let sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
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
            Err(TokenError::Invalid(_))
        ));

        // Size: a credential larger than MAX_CHAIN_BYTES is refused before parsing.
        let big = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(vec![0x80u8; MAX_CHAIN_BYTES + 1]);
        assert!(matches!(
            verify_credential(&big, &pk, NOW),
            Err(TokenError::Invalid(_))
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
        //     join token. `verify()` is kind-agnostic by contract (it returns `br_kind` for the
        //     caller to gate), so the role-path guarantee is that it reports a kind that is NOT
        //     `KIND_ROLE` — any role-gated caller then rejects it. The strongly-typed verifiers
        //     reject it outright via their own exact-kind checks.
        let s3 = mint_s3_session(&s3_scope_key(), 300, NOW, &signer)
            .await
            .unwrap();
        let as_role = verify(&s3, &public, NOW + 1).unwrap();
        assert_eq!(
            as_role.kind, KIND_S3_SESSION,
            "an s3-session's kind must be distinct from KIND_ROLE so a role-gated path rejects it"
        );
        assert_ne!(as_role.kind, KIND_ROLE);
        assert!(
            as_role.roles.is_empty(),
            "an s3-session carries no RBAC roles"
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
}
