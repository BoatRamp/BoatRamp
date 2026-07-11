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
    iana, Algorithm as CoseAlg, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder,
    TaggedCborSerializable,
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
    fn tighten(&mut self, other: &Caveats) {
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
        if let Some(site) = &self.only_site {
            if required.target_term() != site {
                return false;
            }
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
    fn from_cbor(value: &CborValue) -> Caveats {
        let mut caveats = Caveats::default();
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
            TokenAlg::Es256 => iana::Algorithm::ES256,
            TokenAlg::Ed25519 => iana::Algorithm::EdDSA,
        }
    }
    fn label(self) -> &'static str {
        match self {
            TokenAlg::Es256 => "es256",
            TokenAlg::Ed25519 => "ed25519",
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
            LocalSigner::Es256(sk) => format!("es256:{}", hex::encode(sk.to_bytes())),
            LocalSigner::Ed25519(sk) => format!("ed25519:{}", hex::encode(sk.to_bytes())),
        }
    }
}

#[async_trait]
impl Signer for LocalSigner {
    fn alg(&self) -> TokenAlg {
        match self {
            LocalSigner::Es256(_) => TokenAlg::Es256,
            LocalSigner::Ed25519(_) => TokenAlg::Ed25519,
        }
    }

    fn public_key(&self) -> TokenPublicKey {
        match self {
            LocalSigner::Es256(sk) => TokenPublicKey::Es256(*sk.verifying_key()),
            LocalSigner::Ed25519(sk) => TokenPublicKey::Ed25519(sk.verifying_key()),
        }
    }

    async fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, TokenError> {
        match self {
            LocalSigner::Es256(sk) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = sk
                    .try_sign(tbs)
                    .map_err(|e| TokenError::Signer(e.to_string()))?;
                Ok(sig.to_bytes().to_vec())
            }
            LocalSigner::Ed25519(sk) => {
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
            TokenPublicKey::Es256(_) => TokenAlg::Es256,
            TokenPublicKey::Ed25519(_) => TokenAlg::Ed25519,
        }
    }

    /// `"<alg>:<hex>"` — ES256 is the 33-byte compressed SEC1 point, Ed25519 the
    /// 32-byte key. This is the config trust anchor (`auth_root_public_key`).
    pub fn to_hex(&self) -> String {
        match self {
            TokenPublicKey::Es256(vk) => {
                format!(
                    "es256:{}",
                    hex::encode(vk.to_encoded_point(true).as_bytes())
                )
            }
            TokenPublicKey::Ed25519(vk) => format!("ed25519:{}", hex::encode(vk.as_bytes())),
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
            TokenAlg::Es256 => Ok(TokenPublicKey::Es256(
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw)
                    .map_err(|e| TokenError::Key(format!("es256 public key: {e}")))?,
            )),
            TokenAlg::Ed25519 => {
                let bytes: [u8; 32] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| TokenError::Key("ed25519 public key must be 32 bytes".into()))?;
                Ok(TokenPublicKey::Ed25519(
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
            TokenPublicKey::Es256(vk) => {
                use p256::ecdsa::signature::Verifier as _;
                let sig = p256::ecdsa::Signature::from_slice(sig)
                    .map_err(|e| TokenError::Invalid(format!("es256 signature: {e}")))?;
                vk.verify(tbs, &sig)
                    .map_err(|_| TokenError::Invalid("signature verification failed".into()))
            }
            TokenPublicKey::Ed25519(vk) => {
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

/// A verified mesh join token's claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinClaim {
    /// The node id the token authorizes joining as.
    pub node_id: u64,
    /// The mesh public key (SPKI hex) the token authorizes trusting.
    pub pubkey_hex: String,
    /// Single-use handle: the token's revocation id (`cti`, hex). The cluster
    /// records this as spent on admission so the token can't be replayed.
    pub jti: String,
}

/// Mint a **single-use mesh join token**: a `COSE_Sign1` CWT whose
/// claims bind it to exactly one joining node — `br_node`/`br_pubkey` — with
/// `br_kind = "join"` (domain separation from role tokens) and a TTL (`exp`).
/// Bound to the pubkey, a stolen token can't admit a different key; bound to the
/// node id, it can't be replayed as another node; and its `cti` is the single-use
/// handle the cluster records as spent. Minted server-side; shown once.
pub async fn mint_join(
    node_id: u64,
    pubkey_hex: &str,
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
        .text_claim(CLAIM_NODE.to_string(), CborValue::from(node_id))
        .text_claim(
            CLAIM_PUBKEY.to_string(),
            CborValue::Text(pubkey_hex.to_string()),
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

/// Verify a base64url mesh **join** token: signature + alg pin +
/// TTL, and that it is a `br_kind = "join"` token carrying a `(node_id, pubkey)`
/// binding. Returns the single `(node_id, pubkey)` it authorizes plus its
/// single-use handle (`jti` = `cti`). IO-free: the caller must still, at
/// admission, (a) confirm the joiner holds `pubkey_hex` and (b) reject a `jti`
/// already recorded as spent. A role token presented here is rejected on the kind
/// check ([`TokenError::Claims`]).
pub fn verify_join(
    token: &str,
    public: &TokenPublicKey,
    now_unix: u64,
) -> Result<JoinClaim, TokenError> {
    let claims = verify_envelope(token, public)?;
    let jti = claim_cti(&claims)?;
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
    if kind != KIND_JOIN {
        return Err(TokenError::Claims("not a mesh join token".into()));
    }
    let node_id = node_id.ok_or_else(|| TokenError::Claims("join token has no node id".into()))?;
    let pubkey_hex =
        pubkey_hex.ok_or_else(|| TokenError::Claims("join token has no pubkey".into()))?;
    Ok(JoinClaim {
        node_id,
        pubkey_hex,
        jti,
    })
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
        .text_claim(CLAIM_KIND.to_string(), CborValue::Text(KIND_POP.to_string()))
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
    if let Some(exp) = exp {
        if now_unix > exp {
            return Err(TokenError::Expired);
        }
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
                out.push(GrantedRole::scoped(name, target))
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
            )))
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
    async fn join_token_round_trips_and_binds_node_and_pubkey() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let public = signer.public_key();
        let token = mint_join(7, "aa01bb02", 3600, NOW, &signer).await.unwrap();

        let claim = verify_join(&token, &public, NOW + 60).unwrap();
        assert_eq!(claim.node_id, 7);
        assert_eq!(claim.pubkey_hex, "aa01bb02");
        assert!(!claim.jti.is_empty(), "the jti is the single-use handle");
        // Stable across re-verification (the cluster spends it once).
        assert_eq!(
            verify_join(&token, &public, NOW + 60).unwrap().jti,
            claim.jti
        );
    }

    #[tokio::test]
    async fn join_token_expires_and_rejects_foreign_key() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let token = mint_join(3, "cccc", 100, NOW, &signer).await.unwrap();
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
        assert_eq!(verify_attestation(&att, &public, NOW + 60).unwrap(), tls_spki);

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
        let join = mint_join(1, tls_spki, 3600, NOW, &root).await.unwrap();
        assert!(matches!(
            verify_attestation(&join, &public, NOW + 60),
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
        let join = mint_join(1, "dead", 3600, NOW, &signer).await.unwrap();
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
        let token =
            delegatable_root(&root, &holder.public_key(), vec![GrantedRole::global("admin")]).await;
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
            PopClaims { htm: "GET".into(), ..want.clone() },
            PopClaims { htp: "/api/sites/y/config".into(), ..want.clone() },
            PopClaims { aud: "https://evil.example.com".into(), ..want.clone() },
            PopClaims { ath: pop_sha256_hex(b"other-token"), ..want.clone() },
            PopClaims { bh: Some(pop_sha256_hex(b"swapped")), ..want.clone() },
            PopClaims { bh: None, ..want.clone() },
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
}
