//! A generic, attenuable **COSE_Sign1 / CWT capability-credential engine**.
//!
//! This is the vocabulary-free core extracted from `boatramp-core::cose`: the
//! `COSE_Sign1` (RFC 9052) + CWT (RFC 8392) envelope machinery, a pluggable
//! [`Signer`] (ES256 default + Ed25519, so the root key can be local, an HSM, or a
//! cloud KMS — **verification needs only the [`TokenPublicKey`]**), and the
//! offline **delegation chain-walk** that enforces *narrowing* authority.
//!
//! The engine is generic over the caveat vocabulary via the [`NarrowingCaveats`]
//! trait. A consumer supplies its own restrict-only caveat type (e.g. boatramp's
//! `Caveats { only_site, read_only, not_after }`); the engine supplies the
//! cryptography, the chain framing, and — crucially — the **structural narrowing
//! guarantee**:
//!
//! 1. **Authority is root-only.** [`verify_credential`] returns the *root* block's
//!    verified claim set and reads authority from no child block. No delegate can
//!    *add* authority (the anti-escalation invariant).
//! 2. **Expiry is min-folded by the engine.** Each block's expiry is intersected
//!    with [`min_opt`]; a delegate can only *shorten* a credential's lifetime.
//! 3. **Caveats only narrow, and the engine verifies it.** Each delegation step's
//!    accumulated caveat is checked with [`NarrowingCaveats::is_narrower_or_equal`]
//!    against *both* the running accumulator and the block's own caveat; a
//!    [`NarrowingCaveats::meet`] that ever *widens* (a buggy or adversarial consumer
//!    impl) is caught and the whole credential is **rejected, fail-closed**. So a
//!    faulty consumer `meet` can only cause a denial, never a privilege
//!    escalation. (The *meaning* of a caveat set — its decode/`allows` — is
//!    necessarily the consumer's; what the engine guarantees is that a chain can
//!    only move *down* the narrowing lattice.)
//!
//! Algorithms are pinned on verify to the *verifying key's* algorithm (never the
//! attacker-controlled protected header) to defeat algorithm confusion.

use async_trait::async_trait;
use base64::Engine as _;
use coset::{
    Algorithm as CoseAlg, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder,
    TaggedCborSerializable, iana,
};

// (U8–U10, #6 · U11-3) Re-export the foreign types this engine's public API speaks,
// so a consumer need not add a direct `coset` / `ciborium` dependency (nor pin its
// version independently): `ClaimsSet` is the claim-set type `sign_claims` /
// `verify_envelope` / `CredentialChain::root_claims` traffic in, and `Value`
// (aliased `CborValue`) is the CBOR model the `NarrowingCaveats` wire form uses.
//
// (U11-3) Additionally re-export the claim-BUILDING helpers — `ClaimsSetBuilder`
// (the fluent builder a consumer mints a claim set with), `ClaimName` (the claim-key
// type `ClaimsSet::rest` is keyed by, for reading/building private-use claims) and
// `Timestamp` (the `iat`/`exp` representation) — so a consumer can construct a token
// end-to-end through `boatramp-cwt` without depending on `coset` directly. These are
// also used internally by this crate (e.g. `attenuate`, `sign_claims`), so the
// re-export doubles as the in-module import.
pub use ciborium::Value;
pub use ciborium::value::Value as CborValue;
pub use coset::cwt::{ClaimName, ClaimsSet, ClaimsSetBuilder, Timestamp};

/// Max blocks in a presented delegation chain — a resource bound checked *before*
/// any signature verification.
pub const MAX_CHAIN_DEPTH: usize = 8;
/// Max serialized bytes of a presented delegation chain — bounded before parsing.
pub const MAX_CHAIN_BYTES: usize = 8 * 1024;

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
    /// The protected-header algorithm does not match the *trusted key's*
    /// algorithm. A distinct, typed authenticity failure (a specialization of
    /// [`Invalid`](Self::Invalid)) so a consumer can detect algorithm confusion
    /// (`none`/ES↔Ed swap) by **variant** rather than by matching the error text.
    /// Classified exactly like [`Invalid`](Self::Invalid) (unauthenticated).
    #[error("token invalid: algorithm mismatch")]
    AlgMismatch,
    /// A presented or minted delegation chain exceeds a **resource bound** — too
    /// many blocks ([`MAX_CHAIN_DEPTH`]) or too many serialized bytes
    /// ([`MAX_CHAIN_BYTES`]) — rejected *before* any signature verification (so a
    /// hostile credential can't force unbounded work). A distinct, typed variant
    /// (U11-2; previously folded into [`Invalid`](Self::Invalid)/[`Build`](Self::Build))
    /// so a consumer can tell "too big / too deep" from other invalidity **by
    /// variant** rather than by matching the error text. Classified exactly like
    /// [`Invalid`](Self::Invalid): a framing / resource-bound rejection
    /// (unauthenticated), never an authentic-but-wrong token.
    #[error("token bounds: {0}")]
    Bounds(String),
    /// A delegation step would **widen** authority: either the consumer
    /// [`meet`](NarrowingCaveats::meet) is not a true lower bound (a buggy/hostile
    /// impl — caught fail-closed), or a block names *looser* restrictions than are
    /// already in force (a block that narrows nothing — an attenuation mistake or a
    /// truncation attempt). A typed variant so a consumer need not match on the
    /// old `Claims("… must only narrow …")` text. Always a rejection, fail-closed.
    #[error("token widened: {0}")]
    Widened(String),
    /// A **presented** delegation chain ends at an *intermediate* (unsealed)
    /// holder — a terminal block that names a further `cnf` holder (not the root's
    /// own key). Such a prefix could be a truncation of a longer, more-narrowed
    /// chain, so accepting it without a per-request proof of possession of
    /// `leaf_cnf` would let a holder of that key strip the trailing narrowing
    /// blocks and recover the parent's authority ([`verify_presented`]). Refused
    /// for any consumer that cannot prove PoP of the leaf (uchron RFC-009 §7, C1).
    #[error("token unsealed: {0}")]
    Unsealed(String),
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
            // P-256 (RustCrypto 0.14): the `Generate` trait's `generate()` draws from the system CSPRNG
            // (`getrandom::SysRng`) and panics only if the OS RNG fails — the same fail-stop behavior as
            // the old `SigningKey::random(&mut OsRng)` (now deprecated), with no direct rand_core dep.
            TokenAlg::Es256 => {
                use p256::elliptic_curve::Generate as _;
                Self::Es256(p256::ecdsa::SigningKey::generate())
            }
            // Ed25519 (rand_core 0.6): `ed25519-dalek 2` is pinned to the rand_core 0.6 trait family,
            // so its `generate` takes a 0.6 `OsRng` — unchanged by the P-256 migration.
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
                // ecdsa 0.17 renamed `to_encoded_point` → `to_sec1_point`. `true` = point
                // compression, so this is the identical 33-byte compressed SEC1 point (0x02/0x03 ‖ x)
                // the old code emitted — the on-wire trust anchor is byte-unchanged.
                format!("es256:{}", hex::encode(vk.to_sec1_point(true).as_bytes()))
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

/// A random 16-byte revocation/single-use id (`cti`).
pub fn random_cti() -> Result<Vec<u8>, TokenError> {
    let mut cti = [0u8; 16];
    getrandom::getrandom(&mut cti).map_err(|e| TokenError::Build(format!("rng: {e}")))?;
    Ok(cti.to_vec())
}

/// Wrap a CWT claim set in a signed `COSE_Sign1` and base64url-encode it. The
/// protected header carries the signer's algorithm; the canonical `ToBeSigned`
/// bytes are what gets signed (never hand-rolled).
pub async fn sign_claims(claims: ClaimsSet, signer: &dyn Signer) -> Result<String, TokenError> {
    let bytes = sign_claims_bytes(claims, signer).await?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Sign a claim set into the tagged `COSE_Sign1` bytes (the raw block form used
/// inside a delegation chain, and the pre-base64 form of a plain token).
pub async fn sign_claims_bytes(
    claims: ClaimsSet,
    signer: &dyn Signer,
) -> Result<Vec<u8>, TokenError> {
    sign_claims_bytes_inner(claims, signer, None).await
}

/// Like [`sign_claims`], additionally stamping a **protected-header `kid`** (RFC
/// 9052 key id). Because the `kid` sits in the *protected* header it is covered by
/// the signature (part of the `ToBeSigned`), so it cannot be swapped; a verifier
/// may read it **unverified** with [`peek_protected_kid`] to *select* the right
/// verifying key from a set (newest-first multi-key rotation) before doing the
/// full verify.
///
/// **Wire note:** stamping a `kid` changes the signed bytes — a token minted with
/// a `kid` differs from one minted without. This is **opt-in**; the plain
/// [`sign_claims`] / [`sign_claims_bytes`] path (what boatramp mints today) is
/// byte-for-byte unchanged, so existing tokens are unaffected.
pub async fn sign_claims_with_kid(
    claims: ClaimsSet,
    signer: &dyn Signer,
    kid: &[u8],
) -> Result<String, TokenError> {
    let bytes = sign_claims_bytes_with_kid(claims, signer, kid).await?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// [`sign_claims_bytes`] with a protected-header `kid` — see [`sign_claims_with_kid`].
pub async fn sign_claims_bytes_with_kid(
    claims: ClaimsSet,
    signer: &dyn Signer,
    kid: &[u8],
) -> Result<Vec<u8>, TokenError> {
    sign_claims_bytes_inner(claims, signer, Some(kid)).await
}

async fn sign_claims_bytes_inner(
    claims: ClaimsSet,
    signer: &dyn Signer,
    kid: Option<&[u8]>,
) -> Result<Vec<u8>, TokenError> {
    let payload = claims
        .to_vec()
        .map_err(|e| TokenError::Build(e.to_string()))?;
    let mut header = HeaderBuilder::new().algorithm(signer.alg().iana());
    if let Some(kid) = kid {
        header = header.key_id(kid.to_vec());
    }
    let mut sign1 = CoseSign1Builder::new()
        .protected(header.build())
        .payload(payload)
        .build();
    let tbs = sign1.tbs_data(&[]);
    sign1.signature = signer.sign(&tbs).await?;
    sign1
        .to_tagged_vec()
        .map_err(|e| TokenError::Build(e.to_string()))
}

/// Peek the **unverified** protected-header `kid` of a presented token (or the
/// first block of a chain) **without verifying the signature**. For newest-first
/// multi-key *selection* only: the bytes are attacker-controlled until a full
/// verify ([`verify_envelope`] / [`verify_credential`]) confirms the signature, so
/// never read authority from them — use them only to *choose* a candidate key.
/// `None` when absent or the token can't be parsed.
pub fn peek_protected_kid(token: &str) -> Option<Vec<u8>> {
    let blocks = decode_credential(token).ok()?;
    let first = blocks.first()?;
    let sign1 = CoseSign1::from_tagged_slice(first).ok()?;
    let kid = &sign1.protected.header.key_id;
    (!kid.is_empty()).then(|| kid.clone())
}

/// Decode a presented token's CWT [`ClaimsSet`] **without verifying the
/// signature** (the first block, for a chain). **Untrusted:** for key selection /
/// routing only (e.g. reading an issuer/`kid`-like claim to pick a verifying key
/// before a full verify); never read authority or make a trust decision from it.
/// Re-verify with [`verify_envelope`] / [`verify_credential`] before trusting any
/// claim. Enforces the same size/depth bounds as [`decode_credential`].
pub fn peek_unverified_claims(token: &str) -> Result<ClaimsSet, TokenError> {
    let blocks = decode_credential(token)?;
    let first = blocks
        .first()
        .ok_or_else(|| TokenError::Invalid("empty credential".into()))?;
    let sign1 =
        CoseSign1::from_tagged_slice(first).map_err(|e| TokenError::Invalid(e.to_string()))?;
    let payload = sign1
        .payload
        .as_ref()
        .ok_or_else(|| TokenError::Invalid("no payload".into()))?;
    ClaimsSet::from_slice(payload).map_err(|e| TokenError::Invalid(e.to_string()))
}

/// Decode a presented credential into its ordered blocks (raw tagged
/// `COSE_Sign1` bytes). A plain token is a bare `COSE_Sign1` (one block); a chain
/// is a CBOR array of byte strings. Enforces the size/depth bounds *before* any
/// verification, so a hostile credential can't force unbounded work.
pub fn decode_credential(credential: &str) -> Result<Vec<Vec<u8>>, TokenError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(credential.trim())
        .map_err(|e| TokenError::Invalid(format!("base64: {e}")))?;
    if bytes.len() > MAX_CHAIN_BYTES {
        return Err(TokenError::Bounds("credential exceeds size bound".into()));
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
        return Err(TokenError::Bounds(
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
pub fn encode_chain(blocks: Vec<Vec<u8>>) -> Result<String, TokenError> {
    let array = CborValue::Array(blocks.into_iter().map(CborValue::Bytes).collect());
    let mut buf = Vec::new();
    ciborium::into_writer(&array, &mut buf).map_err(|e| TokenError::Build(e.to_string()))?;
    if buf.len() > MAX_CHAIN_BYTES {
        return Err(TokenError::Bounds(
            "delegation chain exceeds size bound".into(),
        ));
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

/// The tighter of two optional expiries (treating `None` as "no bound").
pub fn min_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
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
pub fn verify_envelope(token: &str, public: &TokenPublicKey) -> Result<ClaimsSet, TokenError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token.trim())
        .map_err(|e| TokenError::Invalid(format!("base64: {e}")))?;
    verify_envelope_bytes(&bytes, public)
}

/// Verify the tagged `COSE_Sign1` bytes of one block against `public`, returning
/// its claim set. The shared core of plain-token verify and the delegation chain
/// walk.
pub fn verify_envelope_bytes(
    bytes: &[u8],
    public: &TokenPublicKey,
) -> Result<ClaimsSet, TokenError> {
    let sign1 =
        CoseSign1::from_tagged_slice(bytes).map_err(|e| TokenError::Invalid(e.to_string()))?;

    let want = CoseAlg::Assigned(public.alg().iana());
    if sign1.protected.header.alg.as_ref() != Some(&want) {
        // Algorithm pinning (defeats `none`/ES↔Ed confusion): the token is verified
        // with the *trusted key's* algorithm, never the attacker-controlled header.
        // A dedicated variant so a consumer detects this by type, not error text.
        return Err(TokenError::AlgMismatch);
    }
    sign1.verify_signature(&[], |sig, tbs| public.verify(tbs, sig))?;

    let payload = sign1
        .payload
        .as_ref()
        .ok_or_else(|| TokenError::Invalid("no payload".into()))?;
    ClaimsSet::from_slice(payload).map_err(|e| TokenError::Invalid(e.to_string()))
}

/// Look up a text-keyed private-use claim by name.
pub fn text_claim<'a>(claims: &'a ClaimsSet, name: &str) -> Option<&'a CborValue> {
    claims.rest.iter().find_map(|(k, v)| match k {
        coset::cwt::ClaimName::Text(t) if t == name => Some(v),
        _ => None,
    })
}

/// Read a text-keyed private-use claim as an owned `String`, if present and text.
pub fn claim_text(claims: &ClaimsSet, name: &str) -> Option<String> {
    text_claim(claims, name).and_then(|v| match v {
        CborValue::Text(t) => Some(t.clone()),
        _ => None,
    })
}

/// The token's revocation id (`cti`, hex). A token with no `cti` is malformed.
pub fn claim_cti(claims: &ClaimsSet) -> Result<String, TokenError> {
    claims
        .cwt_id
        .as_ref()
        .map(hex::encode)
        .ok_or_else(|| TokenError::Invalid("no cti".into()))
}

/// Read the `exp` claim and enforce it against `now_unix`. Returns the expiry (if
/// any); [`TokenError::Expired`] when past it.
pub fn check_exp(claims: &ClaimsSet, now_unix: u64) -> Result<Option<u64>, TokenError> {
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

/// A restrict-only caveat vocabulary a consumer plugs into the delegation engine.
///
/// A delegation block carries one value of this type (CBOR-encoded under
/// [`CAVEATS_CLAIM`](Self::CAVEATS_CLAIM)); the engine walks a chain, folding each
/// block's caveat into a running accumulator with [`meet`](Self::meet) and
/// **verifying every step only narrows** with
/// [`is_narrower_or_equal`](Self::is_narrower_or_equal). The engine owns the walk
/// and the monotonicity check. Two guarantees hold **independently of the consumer
/// impl**: authority is read only from the verified root block (a delegation block
/// can never *add* a right), and the credential's expiry is the engine's min-fold
/// over every block's expiry (a block can never *extend* lifetime past the root).
/// The caveat-monotonicity check additionally relies on the consumer's
/// [`is_narrower_or_equal`](Self::is_narrower_or_equal) being honest; but even a
/// dishonest [`meet`](Self::meet) or ordering can at worst *deny* or *wrongly
/// scope* within its own caveat vocabulary — it can never add authority or extend
/// lifetime past the root. What the consumer owns is the *meaning* of its caveats
/// (their wire form and, outside this engine, their `allows` semantics).
///
/// The narrowing lattice is a *meet-semilattice*: [`default`](Default::default) is
/// its **top** (the empty, unrestricted caveat a plain/root token carries), and
/// [`meet`](Self::meet) is the greatest-lower-bound of two restriction sets.
pub trait NarrowingCaveats: Sized + Clone + Default {
    /// CWT text claim key carrying a block's **kind** tag (domain separation).
    const KIND_CLAIM: &'static str;
    /// CWT text claim key carrying a block's **holder key** (RFC 8747 `cnf`): the
    /// key allowed to sign the next delegation block.
    const CNF_CLAIM: &'static str;
    /// CWT text claim key carrying a delegation block's **caveats** (CBOR).
    const CAVEATS_CLAIM: &'static str;
    /// The [`KIND_CLAIM`](Self::KIND_CLAIM) value that marks a delegation block.
    /// The walk rejects a block whose kind is anything else (a role token can't
    /// masquerade as a delegation block).
    const DELEGATION_KIND: &'static str;

    /// Greatest-lower-bound: combine the running accumulator (`self`, shallower)
    /// with the next block's caveat (`deeper`), returning a caveat that restricts
    /// **at least as much as either input**. The engine does not trust this to
    /// narrow — it verifies the result with
    /// [`is_narrower_or_equal`](Self::is_narrower_or_equal) and rejects a chain
    /// whose meet widens — but a correct impl returns a true meet.
    fn meet(&self, deeper: &Self) -> Self;

    /// Partial order of the narrowing lattice: `self.is_narrower_or_equal(other)`
    /// iff `self` restricts **at least as much as** `other` (`self ⊑ other`,
    /// `self`'s permitted set ⊆ `other`'s). The engine calls this to verify each
    /// [`meet`](Self::meet) step only moves *down* the lattice.
    fn is_narrower_or_equal(&self, other: &Self) -> bool;

    /// CBOR wire form of a block's caveats (what [`attenuate`] stamps and the walk
    /// decodes with [`from_cbor`](Self::from_cbor)).
    fn to_cbor(&self) -> CborValue;

    /// Decode a block's caveats from CBOR. **Must never panic** on hostile input.
    ///
    /// **Fallible (U8–U10, #3):** an entry the vocabulary cannot interpret — an
    /// unknown restriction key, or a known key with the wrong CBOR type — must be
    /// **refused** with a reason (`Err`), not silently dropped. Silently ignoring a
    /// restriction the verifier does not understand could *widen* authority (the
    /// dropped narrowing goes unreported), so decoding **fails closed**: the chain
    /// walk propagates the error and rejects the whole credential rather than honor
    /// a partially-understood one. (This replaces the previous "unknown/ill-typed
    /// entries are ignored" contract, which could map a narrowing to deny-all with
    /// no reason surfaced.)
    ///
    /// **Versioning (L2):** because an unknown key is refused, fail-closed decoding
    /// strictly *versions* the caveat vocabulary — a token carrying a NEW caveat key
    /// is **rejected by every OLDER verifier** that predates it. So any addition to a
    /// consumer's caveat vocabulary is a wire change that must be rolled out to all
    /// verifiers before any issuer mints it, coordinated via the same
    /// shim-alignment / wire-version discipline as any other guest-facing wire change.
    fn from_cbor(value: &CborValue) -> Result<Self, TokenError>;

    /// An expiry this caveat imposes, if any. [`attenuate`] stamps it as the
    /// block's `exp` claim, and the chain walk folds it into the credential's
    /// effective expiry by engine-owned [`min_opt`] (so a block can only *shorten*
    /// the lifetime). Default: no expiry.
    fn not_after(&self) -> Option<u64> {
        None
    }
}

/// A verified credential chain: the engine-owned result of [`verify_credential`].
///
/// Authority comes from [`root_claims`](Self::root_claims) **only** — the consumer
/// projects its own claims (roles/kind/…) from the verified root; no child block's
/// payload is read as authority. The [`caveats`](Self::caveats) are the
/// engine-verified monotone intersection of every block, and [`exp`](Self::exp)
/// the min across the chain.
///
/// (U8–U10, #9) Derives [`Debug`] (when the caveat vocabulary `C` is `Debug`), so
/// a consumer can log / `assert_eq!` a verified chain directly.
///
/// `#[non_exhaustive]`: the engine-owned result of a verification — a consumer reads its
/// fields and never forges one, so a future verified attribute is an additive, non-breaking
/// field (the only constructor is this crate's `verify_credential`).
#[derive(Debug)]
#[non_exhaustive]
pub struct CredentialChain<C: NarrowingCaveats> {
    /// The verified **root** block's CWT claim set — the sole authority source.
    pub root_claims: ClaimsSet,
    /// The root's revocation id (`cti`, hex): revoking it revokes the whole chain.
    pub cti: String,
    /// The effective expiry (Unix seconds) — the min across the chain, if any.
    pub exp: Option<u64>,
    /// The intersected, engine-verified-monotone narrowing caveats.
    pub caveats: C,
    /// The **terminal** holder key (`cnf`) of the presented credential — the leaf
    /// delegate's key, or the root's own for a plain token; `None` for a
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
pub async fn attenuate<C: NarrowingCaveats>(
    credential: &str,
    holder_signer: &dyn Signer,
    caveats: &C,
    next_holder: Option<&TokenPublicKey>,
    now_unix: u64,
) -> Result<String, TokenError> {
    let mut blocks = decode_credential(credential)?;
    let mut builder = ClaimsSetBuilder::new()
        .issued_at(Timestamp::WholeSeconds(now_unix as i64))
        .cwt_id(random_cti()?)
        .text_claim(
            C::KIND_CLAIM.to_string(),
            CborValue::Text(C::DELEGATION_KIND.to_string()),
        )
        .text_claim(C::CAVEATS_CLAIM.to_string(), caveats.to_cbor());
    if let Some(holder) = next_holder {
        builder = builder.text_claim(C::CNF_CLAIM.to_string(), CborValue::Text(holder.to_hex()));
    }
    // Fold `not_after` into `exp` so the standard expiry check enforces it.
    if let Some(na) = caveats.not_after() {
        builder = builder.expiration_time(Timestamp::WholeSeconds(na as i64));
    }
    // A block carries NO authority claims: children can only narrow (the
    // anti-escalation invariant — the walk never reads a block's authority).
    blocks.push(sign_claims_bytes(builder.build(), holder_signer).await?);
    encode_chain(blocks)
}

/// Read a block's `exp` as Unix seconds (no enforcement) — the raw value the walk
/// min-folds. `None` when absent. Enforcement is separate (see [`walk_chain`]).
fn block_exp(claims: &ClaimsSet) -> Option<u64> {
    match claims.expiration_time {
        Some(Timestamp::WholeSeconds(s)) => Some(s.max(0) as u64),
        _ => None,
    }
}

/// Verify a presented credential — a plain token *or* a delegation chain — against
/// the root public key at `now_unix`. Walks the chain (each block under its
/// parent's `cnf`, PoP-style), **verifies every caveat step only narrows**
/// (fail-closed), folds the expiry by `min`, enforces it, and returns the
/// **root's** claim set and `cti`. Resource bounds
/// ([`MAX_CHAIN_BYTES`]/[`MAX_CHAIN_DEPTH`]) are enforced *before* any signature
/// verification. Revocation (root `cti`) stays the caller's job.
///
/// **Truncation note:** this accepts *any valid prefix* of a chain, so its leaf may
/// be an intermediate holder. A caller with **no** per-request proof of possession
/// of the leaf must use [`verify_presented`] (which additionally requires a sealed
/// leaf); a PoP-capable caller uses this plus a proof against
/// [`CredentialChain::leaf_cnf`]. See [`verify_presented`] (uchron RFC-009 §7, C1).
pub fn verify_credential<C: NarrowingCaveats>(
    credential: &str,
    root_public: &TokenPublicKey,
    now_unix: u64,
) -> Result<CredentialChain<C>, TokenError> {
    walk_chain(credential, root_public, Some(now_unix))
}

/// Like [`verify_credential`], but **does not enforce expiry** — it proves
/// *authenticity* (signatures, PoP `cnf` binding, the engine-verified monotone
/// narrowing) and returns the chain with its min-folded effective
/// [`exp`](CredentialChain::exp) for the caller to check against its **own** clock
/// (U8–U10, #2). A consumer whose time is not the wall clock — uchron runs expiry
/// on a hybrid logical clock — needs "authentic" and "expired" as *separate*
/// outcomes: it calls this, then [`CredentialChain::is_expired_at`] (or compares
/// `exp` itself). `verify_credential(c, k, now)` is exactly this plus a
/// `now > exp` ⇒ [`TokenError::Expired`] check.
pub fn verify_credential_unexpired<C: NarrowingCaveats>(
    credential: &str,
    root_public: &TokenPublicKey,
) -> Result<CredentialChain<C>, TokenError> {
    walk_chain(credential, root_public, None)
}

/// The chain walk shared by [`verify_credential`] (enforcing) and
/// [`verify_credential_unexpired`] (authenticity only). `enforce_expiry_at =
/// Some(now)` applies the per-block `now > exp` ⇒ [`TokenError::Expired`] check at
/// exactly the points the enforcing verifier always has; `None` skips it (the
/// returned `exp` is still the min-fold, for the caller's own clock).
fn walk_chain<C: NarrowingCaveats>(
    credential: &str,
    root_public: &TokenPublicKey,
    enforce_expiry_at: Option<u64>,
) -> Result<CredentialChain<C>, TokenError> {
    let blocks = decode_credential(credential)?;
    let (root_bytes, children) = blocks
        .split_first()
        .ok_or_else(|| TokenError::Invalid("empty credential".into()))?;

    let root_claims = verify_envelope_bytes(root_bytes, root_public)?;
    let cti = claim_cti(&root_claims)?;

    // (U8–U10, #8) Read caveats on the ROOT block too (previously never read): a
    // root that self-restricts is honored as the initial accumulator rather than
    // silently ignored. Every root boatramp/uchron mint today carries none, so the
    // accumulator still starts at `default()` (the lattice top) for them — but a
    // root that *does* carry caveats now has them enforced, fail-safe. Decoding is
    // the same fallible path as a block's (#3): an undecodable root caveat refuses.
    let mut caveats = match text_claim(&root_claims, C::CAVEATS_CLAIM) {
        Some(v) => C::from_cbor(v)?,
        None => C::default(),
    };

    let root_exp = block_exp(&root_claims);
    if let Some(now) = enforce_expiry_at
        && let Some(exp) = root_exp
        && now > exp
    {
        return Err(TokenError::Expired);
    }
    let mut effective_exp = root_exp;
    let mut parent_cnf = claim_text(&root_claims, C::CNF_CLAIM);

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
        let kind = text_claim(&claims, C::KIND_CLAIM).and_then(|v| match v {
            CborValue::Text(t) => Some(t.as_str()),
            _ => None,
        });
        if kind != Some(C::DELEGATION_KIND) {
            return Err(TokenError::Claims("not a delegation block".into()));
        }

        // (#3) Decode this block's caveats fail-closed: an unknown restriction key
        // (or an ill-typed one) refuses the whole credential rather than silently
        // dropping a narrowing the verifier can't interpret.
        let block_caveats = match text_claim(&claims, C::CAVEATS_CLAIM) {
            Some(v) => C::from_cbor(v)?,
            None => C::default(),
        };

        // Anti-escalation: a block's authority is never read — only its caveats
        // narrow. The engine folds with the consumer `meet`, then VERIFIES the
        // result is narrower-or-equal than BOTH the accumulator and this block. A
        // consumer `meet` that widens (buggy or adversarial) is caught here and the
        // whole credential rejected — a widening chain is structurally impossible.
        let tightened = caveats.meet(&block_caveats);
        if !tightened.is_narrower_or_equal(&caveats)
            || !tightened.is_narrower_or_equal(&block_caveats)
        {
            return Err(TokenError::Widened(
                "delegation meet is not a lower bound (consumer meet widens authority)".into(),
            ));
        }

        // (U8–U10, #4) Report a block that TRIES to widen: the accumulator is
        // *strictly* narrower than this block, so the block names looser
        // restrictions than are already in force and narrows nothing (the honest
        // `meet` just absorbs it). Previously unreported — now a typed rejection, so
        // an attenuation mistake / truncation attempt surfaces instead of hiding. A
        // block that adds no caveat at all (the lattice top — e.g. a pure
        // re-delegation that only names the next holder) is *not* flagged.
        let block_is_top = C::default().is_narrower_or_equal(&block_caveats);
        if !block_is_top
            && caveats.is_narrower_or_equal(&block_caveats)
            && !block_caveats.is_narrower_or_equal(&caveats)
        {
            return Err(TokenError::Widened(
                "a delegation block tries to widen the running authority".into(),
            ));
        }

        caveats = tightened;
        let be = block_exp(&claims);
        if let Some(now) = enforce_expiry_at
            && let Some(exp) = be
            && now > exp
        {
            return Err(TokenError::Expired);
        }
        effective_exp = min_opt(effective_exp, be);
        parent_cnf = claim_text(&claims, C::CNF_CLAIM);
    }

    Ok(CredentialChain {
        root_claims,
        cti,
        exp: effective_exp,
        caveats,
        // After the walk, `parent_cnf` holds the terminal block's declared holder
        // key (or the root's, for a plain token) — the leaf a PoP proof binds to.
        leaf_cnf: parent_cnf,
    })
}

/// The **sealed-leaf** predicate (uchron RFC-009 §7, finding C1). A presented
/// chain's terminal holder (`leaf_cnf`) is *sealed* iff it names **no** next holder
/// (`None`), **or** names the **root's own verifying key** — in both cases the leaf
/// has no presentable extension (to append a further narrowing block you must sign
/// with the leaf's declared `cnf`, which is either absent or the root signing key a
/// client never holds). An **unsealed** leaf names a further holder that could
/// delegate on, so a prefix ending there may be a *truncation* of a longer,
/// more-narrowed chain. This is the single source of truth for the rule, shared by
/// [`CredentialChain::leaf_is_sealed`] and the thin consumer layers.
pub fn leaf_cnf_is_sealed(leaf_cnf: Option<&str>, root_public: &TokenPublicKey) -> bool {
    match leaf_cnf {
        None => true,
        Some(cnf) => cnf == root_public.to_hex(),
    }
}

impl<C: NarrowingCaveats> CredentialChain<C> {
    /// Whether this presented chain ends in a **sealed** leaf — see
    /// [`leaf_cnf_is_sealed`] and [`verify_presented`] (uchron RFC-009 §7, C1). A
    /// sealed leaf has no un-presented narrowing beyond what is shown; an unsealed
    /// leaf is trustworthy only with a per-request PoP of [`leaf_cnf`](Self::leaf_cnf).
    pub fn leaf_is_sealed(&self, root_public: &TokenPublicKey) -> bool {
        leaf_cnf_is_sealed(self.leaf_cnf.as_deref(), root_public)
    }

    /// Whether the credential's effective [`exp`](Self::exp) is past `now_unix`.
    /// Pairs with [`verify_credential_unexpired`] (authenticity without expiry
    /// enforcement) so a consumer on a non-wall clock separates "authentic" from
    /// "expired" (U8–U10, #2). `None` (no expiry) is never expired.
    pub fn is_expired_at(&self, now_unix: u64) -> bool {
        matches!(self.exp, Some(exp) if now_unix > exp)
    }
}

/// Verify a **presented** credential for a consumer that has **no** per-request
/// proof of possession (a cookie, an in-process channel, a protected-preview or
/// identity gate): exactly [`verify_credential`], but additionally **requires a
/// sealed leaf** ([`CredentialChain::leaf_is_sealed`]).
///
/// This closes the chain-prefix **truncation** escalation (uchron RFC-009 §7, C1):
/// a delegation block is not bound to the blocks after it, so every prefix of a
/// chain is itself a valid chain. A holder who possesses an *intermediate* `cnf`
/// key could otherwise strip the trailing narrowing blocks, present the shorter
/// prefix (which ends at a key it holds), and recover the parent's **un-narrowed**
/// authority. Requiring a sealed leaf refuses any prefix that ends at an
/// intermediate (further-delegatable) holder, so the only chains accepted are
/// terminal ones with no un-presented narrowing.
///
/// A **PoP-capable** caller (DPoP) must *not* route through this: it calls
/// [`verify_credential`] and then proves possession of
/// [`CredentialChain::leaf_cnf`] per request, which treats the (possibly unsealed)
/// leaf as the endpoint by binding the request to that exact key — so a prefix
/// ending at a key the presenter does not hold fails the PoP check instead. The two
/// are the complementary halves of "a presented chain must end in a sealed leaf,
/// **or** the caller must prove PoP of `leaf_cnf`".
///
/// **Minting note:** a consumer that narrows only *offline, on the holder's side*
/// (boatramp's `attenuate` / `token attenuate`) has no presentable prefix to
/// escalate *to*, because the narrower already holds the broader authority. An
/// *issuer-side* narrowing (a host appending a narrowing block to a credential it
/// signs and hands out) must **re-root** — mint a fresh root whose leaf names the
/// root's own key — so the handed-out credential has no presentable prefix (uchron's
/// `attenuate_as_issuer`). boatramp performs no such issuer-side narrowing today.
pub fn verify_presented<C: NarrowingCaveats>(
    credential: &str,
    root_public: &TokenPublicKey,
    now_unix: u64,
) -> Result<CredentialChain<C>, TokenError> {
    require_sealed_leaf(
        verify_credential(credential, root_public, now_unix)?,
        root_public,
    )
}

/// Verify a **presented** credential for a PoP-less consumer **without enforcing
/// wall-clock expiry** — the sealed-leaf + authenticity half of [`verify_presented`],
/// leaving the expiry comparison to the caller's own clock (U11-1, pairing the
/// presented form with [`verify_credential_unexpired`]).
///
/// This is exactly [`verify_credential_unexpired`] plus the **sealed-leaf**
/// requirement of [`verify_presented`]: it proves authenticity (signatures, the PoP
/// `cnf` chain-binding, and the engine-verified monotone narrowing) **and** refuses
/// an unsealed (onward-delegatable) leaf — closing the chain-prefix truncation
/// escalation (C1) — but does **not** compare the min-folded
/// [`exp`](CredentialChain::exp) against any clock. A consumer whose notion of "now"
/// is not the wall clock — uchron runs expiry on a hybrid logical clock — calls
/// this, then checks expiry itself with [`CredentialChain::is_expired_at`] (passing
/// its own `now`) or by comparing [`exp`](CredentialChain::exp) directly. It no
/// longer has to hand-compose [`verify_credential_unexpired`] +
/// [`leaf_is_sealed`](CredentialChain::leaf_is_sealed) (and risk forgetting the
/// sealed-leaf gate, re-opening the truncation hole).
///
/// `verify_presented(c, k, now)` is exactly this followed by a `now > exp` ⇒
/// [`TokenError::Expired`] check. A **PoP-capable** caller must still route through
/// [`verify_credential_unexpired`] + a per-request proof against
/// [`CredentialChain::leaf_cnf`] instead — see [`verify_presented`] for why the two
/// are complementary.
pub fn verify_presented_unexpired<C: NarrowingCaveats>(
    credential: &str,
    root_public: &TokenPublicKey,
) -> Result<CredentialChain<C>, TokenError> {
    require_sealed_leaf(
        verify_credential_unexpired(credential, root_public)?,
        root_public,
    )
}

/// The **sealed-leaf** gate shared by [`verify_presented`] (expiry-enforcing) and
/// [`verify_presented_unexpired`] (caller-clock): pass an already-verified chain
/// through iff its leaf is sealed ([`CredentialChain::leaf_is_sealed`]), else refuse
/// with [`TokenError::Unsealed`]. The single source of truth for the presented-form
/// truncation refusal (C1), so the two presented verifiers never drift apart.
fn require_sealed_leaf<C: NarrowingCaveats>(
    verified: CredentialChain<C>,
    root_public: &TokenPublicKey,
) -> Result<CredentialChain<C>, TokenError> {
    if !verified.leaf_is_sealed(root_public) {
        return Err(TokenError::Unsealed(
            "presented credential ends at an intermediate holder (unsealed leaf); \
             present the sealed delegate, or prove possession of the leaf cnf"
                .into(),
        ));
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A faithful, well-behaved caveat vocabulary for the engine tests: a single
    // monotone `read_only` bit. `meet` is OR (a true meet), the order is honest.
    #[derive(Clone, Default, Debug, PartialEq)]
    struct ReadOnly(bool);

    impl NarrowingCaveats for ReadOnly {
        const KIND_CLAIM: &'static str = "k";
        const CNF_CLAIM: &'static str = "cnf";
        const CAVEATS_CLAIM: &'static str = "cav";
        const DELEGATION_KIND: &'static str = "delegation";

        fn meet(&self, deeper: &Self) -> Self {
            Self(self.0 || deeper.0)
        }
        fn is_narrower_or_equal(&self, other: &Self) -> bool {
            // self ⊑ other iff self restricts at least as much: other read_only ⇒ self read_only.
            !other.0 || self.0
        }
        fn to_cbor(&self) -> CborValue {
            CborValue::Bool(self.0)
        }
        fn from_cbor(value: &CborValue) -> Result<Self, TokenError> {
            match value {
                CborValue::Bool(b) => Ok(Self(*b)),
                // Fallible (#3): an ill-typed caveat refuses rather than silently
                // decoding to the top (which would drop the narrowing).
                _ => Err(TokenError::Claims("read_only caveat must be a bool".into())),
            }
        }
    }

    // An ADVERSARIAL / faulty vocabulary: its `meet` *widens* (it drops a
    // restriction the accumulator carried) while its order relation stays honest.
    // The engine must catch the widening and reject the chain — a faulty
    // consumer caveat cannot mint a credential whose chain widens authority.
    #[derive(Clone, Default, Debug, PartialEq)]
    struct Widening(bool);

    impl NarrowingCaveats for Widening {
        const KIND_CLAIM: &'static str = "k";
        const CNF_CLAIM: &'static str = "cnf";
        const CAVEATS_CLAIM: &'static str = "cav";
        const DELEGATION_KIND: &'static str = "delegation";

        fn meet(&self, deeper: &Self) -> Self {
            // BUG/ATTACK: ignore the accumulator entirely and take ONLY this block's
            // value — so a child block with `false` erases a parent's `true`.
            Self(deeper.0)
        }
        fn is_narrower_or_equal(&self, other: &Self) -> bool {
            // Honest order (same as ReadOnly): this is what the engine checks against.
            !other.0 || self.0
        }
        fn to_cbor(&self) -> CborValue {
            CborValue::Bool(self.0)
        }
        fn from_cbor(value: &CborValue) -> Result<Self, TokenError> {
            match value {
                CborValue::Bool(b) => Ok(Self(*b)),
                _ => Err(TokenError::Claims("widening caveat must be a bool".into())),
            }
        }
    }

    // An ORDERED vocabulary with a non-top "looser" value, so a block that NARROWS
    // NOTHING yet is not the lattice top is expressible — the case the #4
    // block-widened report catches. `Floor(n)`: a numeric restriction floor where a
    // HIGHER `n` is NARROWER; `0` is the top (unrestricted). `meet` is the max
    // (tightest wins); the order is `self ⊒ other ⇔ self.0 >= other.0`.
    #[derive(Clone, Copy, Default, Debug, PartialEq)]
    struct Floor(u8);

    impl NarrowingCaveats for Floor {
        const KIND_CLAIM: &'static str = "k";
        const CNF_CLAIM: &'static str = "cnf";
        const CAVEATS_CLAIM: &'static str = "cav";
        const DELEGATION_KIND: &'static str = "delegation";

        fn meet(&self, deeper: &Self) -> Self {
            Self(self.0.max(deeper.0))
        }
        fn is_narrower_or_equal(&self, other: &Self) -> bool {
            self.0 >= other.0
        }
        fn to_cbor(&self) -> CborValue {
            CborValue::Integer(self.0.into())
        }
        fn from_cbor(value: &CborValue) -> Result<Self, TokenError> {
            match value {
                CborValue::Integer(i) => u8::try_from(*i)
                    .map(Self)
                    .map_err(|_| TokenError::Claims("floor out of range".into())),
                _ => Err(TokenError::Claims("floor caveat must be an integer".into())),
            }
        }
    }

    // A caveat that carries only an EXPIRY (`not_after`), to exercise the expiry
    // fold + the caller-clock presented verifier (U11-1). An EARLIER `not_after` is
    // NARROWER (shorter life); the lattice top is "no expiry" (`u64::MAX`, which
    // `not_after` reports as `None`). `meet` is the min (tightest/earliest wins).
    #[derive(Clone, Copy, Debug, PartialEq)]
    struct Expiring(u64);

    impl Default for Expiring {
        fn default() -> Self {
            Self(u64::MAX) // top: no expiry restriction
        }
    }

    impl NarrowingCaveats for Expiring {
        const KIND_CLAIM: &'static str = "k";
        const CNF_CLAIM: &'static str = "cnf";
        const CAVEATS_CLAIM: &'static str = "cav";
        const DELEGATION_KIND: &'static str = "delegation";

        fn meet(&self, deeper: &Self) -> Self {
            Self(self.0.min(deeper.0))
        }
        fn is_narrower_or_equal(&self, other: &Self) -> bool {
            // self ⊑ other iff self expires no later than other (at least as restrictive).
            self.0 <= other.0
        }
        fn to_cbor(&self) -> CborValue {
            CborValue::Integer(self.0.into())
        }
        fn from_cbor(value: &CborValue) -> Result<Self, TokenError> {
            match value {
                CborValue::Integer(i) => u64::try_from(*i)
                    .map(Self)
                    .map_err(|_| TokenError::Claims("expiring caveat out of range".into())),
                _ => Err(TokenError::Claims(
                    "expiring caveat must be an integer".into(),
                )),
            }
        }
        fn not_after(&self) -> Option<u64> {
            (self.0 != u64::MAX).then_some(self.0)
        }
    }

    async fn mint_root(signer: &dyn Signer, holder: &TokenPublicKey) -> String {
        // A minimal root block: a kind tag + the holder `cnf`, signed by the root.
        let claims = ClaimsSetBuilder::new()
            .issued_at(Timestamp::WholeSeconds(1_000))
            .cwt_id(random_cti().unwrap())
            .text_claim("k".to_string(), CborValue::Text("role".to_string()))
            .text_claim("cnf".to_string(), CborValue::Text(holder.to_hex()))
            .build();
        sign_claims(claims, signer).await.unwrap()
    }

    #[tokio::test]
    async fn honest_chain_narrows_and_verifies() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let h1 = LocalSigner::generate(TokenAlg::Ed25519);
        let h1_pub = h1.public_key();
        let h2 = LocalSigner::generate(TokenAlg::Ed25519);
        let h2_pub = h2.public_key();

        let token = mint_root(&root, &h1_pub).await;
        // h1 narrows to read-only, delegating onward to h2.
        let c1 = attenuate(&token, &h1, &ReadOnly(true), Some(&h2_pub), 1_000)
            .await
            .unwrap();
        // h2 adds no further restriction.
        let c2 = attenuate(&c1, &h2, &ReadOnly(false), None, 1_000)
            .await
            .unwrap();

        let chain = verify_credential::<ReadOnly>(&c2, &root_pub, 1_000).unwrap();
        // The accumulated caveat stays narrowed (read-only), never re-widened.
        assert_eq!(chain.caveats, ReadOnly(true));
        assert_eq!(chain.leaf_cnf, None);
    }

    #[tokio::test]
    async fn engine_rejects_a_widening_consumer_meet() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let h1 = LocalSigner::generate(TokenAlg::Ed25519);
        let h1_pub = h1.public_key();
        let h2 = LocalSigner::generate(TokenAlg::Ed25519);
        let h2_pub = h2.public_key();

        let token = mint_root(&root, &h1_pub).await;
        // Block 1 imposes the restriction (`true`), delegating onward to h2.
        let c1 = attenuate(&token, &h1, &Widening(true), Some(&h2_pub), 1_000)
            .await
            .unwrap();
        // Block 2 carries `false`; the adversarial `meet` would DROP block 1's
        // restriction (widen `true` → `false`).
        let c2 = attenuate(&c1, &h2, &Widening(false), None, 1_000)
            .await
            .unwrap();

        // The engine's monotonicity check catches the widening and fails closed,
        // now with the typed `Widened` variant (U8–U10, #1/#4) rather than a
        // text-matched `Claims`.
        assert!(
            matches!(
                verify_credential::<Widening>(&c2, &root_pub, 1_000),
                Err(TokenError::Widened(_))
            ),
            "a widening consumer meet must be rejected with TokenError::Widened",
        );

        // Sanity: the SAME chain shape with the honest `ReadOnly` vocabulary (whose
        // `meet` is a true meet) verifies — so it is the widening, not the shape,
        // the engine rejects. (Re-mint under ReadOnly: the wire caveat is identical.)
        let c1b = attenuate(&token, &h1, &ReadOnly(true), Some(&h2_pub), 1_000)
            .await
            .unwrap();
        let c2b = attenuate(&c1b, &h2, &ReadOnly(false), None, 1_000)
            .await
            .unwrap();
        let ok = verify_credential::<ReadOnly>(&c2b, &root_pub, 1_000).unwrap();
        assert_eq!(ok.caveats, ReadOnly(true));
    }

    // ---- C1: sealed-leaf / chain-prefix truncation -------------------------

    /// The engine-level exploit witness + fix (uchron RFC-009 §7, C1), on the
    /// GENERIC `CredentialChain<C>` so any consumer vocabulary gets truncation
    /// resistance by construction. A stripped prefix recovers the un-narrowed
    /// caveat under `verify_credential`; `verify_presented` refuses it (unsealed
    /// leaf), and still accepts a legitimately-narrowed chain that seals its leaf.
    #[tokio::test]
    async fn verify_presented_seals_against_truncation() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let h1 = LocalSigner::generate(TokenAlg::Ed25519);
        let h1_pub = h1.public_key();
        let h2 = LocalSigner::generate(TokenAlg::Ed25519);
        let h2_pub = h2.public_key();

        // root(cnf = h1) → block1(read-only, cnf = h2): the legitimate narrowed chain.
        let token = mint_root(&root, &h1_pub).await;
        let narrowed = attenuate(&token, &h1, &ReadOnly(true), Some(&h2_pub), 1_000)
            .await
            .unwrap();
        let v = verify_credential::<ReadOnly>(&narrowed, &root_pub, 1_000).unwrap();
        assert_eq!(v.caveats, ReadOnly(true));
        assert_eq!(v.leaf_cnf, Some(h2_pub.to_hex()));

        // WITNESS: the root prefix ALONE drops the narrowing — authority recovered —
        // and `verify_credential` accepts it (its leaf, h1, is a key the stripper holds).
        let stripped = verify_credential::<ReadOnly>(&token, &root_pub, 1_000).unwrap();
        assert_eq!(
            stripped.caveats,
            ReadOnly(false),
            "WITNESS: truncation recovers the un-narrowed caveat"
        );
        assert_eq!(stripped.leaf_cnf, Some(h1_pub.to_hex()));
        assert!(
            !stripped.leaf_is_sealed(&root_pub),
            "the prefix ends at an intermediate holder → unsealed"
        );

        // FIX: `verify_presented` refuses the truncated prefix...
        assert!(matches!(
            verify_presented::<ReadOnly>(&token, &root_pub, 1_000),
            Err(TokenError::Unsealed(_))
        ));
        // ...and also the FULL chain whose leaf is still onward-delegatable (h2):
        // without a PoP of that leaf the verifier can't tell it from a truncation.
        assert!(matches!(
            verify_presented::<ReadOnly>(&narrowed, &root_pub, 1_000),
            Err(TokenError::Unsealed(_))
        ));

        // A SEALED narrowed chain (next_holder = None) verifies and still narrows.
        let sealed = attenuate(&token, &h1, &ReadOnly(true), None, 1_000)
            .await
            .unwrap();
        let vs = verify_presented::<ReadOnly>(&sealed, &root_pub, 1_000).unwrap();
        assert!(vs.leaf_is_sealed(&root_pub));
        assert_eq!(vs.leaf_cnf, None);
        assert_eq!(vs.caveats, ReadOnly(true));

        // A plain token (no `cnf` at all) is sealed too.
        let plain = {
            let claims = ClaimsSetBuilder::new()
                .cwt_id(random_cti().unwrap())
                .text_claim("k".to_string(), CborValue::Text("role".to_string()))
                .build();
            sign_claims(claims, &root).await.unwrap()
        };
        assert!(
            verify_presented::<ReadOnly>(&plain, &root_pub, 1_000)
                .unwrap()
                .leaf_is_sealed(&root_pub)
        );
    }

    /// A terminal block that names the **root's own verifying key** is sealed
    /// (uchron's issuer re-root / self-narrow endpoint): a client never holds the
    /// root signing key, so it cannot extend such a leaf.
    #[tokio::test]
    async fn verify_presented_treats_a_root_keyed_leaf_as_sealed() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let h1 = LocalSigner::generate(TokenAlg::Ed25519);
        let token = mint_root(&root, &h1.public_key()).await;
        let chain = attenuate(&token, &h1, &ReadOnly(true), Some(&root_pub), 1_000)
            .await
            .unwrap();
        let v = verify_presented::<ReadOnly>(&chain, &root_pub, 1_000)
            .expect("a leaf naming the root key is a sealed endpoint");
        assert_eq!(v.leaf_cnf, Some(root_pub.to_hex()));
        assert!(v.leaf_is_sealed(&root_pub));
    }

    // ---- Ergonomics (U8–U10) ----------------------------------------------

    /// (#4) A block that tries to WIDEN — names looser restrictions than are in
    /// force, narrowing nothing, yet is not the lattice top — is reported with
    /// `TokenError::Widened` rather than silently absorbed. Controls: a
    /// further-narrowing block and a pure re-delegation (top) block are accepted.
    #[tokio::test]
    async fn engine_reports_a_block_that_tries_to_widen() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let h1 = LocalSigner::generate(TokenAlg::Ed25519);
        let h1_pub = h1.public_key();
        let h2 = LocalSigner::generate(TokenAlg::Ed25519);
        let h2_pub = h2.public_key();

        let token = mint_root(&root, &h1_pub).await;
        // Block 1 raises the floor to 5 (narrow), delegating onward to h2.
        let c1 = attenuate(&token, &h1, &Floor(5), Some(&h2_pub), 1_000)
            .await
            .unwrap();
        // Block 2 names floor 2 — LOOSER than the 5 in force: narrows nothing, not top.
        let c2 = attenuate(&c1, &h2, &Floor(2), None, 1_000).await.unwrap();
        assert!(matches!(
            verify_credential::<Floor>(&c2, &root_pub, 1_000),
            Err(TokenError::Widened(_))
        ));

        // Control: a block that FURTHER narrows (floor 8 ≥ 5) is accepted.
        let c2b = attenuate(&c1, &h2, &Floor(8), None, 1_000).await.unwrap();
        assert_eq!(
            verify_credential::<Floor>(&c2b, &root_pub, 1_000)
                .unwrap()
                .caveats,
            Floor(8)
        );
        // Control: a pure re-delegation (the top, floor 0) is NOT flagged.
        let c2c = attenuate(&c1, &h2, &Floor(0), None, 1_000).await.unwrap();
        assert_eq!(
            verify_credential::<Floor>(&c2c, &root_pub, 1_000)
                .unwrap()
                .caveats,
            Floor(5)
        );
    }

    /// (#3) A block whose caveat is undecodable for the vocabulary (here, the wrong
    /// CBOR type) refuses the whole credential (fail-closed) rather than silently
    /// decoding to the top and dropping the narrowing.
    #[tokio::test]
    async fn engine_refuses_an_undecodable_block_caveat() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let h1 = LocalSigner::generate(TokenAlg::Ed25519);
        let token = mint_root(&root, &h1.public_key()).await;

        // A delegation block whose `cav` is text, not the bool ReadOnly expects.
        let claims = ClaimsSetBuilder::new()
            .cwt_id(random_cti().unwrap())
            .text_claim("k".to_string(), CborValue::Text("delegation".to_string()))
            .text_claim("cav".to_string(), CborValue::Text("not-a-bool".to_string()))
            .build();
        let block = sign_claims_bytes(claims, &h1).await.unwrap();
        let mut blocks = decode_credential(&token).unwrap();
        blocks.push(block);
        let chain = encode_chain(blocks).unwrap();
        assert!(matches!(
            verify_credential::<ReadOnly>(&chain, &root_pub, 1_000),
            Err(TokenError::Claims(_))
        ));
    }

    /// (#8) A root that self-restricts (carries a caveats claim) has it honored as
    /// the initial accumulator, rather than silently ignored.
    #[tokio::test]
    async fn root_caveats_are_read_as_the_initial_accumulator() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let claims = ClaimsSetBuilder::new()
            .cwt_id(random_cti().unwrap())
            .text_claim("k".to_string(), CborValue::Text("role".to_string()))
            .text_claim("cav".to_string(), ReadOnly(true).to_cbor())
            .build();
        let token = sign_claims(claims, &root).await.unwrap();
        assert_eq!(
            verify_credential::<ReadOnly>(&token, &root_pub, 1_000)
                .unwrap()
                .caveats,
            ReadOnly(true),
            "a self-restricting root's caveats are honored, not ignored"
        );
    }

    /// (#2) Authenticity and expiry are separable: `verify_credential_unexpired`
    /// returns an AUTHENTIC chain past its `exp` (carrying the effective expiry),
    /// while the enforcing `verify_credential` returns `Expired`. An inauthentic
    /// token still fails the unexpired path.
    #[tokio::test]
    async fn unexpired_verify_separates_authenticity_from_expiry() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let claims = ClaimsSetBuilder::new()
            .cwt_id(random_cti().unwrap())
            .text_claim("k".to_string(), CborValue::Text("role".to_string()))
            .expiration_time(Timestamp::WholeSeconds(2_000))
            .build();
        let token = sign_claims(claims, &root).await.unwrap();

        assert!(matches!(
            verify_credential::<ReadOnly>(&token, &root_pub, 3_000),
            Err(TokenError::Expired)
        ));
        let v = verify_credential_unexpired::<ReadOnly>(&token, &root_pub).unwrap();
        assert_eq!(v.exp, Some(2_000));
        assert!(v.is_expired_at(3_000));
        assert!(!v.is_expired_at(1_500));

        let other = LocalSigner::generate(TokenAlg::Es256).public_key();
        assert!(verify_credential_unexpired::<ReadOnly>(&token, &other).is_err());
    }

    /// (#5) A protected-header `kid` is stamped (signed-over), peekable WITHOUT the
    /// verifying key for key selection, and the token still verifies; a plain token
    /// peeks as `None`. Unverified claims are readable for routing.
    #[tokio::test]
    async fn kid_is_stamped_and_peekable_without_verifying() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let kid = b"key-2026-11";
        let claims = ClaimsSetBuilder::new()
            .cwt_id(random_cti().unwrap())
            .text_claim("k".to_string(), CborValue::Text("role".to_string()))
            .build();
        let token = sign_claims_with_kid(claims, &root, kid).await.unwrap();

        assert_eq!(peek_protected_kid(&token).as_deref(), Some(&kid[..]));
        assert!(verify_envelope(&token, &root_pub).is_ok());

        let plain = {
            let c = ClaimsSetBuilder::new()
                .cwt_id(random_cti().unwrap())
                .text_claim("k".to_string(), CborValue::Text("role".to_string()))
                .build();
            sign_claims(c, &root).await.unwrap()
        };
        assert_eq!(peek_protected_kid(&plain), None);

        let peeked = peek_unverified_claims(&token).unwrap();
        assert_eq!(claim_text(&peeked, "k").as_deref(), Some("role"));
    }

    /// (#9) `CredentialChain` is `Debug`.
    #[tokio::test]
    async fn credential_chain_is_debug() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let h1 = LocalSigner::generate(TokenAlg::Ed25519);
        let token = mint_root(&root, &h1.public_key()).await;
        let v = verify_credential::<ReadOnly>(&token, &root.public_key(), 1_000).unwrap();
        assert!(!format!("{v:?}").is_empty());
    }

    // ---- U11-1: presented + caller-supplied expiry -------------------------

    /// (U11-1) `verify_presented_unexpired` does the sealed-leaf + authenticity
    /// checks of `verify_presented` but leaves expiry to the caller: an authentic,
    /// SEALED chain past its `exp` passes (carrying the effective expiry for the
    /// caller's own clock), while the enforcing `verify_presented` returns `Expired`.
    /// An UNSEALED (onward-delegatable) prefix is still refused (`Unsealed`), and an
    /// inauthentic credential still fails.
    #[tokio::test]
    async fn verify_presented_unexpired_seals_and_defers_expiry() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();
        let h1 = LocalSigner::generate(TokenAlg::Ed25519);
        let h1_pub = h1.public_key();
        let h2 = LocalSigner::generate(TokenAlg::Ed25519);
        let h2_pub = h2.public_key();

        // A SEALED, narrowed chain carrying an expiry at t=2_000 (via the caveat's
        // `not_after`, folded into the block `exp`).
        let token = mint_root(&root, &h1_pub).await;
        let sealed = attenuate(&token, &h1, &Expiring(2_000), None, 1_000)
            .await
            .unwrap();

        // Past expiry: the ENFORCING presented verifier rejects with `Expired`...
        assert!(matches!(
            verify_presented::<Expiring>(&sealed, &root_pub, 3_000),
            Err(TokenError::Expired)
        ));
        // ...but the caller-clock variant returns the AUTHENTIC chain (sealed leaf),
        // with the effective expiry for the caller to check against its own clock.
        let v = verify_presented_unexpired::<Expiring>(&sealed, &root_pub).unwrap();
        assert_eq!(v.exp, Some(2_000));
        assert!(v.is_expired_at(3_000));
        assert!(!v.is_expired_at(1_500));
        assert!(v.leaf_is_sealed(&root_pub));

        // An UNSEALED prefix (leaf names a further holder h2) is refused even past no
        // clock at all — the sealed-leaf gate (C1) is enforced here too.
        let unsealed = attenuate(&token, &h1, &Expiring(2_000), Some(&h2_pub), 1_000)
            .await
            .unwrap();
        assert!(matches!(
            verify_presented_unexpired::<Expiring>(&unsealed, &root_pub),
            Err(TokenError::Unsealed(_))
        ));

        // An inauthentic credential (wrong root key) fails regardless of expiry.
        let other = LocalSigner::generate(TokenAlg::Es256).public_key();
        assert!(verify_presented_unexpired::<Expiring>(&sealed, &other).is_err());
    }

    // ---- U11-2: typed chain-bounds error -----------------------------------

    /// (U11-2) A too-deep chain and an over-sized credential both surface as the
    /// typed `TokenError::Bounds(_)` (not `Invalid`/`Build`), so a consumer can tell
    /// "too big / too deep" from other invalidity by variant.
    #[tokio::test]
    async fn chain_bounds_are_typed() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let root_pub = root.public_key();

        // Depth: a chain of MAX_CHAIN_DEPTH+1 dummy blocks is refused before verify.
        let one = decode_credential(&mint_root(&root, &root_pub).await)
            .unwrap()
            .pop()
            .unwrap();
        let deep = encode_chain(vec![one; MAX_CHAIN_DEPTH + 1]).unwrap();
        assert!(matches!(
            verify_credential::<ReadOnly>(&deep, &root_pub, 1_000),
            Err(TokenError::Bounds(_))
        ));

        // Size: a credential larger than MAX_CHAIN_BYTES is refused before parsing.
        let big = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(vec![0x80u8; MAX_CHAIN_BYTES + 1]);
        assert!(matches!(
            verify_credential::<ReadOnly>(&big, &root_pub, 1_000),
            Err(TokenError::Bounds(_))
        ));

        // Mint side: `encode_chain` over an over-sized block set is `Bounds` too.
        let huge_block = vec![0u8; MAX_CHAIN_BYTES];
        assert!(matches!(
            encode_chain(vec![huge_block, vec![0u8; MAX_CHAIN_BYTES]]),
            Err(TokenError::Bounds(_))
        ));
    }

    // ---- U11-3: claim-builder re-exports -----------------------------------

    /// (U11-3) A consumer can build AND read a token end-to-end through the types
    /// `boatramp-cwt` re-exports (`ClaimsSetBuilder`, `Timestamp`, `ClaimName`,
    /// `Value`/`CborValue`, `ClaimsSet`) without a direct `coset` dependency. This
    /// test references them via `crate::` to assert they are part of the public
    /// surface.
    #[tokio::test]
    async fn claim_builder_reexports_round_trip() {
        use crate::{ClaimName, ClaimsSet, ClaimsSetBuilder, Timestamp, Value};

        let root = LocalSigner::generate(TokenAlg::Es256);
        let claims: ClaimsSet = ClaimsSetBuilder::new()
            .issued_at(Timestamp::WholeSeconds(1_000))
            .expiration_time(Timestamp::WholeSeconds(2_000))
            .cwt_id(random_cti().unwrap())
            .text_claim("role".to_string(), Value::Text("publisher".to_string()))
            .build();
        let token = sign_claims(claims, &root).await.unwrap();

        let verified = verify_envelope(&token, &root.public_key()).unwrap();
        // Read the private-use claim back by matching the re-exported `ClaimName`.
        let role = verified.rest.iter().find_map(|(k, v)| match (k, v) {
            (ClaimName::Text(t), Value::Text(val)) if t == "role" => Some(val.clone()),
            _ => None,
        });
        assert_eq!(role.as_deref(), Some("publisher"));
    }
}
