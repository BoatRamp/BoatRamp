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
use ciborium::value::Value as CborValue;
use coset::cwt::{ClaimsSet, ClaimsSetBuilder, Timestamp};
use coset::{
    Algorithm as CoseAlg, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder,
    TaggedCborSerializable, iana,
};

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

/// Decode a presented credential into its ordered blocks (raw tagged
/// `COSE_Sign1` bytes). A plain token is a bare `COSE_Sign1` (one block); a chain
/// is a CBOR array of byte strings. Enforces the size/depth bounds *before* any
/// verification, so a hostile credential can't force unbounded work.
pub fn decode_credential(credential: &str) -> Result<Vec<Vec<u8>>, TokenError> {
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
pub fn encode_chain(blocks: Vec<Vec<u8>>) -> Result<String, TokenError> {
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
        return Err(TokenError::Invalid("algorithm mismatch".into()));
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
/// and the monotonicity check, so the *narrowing* guarantee does not depend on the
/// consumer impl being correct: a `meet` that widens is caught and the credential
/// rejected (fail-closed). What the consumer owns is the *meaning* of its caveats
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

    /// Decode a block's caveats from CBOR. **Must never panic** on hostile input —
    /// unknown/ill-typed entries are ignored.
    fn from_cbor(value: &CborValue) -> Self;

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

/// Verify a presented credential — a plain token *or* a delegation chain — against
/// the root public key at `now_unix`. Walks the chain (each block under its
/// parent's `cnf`, PoP-style), **verifies every caveat step only narrows**
/// (fail-closed), folds the expiry by `min`, and returns the **root's** claim set
/// and `cti`. Resource bounds ([`MAX_CHAIN_BYTES`]/[`MAX_CHAIN_DEPTH`]) are enforced
/// *before* any signature verification. Revocation (root `cti`) stays the caller's
/// job.
pub fn verify_credential<C: NarrowingCaveats>(
    credential: &str,
    root_public: &TokenPublicKey,
    now_unix: u64,
) -> Result<CredentialChain<C>, TokenError> {
    let blocks = decode_credential(credential)?;
    let (root_bytes, children) = blocks
        .split_first()
        .ok_or_else(|| TokenError::Invalid("empty credential".into()))?;

    let root_claims = verify_envelope_bytes(root_bytes, root_public)?;
    let cti = claim_cti(&root_claims)?;

    let mut effective_exp = check_exp(&root_claims, now_unix)?;
    let mut caveats = C::default();
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

        // Anti-escalation: a block's authority is never read — only its caveats
        // narrow. The engine folds with the consumer `meet`, then VERIFIES the
        // result is narrower-or-equal than BOTH the accumulator and this block. A
        // consumer `meet` that widens (buggy or adversarial) is caught here and the
        // whole credential rejected — a widening chain is structurally impossible.
        let block_caveats = text_claim(&claims, C::CAVEATS_CLAIM)
            .map(C::from_cbor)
            .unwrap_or_default();
        let tightened = caveats.meet(&block_caveats);
        if !tightened.is_narrower_or_equal(&caveats)
            || !tightened.is_narrower_or_equal(&block_caveats)
        {
            return Err(TokenError::Claims(
                "delegation caveats must only narrow authority".into(),
            ));
        }
        caveats = tightened;
        effective_exp = min_opt(effective_exp, check_exp(&claims, now_unix)?);
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
        fn from_cbor(value: &CborValue) -> Self {
            Self(matches!(value, CborValue::Bool(true)))
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
        fn from_cbor(value: &CborValue) -> Self {
            Self(matches!(value, CborValue::Bool(true)))
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

        // The engine's monotonicity check catches the widening and fails closed.
        // (Match rather than `expect_err`: `CredentialChain` carries no `Debug`.)
        let err = match verify_credential::<Widening>(&c2, &root_pub, 1_000) {
            Ok(_) => panic!("a widening chain must be rejected"),
            Err(e) => e,
        };
        assert!(
            matches!(err, TokenError::Claims(m) if m.contains("narrow")),
            "widening must be rejected with a narrowing-violation claim error",
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
}
