//! Overlay identity (IU-1).
//!
//! An overlay identity **is** a raw Ed25519 public key — no PKI, no CA, no
//! session-resumption tokens. Trust is pin-or-allowlist of keys ([`crate::peer_policy`]).
//!
//! The subtlety this module resolves: boatramp has *two* Ed25519 worlds that
//! must name the same principal. [`boatramp_rpktls`] presents a TLS identity as
//! an RFC-7250 SubjectPublicKeyInfo (SPKI DER), while [`boatramp_core::cose`]
//! names identities as `TokenPublicKey` hex (`"ed25519:<hex>"`) and signs with a
//! `LocalSigner`. The overlay drives **both from one 32-byte seed** so the
//! identity pinned at the TLS layer and the identity bound into a capability
//! token / E2EE handshake are provably the same key.

use boatramp_core::cose::{LocalSigner, Signer, TokenAlg, TokenError, TokenPublicKey};
use boatramp_rpktls::{RpkError, RpkIdentity};
use zeroize::Zeroizing;

/// The fixed 12-byte DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410
/// §4): `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING }`. A full Ed25519
/// SPKI is this prefix followed by the 32-byte raw key — exactly 44 bytes. This
/// is the form `boatramp_rpktls` advertises and pins in its `TrustSet`.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Length of an Ed25519 SPKI DER (12-byte prefix + 32-byte key).
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32;

/// Errors constructing or rendering an [`OverlayId`] / [`OverlaySecret`].
#[derive(Debug, thiserror::Error)]
pub enum OverlayIdError {
    /// The supplied `TokenPublicKey` was ES256, not Ed25519. Overlay identities
    /// are Ed25519-only (the raw-public-key TLS layer is Ed25519).
    #[error("overlay identities are Ed25519-only (got a non-Ed25519 key)")]
    NotEd25519,
    /// Raw key bytes were not a valid Ed25519 public point.
    #[error("malformed Ed25519 public key: {0}")]
    MalformedKey(String),
    /// SPKI DER was the wrong length or lacked the Ed25519 prefix.
    #[error("malformed Ed25519 SPKI DER")]
    MalformedSpki,
    /// A bech32 `bro1…` rendering could not be parsed.
    #[error("bech32 identity: {0}")]
    Bech32(String),
    /// Error from the COSE identity/signing substrate.
    #[error(transparent)]
    Token(#[from] TokenError),
    /// Error from the raw-public-key TLS substrate.
    #[error(transparent)]
    Rpk(#[from] RpkError),
}

/// Parse a tagged `"ed25519:<64-hex>"` secret/public spec into its 32 raw bytes.
fn parse_ed25519_hex(spec: &str) -> Result<[u8; 32], OverlayIdError> {
    let hex_part = spec.strip_prefix("ed25519:").ok_or_else(|| {
        OverlayIdError::MalformedKey(format!("expected `ed25519:` tag in `{spec}`"))
    })?;
    let bytes = hex::decode(hex_part).map_err(|e| OverlayIdError::MalformedKey(e.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| OverlayIdError::MalformedKey("expected 32 bytes".into()))
}

/// An overlay peer identity — a raw Ed25519 public key.
///
/// The canonical value is the 32-byte key, so [`OverlayId`] derives `Eq`/`Ord`/
/// `Hash` (which `TokenPublicKey` does not) and can key the overlay's in-memory
/// maps directly. Every stored id is a validated Ed25519 point.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OverlayId([u8; 32]);

impl OverlayId {
    /// Build from a boatramp-core `TokenPublicKey` (must be the Ed25519 arm).
    pub fn from_public(pk: &TokenPublicKey) -> Result<Self, OverlayIdError> {
        if pk.alg() != TokenAlg::Ed25519 {
            return Err(OverlayIdError::NotEd25519);
        }
        // `to_hex()` renders `"ed25519:<hex>"`; extract the 32 raw bytes.
        Self::try_from_bytes(parse_ed25519_hex(&pk.to_hex())?)
    }

    /// Build from 32 raw bytes, validating they are a legal Ed25519 point.
    pub fn try_from_bytes(raw: [u8; 32]) -> Result<Self, OverlayIdError> {
        // Round-trip through TokenPublicKey::from_hex, whose Ed25519 arm rejects
        // a non-canonical / off-curve key — so a stored OverlayId is always
        // reconstructable into a usable verifying key.
        TokenPublicKey::from_hex(&format!("ed25519:{}", hex::encode(raw)))?;
        Ok(Self(raw))
    }

    /// The 32 raw public-key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The boatramp-core `TokenPublicKey` (Ed25519) for this identity — the
    /// verifying key used to check E2EE shares and the holder-key of a dial
    /// capability.
    #[must_use]
    pub fn to_public(&self) -> TokenPublicKey {
        // Infallible: `self.0` was validated at construction.
        TokenPublicKey::from_hex(&self.to_hex()).expect("OverlayId holds a validated Ed25519 key")
    }

    /// Canonical hex rendering, `"ed25519:<hex>"` (matches boatramp-core).
    #[must_use]
    pub fn to_hex(&self) -> String {
        format!("ed25519:{}", hex::encode(self.0))
    }

    /// Parse the canonical hex form `"ed25519:<hex>"`.
    pub fn from_hex(spec: &str) -> Result<Self, OverlayIdError> {
        Self::try_from_bytes(parse_ed25519_hex(spec)?)
    }

    /// The RFC-7250 SPKI DER form `boatramp_rpktls` pins in its `TrustSet`.
    #[must_use]
    pub fn to_spki(&self) -> Vec<u8> {
        let mut der = Vec::with_capacity(ED25519_SPKI_LEN);
        der.extend_from_slice(&ED25519_SPKI_PREFIX);
        der.extend_from_slice(&self.0);
        der
    }

    /// Parse an Ed25519 SPKI DER (the form a peer advertises at the TLS layer).
    pub fn from_spki(spki: &[u8]) -> Result<Self, OverlayIdError> {
        if spki.len() != ED25519_SPKI_LEN
            || spki[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX
        {
            return Err(OverlayIdError::MalformedSpki);
        }
        let raw: [u8; 32] = spki[ED25519_SPKI_PREFIX.len()..]
            .try_into()
            .map_err(|_| OverlayIdError::MalformedSpki)?;
        Self::try_from_bytes(raw)
    }

    /// Friendly bech32m rendering, `bro1…` (HRP [`crate::wire::HRP_IDENTITY`]).
    /// A display form only — the canonical identity stays hex.
    #[must_use]
    pub fn to_bech32(&self) -> String {
        let hrp = bech32::Hrp::parse(crate::wire::HRP_IDENTITY).expect("HRP_IDENTITY is valid");
        bech32::encode::<bech32::Bech32m>(hrp, &self.0).expect("32 bytes encode under a valid HRP")
    }

    /// Parse the friendly bech32m `bro1…` form.
    pub fn from_bech32(s: &str) -> Result<Self, OverlayIdError> {
        let (hrp, data) = bech32::decode(s).map_err(|e| OverlayIdError::Bech32(e.to_string()))?;
        if hrp.as_str() != crate::wire::HRP_IDENTITY {
            return Err(OverlayIdError::Bech32(format!(
                "wrong prefix `{}` (expected `{}`)",
                hrp.as_str(),
                crate::wire::HRP_IDENTITY
            )));
        }
        let raw: [u8; 32] = data
            .try_into()
            .map_err(|_| OverlayIdError::Bech32("expected 32 bytes".into()))?;
        Self::try_from_bytes(raw)
    }
}

impl std::fmt::Display for OverlayId {
    /// Canonical hex — stable and matches the rest of boatramp.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl std::fmt::Debug for OverlayId {
    /// Friendly bech32 in logs (short, copy-pasteable); never the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OverlayId({})", self.to_bech32())
    }
}

/// An overlay identity secret: a 32-byte Ed25519 seed, held zeroized.
///
/// One seed derives everything the overlay needs for this identity:
/// - the public [`OverlayId`];
/// - the hot-path **local** COSE/E2EE signer ([`LocalSigner::Ed25519`]) — never
///   a network KMS on the data path (overlay guardrail 2);
/// - the [`RpkIdentity`] presented at the raw-public-key TLS layer.
///
/// These are the same key in three framings; [`OverlaySecret::id`]'s SPKI is
/// guaranteed equal to [`OverlaySecret::rpk_identity`]'s advertised key.
pub struct OverlaySecret {
    seed: Zeroizing<[u8; 32]>,
}

impl OverlaySecret {
    /// Generate a fresh identity, reusing boatramp-core's Ed25519 keygen RNG.
    pub fn generate() -> Result<Self, OverlayIdError> {
        // `LocalSigner::generate` seeds from the platform RNG; `private_hex()`
        // round-trips the 32-byte seed as `"ed25519:<hex>"`.
        let seed_hex = LocalSigner::generate(TokenAlg::Ed25519).private_hex();
        Ok(Self::from_seed(parse_ed25519_hex(&seed_hex)?))
    }

    /// Build from a known 32-byte seed (e.g. loaded from disk).
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(seed),
        }
    }

    /// Parse a tagged `"ed25519:<hex>"` seed.
    pub fn from_seed_hex(spec: &str) -> Result<Self, OverlayIdError> {
        Ok(Self::from_seed(parse_ed25519_hex(spec)?))
    }

    /// The tagged `"ed25519:<hex>"` seed, for persistence. Zeroized on drop.
    #[must_use]
    pub fn seed_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("ed25519:{}", hex::encode(&*self.seed)))
    }

    /// This identity's public [`OverlayId`].
    #[must_use]
    pub fn id(&self) -> OverlayId {
        OverlayId::from_public(&self.signer().public_key())
            .expect("a 32-byte seed yields a valid Ed25519 identity")
    }

    /// The local COSE/E2EE signer for this identity. Building from the seed
    /// cannot fail (every 32-byte value is a valid Ed25519 seed).
    #[must_use]
    pub fn signer(&self) -> LocalSigner {
        LocalSigner::from_private_hex(&self.seed_hex())
            .expect("a 32-byte seed is a valid Ed25519 LocalSigner")
    }

    /// The raw-public-key TLS identity for this seed (same key as [`id`]).
    ///
    /// [`id`]: OverlaySecret::id
    pub fn rpk_identity(&self) -> Result<RpkIdentity, OverlayIdError> {
        Ok(RpkIdentity::from_ed25519_seed(&self.seed)?)
    }
}

impl std::fmt::Debug for OverlaySecret {
    /// Never prints the seed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OverlaySecret({})", self.id().to_bech32())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_renders_and_parses_in_every_form() {
        let secret = OverlaySecret::generate().unwrap();
        let id = secret.id();

        assert_eq!(OverlayId::from_hex(&id.to_hex()).unwrap(), id);
        assert_eq!(OverlayId::from_bech32(&id.to_bech32()).unwrap(), id);
        assert_eq!(OverlayId::from_spki(&id.to_spki()).unwrap(), id);
        assert_eq!(OverlayId::from_public(&id.to_public()).unwrap(), id);
        assert!(id.to_bech32().starts_with("bro1"));
    }

    #[test]
    fn one_seed_binds_the_cose_identity_and_the_tls_identity() {
        // The whole model rests on this: the key pinned at the TLS layer and the
        // key a dial capability / E2EE handshake binds are the SAME principal.
        let secret = OverlaySecret::generate().unwrap();
        let rpk = secret.rpk_identity().unwrap();

        // rpktls advertises the SPKI; the overlay id's SPKI must match it byte
        // for byte, and the cose signer's public key must be the same id.
        assert_eq!(secret.id().to_spki(), rpk.public_key());
        assert_eq!(OverlayId::from_spki(rpk.public_key()).unwrap(), secret.id());
        assert_eq!(
            OverlayId::from_public(&secret.signer().public_key()).unwrap(),
            secret.id()
        );
    }

    #[test]
    fn seed_round_trips_through_hex() {
        let secret = OverlaySecret::generate().unwrap();
        let again = OverlaySecret::from_seed_hex(&secret.seed_hex()).unwrap();
        assert_eq!(secret.id(), again.id());
    }

    #[test]
    fn bech32_rejects_a_foreign_prefix() {
        let secret = OverlaySecret::generate().unwrap();
        // Re-encode the same bytes under a different HRP and confirm we reject it.
        let hrp = bech32::Hrp::parse("xy").unwrap();
        let foreign = bech32::encode::<bech32::Bech32m>(hrp, secret.id().as_bytes()).unwrap();
        assert!(matches!(
            OverlayId::from_bech32(&foreign),
            Err(OverlayIdError::Bech32(_))
        ));
    }
}
