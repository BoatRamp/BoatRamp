//! The S3-ingress **credential model** (PLAN-blob-s3-ingress, folded "Credential model" —
//! Security CRITICAL-1).
//!
//! A temporary S3 credential is `{ access_key_id, secret_access_key, session_token, expiry }`:
//! - `access_key_id` — a random public id (`BRUP` + base32).
//! - `session_token` — a fleet-signed [`KIND_S3_SESSION`](boatramp_core::cose) COSE token carrying
//!   the full host-stamped scope (minted/verified in `boatramp_core::cose`).
//! - `secret_access_key` — **derived, never stored**:
//!   `HKDF-SHA256(root = dedicated ingress secret, info = "boatramp-s3-ingress/hmac/v1",
//!   salt = access_key_id ‖ session_token.cti)`.
//!
//! The root is a **dedicated, independently-rotatable secret** — hard domain separation from the
//! `[secrets]` KEK and the COSE signing key. Because the secret is derived (not stored), any node can
//! recompute it from the public `access_key_id` + the token's `cti`, so the credential survives
//! restart and is cluster-uniform WITHOUT a replicated credential record. The cluster-uniformity of
//! the *root* is the operator's responsibility, enforced fail-closed by [`multi_node_secret_ok`].
//!
//! **Rotation** carries an overlap window: an [`S3IngressSecret`] holds the current root plus an
//! optional previous root, and verification accepts a signature derived under either — so credentials
//! minted just before a rotation keep working until they expire (rotation is the coarse revocation
//! lever). New credentials are always minted under the current root.
//!
//! This module is SDK- and listener-free (M1): it derives/verifies the secret and models the config
//! guard. The SigV4 wire verification lives in [`super::sigv4`]; wiring a live listener is M2.

use aws_lc_rs::hkdf;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

/// The HKDF `info` string binding the derivation to this exact purpose + version. Changing it (or
/// feeding a different root) yields a completely different `secret_access_key` — the hard domain
/// separation the security review (CRITICAL-1) requires. Versioned so a future scheme can co-exist.
pub const HKDF_INFO: &[u8] = b"boatramp-s3-ingress/hmac/v1";

/// Length of the dedicated ingress root secret, in bytes (256-bit, matching the KEK).
pub const INGRESS_SECRET_LEN: usize = 32;

/// Length of the derived `secret_access_key` material, in bytes, before hex-encoding. 32 bytes gives
/// a 64-hex-char secret — ample entropy, and a shape every S3 SDK accepts as an opaque secret.
const DERIVED_SECRET_LEN: usize = 32;

/// The `access_key_id` prefix marking a boatramp-issued S3-ingress credential (greppable; lets the
/// face fast-reject an id that was never one of ours before any crypto).
pub const ACCESS_KEY_PREFIX: &str = "BRUP";

/// A failure in the credential model.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The RNG failed (should be effectively impossible on a healthy host).
    #[error("s3-ingress credential rng failure")]
    Rng,
    /// HKDF expansion failed (a bad output length — a programming error, never input-driven).
    #[error("s3-ingress credential key derivation failed")]
    Derive,
    /// A configured root secret was the wrong length.
    #[error("s3-ingress ingress secret must be exactly {INGRESS_SECRET_LEN} bytes")]
    BadSecretLen,
    /// The local S3 face is enabled on a multi-node deployment without an explicitly configured,
    /// cluster-uniform ingress secret. Fail closed rather than silently reuse an auto-generated
    /// per-node key (which would make credentials un-verifiable across nodes) — the operator MUST set
    /// a shared secret.
    #[error(
        "the local S3 ingress face requires an explicitly configured, cluster-uniform \
         `s3_ingress_secret` on a multi-node deployment (refusing to auto-generate a per-node key)"
    )]
    MultiNodeSecretRequired,
}

/// The dedicated, independently-rotatable S3-ingress root secret(s). Holds the **current** root and,
/// during a rotation overlap, the **previous** root — so in-flight credentials minted under the old
/// root still verify until they expire.
///
/// This is DISTINCT from `LocalKek` (secrets-at-rest) and the COSE `Signer` key (token signing): the
/// `secret_access_key` HKDF is keyed ONLY by this material, so compromising an S3 credential can never
/// reveal — and is never derivable from — the KEK or the signing key, and vice-versa.
pub struct S3IngressSecret {
    /// The current root — new credentials are minted (and preferentially verified) under this.
    current: [u8; INGRESS_SECRET_LEN],
    /// The previous root during a rotation overlap — accepted on verify only, never used to mint.
    previous: Option<[u8; INGRESS_SECRET_LEN]>,
}

impl S3IngressSecret {
    /// Build from an explicitly configured current root (the operator-distributed, cluster-uniform
    /// secret). No previous root — call [`with_previous`](Self::with_previous) to open a rotation
    /// overlap.
    pub fn new(current: [u8; INGRESS_SECRET_LEN]) -> Self {
        Self {
            current,
            previous: None,
        }
    }

    /// Build from raw bytes, validating the length (the config path).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CredentialError> {
        let current: [u8; INGRESS_SECRET_LEN] =
            bytes.try_into().map_err(|_| CredentialError::BadSecretLen)?;
        Ok(Self::new(current))
    }

    /// Generate a fresh random root — for **single-node** deployments / tests only. A multi-node
    /// fleet MUST supply an explicit, shared secret (see [`multi_node_secret_ok`]); auto-generating
    /// here would give each node a different root and make credentials un-verifiable across nodes.
    pub fn generate() -> Result<Self, CredentialError> {
        let mut current = [0u8; INGRESS_SECRET_LEN];
        SystemRandom::new()
            .fill(&mut current)
            .map_err(|_| CredentialError::Rng)?;
        Ok(Self::new(current))
    }

    /// Open a rotation overlap: keep `self`'s current root, and additionally accept `previous` on the
    /// verify path (mirrors `auth rotate-root`'s make-before-break — both roots are trusted during
    /// the overlap, so no in-flight credential is rejected). New credentials still derive under
    /// `current`.
    pub fn with_previous(mut self, previous: [u8; INGRESS_SECRET_LEN]) -> Self {
        self.previous = Some(previous);
        self
    }

    /// Derive the `secret_access_key` (hex) under the **current** root — the value handed to the
    /// client at mint. Bound to the public `access_key_id` and the session token's `cti`, so the
    /// secret is unique per credential and cannot be recomputed for a different one.
    pub fn derive_secret(
        &self,
        access_key_id: &str,
        session_cti: &str,
    ) -> Result<String, CredentialError> {
        let raw = derive_raw(&self.current, access_key_id, session_cti)?;
        Ok(hex::encode(raw))
    }

    /// The set of derived secrets a *verifier* must accept for `(access_key_id, session_cti)`: the
    /// current root first (the common path), then the previous root during a rotation overlap. The
    /// SigV4 verifier tries each with a **constant-time** compare and fails closed if none match.
    ///
    /// Returned as raw 32-byte material (the verifier signs the SigV4 string-to-sign with the *hex*
    /// form as the HMAC key, matching what the client received; [`derive_secret`](Self::derive_secret)
    /// hex-encodes the same bytes).
    pub fn candidate_secrets(
        &self,
        access_key_id: &str,
        session_cti: &str,
    ) -> Result<Vec<String>, CredentialError> {
        let mut out = Vec::with_capacity(2);
        out.push(hex::encode(derive_raw(
            &self.current,
            access_key_id,
            session_cti,
        )?));
        if let Some(prev) = &self.previous {
            out.push(hex::encode(derive_raw(prev, access_key_id, session_cti)?));
        }
        Ok(out)
    }
}

/// The HKDF-SHA256 core: `salt = access_key_id ‖ session_cti`, `info = HKDF_INFO`, keyed by `root`.
/// Both the public id AND the token's `cti` are in the salt, so the secret is bound to that exact
/// credential (a different id or a different token ⇒ a different, non-transferable secret).
fn derive_raw(
    root: &[u8; INGRESS_SECRET_LEN],
    access_key_id: &str,
    session_cti: &str,
) -> Result<[u8; DERIVED_SECRET_LEN], CredentialError> {
    let mut salt = Vec::with_capacity(access_key_id.len() + session_cti.len());
    salt.extend_from_slice(access_key_id.as_bytes());
    salt.extend_from_slice(session_cti.as_bytes());
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(root);
    let okm = prk
        .expand(&[HKDF_INFO], MyKeyLen)
        .map_err(|_| CredentialError::Derive)?;
    let mut out = [0u8; DERIVED_SECRET_LEN];
    okm.fill(&mut out).map_err(|_| CredentialError::Derive)?;
    Ok(out)
}

/// A [`hkdf::KeyType`] fixing the OKM length to [`DERIVED_SECRET_LEN`] (aws-lc-rs's `expand` is
/// generic over the output length).
#[derive(Clone, Copy)]
struct MyKeyLen;
impl hkdf::KeyType for MyKeyLen {
    fn len(&self) -> usize {
        DERIVED_SECRET_LEN
    }
}

/// Generate a fresh public `access_key_id`: `BRUP` + 20 base32 (Crockford, no padding) chars over 100
/// random bits. Opaque + collision-safe; the prefix lets the face fast-reject a foreign id.
pub fn generate_access_key_id() -> Result<String, CredentialError> {
    let mut raw = [0u8; 13]; // 104 bits → 21 base32 chars (we take a fixed slice below)
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| CredentialError::Rng)?;
    Ok(format!("{ACCESS_KEY_PREFIX}{}", base32_crockford(&raw)))
}

/// Lower-collision Crockford base32 (uppercase, no padding) of `bytes`. Small, dependency-free — this
/// is an id encoder, not a cryptographic primitive.
fn base32_crockford(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

/// **Fail-closed multi-node startup guard** (CRITICAL-1). Returns `Ok(())` only when the local S3
/// face may safely enable: a single-node deployment may auto-generate a per-node secret; a multi-node
/// deployment MUST have an explicitly configured secret (so every node derives the same
/// `secret_access_key`). A multi-node deployment WITHOUT an explicit secret is refused — never
/// silently fall back to the auto-generating `LocalKek`-style per-node key.
///
/// `multi_node` is whether this deployment is clustered; `explicit_secret_configured` is whether the
/// operator set a `s3_ingress_secret`. Pure so it is unit-testable and the live wiring (M2) just
/// supplies the two booleans from cluster membership + config.
pub fn multi_node_secret_ok(
    multi_node: bool,
    explicit_secret_configured: bool,
) -> Result<(), CredentialError> {
    if multi_node && !explicit_secret_configured {
        return Err(CredentialError::MultiNodeSecretRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::constant_time::verify_slices_are_equal;

    const ROOT_A: [u8; INGRESS_SECRET_LEN] = [0x11; INGRESS_SECRET_LEN];
    const ROOT_B: [u8; INGRESS_SECRET_LEN] = [0x22; INGRESS_SECRET_LEN];
    const AKID: &str = "BRUPABCDEFGH";
    const CTI: &str = "0011223344556677";

    #[test]
    fn derive_is_deterministic_per_node() {
        // Any node with the same root derives the SAME secret for the same (akid, cti) — the basis
        // for the stateless, restart-safe, cluster-uniform credential.
        let a = S3IngressSecret::new(ROOT_A);
        let b = S3IngressSecret::new(ROOT_A);
        assert_eq!(
            a.derive_secret(AKID, CTI).unwrap(),
            b.derive_secret(AKID, CTI).unwrap()
        );
    }

    #[test]
    fn secret_is_bound_to_akid_and_cti() {
        let s = S3IngressSecret::new(ROOT_A);
        let base = s.derive_secret(AKID, CTI).unwrap();
        // A different access-key-id ⇒ a different secret.
        assert_ne!(base, s.derive_secret("BRUPZZZZZZZZ", CTI).unwrap());
        // A different session cti ⇒ a different secret (so a token swap can't reuse a secret).
        assert_ne!(base, s.derive_secret(AKID, "ffffffffffffffff").unwrap());
    }

    #[test]
    fn domain_separation_root_info_and_key_material() {
        // (1) A different ROOT (e.g. someone feeding the KEK or the COSE key here) ⇒ a totally
        //     different secret. This is the CRITICAL-1 hard separation: the secret is a pure function
        //     of the dedicated root, so no other key material can reproduce it.
        let a = S3IngressSecret::new(ROOT_A);
        let b = S3IngressSecret::new(ROOT_B);
        assert_ne!(
            a.derive_secret(AKID, CTI).unwrap(),
            b.derive_secret(AKID, CTI).unwrap()
        );

        // (2) Mutating the HKDF `info` domain string ⇒ a different secret. We derive by hand with a
        //     tweaked info and confirm it differs from the production derivation.
        let real = derive_raw(&ROOT_A, AKID, CTI).unwrap();
        let salt = {
            let mut s = Vec::new();
            s.extend_from_slice(AKID.as_bytes());
            s.extend_from_slice(CTI.as_bytes());
            s
        };
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(&ROOT_A);
        let okm = prk
            .expand(&[b"boatramp-s3-ingress/hmac/v2"], MyKeyLen)
            .unwrap();
        let mut tweaked = [0u8; DERIVED_SECRET_LEN];
        okm.fill(&mut tweaked).unwrap();
        assert!(
            verify_slices_are_equal(&real, &tweaked).is_err(),
            "changing the HKDF info domain must change the derived secret"
        );

        // (3) The production info is exactly the pinned v1 string (a change is a breaking, reviewed
        //     event, not a silent drift).
        assert_eq!(HKDF_INFO, b"boatramp-s3-ingress/hmac/v1");
    }

    #[test]
    fn rotation_overlap_accepts_current_and_previous() {
        // Before rotation, a credential's secret was derived under ROOT_A. After rotation, the
        // current root is ROOT_B but ROOT_A is retained as `previous` during the overlap — so the
        // verifier accepts the still-in-flight ROOT_A-derived secret AND newly-minted ROOT_B ones.
        let old = S3IngressSecret::new(ROOT_A);
        let in_flight_secret = old.derive_secret(AKID, CTI).unwrap();

        let rotated = S3IngressSecret::new(ROOT_B).with_previous(ROOT_A);
        let candidates = rotated.candidate_secrets(AKID, CTI).unwrap();

        // New mints use the current (ROOT_B) root...
        assert_eq!(rotated.derive_secret(AKID, CTI).unwrap(), candidates[0]);
        assert_ne!(candidates[0], in_flight_secret);
        // ...but the in-flight (ROOT_A) secret is still among the accepted candidates.
        assert!(
            candidates.iter().any(|c| c == &in_flight_secret),
            "a credential minted under the previous root must still verify during the overlap"
        );

        // Without the overlap (no `previous`), the old secret is NOT accepted — rotation is complete
        // and is the coarse revocation lever.
        let post = S3IngressSecret::new(ROOT_B);
        let post_candidates = post.candidate_secrets(AKID, CTI).unwrap();
        assert_eq!(post_candidates.len(), 1);
        assert!(!post_candidates.iter().any(|c| c == &in_flight_secret));
    }

    #[test]
    fn candidate_secrets_shape() {
        // No overlap ⇒ exactly one candidate (the current root); overlap ⇒ two (current, previous).
        assert_eq!(
            S3IngressSecret::new(ROOT_A)
                .candidate_secrets(AKID, CTI)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            S3IngressSecret::new(ROOT_A)
                .with_previous(ROOT_B)
                .candidate_secrets(AKID, CTI)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn multi_node_guard_fails_closed_without_an_explicit_secret() {
        // Single node: auto-generate is fine (with or without explicit config).
        assert!(multi_node_secret_ok(false, false).is_ok());
        assert!(multi_node_secret_ok(false, true).is_ok());
        // Multi node WITH an explicit shared secret: allowed.
        assert!(multi_node_secret_ok(true, true).is_ok());
        // Multi node WITHOUT one: refused (never silently per-node auto-generate).
        assert!(matches!(
            multi_node_secret_ok(true, false),
            Err(CredentialError::MultiNodeSecretRequired)
        ));
    }

    #[test]
    fn from_bytes_validates_length() {
        assert!(S3IngressSecret::from_bytes(&[0u8; INGRESS_SECRET_LEN]).is_ok());
        assert!(matches!(
            S3IngressSecret::from_bytes(&[0u8; 16]),
            Err(CredentialError::BadSecretLen)
        ));
        assert!(matches!(
            S3IngressSecret::from_bytes(&[0u8; 64]),
            Err(CredentialError::BadSecretLen)
        ));
    }

    #[test]
    fn access_key_id_is_prefixed_and_random() {
        let a = generate_access_key_id().unwrap();
        let b = generate_access_key_id().unwrap();
        assert!(a.starts_with(ACCESS_KEY_PREFIX));
        assert_ne!(a, b, "each access-key-id must be random");
        // Body is uppercase Crockford base32 only.
        let body = &a[ACCESS_KEY_PREFIX.len()..];
        assert!(
            body.bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
            "access-key-id body must be base32 (uppercase alnum): {body}"
        );
    }

    #[test]
    fn derived_secret_is_hex_of_expected_length() {
        let s = S3IngressSecret::new(ROOT_A).derive_secret(AKID, CTI).unwrap();
        assert_eq!(s.len(), DERIVED_SECRET_LEN * 2, "hex-encoded 32 bytes");
        assert!(hex::decode(&s).is_ok());
    }
}
