//! Kernel-trust verification — the **posture-scaled** bar a microVM kernel must
//! clear before it boots. See `PLAN-dynamic-config` S3.
//!
//! A dynamically-selected kernel is a code-execution supply-chain input, so:
//!
//! - **Always** (verify-before-boot): the staged kernel bytes must hash to the
//!   [`KernelRef::sha256`] pin. A content-hash mismatch never boots.
//! - **Strict posture** (multi-tenant): the pinned hash must additionally be on a
//!   static allow-list, and the [`KernelRef::sig`] must be a valid signature over
//!   the hash by one of the statically-configured signing keys — so an admin-token
//!   holder can only *select* a kernel the host operator pre-vetted and signed,
//!   never introduce a new one.
//! - **Relaxed posture** (single-tenant / dev): the verified hash pin alone
//!   suffices (the operator owns every tenant and the host).

use crate::cose::TokenPublicKey;
use crate::daemon_config::KernelRef;

/// Why a kernel failed the trust bar.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KernelTrustError {
    /// The staged bytes don't hash to the pinned `sha256` (verify-before-boot).
    #[error("kernel hash mismatch: staged {computed}, pinned {expected}")]
    HashMismatch {
        /// The hash of the bytes actually staged.
        computed: String,
        /// The hash the [`KernelRef`] pins.
        expected: String,
    },
    /// Strict posture but the kernel carries no signature.
    #[error("strict posture requires a signed kernel, but this one is unsigned")]
    Unsigned,
    /// The signature hex is malformed.
    #[error("kernel signature is malformed: {0}")]
    BadSigFormat(String),
    /// No configured signing key verifies the signature.
    #[error("kernel signature verifies against none of the configured signing keys")]
    BadSignature,
    /// The pinned hash is not on the static allow-list.
    #[error("kernel hash is not on the static `[compute] kernel_allowed_hashes` allow-list")]
    NotAllowlisted,
    /// A configured signing key spec is malformed.
    #[error("a configured kernel signing key is malformed: {0}")]
    BadSigningKey(String),
}

/// Verify a staged kernel's `bytes` against its `kref` under the posture bar.
/// `strict` = the multi-tenant posture. `signing_keys` are the static
/// `[compute] kernel_signing_pubkeys` (`"<alg>:<hex>"`); `allowed_hashes` the
/// static `[compute] kernel_allowed_hashes`.
pub fn verify_kernel(
    bytes: &[u8],
    kref: &KernelRef,
    strict: bool,
    signing_keys: &[String],
    allowed_hashes: &[String],
) -> Result<(), KernelTrustError> {
    // 1. Verify-before-boot: content hash must match the pin — always.
    let computed = boatramp_types::manifest::sha256_hex(bytes);
    if computed != kref.sha256 {
        return Err(KernelTrustError::HashMismatch {
            computed,
            expected: kref.sha256.clone(),
        });
    }
    // Relaxed posture: a verified hash pin is sufficient.
    if !strict {
        return Ok(());
    }
    // 2. Strict: the pinned hash must be on the static allow-list.
    if !allowed_hashes.iter().any(|h| h == &kref.sha256) {
        return Err(KernelTrustError::NotAllowlisted);
    }
    // 3. Strict: a valid signature over the pinned hash by a configured key.
    let sig_hex = kref.sig.as_deref().ok_or(KernelTrustError::Unsigned)?;
    let sig = hex::decode(sig_hex).map_err(|e| KernelTrustError::BadSigFormat(e.to_string()))?;
    let message = kref.sha256.as_bytes();
    for spec in signing_keys {
        let key = TokenPublicKey::from_hex(spec)
            .map_err(|e| KernelTrustError::BadSigningKey(e.to_string()))?;
        if key.verify(message, &sig).is_ok() {
            return Ok(());
        }
    }
    Err(KernelTrustError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::{LocalSigner, Signer, TokenAlg};

    fn kref_for(bytes: &[u8], sig: Option<String>) -> KernelRef {
        KernelRef {
            source: "blob".into(),
            sha256: boatramp_types::manifest::sha256_hex(bytes),
            sig,
        }
    }

    #[test]
    fn hash_mismatch_never_boots() {
        let kref = KernelRef {
            source: "blob".into(),
            sha256: "0".repeat(64),
            sig: None,
        };
        let err = verify_kernel(b"kernel-bytes", &kref, false, &[], &[]).unwrap_err();
        assert!(matches!(err, KernelTrustError::HashMismatch { .. }));
    }

    #[test]
    fn relaxed_accepts_verified_hash_pin() {
        let bytes = b"a microvm vmlinux";
        let kref = kref_for(bytes, None);
        assert!(verify_kernel(bytes, &kref, false, &[], &[]).is_ok());
    }

    #[test]
    fn strict_rejects_unsigned_and_unlisted() {
        let bytes = b"a microvm vmlinux";
        let kref = kref_for(bytes, None);
        // Not on the allow-list → rejected before the signature check.
        assert_eq!(
            verify_kernel(bytes, &kref, true, &[], &[]).unwrap_err(),
            KernelTrustError::NotAllowlisted
        );
        // Allow-listed but unsigned → rejected.
        assert_eq!(
            verify_kernel(bytes, &kref, true, &[], std::slice::from_ref(&kref.sha256)).unwrap_err(),
            KernelTrustError::Unsigned
        );
    }

    /// Release gate: verify a **shipped** kernel artifact clears the strict
    /// production bar (content-hash pin + allow-list + ES256/Ed25519 signature).
    /// Env-driven + `#[ignore]`d so it runs only in the release-boot workflow,
    /// which points it at the downloaded `boatramp-vmlinux-<arch>` + its `.sig` +
    /// the built-in signing pubkey:
    /// `BOATRAMP_RELEASE_KERNEL` (path), `BOATRAMP_RELEASE_SHA256`,
    /// `BOATRAMP_RELEASE_SIG` (hex), `BOATRAMP_RELEASE_PUBKEY` (`<alg>:<hex>`).
    #[test]
    #[ignore = "verifies a downloaded release kernel; needs BOATRAMP_RELEASE_* env"]
    fn released_kernel_verifies_under_strict() {
        let (Ok(path), Ok(sha256), Ok(sig), Ok(pubkey)) = (
            std::env::var("BOATRAMP_RELEASE_KERNEL"),
            std::env::var("BOATRAMP_RELEASE_SHA256"),
            std::env::var("BOATRAMP_RELEASE_SIG"),
            std::env::var("BOATRAMP_RELEASE_PUBKEY"),
        ) else {
            eprintln!("SKIP: set BOATRAMP_RELEASE_{{KERNEL,SHA256,SIG,PUBKEY}}");
            return;
        };
        let bytes = std::fs::read(&path).expect("read release kernel");
        let kref = KernelRef {
            source: "release".into(),
            sha256: sha256.trim().to_string(),
            sig: Some(sig.trim().to_string()),
        };
        verify_kernel(
            &bytes,
            &kref,
            true,
            &[pubkey.trim().to_string()],
            &[sha256.trim().to_string()],
        )
        .expect("release kernel must clear the strict verify-before-boot bar");
    }

    #[tokio::test]
    async fn strict_accepts_valid_signature_rejects_wrong_key() {
        let bytes = b"a microvm vmlinux";
        let hash = boatramp_types::manifest::sha256_hex(bytes);
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let sig = signer.sign(hash.as_bytes()).await.unwrap();
        let pubkey = signer.public_key().to_hex();
        let kref = kref_for(bytes, Some(hex::encode(&sig)));

        // Right key + allow-listed → boots.
        assert!(verify_kernel(bytes, &kref, true, &[pubkey], std::slice::from_ref(&hash)).is_ok());

        // A different key does not verify the signature → rejected (anti-swap: an
        // admin who sets a kernel we didn't sign can't boot it under strict).
        let other = LocalSigner::generate(TokenAlg::Es256).public_key().to_hex();
        assert_eq!(
            verify_kernel(bytes, &kref, true, &[other], &[hash]).unwrap_err(),
            KernelTrustError::BadSignature
        );
    }
}
