//! Verify-before-boot — the last trust gate before a staged kernel is loaded
//! into a guest.
//!
//! A microVM kernel is a code-execution supply-chain input: whoever picks it
//! picks ring-0 code for every workload that boots on it. So the backend calls
//! [`KernelVerifier::verify`] on the *staged bytes* immediately before boot, and
//! a failure aborts the launch — the guest never starts.
//!
//! The trait lives in this crate so the backend can hold one, but the
//! posture-scaled implementation (allow-list + ES256/Ed25519 signature over the
//! content hash, keyed off the live daemon config) lives in the server, which
//! already carries the COSE primitives. That keeps the VMM crate free of the
//! auth dep tree; here we only offer the relaxed [`HashOnlyVerifier`].

use boatramp_types::manifest::sha256_hex;

/// The trust gate a staged kernel must clear before it boots.
pub trait KernelVerifier: Send + Sync + std::fmt::Debug {
    /// `Ok(())` iff the staged kernel `bytes` may boot. `expected_hash` is the
    /// content address the spec pinned ([`ComputeSpec::kernel`]). The returned
    /// error is surfaced as a materialize failure, so the guest never starts.
    ///
    /// [`ComputeSpec::kernel`]: boatramp_types::compute::ComputeSpec::kernel
    fn verify(&self, bytes: &[u8], expected_hash: &str) -> Result<(), String>;
}

/// The relaxed-posture verifier: the staged bytes must hash to the pinned content
/// address (the always-on verify-before-boot check), nothing more. This is the
/// correct bar under the single-tenant / dev posture — the operator owns every
/// tenant and the host — and a safe default where no posture-scaled verifier is
/// injected (e.g. tests booting a locally-built kernel).
#[derive(Debug, Default, Clone, Copy)]
pub struct HashOnlyVerifier;

impl KernelVerifier for HashOnlyVerifier {
    fn verify(&self, bytes: &[u8], expected_hash: &str) -> Result<(), String> {
        let computed = sha256_hex(bytes);
        if computed == expected_hash {
            Ok(())
        } else {
            Err(format!(
                "kernel hash mismatch: staged {computed}, pinned {expected_hash}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_only_accepts_matching_and_rejects_tampered() {
        let bytes = b"a staged vmlinux";
        let hash = sha256_hex(bytes);
        assert!(HashOnlyVerifier.verify(bytes, &hash).is_ok());
        // A one-byte change no longer matches the pinned address.
        assert!(HashOnlyVerifier.verify(b"a staged vmlinuY", &hash).is_err());
    }
}
