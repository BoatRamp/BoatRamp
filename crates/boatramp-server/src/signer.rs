//! External [`Signer`](boatramp_core::cose::Signer) backends for the control-plane
//! token issuer.
//!
//! The implementations were extracted into the standalone [`boatramp_signer`] crate
//! (v0.62.0) so the heavy KMS/HSM SDKs sit behind their own crate boundary. They are
//! re-exported here unchanged, so existing call sites
//! (`boatramp_server::signer::{SignerConfig, build_signer, SignerError}`, the per-backend
//! `VaultSigner`/`AwsKmsSigner`/`GcpKmsSigner`/`AzureKvSigner`/`Pkcs11Signer` types) and the
//! `signer-*` cargo features are byte-for-byte identical. The server's `signer-<x>`
//! features forward one-to-one to `boatramp-signer/signer-<x>`.
pub use boatramp_signer::*;
