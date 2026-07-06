//! Envelope encryption for secrets at rest.
//!
//! A private key must never sit in cleartext in the **replicated** control plane
//! (cluster-managed cert keys live in the Raft KV, readable by every node's local
//! state). The [`KeyEnvelope`] trait wraps such material with a key-encryption
//! key (KEK) so the stored blob is opaque; the default is a machine-local KEK and
//! a Vault (Transit) backend is available. The concrete backends pull crypto /
//! HTTP deps, so they live in a native crate — this module is just the pluggable
//! seam, kept dependency-free so `boatramp-core` stays wasm-clean.

use async_trait::async_trait;

/// A wrap/unwrap failure (bad key, tampered/foreign blob, or a KMS round-trip
/// error). Carries a human-readable reason only — never key material.
#[derive(Debug)]
pub struct EnvelopeError(pub String);

impl EnvelopeError {
    /// Build from anything printable.
    pub fn new(reason: impl std::fmt::Display) -> Self {
        Self(reason.to_string())
    }
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "envelope error: {}", self.0)
    }
}

impl std::error::Error for EnvelopeError {}

/// Pluggable envelope encryption for secrets at rest. Implementations wrap
/// plaintext under a KEK they hold (machine-local key file, Vault Transit, an
/// HSM) and reverse it. `wrap` output is opaque and self-describing (a backend
/// tags its own format) so `unwrap` fail-closes on a foreign or tampered blob.
/// Async so a remote KMS (an HTTP round-trip) fits the same seam as local AEAD.
#[async_trait]
pub trait KeyEnvelope: Send + Sync {
    /// Wrap `plaintext`, returning an opaque blob to store at rest.
    async fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError>;
    /// Unwrap a blob produced by [`wrap`](Self::wrap), returning the plaintext.
    async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, EnvelopeError>;
}
