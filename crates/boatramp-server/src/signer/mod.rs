//! External [`Signer`] backends for the control-plane token issuer.
//!
//! The token format ([`boatramp_core::cose`]) signs through the [`Signer`] trait,
//! so the **root signing key can live outside the process**: a cloud KMS *signer*
//! (AWS / GCP / Azure), a Vault Transit key, or a PKCS#11 HSM. Verification still
//! needs only the public key, so only *minting* touches the backend.
//!
//! Every backend is feature-gated (heavy SDKs stay out of the lean build) and
//! resolves its public key at construction (the trust anchor other nodes verify
//! against), so `public_key()` is a cheap cached read on the hot mint path. The
//! deterministic request/response + signature-format logic is unit-tested; the
//! live network / HSM round-trip is exercised only in integration testing (`#[ignore]`), matching the
//! project's `fc_live` / container-live norm.
//!
//! Signature normalization: AWS + GCP KMS return **DER** ECDSA signatures, which
//! [`boatramp_core::cose::p256_der_sig_to_raw`] converts to the raw `r‖s` COSE
//! form; Vault (`marshaling_algorithm=jws`), Azure Key Vault, and PKCS#11
//! (`CKM_ECDSA`) already return raw. All ECDSA backends are **ES256** (P-256) —
//! the portable algorithm every KMS can sign; Ed25519 is offered by the local and
//! (optionally) Vault/PKCS#11 backends only.

use std::sync::Arc;

use boatramp_core::cose::{LocalSigner, Signer, TokenAlg};

#[cfg(feature = "signer-aws")]
mod aws_kms;
#[cfg(feature = "signer-azure")]
mod azure;
#[cfg(feature = "signer-gcp")]
mod gcp;
#[cfg(feature = "signer-pkcs11")]
mod pkcs11;
#[cfg(any(
    feature = "signer-vault",
    feature = "signer-gcp",
    feature = "signer-azure"
))]
mod rest;
#[cfg(feature = "signer-vault")]
mod vault;

/// A failure constructing or driving an external signer.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// The signer backend requested is not built into this binary (its feature is
    /// off).
    #[error("signer backend `{0}` is not enabled in this build")]
    Unsupported(&'static str),
    /// A required environment variable (a token / PIN) is unset.
    #[error("environment variable `{0}` is not set")]
    MissingEnv(String),
    /// The backend rejected the key algorithm (e.g. Ed25519 on GCP/Azure KMS).
    #[error("unsupported algorithm for this backend: {0:?}")]
    UnsupportedAlg(TokenAlg),
    /// Key material failed to parse/load.
    #[error("key: {0}")]
    Key(String),
    /// A transport / API error talking to the backend.
    #[error("backend `{backend}`: {message}")]
    Backend {
        /// The backend name (`vault`, `aws-kms`, …).
        backend: &'static str,
        /// The human-readable failure.
        message: String,
    },
}

impl SignerError {
    /// A backend transport/API error. Used only by the feature-gated external
    /// backends (dead when none are enabled).
    #[allow(dead_code)]
    pub(crate) fn backend(backend: &'static str, message: impl std::fmt::Display) -> Self {
        SignerError::Backend {
            backend,
            message: message.to_string(),
        }
    }

    /// Resolve a required secret from the environment (a token or PIN), never
    /// baked into config on disk. Feature-gated
    /// backends only.
    #[allow(dead_code)]
    pub(crate) fn env(name: &str) -> Result<String, SignerError> {
        std::env::var(name).map_err(|_| SignerError::MissingEnv(name.to_string()))
    }
}

/// Which signer backend issues control-plane tokens, and its parameters. Selected
/// by the operator (config `[auth.signer]`); the default is [`SignerConfig::Local`].
#[derive(Debug, Clone)]
pub enum SignerConfig {
    /// An in-process key (`"<alg>:<hex>"`) — the default / dev backend.
    Local {
        /// The private key spec, `"<alg>:<hex>"` (from `boatramp auth init`).
        private_key: String,
    },
    /// A HashiCorp Vault Transit key. Token from `token_env`.
    Vault {
        /// Vault base address, e.g. `https://vault.example:8200`.
        address: String,
        /// The Transit key name.
        key: String,
        /// Env var holding the Vault token.
        token_env: String,
        /// The key's algorithm (ES256 or Ed25519).
        alg: TokenAlg,
    },
    /// An AWS KMS asymmetric signing key (ES256 only). Credentials from the
    /// standard AWS provider chain (env / profile / IMDS).
    AwsKms {
        /// The KMS key id or ARN.
        key_id: String,
        /// Optional region override (else the provider chain's region).
        region: Option<String>,
    },
    /// A GCP Cloud KMS asymmetric signing key version (ES256 only). Access token
    /// from `access_token_env` (a sidecar / workload-identity refreshes it).
    GcpKms {
        /// The full key-version resource name
        /// (`projects/…/cryptoKeyVersions/N`).
        key_version: String,
        /// Env var holding a GCP OAuth2 access token.
        access_token_env: String,
    },
    /// An Azure Key Vault signing key (ES256 only). Access token from
    /// `access_token_env` (managed identity / a sidecar refreshes it).
    AzureKv {
        /// The vault base URL, e.g. `https://kv.vault.azure.net`.
        vault_url: String,
        /// The key name.
        key: String,
        /// The key version (a specific version id).
        key_version: String,
        /// Env var holding an Azure AD access token for the Key Vault resource.
        access_token_env: String,
    },
    /// A PKCS#11 HSM key. PIN from `pin_env`.
    Pkcs11 {
        /// Path to the PKCS#11 module (`.so`).
        module: String,
        /// The token label to open a session on.
        token_label: String,
        /// The signing key's `CKA_LABEL`.
        key_label: String,
        /// Env var holding the user PIN.
        pin_env: String,
        /// The key's algorithm (ES256 or Ed25519).
        alg: TokenAlg,
    },
}

/// Construct the configured [`Signer`], resolving its public key (the trust
/// anchor) from the backend. Async because external backends do a network / HSM
/// round-trip at construction. The returned signer's `public_key()` is then a
/// cached read on the hot mint path.
pub async fn build_signer(config: &SignerConfig) -> Result<Arc<dyn Signer>, SignerError> {
    match config {
        SignerConfig::Local { private_key } => Ok(Arc::new(
            LocalSigner::from_private_hex(private_key)
                .map_err(|e| SignerError::Key(e.to_string()))?,
        )),
        #[cfg(feature = "signer-vault")]
        SignerConfig::Vault {
            address,
            key,
            token_env,
            alg,
        } => Ok(Arc::new(
            vault::VaultSigner::connect(address, key, token_env, *alg).await?,
        )),
        #[cfg(not(feature = "signer-vault"))]
        SignerConfig::Vault { .. } => Err(SignerError::Unsupported("vault")),
        #[cfg(feature = "signer-aws")]
        SignerConfig::AwsKms { key_id, region } => Ok(Arc::new(
            aws_kms::AwsKmsSigner::connect(key_id, region.as_deref()).await?,
        )),
        #[cfg(not(feature = "signer-aws"))]
        SignerConfig::AwsKms { .. } => Err(SignerError::Unsupported("aws-kms")),
        #[cfg(feature = "signer-gcp")]
        SignerConfig::GcpKms {
            key_version,
            access_token_env,
        } => Ok(Arc::new(
            gcp::GcpKmsSigner::connect(key_version, access_token_env).await?,
        )),
        #[cfg(not(feature = "signer-gcp"))]
        SignerConfig::GcpKms { .. } => Err(SignerError::Unsupported("gcp-kms")),
        #[cfg(feature = "signer-azure")]
        SignerConfig::AzureKv {
            vault_url,
            key,
            key_version,
            access_token_env,
        } => Ok(Arc::new(
            azure::AzureKvSigner::connect(vault_url, key, key_version, access_token_env).await?,
        )),
        #[cfg(not(feature = "signer-azure"))]
        SignerConfig::AzureKv { .. } => Err(SignerError::Unsupported("azure-kv")),
        #[cfg(feature = "signer-pkcs11")]
        SignerConfig::Pkcs11 {
            module,
            token_label,
            key_label,
            pin_env,
            alg,
        } => Ok(Arc::new(pkcs11::Pkcs11Signer::connect(
            module,
            token_label,
            key_label,
            pin_env,
            *alg,
        )?)),
        #[cfg(not(feature = "signer-pkcs11"))]
        SignerConfig::Pkcs11 { .. } => Err(SignerError::Unsupported("pkcs11")),
    }
}

/// SHA-256 of `data` (the digest KMS/HSM ECDSA signing consumes). Uses the
/// `aws-lc-rs` provider already in the tree (the mesh + rustls use it).
#[cfg(any(
    feature = "signer-gcp",
    feature = "signer-azure",
    feature = "signer-pkcs11"
))]
pub(crate) fn sha256(data: &[u8]) -> Vec<u8> {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

/// Live-test helper: mint a token **through `signer`** and verify it against the
/// public key the signer resolved at connect — the full end-to-end round-trip
/// that proves an external backend actually signs valid boatramp tokens. Shared by
/// the `#[ignore]` live tests (each constructs its backend from env, then calls
/// this). Run e.g. `cargo test -p boatramp-server --features signer-vault -- --ignored`.
#[cfg(all(
    test,
    any(
        feature = "signer-vault",
        feature = "signer-gcp",
        feature = "signer-azure",
        feature = "signer-aws",
        feature = "signer-pkcs11"
    )
))]
pub(crate) async fn assert_signs_and_verifies(signer: &dyn Signer) {
    use boatramp_core::authz::GrantedRole;
    use boatramp_core::cose::{self, Claims};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let claims = Claims {
        roles: vec![GrantedRole::global("admin")],
        kind: cose::KIND_ROLE.to_string(),
        ttl_secs: Some(300),
        now_unix: now,
    };
    let token = cose::mint(&claims, signer)
        .await
        .expect("mint through the external signer");
    let verified =
        cose::verify(&token, &signer.public_key(), now).expect("verify against the resolved key");
    assert_eq!(verified.roles, vec![GrantedRole::global("admin")]);
    assert_eq!(verified.kind, cose::KIND_ROLE);
}
