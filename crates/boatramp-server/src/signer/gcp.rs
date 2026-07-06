//! GCP **Cloud KMS** signer (feature `signer-gcp`).
//!
//! Signs through `…:asymmetricSign` on an `EC_SIGN_P256_SHA256` key version; the
//! private key never leaves Cloud KMS. KMS returns a **DER** ECDSA signature,
//! normalized to the raw `r‖s` COSE form. ES256 only (Cloud KMS can't sign
//! Ed25519). The OAuth2 access token is read from an env var on each call, so a
//! workload-identity sidecar can refresh it without a restart; obtaining that
//! token (metadata server / service-account flow) is the deployment's job.

use async_trait::async_trait;
use base64::Engine as _;

use boatramp_core::cose::{self, Signer, TokenAlg, TokenError, TokenPublicKey};

use super::{rest, sha256, SignerError};

const BACKEND: &str = "gcp-kms";
const API: &str = "https://cloudkms.googleapis.com/v1";

/// A GCP Cloud KMS asymmetric signing key version.
pub(crate) struct GcpKmsSigner {
    http: reqwest::Client,
    key_version: String,
    access_token_env: String,
    public: TokenPublicKey,
}

impl GcpKmsSigner {
    /// Connect, fetch the key version's public key (PEM SPKI), and cache it.
    pub(crate) async fn connect(
        key_version: &str,
        access_token_env: &str,
    ) -> Result<Self, SignerError> {
        let token = SignerError::env(access_token_env)?;
        let http = rest::client();
        let url = format!("{API}/{key_version}/publicKey");
        let resp = http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| SignerError::backend(BACKEND, e))?;
        if !resp.status().is_success() {
            return Err(SignerError::backend(
                BACKEND,
                format!("reading public key: HTTP {}", resp.status()),
            ));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SignerError::backend(BACKEND, e))?;
        let pem = body["pem"]
            .as_str()
            .ok_or_else(|| SignerError::backend(BACKEND, "no pem in publicKey response"))?;
        let public = TokenPublicKey::es256_from_spki_pem(pem)
            .map_err(|e| SignerError::Key(e.to_string()))?;
        Ok(Self {
            http,
            key_version: key_version.to_string(),
            access_token_env: access_token_env.to_string(),
            public,
        })
    }
}

#[async_trait]
impl Signer for GcpKmsSigner {
    fn alg(&self) -> TokenAlg {
        TokenAlg::Es256
    }

    fn public_key(&self) -> TokenPublicKey {
        self.public.clone()
    }

    async fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, TokenError> {
        let token = std::env::var(&self.access_token_env)
            .map_err(|_| TokenError::Signer(format!("gcp: {} unset", self.access_token_env)))?;
        let digest = base64::engine::general_purpose::STANDARD.encode(sha256(tbs));
        let url = format!("{API}/{}:asymmetricSign", self.key_version);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .json(&serde_json::json!({ "digest": { "sha256": digest } }))
            .send()
            .await
            .map_err(|e| TokenError::Signer(format!("gcp: {e}")))?;
        if !resp.status().is_success() {
            return Err(TokenError::Signer(format!("gcp: HTTP {}", resp.status())));
        }
        let parsed: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TokenError::Signer(format!("gcp: {e}")))?;
        let sig_b64 = parsed["signature"]
            .as_str()
            .ok_or_else(|| TokenError::Signer("gcp: no signature in response".into()))?;
        let der = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .map_err(|e| TokenError::Signer(format!("gcp signature base64: {e}")))?;
        cose::p256_der_sig_to_raw(&der).map_err(|e| TokenError::Signer(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live round-trip against a real GCP Cloud KMS key version. Env:
    /// `BOATRAMP_TEST_GCP_KEY_VERSION`, `GCP_ACCESS_TOKEN` (e.g. `gcloud auth
    /// print-access-token`).
    #[tokio::test]
    #[ignore = "requires a live GCP Cloud KMS key version (BOATRAMP_TEST_GCP_KEY_VERSION, GCP_ACCESS_TOKEN)"]
    async fn gcp_live() {
        let key_version =
            std::env::var("BOATRAMP_TEST_GCP_KEY_VERSION").expect("key version resource name");
        let signer = GcpKmsSigner::connect(&key_version, "GCP_ACCESS_TOKEN")
            .await
            .expect("connect to Cloud KMS");
        super::super::assert_signs_and_verifies(&signer).await;
    }
}
