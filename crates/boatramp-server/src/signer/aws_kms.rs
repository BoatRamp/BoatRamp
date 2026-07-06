//! AWS **KMS** signer (feature `signer-aws`).
//!
//! Signs through the KMS `Sign` API on an `ECC_NIST_P256` asymmetric key; the
//! private key never leaves KMS. Credentials come from the standard AWS provider
//! chain (env / profile / IMDS), so no secret lives in boatramp config. KMS
//! returns a **DER** ECDSA signature, normalized to the raw `r‖s` COSE form.
//! ES256 only (KMS asymmetric signing is ECDSA/RSA — no Ed25519). `MessageType =
//! Raw` lets KMS hash the small `ToBeSigned` with SHA-256 (well under the 4 KiB
//! raw limit), so we don't pre-hash.

use async_trait::async_trait;

use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use boatramp_core::cose::{self, Signer, TokenAlg, TokenError, TokenPublicKey};

use super::SignerError;

const BACKEND: &str = "aws-kms";

/// An AWS KMS asymmetric (P-256) signing key.
pub(crate) struct AwsKmsSigner {
    client: aws_sdk_kms::Client,
    key_id: String,
    public: TokenPublicKey,
}

impl AwsKmsSigner {
    /// Connect (resolving credentials + region from the provider chain), fetch the
    /// key's public half (SPKI DER), and cache it.
    pub(crate) async fn connect(key_id: &str, region: Option<&str>) -> Result<Self, SignerError> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = region {
            loader = loader.region(aws_sdk_kms::config::Region::new(region.to_string()));
        }
        let config = loader.load().await;
        let client = aws_sdk_kms::Client::new(&config);

        let out = client
            .get_public_key()
            .key_id(key_id)
            .send()
            .await
            .map_err(|e| SignerError::backend(BACKEND, e))?;
        let der = out
            .public_key()
            .ok_or_else(|| SignerError::backend(BACKEND, "GetPublicKey returned no key"))?;
        let public = TokenPublicKey::es256_from_spki_der(der.as_ref())
            .map_err(|e| SignerError::Key(e.to_string()))?;
        Ok(Self {
            client,
            key_id: key_id.to_string(),
            public,
        })
    }
}

#[async_trait]
impl Signer for AwsKmsSigner {
    fn alg(&self) -> TokenAlg {
        TokenAlg::Es256
    }

    fn public_key(&self) -> TokenPublicKey {
        self.public.clone()
    }

    async fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, TokenError> {
        let out = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(tbs.to_vec()))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .map_err(|e| TokenError::Signer(format!("aws-kms: {e}")))?;
        let der = out
            .signature()
            .ok_or_else(|| TokenError::Signer("aws-kms: Sign returned no signature".into()))?;
        cose::p256_der_sig_to_raw(der.as_ref()).map_err(|e| TokenError::Signer(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live round-trip against a real AWS KMS `ECC_NIST_P256` signing key. Env:
    /// `BOATRAMP_TEST_AWS_KMS_KEY_ID` (+ optional `BOATRAMP_TEST_AWS_REGION`); AWS
    /// credentials come from the standard provider chain.
    #[tokio::test]
    #[ignore = "requires a live AWS KMS ECC_NIST_P256 key (BOATRAMP_TEST_AWS_KMS_KEY_ID; AWS creds from the provider chain)"]
    async fn aws_kms_live() {
        let key_id = std::env::var("BOATRAMP_TEST_AWS_KMS_KEY_ID").expect("KMS key id/ARN");
        let region = std::env::var("BOATRAMP_TEST_AWS_REGION").ok();
        let signer = AwsKmsSigner::connect(&key_id, region.as_deref())
            .await
            .expect("connect to KMS");
        super::super::assert_signs_and_verifies(&signer).await;
    }
}
