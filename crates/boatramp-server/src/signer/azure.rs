//! Azure **Key Vault** signer (feature `signer-azure`).
//!
//! Signs through `POST /keys/<key>/<version>/sign` with `alg = ES256`; the
//! private key never leaves Key Vault. Azure returns the raw `r‖s` (P1363) form —
//! no DER conversion. ES256 only. The Azure AD access token (for the Key Vault
//! resource) is read from an env var on each call so a managed-identity sidecar
//! can refresh it; obtaining it is the deployment's job.

use async_trait::async_trait;
use base64::Engine as _;

use boatramp_core::cose::{Signer, TokenAlg, TokenError, TokenPublicKey};

use super::{rest, sha256, SignerError};

const BACKEND: &str = "azure-kv";
const API_VERSION: &str = "7.4";

/// An Azure Key Vault EC (P-256) signing key.
pub(crate) struct AzureKvSigner {
    http: reqwest::Client,
    sign_url: String,
    access_token_env: String,
    public: TokenPublicKey,
}

impl AzureKvSigner {
    /// Connect, fetch the key's JWK (x/y), and cache the public key.
    pub(crate) async fn connect(
        vault_url: &str,
        key: &str,
        key_version: &str,
        access_token_env: &str,
    ) -> Result<Self, SignerError> {
        let token = SignerError::env(access_token_env)?;
        let http = rest::client();
        let base = vault_url.trim_end_matches('/');
        let key_url = format!("{base}/keys/{key}/{key_version}?api-version={API_VERSION}");
        let sign_url = format!("{base}/keys/{key}/{key_version}/sign?api-version={API_VERSION}");

        let resp = http
            .get(&key_url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| SignerError::backend(BACKEND, e))?;
        if !resp.status().is_success() {
            return Err(SignerError::backend(
                BACKEND,
                format!("reading key: HTTP {}", resp.status()),
            ));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SignerError::backend(BACKEND, e))?;
        let public = parse_jwk_p256(&body["key"])?;
        Ok(Self {
            http,
            sign_url,
            access_token_env: access_token_env.to_string(),
            public,
        })
    }
}

/// Build a P-256 public key from an Azure Key Vault EC JWK (`x`/`y`, base64url).
fn parse_jwk_p256(jwk: &serde_json::Value) -> Result<TokenPublicKey, SignerError> {
    let decode = |field: &str| -> Result<Vec<u8>, SignerError> {
        let s = jwk[field]
            .as_str()
            .ok_or_else(|| SignerError::backend(BACKEND, format!("JWK missing `{field}`")))?;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| SignerError::Key(format!("JWK {field} base64url: {e}")))
    };
    let x = decode("x")?;
    let y = decode("y")?;
    // SEC1 uncompressed point: 0x04 ‖ x ‖ y — accepted by `from_sec1_bytes`.
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    TokenPublicKey::from_hex(&format!("es256:{}", hex::encode(point)))
        .map_err(|e| SignerError::Key(e.to_string()))
}

#[async_trait]
impl Signer for AzureKvSigner {
    fn alg(&self) -> TokenAlg {
        TokenAlg::Es256
    }

    fn public_key(&self) -> TokenPublicKey {
        self.public.clone()
    }

    async fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, TokenError> {
        let token = std::env::var(&self.access_token_env)
            .map_err(|_| TokenError::Signer(format!("azure: {} unset", self.access_token_env)))?;
        // ES256 signs the SHA-256 digest; Key Vault takes it base64url-encoded.
        let value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha256(tbs));
        let resp = self
            .http
            .post(&self.sign_url)
            .bearer_auth(&token)
            .json(&serde_json::json!({ "alg": "ES256", "value": value }))
            .send()
            .await
            .map_err(|e| TokenError::Signer(format!("azure: {e}")))?;
        if !resp.status().is_success() {
            return Err(TokenError::Signer(format!("azure: HTTP {}", resp.status())));
        }
        let parsed: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TokenError::Signer(format!("azure: {e}")))?;
        let sig_b64 = parsed["value"]
            .as_str()
            .ok_or_else(|| TokenError::Signer("azure: no value in response".into()))?;
        // Azure returns the raw r‖s (P1363) form directly.
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| TokenError::Signer(format!("azure signature base64url: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p256_public_key_parsed_from_ec_jwk() {
        // Encode a real P-256 key's affine x/y as a Key Vault EC JWK, then parse.
        let sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        });
        let parsed = parse_jwk_p256(&jwk).unwrap();
        let want = TokenPublicKey::Es256(*sk.verifying_key()).to_hex();
        assert_eq!(parsed.to_hex(), want);
    }

    /// Live round-trip against a real Azure Key Vault EC key. Env:
    /// `BOATRAMP_TEST_AZURE_VAULT_URL`/`_KEY`/`_KEY_VERSION`, `AZURE_ACCESS_TOKEN`.
    #[tokio::test]
    #[ignore = "requires a live Azure Key Vault key (BOATRAMP_TEST_AZURE_VAULT_URL/_KEY/_KEY_VERSION, AZURE_ACCESS_TOKEN)"]
    async fn azure_live() {
        let url = std::env::var("BOATRAMP_TEST_AZURE_VAULT_URL").expect("vault url");
        let key = std::env::var("BOATRAMP_TEST_AZURE_KEY").expect("key");
        let ver = std::env::var("BOATRAMP_TEST_AZURE_KEY_VERSION").expect("key version");
        let signer = AzureKvSigner::connect(&url, &key, &ver, "AZURE_ACCESS_TOKEN")
            .await
            .expect("connect to Key Vault");
        super::super::assert_signs_and_verifies(&signer).await;
    }
}
