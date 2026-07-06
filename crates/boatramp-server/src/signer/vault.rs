//! HashiCorp Vault **Transit** signer (feature `signer-vault`).
//!
//! Signs through `POST /v1/transit/sign/<key>`; the private key never leaves
//! Vault. ES256 uses `marshaling_algorithm=jws`, so Vault returns the raw `r‖s`
//! form directly (no DER conversion). The public key (trust anchor) is read once
//! from `GET /v1/transit/keys/<key>` at connect.

use async_trait::async_trait;
use base64::Engine as _;

use boatramp_core::cose::{Signer, TokenAlg, TokenError, TokenPublicKey};

use super::{rest, SignerError};

const BACKEND: &str = "vault";

/// A Vault Transit signing key.
pub(crate) struct VaultSigner {
    http: reqwest::Client,
    /// `POST` target for signing, `.../v1/transit/sign/<key>`.
    sign_url: String,
    token: String,
    alg: TokenAlg,
    public: TokenPublicKey,
}

impl VaultSigner {
    /// Connect to Vault, resolve the key's public half, and cache it.
    pub(crate) async fn connect(
        address: &str,
        key: &str,
        token_env: &str,
        alg: TokenAlg,
    ) -> Result<Self, SignerError> {
        let token = SignerError::env(token_env)?;
        let http = rest::client();
        let base = address.trim_end_matches('/');
        let keys_url = format!("{base}/v1/transit/keys/{key}");
        let sign_url = format!("{base}/v1/transit/sign/{key}");

        let resp = http
            .get(&keys_url)
            .header("X-Vault-Token", &token)
            .send()
            .await
            .map_err(|e| SignerError::backend(BACKEND, e))?;
        if !resp.status().is_success() {
            return Err(SignerError::backend(
                BACKEND,
                format!("reading key `{key}`: HTTP {}", resp.status()),
            ));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SignerError::backend(BACKEND, e))?;
        let public = parse_public_key(&body, alg)?;
        Ok(Self {
            http,
            sign_url,
            token,
            alg,
            public,
        })
    }
}

/// Extract the latest key version's public key from a `transit/keys/<key>`
/// response. ES256 is a PEM SPKI block; Ed25519 is base64 of the raw 32-byte key.
fn parse_public_key(
    body: &serde_json::Value,
    alg: TokenAlg,
) -> Result<TokenPublicKey, SignerError> {
    let data = &body["data"];
    let latest = data["latest_version"]
        .as_u64()
        .ok_or_else(|| SignerError::backend(BACKEND, "no latest_version in key response"))?;
    let entry = &data["keys"][latest.to_string()];
    let public_key = entry["public_key"]
        .as_str()
        .ok_or_else(|| SignerError::backend(BACKEND, "no public_key in key response"))?;
    match alg {
        TokenAlg::Es256 => TokenPublicKey::es256_from_spki_pem(public_key)
            .map_err(|e| SignerError::Key(e.to_string())),
        TokenAlg::Ed25519 => {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(public_key.trim())
                .map_err(|e| SignerError::Key(format!("ed25519 public key base64: {e}")))?;
            TokenPublicKey::from_hex(&format!("ed25519:{}", hex::encode(raw)))
                .map_err(|e| SignerError::Key(e.to_string()))
        }
    }
}

#[async_trait]
impl Signer for VaultSigner {
    fn alg(&self) -> TokenAlg {
        self.alg
    }

    fn public_key(&self) -> TokenPublicKey {
        self.public.clone()
    }

    async fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, TokenError> {
        let input = base64::engine::general_purpose::STANDARD.encode(tbs);
        let body = match self.alg {
            // JWS marshaling ⇒ raw r‖s; Vault hashes with SHA-256 internally.
            TokenAlg::Es256 => serde_json::json!({
                "input": input,
                "hash_algorithm": "sha2-256",
                "prehashed": false,
                "marshaling_algorithm": "jws",
            }),
            // Ed25519 signs the message directly; the signature is already raw.
            TokenAlg::Ed25519 => serde_json::json!({ "input": input }),
        };
        let resp = self
            .http
            .post(&self.sign_url)
            .header("X-Vault-Token", &self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| TokenError::Signer(format!("vault: {e}")))?;
        if !resp.status().is_success() {
            return Err(TokenError::Signer(format!("vault: HTTP {}", resp.status())));
        }
        let parsed: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TokenError::Signer(format!("vault: {e}")))?;
        let signature = parsed["data"]["signature"]
            .as_str()
            .ok_or_else(|| TokenError::Signer("vault: no signature in response".into()))?;
        decode_signature(signature, self.alg)
    }
}

/// Decode a Vault `vault:v<n>:<b64>` signature into the raw COSE form. ES256 (JWS
/// marshaling) is base64url of `r‖s`; Ed25519 is base64-std of the raw 64 bytes.
fn decode_signature(signature: &str, alg: TokenAlg) -> Result<Vec<u8>, TokenError> {
    let b64 = signature
        .rsplit(':')
        .next()
        .ok_or_else(|| TokenError::Signer("vault: malformed signature".into()))?;
    let raw = match alg {
        TokenAlg::Es256 => base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| TokenError::Signer(format!("vault es256 signature base64: {e}")))?,
        TokenAlg::Ed25519 => base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| TokenError::Signer(format!("vault ed25519 signature base64: {e}")))?,
    };
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_prefix_is_stripped_and_decoded() {
        // JWS-marshaled ES256 sig: `vault:v1:<base64url of 64 bytes>`.
        let raw = vec![7u8; 64];
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw);
        let vault = format!("vault:v1:{b64}");
        assert_eq!(decode_signature(&vault, TokenAlg::Es256).unwrap(), raw);
    }

    #[test]
    fn es256_public_key_parsed_from_transit_keys_response() {
        // Shape a `transit/keys/<key>` response around a real P-256 SPKI PEM.
        use p256::pkcs8::{EncodePublicKey as _, LineEnding};
        let sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let pem = sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let body = serde_json::json!({
            "data": { "latest_version": 3, "keys": { "3": { "public_key": pem } } }
        });
        let parsed = parse_public_key(&body, TokenAlg::Es256).unwrap();
        let want = TokenPublicKey::Es256(*sk.verifying_key()).to_hex();
        assert_eq!(parsed.to_hex(), want);
    }

    /// Live round-trip against a real Vault Transit key. Env:
    /// `BOATRAMP_TEST_VAULT_ADDR`, `BOATRAMP_TEST_VAULT_KEY`, `VAULT_TOKEN`.
    #[tokio::test]
    #[ignore = "requires a live Vault Transit key (BOATRAMP_TEST_VAULT_ADDR/_KEY, VAULT_TOKEN)"]
    async fn vault_live() {
        let addr = std::env::var("BOATRAMP_TEST_VAULT_ADDR").expect("BOATRAMP_TEST_VAULT_ADDR");
        let key = std::env::var("BOATRAMP_TEST_VAULT_KEY").expect("BOATRAMP_TEST_VAULT_KEY");
        let signer = VaultSigner::connect(&addr, &key, "VAULT_TOKEN", TokenAlg::Es256)
            .await
            .expect("connect to Vault");
        super::super::assert_signs_and_verifies(&signer).await;
    }
}
