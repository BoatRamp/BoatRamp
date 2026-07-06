//! OIDC bearer-JWT verification for the control plane.
//!
//! A third auth mode beside the single bootstrap token and KV multi-tokens: a
//! request's `Authorization: Bearer <jwt>` is verified against an OIDC issuer's
//! signing keys (JWKS), and a configured claim (default `scope`) is mapped to
//! boatramp scopes (`*`, `site:<name>`). The IdP must therefore mint tokens
//! whose scope claim already carries boatramp scopes — an OIDC identity with no
//! mapped scope is rejected (a valid token is *not* implicitly admin, unlike the
//! empty-scope KV-token convention).
//!
//! The verify path (signature + `iss`/`aud`/`exp` validation + claim→scope
//! mapping) is pure and synchronous once the signing keys are loaded, so it is
//! unit-tested with an injected key. Fetching the live JWKS from the issuer is
//! the only network step ([`OidcVerifier::from_discovery`]) — reached only in live/integration testing.

use std::collections::HashMap;
use std::sync::RwLock;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

/// Static OIDC settings (issuer + expected audience + which claim carries the
/// boatramp scopes). The signing keys come from the issuer's JWKS.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Expected `iss` — the OIDC issuer URL.
    pub issuer: String,
    /// Expected `aud`, if the deployment pins one (e.g. the boatramp API's
    /// client id). `None` skips audience validation.
    pub audience: Option<String>,
    /// The claim whose value carries boatramp scopes (space-delimited string or
    /// a JSON array). Defaults to `scope`.
    pub scope_claim: String,
}

impl OidcConfig {
    /// A config for `issuer` with the default `scope` claim.
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: None,
            scope_claim: "scope".to_string(),
        }
    }
}

/// The signing keys, swappable so a periodic JWKS refresh can rotate them.
#[derive(Default)]
struct Keys {
    by_kid: HashMap<String, DecodingKey>,
    /// Used when a token header carries no `kid` and exactly one key is known.
    sole: Option<DecodingKey>,
}

impl Keys {
    fn new(by_kid: HashMap<String, DecodingKey>) -> Self {
        let sole = if by_kid.len() == 1 {
            by_kid.values().next().cloned()
        } else {
            None
        };
        Self { by_kid, sole }
    }
}

/// Verifies bearer JWTs against the issuer's signing keys (by `kid`). The
/// keyset is behind an `RwLock` so [`refresh`](Self::refresh) can rotate it
/// (handles IdP key rollover) while reads stay cheap.
pub struct OidcVerifier {
    keys: RwLock<Keys>,
    validation: Validation,
    scope_claim: String,
    /// Set for verifiers built from a live issuer, so `refresh` can re-fetch.
    refresh: Option<(reqwest::Client, OidcConfig)>,
}

impl OidcVerifier {
    /// Build a verifier from already-loaded signing keys (`kid` → key) and a
    /// [`Validation`]. Used by tests (injecting an HS256 key to exercise the
    /// verify path); such verifiers can't [`refresh`](Self::refresh).
    pub fn new(
        keys: HashMap<String, DecodingKey>,
        validation: Validation,
        scope_claim: impl Into<String>,
    ) -> Self {
        Self {
            keys: RwLock::new(Keys::new(keys)),
            validation,
            scope_claim: scope_claim.into(),
            refresh: None,
        }
    }

    /// Verify `token`; on success return the boatramp scopes its scope claim
    /// maps to. Returns `None` if the signature/claims are invalid or the token
    /// carries no mapped scope.
    pub fn verify(&self, token: &str) -> Option<Vec<String>> {
        let header = decode_header(token).ok()?;
        let keys = self.keys.read().ok()?;
        let key = match header.kid.as_deref() {
            Some(kid) => keys.by_kid.get(kid)?,
            None => keys.sole.as_ref()?,
        };
        let data = decode::<serde_json::Value>(token, key, &self.validation).ok()?;
        let scopes = data
            .claims
            .get(&self.scope_claim)
            .map(claim_to_scopes)
            .unwrap_or_default();
        // A valid token with no mapped scope grants nothing (not implicit admin).
        (!scopes.is_empty()).then_some(scopes)
    }

    /// Re-fetch the issuer's JWKS and atomically swap the keyset in, so a key
    /// the IdP rotated in is honored without a restart. A no-op for verifiers
    /// not built from a live issuer (e.g. tests). The fetch is exercised only in live testing.
    pub async fn refresh(&self) -> Result<(), OidcError> {
        let Some((http, config)) = &self.refresh else {
            return Ok(());
        };
        let by_kid = fetch_jwks_keys(http, config).await?;
        *self.keys.write().map_err(|_| OidcError::NoKeys)? = Keys::new(by_kid);
        Ok(())
    }

    /// Discover the issuer's JWKS and build an RS256 verifier (the live network
    /// step — exercised only in live testing). Reads `<issuer>/.well-known/openid-configuration`
    /// for `jwks_uri`, fetches the JWKS, and builds a [`DecodingKey`] per RSA key.
    pub async fn from_discovery(
        http: &reqwest::Client,
        config: &OidcConfig,
    ) -> Result<Self, OidcError> {
        let by_kid = fetch_jwks_keys(http, config).await?;
        Ok(Self {
            keys: RwLock::new(Keys::new(by_kid)),
            validation: config.validation(),
            scope_claim: config.scope_claim.clone(),
            // Keep the client + config so `refresh` can re-fetch on key rollover.
            refresh: Some((http.clone(), config.clone())),
        })
    }
}

/// Fetch the issuer's discovery doc + JWKS and build the `kid` → key map (the
/// live network step). Errors if the issuer exposes no usable RSA key.
async fn fetch_jwks_keys(
    http: &reqwest::Client,
    config: &OidcConfig,
) -> Result<HashMap<String, DecodingKey>, OidcError> {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        config.issuer.trim_end_matches('/')
    );
    let discovery: Discovery = http
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| OidcError::Fetch(e.to_string()))?
        .error_for_status()
        .map_err(|e| OidcError::Fetch(e.to_string()))?
        .json()
        .await
        .map_err(|e| OidcError::Parse(e.to_string()))?;
    let jwks: JwkSet = http
        .get(&discovery.jwks_uri)
        .send()
        .await
        .map_err(|e| OidcError::Fetch(e.to_string()))?
        .error_for_status()
        .map_err(|e| OidcError::Fetch(e.to_string()))?
        .json()
        .await
        .map_err(|e| OidcError::Parse(e.to_string()))?;
    let keys = jwks.decoding_keys()?;
    if keys.is_empty() {
        return Err(OidcError::NoKeys);
    }
    Ok(keys)
}

impl OidcConfig {
    /// The RS256 [`Validation`] this config implies (issuer always checked;
    /// audience only when pinned).
    fn validation(&self) -> Validation {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        match &self.audience {
            Some(aud) => validation.set_audience(&[aud]),
            None => validation.validate_aud = false,
        }
        validation
    }
}

/// Map a scope claim value to boatramp scopes: a space-delimited string (OAuth
/// `scope`) or a JSON array of strings.
fn claim_to_scopes(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::String(s) => s.split_whitespace().map(String::from).collect(),
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

/// The subset of OIDC discovery we need.
#[derive(Debug, Deserialize)]
struct Discovery {
    jwks_uri: String,
}

/// A JSON Web Key Set.
#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// A single RSA JSON Web Key (the only key type we accept).
#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    /// base64url modulus.
    n: Option<String>,
    /// base64url exponent.
    e: Option<String>,
}

impl JwkSet {
    /// Build a `kid` → [`DecodingKey`] map from the RSA keys in the set
    /// (non-RSA keys are skipped). Keys without a `kid` are stored under "".
    fn decoding_keys(&self) -> Result<HashMap<String, DecodingKey>, OidcError> {
        let mut out = HashMap::new();
        for jwk in &self.keys {
            if jwk.kty != "RSA" {
                continue;
            }
            let (Some(n), Some(e)) = (&jwk.n, &jwk.e) else {
                continue;
            };
            let key = DecodingKey::from_rsa_components(n, e)
                .map_err(|err| OidcError::Key(err.to_string()))?;
            out.insert(jwk.kid.clone().unwrap_or_default(), key);
        }
        Ok(out)
    }
}

/// Errors loading an OIDC verifier from a live issuer.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    /// A discovery/JWKS HTTP fetch failed.
    #[error("oidc fetch failed: {0}")]
    Fetch(String),
    /// A discovery/JWKS document didn't parse.
    #[error("oidc parse failed: {0}")]
    Parse(String),
    /// A JWK could not be turned into a verification key.
    #[error("oidc key error: {0}")]
    Key(String),
    /// The issuer's JWKS held no usable (RSA) signing keys.
    #[error("oidc issuer exposed no usable signing keys")]
    NoKeys,
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    /// Build a verifier + matching signer using a symmetric (HS256) key — this
    /// exercises the exact decode/validate/scope-map path the RS256 production
    /// build uses, without RSA keygen in the test.
    fn hs256_pair(issuer: &str, audience: Option<&str>) -> (OidcVerifier, EncodingKey, Header) {
        let secret = b"test-signing-secret-0123456789";
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[issuer]);
        match audience {
            Some(aud) => validation.set_audience(&[aud]),
            None => validation.validate_aud = false,
        }
        let mut keys = HashMap::new();
        keys.insert("test-kid".to_string(), DecodingKey::from_secret(secret));
        let verifier = OidcVerifier::new(keys, validation, "scope");
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-kid".to_string());
        (verifier, EncodingKey::from_secret(secret), header)
    }

    fn sign(key: &EncodingKey, header: &Header, claims: serde_json::Value) -> String {
        encode(header, &claims, key).unwrap()
    }

    fn exp() -> i64 {
        // A fixed far-future expiry (avoids wall-clock in the test).
        4_102_444_800 // 2100-01-01
    }

    #[test]
    fn maps_space_delimited_scope_claim() {
        let (v, key, header) = hs256_pair("https://issuer.test", None);
        let token = sign(
            &key,
            &header,
            serde_json::json!({"iss": "https://issuer.test", "exp": exp(), "scope": "site:blog site:docs"}),
        );
        assert_eq!(
            v.verify(&token),
            Some(vec!["site:blog".to_string(), "site:docs".to_string()])
        );
    }

    #[test]
    fn maps_array_scope_claim() {
        let (v, key, header) = hs256_pair("https://issuer.test", None);
        let token = sign(
            &key,
            &header,
            serde_json::json!({"iss": "https://issuer.test", "exp": exp(), "scope": ["*"]}),
        );
        assert_eq!(v.verify(&token), Some(vec!["*".to_string()]));
    }

    #[test]
    fn rejects_wrong_issuer() {
        let (v, key, header) = hs256_pair("https://issuer.test", None);
        let token = sign(
            &key,
            &header,
            serde_json::json!({"iss": "https://evil.test", "exp": exp(), "scope": "*"}),
        );
        assert_eq!(v.verify(&token), None);
    }

    #[test]
    fn rejects_wrong_audience() {
        let (v, key, header) = hs256_pair("https://issuer.test", Some("boatramp-api"));
        let token = sign(
            &key,
            &header,
            serde_json::json!({"iss": "https://issuer.test", "aud": "other", "exp": exp(), "scope": "*"}),
        );
        assert_eq!(v.verify(&token), None);
    }

    #[test]
    fn rejects_expired_token() {
        let (v, key, header) = hs256_pair("https://issuer.test", None);
        let token = sign(
            &key,
            &header,
            serde_json::json!({"iss": "https://issuer.test", "exp": 1_000_000_000, "scope": "*"}),
        );
        assert_eq!(v.verify(&token), None);
    }

    #[test]
    fn rejects_valid_token_with_no_scope() {
        let (v, key, header) = hs256_pair("https://issuer.test", None);
        let token = sign(
            &key,
            &header,
            serde_json::json!({"iss": "https://issuer.test", "exp": exp()}),
        );
        assert_eq!(v.verify(&token), None, "no scope claim → not authenticated");
    }

    #[test]
    fn rejects_tampered_signature() {
        let (v, key, header) = hs256_pair("https://issuer.test", None);
        let token = sign(
            &key,
            &header,
            serde_json::json!({"iss": "https://issuer.test", "exp": exp(), "scope": "*"}),
        );
        let tampered = format!("{token}x");
        assert_eq!(v.verify(&tampered), None);
    }

    #[test]
    fn parses_rsa_jwks_into_keys() {
        // A well-formed RSA JWK (components from the jsonwebtoken test vectors)
        // builds a decoding key; a non-RSA key is skipped.
        let jwks: JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "r1",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                },
                { "kty": "oct", "kid": "skip" }
            ]
        }))
        .unwrap();
        let keys = jwks.decoding_keys().unwrap();
        assert_eq!(keys.len(), 1, "only the RSA key is usable");
        assert!(keys.contains_key("r1"));
    }
}
