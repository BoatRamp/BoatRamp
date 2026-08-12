//! Verifying an **application** bearer token whose claims the data connector's `row_filter`
//! may bind — the seam that unlocks multi-tenant-within-one-project isolation.
//!
//! Distinct from boatramp's own control-plane auth ([`crate::oidc`]): here the *app's* IdP
//! signs scoped tokens (e.g. carrying a `tid`), and boatramp verifies them against an
//! operator-configured issuer + JWKS purely to *source claim values* for row-level filtering.
//! It grants no boatramp scope.
//!
//! Security invariants (this is a tenant-isolation seam):
//! - A claim is used **only** from a fully verified token — signature, `iss`, `exp`/`nbf`,
//!   and a `kid` that resolves to a JWKS key. `verify` returns `None` on any failure, so a
//!   missing/expired/forged/wrong-issuer/unknown-`kid` token yields *no* claims (fail-closed);
//!   a `row_filter` referencing an absent claim then denies via `PolicyError::MissingClaim`.
//! - The verification algorithm is **pinned to the JWKS key's own type**, never the token
//!   header's `alg`, so algorithm-confusion (`alg:none`, RS256↔HS256) can't downgrade it.
//! - The host-asserted `project` claim is never sourced here, so a token can't spoof it.

use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use boatramp_core::config::HandlerGraphqlTokenClaims;

/// A verifier for one app IdP: its signing keys (by `kid`) + the expected `iss`/`aud`.
pub(crate) struct TokenVerifier {
    by_kid: HashMap<String, (DecodingKey, Algorithm)>,
    /// Used when a token carries no `kid` and the JWKS has exactly one key.
    sole: Option<(DecodingKey, Algorithm)>,
    issuer: String,
    audience: Option<String>,
}

impl TokenVerifier {
    /// Build from a JWKS JSON document. Only asymmetric keys usable for signature
    /// verification are kept (RSA → RS256, EC P-256/P-384 → ES256/384, OKP Ed25519 → EdDSA);
    /// symmetric/other keys are skipped. Errors if none are usable.
    pub(crate) fn from_jwks_json(
        jwks: &str,
        issuer: &str,
        audience: Option<&str>,
    ) -> Result<Self, String> {
        let set: JwkSet = serde_json::from_str(jwks).map_err(|e| format!("parsing JWKS: {e}"))?;
        let mut by_kid = HashMap::new();
        for jwk in &set.keys {
            let (Some(alg), Ok(key)) = (jwk_algorithm(jwk), DecodingKey::from_jwk(jwk)) else {
                continue;
            };
            by_kid.insert(jwk.common.key_id.clone().unwrap_or_default(), (key, alg));
        }
        if by_kid.is_empty() {
            return Err("JWKS held no usable signing keys".to_string());
        }
        let sole = (by_kid.len() == 1)
            .then(|| by_kid.values().next().cloned())
            .flatten();
        Ok(Self {
            by_kid,
            sole,
            issuer: issuer.to_string(),
            audience: audience.map(str::to_string),
        })
    }

    /// The `kid` in `token`'s header (for cache lookup); does **not** verify.
    fn token_kid(token: &str) -> Option<String> {
        decode_header(token).ok()?.kid
    }

    /// Whether this verifier could select a key for a token with `kid` (a keyless token uses
    /// the sole key). Used to decide whether a JWKS refresh is worth attempting.
    fn knows_kid(&self, kid: Option<&str>) -> bool {
        match kid {
            Some(kid) => self.by_kid.contains_key(kid),
            None => self.sole.is_some(),
        }
    }

    /// Verify `token` fully and return its claims as a JSON object, or `None` on any failure
    /// (fail-closed).
    pub(crate) fn verify(&self, token: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
        let header = decode_header(token).ok()?;
        let (key, alg) = match header.kid.as_deref() {
            Some(kid) => self.by_kid.get(kid)?,
            None => self.sole.as_ref()?,
        };
        // Pin to the key's algorithm — never trust the token header's `alg`.
        let mut validation = Validation::new(*alg);
        validation.set_issuer(&[&self.issuer]);
        validation.validate_nbf = true; // exp is validated by default
        match &self.audience {
            Some(aud) => validation.set_audience(&[aud]),
            None => validation.validate_aud = false,
        }
        let data =
            decode::<serde_json::Map<String, serde_json::Value>>(token, key, &validation).ok()?;
        Some(data.claims)
    }
}

/// The JWA algorithm implied by a JWK's key material (not any declared `alg`). `None` for key
/// types we can't verify a public signature with (symmetric keys, P-521).
fn jwk_algorithm(jwk: &Jwk) -> Option<Algorithm> {
    match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Some(Algorithm::RS256),
        AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
            EllipticCurve::P256 => Some(Algorithm::ES256),
            EllipticCurve::P384 => Some(Algorithm::ES384),
            _ => None,
        },
        AlgorithmParameters::OctetKeyPair(okp) => match okp.curve {
            EllipticCurve::Ed25519 => Some(Algorithm::EdDSA),
            _ => None,
        },
        AlgorithmParameters::OctetKey(_) => None,
    }
}

/// Verify `bearer` against the app-token config and return its claims, or `None` if the config
/// can't be satisfied or the token doesn't verify (fail-closed).
pub(crate) async fn verified_claims(
    cfg: &HandlerGraphqlTokenClaims,
    bearer: &str,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    resolve_verifier(cfg, bearer).await?.verify(bearer)
}

/// Resolve the verifier for `cfg`: from the JWKS env var (fresh each call — rotation-safe), or
/// from the JWKS URL (process-cached, re-fetched when the token's `kid` isn't known yet).
async fn resolve_verifier(
    cfg: &HandlerGraphqlTokenClaims,
    bearer: &str,
) -> Option<Arc<TokenVerifier>> {
    let audience = cfg.audience.as_deref();
    if let Some(env_name) = &cfg.jwks_env {
        let jwks = std::env::var(env_name).ok()?;
        return TokenVerifier::from_jwks_json(&jwks, &cfg.issuer, audience)
            .ok()
            .map(Arc::new);
    }
    if let Some(url) = &cfg.jwks_url {
        return resolve_url_verifier(url, &cfg.issuer, audience, bearer).await;
    }
    None
}

/// The process-wide JWKS-URL verifier cache (public keys, keyed by URL).
fn jwks_cache() -> &'static Mutex<HashMap<String, Arc<TokenVerifier>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<TokenVerifier>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

async fn resolve_url_verifier(
    url: &str,
    issuer: &str,
    audience: Option<&str>,
    bearer: &str,
) -> Option<Arc<TokenVerifier>> {
    let token_kid = TokenVerifier::token_kid(bearer);
    // Fast path: a cached verifier that already knows this token's key.
    if let Some(cached) = jwks_cache().lock().ok().and_then(|c| c.get(url).cloned()) {
        if cached.knows_kid(token_kid.as_deref()) {
            return Some(cached);
        }
    }
    // Cold, or the IdP rotated in a new `kid`: re-fetch (operator-configured URL, so not a
    // request-controlled fetch).
    let jwks = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .text()
        .await
        .ok()?;
    let verifier = Arc::new(TokenVerifier::from_jwks_json(&jwks, issuer, audience).ok()?);
    if let Ok(mut cache) = jwks_cache().lock() {
        cache.insert(url.to_string(), verifier.clone());
    }
    Some(verifier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use jsonwebtoken::{encode, EncodingKey, Header};

    const ISS: &str = "https://idp.test";
    fn far_future() -> i64 {
        4_102_444_800 // 2100-01-01
    }

    // ---- HS256 verifier for the validation matrix (issuer/exp/aud/kid/signature) ----

    fn hs256(secret: &[u8], kid: &str, audience: Option<&str>) -> TokenVerifier {
        let mut by_kid = HashMap::new();
        by_kid.insert(
            kid.to_string(),
            (DecodingKey::from_secret(secret), Algorithm::HS256),
        );
        TokenVerifier {
            by_kid,
            sole: None,
            issuer: ISS.to_string(),
            audience: audience.map(str::to_string),
        }
    }

    fn hs256_token(secret: &[u8], kid: &str, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.to_string());
        encode(&header, &claims, &EncodingKey::from_secret(secret)).unwrap()
    }

    #[test]
    fn a_valid_token_yields_its_claims() {
        let v = hs256(b"secret-0123456789", "k1", None);
        let token = hs256_token(
            b"secret-0123456789",
            "k1",
            serde_json::json!({ "iss": ISS, "exp": far_future(), "tid": "acme", "sub": "u42" }),
        );
        let claims = v.verify(&token).expect("verifies");
        assert_eq!(claims["tid"], serde_json::json!("acme"));
        assert_eq!(claims["sub"], serde_json::json!("u42"));
    }

    #[test]
    fn rejections_are_fail_closed() {
        let secret = b"secret-0123456789";
        let v = hs256(secret, "k1", None);
        // Wrong issuer.
        assert!(v
            .verify(&hs256_token(
                secret,
                "k1",
                serde_json::json!({ "iss": "https://evil.test", "exp": far_future() })
            ))
            .is_none());
        // Expired.
        assert!(v
            .verify(&hs256_token(
                secret,
                "k1",
                serde_json::json!({ "iss": ISS, "exp": 1_000_000_000 })
            ))
            .is_none());
        // Unknown kid.
        assert!(v
            .verify(&hs256_token(
                secret,
                "other-kid",
                serde_json::json!({ "iss": ISS, "exp": far_future() })
            ))
            .is_none());
        // Tampered signature.
        let good = hs256_token(
            secret,
            "k1",
            serde_json::json!({ "iss": ISS, "exp": far_future() }),
        );
        assert!(v.verify(&format!("{good}x")).is_none());
        // Wrong signing key.
        assert!(v
            .verify(&hs256_token(
                b"a-different-secret-999",
                "k1",
                serde_json::json!({ "iss": ISS, "exp": far_future() })
            ))
            .is_none());
    }

    #[test]
    fn audience_is_enforced_when_pinned() {
        let secret = b"secret-0123456789";
        let v = hs256(secret, "k1", Some("orders-api"));
        assert!(v
            .verify(&hs256_token(
                secret,
                "k1",
                serde_json::json!({ "iss": ISS, "aud": "other", "exp": far_future() })
            ))
            .is_none());
        assert!(v
            .verify(&hs256_token(
                secret,
                "k1",
                serde_json::json!({ "iss": ISS, "aud": "orders-api", "exp": far_future() })
            ))
            .is_some());
    }

    // ---- the real production path: a JWKS-derived Ed25519 verifier + a signed token ----

    fn b64url(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Sign a JWT with Ed25519 by hand (jsonwebtoken verifies it via the JWKS).
    fn ed25519_token(key: &SigningKey, kid: &str, claims: serde_json::Value) -> String {
        let header = b64url(
            serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid })
                .to_string()
                .as_bytes(),
        );
        let payload = b64url(claims.to_string().as_bytes());
        let signing_input = format!("{header}.{payload}");
        let sig = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64url(&sig.to_bytes()))
    }

    #[test]
    fn a_jwks_ed25519_key_verifies_a_real_token() {
        let key = SigningKey::from_bytes(&[7u8; 32]); // deterministic test key
        let jwks = serde_json::json!({ "keys": [ {
            "kty": "OKP", "crv": "Ed25519", "kid": "app-1",
            "x": b64url(key.verifying_key().as_bytes()),
        } ] })
        .to_string();
        let v = TokenVerifier::from_jwks_json(&jwks, ISS, None).unwrap();

        let token = ed25519_token(
            &key,
            "app-1",
            serde_json::json!({ "iss": ISS, "exp": far_future(), "tid": "acme" }),
        );
        assert_eq!(v.verify(&token).unwrap()["tid"], serde_json::json!("acme"));

        // A token signed by a *different* key with the same kid is rejected.
        let forged = ed25519_token(
            &SigningKey::from_bytes(&[9u8; 32]),
            "app-1",
            serde_json::json!({ "iss": ISS, "exp": far_future(), "tid": "acme" }),
        );
        assert!(v.verify(&forged).is_none());
    }
}
