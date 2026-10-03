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

use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

use boatramp_core::config::{HandlerGraphqlTokenClaims, IssuerTrust, JwksDiscovery};

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
    env_source: &dyn boatramp_core::env::EnvSource,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    resolve_verifier(cfg, bearer, env_source)
        .await?
        .verify(bearer)
}

/// Resolve the verifier for `cfg`: from the JWKS env var (fresh each call — rotation-safe), or
/// from the JWKS URL (process-cached, re-fetched when the token's `kid` isn't known yet). The
/// `jwks_env` name is looked up through an injectable [`EnvSource`](boatramp_core::env::EnvSource)
/// so a test injects the JWKS without mutating the process environment.
async fn resolve_verifier(
    cfg: &HandlerGraphqlTokenClaims,
    bearer: &str,
    env_source: &dyn boatramp_core::env::EnvSource,
) -> Option<Arc<TokenVerifier>> {
    let audience = cfg.audience.as_deref();
    // MULTI-ISSUER TRUST (`issuer_trust` + `jwks`): verify the token's `iss` against the operator
    // policy BEFORE any fetch, then discover the JWKS per verified `iss` (SSRF-guarded, host-pinned).
    // Takes precedence; the single-issuer fields below are the mutually-exclusive legacy form
    // (apply-time enforced), so this branch is reached only when the operator chose the new form.
    if let (Some(trust), Some(jwks)) = (cfg.issuer_trust.as_ref(), cfg.jwks.as_ref()) {
        return resolve_multi_issuer(trust, jwks, audience, bearer).await;
    }
    if let Some(env_name) = &cfg.jwks_env {
        let jwks = env_source.get(env_name)?;
        return TokenVerifier::from_jwks_json(&jwks, &cfg.issuer, audience)
            .ok()
            .map(Arc::new);
    }
    if let Some(url) = &cfg.jwks_url {
        // Single-issuer `jwks_url` is operator-fixed (may legitimately point at an internal IdP), so
        // it keeps its unguarded fetch — `guarded: false`. The SSRF guard applies ONLY to the
        // per-`iss`-derived multi-issuer discovery.
        return resolve_url_verifier(url, &cfg.issuer, audience, bearer, false).await;
    }
    None
}

/// The multi-issuer resolve path: UNVERIFIED `iss` read → policy (fail-closed, no fetch on an
/// untrusted `iss`) → host-pinned JWKS URL → SSRF-guarded fetch → verifier pinned to that same
/// `iss` (so the final signature check binds the token's `iss` to the discovered keys).
async fn resolve_multi_issuer(
    trust: &IssuerTrust,
    jwks: &JwksDiscovery,
    audience: Option<&str>,
    bearer: &str,
) -> Option<Arc<TokenVerifier>> {
    // The payload `iss`, read WITHOUT signature verification — used ONLY to test the policy and
    // derive the fetch URL. The same `iss` is re-pinned into `set_issuer`/`from_jwks_json` below, so
    // a forged `iss` naming a trusted org the attacker doesn't control fetches that org's REAL keys
    // and then fails the signature check.
    let iss = unverified_iss(bearer)?;
    if !issuer_trusted(&iss, trust) {
        tracing::warn!(
            outcome = "iss_not_trusted",
            allow = ?trust.allow,
            suffix = ?trust.suffix,
            "multi-issuer token rejected: iss not in the trust policy (no JWKS fetch attempted)"
        );
        return None;
    }
    let url = derive_jwks_url(&iss, jwks).await?;
    resolve_url_verifier(&url, &iss, audience, bearer, true).await
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
    guarded: bool,
) -> Option<Arc<TokenVerifier>> {
    let token_kid = TokenVerifier::token_kid(bearer);
    // Fast path: a cached verifier that already knows this token's key.
    if let Some(cached) = jwks_cache().lock().ok().and_then(|c| c.get(url).cloned())
        && cached.knows_kid(token_kid.as_deref())
    {
        return Some(cached);
    }
    // Cold, or the IdP rotated in a new `kid`: re-fetch. The single-issuer path uses an operator-
    // fixed URL (unguarded); the multi-issuer path derives the URL from a verified `iss`, so it goes
    // through the SSRF guard (`guarded`).
    let jwks = if guarded {
        match ssrf_guarded_get(url).await {
            Some(body) => body,
            None => {
                tracing::warn!(
                    outcome = "jwks_discovery_failed",
                    url = %url,
                    "multi-issuer JWKS fetch failed or was blocked by the SSRF guard"
                );
                return None;
            }
        }
    } else {
        reqwest::Client::new()
            .get(url)
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .text()
            .await
            .ok()?
    };
    let verifier = match TokenVerifier::from_jwks_json(&jwks, issuer, audience) {
        Ok(v) => Arc::new(v),
        Err(_) => {
            if guarded {
                tracing::warn!(
                    outcome = "jwks_no_usable_key",
                    url = %url,
                    "multi-issuer JWKS held no usable signing key"
                );
            }
            return None;
        }
    };
    if let Ok(mut cache) = jwks_cache().lock() {
        cache.insert(url.to_string(), verifier.clone());
    }
    Some(verifier)
}

/// The active issuer-trust mutation (anti-hollow gate), or `None`. Present ONLY under `cfg(test)`
/// or the `issuer-trust-gate-mutation` feature; a shipped build has neither, so the policy, the
/// anchored-suffix match, the jwks-uri host-pin, and the SSRF guard below are all unconditional and
/// this is a dead `None`. Not a backdoor — it only exposes a test env var.
#[cfg(any(test, feature = "issuer-trust-gate-mutation"))]
fn issuertrust_mutation() -> Option<String> {
    std::env::var("BOATRAMP_ISSUERTRUST_MUTATION").ok()
}
#[cfg(not(any(test, feature = "issuer-trust-gate-mutation")))]
#[inline]
fn issuertrust_mutation() -> Option<String> {
    None
}

/// Read the `iss` from the token payload WITHOUT verifying the signature (base64url-decode the
/// claims segment). Used only to test the trust policy and derive the fetch URL; the signature is
/// still checked afterward with `iss` pinned to this value.
fn unverified_iss(bearer: &str) -> Option<String> {
    let payload = bearer.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("iss")?.as_str().map(str::to_string)
}

/// Parse an issuer URL and return its canonical host, or `None` if it is not a plain `https://`
/// URL with a bare host (reject non-https, any userinfo, and an explicit non-default port). This is
/// the authoritative host extraction the anchored-suffix policy matches on — never a raw-string op.
fn issuer_host(iss: &str) -> Option<String> {
    let u = reqwest::Url::parse(iss).ok()?;
    if u.scheme() != "https" {
        return None;
    }
    if !u.username().is_empty() || u.password().is_some() {
        return None; // reject `user@host` userinfo tricks
    }
    if u.port().is_some() {
        return None; // reject an explicit non-default port
    }
    let host = u.host_str()?;
    Some(host.trim_end_matches('.').to_ascii_lowercase())
}

/// Whether `iss` is trusted by the policy: an exact string in `allow`, OR its parsed host under the
/// anchored `suffix` at a label boundary. Checked BEFORE any network fetch (fail-closed).
fn issuer_trusted(iss: &str, trust: &IssuerTrust) -> bool {
    // MUTATION SEAM (gate `skip_iss_policy`): short-circuit to "trusted" — an `iss` outside the
    // policy then resolves a tenant, turning the gate RED.
    if issuertrust_mutation().as_deref() == Some("skip_iss_policy") {
        return true;
    }
    if trust.allow.iter().any(|a| a == iss) {
        return true;
    }
    if let (Some(sfx), Some(host)) = (trust.suffix.as_deref(), issuer_host(iss)) {
        let bare = sfx
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        // MUTATION SEAM (gate `loosen_suffix_anchor`): a naive substring `ends_with` with NO label
        // boundary — `evil-my.salesforce.com` then passes `.my.salesforce.com`, turning the gate RED.
        let matched = if issuertrust_mutation().as_deref() == Some("loosen_suffix_anchor") {
            host.ends_with(&bare)
        } else {
            boatramp_core::config::host_matches_suffix(&host, &bare)
        };
        if matched {
            return true;
        }
    }
    false
}

/// Derive the JWKS URL for a VERIFIED-trusted `iss`, host-pinned to the `iss` host. `template` is
/// host-pinned by construction (`{iss}/id/keys`); `discover: "oidc"` fetches the issuer's
/// `.well-known/openid-configuration` and pins its `jwks_uri` host to the `iss` host.
async fn derive_jwks_url(iss: &str, jwks: &JwksDiscovery) -> Option<String> {
    if let Some(template) = &jwks.template {
        return Some(template.replace("{iss}", iss.trim_end_matches('/')));
    }
    // OIDC discovery (`discover: "oidc"`).
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        iss.trim_end_matches('/')
    );
    let Some(doc) = ssrf_guarded_get(&discovery_url).await else {
        tracing::warn!(
            outcome = "jwks_discovery_failed",
            url = %discovery_url,
            "OIDC discovery fetch failed or was blocked by the SSRF guard"
        );
        return None;
    };
    let parsed: serde_json::Value = serde_json::from_str(&doc).ok()?;
    let jwks_uri = parsed.get("jwks_uri")?.as_str()?.to_string();
    if !jwks_uri_host_pinned(&jwks_uri, iss) {
        tracing::warn!(
            outcome = "jwks_discovery_failed",
            iss_host = ?issuer_host(iss),
            jwks_uri = %jwks_uri,
            "OIDC jwks_uri host is not pinned to the iss host — refusing the off-issuer fetch"
        );
        return None;
    }
    Some(jwks_uri)
}

/// Whether a discovery doc's `jwks_uri` host is pinned to the verified `iss` host (a trusted-but-
/// malicious org controls its own discovery doc, so the advertised `jwks_uri` must not point off the
/// issuer). Both are parsed with [`issuer_host`], so non-https / userinfo / off-host all fail-closed.
fn jwks_uri_host_pinned(jwks_uri: &str, iss: &str) -> bool {
    // MUTATION SEAM (gate `skip_jwks_host_pin`): drop the pin — an off-issuer `jwks_uri` then passes,
    // turning the gate RED.
    if issuertrust_mutation().as_deref() == Some("skip_jwks_host_pin") {
        return true;
    }
    match (issuer_host(jwks_uri), issuer_host(iss)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// The SSRF guard DECISION (no fetch): parse the URL, require `https`, reject userinfo, resolve
/// every address and require it globally routable ([`is_global_ip`](boatramp_core::access::is_global_ip)),
/// and return one resolved address to PIN (so a DNS rebind can't swap in a private target between
/// resolve and connect). `None` ⇒ refused. Split out from the fetch so it is deterministically
/// testable (an IP-literal URL needs no network). Mirrors [`crate::proxy`]'s target guard.
async fn ssrf_resolve_pin(url: &str) -> Option<(String, SocketAddr)> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let skip = issuertrust_mutation().as_deref() == Some("skip_ssrf_guard");
    let mut pinned: Option<SocketAddr> = None;
    for addr in tokio::net::lookup_host((host.as_str(), port)).await.ok()? {
        // MUTATION SEAM (gate `skip_ssrf_guard`): drop the public-IP requirement — a URL resolving
        // to a private/loopback address then pins (would be fetched), turning the gate RED.
        if !skip && !boatramp_core::access::is_global_ip(addr.ip()) {
            return None;
        }
        pinned.get_or_insert(addr);
    }
    pinned.map(|addr| (host, addr))
}

/// An HTTPS GET fenced by [`ssrf_resolve_pin`]: the resolved public address is pinned on the client,
/// and `https_only` is enforced. Returns the body, or `None` if blocked/failed.
async fn ssrf_guarded_get(url: &str) -> Option<String> {
    let (host, addr) = ssrf_resolve_pin(url).await?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .resolve(&host, addr)
        .build()
        .ok()?;
    client
        .get(url)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .text()
        .await
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use jsonwebtoken::{EncodingKey, Header, encode};

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
        assert!(
            v.verify(&hs256_token(
                secret,
                "k1",
                serde_json::json!({ "iss": "https://evil.test", "exp": far_future() })
            ))
            .is_none()
        );
        // Expired.
        assert!(
            v.verify(&hs256_token(
                secret,
                "k1",
                serde_json::json!({ "iss": ISS, "exp": 1_000_000_000 })
            ))
            .is_none()
        );
        // Unknown kid.
        assert!(
            v.verify(&hs256_token(
                secret,
                "other-kid",
                serde_json::json!({ "iss": ISS, "exp": far_future() })
            ))
            .is_none()
        );
        // Tampered signature.
        let good = hs256_token(
            secret,
            "k1",
            serde_json::json!({ "iss": ISS, "exp": far_future() }),
        );
        assert!(v.verify(&format!("{good}x")).is_none());
        // Wrong signing key.
        assert!(
            v.verify(&hs256_token(
                b"a-different-secret-999",
                "k1",
                serde_json::json!({ "iss": ISS, "exp": far_future() })
            ))
            .is_none()
        );
    }

    #[test]
    fn audience_is_enforced_when_pinned() {
        let secret = b"secret-0123456789";
        let v = hs256(secret, "k1", Some("orders-api"));
        assert!(
            v.verify(&hs256_token(
                secret,
                "k1",
                serde_json::json!({ "iss": ISS, "aud": "other", "exp": far_future() })
            ))
            .is_none()
        );
        assert!(
            v.verify(&hs256_token(
                secret,
                "k1",
                serde_json::json!({ "iss": ISS, "aud": "orders-api", "exp": far_future() })
            ))
            .is_some()
        );
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

    // ---- Multi-issuer trust: the anti-hollow gate (mutation-verified) ----

    fn trust() -> IssuerTrust {
        IssuerTrust {
            allow: vec!["https://acme.my.salesforce.com".to_string()],
            suffix: Some(".my.salesforce.com".to_string()),
        }
    }

    /// GATE (multi-issuer trust) — the four load-bearing invariants of the trust/discovery path,
    /// asserted as SECURE in the clean run. Each `BOATRAMP_ISSUERTRUST_MUTATION` (armed by the CI
    /// loop with `--features issuer-trust-gate-mutation`) disables ONE invariant and MUST turn this
    /// RED: `skip_iss_policy` (an untrusted iss becomes trusted), `loosen_suffix_anchor`
    /// (`evil-my.salesforce.com` passes the suffix), `skip_jwks_host_pin` (an off-issuer jwks_uri
    /// passes the pin), `skip_ssrf_guard` (a loopback target resolves/pins). Marker
    /// `MULTI-ISSUER TRUST OK`. The test never sets the env itself (the loop does), so it is race-free.
    #[tokio::test]
    async fn issuer_trust_policy_discovery_and_ssrf_gates() {
        let t = trust();

        // (1) iss policy: allow (exact) ∪ suffix (label boundary) — and NOTHING else.
        assert!(
            issuer_trusted("https://acme.my.salesforce.com", &t),
            "an exact `allow` issuer is trusted"
        );
        assert!(
            issuer_trusted("https://foo.my.salesforce.com", &t),
            "a sub-label under the anchored suffix is trusted"
        );
        assert!(
            !issuer_trusted("https://evil.com", &t),
            "an issuer outside allow and the suffix is NOT trusted (skip_iss_policy → RED)"
        );
        // (2) the anchored suffix refutes the classic bypasses.
        for bad in [
            "https://evil-my.salesforce.com", // no label boundary (loosen_suffix_anchor → RED)
            "https://a.my.salesforce.com@evil.com", // userinfo trick → host is evil.com
            "https://evil.com/.my.salesforce.com", // suffix in the path → host is evil.com
            "http://foo.my.salesforce.com",   // non-https
            "https://foo.my.salesforce.com:8443", // explicit non-default port
            "https://foo.evil.com",           // unrelated host
        ] {
            assert!(!issuer_trusted(bad, &t), "bypass must be refused: {bad}");
        }

        // (3) jwks_uri host-pin: same host as iss passes, off-host fails.
        assert!(
            jwks_uri_host_pinned(
                "https://acme.my.salesforce.com/id/keys",
                "https://acme.my.salesforce.com"
            ),
            "an on-issuer jwks_uri is pinned"
        );
        assert!(
            !jwks_uri_host_pinned("https://evil.com/keys", "https://acme.my.salesforce.com"),
            "an off-issuer jwks_uri is refused (skip_jwks_host_pin → RED)"
        );

        // (4) SSRF guard decision (no network — IP-literal/loopback resolve locally): a private or
        // loopback or non-https or userinfo target is refused; a public IP-literal pins.
        assert!(
            ssrf_resolve_pin("https://127.0.0.1/x").await.is_none(),
            "a loopback target is refused (skip_ssrf_guard → RED)"
        );
        assert!(
            ssrf_resolve_pin("https://10.0.0.1/x").await.is_none(),
            "a private target is refused"
        );
        assert!(
            ssrf_resolve_pin("http://1.1.1.1/x").await.is_none(),
            "a non-https target is refused"
        );
        assert!(
            ssrf_resolve_pin("https://1.1.1.1/x").await.is_some(),
            "a public target resolves + pins"
        );

        println!("MULTI-ISSUER TRUST OK");
    }

    /// The unverified-`iss` read (payload only), used to gate the policy before signature.
    #[test]
    fn unverified_iss_reads_the_payload_issuer() {
        // iss=https://acme.my.salesforce.com, unsigned (alg=none-style) — we only read the payload.
        let token = hs256_token(
            b"irrelevant-secret-not-checked-here",
            "k1",
            serde_json::json!({ "iss": "https://acme.my.salesforce.com", "sub": "x" }),
        );
        assert_eq!(
            unverified_iss(&token).as_deref(),
            Some("https://acme.my.salesforce.com")
        );
        assert_eq!(unverified_iss("not-a-jwt").as_deref(), None);
    }
}
