//! OIDC sign-in — the OAuth2 **Authorization Code + PKCE** flow.
//!
//! Pure client-side, no server change: the console redirects the browser to the
//! IdP's authorization endpoint, handles the `?code=&state=` callback, exchanges
//! the code for a JWT at the token endpoint, then hands the JWT to the existing
//! [`crate::auth::Session`] as a Bearer (the API's `oidc` feature validates it —
//! it must be a **JWT access token carrying the `scope` claim** boatramp checks).
//!
//! The console's `client_id` is its *own* registration with the IdP (distinct
//! from the API's audience), so it is operator-supplied along with the issuer
//! URL. Issuer + client_id + scope are persisted in `localStorage` (not secret)
//! for convenience; the per-flow PKCE secrets live in `sessionStorage` and are
//! cleared the moment the callback completes.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use gloo_net::http::{Method, RequestBuilder};
use gloo_storage::{LocalStorage, SessionStorage, Storage};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// `localStorage` keys for the (non-secret) operator-entered IdP config, so the
/// login form pre-fills on the next visit.
const ISSUER_KEY: &str = "boatramp.console.oidc.issuer";
const CLIENT_ID_KEY: &str = "boatramp.console.oidc.client_id";
const SCOPE_KEY: &str = "boatramp.console.oidc.scope";

/// `sessionStorage` keys for the per-flow PKCE state, carried across the IdP
/// redirect and cleared once the callback completes (or fails).
const PKCE_VERIFIER_KEY: &str = "boatramp.console.oidc.pkce.verifier";
const PKCE_STATE_KEY: &str = "boatramp.console.oidc.pkce.state";
const PKCE_TOKEN_ENDPOINT_KEY: &str = "boatramp.console.oidc.pkce.token_endpoint";
const PKCE_CLIENT_ID_KEY: &str = "boatramp.console.oidc.pkce.client_id";
const PKCE_REDIRECT_URI_KEY: &str = "boatramp.console.oidc.pkce.redirect_uri";

/// The default OIDC scope when the operator leaves the field blank.
pub const DEFAULT_SCOPE: &str = "openid";

/// The operator-entered IdP config, persisted in `localStorage` for pre-fill.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OidcConfig {
    /// The IdP issuer URL (the base for `/.well-known/openid-configuration`).
    pub issuer: String,
    /// The console's own client registration with the IdP.
    pub client_id: String,
    /// The requested scope (defaults to [`DEFAULT_SCOPE`] when blank).
    pub scope: String,
}

impl OidcConfig {
    /// Load the persisted config from `localStorage` (all fields default to
    /// empty when absent), so the login form can pre-fill.
    pub fn load() -> Self {
        Self {
            issuer: LocalStorage::get(ISSUER_KEY).unwrap_or_default(),
            client_id: LocalStorage::get(CLIENT_ID_KEY).unwrap_or_default(),
            scope: LocalStorage::get(SCOPE_KEY).unwrap_or_default(),
        }
    }

    /// Persist the (non-secret) config to `localStorage` for next-visit
    /// pre-fill; failures (private mode) are non-fatal.
    fn persist(&self) {
        let _ = LocalStorage::set(ISSUER_KEY, &self.issuer);
        let _ = LocalStorage::set(CLIENT_ID_KEY, &self.client_id);
        let _ = LocalStorage::set(SCOPE_KEY, &self.scope);
    }
}

/// A relevant slice of the IdP's `/.well-known/openid-configuration` document.
#[derive(Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
}

/// The IdP's token-endpoint response; we only need the access token (a JWT the
/// boatramp control plane exchanges for a token).
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// boatramp's `/api/auth/exchange` response — the minted token.
#[derive(Deserialize)]
struct TokenExchange {
    token: String,
}

/// Exchange a validated OIDC JWT for a boatramp **token** at the control
/// plane's `POST /api/auth/exchange`: the edge only authorizes
/// tokens, so the console trades the IdP JWT for one and uses *that* as the
/// API bearer. `api_base` is empty for the same-origin dogfood deploy. The
/// token's roles come from the IdP's configured claim.
pub async fn exchange_for_token(api_base: &str, jwt: &str) -> Result<String, String> {
    let url = format!("{}/api/auth/exchange", api_base.trim_end_matches('/'));
    let resp = RequestBuilder::new(&url)
        .method(Method::POST)
        .header("Authorization", &format!("Bearer {jwt}"))
        .send()
        .await
        .map_err(|err| format!("token exchange request failed: {err}"))?;
    if !(200..300).contains(&resp.status()) {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "token exchange failed: HTTP {} {}",
            resp.status(),
            body.trim()
        ));
    }
    let parsed: TokenExchange = resp
        .json()
        .await
        .map_err(|err| format!("token exchange parse failed: {err}"))?;
    Ok(parsed.token)
}

/// `redirect_uri` = `window.location.origin + window.location.pathname` (no
/// query/hash), so the callback lands back on the SPA exactly where it started.
fn redirect_uri() -> Result<String, String> {
    let location = web_sys::window()
        .ok_or_else(|| "no window".to_string())?
        .location();
    let origin = location.origin().map_err(|_| "no origin".to_string())?;
    let pathname = location.pathname().map_err(|_| "no pathname".to_string())?;
    Ok(format!("{origin}{pathname}"))
}

/// `n` cryptographically-random bytes, base64url-encoded without padding (the
/// `getrandom` `js` feature routes to the browser's `crypto.getRandomValues`).
fn random_b64url(n: usize) -> Result<String, String> {
    let mut bytes = vec![0u8; n];
    getrandom::getrandom(&mut bytes).map_err(|err| format!("random: {err}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// The PKCE `code_challenge` for a `code_verifier`: base64url(SHA-256(verifier)).
fn code_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Percent-encode a query-parameter value (RFC 3986 unreserved set kept raw;
/// everything else percent-escaped). Avoids a `url`/`urlencoding` dep for the
/// handful of values we put in the authorization-endpoint query string.
fn encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Whether the current URL is an OIDC callback (`?code=&state=` present).
pub fn is_callback() -> bool {
    callback_params().is_some()
}

/// The `(code, state)` pair from the current URL's query string, if both are
/// present. Parsed from `window.location.search` so we don't depend on a router.
fn callback_params() -> Option<(String, String)> {
    let search = web_sys::window()?.location().search().ok()?;
    let query = search.strip_prefix('?').unwrap_or(&search);
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        let (key, raw) = pair.split_once('=')?;
        let value = decode_query(raw);
        match key {
            "code" => code = Some(value),
            "state" => state = Some(value),
            _ => {}
        }
    }
    Some((code?, state?))
}

/// Percent-decode a query-parameter value (`+` → space, `%XX` → byte). Lossy on
/// malformed input — fine for the authorization-code callback we parse.
fn decode_query(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Begin the PKCE flow: persist the (non-secret) config, fetch the issuer's
/// discovery document for the endpoints, mint the verifier/challenge/state,
/// stash the per-flow PKCE state in `sessionStorage`, then navigate the browser
/// to the authorization endpoint. Returns `Err` with a user-facing message on
/// any failure *before* the redirect (after the redirect the page is gone).
pub async fn start_login(config: OidcConfig) -> Result<(), String> {
    let issuer = config.issuer.trim().trim_end_matches('/').to_string();
    let client_id = config.client_id.trim().to_string();
    if issuer.is_empty() {
        return Err("Enter the issuer URL.".into());
    }
    if client_id.is_empty() {
        return Err("Enter the client_id.".into());
    }
    let scope = {
        let s = config.scope.trim();
        if s.is_empty() {
            DEFAULT_SCOPE.to_string()
        } else {
            s.to_string()
        }
    };

    // Persist for next-visit pre-fill (issuer/client_id/scope are not secret).
    OidcConfig {
        issuer: issuer.clone(),
        client_id: client_id.clone(),
        scope: scope.clone(),
    }
    .persist();

    // 1. Discover the authorization + token endpoints.
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    let resp = RequestBuilder::new(&discovery_url)
        .send()
        .await
        .map_err(|err| format!("discovery request failed: {err}"))?;
    if !(200..300).contains(&resp.status()) {
        return Err(format!(
            "discovery failed: HTTP {} at {discovery_url}",
            resp.status()
        ));
    }
    let discovery: Discovery = resp
        .json()
        .await
        .map_err(|err| format!("discovery parse failed: {err}"))?;

    // 2. Mint PKCE verifier/challenge + an anti-CSRF state.
    let verifier = random_b64url(32)?;
    let challenge = code_challenge(&verifier);
    let state = random_b64url(16)?;
    let redirect_uri = redirect_uri()?;

    // 3. Stash the per-flow PKCE state for the callback. Persisting these is what
    //    lets the redirect round-trip; a failure here is fatal (the callback
    //    could not validate `state` or exchange the code).
    SessionStorage::set(PKCE_VERIFIER_KEY, &verifier).map_err(|err| err.to_string())?;
    SessionStorage::set(PKCE_STATE_KEY, &state).map_err(|err| err.to_string())?;
    SessionStorage::set(PKCE_TOKEN_ENDPOINT_KEY, &discovery.token_endpoint)
        .map_err(|err| err.to_string())?;
    SessionStorage::set(PKCE_CLIENT_ID_KEY, &client_id).map_err(|err| err.to_string())?;
    SessionStorage::set(PKCE_REDIRECT_URI_KEY, &redirect_uri).map_err(|err| err.to_string())?;

    // 4. Redirect to the authorization endpoint.
    let authorize_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}\
         &code_challenge={}&code_challenge_method=S256",
        discovery.authorization_endpoint,
        encode_query(&client_id),
        encode_query(&redirect_uri),
        encode_query(&scope),
        encode_query(&state),
        encode_query(&challenge),
    );
    web_sys::window()
        .ok_or_else(|| "no window".to_string())?
        .location()
        .set_href(&authorize_url)
        .map_err(|_| "redirect failed".to_string())?;
    Ok(())
}

/// Complete the PKCE flow from the `?code=&state=` callback: validate `state`
/// against `sessionStorage`, exchange the code at the token endpoint, and return
/// the `access_token` (a JWT) for [`crate::auth::Session::sign_in`]. Always
/// clears the per-flow PKCE state and strips the query from the URL — on success
/// *and* on failure — so a reload never re-runs a spent or broken exchange.
pub async fn complete_callback() -> Result<String, String> {
    let result = exchange().await;
    // Strip the query + clear the PKCE secrets regardless of outcome.
    clear_pkce();
    strip_query();
    result
}

/// The token exchange proper (kept separate so [`complete_callback`] can clean
/// up unconditionally around it).
async fn exchange() -> Result<String, String> {
    let (code, state) = callback_params().ok_or_else(|| "no callback parameters".to_string())?;

    let expected_state: String =
        SessionStorage::get(PKCE_STATE_KEY).map_err(|_| "missing PKCE state — restart sign-in")?;
    if state != expected_state {
        return Err("state mismatch — possible CSRF; sign in again".into());
    }

    let verifier: String = SessionStorage::get(PKCE_VERIFIER_KEY)
        .map_err(|_| "missing PKCE verifier — restart sign-in")?;
    let token_endpoint: String = SessionStorage::get(PKCE_TOKEN_ENDPOINT_KEY)
        .map_err(|_| "missing token endpoint — restart sign-in")?;
    let client_id: String = SessionStorage::get(PKCE_CLIENT_ID_KEY)
        .map_err(|_| "missing client_id — restart sign-in")?;
    let redirect_uri: String = SessionStorage::get(PKCE_REDIRECT_URI_KEY)
        .map_err(|_| "missing redirect_uri — restart sign-in")?;

    // POST the code exchange as application/x-www-form-urlencoded.
    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        encode_query(&code),
        encode_query(&redirect_uri),
        encode_query(&client_id),
        encode_query(&verifier),
    );
    let resp = RequestBuilder::new(&token_endpoint)
        .method(Method::POST)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form)
        .map_err(|err| format!("token request build failed: {err}"))?
        .send()
        .await
        .map_err(|err| format!("token request failed: {err}"))?;
    if !(200..300).contains(&resp.status()) {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "token exchange failed: HTTP {} {}",
            resp.status(),
            body.trim()
        ));
    }
    let token: TokenResponse = resp
        .json()
        .await
        .map_err(|err| format!("token response parse failed: {err}"))?;
    Ok(token.access_token)
}

/// Clear the per-flow PKCE `sessionStorage` keys.
fn clear_pkce() {
    SessionStorage::delete(PKCE_VERIFIER_KEY);
    SessionStorage::delete(PKCE_STATE_KEY);
    SessionStorage::delete(PKCE_TOKEN_ENDPOINT_KEY);
    SessionStorage::delete(PKCE_CLIENT_ID_KEY);
    SessionStorage::delete(PKCE_REDIRECT_URI_KEY);
}

/// `history.replaceState` the query (`?code=&state=`) off the URL so a reload
/// doesn't re-trigger the (now-spent) callback. Best-effort.
fn strip_query() {
    if let Some(window) = web_sys::window() {
        if let Ok(history) = window.history() {
            if let Ok(clean) = redirect_uri() {
                let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&clean));
            }
        }
    }
}
