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
        return resolve_url_verifier(url, &cfg.issuer, audience, false).await;
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
    resolve_url_verifier(&url, &iss, audience, true).await
}

/// One tier's JWKS freshness policy. `refresh` = the soft age at which a NON-BLOCKING background
/// refresh is kicked off while the current keys keep serving (stale-while-revalidate); `hard_ttl` =
/// the age past which the keys are no longer served and a request must BLOCK on a successful refresh
/// (else fail closed). `refresh < hard_ttl`; the gap is the grace window the background refresh
/// completes in, so in steady state NO request blocks on a JWKS fetch (except the one cold fetch per
/// key). The ~1 s-per-request gateway overhead is gone: a flood of tokens with an unknown / rotated-out
/// / keyless `kid` is served from the cached verifier (and fails verification) with no network hop.
#[derive(Clone, Copy, Debug)]
pub struct JwksTier {
    pub refresh: std::time::Duration,
    pub hard_ttl: std::time::Duration,
}

/// The node-wide JWKS freshness configuration, in TWO tiers selected by trust:
/// - `own` — first-party, operator-fixed `jwks_url`/`jwks_env` (the `guarded == false` path).
/// - `foreign` — user-declared multi-issuer discovery (the `guarded == true`, SSRF-guarded path);
///   less trusted, so the operator typically sets a tighter `hard_ttl` (faster revocation of a
///   potentially-compromised user-declared issuer's key).
///
/// `prewarm` fetches the configured first-party `jwks_url`s at startup so even the first request is
/// instant; foreign issuers can't be pre-warmed (they aren't known until a token arrives).
#[derive(Clone, Copy, Debug)]
pub struct JwksConfig {
    pub own: JwksTier,
    pub foreign: JwksTier,
    pub prewarm: bool,
}

impl Default for JwksConfig {
    /// Defaults: own = refresh 120 s / hard_ttl 600 s (keeps the reviewed 600 s revocation bound);
    /// foreign = refresh 60 s / hard_ttl 300 s (tighter — faster revocation); pre-warm on.
    fn default() -> Self {
        Self {
            own: JwksTier {
                refresh: std::time::Duration::from_secs(120),
                hard_ttl: std::time::Duration::from_secs(600),
            },
            foreign: JwksTier {
                refresh: std::time::Duration::from_secs(60),
                hard_ttl: std::time::Duration::from_secs(300),
            },
            prewarm: true,
        }
    }
}

/// The installed node-wide JWKS config (process-global, set once at startup; [`JwksConfig::default`]
/// until then — so tests and a pre-startup access get the safe defaults).
static JWKS_CONFIG: OnceLock<JwksConfig> = OnceLock::new();

fn jwks_config() -> &'static JwksConfig {
    JWKS_CONFIG.get_or_init(JwksConfig::default)
}

/// Install the node's JWKS freshness configuration (from `[handlers]`), once at startup. Idempotent —
/// the first set wins; a later call (or a call after the first read) is ignored, so the policy can't
/// flip mid-flight.
pub fn set_jwks_config(cfg: JwksConfig) {
    if JWKS_CONFIG.set(cfg).is_err() {
        tracing::warn!(
            "set_jwks_config called after the JWKS config was already initialised — the new config is \
             ignored (an init-ordering bug; the defaults or first-set config remain in effect)"
        );
    }
}

/// A shared, connection-pooled client for the unguarded (operator-fixed-URL) JWKS fetch, so each
/// refresh reuses a pooled TLS connection instead of a fresh `Client::new()` DNS+TCP+TLS handshake.
/// Carries fail-fast connect+request timeouts so a HUNG IdP's refresh fails fast (the background
/// refresh gives up and the current keys keep serving until `hard_ttl`) rather than pinning a worker.
/// (The guarded multi-issuer path builds its own SSRF-guarded client in `ssrf_guarded_get`.)
fn jwks_http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Read a cache entry (verifier + its fetch time) for `key`, or `None`. A poisoned lock reads as a
/// miss (fail toward a fetch, never a panic).
fn cache_get(key: &JwksKey) -> Option<CachedVerifier> {
    jwks_cache().lock().ok().and_then(|c| c.get(key).cloned())
}

/// Store a freshly-fetched verifier under `key`, stamped `now`, applying the entry cap. A poisoned
/// lock drops the store (the next request simply re-fetches).
fn cache_store(key: JwksKey, verifier: Arc<TokenVerifier>) {
    if let Ok(mut cache) = jwks_cache().lock() {
        insert_capped(
            &mut cache,
            key,
            (verifier, std::time::Instant::now()),
            JWKS_CACHE_MAX_ENTRIES,
        );
    }
}

/// Per-(url, issuer, audience) coordination for the single-flight refresh:
/// - `lock`: at most one in-flight JWKS fetch per key (async mutex — a background refresh `try_lock`s
///   and skips if busy; a cold / past-`hard_ttl` request `lock().await`s, then re-reads the cache so it
///   RIDES the in-flight fetch instead of starting a duplicate).
/// - `last_failure`: the instant a BLOCKING fetch last failed, for a short negative-cache
///   ([`JWKS_FETCH_FAILURE_COOLDOWN`]) so a burst of past-`hard_ttl` requests during an IdP outage
///   fail-closed FAST rather than each serializing on the lock and paying its own fetch-timeout.
#[derive(Default)]
struct KeyState {
    lock: tokio::sync::Mutex<()>,
    last_failure: Mutex<Option<std::time::Instant>>,
}

/// A short window during which, after a blocking JWKS fetch for a key FAILED, further blocking requests
/// for that key fail closed immediately instead of re-fetching — collapses an outage pile-up to one
/// fetch per window while keeping fail-closed semantics. Deliberately short so recovery is prompt.
const JWKS_FETCH_FAILURE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(2);

/// Hard ceiling on the per-key [`KeyState`] map, mirroring the cache cap so the single-flight
/// bookkeeping can't become an unbounded-growth vector (closes the twin of the gap the cache cap closed).
const JWKS_KEY_STATE_MAX: usize = 256;

/// Get-or-create the [`KeyState`] for `key`. Caps the map at [`JWKS_KEY_STATE_MAX`]: when full, idle
/// states (held ONLY by the map — `strong_count == 1`) are GC'd before admitting a new key. Clones are
/// handed out only under this same std lock, so a `strong_count == 1` entry is provably not in use by
/// any in-flight fetch and is safe to drop (single-flight is per-moment; the next refresh re-creates
/// it). Graceful on poison (the critical section is panic-free) — never propagates a panic to a request.
fn key_state(key: &JwksKey) -> Arc<KeyState> {
    static STATES: OnceLock<Mutex<HashMap<JwksKey, Arc<KeyState>>>> = OnceLock::new();
    let states = STATES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = states
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.len() >= JWKS_KEY_STATE_MAX && !guard.contains_key(key) {
        guard.retain(|_, st| Arc::strong_count(st) > 1);
    }
    guard.entry(key.clone()).or_default().clone()
}

/// An absolute ceiling on a single JWKS fetch+build, independent of the HTTP client's own timeouts.
/// A caller may hold the per-key single-flight lock across this, so bounding it here guarantees the
/// lock is released within a bounded duration even if a client's own timeout is somehow not honored —
/// the defense that prevents a stalled (foreign) IdP from permanently wedging an issuer's verification.
/// Set slightly above the clients' 5 s request timeout so the client's finer-grained timeout normally
/// fires first and this is the backstop.
const JWKS_FETCH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(8);

/// Fetch the JWKS and build a verifier, or `None` on ANY failure — NO stale fallback here (the callers
/// are either cold or past `hard_ttl`, both of which must fail closed). Bounded by [`JWKS_FETCH_DEADLINE`]
/// so the single-flight lock a caller holds across it is always released. The guarded (multi-issuer)
/// branch keeps its OWN SSRF-guarded, no-redirect, https-only, resolve-pinned, now-timed-out client
/// ([`ssrf_guarded_get`]); the unguarded (operator-fixed single-issuer) branch uses the shared pooled
/// [`jwks_http_client`]. Preserves the existing `jwks_discovery_failed` / `jwks_no_usable_key` traces.
async fn fetch_and_build(
    url: &str,
    issuer: &str,
    audience: Option<&str>,
    guarded: bool,
) -> Option<Arc<TokenVerifier>> {
    match tokio::time::timeout(
        JWKS_FETCH_DEADLINE,
        fetch_and_build_inner(url, issuer, audience, guarded),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!(
                outcome = "jwks_fetch_timed_out",
                url = %url,
                "JWKS fetch exceeded the deadline; failing closed (single-flight lock released)"
            );
            None
        }
    }
}

async fn fetch_and_build_inner(
    url: &str,
    issuer: &str,
    audience: Option<&str>,
    guarded: bool,
) -> Option<Arc<TokenVerifier>> {
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
        match jwks_http_client()
            .get(url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
        {
            Ok(resp) => match resp.text().await {
                Ok(body) => body,
                Err(_) => return None,
            },
            Err(_) => return None,
        }
    };
    match TokenVerifier::from_jwks_json(&jwks, issuer, audience) {
        Ok(v) => Some(Arc::new(v)),
        Err(_) => {
            if guarded {
                tracing::warn!(
                    outcome = "jwks_no_usable_key",
                    url = %url,
                    "multi-issuer JWKS held no usable signing key"
                );
            }
            None
        }
    }
}

/// The single-flight BLOCKING refresh (cold cache, or past `hard_ttl`): wait for any in-flight refresh
/// on this key, then DOUBLE-CHECK the cache (the refresh we waited on may have just filled a FRESH
/// entry — serve it, no second fetch), else fetch ourselves. `None` on failure → the caller fails
/// closed, so a verifier older than `hard_ttl` is NEVER served without a successful fresh fetch.
async fn refresh_under_lock(
    key: JwksKey,
    url: &str,
    issuer: &str,
    audience: Option<&str>,
    guarded: bool,
    refresh: std::time::Duration,
) -> Option<Arc<TokenVerifier>> {
    let st = key_state(&key);
    // Negative-cache: a recent blocking-fetch failure for this key ⇒ fail closed FAST (don't queue on
    // the lock and pay another fetch-timeout). A short, read-only std-lock check — no await held across.
    let failed_recently = || {
        st.last_failure
            .lock()
            .ok()
            .and_then(|f| *f)
            .is_some_and(|at| at.elapsed() < JWKS_FETCH_FAILURE_COOLDOWN)
    };
    if failed_recently() {
        return None;
    }
    let _g = st.lock.lock().await;
    // Double-check: a concurrent success we queued behind may have filled a FRESH entry — serve it.
    if let Some((verifier, fetched_at)) = cache_get(&key)
        && std::time::Instant::now().saturating_duration_since(fetched_at) < refresh
    {
        return Some(verifier); // a refresh we queued behind just filled a fresh entry
    }
    // Re-check after acquiring the lock: the holder just ahead of us may have just failed.
    if failed_recently() {
        return None;
    }
    match fetch_and_build(url, issuer, audience, guarded).await {
        Some(verifier) => {
            cache_store(key, verifier.clone());
            if let Ok(mut f) = st.last_failure.lock() {
                *f = None; // a success clears the failure mark
            }
            Some(verifier)
        }
        None => {
            if let Ok(mut f) = st.last_failure.lock() {
                *f = Some(std::time::Instant::now());
            }
            None
        }
    }
}

/// Kick off a NON-BLOCKING single-flight refresh for a stale-but-serviceable key (within `hard_ttl`,
/// past `refresh`). Best-effort: if a refresh is already in flight (`try_lock` fails) it skips; on
/// fetch failure it leaves the current entry (served again until `hard_ttl`, then a request blocks).
/// Never blocks the request, never panics — this is what makes steady-state the ZERO-hiccup path.
fn spawn_background_refresh(
    key: JwksKey,
    url: String,
    issuer: String,
    audience: Option<String>,
    guarded: bool,
) {
    // Only spawn when there's a runtime to spawn onto — always true on the async request path; this
    // guard just avoids a panic if ever reached outside a tokio context (e.g. a non-async unit test).
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    tokio::spawn(async move {
        let st = key_state(&key);
        let Ok(_g) = st.lock.try_lock() else {
            return; // a refresh is already in flight — single-flight dedup
        };
        match fetch_and_build(&url, &issuer, audience.as_deref(), guarded).await {
            Some(verifier) => {
                cache_store(key, verifier);
                if let Ok(mut f) = st.last_failure.lock() {
                    *f = None; // a success clears any prior failure mark
                }
            }
            // WARN (not debug): a prolonged silent background-refresh failure immediately precedes a
            // hard_ttl fail-closed outage, so operators should see it coming.
            None => tracing::warn!(
                outcome = "jwks_background_refresh_failed",
                url = %url,
                "JWKS background refresh failed; serving the current verifier until hard_ttl, then requests block"
            ),
        }
    });
}

/// Pre-warm the cache for the configured first-party (`own`-tier) JWKS URLs at startup, so even the
/// first request is instant. No-op when `prewarm` is disabled. Best-effort: a failed fetch is logged
/// and skipped (the URL stays cold and its first request pays the fetch — today's behavior). Foreign
/// (multi-issuer) issuers can't be pre-warmed: they aren't known until a token arrives.
pub async fn prewarm_own_jwks(entries: &[(String, String, Option<String>)]) {
    if !jwks_config().prewarm {
        return;
    }
    for (url, issuer, audience) in entries {
        match fetch_and_build(url, issuer, audience.as_deref(), false).await {
            Some(verifier) => {
                cache_store((url.clone(), issuer.clone(), audience.clone()), verifier);
            }
            None => tracing::warn!(
                outcome = "jwks_prewarm_failed",
                url = %url,
                "JWKS pre-warm fetch failed; the first request will fetch"
            ),
        }
    }
}

/// The JWKS cache key: the fetch URL PLUS the issuer and audience the verifier is pinned to. A single
/// `jwks_url` can legitimately be shared by two routes/projects that pin DIFFERENT `issuer`/`audience`
/// (the [`TokenVerifier`] bakes both in), so keying by URL ALONE would serve route A's
/// issuer/audience-pinned verifier to route B — a cross-issuer / cross-audience confusion (route B's
/// token checked against route A's expected `iss`/`aud`). Keying by the full tuple gives each distinct
/// (url, issuer, audience) its own cache entry.
type JwksKey = (String, String, Option<String>);

/// A cached verifier plus the [`Instant`](std::time::Instant) it was last successfully fetched — the
/// basis for both the TTL (refresh-after) and the max-stale (serve-stale cap) decisions.
type CachedVerifier = (Arc<TokenVerifier>, std::time::Instant);

/// The process-wide JWKS verifier cache: the verifier plus its fetch time (for the TTL), keyed by
/// [`JwksKey`] (url + issuer + audience — never url alone; see that type's note).
fn jwks_cache() -> &'static Mutex<HashMap<JwksKey, CachedVerifier>> {
    static CACHE: OnceLock<Mutex<HashMap<JwksKey, CachedVerifier>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The hard ceiling on distinct (url, issuer, audience) entries the JWKS cache holds — a
/// defense-in-depth bound so a misconfigured broad `issuer_trust.suffix` (already a trust misconfig)
/// can't ALSO drive unbounded memory growth. A correctly-configured node holds a handful of entries
/// (single-issuer: one; allow-list: its length), far under this.
const JWKS_CACHE_MAX_ENTRIES: usize = 256;

/// Insert `(key, val)`, first evicting the oldest-by-fetch-time entry whenever a NEW key would push
/// the map past `max`. Refreshing an EXISTING key never evicts. Pure (the map + cap are passed) so the
/// bound is unit-testable. Eviction by oldest `fetched_at` drops the least-recently-refreshed verifier
/// (most likely already stale); it only ever triggers in the pathological over-cap case.
fn insert_capped(
    cache: &mut HashMap<JwksKey, CachedVerifier>,
    key: JwksKey,
    val: CachedVerifier,
    max: usize,
) {
    if !cache.contains_key(&key)
        && cache.len() >= max
        && let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, (_, fetched_at))| *fetched_at)
            .map(|(k, _)| k.clone())
    {
        cache.remove(&oldest);
    }
    cache.insert(key, val);
}

/// The three-state freshness decision for a JWKS-cache entry, factored out PURE (both bounds + `now`
/// injected) so the fetch-gating AND the security bound are unit-testable without a network or
/// wall-clock games:
/// - `Fresh` — age < `refresh`: serve as-is, no fetch (bounds the JWKS round-trip to once per
///   `refresh`; the ~1 s-per-request fix).
/// - `ServeStaleRefresh` — `refresh` ≤ age < `hard_ttl`: serve the current verifier NOW and refresh
///   in the background (the zero-hiccup path — no request blocks on the fetch).
/// - `BlockingFetch` — age ≥ `hard_ttl`, or a cold miss: the keys are too old to serve (the revocation
///   bound) or absent, so a request must block on a successful fetch and fail closed otherwise. This
///   arm is THE control that caps how long a key revoked/compromised at the IdP can keep verifying.
enum JwksLookup {
    Fresh(Arc<TokenVerifier>),
    ServeStaleRefresh(Arc<TokenVerifier>),
    BlockingFetch,
}

fn jwks_lookup(
    entry: Option<CachedVerifier>,
    now: std::time::Instant,
    refresh: std::time::Duration,
    hard_ttl: std::time::Duration,
) -> JwksLookup {
    match entry {
        Some((verifier, fetched_at)) => {
            let age = now.saturating_duration_since(fetched_at);
            if age < refresh {
                JwksLookup::Fresh(verifier)
            } else if age < hard_ttl {
                JwksLookup::ServeStaleRefresh(verifier)
            } else {
                // Past the revocation bound → do NOT serve; block on a fresh fetch (fail closed).
                JwksLookup::BlockingFetch
            }
        }
        None => JwksLookup::BlockingFetch,
    }
}

async fn resolve_url_verifier(
    url: &str,
    issuer: &str,
    audience: Option<&str>,
    guarded: bool,
) -> Option<Arc<TokenVerifier>> {
    // Keyed by (url, issuer, audience) — never url alone (see `JwksKey`), so two routes sharing a
    // `jwks_url` but pinning different issuer/audience get distinct verifiers.
    let key: JwksKey = (
        url.to_string(),
        issuer.to_string(),
        audience.map(str::to_string),
    );

    // MUTATION SEAM (perf gate `disable_cache`): bypass the cache + single-flight entirely — every
    // request does its OWN blocking JWKS fetch, reproducing the ~1 s-per-request / mass-call spike the
    // cache fixes, turning the FEDERATION-20 perf gate RED.
    if jwks_mutation().as_deref() == Some("disable_cache") {
        return fetch_and_build(url, issuer, audience, guarded).await;
    }

    // TIER: an operator-fixed single-issuer URL (`guarded == false`) is OWN; a user-declared
    // multi-issuer discovery URL (`guarded == true`) is FOREIGN (tighter `hard_ttl` by default).
    let tier = if guarded {
        &jwks_config().foreign
    } else {
        &jwks_config().own
    };
    resolve_url_verifier_with(
        key,
        url,
        issuer,
        audience,
        guarded,
        tier.refresh,
        tier.hard_ttl,
    )
    .await
}

/// The tier-agnostic core of [`resolve_url_verifier`], with the freshness bounds passed in explicitly
/// (rather than read from the global config) so the Fresh / ServeStaleRefresh / BlockingFetch behavior
/// — and the single-flight / zero-hiccup property — is deterministically unit-testable with small
/// injected bounds and no wall-clock games.
async fn resolve_url_verifier_with(
    key: JwksKey,
    url: &str,
    issuer: &str,
    audience: Option<&str>,
    guarded: bool,
    refresh: std::time::Duration,
    hard_ttl: std::time::Duration,
) -> Option<Arc<TokenVerifier>> {
    let entry = cache_get(&key);
    match jwks_lookup(entry, std::time::Instant::now(), refresh, hard_ttl) {
        // FRESH: serve, no fetch. A known kid verifies; an unknown / rotated-out / keyless kid fails
        // verification (→ anonymous) with NO network hop — the ~1 s-per-request fix.
        JwksLookup::Fresh(verifier) => Some(verifier),
        // Past `refresh`, within `hard_ttl`: serve the current verifier NOW and refresh in the
        // background (single-flight) — no request blocks on the JWKS fetch (the zero-hiccup path).
        JwksLookup::ServeStaleRefresh(verifier) => {
            spawn_background_refresh(
                key,
                url.to_string(),
                issuer.to_string(),
                audience.map(str::to_string),
                guarded,
            );
            Some(verifier)
        }
        // Cold, or past `hard_ttl` (the revocation bound): block on a single-flight fetch; fail closed
        // if it fails (a verifier older than `hard_ttl` is never served without a fresh fetch).
        JwksLookup::BlockingFetch => {
            refresh_under_lock(key, url, issuer, audience, guarded, refresh).await
        }
    }
}

// Defense-in-depth: the anti-hollow seam is for `cargo test` only. Fail the build loudly if the gate
// feature is ever enabled in a non-test RELEASE profile (scoped to THIS seam, not the others).
#[cfg(all(
    feature = "issuer-trust-gate-mutation",
    not(test),
    not(debug_assertions)
))]
compile_error!(
    "issuer-trust-gate-mutation is a test-only anti-hollow seam and must never be compiled into a \
     release build — remove it from the feature set"
);

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

// Defense-in-depth: the JWKS perf-gate anti-hollow seam is for `cargo test` only. Fail the build
// loudly if the gate feature is ever enabled in a non-test RELEASE profile (scoped to THIS seam).
#[cfg(all(feature = "jwks-gate-mutation", not(test), not(debug_assertions)))]
compile_error!(
    "jwks-gate-mutation is a test-only anti-hollow seam and must never be compiled into a release \
     build — remove it from the feature set"
);

/// The active JWKS perf-gate mutation, or `None`. Present ONLY under `cfg(test)` or the
/// `jwks-gate-mutation` feature; a shipped build has neither, so the cache + background-refresh is
/// unconditional and this is a dead `None`. Not a backdoor — it only exposes a test env var that, when
/// set to `disable_cache`, forces a per-request fetch so the FEDERATION-20 perf gate can prove the
/// cache is load-bearing (the gate goes RED under it).
#[cfg(any(test, feature = "jwks-gate-mutation"))]
fn jwks_mutation() -> Option<String> {
    std::env::var("BOATRAMP_JWKS_MUTATION").ok()
}
#[cfg(not(any(test, feature = "jwks-gate-mutation")))]
#[inline]
fn jwks_mutation() -> Option<String> {
    None
}

/// Test-only FIXTURE flag (NOT a mutation): when armed by the live gate, the real discovery/fetch
/// path accepts a loopback `http` mock (so the end-to-end policy → host-pin → redirect-refusal →
/// fetch → verify flow can run against a localhost server) while every invariant UNDER TEST stays
/// active. `false` in every shipped build (the static exists only under `cfg(test)`).
#[cfg(test)]
pub(crate) static TEST_LOOPBACK: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
fn test_loopback_allowed() -> bool {
    TEST_LOOPBACK.load(std::sync::atomic::Ordering::Relaxed)
}
#[cfg(not(test))]
#[inline]
fn test_loopback_allowed() -> bool {
    false
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
    let loopback = test_loopback_allowed();
    if u.scheme() != "https" && !(loopback && u.scheme() == "http") {
        return None;
    }
    if !u.username().is_empty() || u.password().is_some() {
        return None; // reject `user@host` userinfo tricks
    }
    if u.port().is_some() && !loopback {
        return None; // reject an explicit non-default port (the loopback mock uses one)
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
    let loopback = test_loopback_allowed();
    match parsed.scheme() {
        "https" => {}
        "http" if loopback => {} // the live-gate loopback mock (test fixture only)
        _ => return None,
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
        // to a private/loopback address then pins (would be fetched), turning the gate RED. The
        // `loopback` fixture (test-only) likewise permits loopback so the live mock is reachable.
        if !skip && !loopback && !boatramp_core::access::is_global_ip(addr.ip()) {
            return None;
        }
        pinned.get_or_insert(addr);
    }
    pinned.map(|addr| (host, addr))
}

/// An HTTPS GET fenced by [`ssrf_resolve_pin`]: the resolved public address is pinned on the client,
/// `https_only` is enforced, and **redirects are NOT followed** — `.resolve()` pins only the ORIGINAL
/// host, so a 3xx `Location:` to another host would be resolved via the system resolver, un-pinned and
/// un-`is_global_ip`-checked, escaping the guard into the internal network (a trusted-but-malicious
/// issuer controls its own HTTP server). Any 3xx is treated as a fetch failure. OIDC discovery / JWKS
/// endpoints never need a redirect. Returns the body, or `None` if blocked/failed.
async fn ssrf_guarded_get(url: &str) -> Option<String> {
    let (host, addr) = ssrf_resolve_pin(url).await?;
    let mut builder = reqwest::Client::builder()
        .resolve(&host, addr)
        // Fail-fast connect+request timeouts — the SAME bound the own-tier `jwks_http_client` carries.
        // The guarded (FOREIGN/multi-issuer) path fetches a URL whose server is controlled by a
        // trusted-but-possibly-malicious (or merely overloaded) issuer; without this a stalled response
        // would pin the per-key single-flight lock indefinitely and wedge verification for that issuer.
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(5));
    if !test_loopback_allowed() {
        builder = builder.https_only(true);
    }
    // MUTATION SEAM (gate `follow_redirects`): build WITHOUT the no-redirect policy, so a cross-host
    // 3xx is followed off the pinned host — turning the live redirect gate RED.
    if issuertrust_mutation().as_deref() != Some("follow_redirects") {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }
    let client = builder.build().ok()?;
    let resp = client.get(url).send().await.ok()?;
    if resp.status().is_redirection() {
        return None; // never follow off the pinned host (SSRF escape)
    }
    resp.error_for_status().ok()?.text().await.ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serial_test::serial;

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
    #[serial] // shares the process-global TEST_LOOPBACK with the live gate
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

    // ---- JWKS cache TTL: the fix for the ~1 s-per-request gateway JWKS fetch ----

    fn dummy_verifier() -> Arc<TokenVerifier> {
        Arc::new(TokenVerifier {
            by_kid: HashMap::new(),
            sole: None,
            issuer: "https://idp.example".to_string(),
            audience: None,
        })
    }

    #[test]
    fn jwks_lookup_is_fresh_then_serve_stale_refresh_then_blocking_fetch() {
        use std::time::{Duration, Instant};
        let refresh = Duration::from_secs(120);
        let hard_ttl = Duration::from_secs(600);
        let base = Instant::now();
        let v = dummy_verifier();
        // age < refresh → FRESH (served as-is, no fetch). THE FIX: a flood of tokens with an unknown /
        // rotated-out / keyless `kid` against a fresh cache no longer forces a per-request JWKS
        // round-trip — the cached verifier is returned and simply fails verification (→ anonymous).
        assert!(matches!(
            jwks_lookup(Some((v.clone(), base)), base, refresh, hard_ttl),
            JwksLookup::Fresh(_)
        ));
        assert!(matches!(
            jwks_lookup(
                Some((v.clone(), base)),
                base + refresh - Duration::from_secs(1),
                refresh,
                hard_ttl
            ),
            JwksLookup::Fresh(_)
        ));
        // refresh ≤ age < hard_ttl → serve NOW, refresh in the background (zero-hiccup — no block).
        assert!(matches!(
            jwks_lookup(Some((v.clone(), base)), base + refresh, refresh, hard_ttl),
            JwksLookup::ServeStaleRefresh(_)
        ));
        // COLD (no entry) → BLOCKING fetch.
        assert!(matches!(
            jwks_lookup(None, base, refresh, hard_ttl),
            JwksLookup::BlockingFetch
        ));
    }

    /// GATE (hard-ttl revocation bound): past `hard_ttl` the cached keys are NO LONGER served — the
    /// lookup returns `BlockingFetch`, so a request must obtain a FRESH fetch and fail closed otherwise.
    /// This is the control that caps how long a key revoked/compromised at the IdP can keep verifying
    /// while the IdP is unreachable. Pure (`now` + bounds injected) so the boundary is asserted
    /// deterministically; weakening it (serving past `hard_ttl`) turns the at/past-bound arms RED.
    #[test]
    fn jwks_lookup_fails_closed_past_the_hard_ttl_revocation_bound() {
        use std::time::{Duration, Instant};
        let refresh = Duration::from_secs(120);
        let hard_ttl = Duration::from_secs(600);
        let base = Instant::now();
        let v = dummy_verifier();
        // Just inside hard_ttl → still served (and background-refreshed), no outage on a blip.
        assert!(
            matches!(
                jwks_lookup(
                    Some((v.clone(), base)),
                    base + hard_ttl - Duration::from_secs(1),
                    refresh,
                    hard_ttl
                ),
                JwksLookup::ServeStaleRefresh(_)
            ),
            "within hard_ttl, the verifier is still served (zero-hiccup background refresh)"
        );
        // AT the bound → stop serving: block on a fresh fetch (fail closed).
        assert!(
            matches!(
                jwks_lookup(Some((v.clone(), base)), base + hard_ttl, refresh, hard_ttl),
                JwksLookup::BlockingFetch
            ),
            "at the hard_ttl bound, stop serving — block on a fresh fetch (fail closed)"
        );
        // PAST the bound → block on a fresh fetch (a revoked key can't verify forever).
        assert!(
            matches!(
                jwks_lookup(
                    Some((v.clone(), base)),
                    base + hard_ttl + Duration::from_secs(1),
                    refresh,
                    hard_ttl
                ),
                JwksLookup::BlockingFetch
            ),
            "past the hard_ttl bound, a revoked key can't keep verifying"
        );
        println!("JWKS MAX-STALE BOUND OK");
    }

    /// GATE (#4 — cache key): the JWKS cache is keyed by (url, issuer, audience), NOT url alone. A
    /// single `jwks_url` can be shared by two routes/projects pinning DIFFERENT issuer/audience; since
    /// the verifier bakes issuer+audience in, a url-only key would let route B's token be checked
    /// against route A's expected iss/aud (cross-issuer / cross-audience confusion). Driven through the
    /// real `resolve_url_verifier` FRESH-hit path (no network): two verifiers cached under the SAME url
    /// but different (issuer, audience) must coexist, each key returning its OWN verifier. Under a
    /// url-only key the second insert would clobber the first and the `ptr_eq` for route A would fail.
    #[tokio::test]
    #[serial] // touches the process-global jwks_cache
    async fn jwks_cache_is_keyed_by_url_issuer_and_audience_not_url_alone() {
        use std::sync::Arc;
        let url = "https://cache-key-test.invalid/jwks";
        let mk = |iss: &str, aud: &str| {
            Arc::new(TokenVerifier {
                by_kid: HashMap::new(),
                sole: None,
                issuer: iss.to_string(),
                audience: Some(aud.to_string()),
            })
        };
        let va = mk("https://iss-a.example", "aud-a");
        let vb = mk("https://iss-b.example", "aud-b");
        // Both FRESH (fetched_at = now), same URL, different (issuer, audience).
        {
            let now = std::time::Instant::now();
            let mut c = jwks_cache().lock().unwrap();
            c.insert(
                (
                    url.to_string(),
                    "https://iss-a.example".to_string(),
                    Some("aud-a".to_string()),
                ),
                (va.clone(), now),
            );
            c.insert(
                (
                    url.to_string(),
                    "https://iss-b.example".to_string(),
                    Some("aud-b".to_string()),
                ),
                (vb.clone(), now),
            );
        }
        // Each key resolves to its OWN verifier via the fresh path (no fetch — the URL is unreachable,
        // so a cache MISS would fall through to a fetch and return None, never the other verifier).
        let got_a = resolve_url_verifier(url, "https://iss-a.example", Some("aud-a"), false)
            .await
            .expect("route A hits its fresh entry");
        let got_b = resolve_url_verifier(url, "https://iss-b.example", Some("aud-b"), false)
            .await
            .expect("route B hits its fresh entry");
        assert!(Arc::ptr_eq(&got_a, &va), "route A gets A's verifier");
        assert!(
            Arc::ptr_eq(&got_b, &vb),
            "route B gets B's verifier — NOT clobbered by A under a url-only key"
        );
        assert!(
            !Arc::ptr_eq(&got_a, &got_b),
            "distinct (issuer, audience) under one URL are distinct cache entries"
        );
        // Don't leak into the process-global cache used by other tests.
        jwks_cache().lock().unwrap().retain(|(u, _, _), _| u != url);
        println!("JWKS CACHE KEY OK");
    }

    /// GATE (zero-hiccup background refresh + single-flight): a request landing in [refresh, hard_ttl)
    /// serves the CURRENT verifier IMMEDIATELY (never blocks on the JWKS fetch) while a SINGLE background
    /// refresh runs OFF the request path; N concurrent such requests trigger ONE refresh, not N. This is
    /// the property that makes steady-state "really zero hiccup" (vs. a lazy refetch that blocks one
    /// request per TTL). Deterministic via injected bounds (`resolve_url_verifier_with`) + an aged cache
    /// entry + the delayed mock — no wall-clock games, no global-config dependence.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial] // touches the process-global jwks_cache + key-state
    #[ignore = "run via the server-feature-union CI gate (spawns a localhost HTTP mock; timing-based)"]
    async fn background_refresh_serves_immediately_and_is_single_flight() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;
        use std::time::{Duration, Instant};

        // A delayed JWKS mock: each /keys fetch costs D, so a request that BLOCKED on a fetch takes ~D,
        // distinguishable from "served from cache" (≪ D).
        const D: Duration = Duration::from_millis(400);
        let key = SigningKey::from_bytes(&[23u8; 32]);
        let jwks = serde_json::json!({ "keys": [ {
            "kty": "OKP", "crv": "Ed25519", "kid": "bg", "x": b64url(key.verifying_key().as_bytes()),
        } ] })
        .to_string();
        let (port, hits) = spawn_oidc_mock(jwks, D).await;
        let url = format!("http://127.0.0.1:{port}/keys");
        let issuer = format!("http://127.0.0.1:{port}");
        let ckey: JwksKey = (url.clone(), issuer.clone(), None);

        // Inject tiny bounds so an aged entry is stale-but-serviceable (→ ServeStaleRefresh), not Fresh
        // and not past hard_ttl.
        let refresh = Duration::from_millis(50);
        let hard_ttl = Duration::from_secs(10);
        let seeded = Arc::new(TokenVerifier {
            by_kid: HashMap::new(),
            sole: None,
            issuer: issuer.clone(),
            audience: None,
        });
        let age_into_window = || {
            Instant::now()
                .checked_sub(Duration::from_millis(120))
                .expect("test host has run > 120ms")
        };
        jwks_cache()
            .lock()
            .unwrap()
            .insert(ckey.clone(), (seeded.clone(), age_into_window()));

        // A single stale request serves the SEEDED verifier IMMEDIATELY (≪ D) — it must NOT block on
        // the D-delayed background fetch.
        let t = Instant::now();
        let got =
            resolve_url_verifier_with(ckey.clone(), &url, &issuer, None, false, refresh, hard_ttl)
                .await;
        let served_in = t.elapsed();
        assert!(
            got.as_ref().is_some_and(|v| Arc::ptr_eq(v, &seeded)),
            "a stale-but-serviceable request serves the CURRENT (seeded) verifier"
        );
        assert!(
            served_in < D / 2,
            "served in {served_in:?} — must NOT block on the ~{D:?} background fetch"
        );

        // The background refresh ran OFF the request path: after ~D it fetched exactly once and replaced
        // the seeded entry with a freshly-fetched (real) verifier.
        tokio::time::sleep(D + Duration::from_millis(250)).await;
        assert_eq!(
            hits.load(Ordering::Relaxed),
            1,
            "exactly one background fetch ran"
        );
        {
            let c = jwks_cache().lock().unwrap();
            let v = c.get(&ckey).expect("entry present").0.clone();
            assert!(
                !Arc::ptr_eq(&v, &seeded),
                "the background refresh replaced the seeded verifier with the freshly-fetched one"
            );
        }

        // SINGLE-FLIGHT: re-age the entry, fire N concurrent stale requests — all serve immediately, but
        // only ONE background fetch happens (try_lock dedup), so hits grows by ≈1, not N.
        let before = hits.load(Ordering::Relaxed);
        {
            let mut c = jwks_cache().lock().unwrap();
            let v = c.get(&ckey).unwrap().0.clone();
            c.insert(ckey.clone(), (v, age_into_window()));
        }
        const N: usize = 25;
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..N {
            let (url, issuer, ckey) = (url.clone(), issuer.clone(), ckey.clone());
            set.spawn(async move {
                let t = Instant::now();
                let _ =
                    resolve_url_verifier_with(ckey, &url, &issuer, None, false, refresh, hard_ttl)
                        .await;
                t.elapsed()
            });
        }
        let mut worst = Duration::ZERO;
        while let Some(r) = set.join_next().await {
            worst = worst.max(r.unwrap());
        }
        assert!(
            worst < D / 2,
            "every concurrent stale request served in {worst:?} (≪ {D:?}) — none blocked"
        );
        tokio::time::sleep(D + Duration::from_millis(250)).await;
        let delta = hits.load(Ordering::Relaxed) - before;
        assert!(
            delta <= 2,
            "single-flight: {N} concurrent stale requests triggered {delta} fetches (≈1 expected, NOT {N})"
        );

        jwks_cache().lock().unwrap().remove(&ckey);
        println!("JWKS BACKGROUND-REFRESH SINGLE-FLIGHT OK");
    }

    // ---- Multi-issuer trust: the LIVE end-to-end gate (real discovery → fetch → verify) ----

    /// A no-op env source (the multi-issuer path never reads `jwks_env`).
    struct NoEnv;
    impl boatramp_core::env::EnvSource for NoEnv {
        fn get(&self, _: &str) -> Option<String> {
            None
        }
    }

    /// A minimal loopback HTTP mock for the live gate (bound to `127.0.0.1`): serves OIDC discovery +
    /// an Ed25519 JWKS, an off-host discovery (jwks_uri on a DIFFERENT host — used only as a pin-
    /// mismatch string, never connected), and a same-host 302 redirect. Returns the port + a hit
    /// counter (to prove an untrusted iss triggers NO fetch).
    async fn spawn_oidc_mock(
        jwks: String,
        delay: std::time::Duration,
    ) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let jwks = jwks.clone();
                let hits = hits_srv.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    hits.fetch_add(1, Ordering::Relaxed);
                    let resp = if path.ends_with("/.well-known/openid-configuration") {
                        let jwks_uri = if path.starts_with("/offhost/") {
                            format!("http://127.0.0.2:{port}/keys") // off-host → pin refuses (pre-fetch)
                        } else if path.starts_with("/redir/") {
                            format!("http://127.0.0.1:{port}/redir-keys")
                        } else {
                            format!("http://127.0.0.1:{port}/keys")
                        };
                        let body = format!("{{\"jwks_uri\":\"{jwks_uri}\"}}");
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                    } else if path.ends_with("/redir-keys") {
                        // A 302 we must NOT follow (same host here, so `follow_redirects` is locally
                        // observable; the fix refuses ALL 3xx, so a cross-host Location is a fortiori
                        // refused).
                        format!(
                            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/keys\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    } else if path.ends_with("/keys") {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{jwks}",
                            jwks.len()
                        )
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string()
                    };
                    // Stand-in for the real IdP round-trip latency (the cost that made construens'
                    // calls ~1 s): a per-response delay, so a per-request fetch is OBSERVABLE and the
                    // cache's fetch-collapse is measurable.
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });
        (port, hits)
    }

    /// LIVE end-to-end gate: drives the REAL discovery → host-pin → redirect-refusal → fetch → verify
    /// path against a loopback mock (via the `TEST_LOOPBACK` fixture, which permits only the http
    /// loopback mock while every invariant under test stays active). Asserts (a) a trusted iss
    /// discovers + verifies, (b) an untrusted iss resolves ZERO claims with NO fetch, (c) an off-host
    /// `jwks_uri` is refused, (d) a redirecting JWKS endpoint is refused (never followed — the #1
    /// SSRF fix). Marker `MULTI-ISSUER TRUST LIVE OK`. MUTATION-VERIFIED in CI: `follow_redirects`
    /// turns (d) RED. `#[ignore]` + run via the CI gate (spawns a localhost server).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    #[ignore = "run via the server-feature-union CI gate (spawns a localhost HTTP mock)"]
    async fn multi_issuer_live_discovery_verify_and_redirect_refusal() {
        use std::sync::atomic::Ordering;
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let jwks = serde_json::json!({ "keys": [ {
            "kty": "OKP", "crv": "Ed25519", "kid": "app-1",
            "x": b64url(key.verifying_key().as_bytes()),
        } ] })
        .to_string();
        let (port, hits) = spawn_oidc_mock(jwks, std::time::Duration::ZERO).await;
        let base = format!("http://127.0.0.1:{port}");

        // The multi-issuer config for an iss at `<base><suffix_path>` (exact `allow`, `oidc` discover).
        let cfg = |iss_path: &str| HandlerGraphqlTokenClaims {
            issuer_trust: Some(IssuerTrust {
                allow: vec![format!("{base}{iss_path}")],
                suffix: None,
            }),
            jwks: Some(JwksDiscovery {
                discover: Some("oidc".to_string()),
                template: None,
            }),
            ..Default::default()
        };
        let token = |iss: &str| {
            ed25519_token(
                &key,
                "app-1",
                serde_json::json!({ "iss": iss, "exp": far_future(), "tid": "acme" }),
            )
        };

        TEST_LOOPBACK.store(true, Ordering::Relaxed);

        // (a) happy path: a trusted iss discovers its JWKS and verifies the token.
        let ok = verified_claims(&cfg(""), &token(&base), &NoEnv).await;
        assert_eq!(
            ok.as_ref().and_then(|c| c.get("tid")),
            Some(&serde_json::json!("acme")),
            "(a) a trusted iss discovers + verifies"
        );

        // (b) an untrusted iss resolves ZERO claims and triggers NO fetch.
        let before = hits.load(Ordering::Relaxed);
        let untrusted = format!("http://127.0.0.9:{port}"); // not in `allow`
        assert!(
            verified_claims(&cfg(""), &token(&untrusted), &NoEnv)
                .await
                .is_none(),
            "(b) an untrusted iss resolves no claims"
        );
        assert_eq!(
            hits.load(Ordering::Relaxed),
            before,
            "(b) an untrusted iss triggered NO network fetch"
        );

        // (c) an off-host jwks_uri (different host than iss) is refused (pin fails pre-fetch).
        assert!(
            verified_claims(&cfg("/offhost"), &token(&format!("{base}/offhost")), &NoEnv)
                .await
                .is_none(),
            "(c) an off-host jwks_uri is refused"
        );

        // (d) a redirecting JWKS endpoint is refused — never followed off the pinned host (#1 fix).
        assert!(
            verified_claims(&cfg("/redir"), &token(&format!("{base}/redir")), &NoEnv)
                .await
                .is_none(),
            "(d) a 302 from the JWKS endpoint is refused (not followed)"
        );

        TEST_LOOPBACK.store(false, Ordering::Relaxed);
        println!("MULTI-ISSUER TRUST LIVE OK");
    }

    // ---- E2E PERFORMANCE GATE: 20-subgraph federation + JWKS + empty responses + mass-calls ----

    /// E2E PERFORMANCE GATE — the construens `boatramp-federated-gateway-overhead` repro. A route with
    /// `token_claims:(issuer, jwks_url)` (single-issuer = OWN tier, construens' exact shape) over a
    /// **20-subgraph** federation, firing an empty-returning query under a **concurrent mass-call**,
    /// must stay in the **ms** range with **no per-request JWKS fetch** and **no spike**.
    ///
    /// The failure shape is reproduced with a **delayed JWKS mock** (`D` stands in for the ~1 s IdP
    /// round-trip that made construens' calls ~1 s). The gate PROVES the cache collapses it:
    /// - (a) after one warm-up, the mock `/keys` is hit **O(1)** times (not ~N) — the fetch collapsed;
    /// - (b) every **warm** request is **≪ D** — no request paid a JWKS fetch (no spike);
    /// - (c) the whole concurrent batch finishes **≪ D** — no stampede.
    ///
    /// Marker `FEDERATION-20 JWKS WARM-MS OK`. MUTATION-VERIFIED in CI: `BOATRAMP_JWKS_MUTATION=
    /// disable_cache` forces a per-request fetch → every request pays `D`, hit-count ~N → all three
    /// assertions RED. `#[ignore]` + run via the server-feature-union CI gate (spawns a localhost mock
    /// + composes 20 subgraphs). The OWN tier's single-issuer `jwks_url` fetches the fixed URL directly
    /// (no SSRF/loopback arming needed).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial] // touches the process-global jwks_cache
    #[ignore = "run via the server-feature-union CI gate (spawns a localhost HTTP mock + composes 20 subgraphs)"]
    async fn federation_20_jwks_warm_is_ms_without_spikes() {
        use boatramp_core::kv::MemoryKv;
        use std::sync::Arc;
        use std::sync::atomic::Ordering;
        use std::time::{Duration, Instant};

        // --- the delayed JWKS mock (the stand-in for the IdP round-trip that made calls ~1 s) ---
        const D: Duration = Duration::from_millis(500);
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let jwks = serde_json::json!({ "keys": [ {
            "kty": "OKP", "crv": "Ed25519", "kid": "fed20",
            "x": b64url(key.verifying_key().as_bytes()),
        } ] })
        .to_string();
        let (port, hits) = spawn_oidc_mock(jwks, D).await;
        let jwks_url = format!("http://127.0.0.1:{port}/keys");
        let issuer = format!("http://127.0.0.1:{port}");
        // Construens' shape: `token_claims:(issuer, jwks_url)` — single-issuer = OWN tier (guarded=false).
        let cfg = HandlerGraphqlTokenClaims {
            issuer: issuer.clone(),
            jwks_url: Some(jwks_url),
            ..Default::default()
        };
        let token = ed25519_token(
            &key,
            "fed20",
            serde_json::json!({ "iss": issuer, "exp": far_future(), "tid": "acme" }),
        );

        // --- a real 20-subgraph federation over MemoryKv (real compose + plan; empty fan-out) ---
        let kv = Arc::new(MemoryKv::new());
        let project = "fed20";
        for i in 0..20u32 {
            let sdl = format!(
                "type Query {{ q{i}: T{i} }}\ntype T{i} @key(fields: \"id\") {{ id: ID! v: String }}"
            );
            crate::graphql_registry::stage_subgraph(
                kv.as_ref(),
                project,
                &format!("sub{i}"),
                &sdl,
                &format!("h{i}"),
            )
            .await
            .expect("stage subgraph");
        }
        crate::graphql_registry::compose_batch(kv.as_ref(), project)
            .await
            .expect("compose 20 subgraphs");
        let query = "{ q0 { id } }";
        let op_hash = crate::graphql_apq::sha256_hex(query);
        let variables = serde_json::json!({});
        let cache = Arc::new(crate::graphql_cache::GraphqlCache::default());

        /// Fans out to subgraphs returning empty data — construens' empty/`unauthenticated` response,
        /// the least-work path (its real subgraphs answer in 2–75 ms; empty is a fortiori cheaper).
        struct EmptyFetcher;
        #[async_trait::async_trait]
        impl crate::graphql_gateway::SubgraphFetcher for EmptyFetcher {
            async fn fetch(
                &self,
                _subgraph: &str,
                _query: &str,
                _variables: serde_json::Value,
                _class: &boatramp_core::tenancy::TenancyClass,
            ) -> serde_json::Value {
                serde_json::json!({ "data": {} })
            }
        }
        let fetcher = Arc::new(EmptyFetcher);

        // One request = the full gateway pipeline: JWKS auth → 20-subgraph compose → plan → empty fan-out.
        #[allow(clippy::too_many_arguments)] // a test harness threading the whole request context
        async fn serve_once(
            cache: &crate::graphql_cache::GraphqlCache,
            kv: &MemoryKv,
            fetcher: &EmptyFetcher,
            project: &str,
            query: &str,
            op_hash: &str,
            variables: &serde_json::Value,
            cfg: &HandlerGraphqlTokenClaims,
            token: &str,
        ) -> Option<serde_json::Map<String, serde_json::Value>> {
            let claims = verified_claims(cfg, token, &NoEnv).await;
            let graph = cache.supergraph(kv, project).await.expect("compose cached");
            let plan = cache
                .plan(
                    project,
                    graph.version,
                    op_hash,
                    query,
                    graph.supergraph.as_ref(),
                    crate::graphql_cache::Visibility::Internal,
                )
                .expect("plan");
            let _resp = crate::graphql_gateway::execute(&plan, fetcher, variables).await;
            claims
        }

        // Warm-up: this one request pays the cold JWKS fetch (~D) + first compose/plan.
        let warm = serve_once(
            &cache, &kv, &fetcher, project, query, &op_hash, &variables, &cfg, &token,
        )
        .await;
        assert_eq!(
            warm.as_ref().and_then(|c| c.get("tid")),
            Some(&serde_json::json!("acme")),
            "warm-up must actually VERIFY the token via JWKS (else the cache proves nothing)"
        );
        let hits_after_warm = hits.load(Ordering::Relaxed);
        assert_eq!(
            hits_after_warm, 1,
            "the cold warm-up fetches the JWKS exactly once"
        );

        // Mass-call: N concurrent requests. With a fresh cache NONE pays a JWKS fetch.
        const N: usize = 50;
        let batch_start = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..N {
            let cache = cache.clone();
            let kv = kv.clone();
            let fetcher = fetcher.clone();
            let cfg = cfg.clone();
            let token = token.clone();
            let op_hash = op_hash.clone();
            let variables = variables.clone();
            set.spawn(async move {
                let t = Instant::now();
                let claims = serve_once(
                    &cache,
                    &kv,
                    &fetcher,
                    "fed20",
                    "{ q0 { id } }",
                    &op_hash,
                    &variables,
                    &cfg,
                    &token,
                )
                .await;
                assert!(claims.is_some(), "every warm request still verifies");
                t.elapsed()
            });
        }
        let mut worst = Duration::ZERO;
        while let Some(res) = set.join_next().await {
            worst = worst.max(res.expect("task ok"));
        }
        let batch = batch_start.elapsed();
        let hits_final = hits.load(Ordering::Relaxed);

        let worst_ms = worst.as_secs_f64() * 1000.0;
        let batch_ms = batch.as_secs_f64() * 1000.0;
        eprintln!(
            "FED20: warm_hits={hits_after_warm} final_hits={hits_final} worst_warm={worst_ms:.1}ms \
             batch={batch_ms:.1}ms (D={}ms, N={N})",
            D.as_millis()
        );

        // (a) the JWKS fetch COLLAPSED: O(1) hits total, not ~N (fresh cache ⇒ no background refresh).
        assert!(
            hits_final <= 3,
            "JWKS fetch did NOT collapse: {hits_final} mock hits for {N} requests — a per-request \
             fetch is back (cache disabled?)"
        );
        // (b) NO SPIKE: every warm request is far below the IdP round-trip D (none paid a fetch).
        assert!(
            worst_ms < D.as_secs_f64() * 1000.0 / 5.0,
            "warm request spiked to {worst_ms:.1}ms (≥ D/5={:.0}ms) — a request paid a JWKS fetch",
            D.as_secs_f64() * 1000.0 / 5.0
        );
        // (c) NO STAMPEDE: the whole concurrent batch finishes well under one D.
        assert!(
            batch_ms < D.as_secs_f64() * 1000.0 / 2.0,
            "concurrent batch took {batch_ms:.1}ms (≥ D/2={:.0}ms) — a mass-call stampede/spike",
            D.as_secs_f64() * 1000.0 / 2.0
        );

        // Don't leak into the process-global cache used by other tests.
        jwks_cache()
            .lock()
            .unwrap()
            .retain(|(_, iss, _), _| iss != &issuer);
        println!("FEDERATION-20 JWKS WARM-MS OK");
    }
}
