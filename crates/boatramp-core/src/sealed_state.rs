//! AEAD-sealed tenancy **state tokens** — the crypto heart of the `sealed-state` tenancy source.
//!
//! A `sealed-state` source resolves a request's tenant by UNSEALING an opaque request parameter (an
//! OIDC `state`): at login-start a host op mints a token that carries the guest's host-resolved
//! tenant (plus app fields the guest supplies — a PKCE verifier / its hash, the OIDC nonce, an exp
//! hint); at the PRE-AUTH callback the tenancy source verifies+decrypts that token with the host key
//! and extracts the tenant. The seal is the ONLY thing that carries the tenant across the pre-auth
//! hop — a guest never names it on either leg, and a browser can never read or alter it.
//!
//! # Why AEAD (not a signature)
//! The tenant must be **opaque to the browser** (a confidential IdP `state` round-trips through the
//! user agent) and **tamper-evident**. A bare signature leaves the tenant readable; AEAD
//! (authenticated encryption) gives confidentiality AND integrity in one primitive. We reuse the
//! node's secrets-at-rest [`KeyEnvelope`](crate::envelope::KeyEnvelope) — the SAME `[secrets]`
//! envelope the per-tenant secret store seals with (`LocalKek` AES-256-GCM, or Vault Transit) — so
//! there is no new ad-hoc key store, and the key is fleet-consistent (mint and resolve may land on
//! different nodes behind a load balancer; both unseal under the same KEK).
//!
//! # Security invariants (a flaw here = cross-tenant secret access)
//! 1. **The tenant comes from the crypto seal, never from request text.** `unseal_state` only ever
//!    returns a tenant that was AEAD-sealed under the host key — there is no path that parses a
//!    tenant out of the token string. (The never-parse-text-for-tenancy rule, generalized.)
//! 2. **Fail-closed, always.** A tampered / forged / expired / wrong-key / wrong-(project,site) /
//!    malformed token resolves to an `Err` — never a fallback, a default, or a first tenant. The
//!    caller maps every `Err` to "no tenant resolved" (the scoped op then fails closed).
//! 3. **Per-(project, site) binding.** The seal carries the minting project+site, and
//!    `unseal_state` requires them to equal the resolving request's host-resolved project+site. A
//!    seal minted for site X can NEVER resolve at site Y — even though the KEK is node-wide, the
//!    binding lives in the AEAD-authenticated plaintext (equivalent in strength to AAD binding; the
//!    `KeyEnvelope` trait seals with empty AAD, so we bind inside the ciphertext). This mirrors how
//!    a fleet-signed `capability` is bound to its project audience after a fleet-key verify.
//! 4. **Domain separation from secrets-at-rest.** The sealed plaintext is prefixed with a fixed
//!    [`MAGIC`] tag, checked after decrypt. A secrets-at-rest blob (sealed under the same KEK but
//!    without the tag) can never be misread as a state token, and vice versa.
//! 5. **Bounded lifetime.** `exp - iat` is clamped at seal and RE-checked at unseal against
//!    [`MAX_STATE_TTL_SECS`], so the replay window stays small even if a minting bug tried a long
//!    TTL. Anti-replay is otherwise delegated to the IdP single-use code + OIDC nonce + PKCE + the
//!    app's browser-bound `state` cookie — boatramp stores NO per-login state (stateless by design).
//!
//! This module is wasm-clean: it depends only on the [`KeyEnvelope`](crate::envelope::KeyEnvelope)
//! seam (the concrete AES/Vault backend lives in `boatramp-server`), `serde_json`, and `base64`.

use serde::{Deserialize, Serialize};

use crate::envelope::KeyEnvelope;

/// Domain-separation tag prepended to the AEAD plaintext (boatramp sealed-state, v1). A secrets-at-
/// rest blob sealed under the same KEK lacks this prefix, so it can never be misread as a state
/// token (and a state token can never be misread as a secret). Bump the trailing version when the
/// claims layout changes incompatibly; `unseal_state` then rejects an old tag (fail-closed).
const MAGIC: &[u8] = b"BRSS1\0";

/// The maximum lifetime (`exp - iat`) a sealed state may carry, enforced at BOTH seal and unseal. A
/// login round-trip (redirect to the IdP, authenticate, redirect back) completes in seconds-to-
/// minutes; 15 minutes is generous while keeping the stateless replay window short. RE-checked at
/// unseal so a bug or tampered `iat`/`exp` (both authenticated, so only a host-minted pair is ever
/// seen) cannot widen the window past this ceiling.
pub const MAX_STATE_TTL_SECS: u64 = 900;

/// Clock-skew tolerance for the not-yet-valid (`iat` in the future) check. Applied ONLY to the
/// lower bound — expiry (`exp`) is checked strictly, so skew can never EXTEND a token's life.
const CLOCK_SKEW_SECS: u64 = 120;

/// The claims carried inside a sealed state token. `project`/`site`/`tenant` are HOST-bound at mint
/// (the guest never supplies them); `pkce`/`nonce`/`iat`/`exp` are the app/login fields (the guest
/// supplies the pkce/nonce and an exp hint; the host stamps `iat` and clamps `exp`). The whole
/// struct is AEAD-sealed, so every field is confidential AND integrity-protected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedStateClaims {
    /// The minting project (host-bound). Re-checked at unseal against the resolving request's
    /// project — a seal from another project never resolves.
    pub project: String,
    /// The minting site (host-bound). Re-checked at unseal against the resolving request's site — a
    /// seal from another site never resolves (the per-(project,site) binding).
    pub site: String,
    /// The guest's host-resolved OWN tenant at mint time — the value that becomes the resolved
    /// `ScopeAxis::Tenant` fact at the callback. The guest can NEVER choose or forge this: the mint
    /// op stamps the guest's own already-resolved tenant.
    pub tenant: String,
    /// The app's PKCE verifier (or its S256 hash) — carried through opaquely so the app can bind the
    /// authorization-code exchange. boatramp never interprets it. `None` when the app does not use
    /// PKCE (it should).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkce: Option<String>,
    /// The OIDC `nonce` the app will match against the ID token — carried through opaquely. `None`
    /// when unused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Issued-at, unix seconds (host-stamped at mint).
    pub iat: u64,
    /// Expiry, unix seconds (host-clamped to `iat + min(requested_ttl, MAX_STATE_TTL_SECS)`).
    pub exp: u64,
}

/// Why a seal or unseal failed. Every variant maps, at the tenancy source, to **no tenant resolved**
/// (fail-closed) — the distinction exists only for host-side logging/testing, never to branch the
/// resolution outcome. Carries no key material and no tenant value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedStateError {
    /// The token was not valid URL-safe base64 (unseal), or claims could not be serialized (seal).
    Codec,
    /// The AEAD open failed — wrong key, tampered ciphertext, or a foreign blob. (The dominant
    /// forged/tampered case.)
    Unseal,
    /// The decrypted plaintext did not carry the sealed-state domain tag (a secrets-at-rest blob or
    /// a future/foreign format).
    BadMagic,
    /// The decrypted claims could not be parsed as a `SealedStateClaims`.
    Parse,
    /// The sealed project/site did not match the resolving request's project/site (the
    /// per-(project,site) binding) — a seal from another site/project.
    BindingMismatch,
    /// The claimed lifetime (`exp - iat`) is zero/inverted or exceeds [`MAX_STATE_TTL_SECS`].
    BadLifetime,
    /// The token's `iat` is further in the future than the clock-skew tolerance (not yet valid).
    NotYetValid,
    /// The token has expired (`now >= exp`).
    Expired,
}

impl std::fmt::Display for SealedStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Codec => "sealed-state: codec error",
            Self::Unseal => "sealed-state: AEAD open failed (wrong key, tampered, or foreign)",
            Self::BadMagic => "sealed-state: missing domain tag (not a sealed-state token)",
            Self::Parse => "sealed-state: claims parse failed",
            Self::BindingMismatch => "sealed-state: project/site binding mismatch",
            Self::BadLifetime => "sealed-state: bad or over-long lifetime",
            Self::NotYetValid => "sealed-state: not yet valid (iat in the future)",
            Self::Expired => "sealed-state: expired",
        };
        f.write_str(s)
    }
}

impl std::error::Error for SealedStateError {}

/// The requested-TTL clamp applied at mint: the sealed `exp` is `iat + min(requested, MAX)`. A zero
/// request is treated as "the default" (the max) — a login should always carry a real window.
#[must_use]
pub fn clamp_ttl(requested_secs: u64) -> u64 {
    if requested_secs == 0 {
        MAX_STATE_TTL_SECS
    } else {
        requested_secs.min(MAX_STATE_TTL_SECS)
    }
}

/// Build the host-bound claims for a mint: the host supplies `project`/`site`/`tenant` (NEVER the
/// guest), the guest supplies the opaque `pkce`/`nonce` and a requested TTL (clamped here). `now` is
/// the current unix time (stamped as `iat`). This is the single constructor the mint op uses, so the
/// lifetime clamp is impossible to bypass.
#[must_use]
pub fn mint_claims(
    project: impl Into<String>,
    site: impl Into<String>,
    tenant: impl Into<String>,
    pkce: Option<String>,
    nonce: Option<String>,
    requested_ttl_secs: u64,
    now: u64,
) -> SealedStateClaims {
    let ttl = clamp_ttl(requested_ttl_secs);
    SealedStateClaims {
        project: project.into(),
        site: site.into(),
        tenant: tenant.into(),
        pkce,
        nonce,
        iat: now,
        exp: now.saturating_add(ttl),
    }
}

/// AEAD-seal `claims` under the host `env`, returning the URL-safe base64 `state` string. The
/// plaintext is `MAGIC || json(claims)`, wrapped by the node's secrets envelope — so the tenant is
/// opaque to the browser and tamper-evident. Refuses a zero/inverted or over-long lifetime up front
/// (defense in depth with [`mint_claims`]'s clamp), so a hand-built claims set cannot widen the
/// replay window.
pub async fn seal_state(
    env: &dyn KeyEnvelope,
    claims: &SealedStateClaims,
) -> Result<String, SealedStateError> {
    // Lifetime bound at seal (mirrors the unseal re-check): never emit a token that unseal would
    // reject as over-long, and never seal a zero/inverted window.
    if claims.exp <= claims.iat || claims.exp - claims.iat > MAX_STATE_TTL_SECS {
        return Err(SealedStateError::BadLifetime);
    }
    let json = serde_json::to_vec(claims).map_err(|_| SealedStateError::Codec)?;
    let mut plaintext = Vec::with_capacity(MAGIC.len() + json.len());
    plaintext.extend_from_slice(MAGIC);
    plaintext.extend_from_slice(&json);
    let wrapped = env
        .wrap(&plaintext)
        .await
        .map_err(|_| SealedStateError::Unseal)?;
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wrapped))
}

/// Verify + decrypt a sealed `token` with the host `env` and return its claims — or `Err`
/// (fail-closed) on ANY problem. Enforces, in order: base64 decode, AEAD open (authenticity +
/// confidentiality), the domain tag, claims parse, the per-(project,site) binding against
/// `expected_project`/`expected_site`, the lifetime bound, not-yet-valid (skew-tolerant), and expiry
/// (strict). The returned `tenant` is therefore guaranteed to be a value a host mint sealed for
/// THIS project+site, unexpired — never anything parsed from the token text.
///
/// The caller still VALIDATES that `claims.tenant` is a real tenant in the project before resolving
/// it (defense in depth) — this function proves authenticity + freshness, not provisioning.
pub async fn unseal_state(
    env: &dyn KeyEnvelope,
    token: &str,
    now: u64,
    expected_project: &str,
    expected_site: &str,
) -> Result<SealedStateClaims, SealedStateError> {
    use base64::Engine as _;
    let wrapped = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| SealedStateError::Codec)?;
    // AEAD open: a wrong key, a tampered byte, or a foreign blob fails here (the dominant forged /
    // tampered path). No partial output.
    let plaintext = env
        .unwrap(&wrapped)
        .await
        .map_err(|_| SealedStateError::Unseal)?;
    // Domain separation: strip + check the sealed-state tag.
    let rest = match plaintext.strip_prefix(MAGIC) {
        Some(rest) => rest,
        None if mutation_skips("skip_magic") => &plaintext,
        None => return Err(SealedStateError::BadMagic),
    };
    let claims: SealedStateClaims =
        serde_json::from_slice(rest).map_err(|_| SealedStateError::Parse)?;
    // Per-(project, site) binding: the authenticated project+site must equal the resolving request's.
    // (MUTATION SEAM `skip_binding`: test-only — drops the check so a seal for X resolves at Y → the
    // ≥2-tenant gate goes RED. Compiled out of shipped builds.)
    if !mutation_skips("skip_binding")
        && (claims.project != expected_project || claims.site != expected_site)
    {
        return Err(SealedStateError::BindingMismatch);
    }
    // Lifetime bound (re-checked here regardless of what was sealed).
    if claims.exp <= claims.iat || claims.exp - claims.iat > MAX_STATE_TTL_SECS {
        return Err(SealedStateError::BadLifetime);
    }
    // Not yet valid: reject a token issued further ahead than the skew tolerance.
    if claims.iat > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(SealedStateError::NotYetValid);
    }
    // Expiry (strict — skew never extends life). (MUTATION SEAM `skip_exp`: test-only — drops the
    // expiry check so an expired seal still resolves → the fail-closed gate goes RED.)
    if !mutation_skips("skip_exp") && now >= claims.exp {
        return Err(SealedStateError::Expired);
    }
    Ok(claims)
}

// Defense-in-depth: the sealed-state anti-hollow mutation seam is for `cargo test` / a dedicated CI
// gate lane only. Fail the build loudly if the gate feature is ever enabled in a non-test RELEASE
// profile (scoped to THIS seam), so a neutered check can never ship.
#[cfg(all(
    feature = "sealed-state-gate-mutation",
    not(test),
    not(debug_assertions)
))]
compile_error!(
    "sealed-state-gate-mutation is a test-only anti-hollow seam and must never be compiled into a \
     release build — remove it from the feature set"
);

/// The active sealed-state anti-hollow mutation (`BOATRAMP_SEALEDSTATE_MUTATION`), or `None`. Present
/// ONLY under `cfg(test)` or the `sealed-state-gate-mutation` feature; a shipped build has neither, so
/// every security check above is unconditional and this is a dead `false`. Not a backdoor — it only
/// reads a test env var.
#[cfg(any(test, feature = "sealed-state-gate-mutation"))]
fn mutation_skips(which: &str) -> bool {
    std::env::var("BOATRAMP_SEALEDSTATE_MUTATION")
        .ok()
        .as_deref()
        == Some(which)
}
#[cfg(not(any(test, feature = "sealed-state-gate-mutation")))]
#[inline]
fn mutation_skips(_which: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{EnvelopeError, KeyEnvelope};

    /// A deterministic AEAD-shaped test envelope: `wrap` = magic-tagged `key`-XOR; `unwrap` reverses
    /// it and FAILS on a wrong tag (a foreign/tampered blob) — enough to exercise the authenticity +
    /// confidentiality contract without pulling AES into the wasm-clean core. The real `LocalKek`
    /// AES-256-GCM path is exercised by the server-side ≥2-tenant gate.
    struct FakeKek {
        key: u8,
    }
    const FAKE_TAG: &[u8] = b"FKEK";
    #[async_trait::async_trait]
    impl KeyEnvelope for FakeKek {
        async fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            let mut out = FAKE_TAG.to_vec();
            out.extend(plaintext.iter().map(|b| b ^ self.key));
            Ok(out)
        }
        async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            let body = wrapped
                .strip_prefix(FAKE_TAG)
                .ok_or_else(|| EnvelopeError::new("foreign blob"))?;
            Ok(body.iter().map(|b| b ^ self.key).collect())
        }
    }

    fn claims(now: u64) -> SealedStateClaims {
        mint_claims(
            "acme",
            "console",
            "firm-x",
            Some("pkce-verifier".into()),
            Some("oidc-nonce".into()),
            300,
            now,
        )
    }

    #[tokio::test]
    async fn round_trips_within_the_same_project_site() {
        let env = FakeKek { key: 0x5a };
        let now = 1_000_000;
        let token = seal_state(&env, &claims(now)).await.unwrap();
        let got = unseal_state(&env, &token, now + 10, "acme", "console")
            .await
            .unwrap();
        assert_eq!(got.tenant, "firm-x");
        assert_eq!(got.pkce.as_deref(), Some("pkce-verifier"));
        assert_eq!(got.nonce.as_deref(), Some("oidc-nonce"));
    }

    #[tokio::test]
    async fn the_tenant_is_opaque_in_the_token() {
        // The tenant must not appear in cleartext in the state string (confidentiality).
        let env = FakeKek { key: 0x33 };
        let now = 1_000_000;
        let token = seal_state(&env, &claims(now)).await.unwrap();
        assert!(
            !token.contains("firm-x"),
            "the sealed state must not carry the tenant in cleartext"
        );
    }

    #[tokio::test]
    async fn a_wrong_key_fails_closed() {
        let env = FakeKek { key: 0x5a };
        let token = seal_state(&env, &claims(1_000_000)).await.unwrap();
        let other = FakeKek { key: 0x5b };
        // Fails closed under a different key. (The real `LocalKek` AES-256-GCM rejects it at the AEAD
        // tag → `Unseal`; this XOR `FakeKek` is not authenticated, so a wrong key garbles the
        // plaintext and it fails at the domain-tag check instead — still an `Err`, still no tenant.
        // The server-side ≥2-tenant gate exercises the real-AEAD wrong-key path.)
        assert!(
            unseal_state(&other, &token, 1_000_010, "acme", "console")
                .await
                .is_err(),
            "a token sealed under a different key must not open"
        );
    }

    #[tokio::test]
    async fn a_tampered_token_fails_closed() {
        let env = FakeKek { key: 0x5a };
        let token = seal_state(&env, &claims(1_000_000)).await.unwrap();
        // Flip a character in the middle of the base64 body.
        let mut bytes = token.into_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(
            unseal_state(&env, &tampered, 1_000_010, "acme", "console")
                .await
                .is_err(),
            "a tampered token must fail closed"
        );
    }

    #[tokio::test]
    async fn a_wrong_site_or_project_fails_closed() {
        let env = FakeKek { key: 0x5a };
        let token = seal_state(&env, &claims(1_000_000)).await.unwrap();
        // Right project, WRONG site.
        assert_eq!(
            unseal_state(&env, &token, 1_000_010, "acme", "other-site").await,
            Err(SealedStateError::BindingMismatch)
        );
        // WRONG project, right site.
        assert_eq!(
            unseal_state(&env, &token, 1_000_010, "other-proj", "console").await,
            Err(SealedStateError::BindingMismatch)
        );
    }

    #[tokio::test]
    async fn an_expired_token_fails_closed() {
        let env = FakeKek { key: 0x5a };
        let now = 1_000_000;
        let token = seal_state(&env, &claims(now)).await.unwrap(); // ttl 300
        assert_eq!(
            unseal_state(&env, &token, now + 301, "acme", "console").await,
            Err(SealedStateError::Expired)
        );
    }

    #[tokio::test]
    async fn an_over_long_lifetime_is_refused_at_both_ends() {
        let env = FakeKek { key: 0x5a };
        let now = 1_000_000;
        // A hand-built claims set with an over-long window is refused at seal.
        let long = SealedStateClaims {
            exp: now + MAX_STATE_TTL_SECS + 1,
            ..claims(now)
        };
        assert_eq!(
            seal_state(&env, &long).await,
            Err(SealedStateError::BadLifetime)
        );
        // mint_claims clamps, so a huge request still seals within the ceiling.
        let clamped = mint_claims("acme", "console", "firm-x", None, None, u64::MAX, now);
        assert_eq!(clamped.exp - clamped.iat, MAX_STATE_TTL_SECS);
        let token = seal_state(&env, &clamped).await.unwrap();
        assert!(
            unseal_state(&env, &token, now + 10, "acme", "console")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_secrets_at_rest_blob_is_not_a_state_token() {
        // A blob sealed under the SAME KEK but WITHOUT the sealed-state magic (what the secret store
        // produces) must not be misread as a state token — domain separation.
        let env = FakeKek { key: 0x5a };
        use base64::Engine as _;
        let secret_blob = env.wrap(b"an-oauth-client-secret").await.unwrap();
        let as_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_blob);
        assert_eq!(
            unseal_state(&env, &as_token, 1_000_000, "acme", "console").await,
            Err(SealedStateError::BadMagic)
        );
    }

    // ---- mutation-sensitivity (anti-hollow): each seam, when armed, turns a fail-closed check GREEN,
    // proving the check is load-bearing. These run only under cfg(test). ----

    #[tokio::test]
    async fn mutation_skip_binding_makes_cross_site_resolve_green() {
        let env = FakeKek { key: 0x5a };
        let token = seal_state(&env, &claims(1_000_000)).await.unwrap();
        // Baseline: wrong site fails closed.
        assert!(
            unseal_state(&env, &token, 1_000_010, "acme", "other-site")
                .await
                .is_err()
        );
        // Armed: the binding check is neutered → the wrong-site seal now resolves (RED gate).
        // SAFETY: cfg(test) only; serialized via a mutex to avoid cross-test env races.
        let _g = MUT.lock().unwrap();
        // SAFETY: test-only env var; serialized by MUT.
        unsafe { std::env::set_var("BOATRAMP_SEALEDSTATE_MUTATION", "skip_binding") };
        let leaked = unseal_state(&env, &token, 1_000_010, "acme", "other-site").await;
        // SAFETY: test-only env var; serialized by MUT.
        unsafe { std::env::remove_var("BOATRAMP_SEALEDSTATE_MUTATION") };
        assert!(
            leaked.is_ok(),
            "neutering the binding check must make a cross-site seal resolve (the gate is live)"
        );
    }

    #[tokio::test]
    async fn mutation_skip_exp_makes_expired_resolve_green() {
        let env = FakeKek { key: 0x5a };
        let now = 1_000_000;
        let token = seal_state(&env, &claims(now)).await.unwrap();
        assert!(
            unseal_state(&env, &token, now + 301, "acme", "console")
                .await
                .is_err()
        );
        let _g = MUT.lock().unwrap();
        // SAFETY: test-only env var; serialized by MUT.
        unsafe { std::env::set_var("BOATRAMP_SEALEDSTATE_MUTATION", "skip_exp") };
        let stale = unseal_state(&env, &token, now + 301, "acme", "console").await;
        // SAFETY: test-only env var; serialized by MUT.
        unsafe { std::env::remove_var("BOATRAMP_SEALEDSTATE_MUTATION") };
        assert!(
            stale.is_ok(),
            "neutering the expiry check must make an expired seal resolve (the gate is live)"
        );
    }

    /// Serializes the env-var mutation tests (process-global env).
    static MUT: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
