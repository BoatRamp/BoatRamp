//! The **`sealed-state`** host binding (`boatramp:handlers/sealed-state`, PLAN-sealed-state-source):
//! a granted guest MINTS an AEAD-sealed state token at login-start, bound to THIS invocation's
//! host-resolved **tenant + project + site**. A later PRE-AUTH SSO callback — which carries no bearer
//! and no routed-tenant domain — then resolves that tenant via the `sealed-state` tenancy source
//! ([`boatramp_core::sealed_state`] + `boatramp_server::tenant_resolve`).
//!
//! # The security model (why a guest can never seal another tenant's state)
//!
//! 1. **The tenant/project/site are host-supplied, never guest-supplied.** The WIT surface has no
//!    tenant/project/site parameter. The host holds [`resolved_tenant`](SealedStateMintBinding::resolved_tenant)
//!    — the own-`tenant` fact the SQL scope injector resolves — plus the host-stamped project+site,
//!    and seals exactly those. A guest can neither name, override, nor forge them (mirrors the
//!    `tenant-secrets` / `blob-upload` host-forcing crux).
//! 2. **Deny-by-default.** No grant ⇒ no binding ([`SealedStateMintHost::new(None)`]) ⇒ every call
//!    returns `access-denied`.
//! 3. **No single resolved tenant ⇒ `no-resolved-tenant`; no single resolved site ⇒
//!    `no-resolved-site`** — BEFORE any sealing. An `all`/anonymous/unscoped login-start has no
//!    tenant to seal; a site-less invocation has no site to bind. The binding fails closed rather
//!    than seal a project-wide or "first" tenant / an unbound site.
//! 4. **AEAD, host-keyed.** The seal uses the node's `[secrets]` key envelope (the SAME AES-256-GCM
//!    AEAD the per-tenant secret store uses). The guest never sees the key; the tenant is opaque to
//!    the browser and tamper-evident. The lifetime is clamped host-side ([`mint_claims`] →
//!    [`MAX_STATE_TTL_SECS`](boatramp_core::sealed_state::MAX_STATE_TTL_SECS)).

use std::sync::Arc;

use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::sealed_state;

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/sealed-state-host",
        imports: { default: async },
    });
}

use generated::boatramp::handlers::{sealed_state as wit_sealed_state, sealed_state_types};

/// Why a sealed-state mint was refused (host-native; mapped 1:1 to the WIT `mint-error`). Public so a
/// host-side live gate can drive the real seal WITHOUT a wasm guest, and pattern-match the refusal
/// without depending on the generated WIT type. Mirrors the `tenant-secrets` /
/// `blob-upload` refusal pattern. Carries no key material and no tenant value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedStateMintRefused {
    /// The `sealed-state:mint` capability was not granted — deny-by-default.
    AccessDenied,
    /// This invocation has no single resolved tenant (an `all`/anonymous/unscoped login-start) — fail
    /// closed here BEFORE any sealing, never a project-wide or "first" tenant.
    NoResolvedTenant,
    /// This invocation has no single resolved site — the host cannot bind the seal to a site.
    NoResolvedSite,
    /// The seal failed (an envelope error, or a bad lifetime). Generic detail (internals logged
    /// host-side, never surfaced).
    Failed(String),
}

impl SealedStateMintRefused {
    /// Map a host-native refusal to the WIT `mint-error` the guest sees.
    fn into_wit(self) -> sealed_state_types::MintError {
        match self {
            Self::AccessDenied => sealed_state_types::MintError::AccessDenied,
            Self::NoResolvedTenant => sealed_state_types::MintError::NoResolvedTenant,
            Self::NoResolvedSite => sealed_state_types::MintError::NoResolvedSite,
            Self::Failed(m) => sealed_state_types::MintError::Failed(m),
        }
    }
}

/// A per-invocation `sealed-state` grant: the host `[secrets]` key envelope, the host-stamped project,
/// THIS invocation's host-resolved site + own-tenant, and whether the `mint` right was granted.
///
/// Built by the server's `build_bindings` from the component's grants + the resolved own-tenant fact
/// + the resolved site. `resolved_tenant == None` ⇒ `no-resolved-tenant`; `site == None` ⇒
/// `no-resolved-site`.
#[derive(Clone)]
pub struct SealedStateMintBinding {
    /// The node's `[secrets]` key envelope (the SAME AEAD the per-tenant secret store seals with).
    pub(crate) env: Arc<dyn KeyEnvelope>,
    /// The owning project (host-stamped; the guest never names it).
    pub(crate) project: String,
    /// THIS invocation's host-resolved site (host-stamped). `None` ⇒ every call is `no-resolved-site`.
    pub(crate) site: Option<String>,
    /// THIS invocation's host-resolved own-tenant (the own-`tenant` scope fact). `None` ⇒ every call
    /// is `no-resolved-tenant`.
    pub(crate) resolved_tenant: Option<String>,
    /// Whether the `sealed-state:mint` right was granted — gates `mint`.
    pub(crate) can_mint: bool,
}

impl SealedStateMintBinding {
    /// Host-native `mint` (the whole seal path, applying the SAME right / resolved-tenant / resolved-
    /// site gates the WIT `Host::mint` applies). Public so a host-side live gate can drive the real
    /// AEAD seal without a wasm guest; the WIT layer delegates here. Returns the opaque `state`
    /// string, or the host-native [`SealedStateMintRefused`].
    pub async fn mint(
        &self,
        pkce: Option<String>,
        nonce: Option<String>,
        ttl_seconds: u64,
    ) -> Result<String, SealedStateMintRefused> {
        if !self.can_mint {
            return Err(SealedStateMintRefused::AccessDenied);
        }
        // Both facts are checked BEFORE any sealing, so an unscoped / site-less invocation never
        // produces a token.
        let tenant = self
            .resolved_tenant
            .as_deref()
            .ok_or(SealedStateMintRefused::NoResolvedTenant)?;
        let site = self
            .site
            .as_deref()
            .ok_or(SealedStateMintRefused::NoResolvedSite)?;
        // The host FORCES project/site/tenant and clamps the TTL (inside `mint_claims`); the guest's
        // only inputs are the opaque pkce/nonce and the requested ttl. A guest can never seal a
        // different tenant — there is no tenant parameter to influence.
        let claims = sealed_state::mint_claims(
            self.project.as_str(),
            site,
            tenant,
            pkce,
            nonce,
            ttl_seconds,
            boatramp_core::time::now_unix(),
        );
        sealed_state::seal_state(self.env.as_ref(), &claims)
            .await
            .map_err(|e| {
                tracing::warn!(outcome = %e, "sealed-state mint: seal failed");
                SealedStateMintRefused::Failed(e.to_string())
            })
    }
}

/// Per-invocation view over the (optional) `sealed-state` grant. `None` ⇒ not granted
/// (deny-by-default: every call ⇒ `access-denied`).
pub struct SealedStateMintHost<'a> {
    binding: Option<&'a SealedStateMintBinding>,
}

impl<'a> SealedStateMintHost<'a> {
    /// Build a view; `None` means the capability was not granted.
    pub fn new(binding: Option<&'a SealedStateMintBinding>) -> Self {
        Self { binding }
    }
}

impl wit_sealed_state::Host for SealedStateMintHost<'_> {
    async fn mint(
        &mut self,
        request: sealed_state_types::MintRequest,
    ) -> Result<String, sealed_state_types::MintError> {
        // Deny-by-default: no grant ⇒ no binding ⇒ access-denied. The binding then applies the mint
        // right + resolved-tenant + resolved-site gates (all before any sealing).
        match self.binding {
            Some(b) => b
                .mint(request.pkce, request.nonce, request.ttl_seconds)
                .await
                .map_err(SealedStateMintRefused::into_wit),
            None => Err(sealed_state_types::MintError::AccessDenied),
        }
    }
}

/// Add the `sealed-state` interface to `linker`, resolving the per-invocation
/// [`SealedStateMintHost`] via `host`.
struct LinkData;
impl wasmtime::component::HasData for LinkData {
    type Data<'a> = SealedStateMintHost<'a>;
}

pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: fn(&mut T) -> SealedStateMintHost<'_>,
) -> wasmtime::Result<()> {
    wit_sealed_state::add_to_linker::<T, LinkData>(linker, host)
}

#[cfg(test)]
mod tests {
    use super::wit_sealed_state::Host;
    use super::*;
    use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};

    /// A deterministic test envelope (XOR) — enough to exercise the host-forcing gates; the REAL
    /// LocalKek AES-256-GCM round-trip is covered by the server-side ≥2-tenant gate.
    struct XorEnvelope;
    #[async_trait::async_trait]
    impl KeyEnvelope for XorEnvelope {
        async fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(plaintext.iter().map(|b| b ^ 0x5a).collect())
        }
        async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(wrapped.iter().map(|b| b ^ 0x5a).collect())
        }
    }

    fn binding(tenant: Option<&str>, site: Option<&str>, can_mint: bool) -> SealedStateMintBinding {
        SealedStateMintBinding {
            env: Arc::new(XorEnvelope),
            project: "acme".to_string(),
            site: site.map(str::to_owned),
            resolved_tenant: tenant.map(str::to_owned),
            can_mint,
        }
    }

    fn req() -> sealed_state_types::MintRequest {
        sealed_state_types::MintRequest {
            pkce: Some("pkce-verifier".into()),
            nonce: Some("oidc-nonce".into()),
            ttl_seconds: 300,
        }
    }

    #[tokio::test]
    async fn ungranted_mint_is_access_denied() {
        let mut host = SealedStateMintHost::new(None);
        assert!(matches!(
            host.mint(req()).await.unwrap_err(),
            sealed_state_types::MintError::AccessDenied
        ));
    }

    #[tokio::test]
    async fn mint_right_absent_is_access_denied() {
        let b = binding(Some("firm-a"), Some("console"), false);
        let mut host = SealedStateMintHost::new(Some(&b));
        assert!(matches!(
            host.mint(req()).await.unwrap_err(),
            sealed_state_types::MintError::AccessDenied
        ));
    }

    #[tokio::test]
    async fn no_resolved_tenant_fails_closed_before_sealing() {
        let b = binding(None, Some("console"), true);
        let mut host = SealedStateMintHost::new(Some(&b));
        assert!(matches!(
            host.mint(req()).await.unwrap_err(),
            sealed_state_types::MintError::NoResolvedTenant
        ));
    }

    #[tokio::test]
    async fn no_resolved_site_fails_closed_before_sealing() {
        let b = binding(Some("firm-a"), None, true);
        let mut host = SealedStateMintHost::new(Some(&b));
        assert!(matches!(
            host.mint(req()).await.unwrap_err(),
            sealed_state_types::MintError::NoResolvedSite
        ));
    }

    #[tokio::test]
    async fn a_granted_mint_seals_the_hosts_own_tenant_and_round_trips() {
        // The minted token unseals (same XOR env) to the HOST-forced tenant/project/site — the guest
        // supplied none of them, so it is structurally impossible to seal a different tenant.
        let b = binding(Some("firm-a"), Some("console"), true);
        let mut host = SealedStateMintHost::new(Some(&b));
        let token = host.mint(req()).await.unwrap();
        let claims = boatramp_core::sealed_state::unseal_state(
            &XorEnvelope,
            &token,
            boatramp_core::time::now_unix(),
            "acme",
            "console",
        )
        .await
        .expect("the minted token unseals under the same env at the bound project/site");
        assert_eq!(
            claims.tenant, "firm-a",
            "the seal carries the HOST's own tenant"
        );
        assert_eq!(claims.pkce.as_deref(), Some("pkce-verifier"));
        assert_eq!(claims.nonce.as_deref(), Some("oidc-nonce"));
        // The tenant is opaque in the token (not cleartext).
        assert!(!token.contains("firm-a"));
    }

    #[tokio::test]
    async fn the_ttl_is_clamped_host_side() {
        // A guest requesting an absurd TTL still gets a token clamped to the host ceiling.
        let b = binding(Some("firm-a"), Some("console"), true);
        let mut host = SealedStateMintHost::new(Some(&b));
        let token = host
            .mint(sealed_state_types::MintRequest {
                pkce: None,
                nonce: None,
                ttl_seconds: u64::MAX,
            })
            .await
            .unwrap();
        let claims = boatramp_core::sealed_state::unseal_state(
            &XorEnvelope,
            &token,
            boatramp_core::time::now_unix(),
            "acme",
            "console",
        )
        .await
        .unwrap();
        assert_eq!(
            claims.exp - claims.iat,
            boatramp_core::sealed_state::MAX_STATE_TTL_SECS,
            "the host clamps a too-large requested TTL to the ceiling"
        );
    }
}
