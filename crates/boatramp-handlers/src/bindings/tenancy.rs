//! The `tenancy` capability host binding: an emitter **presents a tenant credential it verified
//! in-guest** for the HOST to re-verify and stamp onto the async lane (`boatramp:handlers/tenancy`,
//! PLAN-first-adopter-cutover-gaps Gap 3).
//!
//! The problem it solves: `signed_context` resolves the async-lane own-tenant on the CONSUMER, but
//! only if the PRODUCER stamped a tenant onto the message — and the host stamps only a tenant IT
//! resolved (a request bearer / routed domain). An emitter whose tenant authority is verified
//! in-guest (an app JWT in a POST body, a portal cookie's bearer) leaves the host with no fact to
//! stamp. `present-token` closes that gap **without handing tenancy authority to the guest**: the
//! guest presents the credential; the HOST re-verifies it against the component's operator-declared
//! `token_claims` + `token` source (the [`ProducerContextSource`] seam, implemented in the server),
//! extracts the tenant, and host-seals it into the shared producer-context cell so every subsequent
//! publish carries it. The guest never NAMES a tenant — it can only cause a stamp for a tenant it
//! holds a validly-signed token for from the configured issuer. This is the async-lane analog of the
//! request-path `token` source; the only new degree of freedom is WHERE the token rides.
//!
//! Deny-by-default: an ungranted guest (no binding) or a token that fails verification stamps
//! nothing (the `present-token` call errors and the producer context is left untouched).

use std::sync::Arc;

use super::messaging::ProducerContext;

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/tenancy-host",
        async: {
            only_imports: ["present-token"],
        },
    });
}

use generated::boatramp::handlers::tenancy as tenancy_iface;

/// The host verify-and-seal seam: re-verify a guest-PRESENTED credential against the emitting
/// component's declared token config, extract its tenant claim, and return a host-**sealed**
/// producer-context envelope for that tenant (the same envelope `mint_producer_context` produces
/// from a host-resolved principal). `Err` ⇒ the token didn't verify / carried no tenant / no
/// verifier configured. The concrete impl lives in the server (it holds the fleet `Signer` + the
/// JWKS verifier + the component's `token_claims`); this seam keeps the binding testable with a fake.
#[async_trait::async_trait]
pub trait ProducerContextSource: Send + Sync {
    async fn seal_presented(&self, token: &str) -> Result<String, String>;
}

/// A per-invocation `tenancy` grant: the verify-and-seal seam + the SHARED producer-context cell it
/// updates on a successful `present-token` (the same cell the `messaging` binding reads at publish).
/// `None` in [`Bindings`](super::Bindings) = not granted (`present-token` ⇒ `access-denied`).
#[derive(Clone)]
pub struct TenancyBinding {
    pub(crate) source: Arc<dyn ProducerContextSource>,
    pub(crate) context: ProducerContext,
}

/// The host-verified sealed principal for one invocation (PLAN-async-persona): the producer's
/// own-tenant plus (optionally) the host-verified caller persona/role, exactly as the host verified
/// them from the durable `signed_context` envelope (`br_ctx` + `br_persona`). Set on `Bindings` ONLY
/// on the consumer / durable async lane — where this invocation's context came from a verified seal —
/// and propagated onto a `graphql::run` sub-fetch alongside the caller tenant. NEVER guest-supplied;
/// the WIT `sealed-principal()` import returns it verbatim (or `none` on the sync/seal-less lane).
/// Shared across WIT + trait per the UX naming condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedPrincipal {
    /// An ordinary TENANT principal: the producer's host-sealed own-tenant + optional persona.
    Tenant {
        /// The producer's host-sealed own-tenant.
        tenant: String,
        /// The caller's host-verified persona/role, or `None` when none was sealed / usable.
        persona: Option<String>,
    },
    /// A SYSTEM principal (construens cron-system-principal): a platform/super-admin with NO tenant —
    /// there is structurally no tenant to read, so a consumer that needs one must handle this arm.
    System {
        /// The caller's host-verified persona/role, or `None`.
        persona: Option<String>,
    },
}

impl SealedPrincipal {
    /// The sealed own-tenant, or `None` for a system principal (which has none).
    pub fn tenant(&self) -> Option<&str> {
        match self {
            Self::Tenant { tenant, .. } => Some(tenant),
            Self::System { .. } => None,
        }
    }
    /// The host-verified persona/role (either class), or `None`.
    pub fn persona(&self) -> Option<&str> {
        match self {
            Self::Tenant { persona, .. } | Self::System { persona } => persona.as_deref(),
        }
    }
    /// Whether this is the system (no-tenant) class.
    pub fn is_system(&self) -> bool {
        matches!(self, Self::System { .. })
    }
}

/// Per-invocation view over the (optional) `tenancy` grant AND the (optional) host-verified sealed
/// principal for this invocation. The two are independent: `present-token` needs the grant; the
/// read-only `sealed-principal()` needs only the host-verified seal (no grant), returning `none`
/// whenever there is no verified seal (the sync/HTTP lane).
pub struct TenancyHost<'a> {
    binding: Option<&'a TenancyBinding>,
    sealed_principal: Option<&'a SealedPrincipal>,
}

impl<'a> TenancyHost<'a> {
    /// Build a view; `binding = None` ⇒ the `present-token` capability was not granted;
    /// `sealed_principal = None` ⇒ this invocation carries no host-verified seal (`sealed-principal()`
    /// returns `none`).
    pub fn new(
        binding: Option<&'a TenancyBinding>,
        sealed_principal: Option<&'a SealedPrincipal>,
    ) -> Self {
        Self {
            binding,
            sealed_principal,
        }
    }
}

impl tenancy_iface::Host for TenancyHost<'_> {
    async fn present_token(&mut self, token: String) -> Result<(), tenancy_iface::TenancyError> {
        use tenancy_iface::TenancyError as E;
        let Some(binding) = self.binding else {
            return Err(E::AccessDenied);
        };
        if token.trim().is_empty() {
            return Err(E::InvalidToken(
                "an empty token cannot be presented".to_string(),
            ));
        }
        // The HOST re-verifies the presented credential (signature / issuer / audience / expiry)
        // against the component's declared config and extracts the tenant — the guest names nothing.
        match binding.source.seal_presented(&token).await {
            Ok(sealed) => {
                // Host-seal succeeded: stamp it onto the shared cell so every subsequent publish in
                // this invocation carries it. A poisoned lock ⇒ fail closed (leave nothing stamped).
                match binding.context.lock() {
                    Ok(mut guard) => {
                        *guard = Some(sealed);
                        Ok(())
                    }
                    Err(_) => Err(E::Failed("producer context unavailable".to_string())),
                }
            }
            Err(err) => Err(E::InvalidToken(err)),
        }
    }

    /// Return the host-verified sealed principal for THIS invocation, or `none` (the WIT func is
    /// `current-principal`; the returned type is the `sealed-principal` record). It is present ONLY
    /// when the invocation's context came from a verified `signed_context` seal (the consumer /
    /// durable async lane) — set host-side from `verify_context_full`. On the sync/HTTP lane, or when
    /// the seal is absent/expired/invalid, the host set no sealed principal and this returns `none`.
    /// The value is exactly what the host verified (guest-blind); the guest can neither name nor
    /// supply it. Synchronous — a pure read of the per-invocation binding.
    fn current_principal(&mut self) -> Option<tenancy_iface::SealedPrincipal> {
        self.sealed_principal.map(|p| match p {
            SealedPrincipal::Tenant { tenant, persona } => {
                tenancy_iface::SealedPrincipal::Tenant(tenancy_iface::TenantPrincipal {
                    tenant: tenant.clone(),
                    persona: persona.clone(),
                })
            }
            SealedPrincipal::System { persona } => {
                tenancy_iface::SealedPrincipal::System(tenancy_iface::SystemPrincipal {
                    persona: persona.clone(),
                })
            }
        })
    }
}

/// Add the `tenancy` interface to `linker`, resolving the per-invocation [`TenancyHost`] via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> TenancyHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    tenancy_iface::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::tenancy_iface::{Host, TenancyError};
    use super::*;

    /// A fake seam: seals a deterministic envelope for a non-empty token when `ok`, else rejects —
    /// modelling the server's real verify-then-mint without a JWKS/signer.
    struct FakeSource {
        ok: bool,
    }

    #[async_trait::async_trait]
    impl ProducerContextSource for FakeSource {
        async fn seal_presented(&self, token: &str) -> Result<String, String> {
            if self.ok && !token.is_empty() {
                Ok(format!("sealed:{token}"))
            } else {
                Err("token did not verify".to_string())
            }
        }
    }

    fn cell() -> ProducerContext {
        Arc::new(std::sync::Mutex::new(None))
    }

    #[tokio::test]
    async fn present_token_host_seals_into_the_shared_cell() {
        let ctx = cell();
        let binding = TenancyBinding {
            source: Arc::new(FakeSource { ok: true }),
            context: ctx.clone(),
        };
        let mut host = TenancyHost::new(Some(&binding), None);
        host.present_token("jwt".into()).await.unwrap();
        // The host-sealed envelope is now in the cell the messaging binding reads at publish.
        assert_eq!(ctx.lock().unwrap().clone(), Some("sealed:jwt".to_string()));
    }

    #[tokio::test]
    async fn present_token_is_access_denied_when_ungranted() {
        let mut host = TenancyHost::new(None, None);
        assert!(matches!(
            host.present_token("jwt".into()).await,
            Err(TenancyError::AccessDenied)
        ));
    }

    #[test]
    fn sealed_principal_is_none_without_a_verified_seal_and_verbatim_with_one() {
        // No seal (the sync/HTTP lane, or a seal-less/invalid consumer message) ⇒ `none`.
        let mut host = TenancyHost::new(None, None);
        assert!(host.current_principal().is_none());

        // A host-verified TENANT seal ⇒ the exact `{tenant, persona}` the host verified, verbatim. It
        // needs NO `present-token` grant (the binding is `None` here) — a pure read of the seal.
        let sealed = SealedPrincipal::Tenant {
            tenant: "acme".into(),
            persona: Some("Integration".into()),
        };
        let mut host = TenancyHost::new(None, Some(&sealed));
        match host
            .current_principal()
            .expect("a verified seal is present")
        {
            tenancy_iface::SealedPrincipal::Tenant(t) => {
                assert_eq!(t.tenant, "acme");
                assert_eq!(t.persona.as_deref(), Some("Integration"));
            }
            other => panic!("expected a tenant principal, got {other:?}"),
        }

        // A seal with a tenant but no persona (no `token_persona_claim` configured) ⇒ persona `none`,
        // so a `role(…)`-gated field fails closed on the trusting side.
        let tenant_only = SealedPrincipal::Tenant {
            tenant: "acme".into(),
            persona: None,
        };
        let mut host = TenancyHost::new(None, Some(&tenant_only));
        match host
            .current_principal()
            .expect("a verified seal is present")
        {
            tenancy_iface::SealedPrincipal::Tenant(t) => {
                assert_eq!(t.tenant, "acme");
                assert_eq!(t.persona, None);
            }
            other => panic!("expected a tenant principal, got {other:?}"),
        }

        // A SYSTEM seal ⇒ the `system` arm, carrying only the persona and NO tenant (construens
        // cron-system-principal). There is structurally no tenant to read.
        let system = SealedPrincipal::System {
            persona: Some("super_admin".into()),
        };
        let mut host = TenancyHost::new(None, Some(&system));
        match host
            .current_principal()
            .expect("a verified seal is present")
        {
            tenancy_iface::SealedPrincipal::System(s) => {
                assert_eq!(s.persona.as_deref(), Some("super_admin"));
            }
            other => panic!("expected a system principal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn present_token_fails_closed_and_stamps_nothing_on_a_bad_token() {
        let ctx = cell();
        let binding = TenancyBinding {
            source: Arc::new(FakeSource { ok: false }),
            context: ctx.clone(),
        };
        let mut host = TenancyHost::new(Some(&binding), None);
        // A token the host can't verify ⇒ invalid-token, and the cell is left untouched.
        assert!(matches!(
            host.present_token("jwt".into()).await,
            Err(TenancyError::InvalidToken(_))
        ));
        assert!(ctx.lock().unwrap().is_none());
        // An empty token is rejected before the seam even runs.
        assert!(matches!(
            host.present_token(String::new()).await,
            Err(TenancyError::InvalidToken(_))
        ));
    }
}
