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

/// Per-invocation view over the (optional) `tenancy` grant.
pub struct TenancyHost<'a> {
    binding: Option<&'a TenancyBinding>,
}

impl<'a> TenancyHost<'a> {
    /// Build a view; `None` means the capability was not granted.
    pub fn new(binding: Option<&'a TenancyBinding>) -> Self {
        Self { binding }
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
        let mut host = TenancyHost::new(Some(&binding));
        host.present_token("jwt".into()).await.unwrap();
        // The host-sealed envelope is now in the cell the messaging binding reads at publish.
        assert_eq!(ctx.lock().unwrap().clone(), Some("sealed:jwt".to_string()));
    }

    #[tokio::test]
    async fn present_token_is_access_denied_when_ungranted() {
        let mut host = TenancyHost::new(None);
        assert!(matches!(
            host.present_token("jwt".into()).await,
            Err(TenancyError::AccessDenied)
        ));
    }

    #[tokio::test]
    async fn present_token_fails_closed_and_stamps_nothing_on_a_bad_token() {
        let ctx = cell();
        let binding = TenancyBinding {
            source: Arc::new(FakeSource { ok: false }),
            context: ctx.clone(),
        };
        let mut host = TenancyHost::new(Some(&binding));
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
