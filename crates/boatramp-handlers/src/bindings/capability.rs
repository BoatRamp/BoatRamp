//! The `capability` capability host binding: a guest **mints a fleet-signed target capability**
//! (`boatramp:handlers/capability`, PLAN-delegable-capabilities).
//!
//! The primitive is object-capability delegation: a project attenuates a bounded slice of its OWN
//! authority into a signed bearer it can hand to a third party (an embed/share/handoff client). The
//! token names a target tenant `B`, a public subset, and an opaque app-context (e.g. a per-client
//! `sub`), and is redeemable **only at the minting project** (the audience is host-forced) — over
//! that project's own data.
//!
//! Where the attenuation is enforced (the load-bearing split): the CEILING lives at **redeem**
//! (`resolve_target_via` binds `audience == project`, requires the capability's subset to match an
//! operator-approved target-eligible route's `public`, and takes the write-allowlist from the route —
//! so a token is inert wherever no matching `via:[capability]` route is opened). This binding — the
//! MINT side — enforces only: **deny-by-default** (an ungranted guest / posture-off has no binding and
//! `mint` returns `access-denied`), **audience host-forcing** (the guest never names the audience —
//! the controller stamps this project), **the TTL clamp** to the operator ceiling, and the opaque
//! app-context **size bounds**. The guest never sees the fleet signing key.

use std::collections::BTreeMap;
use std::sync::Arc;

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/capability-host",
        async: {
            only_imports: ["mint"],
        },
    });
}

use generated::boatramp::handlers::{capability_minter, capability_types};

/// The host mint seam: sign a target capability for `target_tenant`, redeemable **only** at
/// `project` (the audience the caller has already host-forced), scoped to `public_subset`, carrying
/// the opaque `app_context`, living `ttl_secs` (already clamped by the binding). Returns the encoded
/// token or an error string. The concrete implementation lives in the server (it holds the fleet
/// [`Signer`](boatramp_core::cose::Signer)); this seam keeps the binding testable with a fake.
#[async_trait::async_trait]
pub trait CapabilityMinter: Send + Sync {
    async fn mint(
        &self,
        project: &str,
        target_tenant: &str,
        public_subset: &str,
        app_context: &BTreeMap<String, String>,
        ttl_secs: u64,
    ) -> Result<String, String>;
}

/// A per-project `capability` grant: the owning project (host-stamped at bind — the guest never names
/// it, so a minted token's audience is intrinsically this project), the shared minter, and the
/// operator's max TTL ceiling (R5). `None` in [`Bindings`](super::Bindings) = not granted.
#[derive(Clone)]
pub struct CapabilityBinding {
    pub(crate) project: String,
    pub(crate) minter: Arc<dyn CapabilityMinter>,
    pub(crate) max_ttl_secs: u64,
}

/// The maximum number of app-context entries a single mint may carry (mirrors the host-side bound in
/// `boatramp_core::cose`; re-checked there authoritatively). Rejecting early gives the guest a clear
/// `invalid-request` rather than an opaque `failed`.
const MAX_APP_CONTEXT_ENTRIES: usize = 16;
/// The maximum total size (keys + values) of a mint's app-context, in bytes (mirrors cose).
const MAX_APP_CONTEXT_BYTES: usize = 4096;

/// Per-invocation view over the (optional) capability grant.
pub struct CapabilityHost<'a> {
    binding: Option<&'a CapabilityBinding>,
}

impl<'a> CapabilityHost<'a> {
    /// Build a view; `None` means the capability was not granted.
    pub fn new(binding: Option<&'a CapabilityBinding>) -> Self {
        Self { binding }
    }
}

impl capability_minter::Host for CapabilityHost<'_> {
    async fn mint(
        &mut self,
        request: capability_types::MintRequest,
    ) -> Result<String, capability_types::MintError> {
        use capability_types::MintError as E;
        let Some(binding) = self.binding else {
            return Err(E::AccessDenied);
        };
        // A zero ceiling means minting is disabled by posture even if a binding slipped through.
        if binding.max_ttl_secs == 0 {
            return Err(E::AccessDenied);
        }
        // Shape validation (fail-closed on an obviously-bad request).
        if request.target_tenant.trim().is_empty() {
            return Err(E::InvalidRequest("target-tenant is required".to_string()));
        }
        if request.public_subset.trim().is_empty() {
            return Err(E::InvalidRequest("public-subset is required".to_string()));
        }
        if request.ttl_seconds == 0 {
            return Err(E::InvalidRequest(
                "ttl-seconds must be greater than zero".to_string(),
            ));
        }
        // R6: bound the opaque app-context (defense in depth — cose re-checks authoritatively).
        if request.app_context.len() > MAX_APP_CONTEXT_ENTRIES {
            return Err(E::InvalidRequest(format!(
                "app-context has {} entries (max {MAX_APP_CONTEXT_ENTRIES})",
                request.app_context.len()
            )));
        }
        let mut app_context = BTreeMap::new();
        let mut bytes = 0usize;
        for (k, v) in &request.app_context {
            bytes += k.len() + v.len();
            app_context.insert(k.clone(), v.clone());
        }
        if bytes > MAX_APP_CONTEXT_BYTES {
            return Err(E::InvalidRequest(format!(
                "app-context is {bytes} bytes (max {MAX_APP_CONTEXT_BYTES})"
            )));
        }
        // R5: clamp the requested TTL to the operator ceiling — never above it.
        let ttl = request.ttl_seconds.min(binding.max_ttl_secs);
        // R1: the audience is `binding.project` — host-stamped at bind, never guest-named — so the
        // minted token is redeemable ONLY at this project.
        binding
            .minter
            .mint(
                &binding.project,
                request.target_tenant.trim(),
                request.public_subset.trim(),
                &app_context,
                ttl,
            )
            .await
            .map_err(E::Failed)
    }
}

/// Add the `capability-minter` interface to `linker`, resolving the per-invocation
/// [`CapabilityHost`] view via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> CapabilityHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    capability_minter::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::capability_minter::Host;
    use super::*;
    use std::sync::Mutex;

    /// One recorded mint call: (project, target_tenant, public_subset, app_context, ttl_secs).
    type MintCall = (String, String, String, BTreeMap<String, String>, u64);

    /// Records every mint call verbatim (so a test can assert the host-forced audience + the clamp).
    #[derive(Default)]
    struct FakeMinter {
        calls: Mutex<Vec<MintCall>>,
    }
    #[async_trait::async_trait]
    impl CapabilityMinter for FakeMinter {
        async fn mint(
            &self,
            project: &str,
            target_tenant: &str,
            public_subset: &str,
            app_context: &BTreeMap<String, String>,
            ttl_secs: u64,
        ) -> Result<String, String> {
            self.calls.lock().unwrap().push((
                project.to_string(),
                target_tenant.to_string(),
                public_subset.to_string(),
                app_context.clone(),
                ttl_secs,
            ));
            Ok(format!("token-for-{target_tenant}"))
        }
    }

    fn binding(minter: Arc<FakeMinter>, max_ttl_secs: u64) -> CapabilityBinding {
        CapabilityBinding {
            project: "shop".into(),
            minter,
            max_ttl_secs,
        }
    }

    fn request() -> capability_types::MintRequest {
        capability_types::MintRequest {
            target_tenant: "tenant_B".into(),
            public_subset: "storefront".into(),
            app_context: vec![("sub".into(), "client-42".into())],
            ttl_seconds: 300,
        }
    }

    #[tokio::test]
    async fn ungranted_mint_is_denied() {
        let mut host = CapabilityHost::new(None);
        assert!(matches!(
            host.mint(request()).await.unwrap_err(),
            capability_types::MintError::AccessDenied
        ));
    }

    #[tokio::test]
    async fn mint_forces_the_project_audience_and_passes_the_context() {
        let minter = Arc::new(FakeMinter::default());
        let b = binding(minter.clone(), 3600);
        let mut host = CapabilityHost::new(Some(&b));
        let token = host.mint(request()).await.unwrap();
        assert_eq!(token, "token-for-tenant_B");
        let calls = minter.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (project, tenant, subset, ctx, ttl) = &calls[0];
        // The audience is the binding's project — the guest never named it (R1).
        assert_eq!(project, "shop");
        assert_eq!(tenant, "tenant_B");
        assert_eq!(subset, "storefront");
        assert_eq!(ctx.get("sub").map(String::as_str), Some("client-42"));
        assert_eq!(*ttl, 300);
    }

    #[tokio::test]
    async fn ttl_is_clamped_to_the_operator_ceiling() {
        let minter = Arc::new(FakeMinter::default());
        let b = binding(minter.clone(), 600); // ceiling below the request
        let mut host = CapabilityHost::new(Some(&b));
        let mut req = request();
        req.ttl_seconds = 100_000;
        host.mint(req).await.unwrap();
        assert_eq!(
            minter.calls.lock().unwrap()[0].4,
            600,
            "ttl clamped to the ceiling"
        );
    }

    #[tokio::test]
    async fn a_zero_ceiling_denies_even_a_present_binding() {
        let minter = Arc::new(FakeMinter::default());
        let b = binding(minter.clone(), 0); // minting disabled by posture
        let mut host = CapabilityHost::new(Some(&b));
        assert!(matches!(
            host.mint(request()).await.unwrap_err(),
            capability_types::MintError::AccessDenied
        ));
        assert!(minter.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_requests_and_oversized_context_are_refused() {
        let minter = Arc::new(FakeMinter::default());
        let b = binding(minter.clone(), 3600);
        let mut host = CapabilityHost::new(Some(&b));
        for mutate in [
            (|r: &mut capability_types::MintRequest| r.target_tenant = String::new())
                as fn(&mut capability_types::MintRequest),
            |r| r.public_subset = String::new(),
            |r| r.ttl_seconds = 0,
            |r| {
                r.app_context = (0..MAX_APP_CONTEXT_ENTRIES + 1)
                    .map(|i| (format!("k{i}"), "v".into()))
                    .collect();
            },
            |r| r.app_context = vec![("big".into(), "x".repeat(MAX_APP_CONTEXT_BYTES + 1))],
        ] {
            let mut req = request();
            mutate(&mut req);
            assert!(matches!(
                host.mint(req).await.unwrap_err(),
                capability_types::MintError::InvalidRequest(_)
            ));
        }
        assert!(
            minter.calls.lock().unwrap().is_empty(),
            "nothing bad was minted"
        );
    }
}
