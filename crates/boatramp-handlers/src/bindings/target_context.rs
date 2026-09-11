//! The `target-context` capability host binding (`boatramp:handlers/target-context`,
//! PLAN-delegable-capabilities Stage D): a resolver reads back the opaque app-context a verified
//! TARGET **capability** carried (its `br_app` claim — e.g. a per-client `sub`).
//!
//! This is the read-back half of the delegable-capability primitive. Under a `via:[capability]`
//! target route the host verifies the capability once and confines the query to `tenant = B`; the
//! **per-client** filter (`client_id = sub`) stays in the guest's own query (within-tenant authz, not
//! a tenancy axis). This binding is how the guest recovers `sub`: the capability's opaque, app-authored
//! context, carried with integrity on [`HostTenancy`](crate::tenant::HostTenancy) and returned verbatim.
//!
//! Two invariants make it safe to expose at all: (1) the host-forced target tenant `B` is **never**
//! returned — only the app-authored context round-trips, so guest-blindness for *host* facts is
//! preserved; and (2) the content is the guest's OWN signed data (the issuer minted it), so no grant
//! is needed and there is nothing to leak. The list is empty for any non-capability principal
//! (own / session / domain / handle).

/// One `(key, value)` pair of the resolved capability's app-context (the WIT `list<tuple<..>>`).
pub type ContextPair = (String, String);

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/target-context-host",
    });
}

use generated::boatramp::handlers::target_context;

/// Per-invocation view: the resolved capability's app-context pairs (already cloned out of the
/// invocation's [`HostTenancy`](crate::tenant::HostTenancy); empty when there is no capability target).
pub struct TargetContextHost {
    pairs: Vec<ContextPair>,
}

impl TargetContextHost {
    /// Build a view from the invocation's resolved app-context pairs.
    pub fn new(pairs: Vec<ContextPair>) -> Self {
        Self { pairs }
    }
}

impl target_context::Host for TargetContextHost {
    fn get(&mut self) -> Vec<(String, String)> {
        self.pairs.clone()
    }
}

/// Add the `target-context` interface to `linker`, resolving the per-invocation [`TargetContextHost`]
/// view via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> TargetContextHost + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    target_context::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::target_context::Host;
    use super::*;

    #[test]
    fn empty_when_no_capability_target() {
        let mut host = TargetContextHost::new(Vec::new());
        assert!(host.get().is_empty());
    }

    #[test]
    fn returns_the_app_context_pairs_verbatim() {
        let mut host = TargetContextHost::new(vec![
            ("sub".to_string(), "client-42".to_string()),
            ("plan".to_string(), "pro".to_string()),
        ]);
        let got = host.get();
        assert_eq!(got.len(), 2);
        assert!(got.contains(&("sub".to_string(), "client-42".to_string())));
        assert!(got.contains(&("plan".to_string(), "pro".to_string())));
    }
}
