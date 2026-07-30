//! The `invoke` host binding: one function calls another **in-process**, the
//! same HTTP-shaped request/response the platform uses to invoke it, without a
//! network round-trip. The engine cannot resolve or run a target itself (that
//! lives a layer up in the server, which owns the function store + metering), so
//! the binding holds an [`Invoker`] the server implements; the host here enforces
//! the *capability*: deny by default, an operator-configured target allowlist
//! (with `*` wildcards), and a call-depth cap so functions cannot invoke in a
//! loop.

use std::sync::Arc;

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/invoke-host",
        async: {
            only_imports: ["invoke"],
        },
    });
}

use generated::boatramp::handlers::{invoke as invoke_iface, invoke_types};

/// The maximum function-to-function call depth. A chain deeper than this is
/// almost certainly an accidental (or adversarial) loop; the host refuses the
/// call with [`invoke_types::Error::LoopDetected`] rather than nest further and
/// exhaust the node. There is no recursion guard anywhere else, so this cap is
/// the whole defense.
pub const MAX_INVOKE_DEPTH: u32 = 8;

/// A buffered request one function makes to another. The wire (WIT) types are
/// converted to this at the boundary so the [`Invoker`] impl (in the server)
/// never sees the generated bindgen types.
#[derive(Debug, Clone)]
pub struct InvokeRequest {
    pub method: String,
    /// Request target the callee sees: path plus any query.
    pub path: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// The callee's buffered response.
#[derive(Debug, Clone)]
pub struct InvokeResponse {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// Why an [`Invoker::invoke`] failed. The host maps these onto the guest-visible
/// `invoke-types::error`; `access-denied` / `target-not-allowed` / `loop-detected`
/// are decided by the host *before* the invoker runs, so they are not here.
#[derive(Debug)]
pub enum InvokeError {
    /// No function is registered under the target name.
    NotFound,
    /// The callee ran but failed (trap, timeout, overload, unavailable, ...).
    Failed(String),
}

/// Resolves and runs a target function. Implemented by the server (which owns the
/// function store, blob storage, quota, and metering); the engine calls back
/// through it. `depth` is the callee's position in the call chain — the impl
/// builds the callee's own invoke grant at this depth so a nested call is capped.
#[async_trait::async_trait]
pub trait Invoker: Send + Sync {
    async fn invoke(
        &self,
        target: &str,
        request: InvokeRequest,
        depth: u32,
    ) -> Result<InvokeResponse, InvokeError>;
}

/// A per-function invoke grant: who can run targets ([`Invoker`]), which target
/// names this function may call (`targets`, `*`-wildcard patterns), and this
/// function's own depth in the call chain (`depth`), so the host can cap the next
/// hop. Cloned per invocation (an `Arc` + small vecs).
#[derive(Clone)]
pub struct InvokeBinding {
    pub(crate) invoker: Arc<dyn Invoker>,
    pub(crate) targets: Vec<String>,
    pub(crate) depth: u32,
}

/// Per-invocation view over the (optional) invoke grant.
pub struct InvokeHost<'a> {
    binding: Option<&'a InvokeBinding>,
}

impl<'a> InvokeHost<'a> {
    /// Build a view; `None` means the capability was not granted.
    pub fn new(binding: Option<&'a InvokeBinding>) -> Self {
        Self { binding }
    }
}

impl invoke_iface::Host for InvokeHost<'_> {
    async fn invoke(
        &mut self,
        target: String,
        request: invoke_types::InvokeRequest,
    ) -> Result<invoke_types::InvokeResponse, invoke_types::Error> {
        let Some(binding) = self.binding else {
            return Err(invoke_types::Error::AccessDenied);
        };
        // Deny by default: the target must match the operator's allowlist.
        if !binding.targets.iter().any(|p| target_matches(p, &target)) {
            return Err(invoke_types::Error::TargetNotAllowed(target));
        }
        // The callee runs one level deeper; refuse before nesting past the cap.
        let next_depth = binding.depth + 1;
        if next_depth > MAX_INVOKE_DEPTH {
            return Err(invoke_types::Error::LoopDetected);
        }
        let req = InvokeRequest {
            method: request.method,
            path: request.path,
            headers: request
                .headers
                .into_iter()
                .map(|h| (h.name, h.value))
                .collect(),
            body: request.body,
        };
        match binding.invoker.invoke(&target, req, next_depth).await {
            Ok(resp) => Ok(invoke_types::InvokeResponse {
                status: resp.status,
                headers: resp
                    .headers
                    .into_iter()
                    .map(|(name, value)| invoke_types::Header { name, value })
                    .collect(),
                body: resp.body,
            }),
            Err(InvokeError::NotFound) => Err(invoke_types::Error::NotFound(target)),
            Err(InvokeError::Failed(reason)) => Err(invoke_types::Error::Failed(reason)),
        }
    }
}

/// Match a target `name` against one allowlist `pattern`, where `*` in the
/// pattern matches any (possibly empty) run of characters. `*` alone matches
/// everything; a literal pattern matches only its exact name. Matching is
/// anchored (the whole name must be consumed) and greedy-with-backtracking, so
/// multiple `*`s work (`img-*-v*`).
fn target_matches(pattern: &str, name: &str) -> bool {
    // Split on '*'; the pieces between stars must appear in order, the first
    // anchored at the start and the last at the end.
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    // `last` is what remains after the final '*'; the middle parts float.
    let mut middles: Vec<&str> = parts.collect();
    let last = middles.pop();
    for mid in middles {
        // Empty middle (from "**") matches nothing to consume.
        match rest.find(mid) {
            Some(idx) => rest = &rest[idx + mid.len()..],
            None => return false,
        }
    }
    match last {
        // No '*' in the pattern: it was a literal, so `rest` must be empty.
        None => rest.is_empty(),
        // Trailing text after the last '*' must end the name.
        Some(tail) => rest.ends_with(tail),
    }
}

/// Add the `invoke` interface to `linker`, resolving the per-invocation
/// [`InvokeHost`] view via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> InvokeHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    invoke_iface::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::invoke_iface::Host;
    use super::*;
    use std::sync::Mutex;

    /// Records the (target, depth) it was asked to run and returns a canned 200.
    #[derive(Default)]
    struct RecordingInvoker {
        calls: Mutex<Vec<(String, u32)>>,
        /// Targets to answer with `NotFound` instead of a 200.
        missing: Vec<String>,
    }

    #[async_trait::async_trait]
    impl Invoker for RecordingInvoker {
        async fn invoke(
            &self,
            target: &str,
            _request: InvokeRequest,
            depth: u32,
        ) -> Result<InvokeResponse, InvokeError> {
            self.calls.lock().unwrap().push((target.to_string(), depth));
            if self.missing.iter().any(|m| m == target) {
                return Err(InvokeError::NotFound);
            }
            Ok(InvokeResponse {
                status: 200,
                headers: vec![],
                body: b"ok".to_vec(),
            })
        }
    }

    fn req() -> invoke_types::InvokeRequest {
        invoke_types::InvokeRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![],
            body: vec![],
        }
    }

    fn binding(invoker: Arc<dyn Invoker>, targets: &[&str], depth: u32) -> InvokeBinding {
        InvokeBinding {
            invoker,
            targets: targets.iter().map(ToString::to_string).collect(),
            depth,
        }
    }

    #[test]
    fn wildcards_match_as_expected() {
        assert!(target_matches("*", "anything"));
        assert!(target_matches("resize", "resize"));
        assert!(!target_matches("resize", "resize-2"));
        assert!(target_matches("img-*", "img-resize"));
        assert!(target_matches("img-*", "img-"));
        assert!(!target_matches("img-*", "vid-resize"));
        assert!(target_matches("*-worker", "email-worker"));
        assert!(target_matches("img-*-v*", "img-resize-v2"));
        assert!(!target_matches("img-*-v*", "img-resize"));
    }

    #[tokio::test]
    async fn ungranted_is_access_denied() {
        let mut host = InvokeHost::new(None);
        let err = host.invoke("x".into(), req()).await.unwrap_err();
        assert!(matches!(err, invoke_types::Error::AccessDenied));
    }

    #[tokio::test]
    async fn target_outside_allowlist_is_denied() {
        let inv = Arc::new(RecordingInvoker::default());
        let b = binding(inv.clone(), &["img-*"], 0);
        let mut host = InvokeHost::new(Some(&b));
        let err = host.invoke("db-writer".into(), req()).await.unwrap_err();
        assert!(matches!(err, invoke_types::Error::TargetNotAllowed(t) if t == "db-writer"));
        // The invoker was never reached.
        assert!(inv.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn allowed_target_runs_at_depth_plus_one() {
        let inv = Arc::new(RecordingInvoker::default());
        let b = binding(inv.clone(), &["*"], 3);
        let mut host = InvokeHost::new(Some(&b));
        let resp = host.invoke("resize".into(), req()).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");
        assert_eq!(
            inv.calls.lock().unwrap().as_slice(),
            &[("resize".into(), 4)]
        );
    }

    #[tokio::test]
    async fn depth_cap_trips_loop_detected() {
        let inv = Arc::new(RecordingInvoker::default());
        // At the last allowed depth the next hop would exceed the cap.
        let b = binding(inv.clone(), &["*"], MAX_INVOKE_DEPTH);
        let mut host = InvokeHost::new(Some(&b));
        let err = host.invoke("resize".into(), req()).await.unwrap_err();
        assert!(matches!(err, invoke_types::Error::LoopDetected));
        assert!(inv.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_target_maps_to_not_found() {
        let inv = Arc::new(RecordingInvoker {
            missing: vec!["ghost".into()],
            ..Default::default()
        });
        let b = binding(inv.clone(), &["*"], 0);
        let mut host = InvokeHost::new(Some(&b));
        let err = host.invoke("ghost".into(), req()).await.unwrap_err();
        assert!(matches!(err, invoke_types::Error::NotFound(t) if t == "ghost"));
    }
}
