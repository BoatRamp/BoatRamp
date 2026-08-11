//! The `invoke` host binding: one function calls another **in-process**, the
//! same HTTP-shaped request/response the platform uses to invoke it, without a
//! network round-trip. The engine cannot resolve or run a target itself (that
//! lives a layer up in the server, which owns the function store + metering), so
//! the binding holds an [`Invoker`] the server implements; the host here enforces
//! the *capability*: deny by default, an operator-configured target allowlist
//! (with `*` wildcards), and a call-depth cap so functions cannot invoke in a
//! loop.

use std::sync::Arc;

use bytes::Bytes;
use futures::stream::{BoxStream, StreamExt};
use wasmtime::component::{Resource, ResourceTable};

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/invoke-host",
        async: {
            only_imports: ["invoke", "invoke-streaming", "[method]incoming-response.read"],
        },
        with: {
            "boatramp:handlers/invoke/incoming-response": super::IncomingResponse,
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

/// A sibling function's **streaming** response: status + headers are known up
/// front; the body is a byte stream the host reads incrementally on demand, so a
/// large or incrementally-produced response is never buffered whole. Returned by
/// [`Invoker::invoke_streaming`].
pub struct InvokeStreamResponse {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    /// The response body as a stream of byte chunks; a chunk error carries a reason.
    pub body: BoxStream<'static, Result<Bytes, String>>,
}

/// The host state behind a guest `incoming-response` resource: the streamed body
/// plus a small carry buffer holding the remainder of a chunk that exceeded the
/// guest's requested read size. Pulled by [`InvokeHost`]'s `read`.
pub struct IncomingResponse {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: BoxStream<'static, Result<Bytes, String>>,
    /// Bytes read from the stream but not yet handed to the guest.
    carry: Bytes,
    /// The stream has ended (or errored); further reads return end-of-stream.
    done: bool,
}

impl IncomingResponse {
    fn new(resp: InvokeStreamResponse) -> Self {
        Self {
            status: resp.status,
            headers: resp.headers,
            body: resp.body,
            carry: Bytes::new(),
            done: false,
        }
    }

    /// Read up to `max` more bytes, serving from the carry buffer first and pulling
    /// the next non-empty frame otherwise. Returns an empty vec at end of stream;
    /// an empty *mid-stream* frame is skipped so only end-of-stream reads as empty.
    async fn read(&mut self, max: usize) -> Result<Vec<u8>, String> {
        if max == 0 {
            return Ok(Vec::new());
        }
        loop {
            if !self.carry.is_empty() {
                let n = max.min(self.carry.len());
                return Ok(self.carry.split_to(n).to_vec());
            }
            if self.done {
                return Ok(Vec::new());
            }
            match self.body.next().await {
                Some(Ok(chunk)) if chunk.is_empty() => continue,
                Some(Ok(chunk)) => self.carry = chunk,
                Some(Err(reason)) => {
                    self.done = true;
                    return Err(reason);
                }
                None => {
                    self.done = true;
                    return Ok(Vec::new());
                }
            }
        }
    }
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

    /// Invoke `target` and return its response as a **stream**: status + headers up
    /// front, the body pulled incrementally. The default buffers via
    /// [`Invoker::invoke`] then yields the whole body as one chunk — correct but not
    /// memory-streamed; an implementation that can stream the callee's body (running
    /// it and returning its response body stream) should override this.
    async fn invoke_streaming(
        &self,
        target: &str,
        request: InvokeRequest,
        depth: u32,
    ) -> Result<InvokeStreamResponse, InvokeError> {
        let resp = self.invoke(target, request, depth).await?;
        let body = futures::stream::once(async move { Ok(Bytes::from(resp.body)) });
        Ok(InvokeStreamResponse {
            status: resp.status,
            headers: resp.headers,
            body: body.boxed(),
        })
    }
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

/// Per-invocation view over the (optional) invoke grant plus the store's resource
/// table, where a streaming call's `incoming-response` handle lives.
pub struct InvokeHost<'a> {
    table: &'a mut ResourceTable,
    binding: Option<&'a InvokeBinding>,
}

impl<'a> InvokeHost<'a> {
    /// Build a view; `binding == None` means the capability was not granted.
    pub fn new(table: &'a mut ResourceTable, binding: Option<&'a InvokeBinding>) -> Self {
        Self { table, binding }
    }

    /// The shared admission check for both `invoke` and `invoke-streaming`: the
    /// capability must be granted, the target must match the allowlist, and the next
    /// hop must not exceed the depth cap. Returns the invoker (a cheap `Arc` clone, so
    /// no borrow of `self` outlives it) and the callee's depth.
    fn admit(&self, target: &str) -> Result<(Arc<dyn Invoker>, u32), invoke_types::Error> {
        let Some(binding) = self.binding else {
            return Err(invoke_types::Error::AccessDenied);
        };
        // Deny by default: the target must match the operator's allowlist.
        if !binding.targets.iter().any(|p| target_matches(p, target)) {
            return Err(invoke_types::Error::TargetNotAllowed(target.to_string()));
        }
        // The callee runs one level deeper; refuse before nesting past the cap.
        let next_depth = binding.depth + 1;
        if next_depth > MAX_INVOKE_DEPTH {
            return Err(invoke_types::Error::LoopDetected);
        }
        Ok((binding.invoker.clone(), next_depth))
    }
}

/// Convert the wire request into the host's [`InvokeRequest`].
fn to_request(request: invoke_types::InvokeRequest) -> InvokeRequest {
    InvokeRequest {
        method: request.method,
        path: request.path,
        headers: request
            .headers
            .into_iter()
            .map(|h| (h.name, h.value))
            .collect(),
        body: request.body,
    }
}

impl invoke_iface::Host for InvokeHost<'_> {
    async fn invoke(
        &mut self,
        target: String,
        request: invoke_types::InvokeRequest,
    ) -> Result<invoke_types::InvokeResponse, invoke_types::Error> {
        let (invoker, next_depth) = self.admit(&target)?;
        match invoker
            .invoke(&target, to_request(request), next_depth)
            .await
        {
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

    async fn invoke_streaming(
        &mut self,
        target: String,
        request: invoke_types::InvokeRequest,
    ) -> Result<Resource<IncomingResponse>, invoke_types::Error> {
        let (invoker, next_depth) = self.admit(&target)?;
        match invoker
            .invoke_streaming(&target, to_request(request), next_depth)
            .await
        {
            Ok(resp) => self
                .table
                .push(IncomingResponse::new(resp))
                .map_err(|e| invoke_types::Error::Failed(format!("resource table: {e}"))),
            Err(InvokeError::NotFound) => Err(invoke_types::Error::NotFound(target)),
            Err(InvokeError::Failed(reason)) => Err(invoke_types::Error::Failed(reason)),
        }
    }
}

impl invoke_iface::HostIncomingResponse for InvokeHost<'_> {
    fn status(&mut self, resp: Resource<IncomingResponse>) -> u16 {
        self.table.get(&resp).map(|r| r.status).unwrap_or(0)
    }

    fn headers(&mut self, resp: Resource<IncomingResponse>) -> Vec<invoke_types::Header> {
        self.table
            .get(&resp)
            .map(|r| {
                r.headers
                    .iter()
                    .map(|(name, value)| invoke_types::Header {
                        name: name.clone(),
                        value: value.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn read(
        &mut self,
        resp: Resource<IncomingResponse>,
        max: u64,
    ) -> Result<Vec<u8>, invoke_types::Error> {
        let entry = self
            .table
            .get_mut(&resp)
            .map_err(|e| invoke_types::Error::Failed(format!("resource: {e}")))?;
        entry
            .read(max as usize)
            .await
            .map_err(invoke_types::Error::Failed)
    }

    fn drop(&mut self, resp: Resource<IncomingResponse>) -> wasmtime::Result<()> {
        self.table.delete(resp)?;
        Ok(())
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
        let mut table = ResourceTable::new();
        let mut host = InvokeHost::new(&mut table, None);
        let err = host.invoke("x".into(), req()).await.unwrap_err();
        assert!(matches!(err, invoke_types::Error::AccessDenied));
    }

    #[tokio::test]
    async fn target_outside_allowlist_is_denied() {
        let inv = Arc::new(RecordingInvoker::default());
        let b = binding(inv.clone(), &["img-*"], 0);
        let mut table = ResourceTable::new();
        let mut host = InvokeHost::new(&mut table, Some(&b));
        let err = host.invoke("db-writer".into(), req()).await.unwrap_err();
        assert!(matches!(err, invoke_types::Error::TargetNotAllowed(t) if t == "db-writer"));
        // The invoker was never reached.
        assert!(inv.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn allowed_target_runs_at_depth_plus_one() {
        let inv = Arc::new(RecordingInvoker::default());
        let b = binding(inv.clone(), &["*"], 3);
        let mut table = ResourceTable::new();
        let mut host = InvokeHost::new(&mut table, Some(&b));
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
        let mut table = ResourceTable::new();
        let mut host = InvokeHost::new(&mut table, Some(&b));
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
        let mut table = ResourceTable::new();
        let mut host = InvokeHost::new(&mut table, Some(&b));
        let err = host.invoke("ghost".into(), req()).await.unwrap_err();
        assert!(matches!(err, invoke_types::Error::NotFound(t) if t == "ghost"));
    }

    /// An invoker that streams a fixed multi-chunk body, to exercise the streaming
    /// path + the `incoming-response` resource without a guest component.
    struct StreamInvoker;

    #[async_trait::async_trait]
    impl Invoker for StreamInvoker {
        async fn invoke(
            &self,
            _t: &str,
            _r: InvokeRequest,
            _d: u32,
        ) -> Result<InvokeResponse, InvokeError> {
            unreachable!("this invoker is streaming-only")
        }

        async fn invoke_streaming(
            &self,
            _t: &str,
            _r: InvokeRequest,
            _d: u32,
        ) -> Result<InvokeStreamResponse, InvokeError> {
            let chunks: Vec<Result<Bytes, String>> = vec![
                Ok(Bytes::from_static(b"hello ")),
                Ok(Bytes::new()), // an empty mid-stream frame must be skipped, not read as EOF
                Ok(Bytes::from_static(b"streamed ")),
                Ok(Bytes::from_static(b"world")),
            ];
            Ok(InvokeStreamResponse {
                status: 206,
                headers: vec![("content-type".into(), b"text/plain".to_vec())],
                body: futures::stream::iter(chunks).boxed(),
            })
        }
    }

    #[tokio::test]
    async fn streaming_invoke_reassembles_chunks_and_ends() {
        use super::invoke_iface::HostIncomingResponse;
        let inv: Arc<dyn Invoker> = Arc::new(StreamInvoker);
        let b = binding(inv, &["*"], 0);
        let mut table = ResourceTable::new();
        let mut host = InvokeHost::new(&mut table, Some(&b));

        let owned = host.invoke_streaming("x".into(), req()).await.unwrap();
        let rep = owned.rep();
        // Status + headers are available before the body is read.
        assert_eq!(host.status(Resource::new_borrow(rep)), 206);
        let headers = host.headers(Resource::new_borrow(rep));
        assert!(headers.iter().any(|h| h.name == "content-type"));

        // Read in small 4-byte bites: the body reassembles across reads, and the empty
        // mid-stream frame does not prematurely signal end-of-stream.
        let mut collected = Vec::new();
        loop {
            let chunk = host.read(Resource::new_borrow(rep), 4).await.unwrap();
            if chunk.is_empty() {
                break;
            }
            assert!(chunk.len() <= 4);
            collected.extend_from_slice(&chunk);
        }
        assert_eq!(collected, b"hello streamed world");
        // Any further read stays at end-of-stream.
        assert!(host
            .read(Resource::new_borrow(rep), 4)
            .await
            .unwrap()
            .is_empty());
        host.drop(owned).unwrap();
    }
}
