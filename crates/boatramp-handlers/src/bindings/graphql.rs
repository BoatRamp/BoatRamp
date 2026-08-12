//! The `graphql` host binding: a guest runs a GraphQL operation against the project's
//! composed federation supergraph **in-process** — cross-subgraph planning + execution over the
//! invoke path, no network hop, no egress. The engine cannot plan or execute itself (the
//! registry, planner, executor, safelist, and invoker all live a layer up in the server), so the
//! binding holds a [`SupergraphRunner`] the server implements; the host here enforces the
//! *capability*: deny by default (the grant must be present), and the **shared** call-depth cap
//! ([`MAX_INVOKE_DEPTH`](super::invoke::MAX_INVOKE_DEPTH)) so a guest op → subgraph fetch → guest
//! op chain cannot loop.

use std::sync::Arc;

use super::invoke::MAX_INVOKE_DEPTH;

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/graphql-host",
        async: {
            only_imports: ["run", "run-persisted"],
        },
    });
}

use generated::boatramp::handlers::{graphql as graphql_iface, graphql_types};

/// A request to run against the project's composed supergraph, at the host boundary — the wire
/// (WIT) types are converted to this so the [`SupergraphRunner`] impl (in the server) never sees
/// the generated bindgen types. Exactly one of `query` (an ad-hoc op, still safelist-checked) or
/// `persisted_hash` (a pre-registered op by hash) is set.
pub struct GraphqlRequest {
    /// The operation text, for a `run`; `None` for a `run-persisted`.
    pub query: Option<String>,
    /// The safelist hash (sha256-hex of the query text), for a `run-persisted`.
    pub persisted_hash: Option<String>,
    /// Variables as a JSON object string (`{}` when none).
    pub variables: String,
    /// The selected operation name, if the document holds several.
    pub operation_name: Option<String>,
    /// The caller's forwarded bearer (raw `Authorization` value), re-verified per subgraph.
    pub bearer: Option<String>,
}

/// Why a supergraph run failed, as the [`SupergraphRunner`] reports it. Capability failures
/// (missing grant, depth cap) are the host's concern and never reach the runner.
#[derive(Debug)]
pub enum GraphqlError {
    /// The operation is not on the project's registered safelist (guest ops are deny-by-default).
    NotSafelisted,
    /// The query could not be planned against the supergraph. Carries a reason.
    PlanFailed(String),
    /// The run failed (composition, execution, ...). Carries a reason.
    Failed(String),
}

/// Runs a GraphQL operation against a project's composed supergraph. Implemented by the server
/// (which owns the registry, planner, executor, safelist, and the invoker); the host calls back
/// through it after enforcing the capability. `depth` is this run's position in the call chain,
/// so its sub-fetches are depth-capped against [`MAX_INVOKE_DEPTH`](super::invoke::MAX_INVOKE_DEPTH).
#[async_trait::async_trait]
pub trait SupergraphRunner: Send + Sync {
    async fn run(&self, request: GraphqlRequest, depth: u32) -> Result<Vec<u8>, GraphqlError>;
}

/// The per-invocation `graphql` grant: the server-provided runner + this invocation's call
/// depth. The binding being absent (`None`) means the capability is not granted to this function.
#[derive(Clone)]
pub struct GraphqlBinding {
    pub(crate) runner: Arc<dyn SupergraphRunner>,
    pub(crate) depth: u32,
}

/// The per-invocation host view of the `graphql` capability.
pub struct GraphqlHost<'a> {
    binding: Option<&'a GraphqlBinding>,
}

impl<'a> GraphqlHost<'a> {
    /// A host view over the (optional) grant.
    pub fn new(binding: Option<&'a GraphqlBinding>) -> Self {
        Self { binding }
    }

    /// Enforce the capability: the grant must be present, and the run — whose sub-fetches nest
    /// one level deeper — must not exceed the shared call-depth cap.
    fn admit(&self) -> Result<(Arc<dyn SupergraphRunner>, u32), graphql_types::GraphqlError> {
        let Some(binding) = self.binding else {
            return Err(graphql_types::GraphqlError::AccessDenied);
        };
        let next_depth = binding.depth + 1;
        if next_depth > MAX_INVOKE_DEPTH {
            return Err(graphql_types::GraphqlError::DepthExceeded);
        }
        Ok((binding.runner.clone(), next_depth))
    }
}

/// Map the server-facing error to the guest-visible wire error.
fn map_error(err: GraphqlError) -> graphql_types::GraphqlError {
    match err {
        GraphqlError::NotSafelisted => graphql_types::GraphqlError::NotSafelisted,
        GraphqlError::PlanFailed(m) => graphql_types::GraphqlError::PlanFailed(m),
        GraphqlError::Failed(m) => graphql_types::GraphqlError::Failed(m),
    }
}

impl graphql_iface::Host for GraphqlHost<'_> {
    async fn run(
        &mut self,
        request: graphql_types::GraphqlRequest,
    ) -> Result<Vec<u8>, graphql_types::GraphqlError> {
        let (runner, depth) = self.admit()?;
        let req = GraphqlRequest {
            query: Some(request.query),
            persisted_hash: None,
            variables: request.variables,
            operation_name: request.operation_name,
            bearer: request.bearer,
        };
        runner.run(req, depth).await.map_err(map_error)
    }

    async fn run_persisted(
        &mut self,
        hash: String,
        variables: String,
        bearer: Option<String>,
    ) -> Result<Vec<u8>, graphql_types::GraphqlError> {
        let (runner, depth) = self.admit()?;
        let req = GraphqlRequest {
            query: None,
            persisted_hash: Some(hash),
            variables,
            operation_name: None,
            bearer,
        };
        runner.run(req, depth).await.map_err(map_error)
    }
}

/// Add the `graphql` interface to `linker`, resolving the per-invocation [`GraphqlHost`] via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> GraphqlHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    graphql_iface::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::graphql_iface::Host;
    use super::*;
    use std::sync::Mutex;

    /// Records the (query/hash, depth) it was asked to run and returns a canned response.
    #[derive(Default)]
    struct RecordingRunner {
        calls: Mutex<Vec<(String, u32)>>,
    }

    #[async_trait::async_trait]
    impl SupergraphRunner for RecordingRunner {
        async fn run(&self, request: GraphqlRequest, depth: u32) -> Result<Vec<u8>, GraphqlError> {
            let tag = request.query.or(request.persisted_hash).unwrap_or_default();
            self.calls.lock().unwrap().push((tag, depth));
            Ok(br#"{"data":{"ok":true}}"#.to_vec())
        }
    }

    fn binding(runner: Arc<dyn SupergraphRunner>, depth: u32) -> GraphqlBinding {
        GraphqlBinding { runner, depth }
    }

    fn request() -> graphql_types::GraphqlRequest {
        graphql_types::GraphqlRequest {
            query: "{ me { id } }".into(),
            variables: "{}".into(),
            operation_name: None,
            bearer: Some("t-acme".into()),
        }
    }

    #[tokio::test]
    async fn a_granted_run_calls_the_runner_one_level_deeper() {
        let runner = Arc::new(RecordingRunner::default());
        let b = binding(runner.clone(), 2);
        let mut host = GraphqlHost::new(Some(&b));
        let body = host.run(request()).await.expect("granted run succeeds");
        assert_eq!(body, br#"{"data":{"ok":true}}"#.to_vec());
        // The run's sub-fetches nest at depth+1 so the shared cap counts them.
        assert_eq!(
            runner.calls.lock().unwrap().as_slice(),
            &[("{ me { id } }".to_string(), 3)]
        );
    }

    #[tokio::test]
    async fn an_ungranted_run_is_access_denied() {
        let mut host = GraphqlHost::new(None);
        assert!(matches!(
            host.run(request()).await,
            Err(graphql_types::GraphqlError::AccessDenied)
        ));
    }

    #[tokio::test]
    async fn a_run_at_the_depth_cap_is_refused() {
        let runner = Arc::new(RecordingRunner::default());
        let b = binding(runner.clone(), MAX_INVOKE_DEPTH); // next hop would exceed the cap
        let mut host = GraphqlHost::new(Some(&b));
        assert!(matches!(
            host.run(request()).await,
            Err(graphql_types::GraphqlError::DepthExceeded)
        ));
        assert!(runner.calls.lock().unwrap().is_empty());
    }
}
