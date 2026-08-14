//! GraphQL federation executor: run a query plan and stitch the results.
//!
//! The planner (`graphql_plan`) produces an ordered list of fetches; this executor runs
//! each — a root fetch, or a dependent `_entities` fetch whose representations are built
//! from an earlier fetch's data — and merges every fetch's result into one response,
//! joining entities by their `@key`. Dispatching a fetch to its subgraph is abstracted
//! behind [`SubgraphFetcher`], so the stitching logic is tested with a mock and reused over
//! the real [`BackendRouter`] in the serving path — which routes each fetch to its
//! subgraph's backend (a wasm function, or the SQL data connector), letting a GraphQL→SQL
//! subgraph and a GraphQL→Wasi subgraph compose in one supergraph.
//!
//! Scope is **core federation**: object- and list-valued join points; entities are
//! stitched by representation order (which `_entities` preserves). Nested jumps work via
//! response paths into the already-stitched tree.

use crate::graphql_plan::QueryPlan;
use serde_json::{json, Map, Value};

/// Dispatches one planned fetch to a subgraph and returns its GraphQL response JSON
/// (an object with a `data` field, or a bare data object).
#[async_trait::async_trait]
pub(crate) trait SubgraphFetcher: Sync {
    async fn fetch(&self, subgraph: &str, query: &str, variables: Value) -> Value;
}

/// Execute `plan` with `fetcher`, returning the merged `{ "data": … }` response. `variables`
/// is the incoming operation's variables (a JSON object, or null) — forwarded to every root
/// fetch so a field argument bound to `$var` resolves; an `_entities` fetch also receives them
/// alongside its `representations`.
pub(crate) async fn execute(
    plan: &QueryPlan,
    fetcher: &dyn SubgraphFetcher,
    variables: &Value,
) -> Value {
    let mut data = json!({});
    let mut errors: Vec<Value> = Vec::new();
    for fetch in &plan.fetches {
        match &fetch.requires {
            None => {
                let resp = fetcher
                    .fetch(&fetch.subgraph, &fetch.query, variables.clone())
                    .await;
                // A root fetch's errors carry their own path relative to the root.
                collect_errors(&mut errors, &resp, &[]);
                if let Some(d) = fetch_data(&resp) {
                    merge(&mut data, d);
                }
            }
            Some(req) => {
                // Build the entity representations from the already-stitched tree at the
                // provider's response path, run the `_entities` fetch, and stitch the
                // resolved entity fields back in at that path.
                let reprs = representations(&data, &req.path, &req.type_name, &req.key);
                let resp = fetcher
                    .fetch(
                        &fetch.subgraph,
                        &fetch.query,
                        with_representations(variables, reprs),
                    )
                    .await;
                // An `_entities` fetch's errors are relative to `_entities[i]`; prefix them
                // with the provider path so a client can locate the failing field.
                collect_errors(&mut errors, &resp, &req.path);
                let entities = resp
                    .pointer("/data/_entities")
                    .or_else(|| resp.pointer("/_entities"))
                    .cloned()
                    .unwrap_or_else(|| json!([]));
                stitch(&mut data, &req.path, &entities);
            }
        }
    }
    // Assemble the spec envelope: `errors` is present only when at least one fetch reported
    // one, so a wholly-successful query is byte-identical to before.
    if errors.is_empty() {
        return json!({ "data": data });
    }
    // GraphQL error propagation: when a query fully errors so that **nothing** resolved (every
    // contributing fetch nulled its own data or errored, leaving `data` an empty object), the
    // response `data` is `null`, not `{}` — a fully-errored non-nullable root field nulls the
    // whole `data`. A *partial* success (some field resolved, or a nullable field arrived as
    // `{field: null}`) leaves `data` non-empty and is preserved.
    let data = match &data {
        Value::Object(map) if map.is_empty() => Value::Null,
        _ => data,
    };
    json!({ "data": data, "errors": errors })
}

/// The data of a fetch response's `{ "data": … }` envelope to merge into the composed tree,
/// or `None` when there is nothing to merge. An **error-only** response (the infra-failure
/// paths in this file build `{ "errors": [...] }` with no `data`) and an explicit top-level
/// `{ "data": null }` (a subgraph's non-null field failed) both contribute no data — so a
/// failing subgraph never wipes the other subgraphs' data, and its `{"errors":…}` object is
/// never itself merged in as data. A response with neither key is treated as envelope-less
/// raw data (the lenient path some mocks use).
fn fetch_data(resp: &Value) -> Option<&Value> {
    match resp.get("data") {
        Some(Value::Null) => None,
        Some(d) => Some(d),
        None if resp.get("errors").is_some() => None,
        None => Some(resp),
    }
}

/// Accumulate a fetch response's `errors` into `acc`, prefixing each error's `path` with
/// `base_path` (the fetch's response path — empty for a root fetch, the provider path for an
/// `_entities`/`requires` fetch). `message`, `extensions`, and `locations` are forwarded
/// verbatim. An absent / empty / non-array `errors` contributes nothing, so a legitimately
/// null field with no error stays error-free.
fn collect_errors(acc: &mut Vec<Value>, resp: &Value, base_path: &[String]) {
    let Some(errs) = resp.get("errors").and_then(Value::as_array) else {
        return;
    };
    for err in errs {
        let mut err = err.clone();
        if !base_path.is_empty() {
            let suffix = err
                .get("path")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut full: Vec<Value> = base_path.iter().map(|s| Value::String(s.clone())).collect();
            full.extend(suffix);
            if let Value::Object(m) = &mut err {
                m.insert("path".to_string(), Value::Array(full));
            }
        }
        acc.push(err);
    }
}

/// The variables for an `_entities` fetch: the incoming operation variables (when a JSON object)
/// plus the computed `representations` the `_entities(representations: $representations)` binds.
fn with_representations(variables: &Value, reprs: Value) -> Value {
    let mut map = match variables {
        Value::Object(m) => m.clone(),
        _ => serde_json::Map::new(),
    };
    map.insert("representations".to_string(), reprs);
    Value::Object(map)
}

/// Dispatch one fetch to a subgraph **function** over the in-process invoke path (no network
/// hop, no SSRF surface) — the subgraph name is the function name — mapping the result (or a
/// precise error) to a GraphQL response. An external gateway request is the root of the call
/// chain (`depth` 0); a **guest-initiated** run (via the `graphql` capability) dispatches at the
/// guest's own depth so its sub-fetches count against the shared call-depth cap. Used by the
/// [`BackendRouter`]'s function branch.
///
/// The caller's verified `bearer` is forwarded as the `Authorization` header so a subgraph
/// that authorizes per field sees the same principal on **every** fetch — a root fetch and a
/// dependent `_entities` hydration alike. Without it a subgraph's non-`public` field would see
/// an anonymous caller and refuse. `bearer` is the raw token (the gateway already stripped the
/// `Bearer ` scheme), so re-add it.
async fn invoke_subgraph(
    invoker: &dyn boatramp_handlers::Invoker,
    subgraph: &str,
    query: &str,
    variables: Value,
    bearer: Option<&str>,
    depth: u32,
) -> Value {
    let body = json!({ "query": query, "variables": variables })
        .to_string()
        .into_bytes();
    let mut headers = vec![("content-type".to_string(), b"application/json".to_vec())];
    if let Some(token) = bearer {
        headers.push((
            "authorization".to_string(),
            format!("Bearer {token}").into_bytes(),
        ));
    }
    let request = boatramp_handlers::InvokeRequest {
        method: "POST".to_string(),
        path: "/".to_string(),
        headers,
        body,
    };
    match invoker.invoke(subgraph, request, depth).await {
        Ok(resp) => serde_json::from_slice(&resp.body).unwrap_or_else(|_| {
            json!({ "errors": [{ "message": format!("subgraph `{subgraph}` returned invalid JSON") }] })
        }),
        // A registered subgraph with no deployed function of the same name — the registry
        // SDL and the actual subgraph function are decoupled, so surface this precisely
        // rather than as a generic outage (a silently-wrong result would be worse).
        Err(boatramp_handlers::InvokeError::NotFound) => json!({ "errors": [{
            "message": format!(
                "subgraph `{subgraph}` is registered but no function named `{subgraph}` is deployed"
            )
        }] }),
        Err(boatramp_handlers::InvokeError::Failed(msg)) => json!({ "errors": [{
            "message": format!("subgraph `{subgraph}` failed: {msg}")
        }] }),
    }
}

/// A [`SubgraphFetcher`] that dispatches each fetch to the **right backend**: a SQL-backed
/// subgraph (compiled to SQL against a managed database) or, by default, a wasm function.
/// This is where a GraphQL→SQL subgraph and a GraphQL→Wasi subgraph compose in one
/// supergraph — the gateway plans uniformly and this routes each fetch by its subgraph's
/// registered kind.
pub(crate) struct BackendRouter {
    invoker: std::sync::Arc<dyn boatramp_handlers::Invoker>,
    project: String,
    sql_provider: Option<std::sync::Arc<dyn boatramp_core::sql::SqlBackends>>,
    /// SQL-backed subgraphs: `name → (site, data config)`. A subgraph not here is a function.
    sql_subgraphs: std::collections::BTreeMap<
        String,
        (String, boatramp_core::config::HandlerGraphqlDataConfig),
    >,
    /// The request's verified app bearer token — bound to a SQL subgraph's claim-based
    /// `row_filter`, and forwarded as `Authorization` to a function subgraph so its per-field
    /// authorization sees the same principal.
    bearer: Option<String>,
    /// The call-chain depth at which sub-fetches are invoked. `0` for an external gateway
    /// request (the root); a guest-initiated run sets its own depth so the shared cap counts
    /// its sub-fetches. See [`BackendRouter::at_depth`].
    depth: u32,
}

impl BackendRouter {
    pub(crate) fn new(
        invoker: std::sync::Arc<dyn boatramp_handlers::Invoker>,
        project: String,
        sql_provider: Option<std::sync::Arc<dyn boatramp_core::sql::SqlBackends>>,
        sql_subgraphs: std::collections::BTreeMap<
            String,
            (String, boatramp_core::config::HandlerGraphqlDataConfig),
        >,
        bearer: Option<String>,
    ) -> Self {
        Self {
            invoker,
            project,
            sql_provider,
            sql_subgraphs,
            bearer,
            depth: 0,
        }
    }

    /// Dispatch this router's sub-fetches at call-chain `depth` (default `0`, the external
    /// gateway root). A guest-initiated run sets its own depth so the shared invoke depth cap
    /// counts a guest op → subgraph fetch → guest op chain and stops it looping.
    pub(crate) fn at_depth(mut self, depth: u32) -> Self {
        self.depth = depth;
        self
    }

    /// Resolve a fetch for a SQL-backed subgraph: open the site's database, introspect, and
    /// compile + run the fetch (the connector's own path), returning its GraphQL response.
    async fn run_sql(
        &self,
        subgraph: &str,
        site: &str,
        config: &boatramp_core::config::HandlerGraphqlDataConfig,
        query: &str,
        variables: Value,
    ) -> Value {
        let Some(provider) = &self.sql_provider else {
            return json!({ "errors": [{ "message": "the federation gateway has no SQL backend configured" }] });
        };
        let backend = match provider.database(&self.project, site, &config.source).await {
            Ok(backend) => backend,
            Err(err) => {
                return json!({ "errors": [{ "message": format!("subgraph `{subgraph}` database unavailable: {err}") }] })
            }
        };
        let schema = match crate::graphql_data::introspect::introspect_sqlite(backend.as_ref())
            .await
        {
            Ok(schema) => schema,
            Err(err) => {
                return json!({ "errors": [{ "message": format!("subgraph `{subgraph}` introspection failed: {err}") }] })
            }
        };
        let policy = crate::graphql_data::policy_from_config(config);
        let claims =
            crate::graphql_data::request_claims(&self.project, self.bearer.as_deref(), config)
                .await;
        let dialect = crate::graphql_data::dialect::Sqlite;
        let invoker = Some(self.invoker.as_ref());
        // A SQL subgraph resolves both root fetches and — so it's a full federation entity
        // resolver — `_entities` fetches (a keyed SELECT joined back by representation order).
        if crate::graphql_data::compile::is_entities_query(query) {
            crate::graphql_data::runner::execute_entities(
                backend.as_ref(),
                &dialect,
                &schema,
                &policy,
                &claims,
                query,
                &variables,
                invoker,
                self.bearer.as_deref(),
                self.depth,
            )
            .await
        } else {
            crate::graphql_data::runner::execute(
                backend.as_ref(),
                &dialect,
                &schema,
                &policy,
                &claims,
                query,
                &variables,
                invoker,
                self.bearer.as_deref(),
                self.depth,
            )
            .await
        }
    }
}

#[async_trait::async_trait]
impl SubgraphFetcher for BackendRouter {
    async fn fetch(&self, subgraph: &str, query: &str, variables: Value) -> Value {
        if let Some((site, config)) = self.sql_subgraphs.get(subgraph) {
            return self.run_sql(subgraph, site, config, query, variables).await;
        }
        invoke_subgraph(
            self.invoker.as_ref(),
            subgraph,
            query,
            variables,
            self.bearer.as_deref(),
            self.depth,
        )
        .await
    }
}

/// The server's [`SupergraphRunner`](boatramp_handlers::SupergraphRunner): runs a guest's
/// GraphQL operation against the project's composed supergraph in-process — the same planner +
/// executor an external `/graphql` request uses (via [`BackendRouter`]), plus two guest-specific
/// gates: a **forced safelist** (only pre-registered operations run — deny-by-default) and the
/// **shared depth cap** (sub-fetches dispatch at the guest's own depth so a run → subgraph fetch
/// → run chain cannot loop). The caller's own bearer is forwarded and re-verified per subgraph,
/// so a guest cannot escalate by running this.
pub(crate) struct FederationRunner {
    runtime: std::sync::Weak<crate::HandlerRuntimeInner>,
    project: String,
}

impl FederationRunner {
    /// A runner bound to `runtime`; scope it per request with [`FederationRunner::scoped`].
    pub(crate) fn new(runtime: std::sync::Weak<crate::HandlerRuntimeInner>) -> Self {
        Self {
            runtime,
            project: boatramp_core::project::DEFAULT_PROJECT.to_string(),
        }
    }

    /// A runner scoped to `project` (all registry/plan/execute lookups are project-qualified),
    /// as the guest grant needs — mirrors the invoker's per-tenant scoping.
    pub(crate) fn scoped(
        &self,
        project: boatramp_core::project::ProjectRef<'_>,
    ) -> std::sync::Arc<dyn boatramp_handlers::SupergraphRunner> {
        std::sync::Arc::new(Self {
            runtime: self.runtime.clone(),
            project: project.as_str().to_string(),
        })
    }
}

/// Strip a leading `Bearer ` scheme (case-insensitive) from a forwarded Authorization value,
/// leaving the raw token [`BackendRouter`] expects (it re-adds the scheme per subgraph).
fn strip_bearer(raw: &str) -> &str {
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .unwrap_or(raw)
}

#[async_trait::async_trait]
impl boatramp_handlers::SupergraphRunner for FederationRunner {
    async fn run(
        &self,
        request: boatramp_handlers::GraphqlRequest,
        depth: u32,
    ) -> Result<Vec<u8>, boatramp_handlers::SupergraphRunError> {
        use boatramp_handlers::SupergraphRunError;
        let Some(inner) = self.runtime.upgrade() else {
            return Err(SupergraphRunError::Failed(
                "handler runtime is shutting down".into(),
            ));
        };
        let kv = inner.kv.as_ref();
        let project = self.project.as_str();

        // Deny-by-default operation surface: a guest may run only a pre-registered (safelisted)
        // operation — by its hash for `run-persisted`, or the hash of the supplied `query` for
        // `run`. The subgraph field guards remain the hard enforcement; this is the floor.
        let hash = match (&request.query, &request.persisted_hash) {
            (Some(query), _) => crate::graphql_apq::sha256_hex(query),
            (None, Some(hash)) => hash.clone(),
            (None, None) => {
                return Err(SupergraphRunError::PlanFailed(
                    "no query or persisted hash supplied".into(),
                ))
            }
        };
        let Some(query) = crate::graphql_apq::safelisted_query(kv, project, &hash).await else {
            return Err(SupergraphRunError::NotSafelisted);
        };

        // Query-guard the resolved operation (depth/complexity), exactly as at the edge.
        let limits = crate::graphql_guard::limits_from(
            &boatramp_core::config::HandlerGraphqlConfig::default(),
        );
        if let crate::graphql_guard::GuardVerdict::Reject(reason) =
            crate::graphql_guard::guard_query(&query, &limits)
        {
            return Err(SupergraphRunError::PlanFailed(reason));
        }

        // Compose + plan against the project's registered subgraphs — memoized per project by
        // composition version (and, for the plan, the operation hash `hash`), so an agent turn's
        // N runs don't each re-list, re-parse every SDL, and re-plan a graph that only changes on
        // deploy. Invalidation is the version check inside the cache.
        let cached = inner
            .graphql_cache
            .supergraph(kv, project)
            .await
            .map_err(|e| {
                SupergraphRunError::Failed(format!("supergraph composition failed: {e}"))
            })?;
        let plan = inner
            .graphql_cache
            .plan(project, cached.version, &hash, &query, &cached.supergraph)
            .map_err(|_| SupergraphRunError::PlanFailed("the query cannot be planned".into()))?;

        let Some(invoker) = inner.invoker.get() else {
            return Err(SupergraphRunError::Failed("no invoker configured".into()));
        };
        let sql_subgraphs = (*cached.sql_subgraphs).clone();
        // Forward the guest's own bearer (re-verified per subgraph — no escalation), and dispatch
        // sub-fetches at this run's depth so the shared cap counts them.
        let bearer = request
            .authorization
            .as_deref()
            .map(|raw| strip_bearer(raw).to_string());
        let router = BackendRouter::new(
            invoker.scoped(boatramp_core::project::ProjectRef::new(project)),
            project.to_string(),
            inner.sql.clone(),
            sql_subgraphs,
            bearer,
        )
        .at_depth(depth);
        // The guest's operation variables (a JSON object string) — forwarded to the fetches so a
        // mutation/field argument bound to `$var` resolves. An unparsable/empty value is `{}`.
        let variables: Value =
            serde_json::from_str(&request.variables).unwrap_or_else(|_| json!({}));
        let response = execute(&plan, &router, &variables).await;
        serde_json::to_vec(&response)
            .map_err(|e| SupergraphRunError::Failed(format!("serializing response: {e}")))
    }
}

/// Deep-merge `src` into `dst`: objects merge key-by-key; anything else overwrites.
fn merge(dst: &mut Value, src: &Value) {
    match (dst, src) {
        (Value::Object(d), Value::Object(s)) => {
            for (k, v) in s {
                merge(d.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (d, s) => *d = s.clone(),
    }
}

fn navigate<'a>(data: &'a Value, path: &[String]) -> Option<&'a Value> {
    let mut cur = data;
    for seg in path {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

fn navigate_mut<'a>(data: &'a mut Value, path: &[String]) -> Option<&'a mut Value> {
    let mut cur = data;
    for seg in path {
        cur = cur.get_mut(seg)?;
    }
    Some(cur)
}

/// The `_entities` representations for the object(s) at `path`: `{ __typename, <key…> }`
/// for each (an object contributes one; an array contributes one per element).
fn representations(data: &Value, path: &[String], type_name: &str, key: &[String]) -> Value {
    let mut out = Vec::new();
    if let Some(node) = navigate(data, path) {
        collect_reprs(node, type_name, key, &mut out);
    }
    Value::Array(out)
}

fn collect_reprs(node: &Value, type_name: &str, key: &[String], out: &mut Vec<Value>) {
    match node {
        Value::Array(items) => {
            for item in items {
                collect_reprs(item, type_name, key, out);
            }
        }
        Value::Object(_) => {
            let mut repr = Map::new();
            repr.insert("__typename".to_string(), json!(type_name));
            for k in key {
                if let Some(v) = node.get(k) {
                    repr.insert(k.clone(), v.clone());
                }
            }
            out.push(Value::Object(repr));
        }
        _ => {}
    }
}

/// Merge the resolved `entities` back into the tree at `path`, by representation order
/// (an object join point takes the first entity; a list join point takes them positionally).
fn stitch(data: &mut Value, path: &[String], entities: &Value) {
    let Some(node) = navigate_mut(data, path) else {
        return;
    };
    let ents = entities.as_array().cloned().unwrap_or_default();
    match node {
        Value::Array(items) => {
            for (item, ent) in items.iter_mut().zip(ents.iter()) {
                merge(item, ent);
            }
        }
        Value::Object(_) => {
            if let Some(ent) = ents.first() {
                merge(node, ent);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphql_federation::compose;
    use crate::graphql_plan::plan;
    use std::collections::HashMap;

    const ACCOUNTS: &str = r#"
        type Query { me: User }
        type User @key(fields: "id") { id: ID! name: String }
    "#;
    const ACCOUNTS_LIST: &str = r#"
        type Query { users: [User] }
        type User @key(fields: "id") { id: ID! name: String }
    "#;
    const REVIEWS: &str = r#"
        type Query { topReviews: [Review] }
        type Review { id: ID! body: String }
        extend type User @key(fields: "id") { id: ID! @external reviews: [Review] }
    "#;

    /// A mock runner returning a canned response per subgraph. It is **adversarial about its
    /// input**: it asserts the query the gateway sent actually parses as a GraphQL operation
    /// before answering. A mock that ignores its query manufactures confidence — it passes even
    /// when the planner emits garbage (an anonymous mutation, a dropped argument), which is
    /// exactly how a broken planner shipped green. This one cannot.
    struct Mock(HashMap<&'static str, Value>);

    #[async_trait::async_trait]
    impl SubgraphFetcher for Mock {
        async fn fetch(&self, subgraph: &str, query: &str, _variables: Value) -> Value {
            assert!(
                async_graphql_parser::parse_query(query).is_ok(),
                "gateway sent subgraph `{subgraph}` an unparsable query: {query}"
            );
            self.0.get(subgraph).cloned().unwrap_or_else(|| json!({}))
        }
    }

    /// A runner that honors the real federation contract instead of returning a canned
    /// answer: a root fetch returns its data; an `_entities` fetch reads the
    /// `representations` variable and resolves each representation **by its key, in
    /// order** — exactly what an async-graphql federation subgraph's `_entities` resolver
    /// does. Using it end-to-end exercises the whole representations→`_entities`→stitch
    /// round-trip against a faithful subgraph, not a stub that echoes the expected result.
    struct ContractRunner;

    #[async_trait::async_trait]
    impl SubgraphFetcher for ContractRunner {
        async fn fetch(&self, subgraph: &str, query: &str, variables: Value) -> Value {
            match subgraph {
                "accounts" => json!({ "data": { "users": [
                    { "__typename": "User", "id": "1", "name": "Alice" },
                    { "__typename": "User", "id": "2", "name": "Bob" },
                ] } }),
                "reviews" => {
                    assert!(
                        query.contains("_entities"),
                        "entity fetch must use _entities"
                    );
                    let reprs = variables
                        .get("representations")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let entities: Vec<Value> = reprs
                        .iter()
                        .map(|r| {
                            let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            json!({ "reviews": [ { "body": format!("review for {id}") } ] })
                        })
                        .collect();
                    json!({ "data": { "_entities": entities } })
                }
                other => json!({ "errors": [{ "message": format!("unknown subgraph {other}") }] }),
            }
        }
    }

    /// An [`Invoker`](boatramp_handlers::Invoker) with no functions deployed — every
    /// target resolves to `NotFound`, so [`invoke_subgraph`] must report the
    /// registered-but-undeployed subgraph precisely.
    struct MissingInvoker;

    #[async_trait::async_trait]
    impl boatramp_handlers::Invoker for MissingInvoker {
        async fn invoke(
            &self,
            _target: &str,
            _request: boatramp_handlers::InvokeRequest,
            _depth: u32,
        ) -> Result<boatramp_handlers::InvokeResponse, boatramp_handlers::InvokeError> {
            Err(boatramp_handlers::InvokeError::NotFound)
        }
    }

    /// An [`Invoker`](boatramp_handlers::Invoker) that reflects the `Authorization` header it
    /// received back into its response — modelling a subgraph that authorizes per field: with a
    /// forwarded bearer it resolves (echoing the identity), without one it refuses with
    /// `UNAUTHENTICATED`. It lets a test prove the gateway forwards the caller's identity on the
    /// invoke path (root and `_entities` alike) rather than dropping it.
    struct AuthEchoInvoker;

    #[async_trait::async_trait]
    impl boatramp_handlers::Invoker for AuthEchoInvoker {
        async fn invoke(
            &self,
            _target: &str,
            request: boatramp_handlers::InvokeRequest,
            _depth: u32,
        ) -> Result<boatramp_handlers::InvokeResponse, boatramp_handlers::InvokeError> {
            let authz = request
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                .map(|(_, v)| String::from_utf8_lossy(v).into_owned());
            let body = match authz {
                Some(value) => json!({ "data": { "identity": value } }),
                None => json!({ "errors": [
                    { "message": "unauthenticated", "extensions": { "code": "UNAUTHENTICATED" } }
                ] }),
            };
            Ok(boatramp_handlers::InvokeResponse {
                status: 200,
                headers: vec![("content-type".to_string(), b"application/json".to_vec())],
                body: serde_json::to_vec(&body).unwrap(),
            })
        }
    }

    #[tokio::test]
    async fn merges_root_fetches_from_distinct_subgraphs() {
        let sg = compose(&[
            ("accounts".into(), ACCOUNTS.into()),
            ("reviews".into(), REVIEWS.into()),
        ])
        .unwrap();
        let plan = plan("{ me { name } topReviews { body } }", &sg).unwrap();
        let mock = Mock(HashMap::from([
            ("accounts", json!({ "data": { "me": { "name": "Alice" } } })),
            (
                "reviews",
                json!({ "data": { "topReviews": [{ "body": "ok" }] } }),
            ),
        ]));
        let out = execute(&plan, &mock, &json!({})).await;
        assert_eq!(out["data"]["me"]["name"], json!("Alice"));
        assert_eq!(out["data"]["topReviews"][0]["body"], json!("ok"));
        // A wholly-successful query carries no `errors` key (byte-identical to before).
        assert!(out.get("errors").is_none(), "no errors on success: {out}");
    }

    #[tokio::test]
    async fn a_fully_errored_root_nulls_data_and_surfaces_the_error() {
        // A subgraph returns a spec-correct `{ data: null, errors: [...] }` and it is the only
        // root fetch, so nothing resolves. The gateway must forward the real message AND, per
        // GraphQL error propagation, null the whole `data` (a fully-errored non-nullable root
        // field nulls `data`) — not leave it a bare `{}`.
        let sg = compose(&[
            ("accounts".into(), ACCOUNTS.into()),
            ("reviews".into(), REVIEWS.into()),
        ])
        .unwrap();
        let plan = plan("{ me { name } }", &sg).unwrap();
        let mock = Mock(HashMap::from([(
            "accounts",
            json!({ "data": null, "errors": [{ "message": "boom", "path": ["me"] }] }),
        )]));
        let out = execute(&plan, &mock, &json!({})).await;
        assert_eq!(out["errors"][0]["message"], json!("boom"));
        assert_eq!(out["errors"][0]["path"], json!(["me"]));
        // Nothing resolved → `data` is null (not `{}`), and the `{"errors":…}` object was never
        // merged as data.
        assert_eq!(out["data"], json!(null));
    }

    #[tokio::test]
    async fn partial_success_keeps_the_healthy_subgraph_and_surfaces_the_other_error() {
        // Two root fetches: one succeeds, one errors. The successful field survives in `data`
        // and the failing field's error surfaces — a partial failure is not a total wipe.
        let sg = compose(&[
            ("accounts".into(), ACCOUNTS.into()),
            ("reviews".into(), REVIEWS.into()),
        ])
        .unwrap();
        let plan = plan("{ me { name } topReviews { body } }", &sg).unwrap();
        let mock = Mock(HashMap::from([
            ("accounts", json!({ "data": { "me": { "name": "Alice" } } })),
            (
                "reviews",
                json!({ "data": null, "errors": [{ "message": "reviews down", "path": ["topReviews"] }] }),
            ),
        ]));
        let out = execute(&plan, &mock, &json!({})).await;
        // `data` is NOT nulled — a partial success is preserved (contrast the fully-errored case).
        assert!(!out["data"].is_null(), "partial success keeps data: {out}");
        assert_eq!(out["data"]["me"]["name"], json!("Alice"));
        assert_eq!(out["data"]["topReviews"], json!(null));
        assert_eq!(out["errors"][0]["message"], json!("reviews down"));
    }

    #[tokio::test]
    async fn an_entities_fetch_error_is_surfaced_with_the_provider_path() {
        // A dependent `_entities` fetch errors. Its error is surfaced, prefixed with the
        // provider path (`me`), while the root subgraph's data survives.
        let sg = compose(&[
            ("accounts".into(), ACCOUNTS.into()),
            ("reviews".into(), REVIEWS.into()),
        ])
        .unwrap();
        let plan = plan("{ me { name reviews { body } } }", &sg).unwrap();
        let mock = Mock(HashMap::from([
            (
                "accounts",
                json!({ "data": { "me": { "name": "Alice", "__typename": "User", "id": "1" } } }),
            ),
            (
                "reviews",
                json!({ "errors": [{ "message": "FORBIDDEN", "path": ["_entities", 0, "reviews"] }] }),
            ),
        ]));
        let out = execute(&plan, &mock, &json!({})).await;
        // Root data intact; the entity error surfaces with the provider path prefixed.
        assert_eq!(out["data"]["me"]["name"], json!("Alice"));
        assert_eq!(out["errors"][0]["message"], json!("FORBIDDEN"));
        assert_eq!(
            out["errors"][0]["path"],
            json!(["me", "_entities", 0, "reviews"])
        );
    }

    #[tokio::test]
    async fn stitches_a_cross_subgraph_entity_field() {
        let sg = compose(&[
            ("accounts".into(), ACCOUNTS.into()),
            ("reviews".into(), REVIEWS.into()),
        ])
        .unwrap();
        let plan = plan("{ me { name reviews { body } } }", &sg).unwrap();
        let mock = Mock(HashMap::from([
            (
                "accounts",
                json!({ "data": { "me": { "name": "Alice", "__typename": "User", "id": "1" } } }),
            ),
            (
                "reviews",
                json!({ "data": { "_entities": [{ "reviews": [{ "body": "great" }] }] } }),
            ),
        ]));
        let out = execute(&plan, &mock, &json!({})).await;
        // The `me` object now carries both its accounts fields and the stitched reviews.
        assert_eq!(out["data"]["me"]["name"], json!("Alice"));
        assert_eq!(out["data"]["me"]["reviews"][0]["body"], json!("great"));
    }

    #[tokio::test]
    async fn executes_a_list_entity_fetch_joining_each_element_by_its_key() {
        let sg = compose(&[
            ("accounts".into(), ACCOUNTS_LIST.into()),
            ("reviews".into(), REVIEWS.into()),
        ])
        .unwrap();
        let plan = plan("{ users { name reviews { body } } }", &sg).unwrap();
        let out = execute(&plan, &ContractRunner, &json!({})).await;
        // Each list element is joined to *its own* reviews by key — proving the
        // representations→`_entities`→stitch round-trip preserves per-element identity
        // (element 2 gets review-for-2, not review-for-1), which a canned mock can't show.
        assert_eq!(out["data"]["users"][0]["name"], json!("Alice"));
        assert_eq!(
            out["data"]["users"][0]["reviews"][0]["body"],
            json!("review for 1")
        );
        assert_eq!(out["data"]["users"][1]["name"], json!("Bob"));
        assert_eq!(
            out["data"]["users"][1]["reviews"][0]["body"],
            json!("review for 2")
        );
    }

    // A subgraph owning a `Mutation` root field (plus a query, as a subgraph conventionally has).
    const AGENT: &str = r#"
        type Query { ping: String }
        type Mutation { agent(input: String): String }
    "#;

    /// A subgraph fetcher that is **adversarial about a mutation**: it refuses unless the query it
    /// received is a genuine `mutation` operation carrying its argument (and, for the variable
    /// form, the forwarded variable value). This is the regression guard for the shipped bug —
    /// the planner dispatched a Mutation as an anonymous query and dropped arguments/variables, so
    /// the resolver never ran (`data:null`). A test double that echoed a canned answer could not
    /// tell; this one asserts the contract the real subgraph would enforce.
    struct MutationRunner;

    #[async_trait::async_trait]
    impl SubgraphFetcher for MutationRunner {
        async fn fetch(&self, subgraph: &str, query: &str, variables: Value) -> Value {
            assert_eq!(subgraph, "agent");
            let doc = async_graphql_parser::parse_query(query)
                .unwrap_or_else(|e| panic!("mutation fetch didn't parse: {e}\nquery: {query}"));
            // It MUST be a mutation operation — an anonymous/query op is the shipped bug.
            let op = match &doc.operations {
                async_graphql_parser::types::DocumentOperations::Single(op) => &op.node,
                async_graphql_parser::types::DocumentOperations::Multiple(m) => {
                    &m.values().next().unwrap().node
                }
            };
            assert_eq!(
                op.ty,
                async_graphql_parser::types::OperationType::Mutation,
                "the gateway must dispatch a Mutation as a `mutation`, got: {query}"
            );
            // The argument must have arrived — either an inline value or a forwarded variable.
            let inline = query.contains("agent(input:");
            let via_var = variables.get("input").is_some();
            assert!(
                inline && (query.contains("\"hi\"") || via_var),
                "the mutation argument was dropped; query={query} vars={variables}"
            );
            json!({ "data": { "agent": "ok" } })
        }
    }

    #[tokio::test]
    async fn executes_a_federated_mutation_dispatching_it_as_a_mutation_with_arguments() {
        // The exact class that shipped broken: a federated mutation with an argument, driven
        // through the real plan()→execute() path. MutationRunner asserts the subgraph actually
        // received a `mutation { agent(input: …) }`, so a regression (anonymous op or dropped
        // arg) fails here instead of silently returning data:null in production.
        let sg = compose(&[
            ("accounts".into(), ACCOUNTS.into()),
            ("agent".into(), AGENT.into()),
        ])
        .unwrap();

        // Inline-argument form.
        let plan_inline = plan("mutation { agent(input: \"hi\") }", &sg).unwrap();
        let out = execute(&plan_inline, &MutationRunner, &json!({})).await;
        assert_eq!(out["data"]["agent"], json!("ok"), "out: {out}");

        // Variable form — the common client shape; the variable value must be forwarded.
        let plan_var = plan("mutation T($input: String){ agent(input: $input) }", &sg).unwrap();
        let out = execute(&plan_var, &MutationRunner, &json!({ "input": "hi" })).await;
        assert_eq!(out["data"]["agent"], json!("ok"), "out: {out}");
    }

    #[tokio::test]
    async fn a_function_subgraph_that_is_not_deployed_is_reported_precisely() {
        // A router with no SQL subgraphs routes every fetch to the invoke path.
        let router = BackendRouter::new(
            std::sync::Arc::new(MissingInvoker),
            "default".to_string(),
            None,
            std::collections::BTreeMap::new(),
            None,
        );
        let resp = router.fetch("accounts", "{ me { id } }", json!({})).await;
        let msg = resp["errors"][0]["message"].as_str().unwrap_or_default();
        assert!(
            msg.contains("no function named `accounts` is deployed"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn forwards_the_callers_verified_bearer_to_a_function_subgraph() {
        let router = BackendRouter::new(
            std::sync::Arc::new(AuthEchoInvoker),
            "default".to_string(),
            None,
            std::collections::BTreeMap::new(),
            Some("t-acme".to_string()),
        );
        // A root fetch carries the caller's identity as `Bearer <token>`...
        let root = router.fetch("orders", "{ me { id } }", json!({})).await;
        assert_eq!(root["data"]["identity"], json!("Bearer t-acme"));
        // ...and so does a dependent `_entities` hydration fetch (same dispatch path).
        let entity = router
            .fetch(
                "orders",
                "query($r: [_Any!]!) { _entities(representations: $r) { id } }",
                json!({ "representations": [{ "__typename": "Order", "id": "1" }] }),
            )
            .await;
        assert_eq!(
            entity["data"]["identity"],
            json!("Bearer t-acme"),
            "the bearer must ride the _entities fetch too, or a stitched field would go anonymous"
        );
    }

    #[tokio::test]
    async fn an_anonymous_gateway_call_forwards_no_bearer_so_an_authed_field_is_refused() {
        let router = BackendRouter::new(
            std::sync::Arc::new(AuthEchoInvoker),
            "default".to_string(),
            None,
            std::collections::BTreeMap::new(),
            None,
        );
        let resp = router.fetch("orders", "{ me { id } }", json!({})).await;
        assert_eq!(
            resp["errors"][0]["extensions"]["code"],
            json!("UNAUTHENTICATED"),
            "with no forwarded identity a subgraph's authed field must refuse, not resolve anonymously"
        );
    }

    #[test]
    fn merge_is_a_deep_object_merge() {
        let mut a = json!({ "me": { "name": "x" } });
        merge(&mut a, &json!({ "me": { "age": 3 }, "other": 1 }));
        assert_eq!(a, json!({ "me": { "name": "x", "age": 3 }, "other": 1 }));
    }

    /// An invoker that reflects the call-chain `depth` it was dispatched at back into its
    /// response, so a test can prove `BackendRouter::at_depth` threads the guest's depth through
    /// to the sub-fetch (the recursion-safety guarantee).
    struct DepthEchoInvoker;

    #[async_trait::async_trait]
    impl boatramp_handlers::Invoker for DepthEchoInvoker {
        async fn invoke(
            &self,
            _target: &str,
            _request: boatramp_handlers::InvokeRequest,
            depth: u32,
        ) -> Result<boatramp_handlers::InvokeResponse, boatramp_handlers::InvokeError> {
            Ok(boatramp_handlers::InvokeResponse {
                status: 200,
                headers: vec![("content-type".to_string(), b"application/json".to_vec())],
                body: serde_json::to_vec(&json!({ "data": { "depth": depth } })).unwrap(),
            })
        }
    }

    #[tokio::test]
    async fn at_depth_dispatches_function_fetches_at_that_depth() {
        // The external gateway is the root (depth 0)...
        let root = BackendRouter::new(
            std::sync::Arc::new(DepthEchoInvoker),
            "default".to_string(),
            None,
            std::collections::BTreeMap::new(),
            None,
        );
        assert_eq!(
            root.fetch("s", "{ x }", json!({})).await["data"]["depth"],
            json!(0)
        );
        // ...a guest-initiated run dispatches its sub-fetches at its own depth, so the shared
        // invoke cap counts a run → subgraph → run chain and stops it looping.
        let scoped = BackendRouter::new(
            std::sync::Arc::new(DepthEchoInvoker),
            "default".to_string(),
            None,
            std::collections::BTreeMap::new(),
            None,
        )
        .at_depth(4);
        assert_eq!(
            scoped.fetch("s", "{ x }", json!({})).await["data"]["depth"],
            json!(4)
        );
    }
}
